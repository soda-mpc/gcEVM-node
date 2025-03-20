//go:build cgo
// +build cgo

package co2

/*
#cgo CFLAGS: -I/ses_files
#cgo LDFLAGS: -L/ses_files -lses
#include "libses.h"
#include <stdlib.h>
#include <errno.h>
*/
import "C"

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"math"
	"math/big"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/consensus/misc"
	"github.com/ethereum/go-ethereum/consensus/misc/eip1559"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/ethereum/go-ethereum/shared"
	"github.com/ethereum/go-ethereum/trie"
	"github.com/shopspring/decimal"
	"golang.org/x/crypto/sha3"
)

type SodaRoleType string

const (
	// The sequencer is the only role that can gather transactions from the Tx pool.
	// It generates a block with a pseudo-real state (can be validated but has no real meaning)
	// and sends it to the evaluation node (the mpc Executor), it then waits for it to
	// re-broadcast the block with a real state.
	// When it receives the real state block (same transactions, this time with a real execution)
	// it validates the execution using an "execution transcript" and replaces the pseudo-state
	// block with the real one.
	Sequencer SodaRoleType = "sequencer"

	// The executor instance receives a pseudo-real state block from the Sequencer, validates it
	// and extracts the transaction list. It then executes the transaction list sequentially via MPC, using an mpc
	// counterpart (on a different node). It packs the result into a new block of the same height and returns it
	// to the validator.
	Executor SodaRoleType = "executor"

	// The validator is a node meant to hold only the canonical chain, it rejects Sequencer blocks and only accepts
	// Executor blocks. This behavior allows it to function as the "proper" api to all user chain interaction since
	// it is guaranteed to hold the truthful state.
	// The validator can not add blocks to the chain, it can only validate them. it has a Tx pool so it can help
	// tx propagation. It does not validate nor adds Sequencer blocks to it's chain, only Executor blocks. (this
	// means no pseudo-real state blocks are added to it's chain, only real state blocks)
	Validator SodaRoleType = "validator"
)

type blockTimestamp struct {
	number    *big.Int
	timestamp uint64
}

var (
	nonceAuthVote = hexutil.MustDecode("0xffffffffffffffff") // Magic nonce number to vote on adding a new signer
	nonceDropVote = hexutil.MustDecode("0x0000000000000000") // Magic nonce number to vote on removing a signer.

	uncleHash = types.CalcUncleHash(nil) // Always Keccak256(RLP([])) as uncles are meaningless outside of PoW.

	// The differences in difficulty levels are designed to trigger a "reorg" behavior
	// in which the Executor's blocks (the black chain) will always take precedence over the
	// Sequencer's (red) blocks
	difficultySequencer = big.NewInt(1) // Block difficulty for Sequencer (red) blocks
	difficultyExecutor  = big.NewInt(5) // Block difficulty for Executor (black) blocks

	// errUnknownBlock is returned when the list of signers is requested for a block
	// that is not part of the local blockchain.
	errUnknownBlock = errors.New("unknown block")

	// errInvalidVote is returned if a nonce value is something else that the two
	// allowed constants of 0x00..0 or 0xff..f.
	errInvalidVote = errors.New("vote nonce not 0x00..0 or 0xff..f")

	// errMissingSignature is returned if a block's extra-data section doesn't seem
	// to contain a 65 byte secp256k1 signature.
	errMissingSignature = errors.New("extra-data 65 byte signature suffix missing")

	// errInvalidMixDigest is returned if a block's mix digest is non-zero.
	errInvalidMixDigest = errors.New("non-zero mix digest")

	// errInvalidUncleHash is returned if a block contains an non-empty uncle list.
	errInvalidUncleHash = errors.New("non empty uncle hash")

	// errInvalidDifficulty is returned if the difficulty of a block neither 1 or 2.
	errInvalidDifficulty = errors.New("invalid difficulty")

	// errInvalidTimestamp is returned if the timestamp of a block is lower than
	// the previous block's timestamp + the minimum block period.
	errInvalidTimestamp = errors.New("invalid timestamp")

	// errTranscriptUninitialized is returned if the transcript is not initialized
	errTranscriptUninitialized = errors.New("transcript uninitialized")

	errSequencerTranscriptMutationAttempt = errors.New("sequencer cannot mutate transcript")

	errUnauthorizedSigner = errors.New("unauthorized signer")

	errSkipBlockAttempt = errors.New(
		"trying to insert a block with higher number than current head")

	errUnorderedExecutorSignatures = errors.New("signers must be in ascending order")

	errMalformedExtraData = errors.New("malformed extra-data")

	ErrBlockExists = errors.New("block already exists")

	ErrExecutorSigUnavailable = errors.New("executor signature unavailable")

	ErrSigRequestedForCanonicalBlock = errors.New("signature requested for canonical block")

	ErrSigRequestedForPreviousBlock = errors.New("signature requested for previous block")

	ErrMissingSequencerBlock = errors.New("missing sequencer block")

	ErrOutOfSync = errors.New("out of sync")

	ErrSequencerBlockForValidatorNode = errors.New("validator can not accept sequencer blocks")
)

// SignerFn hashes and signs the data to be signed by a backing account.
type SignerFn func(signer accounts.Account, mimeType string, message []byte) ([]byte, error)

type ExecutionState string

const (
	WaitingForSequencerBlock ExecutionState = "WaitingForSequencerBlock"
	InsertingSequencerBlock  ExecutionState = "InsertingSequencerBlock"
	GeneratingExecutorBlock  ExecutionState = "GeneratingExecutorBlock"
	WaitingForExecutorSig    ExecutionState = "WaitingForExecutorSig"
)

var previousExecutionStates = map[ExecutionState]ExecutionState{
	WaitingForSequencerBlock: WaitingForExecutorSig,
	InsertingSequencerBlock:  WaitingForSequencerBlock,
	GeneratingExecutorBlock:  InsertingSequencerBlock,
	WaitingForExecutorSig:    GeneratingExecutorBlock,
}

type SigRequestsForBlock struct {
	RequestedBlockNumber uint64
	RequestedAmount      uint64
}

// Co2 is a consensus engine that combines the eth1 consensus and proof-of-stake
// algorithm. There is a special flag inside to decide whether to use legacy consensus
// rules or new rules. The transition rule is described in the eth1/2 merge spec.
// https://github.com/ethereum/EIPs/blob/master/EIPS/eip-3675.md
//
// The beacon here is a half-functional consensus engine with partial functions which
// is only used for necessary consensus checks. The legacy consensus engine can be any
// engine implements the consensus interface (except the beacon itself).
type Co2 struct {
	config *params.Co2Config // Consensus engine configuration parameters
	db     ethdb.Database    // Database to store and retrieve snapshot checkpoints

	signer common.Address // Ethereum address of the signing key
	signFn SignerFn       // Signer function to authorize hashes with
	lock   sync.RWMutex   // Protects the signer and proposals fields

	sequencerBlockCh          chan *types.Block
	executorSigCh             chan *types.ExecutorSigDetails
	sealInterruptCh           chan *types.SealInterruptMsg
	SodaRole                  SodaRoleType
	SodaSequencerAddress      common.Address
	authorizedSignersSet      map[common.Address]int
	broadcastExecutorSig      func(*types.ExecutorSigDetails)
	requestExecutorSig        func(uint64)
	getBlock                  func(uint64) *types.Block
	getMPCStatus              func() *types.MPCStatus
	requestSequencerBlockFunc func(uint64)
	triggerSyncFunc           func()
	transcript                types.Transcript
	// This field is used to store the latest sequencer header, which will be hashed
	// and stored in the extra-data field of the finalized executor block.
	latestSequencerHeader    *types.Header
	latestExecutorSig        *types.ExecutorSigDetails
	latestBlockTimestamp     blockTimestamp
	latestBlockTimestampLock sync.RWMutex
	executorSigWaitInterval  time.Duration
	etherbase                common.Address
	// We save the latest chain header in cases of a chain rewind.
	// This header will be used for new block insertion checks.
	latestChainHeader *types.Header

	syncing                   atomic.Bool // The indicator whether the node is still syncing.
	ShouldRejectDuplicateHash bool
	executorBlockTimestamp    uint64
	archivalMode              bool
	fullSyncMode              bool

	executionState      ExecutionState
	executionStateLock  sync.RWMutex
	sigRequestsForBlock SigRequestsForBlock
	sigRequestsLock     sync.RWMutex
	RequestSigThreshold uint8

	emissions *params.EmissionsConfig // configuration for coin emissions
}

func validateNonEmptyEmissionsConfig(emissions *params.EmissionsConfig) error {
	errors := make([]string, 0)
	if emissions.MintingInterval == 0 {
		errors = append(errors, "minting interval is empty/zero")
	}
	if emissions.InitialSupply == 0 {
		errors = append(errors, "initial supply is empty/zero")
	}
	if emissions.CoinMintingStartTime == 0 {
		errors = append(errors, "coin minting start time is empty/zero")
	}
	if emissions.FoundationAccount == (common.Address{}) {
		errors = append(errors, "foundation account is empty")
	}
	if emissions.SecondsInMintingEpoch == 0 {
		errors = append(errors, "seconds in minting epoch is empty/zero")
	}
	if emissions.BaseInflation == "" {
		errors = append(errors, "base inflation is empty/zero")
	}
	if emissions.DiminishingRate == "" {
		errors = append(errors, "diminishing rate is empty/zero")
	}

	if len(errors) > 0 {
		return fmt.Errorf("emissions config validation failed: %s", errors)
	}

	return nil
}

// This function is used to keep track of signature requests made to the peer Executor for the latest block.
// The updated field co2.sigRequestsForBlock is used by handler_eth to determine if a threshold of signature
// requests has been made for a single block.
func (co2 *Co2) RegisterSigRequest(blockNum uint64) uint64 {
	co2.sigRequestsLock.Lock()
	defer co2.sigRequestsLock.Unlock()
	if co2.sigRequestsForBlock.RequestedBlockNumber != blockNum {
		co2.sigRequestsForBlock = SigRequestsForBlock{
			RequestedBlockNumber: blockNum,
			RequestedAmount:      0,
		}
	}
	co2.sigRequestsForBlock.RequestedAmount++
	return co2.sigRequestsForBlock.RequestedAmount
}

func (co2 *Co2) SetFullSyncMode(fullSyncMode bool) {
	if !fullSyncMode {
		panic("Snap sync mode is not supported")
	}
	co2.fullSyncMode = fullSyncMode
}

func (co2 *Co2) IsFullSyncMode() bool {
	return co2.fullSyncMode
}

func (co2 *Co2) SetArchivalMode(archivalMode bool) {
	co2.archivalMode = archivalMode
}

func (co2 *Co2) IsArchival() bool {
	return co2.archivalMode
}

func (co2 *Co2) SetExecutorBlockTimestamp(timestamp uint64) {
	co2.executorBlockTimestamp = timestamp
}

func (co2 *Co2) SetLatestChainHeader(header *types.Header) {
	co2.latestChainHeader = header
}

func (co2 *Co2) GetLatestChainHeader() *types.Header {
	return co2.latestChainHeader
}

func (co2 *Co2) GetSelfSigOrder() (int, error) {
	if !co2.IsExecutor() {
		return -1, errors.New("only executors can get their own signature order")
	}
	return co2.authorizedSignersSet[co2.etherbase], nil
}

func updateBuffer(addresses []common.Address) []byte {
	var buf bytes.Buffer
	for _, addr := range addresses {
		buf.Write(addr.Bytes())
	}
	return buf.Bytes()
}

// New creates a consensus engine with the given embedded eth1 engine.
func New(config *params.Co2Config, db ethdb.Database, exec1Addr,
	exec2Addr, seqAddr common.Address, role SodaRoleType) *Co2 {
	// This will change in the future to a method that parses multiple addresses
	signerSet := make(map[common.Address]int)
	// Executor signature order matters for validaton, we compare their addresses
	// and assign the signature order based on this comparison.
	first, second := common.Address{}, common.Address{}
	if bytes.Compare(exec1Addr[:], exec2Addr[:]) > 0 {
		signerSet[exec1Addr] = 1
		signerSet[exec2Addr] = 0
		first, second = exec2Addr, exec1Addr
	} else {
		signerSet[exec1Addr] = 0
		signerSet[exec2Addr] = 1
		first, second = exec1Addr, exec2Addr
	}

	var etherbase common.Address
	if role == Sequencer {
		etherbase = seqAddr
	}
	if role == Executor {
		etherbase = exec1Addr
	}

	updateBytes := updateBuffer([]common.Address{first, second, seqAddr})

	initSES(updateBytes)
	if config.Emissions != nil {
		if err := validateNonEmptyEmissionsConfig(config.Emissions); err != nil {
			panic(err)
		}
	}

	return &Co2{
		config:                    config,
		db:                        db,
		sequencerBlockCh:          make(chan *types.Block, 2),
		executorSigCh:             make(chan *types.ExecutorSigDetails, 2),
		sealInterruptCh:           make(chan *types.SealInterruptMsg, 2),
		SodaRole:                  role,
		SodaSequencerAddress:      seqAddr,
		authorizedSignersSet:      signerSet,
		transcript:                nil,
		executorSigWaitInterval:   1500 * time.Millisecond,
		etherbase:                 etherbase,
		ShouldRejectDuplicateHash: true,
		executionState:            WaitingForSequencerBlock,
		RequestSigThreshold:       10, // TODO: make this a parameter
		latestBlockTimestamp:      blockTimestamp{number: common.Big0, timestamp: 0},
		emissions:                 config.Emissions,
	}
}

func initSES(update []byte) {
	log.Info("Initializing SES")
	if len(update) >= math.MaxInt32 {
		panic("update buffer too large")
	}
	ret := C.InitSES((*C.uchar)(&update[0]), C.int(len(update)))
	if ret.err != nil {
		errString := C.GoString(ret.err)
		C.free(unsafe.Pointer(ret.err))
		panic("failed to initialize SES")
	}
}

func (co2 *Co2) GetExecutionState() ExecutionState {
	co2.executionStateLock.RLock()
	defer co2.executionStateLock.RUnlock()
	return co2.executionState
}

func (co2 *Co2) NextExecutionStep(state ExecutionState) (bool, ExecutionState) {
	co2.executionStateLock.Lock()
	defer co2.executionStateLock.Unlock()
	prevState := co2.executionState
	co2.executionState = state
	if expectedPrevState, ok := previousExecutionStates[state]; ok && prevState == expectedPrevState {
		return true, prevState
	}
	return false, prevState
}

func (co2 *Co2) ApplyInsertBlockConfiguration(block *types.Block, cfg *vm.Config) {
	// Call the function that determines if the header is signed by the sequencer.
	isSeqHeader := co2.IsHeaderSignedBySequencer(block.Header())

	// Marshal the block into RLP.
	blockRLP, err := rlp.EncodeToBytes(block)
	if err != nil {
		panic(fmt.Errorf("failed to marshal block: %v", err))
	}
	if len(blockRLP) == 0 {
		panic(fmt.Errorf("failed to marshal block: empty RLP"))
	}

	// Call the shared library function.
	retCFG := C.ApplyInsertBlockConfiguration(
		(*C.uchar)(unsafe.Pointer(&blockRLP[0])),
		C.int(len(blockRLP)),
		C.bool(isSeqHeader),
	)
	if retCFG.err != nil {
		errStr := C.GoString(retCFG.err)
		C.free(unsafe.Pointer(retCFG.err))
		panic(fmt.Errorf("failed to apply insert block configuration: %v", errStr))
	}

	newCFGBytes := C.GoBytes(retCFG.data, retCFG.len)
	C.free(unsafe.Pointer(retCFG.data))

	var updatedCfg *shared.SlimConfig
	if err := rlp.DecodeBytes(newCFGBytes, &updatedCfg); err != nil {
		panic(fmt.Errorf("failed to unmarshal config: %v", err))
	}

	// (Usually updatedCfg and cfg point to the same underlying object.)
	cfg.ExecType = updatedCfg.ExecType
	cfg.Transcript = updatedCfg.Transcript
	cfg.Header = updatedCfg.Header
}

func (co2 *Co2) SetSigWaitInterval(intervalInMilliseconds int) {
	co2.executorSigWaitInterval = time.Duration(intervalInMilliseconds) * time.Millisecond
}

func (co2 *Co2) SyncEnded() {
	log.Info("Sync ended, Setting syncing to false")
	co2.SetSyncing(false)
}

func (co2 *Co2) SetSyncing(syncing bool) {
	co2.syncing.Store(syncing)
}

func (co2 *Co2) SyncInProgress() bool {
	return co2.syncing.Load()
}

// We create a hash for the sequencer block's header in a way which
// includes it's signature, and then we add it to the extra data field
// in our current (black) block's header in the appropriate position.
func (co2 *Co2) addSequencerBlockHashToExtra(extra []byte) ([]byte, error) {
	hash := co2.completeHeaderHash(co2.latestSequencerHeader)
	return InsertIntoExtraData(shared.SequencerBlockHash, hash.Bytes(), extra)
}

func (co2 *Co2) completeHeaderHash(header *types.Header) common.Hash {
	var hash common.Hash
	hasher := sha3.NewLegacyKeccak256()
	encodeSigHeader(hasher, header, true)
	hasher.(crypto.KeccakState).Read(hash[:])
	return hash
}

func (co2 *Co2) resetLatestSequencerHeader() {
	co2.latestSequencerHeader = nil
}

func (co2 *Co2) RegisterGetLatestBlockFunc(fn func(uint64) *types.Block) {
	co2.getBlock = fn
}

func (co2 *Co2) RegisterGetMPCStatusFunc(fn func() *types.MPCStatus) {
	co2.getMPCStatus = fn
}

func (co2 *Co2) RegisterTriggerSyncFunc(fn func()) {
	co2.triggerSyncFunc = fn
}

func (co2 *Co2) addTranscriptHashToExtra(extra []byte) ([]byte, error) {
	hash := co2.transcript.Hash()
	return InsertIntoExtraData(shared.TranscriptHash, hash.Bytes(), extra)
}

func (co2 *Co2) ResetTranscript() {
	co2.transcript = make(types.Transcript, 0)
}

func (co2 *Co2) GetTranscript() types.Transcript {
	return co2.transcript
}

func (co2 *Co2) SetTranscript(transcript types.Transcript) {
	co2.transcript = transcript
}

func (co2 *Co2) AddExecutionOutputToTranscript(output [][]byte) error {
	log.Debug("Adding output to Transcript!", "output", output)
	if !co2.IsExecutor() {
		return errSequencerTranscriptMutationAttempt
	}
	if co2.transcript == nil {
		return errTranscriptUninitialized
	}
	co2.transcript = append(co2.transcript, output...)
	return nil
}

func (co2 *Co2) AddMPCStatusToTranscript(status *types.MPCStatus) error {
	// We encode the MPCStatus struct and add it to the transcript
	statusBytes, err := status.Encode()
	if err != nil {
		return err
	}
	cell := make([][]byte, 1)
	cell[0] = statusBytes

	return co2.AddExecutionOutputToTranscript(cell)
}

func (co2 *Co2) ValidateBlockForInsertion(block *types.Block, prevHeader *types.Header,
	getBlock func(hash common.Hash, number uint64) *types.Block) error {

	if b := getBlock(prevHeader.Hash(), prevHeader.Number.Uint64()); b == nil && !co2.SyncInProgress() {
		// The block doesn't exist in the database, we return an error.
		log.Error("Block doesn't exist in the database", "hash", prevHeader.Hash(), "number", prevHeader.Number.Uint64())
		return errUnknownBlock // This error should raise an alert since we got a bad block.
	}

	blockRLP, err := rlp.EncodeToBytes(block)
	if err != nil {
		log.Error("error encoding block to rlp", "error", err)
		return err
	}
	headerRLP, err := rlp.EncodeToBytes(prevHeader)
	if err != nil {
		log.Error("error encoding header to rlp", "error", err)
		return err
	}

	ret := C.ValidateBlockForInsertion((*C.uchar)(&blockRLP[0]), C.int(len(blockRLP)),
		(*C.uchar)(&headerRLP[0]), C.int(len(headerRLP)),
		C.int(shared.SodaRoleFromString(string(co2.SodaRole))))

	if ret.err != nil {
		if ret.len == 1 && co2.SyncInProgress() {
			C.free(unsafe.Pointer(ret.err))
			return nil
		}
		errStr := C.GoString(ret.err)
		C.free(unsafe.Pointer(ret.err))
		log.Error("error block for insertion", "error", errStr)
		return errors.New(errStr)
	}
	goRes := C.GoBytes(ret.data, ret.len)
	C.free(unsafe.Pointer(ret.data))
	if ret.len == 1 && goRes[0] == 2 && co2.SyncInProgress() {
		// This return value is used to indicate that we are working on the same block we are accepting, this could happen
		// for a number of reasons. The best choice is to stop working on the block and just accept it from our peers (it
		// has already been validated).
		co2.sealInterruptCh <- &types.SealInterruptMsg{BlockNum: block.NumberU64(), SealHash: SealHash(block.Header())}
	}

	return nil
}

// Change in next PR
func (co2 *Co2) ShouldSequencerAddBlock(header *types.Header, ethbase common.Address) bool {
	// the 0th block is the genesis block, which is always accepted
	if header.Number.Cmp(big.NewInt(0)) == 0 {
		return true
	}
	return !co2.IsHeaderSignedBySequencer(header)
}

func (co2 *Co2) IsSequencer() bool {
	return co2.SodaRole == Sequencer
}

func (co2 *Co2) IsExecutor() bool {
	return co2.SodaRole == Executor
}

func (co2 *Co2) IsValidator() bool {
	return co2.SodaRole == Validator
}

func (co2 *Co2) IsSequencerAddress(addr common.Address) bool {
	return addr.Cmp(co2.SodaSequencerAddress) == 0
}

func (co2 *Co2) GetSequencerBlockChannel() chan *types.Block {
	return co2.sequencerBlockCh
}

func (co2 *Co2) GetExecutorSigChannel() chan *types.ExecutorSigDetails {
	return co2.executorSigCh
}

func (co2 *Co2) GetSealInterruptChannel() chan *types.SealInterruptMsg {
	return co2.sealInterruptCh
}

func (co2 *Co2) GetBlockType(block *types.Block) (*SodaRoleType, error) {
	log.Debug("Getting block type", "blockNum", block.NumberU64())
	if block == nil {
		log.Error("block is nil")
		return nil, errors.New("block is nil")
	}
	header := block.Header()

	// Marshal the block header into a byte slice.
	headerRLP, err := rlp.EncodeToBytes(header)
	if err != nil {
		return nil, err
	}

	retType := C.GetBlockType((*C.uchar)(&headerRLP[0]), C.int(len(headerRLP)))
	if retType.err != nil {
		errStr := C.GoString(retType.err)
		C.free(unsafe.Pointer(retType.err))
		log.Error("error getting block type", "error", errStr)
		return nil, errors.New(errStr)
	}

	typeBytes := C.GoBytes(retType.data, retType.len)
	C.free(unsafe.Pointer(retType.data))

	if len(typeBytes) != 1 {
		log.Error("unexpected return length")
		return nil, errors.New("unexpected return length")
	}
	if typeBytes[0] == byte(shared.Executor) {
		ret := Executor
		return &ret, nil
	}
	if typeBytes[0] == byte(shared.Sequencer) {
		ret := Sequencer
		return &ret, nil
	}
	log.Error("unexpected return value")
	return nil, errors.New("unexpected return value")

}

// Author implements consensus.Engine, returning the Ethereum address recovered
// from the signature in the header's extra-data section.
func (co2 *Co2) Author(header *types.Header) (common.Address, error) {
	return ecrecover(header)
}

// ecrecover extracts the Ethereum account address from a signed header.
func ecrecover(header *types.Header) (common.Address, error) {
	// Retrieve the signature from the header extra-data
	if len(header.Extra) < shared.ExtraSeal {
		return common.Address{}, errMissingSignature
	}
	lastSeal, err := RetrieveFromExtraData(shared.Signature2, header.Extra)
	if err != nil {
		return common.Address{}, err
	}
	return addressFromSignature(SealHash(header).Bytes(), lastSeal)
}

func addressFromSignature(hash, signature []byte) (common.Address, error) {
	if len(signature) != crypto.SignatureLength {
		return common.Address{}, fmt.Errorf("invalid signature length: %d", len(signature))
	}
	pubkey, err := crypto.Ecrecover(hash, signature)
	if err != nil {
		return common.Address{}, err
	}
	var signer common.Address
	copy(signer[:], crypto.Keccak256(pubkey[1:])[12:])
	return signer, nil
}

func (co2 *Co2) IsHeaderSignedBySequencer(header *types.Header) bool {
	if header.Number.Uint64() == 0 {
		return true
	}
	signer, err := co2.Author(header)
	if err != nil {
		log.Error(fmt.Sprintf("failed to get block signer: %s", err.Error()))
		return false
	}
	return co2.IsSequencerAddress(signer)
}

func (co2 *Co2) VerifyExecutorSigners(header *types.Header) error {
	// The extra data field should not diverge from the expected length in any way
	// or the signatures extracted from it will be invalid (or there will be a panic
	// if the field is too short).
	if len(header.Extra) != shared.ExtraDataLength {
		log.Error("extra data length mismatch", "length", len(header.Extra), "expected", shared.ExtraDataLength, "extraData", header.Extra)
		return errMalformedExtraData
	}

	sealHash := co2.SealHash(header).Bytes()
	// Verify each signature against the authorized signers set
	lastSignerNum := -1
	for i := shared.NumExecutors - 1; i >= 0; i-- {
		// get the signature from the header extra-data
		signature := header.Extra[len(header.Extra)-shared.ExtraSeal*(i+1) : len(header.Extra)-shared.ExtraSeal*i]
		// recover the public key and the Ethereum address

		num, err := co2.verifyExecutorSigner(sealHash, signature)
		if err != nil {
			return err
		}
		if num <= lastSignerNum {
			return errUnorderedExecutorSignatures
		}
		lastSignerNum = num
	}

	return nil
}

// This function also returns the signer's number in the authorized signers set.
// The signer's number is used to determine the order of the signatures in the extra-data.
func (co2 *Co2) verifyExecutorSigner(sealHash, signature []byte) (int, error) {
	pubkey, err := crypto.Ecrecover(sealHash, signature)
	if err != nil {
		return -1, err
	}
	var signer common.Address
	copy(signer[:], crypto.Keccak256(pubkey[1:])[12:])
	num, ok := co2.authorizedSignersSet[signer]
	if !ok {
		return -1, errUnauthorizedSigner
	}
	return num, nil
}

func (co2 *Co2) VerifyHeader(chain consensus.ChainHeaderReader, header *types.Header) error {
	if !co2.IsHeaderSignedBySequencer(header) {
		if err := co2.VerifyExecutorSigners(header); err != nil {
			return err
		}
	}
	if header.Number == nil {
		return errUnknownBlock
	}
	number := header.Number.Uint64()

	// Don't waste time checking blocks from the future
	if header.Time > uint64(time.Now().Unix()) {
		return consensus.ErrFutureBlock
	}
	// Nonces must be 0x00..0 or 0xff..f, zeroes enforced on checkpoints
	if !bytes.Equal(header.Nonce[:], nonceAuthVote) && !bytes.Equal(header.Nonce[:], nonceDropVote) {
		return errInvalidVote
	}
	// Check that the extra-data contains all the required fields
	if len(header.Extra) != shared.ExtraDataLength {
		log.Error("extra data length mismatch", "length", len(header.Extra), "expected", shared.ExtraDataLength, "extraData", header.Extra)
		return errMalformedExtraData
	}
	// Ensure that the mix digest is zero as we don't have fork protection currently
	if header.MixDigest != (common.Hash{}) {
		return errInvalidMixDigest
	}
	// Ensure that the block doesn't contain any uncles which are meaningless in PoA
	if header.UncleHash != uncleHash {
		return errInvalidUncleHash
	}
	// Ensure that the block's difficulty is meaningful (may not be correct at this point)
	if number > 0 {
		if header.Difficulty == nil ||
			(header.Difficulty.Cmp(difficultyExecutor) != 0 &&
				header.Difficulty.Cmp(difficultySequencer) != 0) {
			return errInvalidDifficulty
		}
	}
	// Verify that the gas limit is <= 2^63-1
	if header.GasLimit > params.MaxGasLimit {
		return fmt.Errorf("invalid gasLimit: have %v, max %v", header.GasLimit, params.MaxGasLimit)
	}
	if chain.Config().IsShanghai(header.Number, header.Time) {
		return errors.New("co2 does not support shanghai fork")
	}
	if chain.Config().IsCancun(header.Number, header.Time) {
		return errors.New("co2 does not support cancun fork")
	}
	// All basic checks passed, verify cascading fields
	return co2.verifyCascadingFields(chain, header, nil)
}

func (co2 *Co2) verifyCascadingFields(chain consensus.ChainHeaderReader,
	header *types.Header, parents []*types.Header) error {
	// The genesis block is the always valid dead-end
	number := header.Number.Uint64()
	if number == 0 {
		return nil
	}
	// Ensure that the block's timestamp isn't too close to its parent
	var parent *types.Header
	if len(parents) > 0 {
		parent = parents[len(parents)-1]
	} else {
		parent = chain.GetHeader(header.ParentHash, number-1)
	}
	if parent == nil || parent.Number.Uint64() != number-1 || parent.Hash() != header.ParentHash {
		return consensus.ErrUnknownAncestor
	}
	if parent.Time+co2.config.Period > header.Time {
		return errInvalidTimestamp
	}
	// Verify that the gasUsed is <= gasLimit
	if header.GasUsed > header.GasLimit {
		return fmt.Errorf("invalid gasUsed: have %d, gasLimit %d", header.GasUsed, header.GasLimit)
	}
	if !chain.Config().IsLondon(header.Number) {
		// Verify BaseFee not present before EIP-1559 fork.
		if header.BaseFee != nil {
			return fmt.Errorf("invalid baseFee before fork: have %d, want <nil>", header.BaseFee)
		}

		if err := misc.VerifyGaslimit(parent.GasLimit, header.GasLimit); err != nil {
			return err

		}
	} else {
		if err := eip1559.VerifyEIP1559Header(chain.Config(), parent, header); err != nil {
			// Verify the header's EIP-1559 attributes.
			return err
		}
	}
	return nil
}

// VerifyHeaders is similar to VerifyHeader, but verifies a batch of headers
// concurrently. The method returns a quit channel to abort the operations and
// a results channel to retrieve the async verifications.
// VerifyHeaders expect the headers to be ordered and continuous.
// VerifyHeaders is similar to VerifyHeader, but verifies a batch of headers. The
// method returns a quit channel to abort the operations and a results channel to
// retrieve the async verifications (the order is that of the input slice).
func (co2 *Co2) VerifyHeaders(chain consensus.ChainHeaderReader,
	headers []*types.Header) (chan<- struct{}, <-chan error) {
	abort := make(chan struct{})
	results := make(chan error, len(headers))

	go func() {
		for i, header := range headers {
			err := co2.verifyHeader(chain, header, headers[:i])

			select {
			case <-abort:
				return
			case results <- err:
			}
		}
	}()
	return abort, results
}

// verifyHeader checks whether a header conforms to the consensus rules.The
// caller may optionally pass in a batch of parents (ascending order) to avoid
// looking those up from the database. This is useful for concurrently verifying
// a batch of new headers.
func (co2 *Co2) verifyHeader(chain consensus.ChainHeaderReader,
	header *types.Header, parents []*types.Header) error {
	if !co2.IsHeaderSignedBySequencer(header) {
		if err := co2.VerifyExecutorSigners(header); err != nil {
			return err
		}
	}
	if header.Number == nil {
		return errUnknownBlock
	}
	number := header.Number.Uint64()

	// Don't waste time checking blocks from the future
	if header.Time > uint64(time.Now().Unix()) {
		return consensus.ErrFutureBlock
	}
	// Check that the extra-data contains all the required fields
	if len(header.Extra) != shared.ExtraDataLength {
		log.Error("extra data length mismatch", "length", len(header.Extra), "expected", shared.ExtraDataLength, "extraData", header.Extra)
		return errMalformedExtraData
	}
	// Ensure that the mix digest is zero as we don't have fork protection currently
	if header.MixDigest != (common.Hash{}) {
		return errInvalidMixDigest
	}
	// Ensure that the block doesn't contain any uncles which are meaningless in PoA
	if header.UncleHash != uncleHash {
		return errInvalidUncleHash
	}
	// Ensure that the block's difficulty is meaningful (may not be correct at this point)
	if number > 0 {
		if header.Difficulty == nil ||
			(header.Difficulty.Cmp(difficultyExecutor) != 0 &&
				header.Difficulty.Cmp(difficultySequencer) != 0) {
			return errInvalidDifficulty
		}
	}
	// Verify that the gas limit is <= 2^63-1
	if header.GasLimit > params.MaxGasLimit {
		return fmt.Errorf("invalid gasLimit: have %v, max %v", header.GasLimit, params.MaxGasLimit)
	}
	if chain.Config().IsShanghai(header.Number, header.Time) {
		return errors.New("co2 does not support shanghai fork")
	}
	if chain.Config().IsCancun(header.Number, header.Time) {
		return errors.New("co2 does not support cancun fork")
	}
	// All basic checks passed, verify cascading fields
	return co2.verifyCascadingFields(chain, header, parents)
}

// VerifyUncles implements consensus.Engine, always returning an error for any
// uncles as this consensus mechanism doesn't permit uncles.
func (co2 *Co2) VerifyUncles(chain consensus.ChainReader, block *types.Block) error {
	if len(block.Uncles()) > 0 {
		return errors.New("uncles not allowed")
	}
	return nil
}

func (co2 *Co2) SetSequencerBlockHeader(seqHeader *types.Header) {
	co2.latestSequencerHeader = types.CopyHeader(seqHeader)
}

// Prepare implements consensus.Engine, preparing all the consensus fields of the
// header for running the transactions on top.
func (co2 *Co2) Prepare(chain consensus.ChainHeaderReader, header *types.Header) error {
	co2.ResetTranscript()

	header.Coinbase = common.Address{}
	header.Nonce = types.BlockNonce{}

	number := header.Number.Uint64()

	// Set the correct difficulty
	header.Difficulty = co2.calcDifficulty()

	// Ensure the extra data has all its components
	header.Extra = make([]byte, shared.ExtraDataLength)

	// Mix digest is reserved for now, set to empty
	header.MixDigest = common.Hash{}

	parent := chain.GetHeader(header.ParentHash, number-1)
	if parent == nil {
		return consensus.ErrUnknownAncestor
	}
	// Ensure the timestamp has the correct delay
	if co2.IsSequencer() {
		co2.latestBlockTimestampLock.Lock()
		defer co2.latestBlockTimestampLock.Unlock()
		if co2.latestBlockTimestamp.number.Cmp(header.Number) == 0 {
			header.Time = co2.latestBlockTimestamp.timestamp
		} else {
			header.Time = uint64(time.Now().Unix()) + co2.config.Period
			co2.latestBlockTimestamp.number = header.Number
			co2.latestBlockTimestamp.timestamp = header.Time
		}
		// now := uint64(time.Now().Unix())
		// header.Time = co2.executorBlockTimestamp + co2.config.Period
		// if header.Time < now {
		// 	header.Time = now
		// }
	}
	return nil
}

// Finalize implements consensus.Engine. It remains empty since it isn't part of the Co2 consensus.
func (co2 *Co2) Finalize(chain consensus.ChainHeaderReader,
	header *types.Header, stateDB *state.StateDB, _ []*types.Transaction,
	_ []*types.Header, _ []*types.Withdrawal) {
	if co2.shouldMintTokens(header) {
		totalCoinsToMint, err := co2.totalCoinsToMint(header, chain)
		if err != nil {
			log.Error("failed to mint tokens", "error", err)
			return
		}
		co2.mintCoins(stateDB, totalCoinsToMint)
	} else {
		log.Debug("Minting Skipped", "block number", header.Number,
			"time", header.Time)
	}
}

func (co2 *Co2) shouldMintTokens(header *types.Header) bool {
	return (co2.emissions != nil &&
		header.Number.Uint64()%co2.emissions.MintingInterval == 0 &&
		header.Time >= co2.emissions.CoinMintingStartTime)
}

// The last minted time is the time of the block in which coins were last minted.
// lastMintTime will return the initial minting time in case no coins have been minted yet.
func (co2 *Co2) lastMintTime(header *types.Header, chain consensus.ChainHeaderReader) (uint64, error) {
	// we know that 'shouldMintTokens' is true, so we don't have to worry about underflow
	expectedPrevMintedBlockNumber := header.Number.Uint64() - co2.emissions.MintingInterval
	if expectedPrevMintedBlockNumber == 0 {
		// we are minting for the first time, use the initial minting time
		return co2.emissions.CoinMintingStartTime, nil
	}
	prevMintedHeader := chain.GetHeaderByNumber(expectedPrevMintedBlockNumber)
	if prevMintedHeader == nil {
		log.Error("failed to get previous minted block header")
		return 0, errors.New("failed to get previous minted block header")
	}
	if prevMintedHeader.Time <= co2.emissions.CoinMintingStartTime {
		return co2.emissions.CoinMintingStartTime, nil
	}
	return prevMintedHeader.Time, nil
}

// totalCoinsToMint calculates the total amount of coins to mint for the current epoch and any
// previous epochs in which we have not minted all coins yet.
func (co2 *Co2) totalCoinsToMint(header *types.Header, chain consensus.ChainHeaderReader) (*big.Int, error) {
	lastMintedTime, err := co2.lastMintTime(header, chain)
	if err != nil {
		return nil, err
	}

	lastMintEpochNumber := co2.epochNumberForTimestamp(lastMintedTime)
	lastEpochTotalCoins, err := co2.coinsToMintForEpoch(lastMintEpochNumber)
	if err != nil {
		log.Error("failed to get last epoch total coins", "error", err)
		return nil, err
	}
	currentEpochNumber := co2.epochNumberForTimestamp(header.Time)

	log.Debug("Minting Coins", "last minted time", lastMintedTime, "last minted epoch", lastMintEpochNumber,
		"last epoch total coins", lastEpochTotalCoins, "current epoch", currentEpochNumber)

	decimalSecondsInMintingEpoch := decimal.NewFromBigInt(new(big.Int).SetUint64(co2.emissions.SecondsInMintingEpoch), 0)
	if lastMintEpochNumber == currentEpochNumber {
		// We are in the same epoch, we can mine the relative amount of coins for this epoch at the same rate
		decimalTime := decimal.NewFromBigInt(new(big.Int).SetUint64(header.Time-lastMintedTime), 0)
		amountToMint := decimalTime.Div(decimalSecondsInMintingEpoch).Mul(lastEpochTotalCoins)
		amountToMintRounded := amountToMint.Round(0)
		return DecimalETHToWEI(amountToMintRounded), nil
	}

	// We have not been minting coins for at least a part of an epoch:
	// First calculate when the last minting epoch has ended
	prevEpochEnd := co2.emissions.CoinMintingStartTime + co2.emissions.SecondsInMintingEpoch*lastMintEpochNumber

	// Next add the remaining coins for the last epoch in which we minted coins
	decimalTime := decimal.NewFromBigInt(new(big.Int).SetUint64(prevEpochEnd-lastMintedTime), 0)
	amountToMint := decimalTime.Div(decimalSecondsInMintingEpoch).Mul(lastEpochTotalCoins)

	log.Debug("Initial Amount to mint for last UNCOMPLETED epoch", "amount", amountToMint)

	// Now add the coins for any epoch in between (the relative amount of coins is diminishing with each epoch)
	for epoch := lastMintEpochNumber + 1; epoch < currentEpochNumber; epoch++ {
		epochTotalCoins, err := co2.coinsToMintForEpoch(epoch)
		if err != nil {
			log.Error("failed to get epoch total coins", "epoch", epoch, "error", err)
			return nil, err
		}
		amountToMint = amountToMint.Add(epochTotalCoins)
	}
	// Finally, add the relative coins for the current epoch
	currentEpochTotalCoins, err := co2.coinsToMintForEpoch(currentEpochNumber)
	if err != nil {
		log.Error("failed to get current epoch total coins", "error", err)
		return nil, err
	}
	newEpochStart := co2.emissions.CoinMintingStartTime + (currentEpochNumber-1)*co2.emissions.SecondsInMintingEpoch
	decimalTime = decimal.NewFromBigInt(new(big.Int).SetUint64(header.Time-newEpochStart), 0)
	newestEpochPartialAmount := decimalTime.Div(decimalSecondsInMintingEpoch).Mul(currentEpochTotalCoins)
	amountToMint = amountToMint.Add(newestEpochPartialAmount)
	amountToMintRounded := amountToMint.Round(0)
	return DecimalETHToWEI(amountToMintRounded), nil
}

func (co2 *Co2) mintCoins(stateDB *state.StateDB, AmountInWei *big.Int) {
	// Conjure up some coins and give them to the foundation
	prevBalance := stateDB.GetBalance(co2.emissions.FoundationAccount)
	stateDB.AddBalance(co2.emissions.FoundationAccount, AmountInWei)
	currentBalance := stateDB.GetBalance(co2.emissions.FoundationAccount)
	log.Info("Minted coins", "amount in Wei", AmountInWei,
		"prev balance", prevBalance, "current balance", currentBalance)
}

func DecimalETHToWEI(eth decimal.Decimal) *big.Int {
	return new(big.Int).Mul(eth.BigInt(), big.NewInt(int64(math.Pow10(18))))
}

// coinsToMintForEpoch calculates the total amount of coins to mint for a given epoch.
// The amount of coins to mint is calculated by multiplying the total amount of tokens
// by the inflation rate for the given epoch.
// The inflation rate is calculated by multiplying the base inflation rate by the diminishing rate
// for each epoch.
// This means that for each epoch we have less inflation and thus less coins to mint.
// We make the calculation by iterating over all epochs up to the given epoch number
// because there is no closed form solution for the sum of a geometric series.
func (co2 *Co2) coinsToMintForEpoch(epochNumber uint64) (decimal.Decimal, error) {
	var lastEpochMintedTokens decimal.Decimal

	totalTokens := decimal.NewFromBigInt(new(big.Int).SetUint64(co2.emissions.InitialSupply), 0)
	inflationRate, err := decimal.NewFromString(co2.emissions.BaseInflation)
	if err != nil {
		log.Error("Error creating inflationRate decimal: %v", err)
		return decimal.NewFromInt(0), err
	}
	diminishingRate, err := decimal.NewFromString(co2.emissions.DiminishingRate)
	if err != nil {
		log.Error("Error creating DiminishingRate decimal: %v", err)
		return decimal.NewFromInt(0), err
	}
	for epoch := uint64(1); epoch <= epochNumber; epoch++ {
		mintedTokens := totalTokens.Mul(inflationRate).Round(0)
		lastEpochMintedTokens = mintedTokens
		totalTokens = totalTokens.Add(mintedTokens)
		inflationRate = inflationRate.Mul(diminishingRate)
	}
	return lastEpochMintedTokens, nil
}

// epochNumberForTimestamp calculates the epoch number for a given timestamp by
// checking how much time has passed since the start of minting and dividing it
// by the seconds in an epoch. We add 1 to the result because anywhere after the
// end of an epoch is considered the next epoch (we start at epoch 1).
func (co2 *Co2) epochNumberForTimestamp(timestamp uint64) uint64 {
	return (timestamp-co2.emissions.CoinMintingStartTime)/co2.emissions.SecondsInMintingEpoch + 1
}

// finalize is a version of Finalize that is used internally by the Co2 consensus. It gets only
// the header as a parameter and can return an error if something goes wrong.
// finalize either resets the transcript (Sequencer) or adds the transcript hash to the extra data (Executor)
// It also adds the sequencer block hash (it's signature is included in the hash) to the extra data (Executor)
func (co2 *Co2) finalize(header *types.Header) error {
	if co2.IsSequencer() {
		co2.ResetTranscript()
	} else if co2.IsExecutor() {
		if err := co2.AddMPCStatusToTranscript(co2.getMPCStatus()); err != nil {
			return err
		}
		extra, err := co2.addTranscriptHashToExtra(header.Extra)
		if err != nil {
			return err
		}
		extra, err = co2.addSequencerBlockHashToExtra(extra)
		if err != nil {
			return err
		}
		header.Extra = extra
	}
	return nil
}

// FinalizeAndAssemble implements consensus.Engine, ensuring no uncles are set,
// nor block rewards given, and returns the final block.
func (co2 *Co2) FinalizeAndAssemble(chain consensus.ChainHeaderReader,
	header *types.Header, state *state.StateDB, txs []*types.Transaction,
	uncles []*types.Header, receipts []*types.Receipt,
	withdrawals []*types.Withdrawal) (*types.Block, error) {
	log.Debug("FinalizeAndAssemble", "number", header.Number.String())
	if len(withdrawals) > 0 {
		return nil, errors.New("co2 does not support withdrawals")
	}
	// Add any state changes before calculating the intermediate root
	co2.Finalize(chain, header, state, nil, nil, nil)

	// Assign the final state root to header.
	header.Root = state.IntermediateRoot(chain.Config().IsEIP158(header.Number))
	if co2.IsExecutor() && co2.latestSequencerHeader.Number.Cmp(header.Number) != 0 {
		co2.resetLatestSequencerHeader()
		log.Error("sequencer header number does not match executor block header number")
		return nil, errors.New("sequencer header number does not match executor block header number")
	}

	if err := co2.finalize(header); err != nil {
		log.Error("finalize failed", "err", err)
		return nil, err
	}

	// Assemble and return the final block for sealing.
	block := types.NewBlock(header, txs, nil, receipts, trie.NewStackTrie(nil), &co2.transcript)
	block.SetSequencerHeader(co2.latestSequencerHeader)
	co2.resetLatestSequencerHeader()
	return block, nil
}

// Authorize injects a private key into the consensus engine to mint new blocks
// with.
func (co2 *Co2) Authorize(signer common.Address, signFn SignerFn) {
	co2.lock.Lock()
	defer co2.lock.Unlock()

	if co2.signer != (common.Address{}) || co2.signFn != nil {
		return
	}

	co2.signer = signer
	co2.signFn = signFn
	if co2.IsSequencer() {
		co2.SodaSequencerAddress = signer
	}
}

func (co2 *Co2) GetSigner() common.Address {
	return co2.signer
}

// Seal implements consensus.Engine, attempting to create a sealed block using
// the local signing credentials.
// The consensus.ChainHeaderReader argument is overlooked as it is not used in the
// Co2 sealing process. In the original implementation, it was used to get the
// latest signers to determine who's turn it is to seal the block.
// In the Co2 implementation, The order is determined by the node's roles (in the future
// there might be additional rules).
func (co2 *Co2) Seal(_ consensus.ChainHeaderReader, block *types.Block,
	results chan<- *types.Block, stop <-chan struct{}) error {
	log.Debug("Got new block seal request.", "block number", block.Number().String())
	header := block.Header()

	// Sealing the genesis block is not supported
	number := header.Number.Uint64()
	if number == 0 {
		return errUnknownBlock
	}
	// For 0-period chains, refuse to seal empty blocks (no reward but would spin sealing)
	if co2.config.Period == 0 && len(block.Transactions()) == 0 {
		return errors.New("sealing paused while waiting for transactions")
	}
	// Don't hold the signer fields for the entire sealing procedure
	co2.lock.RLock()
	signer, signFn := co2.signer, co2.signFn
	co2.lock.RUnlock()

	// Sweet, the protocol permits us to sign the block, wait for our time
	delay := time.Unix(int64(header.Time), 0).Sub(time.Now()) // nolint: gosimple

	// Sign all the things!
	selfSig, err := signFn(accounts.Account{Address: signer}, accounts.MimetypeClique, SodaRLP(header))
	if err != nil {
		return err
	}

	orderedSignatures := [shared.NumExecutors][]byte{selfSig, selfSig}

	if co2.IsExecutor() {
		sealHash := co2.SealHash(header)
		sealHashBytes := sealHash.Bytes()
		sigDetails := &types.ExecutorSigDetails{
			Signature:     selfSig,
			SignatureHash: sealHashBytes,
			BlockNumber:   number,
		}
		// Send the sig to the peer executor
		co2.updateExecutorSigDetails(sigDetails)
		co2.broadcastExecutorSig(sigDetails)

		var peerSig []byte
		ticker := time.NewTicker(co2.executorSigWaitInterval)
		defer ticker.Stop()

		log.Debug("Waiting for peer executor signature (entering waitSig)", "block number", number)
		ok, prevState := co2.NextExecutionStep(WaitingForExecutorSig)
		if !ok {
			log.Warn("Skipped Execution Step", "current state", co2.GetExecutionState(), "previous state", prevState)
		}

	waitSig:
		for {
			select {
			case interrupt := <-co2.sealInterruptCh:
				if interrupt.BlockNum == number {
					log.Debug("Received interrupt for the current block", "block number", number)
					// We already have this block, no need to continue
					if interrupt.SealHash != sealHash {
						log.Warn("Executor have been working on a different block than the saved one",
							"block number", number, "saved seal hash", interrupt.SealHash, "current seal hash", sealHash)
					}
				}

				if interrupt.BlockNum > number {
					// We already have this block, no need to continue
					log.Warn("Executor have been working on an older block than the last saved one",
						"saved block number", interrupt.BlockNum, "current block number", number)
					return ErrBlockExists
				}

			case sigDetails := <-co2.executorSigCh:
				log.Debug("Received executor signature", "block number", sigDetails.BlockNumber)
				// We first check if there is a mismatch in the block number
				if sigDetails.BlockNumber > number {
					// We are behind the peer Executor, we should sync
					log.Warn("Peer Executor is ahead of us, we should sync", "peer block number", number)
					co2.triggerSyncFunc()
					return ErrOutOfSync
				}
				if sigDetails.BlockNumber < number {
					// The peer Executor is behind us, we wait for it to sync
					log.Warn("Peer Executor is behind us, waiting for it to sync")
					ticker.Reset(co2.executorSigWaitInterval)

				}
				peerSig = sigDetails.Signature
				log.Info("Received peer executor signature", "block number", number)
				if len(peerSig) > 0 {
					if _, err := co2.verifyExecutorSigner(sealHashBytes, peerSig); err != nil {
						log.Error("Executor sig mismatch", "block num in msg", header.Number.String(), "err", err)
					} else {
						log.Debug("Executor sig verified", "block num in msg", header.Number.String())
						break waitSig
					}
				}
			case <-ticker.C:
				log.Debug("Interval for receiving peer executor signature passed, requesting it",
					"block number", number)
				co2.requestExecutorSig(number)
			}
		}

		// no need to check the error since this was just checked in the verification function
		peerExecAddr, _ := signerAddress(sealHashBytes, peerSig)

		// We compare both signer addresses and order the signatures according
		// to their respective address lexicographical order
		if bytes.Compare(co2.signer[:], peerExecAddr[:]) > 0 {
			orderedSignatures[0] = peerSig
		} else {
			orderedSignatures[1] = peerSig
		}
	}

	extra, err := InsertIntoExtraData(shared.Signature1, orderedSignatures[0], header.Extra)
	if err != nil {
		return err
	}
	extra, err = InsertIntoExtraData(shared.Signature2, orderedSignatures[1], extra)
	if err != nil {
		return err
	}
	header.Extra = extra

	// Wait until sealing is terminated or delay timeout.
	log.Trace("Waiting for slot to sign and propagate", "delay", common.PrettyDuration(delay))

	go func() {
		select {
		case <-stop:
			log.Warn("Sealing interrupted", "block number", number, "hash", header.Hash())
			return
		case <-time.After(delay):
			log.Debug("Sealing block (after delay)", "delay", delay, "block number", number, "hash", header.Hash())
		}

		select {
		case results <- block.WithSeal(header):
			log.Debug("Sealing result sent on result channel", "blocks in channel", len(results))
		default:
			log.Warn("Sealing result is not read by miner", "sealhash", co2.SealHash(header))
		}
	}()

	return nil
}

// Retrieves the latest executor signature from the consensus engine.
// This function is meant to be called when a peer Executor is waiting too long
// for the signature of the current block.
//
// If the Executor has the signature (meaning it has signed the block, but somehow the
// peer Executor did not receive the signature), the function will return the signature.
//
// If the Executor has not signed the block yet, but is currently processing the Sequencer's block,
// the function will return nil and the peer Executor would get the signature as soon as the
// Executor signs the block.
//
// If the peer Executor is ahead of the executor buy exactly 1 block (meaning the peer Executor
// had already received a Sequencer block and the Executor didn't) the function will return an error
// that would trigger the peer Executor to request the latest block from the Executor.
//
// If the peer Executor is ahead of the executor by more than 1 block, the function will return an error
// since this means the Executor is probably in the middle of a sync.
//
// If the peer Executor is behind the Executor, the function will return an error since the peer Executor
// should have requested the block and not the signature (it has already signed it).
func (co2 *Co2) GetExecutorSig(blockNum uint64) (*types.ExecutorSigDetails, error) {
	if !co2.IsExecutor() || co2.latestExecutorSig == nil {
		log.Error("Executor signature is not available")
		return nil, ErrExecutorSigUnavailable
	}
	if blockNum < co2.latestExecutorSig.BlockNumber-1 {
		// This should not happen since the requestor should have that block already
		log.Error("Requested signature for a block that is too far behind the latest executor sig block number")
		return nil, ErrSigRequestedForCanonicalBlock
	}
	if blockNum == co2.latestExecutorSig.BlockNumber+1 {
		// We are missing the sequencer block for the requested block number.
		log.Error("Requested signature for a block that is ahead of the latest executor sig block number")
		return nil, ErrMissingSequencerBlock
	}
	if blockNum == co2.latestExecutorSig.BlockNumber {
		// We have the signature for the requested block number
		log.Debug("Requested signature for the latest executor sig block number")
		return co2.latestExecutorSig, nil
	}
	if blockNum == co2.latestExecutorSig.BlockNumber-1 {
		// The Peer Executor is behind the Executor by exactly 1 block
		log.Error("Requested signature for a block that is one block behind the latest executor sig block number")
		return nil, ErrSigRequestedForPreviousBlock
	}

	// We might be in the middle of a sync, if not, we should be.
	log.Warn("Requested signature's block advanced beyond the latest executor sig block number",
		"requested block number", blockNum, "latest block number", co2.latestExecutorSig.BlockNumber)

	// SODO: check if we are indeed syncing
	return nil, ErrOutOfSync

}

// APIs implements consensus.Engine, returning the user facing RPC API to allow
// controlling the signer voting.
func (co2 *Co2) APIs(chain consensus.ChainHeaderReader) []rpc.API {
	return []rpc.API{{
		Namespace: "clique",
		Service:   &API{chain: chain, co2: co2},
	}}
}

func (co2 *Co2) ExtraSealLength() int {
	return ExtraSealLength()
}

// SealHash returns the hash of a block prior to it being sealed.
func (co2 *Co2) SealHash(header *types.Header) common.Hash {
	return SealHash(header)
}

// We just return the difficulty by the soda role
func (co2 *Co2) CalcDifficulty(chain consensus.ChainHeaderReader, time uint64, parent *types.Header) *big.Int {
	return co2.calcDifficulty()
}

func (co2 *Co2) RegisterSigBroadcastFunc(fn func(*types.ExecutorSigDetails)) error {
	if !co2.IsExecutor() {
		return errors.New("only executors can register the sig broadcast func")
	}
	co2.broadcastExecutorSig = fn

	return nil
}

func (co2 *Co2) RegisterSigRequestFunc(fn func(uint64)) error {
	if !co2.IsExecutor() {
		return errors.New("only executors can register the sig request func")
	}
	co2.requestExecutorSig = fn

	return nil
}

func (co2 *Co2) RegisterRequestSequencerBlockFunc(fn func(uint64)) error {
	if !co2.IsExecutor() {
		return errors.New("only executors can register the sequencer block request func")
	}
	co2.requestSequencerBlockFunc = fn

	return nil
}

func (co2 *Co2) RequestSequencerBlock(blockNum uint64) {
	co2.requestSequencerBlockFunc(blockNum)
}

func (co2 *Co2) RestartBlockWork(number uint64) {
	log.Debug("Restarting block work", "block number", number)
	block := co2.getBlock(number)
	if block == nil {
		log.Error("Sequencer block not found (the chain will not advance)", "block number", number)
		return
	}
	if co2.IsHeaderSignedBySequencer(block.Header()) {
		co2.ShouldRejectDuplicateHash = false
		log.Debug("RestartBlockWork sending block on the trigger channel",
			"block number", number,
			"block hash", block.Hash(),
			"blocks in the channel", len(co2.GetSequencerBlockChannel()))
		co2.GetSequencerBlockChannel() <- block
		log.Debug("RestartBlockWork sent block on the trigger channel",
			"blocks in the channel", len(co2.GetSequencerBlockChannel()))
	} else {
		log.Error("The head was not signed by the sequencer! (the chain will not advance)")
	}
}

// Close implements consensus.Engine. It's a noop as there are no background threads.
func (co2 *Co2) Close() error {
	return nil
}

func (co2 *Co2) updateExecutorSigDetails(sigDetails *types.ExecutorSigDetails) {
	co2.latestExecutorSig = sigDetails
}

func signerAddress(sealHash []byte, signature []byte) (common.Address, error) {
	pubkey, err := crypto.Ecrecover(sealHash[:], signature)
	if err != nil {
		return common.Address{}, err
	}
	var signer common.Address
	copy(signer[:], crypto.Keccak256(pubkey[1:])[12:])
	return signer, nil
}

func (co2 *Co2) calcDifficulty() *big.Int {
	return GetDifficulty(co2.SodaRole)
}

func SodaRLP(header *types.Header) []byte {
	b := new(bytes.Buffer)
	encodeSigHeader(b, header, false)
	return b.Bytes()
}

func SealHash(header *types.Header) (hash common.Hash) {
	hasher := sha3.NewLegacyKeccak256()
	encodeSigHeader(hasher, header, false)
	hasher.(crypto.KeccakState).Read(hash[:])
	return hash
}

func FullSealHash(header *types.Header) (hash common.Hash) {
	hasher := sha3.NewLegacyKeccak256()
	encodeSigHeader(hasher, header, true)
	hasher.(crypto.KeccakState).Read(hash[:])
	return hash
}

func ExtraSealLength() int {
	return shared.ExtraSeal * shared.NumExecutors
}

func encodeSigHeader(w io.Writer, header *types.Header, includeExtraSeal bool) {
	enc := []interface{}{
		header.ParentHash,
		header.UncleHash,
		header.Coinbase,
		header.Root,
		header.TxHash,
		header.ReceiptHash,
		header.Bloom,
		header.Difficulty,
		header.Number,
		header.GasLimit,
		header.GasUsed,
		header.Time,
		header.MixDigest,
		header.Nonce,
	}
	if includeExtraSeal {
		enc = append(enc, header.Extra)
	} else {
		enc = append(enc, header.Extra[:len(header.Extra)-ExtraSealLength()]) // Yes, this will panic if extra is too short
	}

	if header.BaseFee != nil {
		enc = append(enc, header.BaseFee)
	}
	if header.WithdrawalsHash != nil {
		panic("unexpected withdrawal hash value in clique")
	}
	if err := rlp.Encode(w, enc); err != nil {
		panic("can't encode: " + err.Error())
	}
}

// This method is used for obtaining the different parts of the extra data field in a human readable way.
func RetrieveFromExtraData(part shared.ExtraDataPart, extra []byte) ([]byte, error) {
	cPart := C.CString(string(part))
	defer C.free(unsafe.Pointer(cPart))

	cExtra := C.CBytes(extra)
	defer C.free(cExtra)

	ret := C.RetrieveFromExtraData(cPart, (*C.uchar)(cExtra), C.int(len(extra)))
	if ret.err != nil {
		errStr := C.GoString(ret.err)
		C.free(unsafe.Pointer(ret.err))
		return nil, errors.New(errStr)
	}
	goRes := C.GoBytes(ret.data, ret.len)
	C.free(ret.data)
	return goRes, nil
}

func InsertIntoExtraData(part shared.ExtraDataPart, data, extra []byte) ([]byte, error) {
	cPart := C.CString(string(part))
	defer C.free(unsafe.Pointer(cPart))

	cData := C.CBytes(data)
	defer C.free(cData)

	cExtra := C.CBytes(extra)
	defer C.free(cExtra)

	ret := C.InsertIntoExtraData(cPart, (*C.uchar)(cData), C.int(len(data)), (*C.uchar)(cExtra), C.int(len(extra)))
	if ret.err != nil {
		errStr := C.GoString(ret.err)
		C.free(unsafe.Pointer(ret.err))
		return nil, errors.New(errStr)
	}
	goRes := C.GoBytes(ret.data, ret.len)
	C.free(ret.data)
	return goRes, nil
}

func GetDifficulty(role SodaRoleType) *big.Int {
	log.Debug("Getting difficulty", "role", role)
	retDifficulty := C.CalcDifficulty(C.int(shared.SodaRoleFromString(string(role))))

	diffBytes := C.GoBytes(retDifficulty.data, retDifficulty.len)
	C.free(unsafe.Pointer(retDifficulty.data))

	return big.NewInt(0).SetBytes(diffBytes)
}

// API is a user facing RPC API to allow controlling the signer and voting
// mechanisms of the proof-of-authority scheme.
type API struct {
	chain consensus.ChainHeaderReader
	co2   *Co2
}

func (api *API) Name() string {
	return "CarbonDioxide"
}
