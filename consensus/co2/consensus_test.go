package co2

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"math/big"
	"reflect"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/secp256k1"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/shared"
	"github.com/ethereum/go-ethereum/trie"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/sha3"
)

const (
	period uint64 = 5
	epoch  uint64 = 30000
)

var (
	addr1Test      = common.Address{0x01}
	execOutputTest = [][]byte{{0x04, 0x05, 0x06}, {0x01, 0x02, 0x03}}
	signatureTest  = []byte{
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A,
		0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14,
		0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E,
		0x1F, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
		0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30, 0x31, 0x32,
		0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C,
		0x3D, 0x3E, 0x3F, 0x40, 0x41,
	}
	extraDataTest = make([]byte, shared.ExtraDataLength)
	headerTest    = &types.Header{
		ParentHash:  common.BytesToHash([]byte("ParentHash")),
		UncleHash:   common.BytesToHash([]byte("UncleHash")),
		Coinbase:    common.HexToAddress("Coinbase"),
		Root:        common.BytesToHash([]byte("Root")),
		TxHash:      common.BytesToHash([]byte("TxHash")),
		ReceiptHash: common.BytesToHash([]byte("ReceiptHash")),
		Bloom:       types.Bloom{},
		Difficulty:  difficultyExecutor,
		Number:      big.NewInt(5),
		GasLimit:    21000,
		GasUsed:     200,
		Time:        uint64(1234567890),
		Extra:       extraDataTest,
		MixDigest:   common.Hash{},
		Nonce:       types.EncodeNonce(1234567890),
		BaseFee:     big.NewInt(10),
	}
	passingGetBlock = func(hash common.Hash, number uint64) *types.Block {
		return blockWithHeader(headerTest, &types.Transcript{})
	}
	failingGetBlock = func(hash common.Hash, number uint64) *types.Block {
		return nil
	}
	mpcStatusTest = types.MPCStatus{
		OpcodesNames:        []string{"opcode1", "opcode2"},
		BatchIds:            []uint64{1, 2},
		CircuitsInsideBatch: []int64{3, 4},
	}
)

type testChainHeaderReader struct {
	getHeaderFunc func(hash common.Hash, number uint64) *types.Header
}

func (t *testChainHeaderReader) Config() *params.ChainConfig {
	return &params.ChainConfig{}
}

// CurrentHeader retrieves the current header from the local chain.
func (t *testChainHeaderReader) CurrentHeader() *types.Header {
	// unimplemented
	return nil
}

// GetHeader retrieves a block header from the database by hash and number.
func (t *testChainHeaderReader) GetHeader(hash common.Hash, number uint64) *types.Header {
	return t.getHeaderFunc(hash, number)
}

// GetHeaderByNumber retrieves a block header from the database by number.
func (t *testChainHeaderReader) GetHeaderByNumber(number uint64) *types.Header {
	// unimplemented
	return nil
}

// GetHeaderByHash retrieves a block header from the database by its hash.
func (t *testChainHeaderReader) GetHeaderByHash(hash common.Hash) *types.Header {
	// unimplemented
	return nil
}

// GetTd retrieves the total difficulty from the database by hash and number.
func (t *testChainHeaderReader) GetTd(hash common.Hash, number uint64) *big.Int {
	// unimplemented
	return nil
}

func Test_SetGetTranscript_Happy(t *testing.T) {
	// Arrange
	engine := co2Engine(Executor)
	expectedTransacript := types.Transcript{execOutputTest[0], execOutputTest[1]}
	expactedHash := expectedTransacript.Hash()

	// Act
	engine.SetTranscript(expectedTransacript)

	transcript := engine.GetTranscript()
	tHash := transcript.Hash()

	// Assert
	assert.Equal(t, expectedTransacript, transcript)
	assert.Equal(t, expactedHash, tHash)
}

func Test_ResetTranscript_Happy(t *testing.T) {
	// Arrange
	engine := co2Engine(Executor)
	engine.ResetTranscript()
	engine.SetTranscript(types.Transcript{execOutputTest[0], execOutputTest[1]})

	// Act
	engine.ResetTranscript()
	transcript := engine.GetTranscript()

	// Assert
	assert.Equal(t, types.Transcript{}, transcript)
}

func Test_addTranscriptHashToExtra_Happy(t *testing.T) {
	// Arrange
	engine := co2Engine(Executor)
	engine.ResetTranscript()
	expectedTransacript := types.Transcript{execOutputTest[0], execOutputTest[1]}
	expactedHash := expectedTransacript.Hash()

	// Act
	err := engine.AddExecutionOutputToTranscript(execOutputTest)
	require.NoError(t, err)

	transcript := engine.GetTranscript()
	tHash := transcript.Hash()

	// Assert
	assert.Equal(t, expectedTransacript, transcript)
	assert.Equal(t, expactedHash, tHash)
}

func Test_addTranscriptHashToExtra_FailTranscriptUninitialized(t *testing.T) {
	// Arrange (we do not reset the transcript)
	engine := co2Engine(Executor)

	// Act
	err := engine.AddExecutionOutputToTranscript(execOutputTest)

	// Assert
	assert.Error(t, err)
	assert.EqualError(t, err, errTranscriptUninitialized.Error())
}

func Test_addTranscriptHashToExtra_FailSequencerAttempt(t *testing.T) {
	// Arrange
	engine := co2Engine(Sequencer)
	engine.ResetTranscript()

	// Act
	err := engine.AddExecutionOutputToTranscript(execOutputTest)

	// Assert
	assert.Error(t, err)
	assert.EqualError(t, err, errSequencerTranscriptMutationAttempt.Error())
}

func Test_SodaRole_Sequencer(t *testing.T) {
	// Arrange
	engine := co2Engine(Sequencer)

	// Assert
	assert.True(t, engine.IsSequencer())
	assert.False(t, engine.IsExecutor())
}

func Test_SodaRole_Executor(t *testing.T) {
	// Arrange
	engine := co2Engine(Executor)

	// Assert
	assert.False(t, engine.IsSequencer())
	assert.True(t, engine.IsExecutor())
}

func Test_GetExecutorSigChannel_Happy(t *testing.T) {
	// Arrange
	engine := co2Engine(Executor)

	// Act
	sigChannel := engine.GetExecutorSigChannel()

	// Assert
	require.NotNil(t, sigChannel)
	// check the maximum capacity of the channel
	assert.Equal(t, cap(sigChannel), 2)
	assert.Equal(t, len(sigChannel), 0)
	sigDetails1 := types.ExecutorSigDetails{
		Signature: []byte{0x01}, SignatureHash: []byte{}, BlockNumber: 1}
	sigChannel <- &sigDetails1
	assert.Equal(t, len(sigChannel), 1)
	sigDetails2 := types.ExecutorSigDetails{
		Signature: []byte{0x02}, SignatureHash: []byte{}, BlockNumber: 1}
	sigChannel <- &sigDetails2
	assert.Equal(t, len(sigChannel), 2)
	firstResult := <-sigChannel
	assert.Equal(t, firstResult.Signature, []byte{0x01})
	secondResult := <-sigChannel
	assert.Equal(t, secondResult.Signature, []byte{0x02})
	assert.Equal(t, reflect.TypeOf(sigChannel).Kind(), reflect.Chan)
}

func Test_CalcDifficulty_Executor(t *testing.T) {
	// Arrange
	engine := co2Engine(Executor)

	// Act
	difficulty := engine.CalcDifficulty(nil, 0, nil)
	require.NotNil(t, difficulty)

	// Assert
	assert.True(t, difficulty.Cmp(difficultyExecutor) == 0)
}

func Test_CalcDifficulty_Sequencer(t *testing.T) {
	// Arrange
	engine := co2Engine(Sequencer)

	// Act
	difficulty := engine.CalcDifficulty(nil, 0, nil)
	require.NotNil(t, difficulty)

	// Assert
	assert.True(t, difficulty.Cmp(difficultySequencer) == 0)
}

// The Finalize method is used by the Co2 engine to insert the transcript hash
// We expect the transcript hash to be inserted in the header extra data after the vanity bytes
// and before the signature.
// In the sequencer's case, we expect the transcript hash to be all 0s.
func Test_Finalize_Sequencer_Happy(t *testing.T) {
	// Arrange
	transcript := types.Transcript{execOutputTest[0], execOutputTest[1]}
	hash := transcript.Hash()
	extraData := make([]byte, shared.ExtraVanityLength+common.HashLength)
	extraData = append(extraData, signatureTest[:]...)

	engine := co2Engine(Sequencer)
	header := &types.Header{
		Extra: extraData,
	}
	engine.SetTranscript(transcript)

	// Act
	err := engine.finalize(header)
	require.NoError(t, err)

	// Assert (make sure the transcript hash, in the sequencer's case all 0s is
	// embedded in the header extra data after the vanity bytes and before the signature)
	newExtraData := header.Extra
	assert.Equal(t, len(newExtraData), shared.ExtraVanityLength+common.HashLength+shared.ExtraSeal)
	assert.True(t, !reflect.DeepEqual(newExtraData[shared.ExtraVanityLength:shared.ExtraVanityLength+common.HashLength], hash.Bytes()))
	// make sure the transcript hash is all 0s
	assert.Equal(t, newExtraData[shared.ExtraVanityLength:shared.ExtraVanityLength+common.HashLength], common.Hash{}.Bytes())
}

// The Finalize method is used by the Co2 engine to insert the transcript hash
// We expect the transcript hash to be inserted in the header extra data after the vanity bytes
// and before the signature.
// In the Executor's case we expect it to be the transcript hash.
func Test_Finalize_Executor_Happy(t *testing.T) {
	// Arrange
	transcript := types.Transcript{execOutputTest[0], execOutputTest[1]}
	extraData := make([]byte, shared.ExtraDataLength)
	doubleSig := append(signatureTest, signatureTest...)
	extraData = append(extraData, doubleSig...)
	sequencerHeader := &types.Header{
		Extra: extraData,
	}
	engine := co2Engine(Executor)
	engine.RegisterGetMPCStatusFunc(func() *types.MPCStatus {
		return &mpcStatusTest
	})
	header := &types.Header{
		Number: big.NewInt(1), // Set a block number to avoid nil pointer dereference
		Extra:  make([]byte, shared.ExtraVanityLength+common.HashLength+common.HashLength+shared.ExtraSeal+shared.ExtraSeal),
	}

	expectedBlockHash := calcSeqBlockHashWithSignature(sequencerHeader)

	engine.SetTranscript(transcript)
	engine.SetSequencerBlockHeader(sequencerHeader)

	// Act
	err := engine.finalize(header)
	require.NoError(t, err)

	transcript = engine.GetTranscript()
	hash := transcript.Hash()

	// Assert
	newExtraData := header.Extra
	assert.Equal(t, len(newExtraData), shared.ExtraDataLength)
	assert.True(t, reflect.DeepEqual(newExtraData[shared.TranscriptHashStart:shared.TranscriptHashEnd], hash.Bytes()))
	assert.True(t, reflect.DeepEqual(newExtraData[shared.SequencerBlockHashStart:shared.SequencerBlockHashEnd], expectedBlockHash.Bytes()))
}

func Test_Authorize_Happy(t *testing.T) {
	// Arrange
	engine := co2Engine(Sequencer)
	authorizedAddr := common.Address{'A'}

	// Act
	engine.Authorize(authorizedAddr, nil)
	newSigner := engine.GetSigner()

	// Assert
	assert.Equal(t, authorizedAddr, newSigner)
}

func Test_HeaderFieldsIncludedInSealHash(t *testing.T) {
	// This test makes sure all fields in the header are included in the seal hash.
	// It does so by changing each field in the header individually and asserting the hash changes.
	type headerFieldsTest struct {
		name              string
		changeHeaderField func(header *types.Header) *types.Header
		expectFailure     bool
	}
	tests := []headerFieldsTest{
		{
			name:              "sanity",
			changeHeaderField: func(header *types.Header) *types.Header { return header },
			expectFailure:     false,
		},
		{
			name: "parent hash",
			changeHeaderField: func(header *types.Header) *types.Header {
				h := types.CopyHeader(header)
				h.ParentHash = common.BytesToHash([]byte("Parent0Hash"))
				return h
			},
			expectFailure: true,
		},
		{
			name: "uncle hash",
			changeHeaderField: func(header *types.Header) *types.Header {
				h := types.CopyHeader(header)
				h.UncleHash = common.BytesToHash([]byte("Uncle-Hash"))
				return h
			},
			expectFailure: true,
		},
		{
			name: "coinbase",
			changeHeaderField: func(header *types.Header) *types.Header {
				h := types.CopyHeader(header)
				h.Coinbase = common.HexToAddress("Coin-base")
				return h
			},
			expectFailure: true,
		},
		{
			name: "root",
			changeHeaderField: func(header *types.Header) *types.Header {
				h := types.CopyHeader(header)
				h.Root = common.BytesToHash([]byte("Root-"))
				return h
			},
			expectFailure: true,
		},
		{
			name: "tx hash",
			changeHeaderField: func(header *types.Header) *types.Header {
				h := types.CopyHeader(header)
				h.TxHash = common.BytesToHash([]byte("Tx-Hash"))
				return h
			},
			expectFailure: true,
		},
		{
			name: "receipt hash",
			changeHeaderField: func(header *types.Header) *types.Header {
				h := types.CopyHeader(header)
				h.ReceiptHash = common.BytesToHash([]byte("Receipt-Hash"))
				return h
			},
			expectFailure: true,
		},
		{
			name: "bloom",
			changeHeaderField: func(header *types.Header) *types.Header {
				h := types.CopyHeader(header)
				h.Bloom = types.Bloom{0x01, 0x02, 0x03}
				return h
			},
			expectFailure: true,
		},
		{
			name: "difficulty",
			changeHeaderField: func(header *types.Header) *types.Header {
				h := types.CopyHeader(header)
				h.Difficulty = big.NewInt(3)
				return h
			},
			expectFailure: true,
		},
		{
			name: "number",
			changeHeaderField: func(header *types.Header) *types.Header {
				h := types.CopyHeader(header)
				h.Number = big.NewInt(1)
				return h
			},
			expectFailure: true,
		},
		{
			name: "gas limit",
			changeHeaderField: func(header *types.Header) *types.Header {
				h := types.CopyHeader(header)
				h.GasLimit = 1
				return h
			},
			expectFailure: true,
		},
		{
			name: "gas used",
			changeHeaderField: func(header *types.Header) *types.Header {
				h := types.CopyHeader(header)
				h.GasUsed = 1
				return h
			},
			expectFailure: true,
		},
		{
			name: "time",
			changeHeaderField: func(header *types.Header) *types.Header {
				h := types.CopyHeader(header)
				h.Time = 1
				return h
			},
			expectFailure: true,
		},
		{
			name: "extra pass - extra seal ignored",
			changeHeaderField: func(header *types.Header) *types.Header {
				h := types.CopyHeader(header)
				h.Extra = make([]byte, shared.ExtraDataLength)
				h.Extra[len(h.Extra)-1] = 0x01
				return h
			},
			expectFailure: false,
		},
		{
			name: "extra fail - vanity changed",
			changeHeaderField: func(header *types.Header) *types.Header {
				h := types.CopyHeader(header)
				h.Extra = make([]byte, shared.ExtraDataLength)
				h.Extra[0] = 0x01
				h.Extra[shared.ExtraVanityLength-1] = 0x01
				return h
			},
			expectFailure: true,
		},
		{
			name: "extra fail - transcript hash changed",
			changeHeaderField: func(header *types.Header) *types.Header {
				h := types.CopyHeader(header)
				h.Extra = make([]byte, shared.ExtraDataLength)
				h.Extra[shared.ExtraVanityLength] = 0x01
				h.Extra[shared.ExtraVanityLength+common.HashLength-1] = 0x01
				return h
			},
			expectFailure: true,
		},
		{
			name: "mix digest",
			changeHeaderField: func(header *types.Header) *types.Header {
				h := types.CopyHeader(header)
				h.MixDigest = common.BytesToHash([]byte("Mix-Digest"))
				return h
			},
			expectFailure: true,
		},
		{
			name: "nonce",
			changeHeaderField: func(header *types.Header) *types.Header {
				h := types.CopyHeader(header)
				h.Nonce = types.EncodeNonce(1)
				return h
			},
			expectFailure: true,
		},
		{
			name: "base fee",
			changeHeaderField: func(header *types.Header) *types.Header {
				h := types.CopyHeader(header)
				h.BaseFee = big.NewInt(1)
				return h
			},
			expectFailure: true,
		},
	}
	// Arrange
	engine := co2Engine(Executor)
	h := types.CopyHeader(headerTest)
	originalHash := engine.SealHash(h)
	// Act & Assert
	for _, test := range tests {
		t.Run(test.name, func(tt *testing.T) {
			NewHeader := test.changeHeaderField(h)
			newHash := engine.SealHash(NewHeader)
			assert.Equal(tt, test.expectFailure, originalHash != newHash)
		})
	}
}

// The happy flow is the Executor having a BLACK block and receiving a RED from the Sequencer.
func Test_ShouldAcceptBlock_Executor_Happy(t *testing.T) {
	// Arrange:
	// create the Sequencer's account and both "Executor" accounts
	_, seqPrivKey, seqAddress := generateAccountParams()
	_, exec1PrivKey, exec1Address := generateAccountParams()
	_, exec2PrivKey, exec2Address := generateAccountParams()
	// Add the "Sequencer" account as the authorized signer
	executorEngine := New(&params.Co2Config{Period: 5},
		nil, exec1Address, exec2Address, seqAddress, Executor)
	// We first generate an Executor (BLACK) header as our previous Header and sign it.
	prevHeader := signedExecutorHeader(t, makeHeader(3, difficultyExecutor.Int64()), exec1PrivKey, exec2PrivKey)
	// We create a Sequencer (RED) block with a higher by 1 block number than the previous header
	// and sign it.
	currentHeader := signedSequencerHeader(t, makeHeader(prevHeader.Number.Int64()+1, difficultySequencer.Int64()), seqPrivKey)

	// Act
	err := executorEngine.ValidateBlockForInsertion(types.NewBlockWithHeader(currentHeader), prevHeader, passingGetBlock)

	// Assert
	assert.NoError(t, err)
}

func Test_ShouldAcceptBlock_Executor_Fail_WrongSigner(t *testing.T) {
	// Arrange:
	// create the Sequencer's account and both "Executor" accounts
	_, _, seqAddress := generateAccountParams()
	_, exec1PrivKey, exec1Address := generateAccountParams()
	_, exec2PrivKey, exec2Address := generateAccountParams()
	_, wrongSignerPrivKey, _ := generateAccountParams()
	// Add the "Sequencer" account as the authorized signer
	executorEngine := New(&params.Co2Config{Period: 5},
		nil, exec1Address, exec2Address, seqAddress, Executor)
	// We first generate an Executor (BLACK) header as our previous Header and sign it.
	prevHeader := signedExecutorHeader(t, makeHeader(3, difficultyExecutor.Int64()), exec1PrivKey, exec2PrivKey)
	// We create a Sequencer (RED) block with a higher by 1 block number than the previous header
	// and sign it with the WRONG private key -- this is the test's manipulation
	currentHeader := signedSequencerHeader(t, makeHeader(prevHeader.Number.Int64()+1, difficultySequencer.Int64()), wrongSignerPrivKey)

	// Act
	err := executorEngine.ValidateBlockForInsertion(types.NewBlockWithHeader(currentHeader), prevHeader, passingGetBlock)

	// Assert
	assert.Error(t, err)
	assert.EqualError(t, err, errUnauthorizedSigner.Error())
}

func Test_ShouldAcceptBlock_Executor_Fail_NoSigner(t *testing.T) {
	// Arrange:
	// create the Sequencer's account and both "Executor" accounts
	_, _, seqAddress := generateAccountParams()
	_, exec1PrivKey, exec1Address := generateAccountParams()
	_, exec2PrivKey, exec2Address := generateAccountParams()
	// Add the "Sequencer" account as the authorized signer
	executorEngine := New(&params.Co2Config{Period: 5},
		nil, exec1Address, exec2Address, seqAddress, Executor)
	// We first generate an Executor (BLACK) header as our previous Header and sign it.
	prevHeader := signedExecutorHeader(t, makeHeader(3, difficultyExecutor.Int64()), exec1PrivKey, exec2PrivKey)
	// We create a Sequencer (RED) block with a higher by 1 block number than the previous header
	// and DON'T SIGN IT -- this is the test's manipulation
	currentHeader := makeHeader(prevHeader.Number.Int64()+1, difficultySequencer.Int64())

	// Act
	err := executorEngine.ValidateBlockForInsertion(types.NewBlockWithHeader(currentHeader), prevHeader, passingGetBlock)

	// Assert
	assert.Error(t, err)
	assert.EqualError(t, err, secp256k1.ErrRecoverFailed.Error())
}

// The Sequencer will accept the block if the following conditions are met:
// 1. The block is signed by both Executors (exec1Addr and exec2Addr)
// 2. The previous block is not a Sequencer (RED) block with a lower height.
func Test_ValidateBlockForInsertion_Sequencer_Happy(t *testing.T) {
	// Arrange:
	// Create the previous header as a Sequencer (RED) block.
	prevHeader := makeHeader(3, difficultySequencer.Int64())
	// create the Sequencer's account and both "Executor" accounts
	_, seqPrivKey, seqAddress := generateAccountParams()
	_, exec1PrivKey, exec1Address := generateAccountParams()
	_, exec2PrivKey, exec2Address := generateAccountParams()
	// Add the "Executor" accounts as the authorized signers
	sequencerEngine := New(&params.Co2Config{Period: 5},
		nil, exec1Address, exec2Address, seqAddress, Sequencer)
	// Sign the sequencer's header with the sequencer's private key
	prevHeader = signedSequencerHeader(t, prevHeader, seqPrivKey)
	// generate the complete Sequencer's header's hash (which includes the signature)
	seqHeaderHash := sequencerEngine.completeHeaderHash(prevHeader)
	// Create the current header as an Executor (BLACK) block with the same
	// block height (number) as the previous header.
	currentHeader := makeHeader(prevHeader.Number.Int64(), difficultyExecutor.Int64())
	// Generate a full (valid) Executor block
	currentBlock := fullExecutorBlock(t, currentHeader, prevHeader, exec1PrivKey, exec2PrivKey,
		exec1Address, exec2Address, seqHeaderHash)

	// Act
	err := sequencerEngine.ValidateBlockForInsertion(currentBlock, prevHeader, passingGetBlock)

	// Assert
	assert.NoError(t, err)
}

func Test_ShouldAcceptBlock_Sequencer_Fail_WrongSigs(t *testing.T) {
	// Arrange:

	// Create the previous header as a Sequencer (RED) block.
	prevHeader := makeHeader(3, difficultySequencer.Int64())
	// Create the Sequencer's account and both "Executor" accounts
	_, seqPrivKey, seqAddress := generateAccountParams()
	_, exec1PrivKey, exec1Address := generateAccountParams()
	_, exec2PrivKey, exec2Address := generateAccountParams()
	// Create two "wrong" accounts (which will not be approved by the engine)
	_, wrongSignerPrivKey1, wrongSignerAddress1 := generateAccountParams()
	_, wrongSignerPrivKey2, wrongSignerAddress2 := generateAccountParams()
	// Add the "Executor" accounts as the authorized signers
	sequencerEngine := New(&params.Co2Config{Period: 5},
		nil, exec1Address, exec2Address, seqAddress, Sequencer)
	// Sign the sequencer's header with the sequencer's private key
	prevHeader = signedSequencerHeader(t, prevHeader, seqPrivKey)
	// Generate the complete sequencer header hash and insert it into the current block's extra data
	seqHeaderHash := sequencerEngine.completeHeaderHash(prevHeader)
	// Create the current header as an Executor (BLACK) block with the same
	// block height (number) as the previous header.
	currentHeader := makeHeader(prevHeader.Number.Int64(), difficultyExecutor.Int64())
	// We now create two blocks, each signed by one of the wrong signers but in different positions.
	// First signature is by the unauthorized account and the second by the authorized one -- This is
	// the test manipulation
	require.NotEqual(t, wrongSignerAddress1, exec1Address) // Make sure key pair was randomly selected
	currentBlock1 := fullExecutorBlock(t, currentHeader, prevHeader, wrongSignerPrivKey1, exec2PrivKey,
		wrongSignerAddress1, exec2Address, seqHeaderHash)
	// First signature is by the authorized account and the second by the unauthorized one
	require.NotEqual(t, wrongSignerAddress2, exec2Address) // Make sure key pair was randomly selected
	currentBlock2 := fullExecutorBlock(t, currentHeader, prevHeader, exec1PrivKey, wrongSignerPrivKey2,
		exec1Address, wrongSignerAddress2, seqHeaderHash)

	// Act
	err1 := sequencerEngine.ValidateBlockForInsertion(currentBlock1, prevHeader, passingGetBlock)
	err2 := sequencerEngine.ValidateBlockForInsertion(currentBlock2, prevHeader, passingGetBlock)

	// Assert
	assert.Error(t, err1)
	assert.Error(t, err2)
	assert.EqualError(t, err1, errUnauthorizedSigner.Error())
	assert.EqualError(t, err2, errUnauthorizedSigner.Error())
	assert.Equal(t, len(sequencerEngine.GetTranscript()), 0)
}

func Test_ValidateBlockForInsertion_Sequencer_Fail_SkippedExecutorBlock(t *testing.T) {
	// Arrange:

	// Create the previous header as a Sequencer (RED) block.
	prevHeader := makeHeader(3, difficultySequencer.Int64())
	// create the Sequencer's account and both "Executor" accounts
	_, seqPrivKey, seqAddress := generateAccountParams()
	_, exec1PrivKey, exec1Address := generateAccountParams()
	_, exec2PrivKey, exec2Address := generateAccountParams()
	// Add the "Executor" accounts as the authorized signers
	sequencerEngine := New(&params.Co2Config{Period: 5},
		nil, exec1Address, exec2Address, seqAddress, Sequencer)
	// Sign the sequencer's header with the sequencer's private key
	prevHeader = signedSequencerHeader(t, prevHeader, seqPrivKey)
	// generate the complete Sequencer's header's hash (which includes the signature)
	seqHeaderHash := sequencerEngine.completeHeaderHash(prevHeader)
	// Create the current header as an Executor (BLACK) block with a block
	// height (number) *HIGHER* than the previous header -- This is the test manipulation
	currentBlockNum := big.NewInt(0).Add(prevHeader.Number, big.NewInt(1))
	currentHeader := makeHeader(currentBlockNum.Int64(), difficultyExecutor.Int64())
	// Generate a full (valid) Executor block
	currentBlock := fullExecutorBlock(t, currentHeader, prevHeader, exec1PrivKey, exec2PrivKey,
		exec1Address, exec2Address, seqHeaderHash)

	// Act
	err := sequencerEngine.ValidateBlockForInsertion(currentBlock, prevHeader, passingGetBlock)

	// Assert
	assert.Error(t, err)
	assert.EqualError(t, err, errSkipBlockAttempt.Error())
	assert.Equal(t, len(sequencerEngine.GetTranscript()), 0)
}

func Test_ValidateBlockForInsertion_Sequencer_Fail_UnorderedSignatures(t *testing.T) {
	// Arrange:

	// Create the previous header as a Sequencer (RED) block.
	prevHeader := makeHeader(3, difficultySequencer.Int64())
	// create the Sequencer's account and both "Executor" accounts
	_, seqPrivKey, seqAddress := generateAccountParams()
	_, exec1PrivKey, exec1Address := generateAccountParams()
	_, exec2PrivKey, exec2Address := generateAccountParams()
	// Add the "Executor" accounts as the authorized signers
	sequencerEngine := New(&params.Co2Config{Period: 5},
		nil, exec1Address, exec2Address, seqAddress, Sequencer)
	// Sign the sequencer's header with the sequencer's private key
	prevHeader = signedSequencerHeader(t, prevHeader, seqPrivKey)
	// generate the complete Sequencer's header's hash (which includes the signature)
	seqHeaderHash := sequencerEngine.completeHeaderHash(prevHeader)
	// Create the current header as an Executor (BLACK) block with a block
	// height (number) *HIGHER* than the previous header.
	currentBlockNum := big.NewInt(0).Add(prevHeader.Number, big.NewInt(1))
	currentHeader := makeHeader(currentBlockNum.Int64(), difficultyExecutor.Int64())
	// Generate a full (valid) Executor block
	currentBlock := fullExecutorBlock(t, currentHeader, prevHeader, exec1PrivKey, exec2PrivKey,
		exec1Address, exec2Address, seqHeaderHash)
	// We REVERSE the order the keys by their address -- This is the test manipulation
	reversedBlock := reverseExtraDataSeals(t, currentBlock)

	// Act
	err := sequencerEngine.ValidateBlockForInsertion(reversedBlock, prevHeader, passingGetBlock)

	// Assert
	assert.Error(t, err)
	assert.EqualError(t, err, "unordered or duplicate signers")
	assert.Equal(t, len(sequencerEngine.GetTranscript()), 0)
}

// Preparing the header should produce a header with some predetermined fields:
// 1. The header's Extra field should be initialized with 0s in the correct length (vanity +
// transcript hash + signature * number of executors).
// 2. The Executor header's time should not change (the Sequencer is the source of truth)
// All other fields should be reset (set to their type's null value).
func Test_Prepare_Happy_Executor(t *testing.T) {
	// Arrange
	// We first make sure the header has some initialized fields
	// otherwise we can't be sure the Prepare method resets them.
	header := types.CopyHeader(headerTest)
	engine := co2Engine(Executor)

	chainHeaderReader := &testChainHeaderReader{
		getHeaderFunc: func(hash common.Hash, number uint64) *types.Header {
			return &types.Header{}
		},
	}

	// Act
	err := engine.Prepare(chainHeaderReader, header)

	// Assert (all the fields below should be reset)
	assert.NoError(t, err)
	assert.Equal(t, header.Coinbase, common.Address{})
	assert.Equal(t, header.Nonce, types.BlockNonce{})
	assert.Equal(t, header.Difficulty, difficultyExecutor)
	assert.Equal(t, header.MixDigest, common.Hash{})
	assert.Equal(t, len(header.Extra), shared.ExtraDataLength)
	assert.Equal(t, header.Extra, make([]byte, shared.ExtraDataLength))
	assert.Equal(t, header.Time, header.Time)
}

func Test_Prepare_Fail_BadParentHash(t *testing.T) {
	// Arrange
	header := types.CopyHeader(headerTest)
	engine := co2Engine(Executor)

	chainHeaderReader := &testChainHeaderReader{
		getHeaderFunc: func(hash common.Hash, number uint64) *types.Header {
			return nil
		},
	}

	// Act
	err := engine.Prepare(chainHeaderReader, header)

	// Assert
	assert.Error(t, err)
	assert.EqualError(t, err, consensus.ErrUnknownAncestor.Error())
}

// Sealing a block in the Co2 engine has two pathways:
// A) The block is sealed by the Sequencer (referred to as a RED block)
// B) The block is sealed by an Executor (referred to as a BLACK block)
// In both cases the block is sealed by the same method (Seal) but the
// behavior is different:
//
// In case of a RED block - the process does not differ by much from the
// original Clique engine. The only difference is in the length of the Extra
// field: it is pre populated with the null value of the the common.Hash type
// and the signature of the Sequencer is inserted twice (or later more).
// This is done to preserve the length of the Extra field (which equals the
// length of the vanity bytes, the length of the hash and the length of the
// signature multiplied by the number of Executors).
//
// In case of a BLACK block - the process is a bit more complicated. The
// Extra field is pre populated with the transcript hash. One signature is
// obtained by the executor signing the header's hash. The second signature
// is obtained by the peer executor broadcasting it's signature to the other.
// This means that before sealing a block each Executor must first broadcast
// it's signature to the other Executor and wait for the peer's signature as
// well. Once both signatures are available they are ordered and added to the
// Extra field, resulting in both Executors having the EXACT SAME block.
func Test_Seal_Happy(t *testing.T) {
	// Arrange:
	// Make a new block to seal
	block, header := noDelayBlock(t, &types.Transcript{})

	// Generate the "peer Executor" account
	_, peerExecPrivKey, peerExecAddress := generateAccountParams()

	// Authorize the "peer Executor" account to sign
	executorEngine := New(&params.Co2Config{Period: period},
		nil, peerExecAddress, peerExecAddress, addr1Test, Executor)

	executorSigCh, broadcastExecSigCh, resultsCh := getSigChannels(executorEngine)

	peerSig := signAndBroadcast(t, header, peerExecPrivKey, executorSigCh)

	// Act:
	err := executorEngine.Seal(nil, block, resultsCh, make(<-chan struct{}))
	// We wait for the broadcasted testSignature
	sigDetails := <-broadcastExecSigCh
	// We wait for the sealed block
	resBlock := <-resultsCh
	resHeader := resBlock.Header()

	// We order the signatures by the lexicographical order of address of the
	// executor accounts.
	orderSignatures := [shared.NumExecutors][]byte{sigDetails.Signature, sigDetails.Signature}
	if bytes.Compare(addr1Test[:], peerExecAddress[:]) > 0 {
		orderSignatures[0] = peerSig
	} else {
		orderSignatures[1] = peerSig
	}

	// We expect the sealed block to have both signatures (lexicographically ordered) in it's
	// extra data field.
	expectedExtra := make([]byte, shared.ExtraDataLength)
	copy(expectedExtra[len(header.Extra)-(shared.ExtraSeal*shared.NumExecutors):], append(sigDetails.Signature, peerSig...))

	// Assert:
	assert.NoError(t, err)
	// The engine broadcasts the expected testSignature
	assert.Equal(t, sigDetails.Signature, signatureTest)
	assert.Equal(t, resHeader.Extra, expectedExtra)
}

func Test_Seal_Fail_BadSigner(t *testing.T) {
	// Arrange:
	// Make a new block to seal
	block, header := noDelayBlock(t, &types.Transcript{})

	// Generate the "peer Executor" account
	_, peerExecPrivKey, peerExecAddress := generateAccountParams()

	// Don't authorize the "peer Executor" account to sign
	executorEngine := New(&params.Co2Config{Period: period},
		nil, addr1Test, addr1Test, addr1Test, Executor)
	// We use an unauthorized account to sign
	require.NotEqual(t, addr1Test, peerExecAddress)

	requestExecutorCh := make(chan uint64, 1)

	executorEngine.SetSigWaitInterval(1)
	executorEngine.RegisterSigRequestFunc(func(u uint64) {
		requestExecutorCh <- u
	})

	executorSigCh, broadcastExecSigCh, resultsCh := getSigChannels(executorEngine)

	// We sign the header with the unauthorized account
	_ = signAndBroadcast(t, header, peerExecPrivKey, executorSigCh)

	// Act:
	go executorEngine.Seal(nil, block, resultsCh, make(<-chan struct{}))
	// We should still get a signature from the engine
	sigDetails := <-broadcastExecSigCh
	blockNum := <-requestExecutorCh

	// Assert:
	// The engine broadcasts the expected testSignature
	assert.Equal(t, sigDetails.Signature, signatureTest)
	assert.Equal(t, blockNum, block.NumberU64())
}

func Test_VerifyHeaders_Happy(t *testing.T) {
	// Arrange:
	_, _, sequencerAddress := generateAccountParams()
	_, executor1PrivKey, executor1Address := generateAccountParams()
	_, executor2PrivKey, executor2Address := generateAccountParams()

	// Sign all the headers with both executors (ordered by the lexicographical order of their addresses)
	key1, key2 := getOrderedKeys(executor1PrivKey, executor2PrivKey, executor1Address, executor2Address, false)
	numBlocks := 5
	headers := generateConsecutiveSignedHeaders(t, numBlocks, key1, key2, nil)
	chainHeaderReader := &testChainHeaderReader{
		getHeaderFunc: func(hash common.Hash, number uint64) *types.Header {
			// The engine uses this func to get the parent header in case the
			// header the first in the slice (no parents).
			return headers[0]
		},
	}

	// Create a sequencer with both executors as authorized signers
	sequencerEngine := New(&params.Co2Config{Period: period},
		nil, executor1Address, executor2Address, sequencerAddress, Sequencer)

	// Act:
	_, results := sequencerEngine.VerifyHeaders(chainHeaderReader, headers[1:])

	// Assert:
	// results (and errors) are returned in a channel, we wait for all results result
	for i := 0; i < numBlocks-1; i++ {
		res := <-results
		assert.NoError(t, res, fmt.Sprintf("Failed to verify header %d", i))
	}
}

func Test_VerifyHeaders_Fail_BadDifficulty(t *testing.T) {
	// Arrange:
	_, privkey1, addr1 := generateAccountParams()
	_, privkey2, addr2 := generateAccountParams()
	key1, key2 := getOrderedKeys(privkey1, privkey2, addr1, addr2, false)
	headers := generateConsecutiveSignedHeaders(t, 3, key1, key2,
		func(header *types.Header) *types.Header {
			// We change the difficulty to a different value than the expected one
			header.Difficulty = big.NewInt(3) // We only support 1 and 5 as a valid difficulty
			return header
		})

	chainHeaderReader := &testChainHeaderReader{
		getHeaderFunc: func(hash common.Hash, number uint64) *types.Header {
			// The engine uses this func to get the parent header in case the
			// header the first in the slice (no parents).
			return headers[0]
		},
	}

	sequencerEngine := New(&params.Co2Config{Period: period},
		nil, addr1, addr2, addr1Test, Sequencer)

	// Act:
	_, results := sequencerEngine.VerifyHeaders(chainHeaderReader, headers[1:])
	// results (and errors) are returned in a channel, we wait for the result
	res := <-results

	// Assert:
	// The method failed
	assert.Error(t, res)
	assert.EqualError(t, res, errInvalidDifficulty.Error())
}

// The complete flow of the Co2 engine is as follows:
//
//  1. The Sequencer creates a and seals RED block:
//     a) The block has no transcript (and the transcript hash in the
//     header's "Extra" field is set to all 0's ).
//     b) the block is signed by the Sequencer and the signature is
//     populated twice in the header's "Extra" field.
//     The block is broadcasted to the Executors.
//     c) The block's difficulty is set to 1.
//
//  2. The Sequencer broadcasts the block to the Executors:
//     a) The Sequencer changes it's state to BLACK (indicating it
//     will not create a new RED block, but rather wait for the
//     Executors to send a BLACK block).
//     b) The Executors accept the block and verify it's
//     signed by the Sequencer.
//
//  3. The Executors create a BLACK block with the same height and
//     and timestamp as the RED block it had just accepted:
//     a) The block has a transcript (and the transcript hash is
//     populated in the header's "Extra" field). The transcript
//     represents the result of an MPC computation between the two
//     Executors and is used to allow the Sequencer to generate a
//     state transition without having access to any of the secrets.
//
//  4. The Executors seal the block:
//     a) The header's hash (which includes the transcript's hash) is
//     signed by each of the Executors and the signature is
//     broadcasted to the other Executor.
//     b) The signatures are ordered by the lexicographical order of
//     the addresses of the Executors and populated in the header's
//     "Extra" field.
//     c) The block's difficulty is set to 5.
//     This step results in both Executors having the EXACT SAME block
//
//  5. The Executors broadcast the block to the Sequencer:
//     a) The Sequencer accepts the block and verifies it's signed by
//     both Executors.
//     b) after accepting the block the Sequencer resets the Transcript
//     and sets it's state to RED again, indicating it's ready to
//     create a new RED block.
//
// Please note that the above flow represents the complete flow only in
// regards to the Co2 engine (which is what we are testing here). Other
// components functionality, integral as it may be, is not explained here.
func Test_CompleteFlow_Happy(t *testing.T) {
	// Create 2 Executors and 1 Sequencer accounts
	_, sequencerPrivKey, sequencerAddress := generateAccountParams()
	_, executor1PrivKey, executor1Address := generateAccountParams()
	_, executor2PrivKey, executor2Address := generateAccountParams()

	// Create 2 Executors and 1 Sequencer engines
	sequencerEngine := New(&params.Co2Config{Period: period},
		nil, executor1Address, executor2Address, sequencerAddress, Sequencer)

	executor1Engine := New(&params.Co2Config{Period: period},
		nil, executor1Address, executor2Address, sequencerAddress, Executor)

	executor2Engine := New(&params.Co2Config{Period: period},
		nil, executor1Address, executor2Address, sequencerAddress, Executor)

	// Register the signer and the signer function for each engine
	sequencerEngine.Authorize(
		sequencerAddress,
		func(signer accounts.Account, mimeType string, message []byte) ([]byte, error) {
			return crypto.Sign(crypto.Keccak256(message), crypto.ToECDSAUnsafe(sequencerPrivKey))
		})
	executor1Engine.Authorize(
		executor1Address,
		func(signer accounts.Account, mimeType string, message []byte) ([]byte, error) {
			return crypto.Sign(crypto.Keccak256(message), crypto.ToECDSAUnsafe(executor1PrivKey))
		})
	executor2Engine.Authorize(
		executor2Address,
		func(signer accounts.Account, mimeType string, message []byte) ([]byte, error) {
			return crypto.Sign(crypto.Keccak256(message), crypto.ToECDSAUnsafe(executor2PrivKey))
		})

	executor1Engine.RegisterGetMPCStatusFunc(func() *types.MPCStatus {
		return &mpcStatusTest
	})
	executor2Engine.RegisterGetMPCStatusFunc(func() *types.MPCStatus {
		return &mpcStatusTest
	})

	key1, key2 := getOrderedKeys(executor1PrivKey, executor2PrivKey, executor1Address, executor2Address, false)
	// Generate 3 consecutive (liked by parent hashes) headers
	headers := generateConsecutiveHeadersWithGenesis(t, 2, key1, key2)
	// This is the header we're going to feed to the Prepare method
	// none of the important fields are initialized other than the
	// block number (2).
	redHeader := types.CopyHeader(headers[2])

	// We make sure the sequencer agrees to add a block (initialized to RED state)
	require.True(t, sequencerEngine.ShouldSequencerAddBlock(headers[0], sequencerAddress))

	chainHeaderReader := &testChainHeaderReader{
		getHeaderFunc: func(hash common.Hash, number uint64) *types.Header {
			// The engine uses this func to get the parent header in case the
			// header the first in the slice (no parents).
			return headers[1]
		},
	}
	err := sequencerEngine.Prepare(chainHeaderReader, redHeader)
	require.NoError(t, err)

	err = sequencerEngine.finalize(redHeader)
	require.NoError(t, err)

	// The RED block is finalized, the Transcript is reset
	require.Empty(t, sequencerEngine.GetTranscript())

	// We bypass the FinalizeAndAssemble method (which insists
	// on a stateDB with all the state transitions, which requires
	// the FinalizeAndAssemble method to generate so nothing will
	// be tested there), and create a block with the current header.
	redBlock := types.NewBlock(
		redHeader,
		[]*types.Transaction{},
		[]*types.Header{},
		[]*types.Receipt{},
		trie.NewStackTrie(nil),
		&sequencerEngine.transcript,
	)

	resChanSequencer := make(chan *types.Block, 1)
	err = sequencerEngine.Seal(nil, redBlock, resChanSequencer, make(<-chan struct{}))
	require.NoError(t, err)

	// We wait for the sealed block.
	blockToBroadcast := <-resChanSequencer

	// At this stage the block would have been broadcasted to the Executors.
	// We verify both Executors accept the block (they verify it's signed by the Sequencer)
	err = executor1Engine.ValidateBlockForInsertion(blockToBroadcast, headers[1], passingGetBlock)
	require.NoError(t, err)
	err = executor2Engine.ValidateBlockForInsertion(blockToBroadcast, headers[1], passingGetBlock)
	require.NoError(t, err)

	// At this point the block would have been passed from the chain to the worker by the
	// trigger channel. We simulate this by passing the block through it.
	triggerChan1 := executor1Engine.GetSequencerBlockChannel()
	go func() {
		triggerChan1 <- blockToBroadcast
	}()
	b1 := <-triggerChan1
	require.NotNil(t, b1)

	triggerChan2 := executor2Engine.GetSequencerBlockChannel()
	go func() {
		triggerChan2 <- blockToBroadcast
	}()
	b2 := <-triggerChan2
	require.NotNil(t, b2)

	// The Executors set the sequencer blocks's header so it can be later added to the block
	// and it's signature to the black block's header.Extra field.
	executor1Engine.SetSequencerBlockHeader(blockToBroadcast.Header())
	executor2Engine.SetSequencerBlockHeader(blockToBroadcast.Header())

	// At this stage a new block at the same height is created by the Executors.
	blackHeader1 := types.CopyHeader(headers[2])
	err = executor1Engine.Prepare(chainHeaderReader, blackHeader1)
	require.NoError(t, err)

	blackHeader2 := types.CopyHeader(headers[2])
	err = executor2Engine.Prepare(chainHeaderReader, blackHeader2)
	require.NoError(t, err)

	// We simulate some execution transcript to be added to the block.
	executor1Engine.SetTranscript(types.Transcript{execOutputTest[0], execOutputTest[1]})
	executor2Engine.SetTranscript(types.Transcript{execOutputTest[0], execOutputTest[1]})

	err = executor1Engine.finalize(blackHeader1)
	require.NoError(t, err)

	err = executor2Engine.finalize(blackHeader2)
	require.NoError(t, err)

	mpcStatus := &mpcStatusTest
	statusBytes, err := mpcStatus.Encode()
	require.NoError(t, err)
	cell := make([][]byte, 1)
	cell[0] = statusBytes

	// The BLACK block is finalized, the Transcript hash is added to the Extra field
	require.Equal(t, executor1Engine.GetTranscript(), types.Transcript{execOutputTest[0], execOutputTest[1], statusBytes})
	require.Equal(t, executor2Engine.GetTranscript(), types.Transcript{execOutputTest[0], execOutputTest[1], statusBytes})

	// Again we bypass FinalizeAndAssemble
	blackBlock1 := types.NewBlock(
		blackHeader1,
		[]*types.Transaction{},
		[]*types.Header{},
		[]*types.Receipt{},
		trie.NewStackTrie(nil),
		&executor1Engine.transcript,
	)
	// We set the Sequencer header
	blackBlock1.SetSequencerHeader(blockToBroadcast.Header())

	blackBlock2 := types.NewBlock(
		blackHeader2,
		[]*types.Transaction{},
		[]*types.Header{},
		[]*types.Receipt{},
		trie.NewStackTrie(nil),
		&executor2Engine.transcript,
	)
	// We set the Sequencer header
	blackBlock2.SetSequencerHeader(blockToBroadcast.Header())

	// We extract each Executor's sigChannel (the channel it listens to for the peer's signature).
	executorSigCh1 := executor1Engine.GetExecutorSigChannel()
	executorSigCh2 := executor2Engine.GetExecutorSigChannel()

	// And register a function that will broadcast the signature to the other Executor's sigChannel.
	executor1Engine.RegisterSigBroadcastFunc(func(sigDetails *types.ExecutorSigDetails) {
		go func() {
			executorSigCh2 <- sigDetails
		}()
	})
	executor2Engine.RegisterSigBroadcastFunc(func(sigDetails *types.ExecutorSigDetails) {
		go func() {
			executorSigCh1 <- sigDetails
		}()
	})

	// We set up the channels that the sealed blocks will be sent on.
	resChExecutor1 := make(chan *types.Block, 2)
	resChExecutor2 := make(chan *types.Block, 2)

	// We use go routines to seal both blocks in parallel, this is done to simulate the
	// scenario where both Executors seal a block at the same time and need to wait for
	// each other's signatures.
	go executor1Engine.Seal(nil, blackBlock1, resChExecutor1, make(<-chan struct{}))
	go executor2Engine.Seal(nil, blackBlock2, resChExecutor2, make(<-chan struct{}))

	// We wait for the sealed block.
	sealedBlock1 := <-resChExecutor1
	sealedBlock2 := <-resChExecutor2

	// We verify both blocks are completely identical.
	assert.Equal(t, sealedBlock1, sealedBlock2)

	// At this point, both BLACK blocks would have been sent to the Sequencer by the executors.
	// We verify the Sequencer accepts the block (it verifies it's signed by both Executors)
	err = sequencerEngine.ValidateBlockForInsertion(sealedBlock1, blockToBroadcast.Header(), passingGetBlock)
	require.NoError(t, err)
	// And with that we've made sure the sequencer would now be able to insert the block
	// as the head of it's canonical chain.
}

func Test_ResendExecutorSig_Happy(t *testing.T) {
	// Arrange:
	// Make a new block to seal
	block, header := noDelayBlock(t, &types.Transcript{})

	// Generate the "peer Executor" account
	_, peerExecPrivKey, peerExecAddress := generateAccountParams()

	// Authorize the "peer Executor" account to sign
	executorEngine := New(&params.Co2Config{Period: period},
		nil, peerExecAddress, peerExecAddress, addr1Test, Executor)

	executorSigCh, broadcastExecSigCh, resultsCh := getSigChannels(executorEngine)

	// We sign the header with the "peer Executor" account to unblock the Seal method
	signAndBroadcast(t, header, peerExecPrivKey, executorSigCh)

	// At this point the executor's signature details should not be populated yet
	require.Empty(t, executorEngine.latestExecutorSig)

	// Act:
	err := executorEngine.Seal(nil, block, resultsCh, make(<-chan struct{}))
	require.NoError(t, err)

	// We wait for the broadcasted signature
	expectedSigDetails := <-broadcastExecSigCh

	// The executor's signature details should now be populated
	require.NotEmpty(t, executorEngine.latestExecutorSig)

	// We first validate the signature details match the expected signature
	require.Equal(t, executorEngine.latestExecutorSig.Signature, expectedSigDetails.Signature)

	// Now let's get the signature
	sigDetails, err := executorEngine.GetExecutorSig(header.Number.Uint64())
	require.NoError(t, err)
	require.NotNil(t, sigDetails)

	// Assert:
	// The engine rebroadcasts the expected testSignature
	assert.Equal(t, sigDetails.Signature, expectedSigDetails.Signature)
}

func Test_ResendExecutorSig_Edge_Cases(t *testing.T) {
	const blockNumber = 1
	const blockOffset = 100
	type resendExecutorSigTest struct {
		name               string
		requestedBlockNum  uint64
		expectedError      error
		existingSigDetails *types.ExecutorSigDetails
		expectedSigDetails *types.ExecutorSigDetails
		manipulateEngine   func(*Co2)
	}
	tests := []resendExecutorSigTest{
		{
			// A request for a signature for a block that
			// is more advance than the last signed block
			// by exactly 1 means that the peer Executor
			// has already received the next Sequencer block
			// and is now sealing a new block.
			// The Executor has not yet received the
			// Sequencer's block for some reason and should
			// request it to continue.

			// We simulate this state by trying to get the
			// signature for the next block (implying that
			// a new Sequencer block has been delivered to
			// the requestor prior)
			name:              "Missing Sequencer Block",
			requestedBlockNum: blockNumber + 1,
			expectedError:     ErrMissingSequencerBlock,
			existingSigDetails: &types.ExecutorSigDetails{
				Signature:     signatureTest,
				SignatureHash: common.Hash{}.Bytes(),
				BlockNumber:   blockNumber,
			},
			expectedSigDetails: nil,
			manipulateEngine: func(engine *Co2) {
			},
		},
		{
			// A request for a signature resend for a block
			// that is more advanced than the last signed
			// block by more than 1 means that the Executor
			// is out of sync (since it has already signed
			// more advanced blocks) and should request the
			// missing blocks to continue (if it is not
			// doing so already).

			// We simulate this state by trying to get the
			// signature for a block (number 101) with an
			// offset of 100 from the last signed block
			// (number 1).
			name:              "Executor is out of sync",
			requestedBlockNum: blockNumber + blockOffset,
			expectedError:     ErrOutOfSync,
			existingSigDetails: &types.ExecutorSigDetails{
				Signature:     signatureTest,
				SignatureHash: common.Hash{}.Bytes(),
				BlockNumber:   blockNumber,
			},
			expectedSigDetails: nil,
			manipulateEngine: func(engine *Co2) {
			},
		},
		{
			// A request for a signature resend for a block
			// that is already canonical (meaning the other
			// network participants should already have it)
			// means that the peer Executor is out of sync
			// and should request the missing blocks in order
			// to continue

			// We simulate this state by trying to get the
			// signature for a block (number 1) with an offset
			// of 100 from the last signed block (number 101).
			name:              "Canonical block signature requested",
			requestedBlockNum: blockNumber,
			expectedError:     ErrSigRequestedForCanonicalBlock,
			existingSigDetails: &types.ExecutorSigDetails{
				Signature:     signatureTest,
				SignatureHash: common.Hash{}.Bytes(),
				BlockNumber:   blockNumber + blockOffset,
			},
			expectedSigDetails: nil,
			manipulateEngine: func(engine *Co2) {
			},
		},
		{
			// If the Executor has not yet signed any blocks
			// it should not be able to resend any signatures

			// We simulate this state by setting the Executor's
			// existingSigDetails property to nil
			name:               "No signature details",
			requestedBlockNum:  blockNumber,
			expectedError:      ErrExecutorSigUnavailable,
			existingSigDetails: nil,
			expectedSigDetails: nil,
			manipulateEngine: func(engine *Co2) {
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(tt *testing.T) {
			t.Log(test.name)
			// Arrange
			engine := co2Engine(Executor)
			if test.manipulateEngine != nil {
				test.manipulateEngine(engine)
			}
			engine.updateExecutorSigDetails(test.existingSigDetails)
			// Act
			requestedSigDetails, err := engine.GetExecutorSig(test.requestedBlockNum)
			// Assert
			if test.expectedError != nil {
				require.Error(tt, err)
				require.Nil(tt, requestedSigDetails)
				require.EqualError(tt, err, test.expectedError.Error())
			} else {
				require.NoError(tt, err)
				require.Equal(tt, test.expectedSigDetails, requestedSigDetails)
			}
		})
	}
}

func Test_ExecutorSigWaitInterval(t *testing.T) {
	// Arrange:
	block, header := noDelayBlock(t, &types.Transcript{})

	executorEngine := co2Engine(Executor)

	_, broadcastExecSigCh, resultsCh := getSigChannels(executorEngine)

	requestExecutorSigChannel := make(chan uint64)
	executorEngine.RegisterSigRequestFunc(func(blockNum uint64) {
		requestExecutorSigChannel <- blockNum
	})

	testInterval := 100

	executorEngine.SetSigWaitInterval(testInterval)

	startTime := time.Now()

	// Act:
	// We run the Seal method in a go routine so it doesn't block
	go func() {
		err := executorEngine.Seal(nil, block, resultsCh, make(<-chan struct{}))
		require.NoError(t, err)
	}()

	sigRequest := <-requestExecutorSigChannel
	elapsedTime := time.Since(startTime)
	sig := <-broadcastExecSigCh

	// Assert:
	assert.Equal(t, header.Number.Uint64(), sigRequest)
	assert.True(t, elapsedTime >= time.Duration(testInterval))
	assert.NotEmpty(t, sig)
}

func Test_AddMPCStatusToTranscript_Happy(t *testing.T) {
	// Arrange:
	// Create a new Co2 engine
	engine := co2Engine(Executor)
	// Add the test transcript to the engine
	engine.ResetTranscript()
	engine.AddExecutionOutputToTranscript(execOutputTest)
	// Act && Assert:
	err := engine.AddMPCStatusToTranscript(&mpcStatusTest)
	require.NoError(t, err)
	transcript := engine.GetTranscript()
	assert.Len(t, transcript, len(execOutputTest)+1)
	encodedMPCStatus := transcript[len(transcript)-1]
	mpcStatusDecoded, err := types.NewMPCStatusFromBytes(encodedMPCStatus)
	require.NoError(t, err)
	assert.Equal(t, &mpcStatusTest, mpcStatusDecoded)
}

func generateConsecutiveHeadersWithGenesis(t *testing.T, amount int, key1, key2 []byte) []*types.Header {
	genesisBlock := &types.Header{
		Number: big.NewInt(0),
	}
	return append([]*types.Header{genesisBlock}, generateConsecutiveSignedHeaders(t, amount, key1, key2, nil)...)

}

func generateConsecutiveSignedHeaders(t *testing.T, amount int, key1, key2 []byte,
	changeHeader func(*types.Header) *types.Header) []*types.Header {
	var headers []*types.Header
	var hash common.Hash
	for i := 1; i <= amount; i++ {
		header := headerWithTime(uint64(time.Now().Unix()) - period*uint64(amount-i))
		header.Number = big.NewInt(int64(i))        // no need for a genesis block
		header.UncleHash = types.CalcUncleHash(nil) // This is expected by the engine
		header.BaseFee = nil
		header.ParentHash = hash
		if changeHeader != nil {
			header = changeHeader(header)
		}
		header = signedExecutorHeader(t, header, key1, key2)
		hash = header.Hash()
		headers = append(headers, header)
	}
	return headers
}

func signAndBroadcast(t *testing.T, header *types.Header, privKey []byte, executorSigCh chan *types.ExecutorSigDetails) []byte {
	peerSig, sealHash := signHeader(t, header, privKey)
	// We send the "peer Executor" signature to the executorSigCh beforehand so
	// it won't block when we call Seal.
	sigDetails := &types.ExecutorSigDetails{
		Signature:     peerSig,
		SignatureHash: sealHash,
		BlockNumber:   header.Number.Uint64(),
	}
	executorSigCh <- sigDetails
	return peerSig
}

func headerWithTime(timeStamp uint64) *types.Header {
	header := types.CopyHeader(headerTest)
	header.Time = timeStamp
	return header
}

func noDelayBlock(t *testing.T, transcript *types.Transcript) (*types.Block, *types.Header) {
	header := headerWithTime(uint64(time.Now().Unix()))
	require.Equal(t, header.Extra, make([]byte, shared.ExtraDataLength))
	return blockWithHeader(header, &types.Transcript{}), header
}

func getSigChannels(engine *Co2) (chan *types.ExecutorSigDetails,
	chan *types.ExecutorSigDetails, chan *types.Block) {
	// Our sign function simply returns the testSignature
	engine.Authorize(addr1Test, func(signer accounts.Account, mimeType string, message []byte) ([]byte, error) {
		return signatureTest, nil
	})
	// The executorSigCh is used by the executor to receive the signature
	executorSigCh := engine.GetExecutorSigChannel()
	// The broadcastExecSigCh is used by the executor to broadcast the signature
	broadcastExecSigCh := make(chan *types.ExecutorSigDetails, 2)
	engine.RegisterSigBroadcastFunc(func(sigDetails *types.ExecutorSigDetails) {
		broadcastExecSigCh <- sigDetails
	})

	return executorSigCh, broadcastExecSigCh, make(chan *types.Block, 1)
}

func signHeader(t *testing.T, header *types.Header, privkey []byte) ([]byte, []byte) {
	// Generate the hash to sign
	sealHash := SealHash(header)
	// Sign the hash
	sig, err := secp256k1.Sign(sealHash[:], privkey)
	require.NoError(t, err)
	return sig, sealHash.Bytes()
}

func blockWithHeader(header *types.Header, transcript *types.Transcript) *types.Block {
	mockHeader := types.CopyHeader(headerTest)
	block := types.NewBlock(mockHeader, nil, nil, nil, nil, transcript)
	return block.WithSeal(header)

}

func generateKeyPair() (pubkey, privkey []byte) {
	key, err := ecdsa.GenerateKey(secp256k1.S256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	pubkey = elliptic.Marshal(secp256k1.S256(), key.X, key.Y)

	privkey = make([]byte, 32)
	blob := key.D.Bytes()
	copy(privkey[32-len(blob):], blob)

	return pubkey, privkey
}

func generateAccountParams() (pubkey, privkey []byte, address common.Address) {
	pubkey, privkey = generateKeyPair()
	pk, _ := crypto.UnmarshalPubkey(pubkey)
	address = crypto.PubkeyToAddress(*pk)
	return pubkey, privkey, address
}

// Please note this function does not order the signatures by the lexicographical order of the signer addresses
func signedExecutorHeader(t *testing.T, header *types.Header, privkey1 []byte, privkey2 []byte) *types.Header {
	sig1, _ := signHeader(t, header, privkey1)
	sig2, _ := signHeader(t, header, privkey2)
	header.Extra = populateExtraDataSigners(t, header.Extra, sig1, sig2)
	return header
}

func signedSequencerHeader(t *testing.T, header *types.Header, privkey []byte) *types.Header {
	sig, _ := signHeader(t, header, privkey)
	header.Extra = populateExtraDataSigners(t, header.Extra, sig, sig)
	return header
}

func populateExtraDataSigners(t *testing.T, extra, sig1, sig2 []byte) []byte {
	extra, err := InsertIntoExtraData(shared.Signature1, sig1, extra)
	require.NoError(t, err)
	extra, err = InsertIntoExtraData(shared.Signature2, sig2, extra)
	require.NoError(t, err)
	return extra
}

func calcSeqBlockHashWithSignature(seqHeader *types.Header) common.Hash {
	var hash common.Hash
	hasher := sha3.NewLegacyKeccak256()
	encodeSigHeader(hasher, seqHeader, true)
	hasher.(crypto.KeccakState).Read(hash[:])
	return hash
}

func co2Engine(role SodaRoleType) *Co2 {
	conf := &params.Co2Config{Period: period}
	return New(conf, nil, addr1Test, addr1Test, addr1Test, role)
}

// This function is used to determine the order of the signatures in the header extra data.
// The order is determined by the addresses of the signers (ascending).
func getOrderedKeys(key1, key2 []byte, addr1, addr2 common.Address, reverse bool) (
	[]byte, []byte) {
	if reverse {
		addr1, addr2 = addr2, addr1
	}
	if bytes.Compare(addr1[:], addr2[:]) > 0 {
		return key2, key1
	}
	return key1, key2
}

func makeHeader(num, diff int64) *types.Header {
	header := types.CopyHeader(headerTest)
	header.Number = big.NewInt(num)
	header.Difficulty = big.NewInt(diff)
	return header
}

// This function is used to create a full valid Executor block.
// Please note that the signatures's validity depends on the engine
// state (correct addresses must be used during engine initialization).
func fullExecutorBlock(t *testing.T, header, seqHeader *types.Header, pk1, pk2 []byte,
	addr1, addr2 common.Address, seqHeaderHash common.Hash) *types.Block {
	// Add the sequencer hash to the current block's extra data
	addSequencerHashToExtraData(t, header, seqHeaderHash)

	// Create a transcript for the block
	transcript := &types.Transcript{execOutputTest[0], execOutputTest[1]}

	// Add the transcript hash to the header's extra data
	// This simulates what happens in the finalize function
	var hash common.Hash
	if header.Number.Uint64() >= 0 { // Hydrogen fork block (default is 0)
		hash = transcript.Hash()
	} else {
		hash = transcript.Last32Bytes()
	}
	extra, err := InsertIntoExtraData(shared.TranscriptHash, hash.Bytes(), header.Extra)
	require.NoError(t, err)
	header.Extra = extra

	// Arrange the keys in ascending order
	key1, key2 := getOrderedKeys(pk1, pk2, addr1, addr2, false)
	// Sign the hash with the two executors and create a block with the current header
	// and a transcript.
	currentBlock := blockWithHeader(
		signedExecutorHeader(t, header, key1, key2),
		transcript,
	)
	// add the Sequencer's header to the block
	currentBlock.SetSequencerHeader(seqHeader)
	return currentBlock

}

func addSequencerHashToExtraData(t *testing.T, execHeader *types.Header, seqHash common.Hash) {
	extra, err := InsertIntoExtraData(shared.SequencerBlockHash, seqHash.Bytes(), execHeader.Extra)
	require.NoError(t, err)
	execHeader.Extra = extra
}

func reverseExtraDataSeals(t *testing.T, block *types.Block) *types.Block {
	header := block.Header()
	sig1, err := RetrieveFromExtraData(shared.Signature1, header.Extra)
	require.NoError(t, err)
	sig2, err := RetrieveFromExtraData(shared.Signature2, header.Extra)
	require.NoError(t, err)
	// We reverse the order of the signatures
	extra, err := InsertIntoExtraData(shared.Signature1, sig2, header.Extra)
	require.NoError(t, err)
	extra, err = InsertIntoExtraData(shared.Signature2, sig1, extra)
	require.NoError(t, err)
	header.Extra = extra
	return block.WithSeal(header)
}
