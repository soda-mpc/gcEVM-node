// Copyright 2015 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package soda_tests

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus/co2"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/secp256k1"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/miner"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/shared"
	"github.com/stretchr/testify/require"
)

var (
	bigZero = big.NewInt(0)
	nonces  = make(map[*common.Address]uint64)
)

type TestTransferTx struct {
	From   *roleEngine
	To     *roleEngine
	Amount *big.Int
}

type roleEngine struct {
	engine     *co2.Co2
	publicKey  []byte
	privateKey []byte
	address    common.Address
	keyObj     *ecdsa.PrivateKey
}

type sodaChainMaker struct {
	co2Conf   *params.Co2Config
	db        ethdb.Database
	sequencer *roleEngine
	executor1 *roleEngine
	executor2 *roleEngine
	chain     *core.BlockChain
	t         *testing.T
}

func (cm *sodaChainMaker) GetDB() ethdb.Database {
	return cm.db
}
func (cm *sodaChainMaker) GetChain() *core.BlockChain {
	return cm.chain
}

func (cm *sodaChainMaker) resetChain(engineRole co2.SodaRoleType) {
	db := rawdb.NewMemoryDatabase()
	cm.db = db
	engine := co2.New(cm.co2Conf, nil, cm.executor1.address, cm.executor2.address, cm.sequencer.address, engineRole)
	chain, err := core.NewBlockChain(db, nil, cm.GenesisBlock(), nil, engine, vm.Config{}, nil, nil)
	require.NoError(cm.t, err)
	cm.chain = chain
}

func newSodaChainMaker(t *testing.T, config *params.Co2Config) *sodaChainMaker {
	sequencerPubKey, sequencerPrivKey, sequencerAddress, seqKeyObj := generateAccountParams()
	executor1PubKey, executor1PrivKey, executor1Address, exec1KeyObj := generateAccountParams()
	executor2PubKey, executor2PrivKey, executor2Address, exec2KeyObj := generateAccountParams()

	sequencerEngine := co2.New(config,
		nil, executor1Address, executor2Address, sequencerAddress, co2.Sequencer)

	executor1Engine := co2.New(config,
		nil, executor2Address, executor2Address, sequencerAddress, co2.Executor)

	executor2Engine := co2.New(config,
		nil, executor1Address, executor1Address, sequencerAddress, co2.Executor)

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
	seqRoleEngine := roleEngine{
		engine:     sequencerEngine,
		publicKey:  sequencerPubKey,
		privateKey: sequencerPrivKey,
		address:    sequencerAddress,
		keyObj:     seqKeyObj,
	}
	exec1RoleEngine := roleEngine{
		engine:     executor1Engine,
		publicKey:  executor1PubKey,
		privateKey: executor1PrivKey,
		address:    executor1Address,
		keyObj:     exec1KeyObj,
	}
	exec2RoleEngine := roleEngine{
		engine:     executor2Engine,
		publicKey:  executor2PubKey,
		privateKey: executor2PrivKey,
		address:    executor2Address,
		keyObj:     exec2KeyObj,
	}
	if bytes.Compare(executor1Address[:], executor2Address[:]) > 0 {
		exec1RoleEngine, exec2RoleEngine = exec2RoleEngine, exec1RoleEngine
	}

	return &sodaChainMaker{
		t:         t,
		co2Conf:   config,
		sequencer: &seqRoleEngine,
		executor1: &exec1RoleEngine,
		executor2: &exec2RoleEngine,
	}

}

func (cm *sodaChainMaker) extraData() []byte {
	return append(make([]byte, 32), append(cm.sequencer.address.Bytes(), append(cm.executor1.address.Bytes(), append(cm.executor2.address.Bytes(), make([]byte, 65)...)...)...)...)
}

func (cm *sodaChainMaker) GenesisBlock() *core.Genesis {
	return &core.Genesis{
		Config: &params.ChainConfig{
			ChainID:             cm.chainConfig().ChainID,
			HomesteadBlock:      bigZero,
			DAOForkBlock:        bigZero,
			DAOForkSupport:      false,
			EIP150Block:         bigZero,
			EIP155Block:         bigZero,
			EIP158Block:         bigZero,
			ByzantiumBlock:      bigZero,
			ConstantinopleBlock: bigZero,
			PetersburgBlock:     bigZero,
			IstanbulBlock:       bigZero,
			MuirGlacierBlock:    bigZero,
			BerlinBlock:         bigZero,
			LondonBlock:         bigZero,
			ArrowGlacierBlock:   bigZero,
			GrayGlacierBlock:    bigZero,
			MergeNetsplitBlock:  bigZero,
			Co2:                 cm.co2Conf,
			IsDevMode:           false,
		},
		Nonce:      0,
		Timestamp:  0,
		ExtraData:  cm.extraData(),
		GasLimit:   params.MaxGasLimit,
		Difficulty: big.NewInt(1),
		Mixhash:    [32]byte{},
		Coinbase:   [20]byte{},
		Alloc: map[common.Address]core.GenesisAccount{
			cm.sequencer.address: {Balance: big.NewInt(0).Exp(big.NewInt(10), big.NewInt(36), nil)},
		},
		Number:     0,
		GasUsed:    0,
		ParentHash: [32]byte{},
	}
}

func (cm *sodaChainMaker) PopulateChain(chainTxs [][]*TestTransferTx, headBlockType co2.SodaRoleType) {
	cm.resetChain(co2.Executor)
	seqBlockChan := cm.chain.Engine().(*co2.Co2).GetSequencerBlockChannel()
	dummySeqWorker := miner.NewDummyWorker(cm.chainConfig(), cm.sequencer.engine, cm.chain)
	dummyExecWorker := miner.NewDummyWorker(cm.chainConfig(), cm.executor1.engine, cm.chain)
	go unblockChan(seqBlockChan)
	for i := 0; i < len(chainTxs); i++ {
		seqBlock, err := dummySeqWorker.GenerateSequencerBlock(cm.getTransferTransactions(cm.t, chainTxs[i]), int64(i))
		require.NoError(cm.t, err)
		signedHeader := signedSequencerHeader(cm.t, seqBlock.Header(), cm.sequencer.privateKey)
		sealedSeqBlock := seqBlock.WithSeal(signedHeader)
		_, err = cm.chain.InsertChain([]*types.Block{sealedSeqBlock})
		require.NoError(cm.t, err)
		if i == len(chainTxs)-1 && headBlockType == co2.Sequencer {
			// The last block will remain a sequencer block
			fmt.Printf("Head block num: %d is a sequencer block\n", sealedSeqBlock.Number())
			continue
		}
		execBlock, err := dummyExecWorker.GenerateExecutorBlock(sealedSeqBlock)
		require.NoError(cm.t, err)
		signedHeader = signedExecutorHeader(cm.t, execBlock.Header(), cm.executor1.privateKey, cm.executor2.privateKey)
		sealedExecBlock := execBlock.WithSeal(signedHeader)
		blockType, err := cm.sequencer.engine.GetBlockType(sealedExecBlock)
		require.NoError(cm.t, err)
		require.Equal(cm.t, *blockType, co2.Executor)
		fmt.Printf("block num: %d is an executor block\n", sealedExecBlock.Number())
		fmt.Printf("extra data: %x\n", sealedExecBlock.Extra())
		fmt.Printf("sequencer header: %x\n", sealedExecBlock.GetSequencerHeader())
		_, err = cm.chain.InsertChain([]*types.Block{sealedExecBlock})
		require.NoError(cm.t, err)
	}
}

func (cm *sodaChainMaker) getTransferTransactions(t *testing.T, ttxs []*TestTransferTx) []*types.Transaction {
	txs := make([]*types.Transaction, len(ttxs))
	for i, ttx := range ttxs {
		txs[i] = cm.getTransferTransaction(t, ttx)
	}
	return txs
}

func (cm *sodaChainMaker) getTransferTransaction(t *testing.T, ttx *TestTransferTx) *types.Transaction {
	cid := cm.chainConfig().ChainID
	signer := types.NewCancunSigner(cid)
	tx, err := types.SignNewTx(ttx.From.keyObj, signer,
		&types.DynamicFeeTx{
			ChainID:   cid,
			Nonce:     cm.useNonce(&ttx.From.address),
			Gas:       21000,
			To:        &ttx.To.address,
			Value:     ttx.Amount,
			GasTipCap: big.NewInt(1e9),
			GasFeeCap: big.NewInt(1e9),
		})
	require.NoError(t, err)
	return tx
}

func (cm *sodaChainMaker) chainConfig() *params.ChainConfig {
	return &params.ChainConfig{
		ChainID:                       big.NewInt(50505050),
		HomesteadBlock:                bigZero,
		DAOForkBlock:                  nil,
		DAOForkSupport:                false,
		EIP150Block:                   bigZero,
		EIP155Block:                   bigZero,
		EIP158Block:                   bigZero,
		ByzantiumBlock:                bigZero,
		ConstantinopleBlock:           bigZero,
		PetersburgBlock:               bigZero,
		IstanbulBlock:                 bigZero,
		MuirGlacierBlock:              bigZero,
		BerlinBlock:                   bigZero,
		LondonBlock:                   bigZero,
		ArrowGlacierBlock:             nil,
		GrayGlacierBlock:              nil,
		MergeNetsplitBlock:            nil,
		ShanghaiTime:                  nil,
		CancunTime:                    nil,
		PragueTime:                    nil,
		VerkleTime:                    nil,
		TerminalTotalDifficulty:       nil,
		TerminalTotalDifficultyPassed: false,
		Ethash:                        nil,
		Co2:                           cm.co2Conf,
	}
}

func (cm *sodaChainMaker) useNonce(addr *common.Address) uint64 {
	nonce := nonces[addr]
	nonces[addr]++
	return nonce
}

func generateKeyPair() (pubkey, privkey []byte, key *ecdsa.PrivateKey) {
	key, err := ecdsa.GenerateKey(secp256k1.S256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	pubkey = elliptic.Marshal(secp256k1.S256(), key.X, key.Y)

	privkey = make([]byte, 32)
	blob := key.D.Bytes()
	copy(privkey[32-len(blob):], blob)

	return pubkey, privkey, key
}

func generateAccountParams() (pubkey, privkey []byte, address common.Address, keyObj *ecdsa.PrivateKey) {
	pubkey, privkey, keyObj = generateKeyPair()
	pk, _ := crypto.UnmarshalPubkey(pubkey)
	address = crypto.PubkeyToAddress(*pk)
	return pubkey, privkey, address, keyObj
}
func signedExecutorHeader(t *testing.T, header *types.Header, privkey1 []byte, privkey2 []byte) *types.Header {
	sig1 := signHeader(t, header, privkey1)
	sig2 := signHeader(t, header, privkey2)
	header.Extra = populateExtraDataSigners(t, header.Extra, sig1, sig2)
	return header
}
func signedSequencerHeader(t *testing.T, header *types.Header, privkey []byte) *types.Header {
	sig := signHeader(t, header, privkey)
	header.Extra = populateExtraDataSigners(t, header.Extra, sig, sig)
	return header
}
func signHeader(t *testing.T, header *types.Header, privkey []byte) []byte {
	// Generate the hash to sign
	sigHash := co2.SealHash(header)
	// Sign the hash
	sig, err := secp256k1.Sign(sigHash[:], privkey)
	require.NoError(t, err)
	return sig
}
func populateExtraDataSigners(t *testing.T, extra, sig1, sig2 []byte) []byte {
	extra, err := co2.InsertIntoExtraData(shared.Signature1, sig1, extra)
	require.NoError(t, err)
	extra, err = co2.InsertIntoExtraData(shared.Signature2, sig2, extra)
	require.NoError(t, err)
	return extra
}

func unblockChan(ch chan *types.Block) {
	for {
		select {
		case <-ch:
		default:
			time.Sleep(1 * time.Millisecond)
		}
	}
}

func ChainMaker(t *testing.T) *sodaChainMaker {
	return newSodaChainMaker(t, &params.Co2Config{
		Period: 0,
	})
}

func MakeSodaChain(cm *sodaChainMaker, numBlocks int, headBlockType co2.SodaRoleType) (*core.BlockChain, ethdb.Database) {
	chainTxs := [][]*TestTransferTx{}
	for i := 0; i < numBlocks; i++ {
		ttxs := []*TestTransferTx{}
		for j := 0; j < 10; j++ {
			ttxs = append(ttxs, &TestTransferTx{
				From:   cm.sequencer,
				To:     cm.executor1,
				Amount: big.NewInt(1e18),
			})
		}
		chainTxs = append(chainTxs, ttxs)
	}
	cm.PopulateChain(chainTxs, headBlockType)
	return cm.chain, cm.db
}

func MakeEmptyChain(cm *sodaChainMaker, engineType co2.SodaRoleType) (*core.BlockChain, ethdb.Database) {
	cm.resetChain(engineType)
	if engineType == co2.Executor {
		seqBlockChan := cm.chain.Engine().(*co2.Co2).GetSequencerBlockChannel()
		go unblockChan(seqBlockChan)
	}

	return cm.chain, cm.db
}
