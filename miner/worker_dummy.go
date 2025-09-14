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

package miner

import (
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/consensus/co2"
	"github.com/ethereum/go-ethereum/consensus/misc/eip1559"
	"github.com/ethereum/go-ethereum/consensus/misc/eip4844"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/params"
)

// worker is the main object which takes care of submitting new work to consensus engine
// and gathering the sealing result.
type dummyWorker struct {
	chainConfig *params.ChainConfig
	engine      consensus.Engine
	chain       *core.BlockChain
}

func NewDummyWorker(chainConfig *params.ChainConfig, engine consensus.Engine, bc *core.BlockChain) *dummyWorker {
	return &dummyWorker{
		chainConfig: chainConfig,
		engine:      engine,
		chain:       bc,
	}
}

func (w *dummyWorker) maxGas() uint64 {
	return params.MaxGasLimit
}

// makeEnv creates a new environment for the sealing block.
func (w *dummyWorker) makeEnv(parent *types.Header, header *types.Header, coinbase common.Address) (*environment, error) {
	// Retrieve the parent state to execute on top and start a prefetcher for
	// the miner to speed block sealing up a bit.
	state, err := w.chain.StateAt(parent.Root)
	if err != nil {
		return nil, err
	}
	state.StartPrefetcher("miner")

	// Note the passed coinbase may be different with header.Coinbase.
	env := &environment{
		signer:   types.MakeSigner(w.chainConfig, header.Number, header.Time),
		state:    state,
		coinbase: coinbase,
		header:   header,
	}
	// Keep track of transactions which return errors so they can be removed
	env.tcount = 0
	return env, nil
}

func (w *dummyWorker) commitTransaction(env *environment, tx *types.Transaction) ([]*types.Log, error) {
	receipt, err := w.applyTransaction(env, tx)
	if err != nil {
		return nil, err
	}
	env.txs = append(env.txs, tx)
	env.receipts = append(env.receipts, receipt)
	return receipt.Logs, nil
}

// applyTransaction runs the transaction. If execution fails, state and gas pool are reverted.
func (w *dummyWorker) applyTransaction(env *environment, tx *types.Transaction) (*types.Receipt, error) {
	var (
		snap = env.state.Snapshot()
		gp   = env.gasPool.Gas()
	)
	receipt, err := core.ApplyTransaction(w.chainConfig, w.chain, &env.coinbase, env.gasPool, env.state, env.header, tx, &env.header.GasUsed, *w.chain.GetVMConfig())
	if err != nil {
		env.state.RevertToSnapshot(snap)
		env.gasPool.SetGas(gp)
	}
	return receipt, err
}

// prepareWork constructs the sealing task according to the given parameters,
// either based on the last chain head or specified parent. In this function
// the pending transactions are not filled yet, only the empty task returned.
func (w *dummyWorker) prepareWork(genParams *generateParams) (*environment, error) {
	// Find the parent block for sealing task
	parent := w.chain.CurrentBlock()
	if genParams.parentHash != (common.Hash{}) {
		block := w.chain.GetBlockByHash(genParams.parentHash)
		if block == nil {
			return nil, fmt.Errorf("missing parent")
		}
		parent = block.Header()
	}
	// Sanity check the timestamp correctness, recap the timestamp
	// to parent+1 if the mutation is allowed.
	timestamp := genParams.timestamp
	if _, ok := w.engine.(*co2.Co2); !ok {
		if parent.Time >= timestamp {
			if genParams.forceTime {
				return nil, fmt.Errorf("invalid timestamp, parent %d given %d", parent.Time, timestamp)
			}
			timestamp = parent.Time + 1
		}
	}
	// Construct the sealing block header.
	header := &types.Header{
		ParentHash: parent.Hash(),
		Number:     new(big.Int).Add(parent.Number, common.Big1),
		GasLimit:   core.CalcGasLimit(parent.GasLimit, w.maxGas()),
		Time:       timestamp,
		Coinbase:   genParams.coinbase,
	}
	// Set the randomness field from the beacon chain if it's available.
	if genParams.random != (common.Hash{}) {
		header.MixDigest = genParams.random
	}
	// Set baseFee and GasLimit if we are on an EIP-1559 chain
	if w.chainConfig.IsLondon(header.Number) {
		header.BaseFee = eip1559.CalcBaseFee(w.chainConfig, parent)
		if !w.chainConfig.IsLondon(parent.Number) {
			parentGasLimit := parent.GasLimit * w.chainConfig.ElasticityMultiplier()
			header.GasLimit = core.CalcGasLimit(parentGasLimit, w.maxGas())
		}
	}
	// Apply EIP-4844, EIP-4788.
	if w.chainConfig.IsCancun(header.Number, header.Time) {
		var excessBlobGas uint64
		if w.chainConfig.IsCancun(parent.Number, parent.Time) {
			excessBlobGas = eip4844.CalcExcessBlobGas(*parent.ExcessBlobGas, *parent.BlobGasUsed)
		} else {
			// For the first post-fork block, both parent.data_gas_used and parent.excess_data_gas are evaluated as 0
			excessBlobGas = eip4844.CalcExcessBlobGas(0, 0)
		}
		header.BlobGasUsed = new(uint64)
		header.ExcessBlobGas = &excessBlobGas
		header.ParentBeaconRoot = genParams.beaconRoot
	}
	// Run the consensus preparation with the default or customized consensus engine.
	if err := w.engine.Prepare(w.chain, header); err != nil {
		log.Error("Failed to prepare header for sealing", "err", err)
		return nil, err
	}
	// Could potentially happen if starting to mine in an odd state.
	// Note genParams.coinbase can be different with header.Coinbase
	// since clique algorithm can modify the coinbase field in header.
	env, err := w.makeEnv(parent, header, genParams.coinbase)
	if err != nil {
		log.Error("Failed to create sealing context", "err", err)
		return nil, err
	}
	return env, nil
}

func (w *dummyWorker) fillOrderedBlockTxs(txs types.Transactions, env *environment) error {
	gasLimit := env.header.GasLimit
	if env.gasPool == nil {
		env.gasPool = new(core.GasPool).AddGas(gasLimit)
	}

	for _, tx := range txs {
		if env.gasPool.Gas() < params.TxGas {
			log.Trace("Not enough gas for further transactions", "have", env.gasPool, "want", params.TxGas)
			// SODA ERROR
			return fmt.Errorf(fmt.Sprintf("Not enough gas for further transactions. have: %v want: %d", env.gasPool, params.TxGas))
		}
		// If we don't have enough space for the next transaction, skip the account.
		if env.gasPool.Gas() < tx.Gas() {
			log.Trace("Not enough gas left for transaction", "hash", tx.Hash, "left", env.gasPool.Gas(), "needed", tx.Gas)
			// SODA ERROR
			return fmt.Errorf("not enough gas left for transaction hash: %v left: %d, needed: %d", tx.Hash(), env.gasPool.Gas(), tx.Gas())
		}
		if left := uint64(params.MaxBlobGasPerBlock - env.blobs*params.BlobTxBlobGasPerBlob); left < tx.BlobGas() {
			log.Trace("Not enough blob gas left for transaction", "hash", tx.Hash, "left", left, "needed", tx.BlobGas)
			// SODA ERROR
			return fmt.Errorf("not enough blob gas left for transaction hash: %v, left: %d needed: %d", tx.Hash(), left, tx.BlobGas())
		}

		// Check whether the tx is replay protected. If we're not in the EIP155 hf
		// phase, start ignoring the sender until we do.
		if tx.Protected() && !w.chainConfig.IsEIP155(env.header.Number) {
			log.Trace("Ignoring replay protected transaction", "hash", tx.Hash, "eip155", w.chainConfig.EIP155Block)
			// SODA ERROR
			return fmt.Errorf("ignoring replay protected transaction hash: %v eip155: %v", tx.Hash(), w.chainConfig.EIP155Block)
		}
		// Start executing the transaction
		env.state.SetTxContext(tx.Hash(), env.tcount)

		_, err := w.commitTransaction(env, tx)
		if err != nil {
			// SODA ERROR
			return err
		}

		env.tcount++
	}

	return nil
}

func (w *dummyWorker) GenerateExecutorBlock(block *types.Block) (*types.Block, error) {
	// Set the coinbase if the worker is running or it's required
	var coinbase common.Address
	if c, ok := w.engine.(*co2.Co2); ok {
		// In our protocol (currently) the only permissable coinbase is the sequencer address.
		// There are numerous reasons for this choice, but the main one is that we want to
		// have both Executors sign the same block hash, which is not possible if we allow
		// a discrepancy in the coinbase field between the two.
		coinbase = c.SodaSequencerAddress
		c.SetSequencerBlockHeader(block.Header())
	}

	work, err := w.prepareWork(&generateParams{
		timestamp: block.Time(),
		coinbase:  coinbase,
		// The Executor's view of the chain includes the Sequencer's block, we want to generate
		// a new block that would replace it, that block should point to the Sequencer's block's
		// parent and not to the soon-to-be-replaced Sequencer block.
		parentHash: block.ParentHash(),
	})
	if err != nil {
		return nil, err
	}
	err = w.fillOrderedBlockTxs(block.Transactions(), work)
	if err != nil {
		// SODA ERROR
		return nil, err
	}
	env := work.copy()
	// Withdrawals are set to nil here, because this is only called in PoW.
	block, err = w.engine.FinalizeAndAssemble(w.chain, env.header, env.state, env.txs, nil, env.receipts, nil)
	if err != nil {
		return nil, err
	}
	return block, nil
}

// commitWork generates several new sealing tasks based on the parent block
// and submit them to the sealer.
func (w *dummyWorker) GenerateSequencerBlock(txs types.Transactions, timestamp int64) (*types.Block, error) {
	// Set the coinbase if the worker is running or it's required
	var coinbase common.Address

	work, err := w.prepareWork(&generateParams{
		timestamp: uint64(timestamp),
		coinbase:  coinbase,
	})
	if err != nil {
		return nil, err
	}
	// Fill pending transactions from the txpool into the block.
	err = w.fillOrderedBlockTxs(txs, work)
	if err != nil {
		return nil, err
	}
	env := work.copy()
	// Withdrawals are set to nil here, because this is only called in PoW.
	block, err := w.engine.FinalizeAndAssemble(w.chain, env.header, env.state, env.txs, nil, env.receipts, nil)
	if err != nil {
		return nil, err
	}
	return block, nil
}
