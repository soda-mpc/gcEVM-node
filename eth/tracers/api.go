// Copyright 2021 The go-ethereum Authors
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

package tracers

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"runtime"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/eth/tracers/logger"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/internal/ethapi"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/rpc"
)

const (
	// defaultTraceTimeout is the amount of time a single transaction can execute
	// by default before being forcefully aborted.
	defaultTraceTimeout = 5 * time.Second

	// defaultTraceReexec is the number of blocks the tracer is willing to go back
	// and reexecute to produce missing historical state necessary to run a specific
	// trace.
	defaultTraceReexec = uint64(128)

	// defaultTracechainMemLimit is the size of the triedb, at which traceChain
	// switches over and tries to use a disk-backed database instead of building
	// on top of memory.
	// For non-archive nodes, this limit _will_ be overblown, as disk-backed tries
	// will only be found every ~15K blocks or so.
	defaultTracechainMemLimit = common.StorageSize(500 * 1024 * 1024)

	// maximumPendingTraceStates is the maximum number of states allowed waiting
	// for tracing. The creation of trace state will be paused if the unused
	// trace states exceed this limit.
	maximumPendingTraceStates = 128
)

var ErrTraceRequiresTranscript = errors.New("tracing requires a non-empty transcript")

var errTxNotFound = errors.New("transaction not found")

// StateReleaseFunc is used to deallocate resources held by constructing a
// historical state for tracing purposes.
type StateReleaseFunc func()

// Backend interface provides the common API services (that are provided by
// both full and light clients) with access to necessary functions.
type Backend interface {
	HeaderByHash(ctx context.Context, hash common.Hash) (*types.Header, error)
	HeaderByNumber(ctx context.Context, number rpc.BlockNumber) (*types.Header, error)
	BlockByHash(ctx context.Context, hash common.Hash) (*types.Block, error)
	BlockByNumber(ctx context.Context, number rpc.BlockNumber) (*types.Block, error)
	GetTransaction(ctx context.Context, txHash common.Hash) (*types.Transaction, common.Hash, uint64, uint64, error)
	RPCGasCap() uint64
	ChainConfig() *params.ChainConfig
	Engine() consensus.Engine
	ChainDb() ethdb.Database
	StateAtBlock(ctx context.Context, block *types.Block, reexec uint64, base *state.StateDB, readOnly bool, preferDisk bool) (*state.StateDB, StateReleaseFunc, error)
	StateAtTransaction(ctx context.Context, block *types.Block, txIndex int, reexec uint64, vmConfig *vm.Config) (*core.Message, vm.BlockContext, *state.StateDB, StateReleaseFunc, error)
}

// API is the collection of tracing APIs exposed over the private debugging endpoint.
type API struct {
	backend Backend
}

// NewAPI creates a new API definition for the tracing methods of the Ethereum service.
func NewAPI(backend Backend) *API {
	return &API{backend: backend}
}

// createVMConfigWithTranscript creates a vm.Config with transcript if available from the block.
func (api *API) createVMConfigWithTranscript(block *types.Block) (*vm.Config, error) {
	if block == nil {
		return nil, ErrTraceRequiresTranscript
	}
	tr := block.GetTranscript()
	if len(tr) == 0 {
		return nil, ErrTraceRequiresTranscript
	}
	execType := vm.TranscriptEvaluation
	cfg := &vm.Config{
		ExecType:   &execType,
		Transcript: tr,
	}
	return cfg, nil
}

// chainContext constructs the context reader which is used by the evm for reading
// the necessary chain context.
func (api *API) chainContext(ctx context.Context) core.ChainContext {
	return ethapi.NewChainContext(ctx, api.backend)
}

// blockByNumber is the wrapper of the chain access function offered by the backend.
// It will return an error if the block is not found.
func (api *API) blockByNumber(ctx context.Context, number rpc.BlockNumber) (*types.Block, error) {
	block, err := api.backend.BlockByNumber(ctx, number)
	if err != nil {
		return nil, err
	}
	if block == nil {
		return nil, fmt.Errorf("block #%d not found", number)
	}
	return block, nil
}

// blockByHash is the wrapper of the chain access function offered by the backend.
// It will return an error if the block is not found.
func (api *API) blockByHash(ctx context.Context, hash common.Hash) (*types.Block, error) {
	block, err := api.backend.BlockByHash(ctx, hash)
	if err != nil {
		return nil, err
	}
	if block == nil {
		return nil, fmt.Errorf("block %s not found", hash.Hex())
	}
	return block, nil
}

// blockByNumberAndHash is the wrapper of the chain access function offered by
// the backend. It will return an error if the block is not found.
//
// Note this function is friendly for the light client which can only retrieve the
// historical(before the CHT) header/block by number.
func (api *API) blockByNumberAndHash(ctx context.Context, number rpc.BlockNumber, hash common.Hash) (*types.Block, error) {
	block, err := api.blockByNumber(ctx, number)
	if err != nil {
		return nil, err
	}
	if block.Hash() == hash {
		return block, nil
	}
	return api.blockByHash(ctx, hash)
}

// TraceConfig holds extra parameters to trace functions.
type TraceConfig struct {
	*logger.Config
	Tracer  *string
	Timeout *string
	Reexec  *uint64
	// Config specific to given tracer. Note struct logger
	// config are historically embedded in main object.
	TracerConfig json.RawMessage
}

// TraceCallConfig is the config for traceCall API. It holds one more
// field to override the state for tracing.
type TraceCallConfig struct {
	TraceConfig
	StateOverrides *ethapi.StateOverride
	BlockOverrides *ethapi.BlockOverrides
}

// StdTraceConfig holds extra parameters to standard-json trace functions.
type StdTraceConfig struct {
	logger.Config
	Reexec *uint64
	TxHash common.Hash
}

// txTraceResult is the result of a single transaction trace.
type txTraceResult struct {
	TxHash common.Hash `json:"txHash"`           // transaction hash
	Result interface{} `json:"result,omitempty"` // Trace results produced by the tracer
	Error  string      `json:"error,omitempty"`  // Trace failure produced by the tracer
}

// blockTraceTask represents a single block trace task when an entire chain is
// being traced.
type blockTraceTask struct {
	statedb *state.StateDB   // Intermediate state prepped for tracing
	block   *types.Block     // Block to trace the transactions from
	release StateReleaseFunc // The function to release the held resource for this task
	results []*txTraceResult // Trace results produced by the task
}

// blockTraceResult represents the results of tracing a single block when an entire
// chain is being traced.
type blockTraceResult struct {
	Block  hexutil.Uint64   `json:"block"`  // Block number corresponding to this trace
	Hash   common.Hash      `json:"hash"`   // Block hash corresponding to this trace
	Traces []*txTraceResult `json:"traces"` // Trace results produced by the task
}

// txTraceTask represents a single transaction trace task when an entire block
// is being traced.
type txTraceTask struct {
	statedb *state.StateDB // Intermediate state prepped for tracing
	index   int            // Transaction offset in the block
}

// TraceChain returns the structured logs created during the execution of EVM
// between two blocks (excluding start) and returns them as a JSON object.
func (api *API) TraceChain(ctx context.Context, start, end rpc.BlockNumber, config *TraceConfig) (*rpc.Subscription, error) { // Fetch the block interval that we want to trace
	from, err := api.blockByNumber(ctx, start)
	if err != nil {
		return nil, err
	}
	to, err := api.blockByNumber(ctx, end)
	if err != nil {
		return nil, err
	}
	if from.Number().Cmp(to.Number()) >= 0 {
		return nil, fmt.Errorf("end block (#%d) needs to come after start block (#%d)", end, start)
	}
	// Tracing a chain is a **long** operation, only do with subscriptions
	notifier, supported := rpc.NotifierFromContext(ctx)
	if !supported {
		return &rpc.Subscription{}, rpc.ErrNotificationsUnsupported
	}
	sub := notifier.CreateSubscription()

	resCh := api.traceChain(from, to, config, notifier.Closed())
	go func() {
		for result := range resCh {
			notifier.Notify(sub.ID, result)
		}
	}()
	return sub, nil
}

// traceChain configures a new tracer according to the provided configuration, and
// executes all the transactions contained within. The tracing chain range includes
// the end block but excludes the start one. The return value will be one item per
// transaction, dependent on the requested tracer.
// The tracing procedure should be aborted in case the closed signal is received.
func (api *API) traceChain(start, end *types.Block, config *TraceConfig, closed <-chan interface{}) chan *blockTraceResult {
	reexec := defaultTraceReexec
	if config != nil && config.Reexec != nil {
		reexec = *config.Reexec
	}
	blocks := int(end.NumberU64() - start.NumberU64())
	threads := runtime.NumCPU()
	if threads > blocks {
		threads = blocks
	}
	var (
		pend    = new(sync.WaitGroup)
		ctx     = context.Background()
		taskCh  = make(chan *blockTraceTask, threads)
		resCh   = make(chan *blockTraceTask, threads)
		tracker = newStateTracker(maximumPendingTraceStates, start.NumberU64())
	)
	for th := 0; th < threads; th++ {
		pend.Add(1)
		go func() {
			defer pend.Done()

			// Fetch and execute the block trace taskCh
			for task := range taskCh {
				var (
					signer   = types.MakeSigner(api.backend.ChainConfig(), task.block.Number(), task.block.Time())
					blockCtx = core.NewEVMBlockContext(task.block.Header(), api.chainContext(ctx), nil)
				)

				// Require transcript for tracing (no fallback)
				vmConfig, err := api.createVMConfigWithTranscript(task.block)
				if err != nil {
					// Report a clear error for each tx in this block, release state, stream result, continue
					errMsg := "gcEVM tracing requires a non-empty transcript"
					for i, tx := range task.block.Transactions() {
						task.results[i] = &txTraceResult{TxHash: tx.Hash(), Error: errMsg}
					}
					// Tracing state is used up — release it (state number = block.number-1)
					tracker.releaseState(task.block.NumberU64()-1, task.release)

					// Stream the result back, then proceed to next task
					select {
					case resCh <- task:
					case <-closed:
						return
					}
					continue
				}
				// Trace all the transactions contained within
				for i, tx := range task.block.Transactions() {
					msg, _ := core.TransactionToMessage(tx, signer, task.block.BaseFee())
					txctx := &Context{
						BlockHash:   task.block.Hash(),
						BlockNumber: task.block.Number(),
						TxIndex:     i,
						TxHash:      tx.Hash(),
					}
					res, err := api.traceTx(ctx, msg, txctx, blockCtx, task.statedb, config, task.block, vmConfig)
					if err != nil {
						task.results[i] = &txTraceResult{TxHash: tx.Hash(), Error: err.Error()}
						log.Warn("Tracing failed", "hash", tx.Hash(), "block", task.block.NumberU64(), "err", err)
						break
					}
					// Only delete empty objects if EIP158/161 (a.k.a Spurious Dragon) is in effect
					task.statedb.Finalise(api.backend.ChainConfig().IsEIP158(task.block.Number()))
					task.results[i] = &txTraceResult{TxHash: tx.Hash(), Result: res}
				}
				// Tracing state is used up, queue it for de-referencing. Note the
				// state is the parent state of trace block, use block.number-1 as
				// the state number.
				tracker.releaseState(task.block.NumberU64()-1, task.release)

				// Stream the result back to the result catcher or abort on teardown
				select {
				case resCh <- task:
				case <-closed:
					return
				}
			}
		}()
	}
	// Start a goroutine to feed all the blocks into the tracers
	go func() {
		var (
			logged  time.Time
			begin   = time.Now()
			number  uint64
			traced  uint64
			failed  error
			statedb *state.StateDB
			release StateReleaseFunc
		)
		// Ensure everything is properly cleaned up on any exit path
		defer func() {
			close(taskCh)
			pend.Wait()

			// Clean out any pending release functions of trace states.
			tracker.callReleases()

			// Log the chain result
			switch {
			case failed != nil:
				log.Warn("Chain tracing failed", "start", start.NumberU64(), "end", end.NumberU64(), "transactions", traced, "elapsed", time.Since(begin), "err", failed)
			case number < end.NumberU64():
				log.Warn("Chain tracing aborted", "start", start.NumberU64(), "end", end.NumberU64(), "abort", number, "transactions", traced, "elapsed", time.Since(begin))
			default:
				log.Info("Chain tracing finished", "start", start.NumberU64(), "end", end.NumberU64(), "transactions", traced, "elapsed", time.Since(begin))
			}
			close(resCh)
		}()
		// Feed all the blocks both into the tracer, as well as fast process concurrently
		for number = start.NumberU64(); number < end.NumberU64(); number++ {
			// Stop tracing if interruption was requested
			select {
			case <-closed:
				return
			default:
			}
			// Print progress logs if long enough time elapsed
			if time.Since(logged) > 8*time.Second {
				logged = time.Now()
				log.Info("Tracing chain segment", "start", start.NumberU64(), "end", end.NumberU64(), "current", number, "transactions", traced, "elapsed", time.Since(begin))
			}
			// Retrieve the parent block and target block for tracing.
			block, err := api.blockByNumber(ctx, rpc.BlockNumber(number))
			if err != nil {
				failed = err
				break
			}
			next, err := api.blockByNumber(ctx, rpc.BlockNumber(number+1))
			if err != nil {
				failed = err
				break
			}
			// Make sure the state creator doesn't go too far. Too many unprocessed
			// trace state may cause the oldest state to become stale(e.g. in
			// path-based scheme).
			if err = tracker.wait(number); err != nil {
				failed = err
				break
			}
			// Prepare the statedb for tracing. Don't use the live database for
			// tracing to avoid persisting state junks into the database. Switch
			// over to `preferDisk` mode only if the memory usage exceeds the
			// limit, the trie database will be reconstructed from scratch only
			// if the relevant state is available in disk.
			var preferDisk bool
			if statedb != nil {
				s1, s2, s3 := statedb.Database().TrieDB().Size()
				preferDisk = s1+s2+s3 > defaultTracechainMemLimit
			}
			statedb, release, err = api.backend.StateAtBlock(ctx, block, reexec, statedb, false, preferDisk)
			if err != nil {
				failed = err
				break
			}
			// Clean out any pending release functions of trace state. Note this
			// step must be done after constructing tracing state, because the
			// tracing state of block next depends on the parent state and construction
			// may fail if we release too early.
			tracker.callReleases()

			// Send the block over to the concurrent tracers (if not in the fast-forward phase)
			txs := next.Transactions()
			select {
			case taskCh <- &blockTraceTask{statedb: statedb.Copy(), block: next, release: release, results: make([]*txTraceResult, len(txs))}:
			case <-closed:
				tracker.releaseState(number, release)
				return
			}
			traced += uint64(len(txs))
		}
	}()

	// Keep reading the trace results and stream them to result channel.
	retCh := make(chan *blockTraceResult)
	go func() {
		defer close(retCh)
		var (
			next = start.NumberU64() + 1
			done = make(map[uint64]*blockTraceResult)
		)
		for res := range resCh {
			// Queue up next received result
			result := &blockTraceResult{
				Block:  hexutil.Uint64(res.block.NumberU64()),
				Hash:   res.block.Hash(),
				Traces: res.results,
			}
			done[uint64(result.Block)] = result

			// Stream completed traces to the result channel
			for result, ok := done[next]; ok; result, ok = done[next] {
				if len(result.Traces) > 0 || next == end.NumberU64() {
					// It will be blocked in case the channel consumer doesn't take the
					// tracing result in time(e.g. the websocket connect is not stable)
					// which will eventually block the entire chain tracer. It's the
					// expected behavior to not waste node resources for a non-active user.
					retCh <- result
				}
				delete(done, next)
				next++
			}
		}
	}()
	return retCh
}

// TraceBlockByNumber returns the structured logs created during the execution of
// EVM and returns them as a JSON object.
func (api *API) TraceBlockByNumber(ctx context.Context, number rpc.BlockNumber, config *TraceConfig) ([]*txTraceResult, error) {
	block, err := api.blockByNumber(ctx, number)
	if err != nil {
		return nil, err
	}
	return api.traceBlock(ctx, block, config)
}

// TraceBlockByHash returns the structured logs created during the execution of
// EVM and returns them as a JSON object.
func (api *API) TraceBlockByHash(ctx context.Context, hash common.Hash, config *TraceConfig) ([]*txTraceResult, error) {
	block, err := api.blockByHash(ctx, hash)
	if err != nil {
		return nil, err
	}
	return api.traceBlock(ctx, block, config)
}

// TraceBlock returns the structured logs created during the execution of EVM
// and returns them as a JSON object.
func (api *API) TraceBlock(ctx context.Context, blob hexutil.Bytes, config *TraceConfig) ([]*txTraceResult, error) {
	block := new(types.Block)
	if err := rlp.DecodeBytes(blob, block); err != nil {
		return nil, fmt.Errorf("could not decode block: %v", err)
	}
	return api.traceBlock(ctx, block, config)
}

// TraceBlockFromFile returns the structured logs created during the execution of
// EVM and returns them as a JSON object.
func (api *API) TraceBlockFromFile(ctx context.Context, file string, config *TraceConfig) ([]*txTraceResult, error) {
	blob, err := os.ReadFile(file)
	if err != nil {
		return nil, fmt.Errorf("could not read file: %v", err)
	}
	return api.TraceBlock(ctx, blob, config)
}

// TraceBadBlock returns the structured logs created during the execution of
// EVM against a block pulled from the pool of bad ones and returns them as a JSON
// object.
func (api *API) TraceBadBlock(ctx context.Context, hash common.Hash, config *TraceConfig) ([]*txTraceResult, error) {
	block := rawdb.ReadBadBlock(api.backend.ChainDb(), hash)
	if block == nil {
		return nil, fmt.Errorf("bad block %#x not found", hash)
	}
	return api.traceBlock(ctx, block, config)
}

// StandardTraceBlockToFile dumps the structured logs created during the
// execution of EVM to the local file system and returns a list of files
// to the caller.
func (api *API) StandardTraceBlockToFile(ctx context.Context, hash common.Hash, config *StdTraceConfig) ([]string, error) {
	block, err := api.blockByHash(ctx, hash)
	if err != nil {
		return nil, err
	}
	return api.standardTraceBlockToFile(ctx, block, config)
}

// StandardTraceBadBlockToFile dumps the structured logs created during the
// execution of EVM against a block pulled from the pool of bad ones to the
// local file system and returns a list of files to the caller.
func (api *API) StandardTraceBadBlockToFile(ctx context.Context, hash common.Hash, config *StdTraceConfig) ([]string, error) {
	block := rawdb.ReadBadBlock(api.backend.ChainDb(), hash)
	if block == nil {
		return nil, fmt.Errorf("bad block %#x not found", hash)
	}
	return api.standardTraceBlockToFile(ctx, block, config)
}

// traceBlock configures a new tracer according to the provided configuration, and
// executes all the transactions contained within. The return value will be one item
// per transaction, dependent on the requested tracer.
func (api *API) traceBlock(ctx context.Context, block *types.Block, config *TraceConfig) ([]*txTraceResult, error) {
	if block.NumberU64() == 0 {
		return nil, errors.New("genesis is not traceable")
	}
	// Prepare base state
	parent, err := api.blockByNumberAndHash(ctx, rpc.BlockNumber(block.NumberU64()-1), block.ParentHash())
	if err != nil {
		return nil, err
	}
	reexec := defaultTraceReexec
	if config != nil && config.Reexec != nil {
		reexec = *config.Reexec
	}
	statedb, release, err := api.backend.StateAtBlock(ctx, parent, reexec, nil, true, false)
	if err != nil {
		return nil, err
	}
	defer release()

	// JS tracers have high overhead. In this case run a parallel
	// process that generates states in one thread and traces txes
	// in separate worker threads.
	if config != nil && config.Tracer != nil && *config.Tracer != "" {
		if isJS := DefaultDirectory.IsJS(*config.Tracer); isJS {
			return api.traceBlockParallel(ctx, block, statedb, config)
		}
	}
	// Native tracers have low overhead
	var (
		txs       = block.Transactions()
		blockHash = block.Hash()
		is158     = api.backend.ChainConfig().IsEIP158(block.Number())
		blockCtx  = core.NewEVMBlockContext(block.Header(), api.chainContext(ctx), nil)
		signer    = types.MakeSigner(api.backend.ChainConfig(), block.Number(), block.Time())
		results   = make([]*txTraceResult, len(txs))
	)

	// Require transcript for tracing (no fallback)
	vmConfig, err := api.createVMConfigWithTranscript(block)
	if err != nil {
		return nil, err
	}

	for i, tx := range txs {
		// Generate the next state snapshot fast without tracing
		msg, _ := core.TransactionToMessage(tx, signer, block.BaseFee())
		txctx := &Context{
			BlockHash:   blockHash,
			BlockNumber: block.Number(),
			TxIndex:     i,
			TxHash:      tx.Hash(),
		}
		res, err := api.traceTx(ctx, msg, txctx, blockCtx, statedb, config, block, vmConfig)
		if err != nil {
			return nil, err
		}
		results[i] = &txTraceResult{TxHash: tx.Hash(), Result: res}
		// Finalize the state so any modifications are written to the trie
		// Only delete empty objects if EIP158/161 (a.k.a Spurious Dragon) is in effect
		statedb.Finalise(is158)
	}
	return results, nil
}

// traceBlockParallel is for tracers that have a high overhead (read JS tracers). One thread
// runs along and executes txes without tracing enabled to generate their prestate.
// Worker threads take the tasks and the prestate and trace them.
func (api *API) traceBlockParallel(ctx context.Context, block *types.Block, statedb *state.StateDB, config *TraceConfig) ([]*txTraceResult, error) {
	// Execute all the transaction contained within the block concurrently
	var (
		txs       = block.Transactions()
		blockHash = block.Hash()
		blockCtx  = core.NewEVMBlockContext(block.Header(), api.chainContext(ctx), nil)
		signer    = types.MakeSigner(api.backend.ChainConfig(), block.Number(), block.Time())
		results   = make([]*txTraceResult, len(txs))
		pend      sync.WaitGroup
	)

	// Require transcript for tracing (no fallback)
	vmConfig, err := api.createVMConfigWithTranscript(block)
	if err != nil {
		return nil, err
	}

	threads := runtime.NumCPU()
	if threads > len(txs) {
		threads = len(txs)
	}
	jobs := make(chan *txTraceTask, threads)
	for th := 0; th < threads; th++ {
		pend.Add(1)
		go func() {
			defer pend.Done()
			// Fetch and execute the next transaction trace tasks
			for task := range jobs {
				msg, _ := core.TransactionToMessage(txs[task.index], signer, block.BaseFee())
				txctx := &Context{
					BlockHash:   blockHash,
					BlockNumber: block.Number(),
					TxIndex:     task.index,
					TxHash:      txs[task.index].Hash(),
				}
				res, err := api.traceTx(ctx, msg, txctx, blockCtx, task.statedb, config, block, vmConfig)
				if err != nil {
					results[task.index] = &txTraceResult{TxHash: txs[task.index].Hash(), Error: err.Error()}
					continue
				}
				results[task.index] = &txTraceResult{TxHash: txs[task.index].Hash(), Result: res}
			}
		}()
	}

	// Feed the transactions into the tracers and return
	var failed error
txloop:
	for i, tx := range txs {
		// Send the trace task over for execution
		task := &txTraceTask{statedb: statedb.Copy(), index: i}
		select {
		case <-ctx.Done():
			failed = ctx.Err()
			break txloop
		case jobs <- task:
		}

		// Generate the next state snapshot fast without tracing
		msg, _ := core.TransactionToMessage(tx, signer, block.BaseFee())
		statedb.SetTxContext(tx.Hash(), i)

		var vmConf vm.Config
		if vmConfig != nil {
			// Use the provided config (which may include transcript configuration)
			vmConf = *vmConfig
		}

		vmenv := vm.NewEVM(blockCtx, core.NewEVMTxContext(msg), statedb, api.backend.ChainConfig(), vmConf)
		if _, err := core.ApplyMessage(vmenv, msg, new(core.GasPool).AddGas(msg.GasLimit)); err != nil {
			failed = err
			break txloop
		}

		// Update the transcript in vmConfig with the updated transcript from vmenv
		if vmConfig != nil {
			vmConfig.Transcript = vmenv.Config.Transcript
		}

		// Finalize the state so any modifications are written to the trie
		// Only delete empty objects if EIP158/161 (a.k.a Spurious Dragon) is in effect
		statedb.Finalise(vmenv.ChainConfig().IsEIP158(block.Number()))
	}

	close(jobs)
	pend.Wait()

	// If execution failed in between, abort
	if failed != nil {
		return nil, failed
	}
	return results, nil
}

// standardTraceBlockToFile configures a new tracer which uses standard JSON output,
// and traces either a full block or an individual transaction. The return value will
// be one filename per transaction traced.
func (api *API) standardTraceBlockToFile(ctx context.Context, block *types.Block, config *StdTraceConfig) ([]string, error) {
	// If we're tracing a single transaction, make sure it's present
	if config != nil && config.TxHash != (common.Hash{}) {
		if !containsTx(block, config.TxHash) {
			return nil, fmt.Errorf("transaction %#x not found in block", config.TxHash)
		}
	}
	if block.NumberU64() == 0 {
		return nil, errors.New("genesis is not traceable")
	}
	parent, err := api.blockByNumberAndHash(ctx, rpc.BlockNumber(block.NumberU64()-1), block.ParentHash())
	if err != nil {
		return nil, err
	}
	reexec := defaultTraceReexec
	if config != nil && config.Reexec != nil {
		reexec = *config.Reexec
	}
	statedb, release, err := api.backend.StateAtBlock(ctx, parent, reexec, nil, true, false)
	if err != nil {
		return nil, err
	}
	defer release()

	// Retrieve the tracing configurations, or use default values
	var (
		logConfig logger.Config
		txHash    common.Hash
	)
	if config != nil {
		logConfig = config.Config
		txHash = config.TxHash
	}
	logConfig.Debug = true

	// Execute transaction, either tracing all or just the requested one
	var (
		dumps       []string
		signer      = types.MakeSigner(api.backend.ChainConfig(), block.Number(), block.Time())
		chainConfig = api.backend.ChainConfig()
		vmctx       = core.NewEVMBlockContext(block.Header(), api.chainContext(ctx), nil)
		canon       = true
	)
	// Check if there are any overrides: the caller may wish to enable a future
	// fork when executing this block. Note, such overrides are only applicable to the
	// actual specified block, not any preceding blocks that we have to go through
	// in order to obtain the state.
	// Therefore, it's perfectly valid to specify `"futureForkBlock": 0`, to enable `futureFork`
	if config != nil && config.Overrides != nil {
		// Note: This copies the config, to not screw up the main config
		chainConfig, canon = overrideConfig(chainConfig, config.Overrides)
	}

	// Require transcript for tracing (no fallback)
	vmConfig, err := api.createVMConfigWithTranscript(block)
	if err != nil {
		return nil, err
	}

	for i, tx := range block.Transactions() {
		// Prepare the transaction for un-traced execution
		var (
			msg, _    = core.TransactionToMessage(tx, signer, block.BaseFee())
			txContext = core.NewEVMTxContext(msg)
			vmConf    vm.Config
			dump      *os.File
			writer    *bufio.Writer
			err       error
		)
		// If the transaction needs tracing, swap out the configs
		if tx.Hash() == txHash || txHash == (common.Hash{}) {
			// Generate a unique temporary file to dump it into
			prefix := fmt.Sprintf("block_%#x-%d-%#x-", block.Hash().Bytes()[:4], i, tx.Hash().Bytes()[:4])
			if !canon {
				prefix = fmt.Sprintf("%valt-", prefix)
			}
			dump, err = os.CreateTemp(os.TempDir(), prefix)
			if err != nil {
				return nil, err
			}
			dumps = append(dumps, dump.Name())

			// Swap out the noop logger to the standard tracer
			writer = bufio.NewWriter(dump)
			vmConf = vm.Config{
				Tracer:                  logger.NewJSONLogger(&logConfig, writer),
				EnablePreimageRecording: true,
			}
		}
		// Execute the transaction and flush any traces to disk
		if vmConfig != nil {
			vmConf.ExecType = vmConfig.ExecType
			vmConf.Transcript = vmConfig.Transcript
		}
		vmenv := vm.NewEVM(vmctx, txContext, statedb, chainConfig, vmConf)
		statedb.SetTxContext(tx.Hash(), i)
		_, err = core.ApplyMessage(vmenv, msg, new(core.GasPool).AddGas(msg.GasLimit))
		if writer != nil {
			writer.Flush()
		}
		if dump != nil {
			dump.Close()
			log.Info("Wrote standard trace", "file", dump.Name())
		}
		if err != nil {
			return dumps, err
		}

		// Update the transcript in vmConfig with the updated transcript from vmenv
		if vmConfig != nil {
			vmConfig.Transcript = vmenv.Config.Transcript
		}

		// Finalize the state so any modifications are written to the trie
		// Only delete empty objects if EIP158/161 (a.k.a Spurious Dragon) is in effect
		statedb.Finalise(vmenv.ChainConfig().IsEIP158(block.Number()))

		// If we've traced the transaction we were looking for, abort
		if tx.Hash() == txHash {
			break
		}
	}
	return dumps, nil
}

// containsTx reports whether the transaction with a certain hash
// is contained within the specified block.
func containsTx(block *types.Block, hash common.Hash) bool {
	for _, tx := range block.Transactions() {
		if tx.Hash() == hash {
			return true
		}
	}
	return false
}

// TraceTransaction returns the structured logs created during the execution of EVM
// and returns them as a JSON object.
func (api *API) TraceTransaction(ctx context.Context, hash common.Hash, config *TraceConfig) (interface{}, error) {
	tx, blockHash, blockNumber, index, err := api.backend.GetTransaction(ctx, hash)
	if err != nil {
		return nil, err
	}
	// Only mined txes are supported
	if tx == nil {
		return nil, errTxNotFound
	}
	// It shouldn't happen in practice.
	if blockNumber == 0 {
		return nil, errors.New("genesis is not traceable")
	}
	reexec := defaultTraceReexec
	if config != nil && config.Reexec != nil {
		reexec = *config.Reexec
	}
	block, err := api.blockByNumberAndHash(ctx, rpc.BlockNumber(blockNumber), blockHash)
	if err != nil {
		return nil, err
	}

	// Create vm.Config with transcript if available
	// Require transcript for tracing (no fallback)
	vmConfig, err := api.createVMConfigWithTranscript(block)
	if err != nil {
		return nil, err
	}

	msg, vmctx, statedb, release, err := api.backend.StateAtTransaction(ctx, block, int(index), reexec, vmConfig)
	log.Info("vmConfig", "execType", vmConfig.ExecType, "transcript length", len(vmConfig.Transcript))
	if err != nil {
		return nil, err
	}
	defer release()

	txctx := &Context{
		BlockHash:   blockHash,
		BlockNumber: block.Number(),
		TxIndex:     int(index),
		TxHash:      hash,
	}
	return api.traceTx(ctx, msg, txctx, vmctx, statedb, config, block, vmConfig)
}

// TraceCall lets you trace a given eth_call. It collects the structured logs
// created during the execution of EVM if the given transaction was added on
// top of the provided block and returns them as a JSON object.
func (api *API) TraceCall(ctx context.Context, args ethapi.TransactionArgs, blockNrOrHash rpc.BlockNumberOrHash, config *TraceCallConfig) (interface{}, error) {
	// Try to retrieve the specified block
	var (
		err   error
		block *types.Block
	)
	if hash, ok := blockNrOrHash.Hash(); ok {
		block, err = api.blockByHash(ctx, hash)
	} else if number, ok := blockNrOrHash.Number(); ok {
		if number == rpc.PendingBlockNumber {
			// We don't have access to the miner here. For tracing 'future' transactions,
			// it can be done with block- and state-overrides instead, which offers
			// more flexibility and stability than trying to trace on 'pending', since
			// the contents of 'pending' is unstable and probably not a true representation
			// of what the next actual block is likely to contain.
			return nil, errors.New("tracing on top of pending is not supported")
		}
		block, err = api.blockByNumber(ctx, number)
	} else {
		return nil, errors.New("invalid arguments; neither block nor hash specified")
	}
	if err != nil {
		return nil, err
	}
	// try to recompute the state
	reexec := defaultTraceReexec
	if config != nil && config.Reexec != nil {
		reexec = *config.Reexec
	}
	statedb, release, err := api.backend.StateAtBlock(ctx, block, reexec, nil, true, false)
	if err != nil {
		return nil, err
	}
	defer release()

	vmctx := core.NewEVMBlockContext(block.Header(), api.chainContext(ctx), nil)
	// Apply the customization rules if required.
	if config != nil {
		if err := config.StateOverrides.Apply(statedb); err != nil {
			return nil, err
		}
		config.BlockOverrides.Apply(&vmctx)
	}
	// Execute the trace
	msg, err := args.ToMessage(api.backend.RPCGasCap(), block.BaseFee())
	if err != nil {
		return nil, err
	}

	var traceConfig *TraceConfig
	if config != nil {
		traceConfig = &config.TraceConfig
	}
	return api.traceTx(ctx, msg, new(Context), vmctx, statedb, traceConfig, block, nil)
}

// traceTx configures a new tracer according to the provided configuration, and
// executes the given message in the provided environment. The return value will
// be tracer dependent.
func (api *API) traceTx(ctx context.Context, message *core.Message, txctx *Context, vmctx vm.BlockContext, statedb *state.StateDB, config *TraceConfig, block *types.Block, vmConfig *vm.Config) (interface{}, error) {
	var (
		tracer    Tracer
		err       error
		timeout   = defaultTraceTimeout
		txContext = core.NewEVMTxContext(message)
	)
	if config == nil {
		config = &TraceConfig{}
	}
	// Default tracer is the struct logger
	tracer = logger.NewStructLogger(config.Config)
	if config.Tracer != nil {
		tracer, err = DefaultDirectory.New(*config.Tracer, txctx, config.TracerConfig)
		if err != nil {
			return nil, err
		}
	}

	// Set up VM config with transcript if available
	var vmConf vm.Config
	vmConf.Tracer = tracer
	vmConf.NoBaseFee = true

	// Prefer passed vmConfig if valid; otherwise derive from block
	src := vmConfig
	if src == nil || src.ExecType == nil || src.Transcript == nil || len(src.Transcript) == 0 {
		var err error
		src, err = api.createVMConfigWithTranscript(block)
		if err != nil { // no transcript → refuse to trace
			return nil, ErrTraceRequiresTranscript
		}
	}
	vmConf.ExecType = src.ExecType
	vmConf.Transcript = src.Transcript

	vmenv := vm.NewEVM(vmctx, txContext, statedb, api.backend.ChainConfig(), vmConf)

	// Define a meaningful timeout of a single transaction trace
	if config.Timeout != nil {
		if timeout, err = time.ParseDuration(*config.Timeout); err != nil {
			return nil, err
		}
	}
	deadlineCtx, cancel := context.WithTimeout(ctx, timeout)
	go func() {
		<-deadlineCtx.Done()
		if errors.Is(deadlineCtx.Err(), context.DeadlineExceeded) {
			tracer.Stop(errors.New("execution timeout"))
			// Stop evm execution. Note cancellation is not necessarily immediate.
			vmenv.Cancel()
		}
	}()
	defer cancel()

	// Call Prepare to clear out the statedb access list
	statedb.SetTxContext(txctx.TxHash, txctx.TxIndex)
	if _, err = core.ApplyMessage(vmenv, message, new(core.GasPool).AddGas(message.GasLimit)); err != nil {
		return nil, fmt.Errorf("tracing failed: %w", err)
	}
	// Update the vmConfig with the transcript from the vmenv
	if vmConfig != nil {
		vmConfig.Transcript = vmenv.Config.Transcript
	}
	return tracer.GetResult()
}

// APIs return the collection of RPC services the tracer package offers.
func APIs(backend Backend) []rpc.API {
	// Append all the local APIs and return
	return []rpc.API{
		{
			Namespace: "debug",
			Service:   NewAPI(backend),
		},
	}
}

// overrideConfig returns a copy of original with forks enabled by override enabled,
// along with a boolean that indicates whether the copy is canonical (equivalent to the original).
// Note: the Clique-part is _not_ deep copied
func overrideConfig(original *params.ChainConfig, override *params.ChainConfig) (*params.ChainConfig, bool) {
	copy := new(params.ChainConfig)
	*copy = *original
	canon := true

	// Apply forks (after Berlin) to the copy.
	if block := override.BerlinBlock; block != nil {
		copy.BerlinBlock = block
		canon = false
	}
	if block := override.LondonBlock; block != nil {
		copy.LondonBlock = block
		canon = false
	}
	if block := override.ArrowGlacierBlock; block != nil {
		copy.ArrowGlacierBlock = block
		canon = false
	}
	if block := override.GrayGlacierBlock; block != nil {
		copy.GrayGlacierBlock = block
		canon = false
	}
	if block := override.MergeNetsplitBlock; block != nil {
		copy.MergeNetsplitBlock = block
		canon = false
	}
	if timestamp := override.ShanghaiTime; timestamp != nil {
		copy.ShanghaiTime = timestamp
		canon = false
	}
	if timestamp := override.CancunTime; timestamp != nil {
		copy.CancunTime = timestamp
		canon = false
	}
	if timestamp := override.PragueTime; timestamp != nil {
		copy.PragueTime = timestamp
		canon = false
	}
	if timestamp := override.VerkleTime; timestamp != nil {
		copy.VerkleTime = timestamp
		canon = false
	}

	return copy, canon
}
