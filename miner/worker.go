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
	"errors"
	"fmt"
	"math/big"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/consensus/co2"
	"github.com/ethereum/go-ethereum/consensus/misc/eip1559"
	"github.com/ethereum/go-ethereum/consensus/misc/eip4844"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/txpool"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/event"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/trie"
)

const (
	// resultQueueSize is the size of channel listening to sealing result.
	resultQueueSize = 10

	// txChanSize is the size of channel listening to NewTxsEvent.
	// The number is referenced from the size of tx pool.
	txChanSize = 4096

	// chainHeadChanSize is the size of channel listening to ChainHeadEvent.
	chainHeadChanSize = 10

	// resubmitAdjustChanSize is the size of resubmitting interval adjustment channel.
	resubmitAdjustChanSize = 10

	// minRecommitInterval is the minimal time interval to recreate the sealing block with
	// any newly arrived transactions.
	minRecommitInterval = 1 * time.Second

	// maxRecommitInterval is the maximum time interval to recreate the sealing block with
	// any newly arrived transactions.
	maxRecommitInterval = 15 * time.Second

	// intervalAdjustRatio is the impact a single interval adjustment has on sealing work
	// resubmitting interval.
	intervalAdjustRatio = 0.1

	// intervalAdjustBias is applied during the new resubmit interval calculation in favor of
	// increasing upper limit or decreasing lower limit so that the limit can be reachable.
	intervalAdjustBias = 200 * 1000.0 * 1000.0

	// staleThreshold is the maximum depth of the acceptable stale block.
	staleThreshold = 7

	// StaleBlockCheckInterval is the interval (in seconds) to check for stale sequencer blocks
	StaleBlockCheckInterval = 30
)

var (
	errBlockInterruptedByNewHead  = errors.New("new head arrived while building block")
	errBlockInterruptedByRecommit = errors.New("recommit interrupt while building block")
	errBlockInterruptedByTimeout  = errors.New("timeout while building block")
)

// environment is the worker's current environment and holds all
// information of the sealing block generation.
type environment struct {
	signer   types.Signer
	state    *state.StateDB // apply state changes here
	tcount   int            // tx count in cycle
	gasPool  *core.GasPool  // available gas used to pack transactions
	coinbase common.Address

	header   *types.Header
	txs      []*types.Transaction
	receipts []*types.Receipt
	sidecars []*types.BlobTxSidecar
	blobs    int
}

// copy creates a deep copy of environment.
func (env *environment) copy() *environment {
	cpy := &environment{
		signer:   env.signer,
		state:    env.state.Copy(),
		tcount:   env.tcount,
		coinbase: env.coinbase,
		header:   types.CopyHeader(env.header),
		receipts: copyReceipts(env.receipts),
	}
	if env.gasPool != nil {
		gasPool := *env.gasPool
		cpy.gasPool = &gasPool
	}
	cpy.txs = make([]*types.Transaction, len(env.txs))
	copy(cpy.txs, env.txs)

	cpy.sidecars = make([]*types.BlobTxSidecar, len(env.sidecars))
	copy(cpy.sidecars, env.sidecars)

	return cpy
}

// discard terminates the background prefetcher go-routine. It should
// always be called for all created environment instances otherwise
// the go-routine leak can happen.
func (env *environment) discard() {
	if env.state == nil {
		return
	}
	env.state.StopPrefetcher()
}

// task contains all information for consensus engine sealing and result submitting.
type task struct {
	receipts  []*types.Receipt
	state     *state.StateDB
	block     *types.Block
	createdAt time.Time
}

const (
	commitInterruptNone int32 = iota
	commitInterruptNewHead
	commitInterruptResubmit
	commitInterruptTimeout
)

// newWorkReq represents a request for new sealing work submitting with relative interrupt notifier.
type newWorkReq struct {
	interrupt *atomic.Int32
	timestamp int64
}

// newPayloadResult is the result of payload generation.
type newPayloadResult struct {
	err      error
	block    *types.Block
	fees     *big.Int               // total block fees
	sidecars []*types.BlobTxSidecar // collected blobs of blob transactions
}

// getWorkReq represents a request for getting a new sealing work with provided parameters.
type getWorkReq struct {
	params *generateParams
	result chan *newPayloadResult // non-blocking channel
}

// intervalAdjust represents a resubmitting interval adjustment.
type intervalAdjust struct {
	ratio float64
	inc   bool
}

type executionMetrics struct {
	executionStart        time.Time
	executionEnd          time.Time
	executionTime         time.Duration
	txNum                 uint64
	txExecutionTimes      []time.Duration
	txExecutionTimeByHash map[common.Hash]time.Duration
	totalTxExecutionTime  time.Duration
}

func newBlockExecutionMetrics() *executionMetrics {
	return &executionMetrics{
		executionStart:        time.Time{},
		executionEnd:          time.Time{},
		executionTime:         0,
		txNum:                 0,
		txExecutionTimes:      []time.Duration{},
		txExecutionTimeByHash: map[common.Hash]time.Duration{},
		totalTxExecutionTime:  0,
	}
}

// worker is the main object which takes care of submitting new work to consensus engine
// and gathering the sealing result.
type worker struct {
	config      *Config
	chainConfig *params.ChainConfig
	engine      consensus.Engine
	eth         Backend
	chain       *core.BlockChain

	// Feeds
	pendingLogsFeed event.Feed

	// Subscriptions
	mux          *event.TypeMux
	txsCh        chan core.NewTxsEvent
	txsSub       event.Subscription
	chainHeadCh  chan core.ChainHeadEvent
	chainHeadSub event.Subscription

	// Channels
	newWorkCh          chan *newWorkReq
	getWorkCh          chan *getWorkReq
	taskCh             chan *task
	resultCh           chan *types.Block
	startCh            chan struct{}
	exitCh             chan struct{}
	resubmitIntervalCh chan time.Duration
	resubmitAdjustCh   chan *intervalAdjust

	wg sync.WaitGroup

	current *environment // An environment for current running cycle.

	mu       sync.RWMutex // The lock used to protect the coinbase and extra fields
	coinbase common.Address
	extra    []byte

	pendingMu    sync.RWMutex
	pendingTasks map[common.Hash]*task

	snapshotMu       sync.RWMutex // The lock used to protect the snapshots below
	snapshotBlock    *types.Block
	snapshotReceipts types.Receipts
	snapshotState    *state.StateDB

	// atomic status counters
	running atomic.Bool  // The indicator whether the consensus engine is running or not.
	newTxs  atomic.Int32 // New arrival transaction count since last sealing work submitting.
	syncing atomic.Bool  // The indicator whether the node is still syncing.

	// newpayloadTimeout is the maximum timeout allowance for creating payload.
	// The default value is 2 seconds but node operator can set it to arbitrary
	// large value. A large timeout allowance may cause Geth to fail creating
	// a non-empty payload within the specified time and eventually miss the slot
	// in case there are some computation expensive transactions in txpool.
	newpayloadTimeout time.Duration

	// recommit is the time interval to re-create sealing work or to re-build
	// payload in proof-of-stake stage.
	recommit time.Duration

	// External functions
	isLocalBlock func(header *types.Header) bool // Function used to determine whether the specified block is mined by local miner.

	// Test hooks
	newTaskHook  func(*task)                        // Method to call upon receiving a new sealing task.
	skipSealHook func(*task) bool                   // Method to decide whether skipping the sealing.
	fullTaskHook func()                             // Method to call before pushing the full sealing task.
	resubmitHook func(time.Duration, time.Duration) // Method to call upon updating resubmitting interval.

	lastBlockNumMu      sync.RWMutex // The lock used to protect the lastSentBlockNumber field
	lastSentBlockNumber *big.Int
}

func newWorker(config *Config, chainConfig *params.ChainConfig, engine consensus.Engine, eth Backend, mux *event.TypeMux, isLocalBlock func(header *types.Header) bool, init bool) *worker {
	worker := &worker{
		config:              config,
		chainConfig:         chainConfig,
		engine:              engine,
		eth:                 eth,
		chain:               eth.BlockChain(),
		mux:                 mux,
		isLocalBlock:        isLocalBlock,
		coinbase:            config.Etherbase,
		extra:               config.ExtraData,
		pendingTasks:        make(map[common.Hash]*task),
		txsCh:               make(chan core.NewTxsEvent, txChanSize),
		chainHeadCh:         make(chan core.ChainHeadEvent, chainHeadChanSize),
		newWorkCh:           make(chan *newWorkReq),
		getWorkCh:           make(chan *getWorkReq),
		taskCh:              make(chan *task),
		resultCh:            make(chan *types.Block, resultQueueSize),
		startCh:             make(chan struct{}, 1),
		exitCh:              make(chan struct{}),
		resubmitIntervalCh:  make(chan time.Duration),
		resubmitAdjustCh:    make(chan *intervalAdjust, resubmitAdjustChanSize),
		lastSentBlockNumber: big.NewInt(0),
	}
	// Subscribe for transaction insertion events (whether from network or resurrects)
	worker.txsSub = eth.TxPool().SubscribeTransactions(worker.txsCh, true)
	// Subscribe events for blockchain
	worker.chainHeadSub = eth.BlockChain().SubscribeChainHeadEvent(worker.chainHeadCh)

	// Sanitize recommit interval if the user-specified one is too short.
	recommit := worker.config.Recommit
	if recommit < minRecommitInterval {
		log.Warn("Sanitizing miner recommit interval", "provided", recommit, "updated", minRecommitInterval)
		recommit = minRecommitInterval
	}
	worker.recommit = recommit

	// Sanitize the timeout config for creating payload.
	newpayloadTimeout := worker.config.NewPayloadTimeout
	if newpayloadTimeout == 0 {
		log.Warn("Sanitizing new payload timeout to default", "provided", newpayloadTimeout, "updated", DefaultConfig.NewPayloadTimeout)
		newpayloadTimeout = DefaultConfig.NewPayloadTimeout
	}
	if newpayloadTimeout < time.Millisecond*100 {
		log.Warn("Low payload timeout may cause high amount of non-full blocks", "provided", newpayloadTimeout, "default", DefaultConfig.NewPayloadTimeout)
	}
	worker.newpayloadTimeout = newpayloadTimeout

	worker.wg.Add(4)
	go worker.mainLoop()
	go worker.newWorkLoop(recommit)
	go worker.resultLoop()
	go worker.taskLoop()

	// Submit first work to initialize pending state.
	if init {
		worker.startCh <- struct{}{}
	}

	return worker
}

// setEtherbase sets the etherbase used to initialize the block coinbase field.
func (w *worker) setEtherbase(addr common.Address) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.coinbase = addr
}

// etherbase retrieves the configured etherbase address.
func (w *worker) etherbase() common.Address {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.coinbase
}

func (w *worker) setGasCeil(ceil uint64) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.config.GasCeil = ceil
}

// setExtra sets the content used to initialize the block extra field.
func (w *worker) setExtra(extra []byte) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.extra = extra
}

// setRecommitInterval updates the interval for miner sealing work recommitting.
func (w *worker) setRecommitInterval(interval time.Duration) {
	select {
	case w.resubmitIntervalCh <- interval:
	case <-w.exitCh:
	}
}

// pending returns the pending state and corresponding block. The returned
// values can be nil in case the pending block is not initialized.
func (w *worker) pending() (*types.Block, *state.StateDB) {
	w.snapshotMu.RLock()
	defer w.snapshotMu.RUnlock()
	if w.snapshotState == nil {
		return nil, nil
	}
	return w.snapshotBlock, w.snapshotState.Copy()
}

// pendingBlock returns pending block. The returned block can be nil in case the
// pending block is not initialized.
func (w *worker) pendingBlock() *types.Block {
	w.snapshotMu.RLock()
	defer w.snapshotMu.RUnlock()
	return w.snapshotBlock
}

// pendingBlockAndReceipts returns pending block and corresponding receipts.
// The returned values can be nil in case the pending block is not initialized.
func (w *worker) pendingBlockAndReceipts() (*types.Block, types.Receipts) {
	w.snapshotMu.RLock()
	defer w.snapshotMu.RUnlock()
	return w.snapshotBlock, w.snapshotReceipts
}

// start sets the running status as 1 and triggers new work submitting.
func (w *worker) start() {
	log.Debug("Worker start method called")
	if c, ok := w.engine.(*co2.Co2); ok {
		if c.IsValidator() {
			log.Warn("Worker is not allowed to start in validator mode, canceling start")
			return
		}
	}
	w.running.Store(true)
	w.startCh <- struct{}{}
}

// stop sets the running status as 0.
func (w *worker) stop() {
	log.Debug("Worker stop method called")
	w.running.Store(false)
}

// isRunning returns an indicator whether worker is running or not.
func (w *worker) isRunning() bool {
	return w.running.Load()
}

// close terminates all background threads maintained by the worker.
// Note the worker does not support being closed multiple times.
func (w *worker) close() {
	log.Debug("Worker close method called")
	w.running.Store(false)
	close(w.exitCh)
	w.wg.Wait()
}

func checkStaleSequencerBlock(c *co2.Co2, header *types.Header) bool {
	log.Debug("Checking for a stale sequencer (pseudo-state) block")
	return (!c.SyncInProgress() &&
		header.Number.Cmp(common.Big0) > 0 &&
		c.IsHeaderSignedBySequencer(header))
}

func (w *worker) reTriggerBlockExecution(c *co2.Co2, header *types.Header) {
	log.Debug("Re-triggering block execution", "hash", header.Hash().Hex(), "number", header.Number.Uint64())
	block := w.chain.GetBlockByHash(header.Hash())
	if block != nil {
		c.GetSequencerBlockChannel() <- block
	} else {
		log.Warn("Block not found for re-triggering", "hash", header.Hash().Hex())
	}
}

// recalcRecommit recalculates the resubmitting interval upon feedback.
func recalcRecommit(minRecommit, prev time.Duration, target float64, inc bool) time.Duration {
	var (
		prevF = float64(prev.Nanoseconds())
		next  float64
	)
	if inc {
		next = prevF*(1-intervalAdjustRatio) + intervalAdjustRatio*(target+intervalAdjustBias)
		max := float64(maxRecommitInterval.Nanoseconds())
		if next > max {
			next = max
		}
	} else {
		next = prevF*(1-intervalAdjustRatio) + intervalAdjustRatio*(target-intervalAdjustBias)
		min := float64(minRecommit.Nanoseconds())
		if next < min {
			next = min
		}
	}
	return time.Duration(int64(next))
}

// newWorkLoop is a standalone goroutine to submit new sealing work upon received events.
func (w *worker) newWorkLoop(recommit time.Duration) {
	defer w.wg.Done()
	var (
		interrupt   *atomic.Int32
		minRecommit = recommit // minimal resubmit interval specified by user.
		timestamp   int64      // timestamp for each round of sealing.
	)

	timer := time.NewTimer(0)
	defer timer.Stop()
	<-timer.C // discard the initial tick

	// commit aborts in-flight transaction execution with given signal and resubmits a new one.
	commit := func(s int32) {
		if interrupt != nil {
			interrupt.Store(s)
		}
		interrupt = new(atomic.Int32)
		select {
		case w.newWorkCh <- &newWorkReq{interrupt: interrupt, timestamp: timestamp}:
		case <-w.exitCh:
			return
		}
		timer.Reset(recommit)
		w.newTxs.Store(0)
	}
	// clearPending cleans the stale pending tasks.
	clearPending := func(number uint64) {
		w.pendingMu.Lock()
		for h, t := range w.pendingTasks {
			if t.block.NumberU64()+staleThreshold <= number {
				delete(w.pendingTasks, h)
			}
		}
		w.pendingMu.Unlock()
	}

	for {
		select {
		case <-w.startCh:
			clearPending(w.chain.CurrentBlock().Number.Uint64())
			timestamp = time.Now().Unix()
			commit(commitInterruptNewHead)

		case head := <-w.chainHeadCh:
			clearPending(head.Block.NumberU64())
			timestamp = time.Now().Unix()
			commit(commitInterruptNewHead)

		case <-timer.C:
			// If sealing is running resubmit a new work cycle periodically to pull in
			// higher priced transactions. Disable this overhead for pending blocks.
			if w.isRunning() && (w.chainConfig.Clique == nil || w.chainConfig.Clique.Period > 0) {
				// Short circuit if no new transaction arrives.
				if w.newTxs.Load() == 0 {
					timer.Reset(recommit)
					continue
				}
				commit(commitInterruptResubmit)
			}

		case interval := <-w.resubmitIntervalCh:
			// Adjust resubmit interval explicitly by user.
			if interval < minRecommitInterval {
				log.Warn("Sanitizing miner recommit interval", "provided", interval, "updated", minRecommitInterval)
				interval = minRecommitInterval
			}
			log.Info("Miner recommit interval update", "from", minRecommit, "to", interval)
			minRecommit, recommit = interval, interval

			if w.resubmitHook != nil {
				w.resubmitHook(minRecommit, recommit)
			}

		case adjust := <-w.resubmitAdjustCh:
			// Adjust resubmit interval by feedback.
			if adjust.inc {
				before := recommit
				target := float64(recommit.Nanoseconds()) / adjust.ratio
				recommit = recalcRecommit(minRecommit, recommit, target, true)
				log.Trace("Increase miner recommit interval", "from", before, "to", recommit)
			} else {
				before := recommit
				recommit = recalcRecommit(minRecommit, recommit, float64(minRecommit.Nanoseconds()), false)
				log.Trace("Decrease miner recommit interval", "from", before, "to", recommit)
			}

			if w.resubmitHook != nil {
				w.resubmitHook(minRecommit, recommit)
			}

		case <-w.exitCh:
			return
		}
	}
}

// mainLoop is responsible for generating and submitting sealing work based on
// the received event. It can support two modes: automatically generate task and
// submit it or return task according to given parameters for various proposes.
func (w *worker) mainLoop() {
	co2Engine, isCo2 := w.engine.(*co2.Co2)
	if isCo2 && co2Engine.IsExecutor() {
		vm.CreateMPCService()
	}

	defer w.wg.Done()
	defer w.txsSub.Unsubscribe()
	defer w.chainHeadSub.Unsubscribe()
	defer func() {
		if w.current != nil {
			w.current.discard()
		}
	}()

	var triggerCh chan *types.Block

	// We will periodically check for stale sequencer (pseudo state) blocks and re-trigger them.
	// This check is only for executors in archival mode since if they don't sync
	// after crash recovery they will not be able to re-trigger the block
	var ticker *time.Ticker
	tickerChan := make(<-chan time.Time)
	stopTicker := func() {
		if ticker != nil {
			log.Debug("Stopping ticker for stale block check")
			ticker.Stop()
		}
		ticker = nil
	}

	if isCo2 {
		triggerCh = co2Engine.GetSequencerBlockChannel()
		if co2Engine.IsExecutor() && co2Engine.IsArchival() {
			ticker = time.NewTicker(StaleBlockCheckInterval * time.Second)
			tickerChan = ticker.C
		}
	}

	for {
		select {
		case <-tickerChan:
			log.Debug("Ticker ticked, checking for a stale sequencer block")
			header := w.chain.CurrentBlock()
			if header == nil {
				log.Warn("Current block (header) is nil")
				continue
			}
			if checkStaleSequencerBlock(co2Engine, header) {
				w.reTriggerBlockExecution(co2Engine, header)
			}
		case block := <-triggerCh:
			stopTicker()
			log.Debug("Sequencer block as chain head received for evaluation on the trigger channel",
				"hash", block.Hash(),
				"number", block.Number(),
				"blocks in channel", len(triggerCh))
			latestSavedBlock := w.chain.CurrentBlock()
			if latestSavedBlock == nil {
				log.Warn("Current block (header) is nil")
			} else {
				if block.Number().Cmp(latestSavedBlock.Number) < 1 && latestSavedBlock.Hash() != block.Hash() {
					log.Warn("Skipping block evaluation as it is not newer than the last saved block",
						"block_number", block.NumberU64(), "last_saved_block_number", latestSavedBlock.Number.Uint64())
					continue
				}
			}

			for co2Engine.SyncInProgress() || !w.isRunning() {
				log.Trace("Waiting for worker", "syncing", co2Engine.SyncInProgress(), "running", w.isRunning())
				time.Sleep(time.Millisecond * 100)
			}
			log.Debug("Not syncing")
			if block.NumberU64() == 1 {
				log.Debug("Setting initial MPC status for 1st block")
				vm.SetInitialMPCStatus()
			} else {
				prevBlock := w.chain.GetBlock(block.ParentHash(), block.NumberU64()-1)
				prevTranscript := prevBlock.GetTranscript()
				prevStatus, err := prevTranscript.GetMPCStatus()
				if err != nil {
					panic(fmt.Sprintf("Error getting MPC status from previous block: %s", err.Error()))
				}
				log.Debug("Setting MPC status from previous block", "parent's number", prevBlock.NumberU64())
				err = vm.SetMPCStatus(prevStatus)
				if err != nil {
					log.Crit("Error setting MPC status", "error", err)
					// report block
					log.Crit("Reporting block", "block_number", block.NumberU64(), "block_hash",
						block.Hash().Hex(), "difficulty", block.Difficulty().Uint64(),
						"timestamp", block.Time, "Etherbase", w.etherbase().Hex(),
						"transcript", block.GetTranscript())
					panic(fmt.Sprintf("Error setting MPC status: %s", err.Error()))
				}
			}
			ok, prevState := co2Engine.NextExecutionStep(co2.GeneratingExecutorBlock)
			if !ok {
				log.Warn("Skipped Execution Step", "current step", co2Engine.GetExecutionState(), "previous step", prevState)
			}
			err := w.commitExecutorWork(block)
			if err != nil {
				log.Warn("Error committing executor work", "error", err)
				if !errors.Is(err, core.ErrMPCRestartBlock) {
					panic(fmt.Sprintf("Extremely bad! error: %s", err.Error()))
				}
			}
			log.Debug("Pseudo state -> Canonical state block evaluation completed")

		case req := <-w.newWorkCh:
			if isCo2 {
				currentHeader := w.chain.CurrentBlock()
				if w.syncing.Load() || !co2Engine.IsSequencer() || !co2Engine.ShouldSequencerAddBlock(currentHeader, w.etherbase()) {
					continue
				}
				log.Debug("Sequencer generating new pseudo state block. Current chain head details:",
					"number", currentHeader.Number.Int64(), "hash", currentHeader.Hash().Hex(), "difficulty",
					currentHeader.Difficulty.Int64(), "timestamp", currentHeader.Time, "Etherbase", w.etherbase().Hex())
			}
			log.Debug("Starting new work", "timestamp", req.timestamp)
			w.commitWork(req.interrupt, req.timestamp)

		case req := <-w.getWorkCh:
			log.Debug("Worker getWorkCh received signal", "params", req.params)
			req.result <- w.generateWork(req.params)

		case ev := <-w.txsCh:
			log.Debug("Worker txsCh Got a new transaction", "count", len(ev.Txs))
			// Apply transactions to the pending state if we're not sealing
			//
			// Note all transactions received may not be continuous with transactions
			// already included in the current sealing block. These transactions will
			// be automatically eliminated.
			if !w.isRunning() && w.current != nil {
				log.Debug("Applying transactions to pending state", "count", len(ev.Txs))
				// If block is already full, abort
				if gp := w.current.gasPool; gp != nil && gp.Gas() < params.TxGas {
					continue
				}
				txs := make(map[common.Address][]*txpool.LazyTransaction, len(ev.Txs))
				for _, tx := range ev.Txs {
					acc, _ := types.Sender(w.current.signer, tx)
					txs[acc] = append(txs[acc], &txpool.LazyTransaction{
						Pool:      w.eth.TxPool(), // We don't know where this came from, yolo resolve from everywhere
						Hash:      tx.Hash(),
						Tx:        nil, // Do *not* set this! We need to resolve it later to pull blobs in
						Time:      tx.Time(),
						GasFeeCap: tx.GasFeeCap(),
						GasTipCap: tx.GasTipCap(),
						Gas:       tx.Gas(),
						BlobGas:   tx.BlobGas(),
					})
				}
				txset := newTransactionsByPriceAndNonce(w.current.signer, txs, w.current.header.BaseFee)
				tcount := w.current.tcount
				w.commitTransactions(w.current, txset, nil)

				// Only update the snapshot if any new transactions were added
				// to the pending block
				if tcount != w.current.tcount {
					log.Debug("Updating snapshot with new transactions")
					w.updateSnapshot(w.current)
				}
			} else {
				// Special case, if the consensus engine is 0 period clique(dev mode),
				// submit sealing work here since all empty submission will be rejected
				// by clique. Of course the advance sealing(empty submission) is disabled.
				if w.chainConfig.Clique != nil && w.chainConfig.Clique.Period == 0 {
					w.commitWork(nil, time.Now().Unix())
				}
			}
			w.newTxs.Add(int32(len(ev.Txs)))

		// System stopped
		case <-w.exitCh:
			log.Warn("Worker EXIT channel received signal")
			return
		case <-w.txsSub.Err():
			log.Error("Transaction subscription failed")
			return
		case <-w.chainHeadSub.Err():
			log.Error("Chain head subscription failed")
			return
		}
	}
}

// taskLoop is a standalone goroutine to fetch sealing task from the generator and
// push them to consensus engine.
func (w *worker) taskLoop() {
	defer w.wg.Done()
	var (
		stopCh chan struct{}
		prev   common.Hash
	)

	// interrupt aborts the in-flight sealing task.
	interrupt := func() {
		if stopCh != nil {
			log.Debug("Interrupting previous sealing task (this is normal)")
			close(stopCh)
			stopCh = nil
		}
	}
	for {
		select {
		case task := <-w.taskCh:
			log.Debug("Got a task on the task channel: ", "block number", task.block.NumberU64(),
				"block hash", task.block.Hash().Hex(), "block difficulty", task.block.Difficulty().Uint64())
			if w.newTaskHook != nil {
				w.newTaskHook(task)
			}
			// Reject duplicate sealing work due to resubmitting.
			sealHash := w.engine.SealHash(task.block.Header())
			log.Debug("Seal hash for task", "hash", sealHash)
			if sealHash == prev {
				if c, ok := w.engine.(*co2.Co2); ok {
					if c.IsExecutor() && !c.ShouldRejectDuplicateHash {
						c.ShouldRejectDuplicateHash = true
					} else {
						continue
					}

				} else {
					continue
				}
			}
			// Interrupt previous sealing operation
			interrupt()
			stopCh, prev = make(chan struct{}), sealHash

			if w.skipSealHook != nil && w.skipSealHook(task) {
				log.Debug("Skipping sealing task")
				continue
			}
			w.pendingMu.Lock()
			w.pendingTasks[sealHash] = task
			w.pendingMu.Unlock()

			if err := w.engine.Seal(w.chain, task.block, w.resultCh, stopCh); err != nil {
				log.Error("Block sealing failed", "err", err)
				w.pendingMu.Lock()
				delete(w.pendingTasks, sealHash)
				w.pendingMu.Unlock()
			}
		case <-w.exitCh:
			log.Debug("Worker taskLoop received exit signal")
			interrupt()
			return
		}
	}
}

// resultLoop is a standalone goroutine to handle sealing result submitting
// and flush relative data to the database.
func (w *worker) resultLoop() {
	defer w.wg.Done()
	for {
		select {
		case block := <-w.resultCh:
			// Short circuit when receiving empty result.
			if block == nil {
				log.Error("Received empty block result")
				continue
			}
			log.Debug("got a block on the results channel", "block number", block.NumberU64(), "block hash", block.Hash().Hex())
			// Short circuit when receiving duplicate result caused by resubmitting.
			if w.chain.HasBlock(block.Hash(), block.NumberU64()) {
				log.Debug("Skipping duplicate block result", "block number", block.NumberU64(), "block hash", block.Hash().Hex())
				continue
			}
			var (
				sealhash = w.engine.SealHash(block.Header())
				hash     = block.Hash()
			)
			w.pendingMu.RLock()
			task, exist := w.pendingTasks[sealhash]
			log.Debug("Checking for pending task", "sealhash", sealhash, "hash", hash, "exist", exist)
			w.pendingMu.RUnlock()
			if !exist {
				log.Error("Block found but no relative pending task", "number", block.Number(), "sealhash", sealhash, "hash", hash)
				continue
			}
			// Different block could share same sealhash, deep copy here to prevent write-write conflict.
			var (
				receipts = make([]*types.Receipt, len(task.receipts))
				logs     []*types.Log
			)
			for i, taskReceipt := range task.receipts {
				receipt := new(types.Receipt)
				receipts[i] = receipt
				*receipt = *taskReceipt

				// add block location fields
				receipt.BlockHash = hash
				receipt.BlockNumber = block.Number()
				receipt.TransactionIndex = uint(i)

				// Update the block hash in all logs since it is now available and not when the
				// receipt/log of individual transactions were created.
				receipt.Logs = make([]*types.Log, len(taskReceipt.Logs))
				for i, taskLog := range taskReceipt.Logs {
					log := new(types.Log)
					receipt.Logs[i] = log
					*log = *taskLog
					log.BlockHash = hash
				}
				logs = append(logs, receipt.Logs...)
			}
			w.lastBlockNumMu.Lock()
			if block.Number().Cmp(w.lastSentBlockNumber) < 1 {
				log.Warn("Skipping block submission as it is older than the last sent block",
					"block_number", block.NumberU64(), "last_sent_block_number", w.lastSentBlockNumber)
				w.lastBlockNumMu.Unlock()
				continue
			}
			previousLastBlockNumber := w.lastSentBlockNumber
			w.lastSentBlockNumber = block.Number()
			w.lastBlockNumMu.Unlock()
			co2Engine, isCO2 := w.engine.(*co2.Co2)
			if isCO2 {
				if co2Engine.IsExecutor() {
					if len(block.GetTranscript()) == 0 {
						log.Warn("Executor block has no transcript, discarding it", "block_number", block.NumberU64())
						continue
					}
				}
			}

			// Commit block and state to database.
			_, err := w.chain.WriteBlockAndSetHead(block, receipts, logs, task.state, true)
			if err != nil {
				log.Error("Failed writing block to chain", "err", err)
				w.lastBlockNumMu.Lock()
				w.lastSentBlockNumber = previousLastBlockNumber
				w.lastBlockNumMu.Unlock()
				continue
			}
			log.Info("Successfully sealed new block", "number", block.Number(), "sealhash", sealhash, "hash", hash,
				"elapsed", common.PrettyDuration(time.Since(task.createdAt)))

			// Broadcast the block and announce chain insertion event
			w.mux.Post(core.NewMinedBlockEvent{Block: block})
			log.Debug("Block broadcast complete", "block_number", block.NumberU64(), "block_hash", block.Hash().Hex())

			if isCO2 {
				if co2Engine.IsExecutor() {
					interrupt := types.SealInterruptMsg{SealHash: sealhash, BlockNum: block.NumberU64()}
					// We first send an interrupt to any sealing work that is currently in progress.
					log.Debug("Iterating over interrupt channel, keeping highest block interrupt")
					var existingInterrupt *types.SealInterruptMsg
					for len(co2Engine.GetSealInterruptChannel()) > 0 {
						existingInterrupt = <-co2Engine.GetSealInterruptChannel()
						if existingInterrupt.BlockNum > interrupt.BlockNum {
							log.Debug("Existing interrupt is higher than new interrupt", "existing block num", existingInterrupt.BlockNum, "current block num", interrupt.BlockNum)
							interrupt = *existingInterrupt
						}
					}
					co2Engine.GetSealInterruptChannel() <- &interrupt
					log.Debug("Sent interrupt to sealing work (this is normal)", "interupts in channel", len(co2Engine.GetSealInterruptChannel()))
					// We then remove the sequencer's block as soon as the Executor's block is saved and propagated.
					// The params are the Sequencer's block hash but the Executor block number (this would interrupt
					// only if the sequencer's block was in fact at the same height as the Executor's)
					w.chain.RemoveBlock(block.GetSequencerHeader().Hash(), block.Number().Uint64())
					log.Debug("Removed sequencer block from chain", "block_number", block.NumberU64(), "block_hash", block.GetSequencerHeader().Hash())
					ok, prevState := co2Engine.NextExecutionStep(co2.WaitingForSequencerBlock)
					if !ok {
						log.Warn("Skipped Execution Step", "current step", co2Engine.GetExecutionState(), "previous step", prevState)
					}
				}
			}

		case <-w.exitCh:
			log.Warn("Worker resultLoop received exit signal")
			return
		}
	}
}

// makeEnv creates a new environment for the sealing block.
func (w *worker) makeEnv(parent *types.Header, header *types.Header, coinbase common.Address) (*environment, error) {
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

// updateSnapshot updates pending snapshot block, receipts and state.
func (w *worker) updateSnapshot(env *environment) {
	w.snapshotMu.Lock()
	defer w.snapshotMu.Unlock()

	w.snapshotBlock = types.NewBlock(
		env.header,
		env.txs,
		nil,
		env.receipts,
		trie.NewStackTrie(nil),
		nil,
	)
	w.snapshotReceipts = copyReceipts(env.receipts)
	w.snapshotState = env.state.Copy()
}

func (w *worker) commitTransaction(env *environment, tx *types.Transaction) ([]*types.Log, error) {
	if tx.Type() == types.BlobTxType {
		return w.commitBlobTransaction(env, tx)
	}
	startTime := time.Now()
	log.Warn("Apply transaction started")
	receipt, err := w.applyTransaction(env, tx)
	if err != nil {
		log.Error("Error applying transaction", "error", err)
		return nil, err
	}
	endTime := time.Now()
	log.Warn("Apply transaction ended", "duration", endTime.Sub(startTime))
	env.txs = append(env.txs, tx)
	env.receipts = append(env.receipts, receipt)
	return receipt.Logs, nil
}

func (w *worker) commitBlobTransaction(env *environment, tx *types.Transaction) ([]*types.Log, error) {
	sc := tx.BlobTxSidecar()
	if sc == nil {
		panic("blob transaction without blobs in miner")
	}
	// Checking against blob gas limit: It's kind of ugly to perform this check here, but there
	// isn't really a better place right now. The blob gas limit is checked at block validation time
	// and not during execution. This means core.ApplyTransaction will not return an error if the
	// tx has too many blobs. So we have to explicitly check it here.
	if (env.blobs+len(sc.Blobs))*params.BlobTxBlobGasPerBlob > params.MaxBlobGasPerBlock {
		return nil, errors.New("max data blobs reached")
	}
	receipt, err := w.applyTransaction(env, tx)
	if err != nil {
		return nil, err
	}
	env.txs = append(env.txs, tx.WithoutBlobTxSidecar())
	env.receipts = append(env.receipts, receipt)
	env.sidecars = append(env.sidecars, sc)
	env.blobs += len(sc.Blobs)
	*env.header.BlobGasUsed += receipt.BlobGasUsed
	return receipt.Logs, nil
}

// applyTransaction runs the transaction. If execution fails, state and gas pool are reverted.
func (w *worker) applyTransaction(env *environment, tx *types.Transaction) (*types.Receipt, error) {
	var (
		snap     = env.state.Snapshot()
		gp       = env.gasPool.Gas()
		vmConfig = *w.chain.GetVMConfig()
	)
	if c, ok := w.engine.(*co2.Co2); ok {
		// There are only two execution types for generating a new block:
		// MPCExecution - Executors will execute transactions and generate secret state via MPC.
		// Sequencing - Sequencers will generate a new block without actually evaluating secret
		// state, this part of the protocol is used to determine the order of transactions in a
		// block.
		var execType vm.ExecutionType
		if c.IsExecutor() {
			execType = vm.MPCExecution
		} else if c.IsSequencer() {
			execType = vm.Sequencing
		} else {
			return nil, errors.New("unknown soda role")
		}
		vmConfig.ExecType = &execType
	}

	receipt, err := core.ApplyTransaction(w.chainConfig, w.chain, &env.coinbase, env.gasPool, env.state, env.header, tx, &env.header.GasUsed, vmConfig)
	if err != nil {
		env.state.RevertToSnapshot(snap)
		env.gasPool.SetGas(gp)
	}
	return receipt, err
}

func (w *worker) commitTransactions(env *environment, txs *transactionsByPriceAndNonce, interrupt *atomic.Int32) error {
	gasLimit := env.header.GasLimit
	if env.gasPool == nil {
		env.gasPool = new(core.GasPool).AddGas(gasLimit)
	}
	var coalescedLogs []*types.Log

	currentGasPool := env.gasPool.Gas()
	log.Info("Initial gas pool for ordered transactions", "gas", currentGasPool)
	for {
		// Check interruption signal and abort building if it's fired.
		if interrupt != nil {
			if signal := interrupt.Load(); signal != commitInterruptNone {
				return signalToErr(signal)
			}
		}
		// If we don't have enough gas for any further transactions then we're done.
		if env.gasPool.Gas() < params.TxGas {
			log.Trace("Not enough gas for further transactions", "have", env.gasPool, "want", params.TxGas)
			break
		}
		// Retrieve the next transaction and abort if all done.
		ltx := txs.Peek()
		if ltx == nil {
			break
		}
		// If we don't have enough space for the next transaction, skip the account.
		if env.gasPool.Gas() < ltx.Gas {
			log.Trace("Not enough gas left for transaction", "hash", ltx.Hash, "left", env.gasPool.Gas(), "needed", ltx.Gas)
			txs.Pop()
			continue
		}
		if left := uint64(params.MaxBlobGasPerBlock - env.blobs*params.BlobTxBlobGasPerBlob); left < ltx.BlobGas {
			log.Trace("Not enough blob gas left for transaction", "hash", ltx.Hash, "left", left, "needed", ltx.BlobGas)
			txs.Pop()
			continue
		}
		// Transaction seems to fit, pull it up from the pool
		tx := ltx.Resolve()
		if tx == nil {
			log.Trace("Ignoring evicted transaction", "hash", ltx.Hash)
			txs.Pop()
			continue
		}

		// Error may be ignored here. The error has already been checked
		// during transaction acceptance is the transaction pool.
		from, _ := types.Sender(env.signer, tx)

		// Check whether the tx is replay protected. If we're not in the EIP155 hf
		// phase, start ignoring the sender until we do.
		if tx.Protected() && !w.chainConfig.IsEIP155(env.header.Number) {
			log.Trace("Ignoring replay protected transaction", "hash", ltx.Hash, "eip155", w.chainConfig.EIP155Block)
			txs.Pop()
			continue
		}
		// Start executing the transaction
		env.state.SetTxContext(tx.Hash(), env.tcount)

		logs, err := w.commitTransaction(env, tx)
		switch {
		case errors.Is(err, core.ErrMPCRestartBlock):
			log.Error("MPC Restart Block", "tx hash", ltx.Hash, "block number", env.header.Number)
			return err
		case errors.Is(err, core.ErrNonceTooLow):
			// New head notification data race between the transaction pool and miner, shift
			log.Trace("Skipping transaction with low nonce", "hash", ltx.Hash, "sender", from, "nonce", tx.Nonce())
			txs.Shift()

		case errors.Is(err, nil):
			subtractedGasPool := env.gasPool.Gas()
			log.Info("Gas pool after transaction", "tx hash", tx.Hash(), "gas", subtractedGasPool, "transaction required gas", currentGasPool-subtractedGasPool)
			currentGasPool = subtractedGasPool
			// Everything ok, collect the logs and shift in the next transaction from the same account
			coalescedLogs = append(coalescedLogs, logs...)
			env.tcount++
			txs.Shift()

		default:
			// Transaction is regarded as invalid, drop all consecutive transactions from
			// the same sender because of `nonce-too-high` clause.
			log.Debug("Transaction failed, account skipped", "hash", ltx.Hash, "err", err)
			txs.Pop()
		}
	}
	if !w.isRunning() && len(coalescedLogs) > 0 {
		// We don't push the pendingLogsEvent while we are sealing. The reason is that
		// when we are sealing, the worker will regenerate a sealing block every 3 seconds.
		// In order to avoid pushing the repeated pendingLog, we disable the pending log pushing.

		// make a copy, the state caches the logs and these logs get "upgraded" from pending to mined
		// logs by filling in the block hash when the block was mined by the local miner. This can
		// cause a race condition if a log was "upgraded" before the PendingLogsEvent is processed.
		cpy := make([]*types.Log, len(coalescedLogs))
		for i, l := range coalescedLogs {
			cpy[i] = new(types.Log)
			*cpy[i] = *l
		}
		w.pendingLogsFeed.Send(cpy)
	}
	return nil
}

// generateParams wraps various of settings for generating sealing task.
type generateParams struct {
	timestamp   uint64            // The timstamp for sealing task
	forceTime   bool              // Flag whether the given timestamp is immutable or not
	parentHash  common.Hash       // Parent block hash, empty means the latest chain head
	coinbase    common.Address    // The fee recipient address for including transaction
	random      common.Hash       // The randomness generated by beacon chain, empty before the merge
	withdrawals types.Withdrawals // List of withdrawals to include in block.
	beaconRoot  *common.Hash      // The beacon root (cancun field).
	noTxs       bool              // Flag whether an empty block without any transaction is expected
}

// prepareWork constructs the sealing task according to the given parameters,
// either based on the last chain head or specified parent. In this function
// the pending transactions are not filled yet, only the empty task returned.
func (w *worker) prepareWork(genParams *generateParams) (*environment, error) {
	log.Debug("Preparing work", "params", genParams)
	w.mu.RLock()
	defer w.mu.RUnlock()

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
	if c, ok := w.engine.(*co2.Co2); !ok {
		if parent.Time >= timestamp {
			if genParams.forceTime {
				return nil, fmt.Errorf("invalid timestamp, parent %d given %d", parent.Time, timestamp)
			}
			timestamp = parent.Time + 1
		}
	} else {
		if c.IsSequencer() {
			if c.IsHeaderSignedBySequencer(parent) && parent.Number.Uint64() > 0 {
				log.Error("Parent block of pseudo state block is signed by sequencer")
				return nil, fmt.Errorf("parent block of pseudo state block cannot also be pseudo state")
			}
			c.SetExecutorBlockTimestamp(parent.Time)
		}
	}
	// Construct the sealing block header.
	header := &types.Header{
		ParentHash: parent.Hash(),
		Number:     new(big.Int).Add(parent.Number, common.Big1),
		GasLimit:   core.CalcGasLimit(parent.GasLimit, w.config.GasCeil),
		Time:       timestamp,
		Coinbase:   genParams.coinbase,
	}
	// Set the extra field.
	if len(w.extra) != 0 {
		header.Extra = w.extra
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
			header.GasLimit = core.CalcGasLimit(parentGasLimit, w.config.GasCeil)
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
	if header.ParentBeaconRoot != nil {
		context := core.NewEVMBlockContext(header, w.chain, nil)
		vmenv := vm.NewEVM(context, vm.TxContext{}, env.state, w.chainConfig, vm.Config{})
		core.ProcessBeaconBlockRoot(*header.ParentBeaconRoot, vmenv, env.state)
	}
	return env, nil
}

func (w *worker) fillOrderedBlockTxs(txs types.Transactions, env *environment) error {
	log.Debug("Filling ordered block transactions", "count", len(txs))

	gasLimit := env.header.GasLimit
	if env.gasPool == nil {
		env.gasPool = new(core.GasPool).AddGas(gasLimit)
	}
	var coalescedLogs []*types.Log

	currentGasPool := env.gasPool.Gas()
	log.Info("Initial gas pool for commit transactions", "gas", currentGasPool)
	for _, tx := range txs {
		log.Warn("transaction started")
		if env.gasPool.Gas() < params.TxGas {
			log.Warn("Not enough gas for further transactions", "have", env.gasPool.Gas(), "want", params.TxGas)
			// This is a temporary solution, this means the transaction is not included in the canonical block even
			// though it was sequenced as part of the pseudo block.
			break
		}
		// If we don't have enough space for the next transaction, skip the account.
		if env.gasPool.Gas() < tx.Gas() {
			log.Warn("Not enough gas left for transaction", "hash", tx.Hash(), "left", env.gasPool.Gas(), "needed", tx.Gas())
			// This is a temporary solution, this means the transaction is not included in the canonical block even
			// though it was sequenced as part of the pseudo block.
			break
		}
		// Technically should not happen, but let's be safe
		if left := uint64(params.MaxBlobGasPerBlock - env.blobs*params.BlobTxBlobGasPerBlob); left < tx.BlobGas() {
			log.Warn("Not enough blob gas left for transaction", "hash", tx.Hash(), "left", left, "needed", tx.BlobGas())
			break
		}

		// Check whether the tx is replay protected. If we're not in the EIP155 hf
		// phase, start ignoring the sender until we do.
		if tx.Protected() && !w.chainConfig.IsEIP155(env.header.Number) {
			log.Error("Ignoring replay protected transaction", "hash", tx.Hash(), "eip155", w.chainConfig.EIP155Block)
			// This remains an error, this transactions should not have been included in the Sequencer's block.
			return fmt.Errorf("received replay-protected tx in Sequencer's block ignoring replay protected transaction hash: %v eip155: %v",
				tx.Hash(), w.chainConfig.EIP155Block)
		}
		// Start executing the transaction
		env.state.SetTxContext(tx.Hash(), env.tcount)

		logs, err := w.commitTransaction(env, tx)

		if err != nil {
			// For MPC restart error propagate the err (will eventually cause a discard of the work)
			if errors.Is(err, core.ErrMPCRestartBlock) {
				log.Error("Transaction failed", "hash", tx.Hash(), "err", err)
				return err
			}
			log.Warn("Transaction failed", "hash", tx.Hash(), "err", err)
			break
		}
		subtractedGasPool := env.gasPool.Gas()
		log.Info("Gas pool after transaction", "tx hash", tx.Hash(), "tx gas", tx.Gas(), "gas",
			subtractedGasPool, "transaction required gas", currentGasPool-subtractedGasPool)
		currentGasPool = subtractedGasPool

		// Everything ok, collect the logs and shift in the next transaction from the same account
		coalescedLogs = append(coalescedLogs, logs...)
		env.tcount++
	}

	if !w.isRunning() && len(coalescedLogs) > 0 {
		// We don't push the pendingLogsEvent while we are sealing. The reason is that
		// when we are sealing, the worker will regenerate a sealing block every 3 seconds.
		// In order to avoid pushing the repeated pendingLog, we disable the pending log pushing.

		// make a copy, the state caches the logs and these logs get "upgraded" from pending to mined
		// logs by filling in the block hash when the block was mined by the local miner. This can
		// cause a race condition if a log was "upgraded" before the PendingLogsEvent is processed.
		cpy := make([]*types.Log, len(coalescedLogs))
		for i, l := range coalescedLogs {
			cpy[i] = new(types.Log)
			*cpy[i] = *l
		}
		w.pendingLogsFeed.Send(cpy)
	}

	log.Debug("Done filling ordered block transactions", "block tx num", env.tcount)

	return nil
}

// fillTransactions retrieves the pending transactions from the txpool and fills them
// into the given sealing block. The transaction selection and ordering strategy can
// be customized with the plugin in the future.
func (w *worker) fillTransactions(interrupt *atomic.Int32, env *environment) error {
	pending := w.eth.TxPool().Pending(true)

	// Split the pending transactions into locals and remotes.
	localTxs, remoteTxs := make(map[common.Address][]*txpool.LazyTransaction), pending
	for _, account := range w.eth.TxPool().Locals() {
		if txs := remoteTxs[account]; len(txs) > 0 {
			delete(remoteTxs, account)
			localTxs[account] = txs
		}
	}

	// Fill the block with all available pending transactions.
	if len(localTxs) > 0 {
		txs := newTransactionsByPriceAndNonce(env.signer, localTxs, env.header.BaseFee)
		if err := w.commitTransactions(env, txs, interrupt); err != nil {
			return err
		}
	}
	if len(remoteTxs) > 0 {
		txs := newTransactionsByPriceAndNonce(env.signer, remoteTxs, env.header.BaseFee)
		if err := w.commitTransactions(env, txs, interrupt); err != nil {
			return err
		}
	}
	return nil
}

// generateWork generates a sealing block based on the given parameters.
func (w *worker) generateWork(params *generateParams) *newPayloadResult {
	work, err := w.prepareWork(params)
	if err != nil {
		return &newPayloadResult{err: err}
	}
	defer work.discard()

	if !params.noTxs {
		interrupt := new(atomic.Int32)
		timer := time.AfterFunc(w.newpayloadTimeout, func() {
			interrupt.Store(commitInterruptTimeout)
		})
		defer timer.Stop()

		err := w.fillTransactions(interrupt, work)
		if errors.Is(err, errBlockInterruptedByTimeout) {
			log.Warn("Block building is interrupted", "allowance", common.PrettyDuration(w.newpayloadTimeout))
		}
	}
	block, err := w.engine.FinalizeAndAssemble(w.chain, work.header, work.state, work.txs, nil, work.receipts, params.withdrawals)
	if err != nil {
		return &newPayloadResult{err: err}
	}
	return &newPayloadResult{
		block:    block,
		fees:     totalFees(block, work.receipts),
		sidecars: work.sidecars,
	}
}

func (w *worker) commitExecutorWork(block *types.Block) error {
	log.Debug("Committing executor work")
	start := time.Now()

	// Set the coinbase if the worker is running or it's required
	var coinbase common.Address
	if c, ok := w.engine.(*co2.Co2); ok {
		// In our protocol (currently) the only permissible coinbase is the sequencer's address.
		// There are numerous reasons for this choice, but the main one is that we want to
		// have both Executors sign the same block hash, which is not possible if we allow
		// a discrepancy in the coinbase field between the two.
		coinbase = c.SodaSequencerAddress
		c.SetSequencerBlockHeader(block.Header())
	}
	if w.isRunning() {
		if coinbase == (common.Address{}) {
			log.Error("Refusing to mine without etherbase")
			return fmt.Errorf("refusing to mine without etherbase")
		}
	}
	work, err := w.prepareWork(&generateParams{
		timestamp: block.Time(),
		coinbase:  coinbase,
		// The Executor's view of the chain includes the pseudo block, we want to generate
		// a new block that would replace it, that block should point to the pseudo block's
		// parent and not to the soon-to-be-replaced pseudo block itself.
		parentHash: block.ParentHash(),
	})
	if err != nil {
		log.Error("Error preparing work", "error", err)
		work.discard()
		return err
	}
	err = w.fillOrderedBlockTxs(block.Transactions(), work)
	if err != nil {
		log.Error("Error filling ordered block transactions", "error", err)
		work.discard()
		return err
	}

	if err := w.commit(work.copy(), w.fullTaskHook, true, start); err != nil {
		log.Error("Error committing work", "error", err)
		work.discard()
		return err
	}

	// Swap out the old work with the new one, terminating any leftover
	// prefetcher processes in the mean time and starting a new one.
	// (Comment Author: Gary Rong)
	if w.current != nil {
		w.current.discard()
	}

	w.current = work
	return nil
}

// commitWork generates several new sealing tasks based on the parent block
// and submit them to the sealer.
func (w *worker) commitWork(interrupt *atomic.Int32, timestamp int64) {
	// Abort committing if node is still syncing
	if w.syncing.Load() {
		log.Debug("Node is still syncing, aborting commit")
		return
	}
	start := time.Now()

	// Set the coinbase if the worker is running or it's required
	var coinbase common.Address
	if w.isRunning() {
		coinbase = w.etherbase()
		if coinbase == (common.Address{}) {
			log.Error("Refusing to mine without etherbase")
			return
		}
	}
	work, err := w.prepareWork(&generateParams{
		timestamp: uint64(timestamp),
		coinbase:  coinbase,
	})
	if err != nil {
		return
	}
	// Fill pending transactions from the txpool into the block.
	err = w.fillTransactions(interrupt, work)
	switch {
	case err == nil:
		// The entire block is filled, decrease resubmit interval in case
		// of current interval is larger than the user-specified one.
		w.resubmitAdjustCh <- &intervalAdjust{inc: false}

	case errors.Is(err, errBlockInterruptedByRecommit):
		// Notify resubmit loop to increase resubmitting interval if the
		// interruption is due to frequent commits.
		gaslimit := work.header.GasLimit
		ratio := float64(gaslimit-work.gasPool.Gas()) / float64(gaslimit)
		if ratio < 0.1 {
			ratio = 0.1
		}
		w.resubmitAdjustCh <- &intervalAdjust{
			ratio: ratio,
			inc:   true,
		}

	case errors.Is(err, errBlockInterruptedByNewHead):
		// If the block building is interrupted by newhead event, discard it
		// totally. Committing the interrupted block introduces unnecessary
		// delay, and possibly causes miner to mine on the previous head,
		// which could result in higher uncle rate.
		work.discard()
		return
	case errors.Is(err, core.ErrMPCRestartBlock):
		// This error indicates there is a critical error while running the MPC
		// it means that the block should be be discarded. a new trigger has
		// already been sent to the trigger channel to start a new block.
		work.discard()
		return
	}

	// Submit the generated block for consensus sealing.
	w.commit(work.copy(), w.fullTaskHook, true, start)

	// Swap out the old work with the new one, terminating any leftover
	// prefetcher processes in the mean time and starting a new one.
	if w.current != nil {
		w.current.discard()
	}
	w.current = work
}

// commit runs any post-transaction state modifications, assembles the final block
// and commits new work if consensus engine is running.
// Note the assumption is held that the mutation is allowed to the passed env, do
// the deep copy first.
func (w *worker) commit(env *environment, interval func(), update bool, start time.Time) error {
	log.Debug("Committing work")
	if w.isRunning() {
		if interval != nil {
			log.Debug("Calling interval hook")
			interval()
		}

		// Create a local environment copy, avoid the data race with snapshot state.
		// https://github.com/ethereum/go-ethereum/issues/24299
		env := env.copy()
		log.Debug("Environment copied")
		// Withdrawals are set to nil here, because this is only called in PoW.
		block, err := w.engine.FinalizeAndAssemble(w.chain, env.header, env.state, env.txs, nil, env.receipts, nil)
		if err != nil {
			log.Error("Failed to finalize block", "err", err)
			return err
		}
		// If we're post merge, just ignore
		if !w.isTTDReached(block.Header()) {
			select {
			case w.taskCh <- &task{receipts: env.receipts, state: env.state, block: block, createdAt: time.Now()}:
				fees := totalFees(block, env.receipts)
				feesInEther := new(big.Float).Quo(new(big.Float).SetInt(fees), big.NewFloat(params.Ether))
				log.Info("Commit new sealing work", "number", block.Number(), "sealhash", w.engine.SealHash(block.Header()),
					"txs", env.tcount, "gas", block.GasUsed(), "fees", feesInEther,
					"elapsed", common.PrettyDuration(time.Since(start)))

			case <-w.exitCh:
				log.Info("Worker has exited")
			}
		}
	} else {
		log.Warn("Worker is not running! did not commit work!")
	}
	if update {
		w.updateSnapshot(env)
	}
	return nil
}

// getSealingBlock generates the sealing block based on the given parameters.
// The generation result will be passed back via the given channel no matter
// the generation itself succeeds or not.
func (w *worker) getSealingBlock(params *generateParams) *newPayloadResult {
	req := &getWorkReq{
		params: params,
		result: make(chan *newPayloadResult, 1),
	}
	select {
	case w.getWorkCh <- req:
		return <-req.result
	case <-w.exitCh:
		return &newPayloadResult{err: errors.New("miner closed")}
	}
}

// isTTDReached returns the indicator if the given block has reached the total
// terminal difficulty for The Merge transition.
func (w *worker) isTTDReached(header *types.Header) bool {
	td, ttd := w.chain.GetTd(header.ParentHash, header.Number.Uint64()-1), w.chain.Config().TerminalTotalDifficulty
	return td != nil && ttd != nil && td.Cmp(ttd) >= 0
}

// copyReceipts makes a deep copy of the given receipts.
func copyReceipts(receipts []*types.Receipt) []*types.Receipt {
	result := make([]*types.Receipt, len(receipts))
	for i, l := range receipts {
		cpy := *l
		result[i] = &cpy
	}
	return result
}

// totalFees computes total consumed miner fees in Wei. Block transactions and receipts have to have the same order.
func totalFees(block *types.Block, receipts []*types.Receipt) *big.Int {
	feesWei := new(big.Int)
	for i, tx := range block.Transactions() {
		minerFee, _ := tx.EffectiveGasTip(block.BaseFee())
		feesWei.Add(feesWei, new(big.Int).Mul(new(big.Int).SetUint64(receipts[i].GasUsed), minerFee))
	}
	return feesWei
}

// signalToErr converts the interruption signal to a concrete error type for return.
// The given signal must be a valid interruption signal.
func signalToErr(signal int32) error {
	switch signal {
	case commitInterruptNewHead:
		return errBlockInterruptedByNewHead
	case commitInterruptResubmit:
		return errBlockInterruptedByRecommit
	case commitInterruptTimeout:
		return errBlockInterruptedByTimeout
	default:
		panic(fmt.Errorf("undefined signal %d", signal))
	}
}
