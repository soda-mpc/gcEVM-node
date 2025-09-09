// Copyright 2020 The go-ethereum Authors
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

package eth

import (
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus/co2"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/eth/protocols/eth"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/p2p/enode"
	"github.com/ethereum/go-ethereum/shared"
)

// ethHandler implements the eth.Backend interface to handle the various network
// packets that are sent as replies or broadcasts.
type ethHandler handler

func (h *ethHandler) Chain() *core.BlockChain { return h.chain }
func (h *ethHandler) TxPool() eth.TxPool      { return h.txpool }

// RunPeer is invoked when a peer joins on the `eth` protocol.
func (h *ethHandler) RunPeer(peer *eth.Peer, hand eth.Handler) error {
	return (*handler)(h).runEthPeer(peer, hand)
}

// PeerInfo retrieves all known `eth` information about a peer.
func (h *ethHandler) PeerInfo(id enode.ID) interface{} {
	if p := h.peers.peer(id.String()); p != nil {
		return p.info()
	}
	return nil
}

// AcceptTxs retrieves whether transaction processing is enabled on the node
// or if inbound transactions should simply be dropped.
func (h *ethHandler) AcceptTxs() bool {
	return h.synced.Load()
}

// Handle is invoked from a peer's message handler when it receives a new remote
// message that the handler couldn't consume and serve itself.
func (h *ethHandler) Handle(peer *eth.Peer, packet eth.Packet) error {
	// Consume any broadcasts and announces, forwarding the rest to the downloader
	switch packet := packet.(type) {
	case *eth.RestartBlockPacket:
		return h.HandleRestartBlock(peer, packet)
	case *eth.ResendSequencerBlockPacket:
		return h.HandleResendSequencerBlock(peer, packet)

	case *eth.ResendExecutorSigPacket:
		return h.HandleResendExecutorsSig(peer, packet)

	case *eth.ExecutorSignaturePacket:
		return h.handleExecutorSignature(peer, packet)

	case *eth.NewBlockHashesPacket:
		hashes, numbers := packet.Unpack()
		if common.IsExecutor() {
			return nil
		}
		return h.handleBlockAnnounces(peer, hashes, numbers)

	case *eth.NewBlockPacket:
		return h.handleBlockBroadcast(peer, packet.Block, packet.TD)

	case *eth.NewPooledTransactionHashesPacket67:
		log.Debug(fmt.Sprintf("Got a NewPooledTransactionHashesPacket67: %s", packet.Name()))
		if common.IsExecutor() {
			return nil
		}
		return h.txFetcher.Notify(peer.ID(), nil, nil, *packet)

	case *eth.NewPooledTransactionHashesPacket68:
		log.Debug(fmt.Sprintf("Got a NewPooledTransactionHashesPacket68: %s", packet.Name()))
		if common.IsExecutor() {
			return nil
		}
		return h.txFetcher.Notify(peer.ID(), packet.Types, packet.Sizes, packet.Hashes)

	case *eth.TransactionsPacket:
		if common.IsExecutor() {
			log.Debug(fmt.Sprintf("Executor got a tx packet: %s, discarding it", packet.Name()))
			return nil
		}
		for _, tx := range *packet {
			if tx.Type() == types.BlobTxType {
				return errors.New("disallowed broadcast blob transaction")
			}
		}
		return h.txFetcher.Enqueue(peer.ID(), *packet, false)

	case *eth.PooledTransactionsResponse:
		log.Debug(fmt.Sprintf("Got a PooledTransactionsResponse: %s", packet.Name()))
		if common.IsExecutor() {
			return nil
		}
		return h.txFetcher.Enqueue(peer.ID(), *packet, true)

	default:
		return fmt.Errorf("unexpected eth packet type: %T", packet)
	}
}

// handleBlockAnnounces is invoked from a peer's message handler when it transmits a
// batch of block announcements for the local node to process.
func (h *ethHandler) handleBlockAnnounces(peer *eth.Peer, hashes []common.Hash, numbers []uint64) error {
	// Drop all incoming block announces from the p2p network if
	// the chain already entered the pos stage and disconnect the
	// remote peer.
	if h.merger.PoSFinalized() {
		return errors.New("disallowed block announcement")
	}
	// Schedule all the unknown hashes for retrieval
	var (
		unknownHashes  = make([]common.Hash, 0, len(hashes))
		unknownNumbers = make([]uint64, 0, len(numbers))
	)
	for i := 0; i < len(hashes); i++ {
		if !h.chain.HasBlock(hashes[i], numbers[i]) {
			unknownHashes = append(unknownHashes, hashes[i])
			unknownNumbers = append(unknownNumbers, numbers[i])
		}
	}
	for i := 0; i < len(unknownHashes); i++ {
		h.blockFetcher.Notify(peer.ID(), unknownHashes[i], unknownNumbers[i], time.Now(), peer.RequestOneHeader, peer.RequestBodies)
	}
	return nil
}

// handleBlockBroadcast is invoked from a peer's message handler when it transmits a
// block broadcast for the local node to process.
func (h *ethHandler) handleBlockBroadcast(peer *eth.Peer, block *types.Block, td *big.Int) error {
	log.Debug("Got a new block broadcast", "difficulty", block.Difficulty().String(), "number", block.Number().Uint64())
	// Drop all incoming block announces from the p2p network if
	// the chain already entered the pos stage and disconnect the
	// remote peer.
	if h.merger.PoSFinalized() {
		return errors.New("disallowed block broadcast")
	}
	// Schedule the block for import
	h.blockFetcher.Enqueue(peer.ID(), block)

	// Assuming the block is importable by the peer, but possibly not yet done so,
	// calculate the head hash and TD that the peer truly must have.
	var (
		trueHead = block.ParentHash()
		trueTD   = new(big.Int).Sub(td, block.Difficulty())
	)
	// Update the peer's total difficulty if better than the previous
	if _, td := peer.Head(); trueTD.Cmp(td) > 0 {
		peer.SetHead(trueHead, trueTD)
		h.chainSync.handlePeerEvent()
	}
	return nil
}

func (h *ethHandler) handleExecutorSignature(peer *eth.Peer, packet *eth.ExecutorSignaturePacket) error {
	log.Debug(fmt.Sprintf("Got an ExecutorSignaturePacket: %s", packet.String()))
	if c, ok := h.chain.Engine().(*co2.Co2); ok {
		if c.IsExecutor() {
			sigDetails := &types.ExecutorSigDetails{
				Signature:     packet.Signature,
				SignatureHash: packet.SignatureHash,
				BlockNumber:   packet.BlockNumber,
			}
			go func() {
				sigCh := c.GetExecutorSigChannel()
				// We first drain the channel of unconsumed irrelevant signatures.
				for len(sigCh) > 0 {
					<-sigCh
				}

				select {
				case sigCh <- sigDetails:
					log.Debug("ExecutorSignaturePacket sent to channel", "block number", packet.BlockNumber)
				default:
					log.Error("ExecutorSignaturePacket dropped", "amount of message sin the channel", len(c.GetExecutorSigChannel()))
				}
			}()
		}
	}

	return nil
}

func (h *ethHandler) HandleResendExecutorsSig(peer *eth.Peer, packet *eth.ResendExecutorSigPacket) error {
	log.Debug("Got a ResendExecutorSigPacket", "block number", packet.BlockNumber, "peer ID", peer.ID(), "peer name", peer.Name())
	if c, ok := h.chain.Engine().(*co2.Co2); ok {
		if c.IsExecutor() {
			// Only Executors should respond to this packet
			requestNumber := c.RegisterSigRequest(packet.BlockNumber)
			sigDetails, err := c.GetExecutorSig(packet.BlockNumber)
			if err != nil {
				// An error returned, we do not have the signature
				if errors.Is(err, co2.ErrMissingSequencerBlock) || errors.Is(err, co2.ErrExecutorSigUnavailable) {
					// We didn't even have the block, let's look for it in the DB
					log.Warn("Executor could not obtain signature, retrieving block from DB")
					block := h.chain.GetBlockByNumber(packet.BlockNumber)
					if block == nil {
						// We didn't find the block in the DB, let's request the pseudo block from the sequencer
						// so we can work on it.
						log.Warn("Executor is missing sequencer block, requesting it from sequencer")
						if err := h.requestSequencerBlockFromSequencer(peer, co2.Executor, packet.BlockNumber); err != nil {
							log.Error("Error while requesting sequencer block", "error", err)
							return err
						}
						log.Debug("Sequencer block requested")
						return nil
					}
					// OK we did have the block number, let's check if it's a Sequencer or an Executor block
					if c.IsHeaderSignedBySequencer(block.Header()) {
						// A sequencer block!
						log.Debug("Executor has not created a 'canonical' block yet")
						if requestNumber >= uint64(c.RequestSigThreshold) {
							// We have been requested for the signature more than the threshold, we might need to remake the block.
							log.Debug("Number of requests above threshold, generating 'canonical' block", "block number", packet.BlockNumber)
							if c.GetExecutionState() == co2.GeneratingExecutorBlock {
								// we are in the middle of generating a block, let's restart the work (discarding previous)
								log.Debug("Restarting block work", "block number", packet.BlockNumber)
								c.RestartBlockWork(packet.BlockNumber)
							} else {
								// we are not generating a block, let's start the work
								log.Debug("Starting work on new block", "block number", packet.BlockNumber)
								c.GetSequencerBlockChannel() <- block
							}
							// we ask for the other Executor to restart in case the block requires MPC
							// TODO: check if the block requires MPC (using a new field in the packet)
							log.Debug("Requesting block restart", "block number", packet.BlockNumber)
							peer.SendBlockRestartRequest(block.Number().Uint64())
						}
						// We are not above the threshold, we wait because we might be in the middle of generating the block
						log.Warn("Requested sig block num is a sequencer block, request amount not above threshold",
							"block number", packet.BlockNumber, "request number", requestNumber)
						return nil
					} else {
						// An executor block!
						// We can get the signature from it directly.
						sigDetails, err = h.ParseBlockForExecutorSig(c, block)
						if err != nil {
							log.Error("Error while getting executor signature", "error", err)
							return err
						}

					}
				} else if errors.Is(err, co2.ErrSigRequestedForPreviousBlock) {
					// The Executor requested a signature for a previous block
					// We should have the block in the DB, let's get the signature from it.
					log.Warn("Executor is requesting a signature for a canonical block")
					block := h.chain.GetBlockByNumber(packet.BlockNumber)
					if block == nil {
						log.Error("Block not found", "block number", packet.BlockNumber)
						return errors.New("block not found")
					}
					// Extract the signature from the block
					sigDetails, err = h.ParseBlockForExecutorSig(c, block)
					if err != nil {
						log.Error("Error while getting executor signature", "error", err)
						return err
					}
				} else {
					// An unexpected error occurred
					log.Error("Error while getting executor signature", "error", err)
					return err
				}
			}
			// We have the signature, let's send it.
			if sigDetails != nil {
				log.Debug("Sending executor signature",
					"block number", sigDetails.BlockNumber, "hash", sigDetails.SignatureHash, "sig", sigDetails.Signature,
					"peer ID", peer.ID(), "peer name", peer.Name())
				return peer.SendExecutorSignature(sigDetails)
			}
			log.Error("Executor signature is nil")
		} else {
			// We are not an executor, we should not respond to this packet
			log.Trace("ResendExecutorSigPacket received by non-executor node, Ignoring it")
		}

	}

	return nil
}

func (h *ethHandler) ParseBlockForExecutorSig(c *co2.Co2, block *types.Block) (*types.ExecutorSigDetails, error) {
	if block == nil {
		log.Error("Block is nil")
		return nil, errors.New("block is nil")
	}
	if c.IsHeaderSignedBySequencer(block.Header()) {
		log.Error("Block is a sequencer block", "block number", block.Number().Uint64())
		return nil, errors.New("block is a sequencer block")
	}
	num, _ := c.GetSelfSigOrder()
	header := block.Header()

	var sig []byte
	var err error
	if num == 0 {
		sig, err = co2.RetrieveFromExtraData(shared.Signature1, header.Extra)
		if err != nil {
			log.Error("Error while retrieving signature from ExtraData", "num", num, "error", err)
			return nil, err
		}
	} else if num == 1 {
		sig, err = co2.RetrieveFromExtraData(shared.Signature2, header.Extra)
		if err != nil {
			log.Error("Error while retrieving signature from ExtraData", "num", num, "error", err)
			return nil, err
		}
	} else {
		log.Error("Unexpected sig order", "num", num)
		return nil, errors.New("unexpected sig order")
	}
	sigDetails := &types.ExecutorSigDetails{
		Signature:     sig,
		SignatureHash: co2.SealHash(header).Bytes(),
		BlockNumber:   block.Number().Uint64(),
	}

	return sigDetails, nil
}

func (h *ethHandler) HandleRestartBlock(peer *eth.Peer, packet *eth.RestartBlockPacket) error {
	log.Debug("Got a RestartBlockPacket", "block number", packet.BlockNumber, "peer ID", peer.ID(), "peer name", peer.Name())
	if c, ok := h.chain.Engine().(*co2.Co2); ok {
		if c.IsExecutor() {
			c.RestartBlockWork(packet.BlockNumber)
		} else {
			log.Trace("RestartBlockPacket received by non-executor node, Ignoring it")
		}
	} else {
		log.Trace("RestartBlockPacket received by non-co2 node, Ignoring it")
	}
	return nil
}

func (h *ethHandler) HandleResendSequencerBlock(peer *eth.Peer, packet *eth.ResendSequencerBlockPacket) error {
	if c, ok := h.chain.Engine().(*co2.Co2); ok {
		log.Info("Got a ResendSequencerBlockPacket", "block number", packet.BlockNumber, "peer ID", peer.ID(), "peer name", peer.Name())
		// If the sequencer is not in black block state, a red block would arrive at the requestor regardless.
		if c.IsSequencer() {
			currentHeader := h.Chain().CurrentBlock()
			// We will send the sequencer's block if it is the latest block (meaning the head is still RED).
			// The requestor can ask for a different RED block number (0 specifies the latest block), but
			// this functionality is currently unimplementable.
			if (currentHeader.Number.Uint64() == packet.BlockNumber || packet.BlockNumber == 0) &&
				currentHeader.Difficulty.Cmp(co2.GetDifficulty(co2.Sequencer)) == 0 {

				td := h.Chain().GetTd(currentHeader.Hash(), currentHeader.Number.Uint64())
				block := h.Chain().GetBlock(currentHeader.Hash(), currentHeader.Number.Uint64())
				peer.AsyncSendNewBlock(block, td)
			} else {
				log.Warn("Sequencer block requested is already black, it should be remade from the header")
			}
		}
	}

	return nil
}

func (h *ethHandler) requestSequencerBlockFromSequencer(peer *eth.Peer, peerRole co2.SodaRoleType, blockNumber uint64) error {
	if peerRole == co2.Sequencer {
		return peer.RequestSequencerBlock(blockNumber)
	}
	for id, p := range h.peers.peers {
		if id != peer.ID() {
			log.Info("Requesting sequencer block from sequencer", "peer", id, "block number", blockNumber)
			return p.RequestSequencerBlock(blockNumber)
		}
	}

	return errors.New("no sequencer peer found")
}
