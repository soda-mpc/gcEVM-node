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

package eth

import (
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/consensus/co2"
	"github.com/ethereum/go-ethereum/eth/downloader"
	"github.com/ethereum/go-ethereum/eth/protocols/eth"
	"github.com/ethereum/go-ethereum/eth/protocols/snap"
	"github.com/ethereum/go-ethereum/p2p"
	"github.com/ethereum/go-ethereum/p2p/enode"
)

// Tests that snap sync is disabled after a successful sync cycle.
func TestSnapSyncDisabling67(t *testing.T) { testSnapSyncDisabling(t, eth.ETH67, snap.SNAP1) }
func TestSnapSyncDisabling68(t *testing.T) { testSnapSyncDisabling(t, eth.ETH68, snap.SNAP1) }
func TestSodaSync(t *testing.T)            { sodaSyncTest(t, eth.SODA) }

// Tests that snap sync gets disabled as soon as a real block is successfully
// imported into the blockchain.
func testSnapSyncDisabling(t *testing.T, ethVer uint, snapVer uint) {
	t.Parallel()

	// Create an empty handler and ensure it's in snap sync mode
	empty := newTestHandler()
	if !empty.handler.snapSync.Load() {
		t.Fatalf("snap sync disabled on pristine blockchain")
	}
	defer empty.close()

	// Create a full handler and ensure snap sync ends up disabled
	full := newTestHandlerWithBlocks(1024)
	if full.handler.snapSync.Load() {
		t.Fatalf("snap sync not disabled on non-empty blockchain")
	}
	defer full.close()

	// Sync up the two handlers via both `eth` and `snap`
	caps := []p2p.Cap{{Name: "eth", Version: ethVer}, {Name: "snap", Version: snapVer}}

	emptyPipeEth, fullPipeEth := p2p.MsgPipe()
	defer emptyPipeEth.Close()
	defer fullPipeEth.Close()

	emptyPeerEth := eth.NewPeer(ethVer, p2p.NewPeer(enode.ID{1}, "", caps), emptyPipeEth, empty.txpool)
	fullPeerEth := eth.NewPeer(ethVer, p2p.NewPeer(enode.ID{2}, "", caps), fullPipeEth, full.txpool)
	defer emptyPeerEth.Close()
	defer fullPeerEth.Close()

	go empty.handler.runEthPeer(emptyPeerEth, func(peer *eth.Peer) error {
		return eth.Handle((*ethHandler)(empty.handler), peer)
	})
	go full.handler.runEthPeer(fullPeerEth, func(peer *eth.Peer) error {
		return eth.Handle((*ethHandler)(full.handler), peer)
	})

	emptyPipeSnap, fullPipeSnap := p2p.MsgPipe()
	defer emptyPipeSnap.Close()
	defer fullPipeSnap.Close()

	emptyPeerSnap := snap.NewPeer(snapVer, p2p.NewPeer(enode.ID{1}, "", caps), emptyPipeSnap)
	fullPeerSnap := snap.NewPeer(snapVer, p2p.NewPeer(enode.ID{2}, "", caps), fullPipeSnap)

	go empty.handler.runSnapExtension(emptyPeerSnap, func(peer *snap.Peer) error {
		return snap.Handle((*snapHandler)(empty.handler), peer)
	})
	go full.handler.runSnapExtension(fullPeerSnap, func(peer *snap.Peer) error {
		return snap.Handle((*snapHandler)(full.handler), peer)
	})
	// Wait a bit for the above handlers to start
	time.Sleep(250 * time.Millisecond)

	// Check that snap sync was disabled
	op := peerToSyncOp(downloader.SnapSync, empty.handler.peers.peerWithHighestTD())
	if err := empty.handler.doSync(op); err != nil {
		t.Fatal("sync failed:", err)
	}
	if empty.handler.snapSync.Load() {
		t.Fatalf("snap sync not disabled after successful synchronisation")
	}
}

func sodaSyncTest(t *testing.T, ethVer uint) {
	testCases := []struct {
		name  string
		empty co2.SodaRoleType
		full  co2.SodaRoleType
	}{
		{
			name:  "Executor engine with Executor head",
			empty: co2.Executor,
			full:  co2.Executor,
		},
		{
			name:  "Executor engine with Sequencer head",
			empty: co2.Executor,
			full:  co2.Sequencer,
		},
		{
			name:  "Sequencer engine with Executor head",
			empty: co2.Sequencer,
			full:  co2.Executor,
		},
		{
			name:  "Sequencer engine with Sequencer head",
			empty: co2.Sequencer,
			full:  co2.Sequencer,
		},
		{
			name:  "Validator engine with Executor head",
			empty: co2.Validator,
			full:  co2.Executor,
		},
	}
	for _, tc := range testCases {
		t.Log(tc.name)
		empty, full := NewSodaTestHandlers(t, 10, tc.empty, tc.full)
		doSodaSync(t, ethVer, empty, full)
		full.close()
		empty.close()
	}

}

func doSodaSync(t *testing.T, ethVer uint, empty, full *testHandler) {
	// Arrange
	caps := []p2p.Cap{{Name: "eth", Version: ethVer}}

	emptyPipeEth, fullPipeEth := p2p.MsgPipe()
	defer emptyPipeEth.Close()
	defer fullPipeEth.Close()

	emptyPeerEth := eth.NewPeer(ethVer, p2p.NewPeer(enode.ID{1}, "", caps), emptyPipeEth, empty.txpool)
	fullPeerEth := eth.NewPeer(ethVer, p2p.NewPeer(enode.ID{2}, "", caps), fullPipeEth, full.txpool)
	defer emptyPeerEth.Close()
	defer fullPeerEth.Close()

	go empty.handler.runEthPeer(emptyPeerEth, func(peer *eth.Peer) error {
		return eth.Handle((*ethHandler)(empty.handler), peer)
	})
	go full.handler.runEthPeer(fullPeerEth, func(peer *eth.Peer) error {
		return eth.Handle((*ethHandler)(full.handler), peer)
	})

	time.Sleep(2500 * time.Millisecond)

	// Act
	op := peerToSyncOp(downloader.FullSync, empty.handler.peers.peerWithHighestTD())

	// Assert
	if err := empty.handler.doSync(op); err != nil {
		t.Fatal("sync failed:", err)
	}

	t.Log("Sync completed")
	time.Sleep(2500 * time.Millisecond)

}
