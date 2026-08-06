// Copyright 2026 The go-ethereum Authors
// This file is part of the go-ethereum library.

package core

import (
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
)

func testBatchBlock(number uint64, extra string) *types.Block {
	return types.NewBlockWithHeader(&types.Header{
		Number: big.NewInt(int64(number)),
		Extra:  []byte(extra),
	})
}

func TestBlockFromDBOrBatch(t *testing.T) {
	dbBlock := testBatchBlock(1, "db")
	batchParent := testBatchBlock(2, "batch-parent")
	batchChild := testBatchBlock(3, "batch-child")
	chain := types.Blocks{batchParent, batchChild}

	db := map[common.Hash]*types.Block{
		dbBlock.Hash(): dbBlock,
	}
	getBlock := func(hash common.Hash, number uint64) *types.Block {
		if b, ok := db[hash]; ok && b.NumberU64() == number {
			return b
		}
		return nil
	}

	t.Run("db hit", func(t *testing.T) {
		got := blockFromDBOrBatch(getBlock, chain, 0, dbBlock.Hash(), dbBlock.NumberU64())
		if got != dbBlock {
			t.Fatalf("expected db block, got %#v", got)
		}
	})

	t.Run("in-batch parent hit", func(t *testing.T) {
		// Simulates validating chain[1] whose parent is chain[0], not yet persisted.
		got := blockFromDBOrBatch(getBlock, chain, 1, batchParent.Hash(), batchParent.NumberU64())
		if got != batchParent {
			t.Fatalf("expected in-batch parent, got %#v", got)
		}
	})

	t.Run("prefers db over batch", func(t *testing.T) {
		// Same hash/number also present earlier in the batch; DB should win.
		overlapping := types.Blocks{dbBlock, batchChild}
		got := blockFromDBOrBatch(getBlock, overlapping, 1, dbBlock.Hash(), dbBlock.NumberU64())
		if got != dbBlock {
			t.Fatalf("expected db block to take precedence, got %#v", got)
		}
	})

	t.Run("miss when not in db or prior batch", func(t *testing.T) {
		unknown := testBatchBlock(99, "unknown")
		got := blockFromDBOrBatch(getBlock, chain, 1, unknown.Hash(), unknown.NumberU64())
		if got != nil {
			t.Fatalf("expected nil for unknown block, got %#v", got)
		}
	})

	t.Run("does not look ahead in batch", func(t *testing.T) {
		// index 0 must not resolve chain[0] from the batch itself.
		got := blockFromDBOrBatch(getBlock, chain, 0, batchParent.Hash(), batchParent.NumberU64())
		if got != nil {
			t.Fatalf("expected nil when looking up current index block, got %#v", got)
		}
	})

	t.Run("number mismatch is a miss", func(t *testing.T) {
		got := blockFromDBOrBatch(getBlock, chain, 1, batchParent.Hash(), batchParent.NumberU64()+1)
		if got != nil {
			t.Fatalf("expected nil on number mismatch, got %#v", got)
		}
	})
}
