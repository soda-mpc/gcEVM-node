package soda_tests

import (
	"log"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/consensus/co2"
	"github.com/ethereum/go-ethereum/params"
	"github.com/stretchr/testify/require"
)

func Test_SodaChainMaker(t *testing.T) {
	// Arrange
	cm := newSodaChainMaker(t, &params.CliqueConfig{
		Period: 0,
		Epoch:  30000,
	})

	const (
		numBlocks      = 10
		numTxsPerBlock = 10
	)

	chainTxs := [][]*TestTransferTx{}
	for i := 0; i < numBlocks; i++ {
		ttxs := []*TestTransferTx{}
		for j := 0; j < numTxsPerBlock; j++ {
			ttxs = append(ttxs, &TestTransferTx{
				From:   cm.sequencer,
				To:     cm.executor1,
				Amount: big.NewInt(1e18),
			})
		}
		chainTxs = append(chainTxs, ttxs)
	}

	// Act
	cm.PopulateChain(chainTxs, co2.Executor)
	currentBlock := cm.chain.CurrentBlock()
	hash := currentBlock.Hash()
	num := currentBlock.Number.Uint64()
	t.Log(cm.chain.GetTd(hash, num))
	for i := 0; i < len(chainTxs); i++ {
		block := cm.chain.GetBlockByNumber(uint64(i))
		t.Log(block.Hash())
	}
	// check the balance of cm.executor1.address in the last block
	state, err := cm.chain.StateAt(currentBlock.Root)
	if err != nil {
		log.Fatalf("failed to get state: %v", err)
	}

	// Get the balance for the address
	exec1Balance := state.GetBalance(cm.executor1.address)
	gotBalance := big.NewInt(0).Mul(big.NewInt(numTxsPerBlock*numBlocks), big.NewInt(1e18))

	// Assert
	require.Equal(t, gotBalance, exec1Balance)
}
