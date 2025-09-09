package common

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

var (
	SodaEngine           bool = false
	SodaRole             SodaRoleType
	SodaExecutor1Address Address
	SodaExecutor2Address Address
	SodaSequencerAddress Address
	SodaSequencerPubKey  string
	MyAddress            Address
	Id                   int = -1
	MpcServerIP          string
	MpcServerPort        string
)

func IsSequencer() bool {
	return SodaRole == Sequencer
}

func IsExecutor() bool {
	return SodaRole == Executor
}

func IsValidator() bool {
	return SodaRole == Validator
}

func IsSoda() bool {
	return SodaEngine
}

func IsSequencerPubKey(pubKey string) bool {
	return pubKey == SodaSequencerPubKey
}

func IsExternalValidator() bool {
	return IsValidator() && SodaSequencerPubKey == "0"
}
