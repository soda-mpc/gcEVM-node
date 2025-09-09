package shared

import (
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
)

type SodaRole int

const (
	Unknown SodaRole = iota
	Sequencer
	Executor
	Validator
)

func SodaRoleFromString(s string) SodaRole {
	switch strings.ToLower(s) {
	case "sequencer":
		return Sequencer
	case "executor":
		return Executor
	case "validator":
		return Validator
	default:
		return Unknown
	}
}

type ExtraDataPart string

// In the Co2 consensus engine, the extra-data section of the block header is used to store
// multiple important pieces of data, each in a predesignated location in the slice. The
// below enum is used to provide reference for the different parts of the field.
const (
	ExtraVanity        ExtraDataPart = "ExtraVanity"        // 32 bytes reserved for signer vanity
	TranscriptHash     ExtraDataPart = "TranscriptHash"     // 32 bytes (hash length) reserved for transcript hash
	SequencerBlockHash ExtraDataPart = "SequencerBlockHash" // 32 bytes (hash length) reserved for the Sequencer block's hash
	Signature1         ExtraDataPart = "Signature1"         // 65 bytes reserved for the 1st signature
	Signature2         ExtraDataPart = "Signature2"         // 65 bytes reserved for the 2nd signature
)

// The header.Extra field composition is as follows ([226]byte):
// [|0..vanity..31|32..transcriptHash..63|64..sequencerBlockHash..95|96..Sig1..160|161..executor2Sig..225|]
// Any uninitialized part of the extra data is padded with 0's.
// Some positions below have the same value, this is for increased readability:
// extra[TranscriptHashStart:TranscriptHashEnd] > extra[VanityEnd:TranscriptHashEnd]
const (
	VanityStart             = 0                                                  // 0
	VanityEnd               = VanityStart + ExtraVanityLength                    // 32
	TranscriptHashStart     = VanityEnd                                          // 32
	TranscriptHashEnd       = TranscriptHashStart + TranscriptHashLength         // 64
	SequencerBlockHashStart = TranscriptHashEnd                                  // 64
	SequencerBlockHashEnd   = SequencerBlockHashStart + SequencerBlockHashLength // 96
	Signature1Start         = SequencerBlockHashEnd                              // 96
	Signature1End           = Signature1Start + ExtraSeal                        // 161
	Signature2Start         = Signature1End                                      // 161
	Signature2End           = Signature2Start + ExtraSeal                        // 226
)

const (
	// num executors is currently a const but this value should be dynamic
	NumExecutors             = 2
	ExtraVanityLength        = 32     // Fixed number of extra-data prefix bytes reserved for signer vanity
	ExtraSeal                = 64 + 1 // Fixed number of extra-data suffix bytes reserved for signer seal
	TranscriptHashLength     = 32     // Fixed number of bytes in a transcript hash
	SequencerBlockHashLength = 32     // Fixed number of bytes in a sequencer block hash
	ExtraDataLength          = ExtraVanityLength + TranscriptHashLength + SequencerBlockHashLength + (ExtraSeal * NumExecutors)
)

type SlimConfig struct {
	Transcript types.Transcript  // The transcript to be used in case of TranscriptEvaluation
	ExecType   *vm.ExecutionType // The Soda Execution Type (Sequencing|MPCExecution|TranscriptEvaluation)
	Header     *types.Header     // The block to be used in case of TranscriptEvaluation
}

type SlimHeader struct {
	ParentHash  common.Hash
	UncleHash   [32]byte
	Coinbase    [20]byte
	Root        [32]byte
	TxHash      [32]byte
	ReceiptHash [32]byte
	Bloom       [256]byte
	Difficulty  string
	Number      string
	GasLimit    uint64
	GasUsed     uint64
	Time        uint64
	MixDigest   [32]byte
	Nonce       [8]byte
	Extra       []byte
	BaseFee     string
}

func (s *SlimHeader) MarshalBinary() ([]byte, error) {
	return []byte{}, nil
}

func (s *SlimHeader) UnmarshalBinary(data []byte) error {
	return nil
}

type SlimBlock struct {
	Header *SlimHeader
}
