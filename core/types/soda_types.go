package types

import (
	"bytes"
	"encoding/gob"
	"errors"
	"fmt"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/log"
)

var (
	ErrTranscriptIsEmpty = errors.New("transcript is empty")
)

type Transcript [][]byte

func (t *Transcript) Last32Bytes() common.Hash {
	// Flatten Transcript into a single []byte slice
	var flat []byte
	for _, v := range *t {
		flat = append(flat, v...)
	}
	// return the last 32 bytes of the flat slice
	return common.BytesToHash(flat)
}

func (t *Transcript) Hash() common.Hash {
	// Flatten Transcript into a single []byte slice
	var flat []byte
	for _, v := range *t {
		flat = append(flat, v...)
	}
	// Return a hash for the flat slice using keccak256
	return crypto.Keccak256Hash(flat)
}

func (t *Transcript) GetMPCStatus() (*MPCStatus, error) {
	byteArray := *t
	if len(byteArray) == 0 {
		return nil, ErrTranscriptIsEmpty
	}
	statusBytes := byteArray[len(byteArray)-1]
	mpcStatus, err := NewMPCStatusFromBytes(statusBytes)
	if err != nil {
		return nil, err
	}
	*t = (*t)[:len(byteArray)-1]
	return mpcStatus, nil
}

func (t *Transcript) ConsumeExecutionOutput() ([]byte, error) {
	log.Trace("ConsumeExecutionOutput", "transcript ptr", fmt.Sprintf("%p", t), "transcript length", len(*t))
	if len(*t) == 0 {
		return nil, ErrTranscriptIsEmpty
	}
	// Each element in the transcript is a different execution result (output),
	// we consume it by removing the first element from the transcript and returning it.
	output := (*t)[0]
	if len(output) == 0 {
		return nil, errors.New("error in transcript")
	}
	if len(*t) == 1 {
		*t = make(Transcript, 0)
	} else {
		*t = (*t)[1:]
	}
	return output, nil
}

type ExecutorSigDetails struct {
	Signature     []byte
	SignatureHash []byte
	BlockNumber   uint64
}

type SealInterruptMsg struct {
	SealHash common.Hash
	BlockNum uint64
}

// WithSodaTypes returns a block with the given transcript and sequencer header
// The block will only include withdrawals if it had them before and the soda fields
// are nil. We don't want to interfere with geth's original functionality.
func (b *Block) WithSodaTypes(transcript *Transcript, seqHeader *Header) *Block {
	block := Block{
		header:          b.header,
		transactions:    b.transactions,
		uncles:          b.uncles,
		transcript:      transcript,
		sequencerHeader: seqHeader,
	}
	if seqHeader == nil && transcript == nil && b.withdrawals != nil {
		block.withdrawals = b.withdrawals
	}

	return &block

}

type MPCStatus struct {
	OpcodesNames        []string
	BatchIds            []uint64
	CircuitsInsideBatch []int64
}

func NewMPCStatus(opcodesNames []string, batchIDs []uint64, circuitsInsideBatch []int64) *MPCStatus {
	return &MPCStatus{
		OpcodesNames:        opcodesNames,
		BatchIds:            batchIDs,
		CircuitsInsideBatch: circuitsInsideBatch,
	}
}

func NewMPCStatusFromBytes(b []byte) (*MPCStatus, error) {
	var s MPCStatus
	err := s.Decode(b)
	if err != nil {
		return nil, err
	}
	return NewMPCStatus(s.OpcodesNames, s.BatchIds, s.CircuitsInsideBatch), nil
}

func (s *MPCStatus) Encode() ([]byte, error) {
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	err := enc.Encode(s)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (s *MPCStatus) Decode(b []byte) error {
	if len(s.OpcodesNames) != 0 || len(s.BatchIds) != 0 || len(s.CircuitsInsideBatch) != 0 {
		return errors.New("MPCStatus already initialized")
	}
	buf := bytes.NewBuffer(b)
	dec := gob.NewDecoder(buf)
	return dec.Decode(s)
}
