package core

import (
	"encoding/binary"
	"fmt"

	"github.com/gtank/merlin"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
)

type Transcript struct {
	*merlin.Transcript
}

func NewTranscript(name string) *Transcript {
	return &Transcript{merlin.NewTranscript(name)}
}

func (t *Transcript) AppendBytes(label string, bytes []byte) {
	t.AppendMessage([]byte(label), bytes)
}

func (t *Transcript) AppendField(label string, element *Element) {
	t.AppendMessage([]byte(label), element.ToBytes())
}

func (t *Transcript) AppendFields(label string, elements []*Element) {
	for _, element := range elements {
		t.AppendField(label, element)
	}
}

func (t *Transcript) AppendCiphertext(label string, ciphertext *rlwe.Ciphertext) {
	fmt.Printf("ciphertext values: %v\n", len(ciphertext.Element.Value))
	fmt.Printf("ciphertext [0]coeffs: %v\n", len(ciphertext.Element.Value[0].Coeffs))
	bytes, err := ciphertext.MarshalBinary()
	if err != nil {
		panic(err)
	}
	t.AppendMessage([]byte(label), bytes)
}

func (t *Transcript) SampleField(label string) *Element {
	bytes := t.ExtractBytes([]byte(label), ElementBytes)
	return NewElement(binary.LittleEndian.Uint64(bytes))
}

func (t *Transcript) SampleUint64(label string) uint64 {
	bytes := t.ExtractBytes([]byte(label), ElementBytes)
	return binary.LittleEndian.Uint64(bytes)
}

func (t *Transcript) SampleFields(label string, elements []*Element) {
	for i := range elements {
		elements[i] = t.SampleField(label)
	}
}

func (t *Transcript) SampleUints(label string, values []uint64) {
	for i := range values {
		values[i] = t.SampleUint64(label)
	}
}
