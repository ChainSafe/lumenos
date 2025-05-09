package vdec

import (
	"github.com/nulltea/lumenos/core"
	"github.com/nulltea/lumenos/fhe"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
)

func BatchCiphertexts(cts []*rlwe.Ciphertext, backend *fhe.ServerBFV, transcript *core.Transcript) (*rlwe.Ciphertext, error) {
	r := make([]uint64, len(cts))
	transcript.SampleUints("pod_alpha", r)

	return nil, nil
}
