package fhe

import (
	"github.com/timofey/fhe-experiments/lattigo/core"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
)

func Encode(matrix []*rlwe.Ciphertext, rhoInv int, field *core.PrimeField, backend *BackendBFV) ([]*rlwe.Ciphertext, error) {
	size := len(matrix)
	encoded := make([]*rlwe.Ciphertext, size*rhoInv)
	for i := 0; i < size; i++ {
		encoded[i] = matrix[i]
	}

	// fill the rest with zeros
	for i := size; i < size*rhoInv; i++ {
		encoded[i] = rlwe.NewCiphertext(backend.params, backend.params.MaxLevel(), backend.params.MaxLevel())
	}

	ntt, err := NTT(encoded, size*rhoInv, field, backend)
	if err != nil {
		return nil, err
	}

	return ntt, nil
}
