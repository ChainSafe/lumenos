package fhe

import (
	"github.com/timofey/fhe-experiments/lattigo/core"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/schemes/bgv"
)

func Encode(matrix []*rlwe.Ciphertext, rows, rhoInv int, field *core.PrimeField, backend *BackendBFV) ([]*rlwe.Ciphertext, error) {
	size := len(matrix)
	encoded := make([]*rlwe.Ciphertext, size*rhoInv)
	for i := 0; i < size; i++ {
		encoded[i] = matrix[i]
	}

	zeroColPt := bgv.NewPlaintext(backend.params, backend.params.MaxLevel())
	if err := backend.Encode(make([]uint64, rows), zeroColPt); err != nil {
		return nil, err
	}
	zeroCol, err := backend.EncryptNew(zeroColPt)
	if err != nil {
		return nil, err
	}

	// fill the rest with zeros
	for i := size; i < size*rhoInv; i++ {
		encoded[i] = zeroCol.CopyNew()
	}

	ntt, err := NTT(encoded, size*rhoInv, field, backend)
	if err != nil {
		return nil, err
	}

	return ntt, nil
}
