package fhe

import (
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/schemes/bgv"
)

func Encode(matrix []*rlwe.Ciphertext, rows, rhoInv int, backend *ServerBFV) ([]*rlwe.Ciphertext, error) {
	size := len(matrix)
	encoded := make([]*rlwe.Ciphertext, size*rhoInv)
	for i := 0; i < size; i++ {
		encoded[i] = matrix[i].CopyNew()
	}

	zeroColPt := bgv.NewPlaintext(backend.params, backend.params.MaxLevel())
	if err := backend.Encode(make([]uint64, rows), zeroColPt); err != nil {
		return nil, err
	}
	zeroCol, err := backend.EncryptNew(zeroColPt)
	if err != nil {
		return nil, err
	}

	for i := size; i < size*rhoInv; i++ {
		encoded[i] = zeroCol.CopyNew()
	}

	ntt, err := NTT(encoded, size*rhoInv, backend)
	if err != nil {
		return nil, err
	}

	return ntt, nil
}
