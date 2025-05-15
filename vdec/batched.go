package vdec

import (
	"errors"
	"fmt"

	"github.com/nulltea/lumenos/core"
	"github.com/nulltea/lumenos/fhe"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
)

func BatchedVdec(cts []*rlwe.Ciphertext, rows int, client *fhe.ClientBFV, transcript *core.Transcript) ([][]*core.Element, error) {
	matrix := make([][]*core.Element, rows)
	for j := range matrix {
		matrix[j] = make([]*core.Element, len(cts))
	}

	for j, col := range cts {
		plaintext := client.DecryptNew(col)
		column := make([]uint64, rows)
		if err := client.Decode(plaintext, column); err != nil {
			return nil, err
		}

		for i := range column {
			matrix[i][j] = core.NewElement(column[i])
		}
	}

	batchedCol, alphas, err := fhe.BatchColumns(matrix, client.Field(), transcript)
	if err != nil {
		return nil, err
	}

	m := make([]uint64, len(batchedCol))
	for i := range batchedCol {
		m[i] = batchedCol[i].Uint64()
	}

	backend := client.PoDBackend()
	if backend == nil {
		return nil, errors.New("backend not found")
	}

	batchCt, err := fhe.BatchCiphertexts(cts, alphas, backend)
	if err != nil {
		return nil, err
	}

	seed := []byte{2} // TODO: make this random?

	// TODO: ring and modulus switch
	if backend.GetParameters().RingQ().Level() > 1 {
		backend.DropLevel(batchCt, 1)
		fmt.Printf("drapped level to batchCt[0].LevelQ(): %d\n", batchCt.LevelQ())
	}

	CallVdecProver(seed, *backend.GetParameters(), client.PoDSK(), batchCt, m)

	return matrix, nil
}
