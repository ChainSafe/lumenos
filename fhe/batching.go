package fhe

import (
	"github.com/nulltea/lumenos/core"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/schemes/bgv"
)

func BatchCiphertexts(cts []*rlwe.Ciphertext, alphas [][]uint64, backend *ServerBFV) (*rlwe.Ciphertext, error) {
	rows := len(alphas)
	cols := len(cts)
	params := *backend.GetParameters()
	alphaPts := make([]*rlwe.Plaintext, len(cts))

	alphasColMajor := make([][]uint64, cols)
	for j := range alphasColMajor {
		column := make([]uint64, rows)
		for i := 0; i < rows; i++ {
			column[i] = alphas[i][j]
		}
		alphasColMajor[j] = column
	}

	for i := range cols {

		alphaPts[i] = bgv.NewPlaintext(params, params.MaxLevel())
		if err := backend.Encode(alphasColMajor[i], alphaPts[i]); err != nil {
			return nil, err
		}

		// TODO: do inner product of column and alpha, how to discard garbage slots?
	}

	batchCt, err := backend.MulNew(cts[0], alphaPts[0])
	if err != nil {
		return nil, err
	}

	for i := 1; i < len(cts); i++ {
		t, err := backend.MulNew(cts[i], alphaPts[i])
		if err != nil {
			return nil, err
		}
		err = backend.Add(batchCt, t, batchCt)
		if err != nil {
			return nil, err
		}
	}

	return batchCt, nil
}

func BatchColumns(matrix [][]*core.Element, field *core.PrimeField, transcript *core.Transcript) ([]*core.Element, [][]uint64, error) {
	rows := len(matrix)
	cols := len(matrix[0])
	alphas := make([][]uint64, rows)
	for i := range alphas {
		r := make([]uint64, cols)
		transcript.SampleUints("pod_alpha", r)
		alphas[i] = r
	}

	batchCol := make([]*core.Element, rows)
	for i := range batchCol {
		batchCol[i] = core.Zero()
	}
	for i := range matrix {
		for j := range matrix[i] {
			batchCol[i] = field.Add(batchCol[i], field.Mul(matrix[i][j], core.NewElement(alphas[i][j])))
		}
	}

	return batchCol, alphas, nil
}
