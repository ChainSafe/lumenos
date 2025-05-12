package fhe

import (
	"github.com/nulltea/lumenos/core"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/schemes/bgv"
)

func BatchCiphertexts(cts []*rlwe.Ciphertext, alphas [][]uint64, backend *ServerBFV) (*rlwe.Ciphertext, error) {
	params := *backend.GetParameters()
	alphaPts := make([]*rlwe.Plaintext, len(cts))
	for i := range cts {

		alphaPts[i] = bgv.NewPlaintext(params, params.MaxLevel())
		if err := backend.Encode(alphas[i], alphaPts[i]); err != nil {
			return nil, err
		}

		// TODO: do inner product of column and alpha, how to discard garbage slots?
	}

	batchCt := backend.EncryptZeroNew(params.MaxLevel())

	for i := range cts {
		err := backend.MulThenAdd(cts[i], alphaPts[i], batchCt)
		if err != nil {
			return nil, err
		}
	}

	return batchCt, nil
}

func BatchColumns(matrix [][]*core.Element, rows int, field *core.PrimeField, transcript *core.Transcript) ([]*core.Element, [][]uint64, error) {
	alphas := make([][]uint64, len(matrix))
	for i := range alphas {
		r := make([]uint64, rows)
		transcript.SampleUint64("pod_alpha")
		alphas[i] = r
	}

	batchCol := make([]*core.Element, len(matrix))
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
