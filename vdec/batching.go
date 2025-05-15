package vdec

import (
	"github.com/nulltea/lumenos/core"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/schemes/bgv"
)

func BatchCiphertexts(cts []*rlwe.Ciphertext, alphasColMajor [][]uint64, backend *bgv.Evaluator) (*rlwe.Ciphertext, error) {
	cols := len(cts)
	params := *backend.GetParameters()
	alphaPts := make([]*rlwe.Plaintext, len(cts))

	for i := range cols {
		alphaPts[i] = bgv.NewPlaintext(params, params.MaxLevel())
		alphaPts[i].MetaData = cts[0].MetaData
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
		t, err := backend.MulScaleInvariantNew(cts[i], alphaPts[i])
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

func BatchColumns(matrixColMajor [][]*core.Element, field *core.PrimeField, transcript *core.Transcript) ([]*core.Element, [][]uint64, error) {
	rows := len(matrixColMajor[0])
	cols := len(matrixColMajor)
	alphasColMajor := make([][]uint64, cols)
	for i := range alphasColMajor {
		r := make([]uint64, rows)
		transcript.SampleUints("pod_alpha", r)
		alphasColMajor[i] = r
	}

	batchCol := make([]*core.Element, rows)
	for i := range batchCol {
		batchCol[i] = core.Zero()
	}
	for j := range matrixColMajor {
		for i := range matrixColMajor[j] {
			batchCol[i] = field.Add(batchCol[i], field.Mul(matrixColMajor[j][i], core.NewElement(alphasColMajor[j][i])))
		}
	}

	return batchCol, alphasColMajor, nil
}
