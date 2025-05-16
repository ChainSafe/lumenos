package vdec_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/nulltea/lumenos/core"
	"github.com/nulltea/lumenos/fhe"
	"github.com/nulltea/lumenos/vdec"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/schemes/bgv"
)

func TestBatchCiphertexts(t *testing.T) {
	programStart := time.Now()
	cases := []struct {
		rows int
		cols int
	}{
		{1, 1},
		{128, 64},
		{256, 128},
		{1024, 1024},
	}

	for _, c := range cases {
		rows := c.rows
		cols := c.cols
		params, err := bgv.NewParametersFromLiteral(bgv.ParametersLiteral{
			LogN:             11,
			LogQ:             []int{60, 60},
			LogP:             []int{55, 55},
			PlaintextModulus: 0x3ee0001,
		})
		if err != nil {
			panic(err)
		}

		kgen := rlwe.NewKeyGenerator(params)
		sk, _ := kgen.GenKeyPairNew()

		ptField, err := core.NewPrimeField(params.PlaintextModulus(), 8*2)
		if err != nil {
			panic(err)
		}

		client := fhe.NewClientBFV(&ptField, params, sk)
		evaluator := bgv.NewEvaluator(params, nil)

		matrixColMajor, ciphertexts, err := core.RandomMatrixColMajor(rows, cols, func(u []uint64) *rlwe.Ciphertext {
			plaintext := bgv.NewPlaintext(params, params.MaxLevel())
			if err := client.Encode(u, plaintext); err != nil {
				panic(err)
			}
			ciphertext, err := client.EncryptNew(plaintext)
			if err != nil {
				panic(err)
			}
			return ciphertext
		})
		if err != nil {
			panic(err)
		}

		transcript := core.NewTranscript("batch_ciphertexts")

		batchColCheck, alphas, err := vdec.BatchColumns(matrixColMajor, &ptField, transcript)
		if err != nil {
			panic(err)
		}

		start := time.Now()
		result, err := vdec.BatchCiphertexts(ciphertexts, alphas, evaluator)
		if err != nil {
			panic(err)
		}
		fmt.Printf("FHE evaluation took: %v\n", time.Since(start))

		batchedCol := make([]*core.Element, rows)
		plaintext := client.DecryptNew(result)
		column := make([]uint64, rows)
		if err := client.Decode(plaintext, column); err != nil {
			panic(err)
		}
		for i := range column {
			batchedCol[i] = core.NewElement(column[i])
		}

		for i := range batchedCol {
			if !batchColCheck[i].Equal(batchedCol[i]) {
				t.Fatalf("Matrices differ at [%d]: expected %v, got %v", i, batchColCheck[i], batchedCol[i])
			}
		}

		fmt.Println("Batched columns are equal")
		fmt.Printf("Total execution time: %v\n", time.Since(programStart))
	}
}
