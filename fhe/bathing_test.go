package fhe_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/nulltea/lumenos/core"
	"github.com/nulltea/lumenos/fhe"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/schemes/bgv"
)

func TestBatchCiphertexts(t *testing.T) {
	programStart := time.Now()
	start := time.Now()

	paramsLiteral, err := fhe.GenerateBGVParamsForNTT(cols, 13, Modulus)
	if err != nil {
		panic(err)
	}

	params, err := bgv.NewParametersFromLiteral(paramsLiteral)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Parameter generation took: %v\n", time.Since(start))

	// Generate keys
	start = time.Now()
	kgen := rlwe.NewKeyGenerator(params)
	sk, pk := kgen.GenKeyPairNew()
	fmt.Printf("Key generation took: %v\n", time.Since(start))

	ptField, err := core.NewPrimeField(params.PlaintextModulus(), cols*2)
	if err != nil {
		panic(err)
	}

	// Initialize the necessary objects
	server := fhe.NewBackendBFV(&ptField, params, pk, nil)
	client := fhe.NewClientBFV(&ptField, params, sk)

	start = time.Now()
	matrix, batchedCols, err := core.RandomMatrix(rows, cols, func(u []uint64) *rlwe.Plaintext {
		plaintext := bgv.NewPlaintext(params, params.MaxLevel())
		if err := client.Encode(u, plaintext); err != nil {
			panic(err)
		}
		return plaintext
	})
	if err != nil {
		panic(err)
	}
	fmt.Printf("Matrix generation and encoding took: %v\n", time.Since(start))

	// Encrypt the batched columns
	ciphertexts := make([]*rlwe.Ciphertext, len(batchedCols))
	for i, plaintext := range batchedCols {
		ciphertext, err := server.EncryptNew(plaintext)
		if err != nil {
			panic(err)
		}
		ciphertexts[i] = ciphertext
	}
	transcript := core.NewTranscript("batch_ciphertexts")

	batchColCheck, alphas, err := fhe.BatchColumns(matrix, rows, &ptField, transcript)
	if err != nil {
		panic(err)
	}

	start = time.Now()
	result, err := fhe.BatchCiphertexts(ciphertexts, alphas, server)
	if err != nil {
		panic(err)
	}
	fmt.Printf("FHE evaluation took: %v\n", time.Since(start))

	batchedCol := make([]*core.Element, rows)
	plaintext := client.DecryptNew(result)
	column := make([]uint64, rows)
	if err := server.Decode(plaintext, column); err != nil {
		panic(err)
	}
	for i := range column {
		batchedCol[i] = core.NewElement(column[i])
	}

	// Assert that batchedCol and batchColCheck are equal
	for i := range batchedCol {
		if !batchedCol[i].Equal(batchColCheck[i]) {
			t.Fatalf("Matrices differ at [%d]: expected %v, got %v", i, batchedCol[i], batchColCheck[i])
		}
	}

	fmt.Println("Batched columns are equal")
	fmt.Printf("Total execution time: %v\n", time.Since(programStart))
}
