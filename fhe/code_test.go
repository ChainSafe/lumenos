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

func TestEncode(t *testing.T) {
	// Reset the multiplication counter at the start
	fhe.MultiplicationsCounter = 0

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
	encoder := bgv.NewEncoder(params)
	decryptor := rlwe.NewDecryptor(params, sk)
	backend := fhe.NewBackendBFV(&ptField, params, pk, nil)

	start = time.Now()
	matrix, batchedCols, err := core.RandomMatrix(rows, cols, func(u []uint64) *rlwe.Plaintext {
		plaintext := bgv.NewPlaintext(params, params.MaxLevel())
		if err := encoder.Encode(u, plaintext); err != nil {
			panic(err)
		}
		return plaintext
	})
	if err != nil {
		panic(err)
	}
	fmt.Printf("Matrix generation and encoding took: %v\n", time.Since(start))

	// fmt.Printf("Matrix before NTT: %v\n", matrix)

	// Encrypt the batched columns
	start = time.Now()
	ciphertexts := make([]*rlwe.Ciphertext, len(batchedCols))
	for i, plaintext := range batchedCols {
		ciphertext, err := backend.EncryptNew(plaintext)
		if err != nil {
			panic(err)
		}
		ciphertexts[i] = ciphertext
	}
	fmt.Printf("Encryption took: %v\n", time.Since(start))

	// Apply NTT
	start = time.Now()
	result, err := fhe.Encode(ciphertexts, rows, rhoInv, backend)
	if err != nil {
		panic(err)
	}
	fmt.Printf("FHE evaluation took: %v\n", time.Since(start))

	// Decrypt and print results
	start = time.Now()
	encodedMatrixRowMajor := make([][]*core.Element, rows)
	for i := range encodedMatrixRowMajor {
		encodedMatrixRowMajor[i] = make([]*core.Element, cols*rhoInv)
	}

	for j, ciphertext := range result {
		plaintext := decryptor.DecryptNew(ciphertext)
		column := make([]uint64, rows)
		if err := encoder.Decode(plaintext, column); err != nil {
			panic(err)
		}
		for i := range column {
			encodedMatrixRowMajor[i][j] = core.NewElement(column[i])
		}
	}
	fmt.Printf("Decryption and decoding took: %v\n", time.Since(start))
	// fmt.Printf("Encoded matrix: %v\n", encodedMatrixRowMajor)

	// Test NTT on plain values
	start = time.Now()
	encodedMatrixCheck := make([][]*core.Element, rows)
	for i := range matrix {
		encodedMatrixCheck[i] = core.Encode(matrix[i], rhoInv, &ptField)
	}
	fmt.Printf("Plain RS encoding: %v\n", time.Since(start))
	// fmt.Printf("Encoded matrix check: %v\n", encodedMatrixCheck)

	// Assert that encodedMatrixRowMajor and encodedMatrixCheck are equal
	for i := range encodedMatrixRowMajor {
		for j := range encodedMatrixRowMajor[i] {
			if !encodedMatrixRowMajor[i][j].Equal(encodedMatrixCheck[i][j]) {
				t.Fatalf("Matrices differ at [%d][%d]: expected %v, got %v", i, j, encodedMatrixRowMajor[i][j], encodedMatrixCheck[i][j])
			}
		}
	}

	fmt.Println("Matrices are equal")
	fmt.Printf("Total execution time: %v\n", time.Since(programStart))

	// Print the number of multiplications after NTT
	fmt.Printf("Number of multiplications in NTT: %d\n", fhe.MultiplicationsCounter)
}
