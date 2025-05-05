package fhe_test

import (
	"encoding/binary"
	"fmt"
	"testing"
	"time"

	"github.com/timofey/fhe-experiments/lattigo/core"
	"github.com/timofey/fhe-experiments/lattigo/fhe"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/schemes/bgv"
	"golang.org/x/crypto/chacha20"
)

// makeMatrix generates a matrix in both row-major and column-major
func makeMatrix(rows, cols int, batchEncoder func([]uint64) *rlwe.Plaintext) ([][]*core.Element, []*rlwe.Plaintext, error) {
	if rows <= 0 || cols <= 0 {
		return nil, nil, fmt.Errorf("dimensions must be positive")
	}
	if rows&(rows-1) != 0 {
		return nil, nil, fmt.Errorf("rows must be a power of 2")
	}

	seed := make([]byte, 32)
	binary.LittleEndian.PutUint64(seed, 1)
	cipher, err := chacha20.NewUnauthenticatedCipher(seed, make([]byte, 12))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to initialize ChaCha20: %v", err)
	}

	rowMatrix := make([][]*core.Element, rows)
	for i := range rowMatrix {
		rowMatrix[i] = make([]*core.Element, cols)
		randomBytes := make([]byte, 8*cols)
		cipher.XORKeyStream(randomBytes, randomBytes)
		for j := 0; j < cols; j++ {
			rowMatrix[i][j] = core.NewElement(binary.LittleEndian.Uint64(randomBytes[j*8:(j+1)*8]) % 255)
		}
	}

	// transpose
	colMatrix := make([]*rlwe.Plaintext, cols)
	for j := range colMatrix {
		column := make([]uint64, rows)
		for i := 0; i < rows; i++ {
			column[i] = rowMatrix[i][j].Uint64()
		}
		colMatrix[j] = batchEncoder(column)
	}

	return rowMatrix, colMatrix, nil
}

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
	matrix, batchedCols, err := makeMatrix(rows, cols, func(u []uint64) *rlwe.Plaintext {
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
