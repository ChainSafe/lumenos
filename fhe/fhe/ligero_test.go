package fhe_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/timofey/fhe-experiments/lattigo/core"
	"github.com/timofey/fhe-experiments/lattigo/fhe"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/schemes/bgv"
)

const (
	rows    = 2
	cols    = 16
	Modulus = 0x3ee0001
	rhoInv  = 2
	// Modulus = 288230376150630401
	// Modulus = 144115188075593729 // allows LogN >= 15
)

func TestLigero(t *testing.T) {
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

	// Relinearization Key
	rlk := kgen.GenRelinearizationKeyNew(sk)

	rotKeys := kgen.GenGaloisKeysNew(params.GaloisElementsForInnerSum(1, rows), sk)

	// Evaluation Key Set with the Relinearization Key
	evk := rlwe.NewMemEvaluationKeySet(rlk, rotKeys...)

	ptField, err := core.NewPrimeField(params.PlaintextModulus(), cols*2)
	if err != nil {
		panic(err)
	}

	// Initialize the necessary objects
	encoder := bgv.NewEncoder(params)
	decryptor := rlwe.NewDecryptor(params, sk)
	backend := fhe.NewBackendBFV(&ptField, params, pk, evk)

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

	transcript := core.NewTranscript("test")
	ligero := &fhe.LigeroCommitter{
		Rows:    rows,
		Cols:    cols,
		RhoInv:  rhoInv,
		Queries: 1,
	}

	comm := fhe.LigeroCommitment{
		Committer:     ligero,
		Matrix:        ciphertexts,
		EncodedMatrix: nil,
	}

	start = time.Now()
	result, err := comm.Prove(backend, transcript)
	if err != nil {
		panic(err)
	}
	fmt.Printf("FHE evaluation took: %v\n", time.Since(start))

	// Decrypt and print results
	start = time.Now()
	vMat := make([]*core.Element, cols)

	for j, ciphertext := range result {
		plaintext := decryptor.DecryptNew(ciphertext)
		column := make([]uint64, rows)
		if err := encoder.Decode(plaintext, column); err != nil {
			panic(err)
		}
		fmt.Printf("column: %v\n", column)
		vMat[j] = core.NewElement(column[0])
	}
	fmt.Printf("Decryption and decoding took: %v\n", time.Since(start))

	transcriptCheck := core.NewTranscript("test")
	start = time.Now()
	vMatCheck, err := ligeroProveReference(matrix, ptField, transcriptCheck)
	if err != nil {
		panic(err)
	}

	fmt.Printf("Plain Ligero: %v\n", time.Since(start))
	fmt.Printf("vMat check: %v\n", vMatCheck)

	for i := range vMat {
		if !vMat[i].Equal(vMatCheck[i]) {
			t.Fatalf("Matrices differ at [%d]: expected %v, got %v", i, vMatCheck[i], vMat[i])
		}
	}

	fmt.Println("Results match")
	fmt.Printf("Total execution time: %v\n", time.Since(programStart))

	fmt.Printf("Number of multiplications: %d\n", fhe.MultiplicationsCounter)
}

func ligeroProveReference(matrix [][]*core.Element, field core.PrimeField, transcript *core.Transcript) ([]*core.Element, error) {
	rows := len(matrix)
	r := make([]*core.Element, rows)
	transcript.SampleFields("r", r)

	// Compute inner products of each row with r
	cols := len(matrix[0])
	rowProducts := make([]*core.Element, cols)

	for j := 0; j < cols; j++ {
		sum := core.Zero()
		for i := 0; i < rows; i++ {
			// multiply matrix[i][j] by r[i] and add to sum
			product := field.Mul(matrix[i][j], r[i])
			sum = field.Add(sum, product)
		}
		rowProducts[j] = sum
	}

	return rowProducts, nil
}
