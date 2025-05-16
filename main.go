//go:generate make build

package main

import (
	"fmt"
	"time"

	"github.com/nulltea/lumenos/core"
	"github.com/nulltea/lumenos/fhe"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/schemes/bgv"
)

const (
	Rows    = 2048
	Cols    = 1024
	Modulus = 144115188075593729
	RhoInv  = 2
)

func main() {
	start := time.Now()

	paramsLiteral, err := fhe.GenerateBGVParamsForNTT(Cols, 13, Modulus)
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

	rotKeys := kgen.GenGaloisKeysNew(params.GaloisElementsForInnerSum(1, Rows), sk)

	// Evaluation Key Set with the Relinearization Key
	evk := rlwe.NewMemEvaluationKeySet(rlk, rotKeys...)

	ptField, err := core.NewPrimeField(params.PlaintextModulus(), Cols*2)
	if err != nil {
		panic(err)
	}

	// Initialize the necessary objects
	s := fhe.NewBackendBFV(&ptField, params, pk, evk)
	c := fhe.NewClientBFV(&ptField, params, sk)

	start = time.Now()
	matrix, batchedCols, err := core.RandomMatrixRowMajor(Rows, Cols, func(u []uint64) *rlwe.Plaintext {
		plaintext := bgv.NewPlaintext(params, params.MaxLevel())
		if err := c.Encode(u, plaintext); err != nil {
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
		ciphertext, err := s.EncryptNew(plaintext)
		if err != nil {
			panic(err)
		}
		ciphertexts[i] = ciphertext
	}
	fmt.Printf("Encryption took: %v\n", time.Since(start))

	ligero := &fhe.LigeroCommitter{
		LigeroMetadata: fhe.LigeroMetadata{
			Rows:    Rows,
			Cols:    Cols,
			RhoInv:  RhoInv,
			Queries: 1,
		},
	}

	comm, _, err := ligero.Commit(ciphertexts, s)
	if err != nil {
		panic(err)
	}

	z := core.NewElement(1)

	start = time.Now()
	transcript := core.NewTranscript("test")
	encryptedProof, err := comm.Prove(z, s, transcript)
	if err != nil {
		panic(err)
	}
	fmt.Printf("FHE evaluation took: %v\n", time.Since(start))

	verifierTranscript := core.NewTranscript("test")

	poly := core.NewDensePolyFromMatrix(matrix)
	value := poly.Evaluate(s.Field(), z)

	proof, err := encryptedProof.Decrypt(c, true)
	if err != nil {
		panic(err)
	}

	err = proof.Verify(z, value, c, verifierTranscript)
	if err != nil {
		panic(err)
	}

	fmt.Printf("Number of multiplications: %d\n", s.MulCounter())
}
