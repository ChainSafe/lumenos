//go:generate make build

package main

import (
	"fmt"

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
	paramsLiteral, err := fhe.GenerateBGVParamsForNTT(Cols, 13, Modulus)
	if err != nil {
		panic(err)
	}

	params, err := bgv.NewParametersFromLiteral(paramsLiteral)
	if err != nil {
		panic(err)
	}

	// Generate keys
	kgen := rlwe.NewKeyGenerator(params)
	sk, pk := kgen.GenKeyPairNew()

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
	// Encrypt the batched columns
	ciphertexts := make([]*rlwe.Ciphertext, len(batchedCols))
	for i, plaintext := range batchedCols {
		ciphertext, err := s.EncryptNew(plaintext)
		if err != nil {
			panic(err)
		}
		ciphertexts[i] = ciphertext
	}

	ligero, err := fhe.NewLigeroCommitter(128, Rows, Cols, RhoInv)
	if err != nil {
		panic(err)
	}

	span := core.StartSpan("Commit FHE evaluation", nil, "Commit FHE evaluation...")
	comm, _, err := ligero.Commit(ciphertexts, s, span)
	if err != nil {
		panic(err)
	}
	span.End()

	z := core.NewElement(1)

	transcript := core.NewTranscript("test")
	span = core.StartSpan("Prove FHE evaluation", nil, "Prove FHE evaluation...")
	encryptedProof, err := comm.Prove(z, s, transcript, span)
	if err != nil {
		panic(err)
	}
	span.End()

	verifierTranscript := core.NewTranscript("test")

	poly := core.NewDensePolyFromMatrix(matrix)
	value := poly.Evaluate(s.Field(), z)

	span = core.StartSpan("Decrypt proof", nil, "Decrypt proof...")
	proof, err := encryptedProof.Decrypt(c, true, span)
	if err != nil {
		panic(err)
	}
	span.End()

	span = core.StartSpan("Verify proof", nil)
	err = proof.Verify(z, value, c, verifierTranscript)
	if err != nil {
		panic(err)
	}
	span.End()
	fmt.Printf("Number of multiplications: %d\n", s.MulCounter())
}
