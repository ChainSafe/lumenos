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

const (
	rows    = 1
	cols    = 2
	Modulus = 0x3ee0001
)

func TestVdecSimple(t *testing.T) {
	run(t, testVdecSimple)
}

func TestVdecBatched(t *testing.T) {
	run(t, testVdecBatched)
}

func run(t *testing.T, test func(bgv.Parameters, *fhe.ServerBFV, *fhe.ClientBFV, *testing.T)) {
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
	// rlk := kgen.GenRelinearizationKeyNew(sk)

	// rotKeys := kgen.GenGaloisKeysNew(params.GaloisElementsForInnerSum(1, rows), sk)

	// // Evaluation Key Set with the Relinearization Key
	// evk := rlwe.NewMemEvaluationKeySet(rlk, rotKeys...)

	ptField, err := core.NewPrimeField(params.PlaintextModulus(), 8)
	if err != nil {
		panic(err)
	}

	// Initialize the necessary objects
	server := fhe.NewBackendBFV(&ptField, params, pk, nil)
	client := fhe.NewClientBFV(&ptField, params, sk)

	client.WithPoD(&ptField, params, sk)

	test(params, server, client, t)
}

func testVdecSimple(params bgv.Parameters, server *fhe.ServerBFV, client *fhe.ClientBFV, t *testing.T) {
	m := []uint64{1}
	plaintext := bgv.NewPlaintext(params, params.MaxLevel())
	plaintext.IsBatched = false
	if err := server.Encode(m, plaintext); err != nil {
		panic(err)
	}

	ct, err := server.Encryptor.EncryptNew(plaintext)
	if err != nil {
		panic(err)
	}

	seed := []byte{2}

	vdec.CallVdecProver(seed, params, client.PoDSK(), ct, m)
}

func testVdecBatched(params bgv.Parameters, s *fhe.ServerBFV, c *fhe.ClientBFV, t *testing.T) {
	_, cols, err := core.RandomMatrix(cols, rows, func(u []uint64) *rlwe.Ciphertext {
		plaintext := bgv.NewPlaintext(params, params.MaxLevel())
		if err := c.Encode(u, plaintext); err != nil {
			panic(err)
		}

		ct, err := s.Encryptor.EncryptNew(plaintext)
		if err != nil {
			panic(err)
		}

		return ct
	})

	if err != nil {
		panic(err)
	}

	transcript := core.NewTranscript("vdec")

	vdec.BatchedVdec(cols, rows, c, transcript)
}
