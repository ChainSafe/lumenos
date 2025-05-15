package vdec_test

import (
	"fmt"
	"testing"

	"github.com/nulltea/lumenos/core"
	"github.com/nulltea/lumenos/fhe"
	"github.com/nulltea/lumenos/vdec"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/schemes/bgv"
)

const (
	Modulus = 0x3ee0001
)

func TestVdecSimple(t *testing.T) {
	run(t, testVdecSimple)
}

func TestVdecBatched(t *testing.T) {
	run(t, testVdecBatched)
}

func run(t *testing.T, test func(bgv.Parameters, *fhe.ServerBFV, *fhe.ClientBFV, *testing.T)) {
	params, err := bgv.NewParametersFromLiteral(bgv.ParametersLiteral{
		LogN: 11,
		LogQ: []int{60, 55},
		// LogP:             []int{},
		PlaintextModulus: 0x3ee0001,
	})
	if err != nil {
		panic(err)
	}

	// Generate keys
	kgen := rlwe.NewKeyGenerator(params)
	sk, pk := kgen.GenKeyPairNew()

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
	m := make([]uint64, 2048)
	for i := range 2048 {
		m[i] = uint64(i)
	}

	plaintext := bgv.NewPlaintext(params, params.MaxLevel())
	// plaintext.IsBatched = false
	if err := server.Encode(m, plaintext); err != nil {
		panic(err)
	}
	fmt.Printf("pt IsBatched: %v IsNTT: %v IsMontgomery: %v\n", plaintext.IsBatched, plaintext.IsNTT, plaintext.IsMontgomery)

	ct, err := server.Encryptor.EncryptNew(plaintext)
	if err != nil {
		panic(err)
	}

	seed := []byte{2}

	pt := client.DecryptNew(ct)
	decrypted := make([]uint64, 100)
	if err := client.Decode(pt, decrypted); err != nil {
		panic(err)
	}
	vdec.CallVdecProver(seed, params, client.PoDSK(), ct, m)

	for i := range decrypted {
		if decrypted[i] != m[i] {
			t.Fatalf("decrypted[%d] = %d, expected %d", i, decrypted[i], m[i])
		}
	}
}

const (
	rows = 64
	cols = 1
)

func testVdecBatched(params bgv.Parameters, server *fhe.ServerBFV, client *fhe.ClientBFV, t *testing.T) {
	matrix, cols, err := core.RandomMatrix(rows, cols, func(u []uint64) *rlwe.Ciphertext {
		plaintext := bgv.NewPlaintext(params, params.MaxLevel())
		if err := client.Encode(u, plaintext); err != nil {
			panic(err)
		}

		ct, err := server.Encryptor.EncryptNew(plaintext)
		if err != nil {
			panic(err)
		}

		return ct
	})

	if err != nil {
		panic(err)
	}

	transcript := core.NewTranscript("vdec")

	vdec.BatchedVdec(cols, rows, client, transcript)

	// Sanity check

	transcript = core.NewTranscript("vdec")

	batchColCheck, alphas, err := fhe.BatchColumns(matrix, client.Field(), transcript)
	if err != nil {
		panic(err)
	}

	result, err := fhe.BatchCiphertexts(cols, alphas, server)
	if err != nil {
		panic(err)
	}

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
		if !batchColCheck[i].Equal(batchedCol[i]) {
			t.Fatalf("Matrices differ at [%d]: expected %v, got %v", i, batchColCheck[i], batchedCol[i])
		}
	}
}
