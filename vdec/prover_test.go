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
		LogN:             11,
		LogQ:             []int{60, 55},
		PlaintextModulus: 0x3ee0001,
	})
	if err != nil {
		panic(err)
	}

	// Generate keys
	kgen := rlwe.NewKeyGenerator(params)
	sk, pk := kgen.GenKeyPairNew()

	ptField, err := core.NewPrimeField(params.PlaintextModulus(), 8)
	if err != nil {
		panic(err)
	}

	server := fhe.NewBackendBFV(&ptField, params, pk, nil)
	client := fhe.NewClientBFV(&ptField, params, sk)

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
	span := core.StartSpan("Prove BfvDecBatched", nil, "Prove BfvDecBatched...")
	vdec.CallVdecProver(seed, params, client.SecretKey(), ct, m, span)
	span.End()

	for i := range decrypted {
		if decrypted[i] != m[i] {
			t.Fatalf("decrypted[%d] = %d, expected %d", i, decrypted[i], m[i])
		}
	}
}

func testVdecBatched(params bgv.Parameters, server *fhe.ServerBFV, client *fhe.ClientBFV, t *testing.T) {
	cases := []struct {
		rows int
		cols int
	}{
		{2048, 1024},
		// {1024, 2048}, // TODO: running two tests consecutively takes longer than expected
	}

	for _, c := range cases {
		rows := c.rows
		cols := c.cols
		matrixColMajor, ciphertexts, err := core.RandomMatrixColMajor(rows, cols, Modulus, func(u []uint64) *rlwe.Ciphertext {
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

		colsCheck := make([]*rlwe.Ciphertext, len(ciphertexts))
		for i := range ciphertexts {
			colsCheck[i] = ciphertexts[i].CopyNew()
		}

		instance := make([]*vdec.ColumnInstance, len(ciphertexts))
		for j := range ciphertexts {
			instance[j] = &vdec.ColumnInstance{
				Values: matrixColMajor[j],
				Ct:     ciphertexts[j],
			}
		}

		transcript := core.NewTranscript("vdec")
		span := core.StartSpan("Prove BfvDecBatched", nil, "Prove BfvDecBatched...")
		err = vdec.ProveBfvDecBatched(instance, client.SecretKey(), server.Evaluator, client.Field(), transcript, span)
		span.End()
		if err != nil {
			panic(err)
		}

		// Sanity check
		batchColCheck, alphas, err := vdec.BatchColumns(matrixColMajor, client.Field(), transcript)
		if err != nil {
			panic(err)
		}
		start := time.Now()
		result, err := vdec.BatchCiphertexts(ciphertexts, alphas, server.Evaluator)
		if err != nil {
			panic(err)
		}
		elapsed := time.Since(start)
		fmt.Printf("BatchCiphertexts took %s\n", elapsed)

		for result.LevelQ() > 0 {
			server.Rescale(result, result)
			fmt.Printf("rescaled batchCt to -> level Q(%d)\n", result.LevelQ())
		}

		start = time.Now()
		batchedCol := make([]*core.Element, rows)
		plaintext := client.DecryptNew(result)
		column := make([]uint64, rows)
		if err := server.Decode(plaintext, column); err != nil {
			panic(err)
		}
		for i := range column {
			batchedCol[i] = core.NewElement(column[i])
		}
		elapsed = time.Since(start)
		fmt.Printf("Decrypt and decode took %s\n", elapsed)

		for i := range batchedCol {
			if !batchColCheck[i].Equal(batchedCol[i]) {
				t.Fatalf("Matrices differ at [%d]: expected %v, got %v", i, batchColCheck[i], batchedCol[i])
			}
		}
	}
}
