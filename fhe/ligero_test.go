package fhe_test

import (
	"fmt"
	"testing"

	"github.com/nulltea/lumenos/core"
	"github.com/nulltea/lumenos/fhe"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/schemes/bgv"
)

const (
	rows    = 256
	cols    = 128
	Modulus = 0x3ee0001
	rhoInv  = 2
	// Modulus = 0x3ee0001
	// Modulus = 288230376150630401
	// Modulus = 144115188075593729 // allows LogN >= 15
)

func TestLigeroE2E(t *testing.T) {
	run(t, testLigeroE2E, false)
}

func TestLigeroPPD(t *testing.T) {
	run(t, testLigeroE2E, true)
}

func TestLigeroRLC(t *testing.T) {
	run(t, testLigeroRLC, false)
}

func run(t *testing.T, test func(bgv.Parameters, *fhe.ServerBFV, *fhe.ClientBFV, *testing.T, bool), vdec bool) {
	paramsLiteral, err := fhe.GenerateBGVParamsForNTT(cols, 13, Modulus)
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

	rotKeys := kgen.GenGaloisKeysNew(params.GaloisElementsForInnerSum(1, rows), sk)

	// Evaluation Key Set with the Relinearization Key
	evk := rlwe.NewMemEvaluationKeySet(rlk, rotKeys...)

	ptField, err := core.NewPrimeField(params.PlaintextModulus(), cols*2)
	if err != nil {
		panic(err)
	}

	// Initialize the necessary objects
	server := fhe.NewBackendBFV(&ptField, params, pk, evk)
	client := fhe.NewClientBFV(&ptField, params, sk)

	test(params, server, client, t, vdec)
}

func testLigeroE2E(params bgv.Parameters, s *fhe.ServerBFV, c *fhe.ClientBFV, t *testing.T, vdec bool) {
	matrix, batchedCols, err := core.RandomMatrixRowMajor(rows, cols, func(u []uint64) *rlwe.Plaintext {
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
	span := core.StartSpan("Encrypt matrix", nil)
	ciphertexts := make([]*rlwe.Ciphertext, len(batchedCols))
	for i, plaintext := range batchedCols {
		ciphertext, err := s.EncryptNew(plaintext)
		if err != nil {
			panic(err)
		}
		ciphertexts[i] = ciphertext
	}
	span.End()

	ligero, err := fhe.NewLigeroCommitter(128, rows, cols, rhoInv)
	if err != nil {
		panic(err)
	}

	println("Number of queried columns:", ligero.Queries)

	span = core.StartSpan("Commit FHE evaluation", nil, "Commit FHE evaluation...")
	comm, _, err := ligero.Commit(ciphertexts, s, span)
	if err != nil {
		panic(err)
	}
	span.EndWithNewline()
	z := core.NewElement(1)

	transcript := core.NewTranscript("test")
	span = core.StartSpan("Prove FHE evaluation", nil, "Prove FHE evaluation...")
	encryptedProof, err := comm.Prove(z, s, transcript, span)
	if err != nil {
		panic(err)
	}
	span.EndWithNewline()

	marshaled, err := encryptedProof.MarshalBinary()
	if err != nil {
		panic(err)
	}

	encryptedProof = &fhe.EncryptedProof{}
	if err := encryptedProof.UnmarshalBinary(marshaled, &params); err != nil {
		panic(err)
	}

	span = core.StartSpan("Decrypt proof", nil, "Decrypt proof...")
	verifierTranscript := core.NewTranscript("test")

	poly := core.NewDensePolyFromMatrix(matrix)
	value := poly.Evaluate(s.Field(), z)

	proof, err := encryptedProof.Decrypt(c, vdec, span)
	if err != nil {
		panic(err)
	}
	span.EndWithNewline()

	span = core.StartSpan("Verify proof", nil)
	err = proof.Verify(z, value, c, verifierTranscript)
	if err != nil {
		panic(err)
	}
	span.EndWithNewline()

	fmt.Printf("Number of multiplications: %d\n", s.MulCounter())
}

func testLigeroRLC(params bgv.Parameters, s *fhe.ServerBFV, c *fhe.ClientBFV, t *testing.T, _ bool) {
	matrix, batchedCols, err := core.RandomMatrixRowMajor(rows, cols, func(u []uint64) *rlwe.Plaintext {
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

	ligero, err := fhe.NewLigeroCommitter(128, rows, cols, rhoInv)
	if err != nil {
		panic(err)
	}

	comm, _, err := ligero.Commit(ciphertexts, s, nil)
	if err != nil {
		panic(err)
	}

	z := core.NewElement(1)

	transcript := core.NewTranscript("test")
	span := core.StartSpan("Prove FHE evaluation", nil)
	result, err := comm.Prove(z, s, transcript, span)
	if err != nil {
		panic(err)
	}
	span.End()

	span = core.StartSpan("Decrypt and decode", nil)
	vMat := make([]*core.Element, cols)

	for j, ciphertext := range result.MatR {
		plaintext := c.DecryptNew(ciphertext)
		column := make([]uint64, rows)
		if err := c.Decode(plaintext, column); err != nil {
			panic(err)
		}
		vMat[j] = core.NewElement(column[0])
	}
	span.End()

	transcriptCheck := core.NewTranscript("test")
	transcriptCheck.AppendBytes("root", comm.Tree.MerkleRoot())
	span = core.StartSpan("Prove reference", nil)
	vMatCheck, err := ligeroProveReference(matrix, s.Field(), transcriptCheck)
	if err != nil {
		panic(err)
	}
	span.End()

	for i := range vMat {
		if !vMat[i].Equal(vMatCheck[i]) {
			t.Fatalf("Matrices differ at [%d]: expected %v, got %v", i, vMatCheck[i], vMat[i])
		}
	}

	fmt.Println("Results match")
	fmt.Printf("Number of multiplications: %d\n", s.MulCounter())
}

func ligeroProveReference(matrix [][]*core.Element, field *core.PrimeField, transcript *core.Transcript) ([]*core.Element, error) {
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
