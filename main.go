//go:generate make build

package main

import (
	"fmt"

	"github.com/nulltea/lumenos/core"
	"github.com/nulltea/lumenos/fhe"
	"github.com/nulltea/lumenos/vdec"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/schemes/bgv"
)

const (
	Rows = 1
	Cols = 1
)

func main() {
	params, err := bgv.NewParametersFromLiteral(bgv.ParametersLiteral{
		LogN: 11,
		LogQ: []int{60},
		// LogP:             []int{55, 55},
		PlaintextModulus: 0x3ee0001,
	})

	if err != nil {
		panic(err)
	}

	fmt.Printf("bgv.Q: %v\n", params.Q())
	fmt.Printf("bgv.P: %v\n", params.P())
	fmt.Printf("bgv.PlaintextModulus: %v\n", params.PlaintextModulus())

	// Generate keys
	kgenFHE := rlwe.NewKeyGenerator(params)
	sk, pk := kgenFHE.GenKeyPairNew()

	ptField, err := core.NewPrimeField(params.PlaintextModulus(), 8)
	if err != nil {
		panic(err)
	}

	s := fhe.NewBackendBFV(&ptField, params, pk, nil)
	c := fhe.NewClientBFV(&ptField, params, sk)
	c.WithPoD(&ptField, params, sk)

	_, cols, err := core.RandomMatrix(Cols, Rows, func(u []uint64) *rlwe.Ciphertext {
		plaintext := bgv.NewPlaintext(params, params.MaxLevel())
		if err := s.Encode(u, plaintext); err != nil {
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

	println("Generating proof...")
	transcript := core.NewTranscript("vdec")

	_, err = vdec.BatchedVdec(cols, Rows, c, transcript)
	if err != nil {
		panic(err)
	}
}

func test_ring_switch() {
	paramsFHE, err := bgv.NewParametersFromLiteral(bgv.ParametersLiteral{
		LogN:             11,
		LogQ:             []int{56},
		LogP:             []int{55, 55},
		PlaintextModulus: 0x3ee0001,
	})

	if err != nil {
		panic(err)
	}

	// Generate keys
	kgenFHE := rlwe.NewKeyGenerator(paramsFHE)
	sk, _ := kgenFHE.GenKeyPairNew()

	// Crucial to use the same moduli
	qs, ps := make([]uint64, len(paramsFHE.Q())), make([]uint64, len(paramsFHE.P()))
	for i, qi := range paramsFHE.Q() {
		qs[i] = qi
	}
	for i, pi := range paramsFHE.P() {
		ps[i] = pi
	}

	paramsPoD, err := bgv.NewParametersFromLiteral(bgv.ParametersLiteral{
		LogN:             10,
		Q:                qs,
		P:                ps,
		PlaintextModulus: 0x3ee0001,
	})
	if err != nil {
		panic(err)
	}

	// Initialize the necessary objects
	server := struct {
		*bgv.Encoder
		*rlwe.Encryptor
		*bgv.Evaluator
	}{
		Encoder:   bgv.NewEncoder(paramsFHE),
		Encryptor: rlwe.NewEncryptor(paramsFHE, sk),
		Evaluator: bgv.NewEvaluator(paramsFHE, nil),
	}

	skPoD := rlwe.NewKeyGenerator(paramsPoD).GenSecretKeyNew()

	lvlQ := paramsFHE.MaxLevel()  // 5
	lvlP := paramsFHE.MaxLevelP() // 2  (three Pi)
	base := 13                    // 2¹³ = 8192

	ringSwitchEvk := rlwe.NewKeyGenerator(paramsFHE).GenEvaluationKeyNew(
		sk, skPoD,
		rlwe.EvaluationKeyParameters{
			LevelQ:               &lvlQ,
			LevelP:               &lvlP,
			BaseTwoDecomposition: &base,
		},
	)
	m := []uint64{1}
	plaintext := bgv.NewPlaintext(paramsFHE, paramsFHE.MaxLevel())
	plaintext.IsBatched = false
	// plaintext.IsNTT = false
	if err := server.Encode(m, plaintext); err != nil {
		panic(err)
	}

	ct, err := server.Encryptor.EncryptNew(plaintext)
	if err != nil {
		panic(err)
	}
	ctPoD := rlwe.NewCiphertext(paramsPoD, 1, paramsPoD.MaxLevel())
	fmt.Printf("ct is batched: %v\n", ct.IsBatched)

	// ringQ := paramsFHE.RingQ().AtLevel(ct.Level()) // current level (≤5) RingQP?

	// for _, poly := range ct.Value { // c0 and c1
	// 	ringQ.IMForm(poly, poly)
	// 	ringQ.INTT(poly, poly) // slots -> coeffs
	// }
	// ct.IsNTT = false
	// ct.IsBatched = false // MUST be false while in coeff domain

	// ct.IsNTT = false
	// ct.IsBatched = false
	if err := server.ApplyEvaluationKey(ct, ringSwitchEvk, ctPoD); err != nil {
		panic(err)
	}
	fmt.Printf("ctPoD is batched: %v\n", ctPoD.IsBatched)

	ptPoD := rlwe.NewDecryptor(paramsPoD, skPoD).DecryptNew(ctPoD)
	fmt.Printf("ptPoD is batched: %v\n", ptPoD.IsBatched)

	mCheck := make([]uint64, 1)
	if err := bgv.NewEncoder(paramsPoD).Decode(ptPoD, mCheck); err != nil {
		panic(err)
	}
	fmt.Printf("dataCheck: %v\n", mCheck)

	if m[0] != mCheck[0] {
		panic("data mismatch")
	}
}
