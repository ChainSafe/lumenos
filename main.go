package main

import (
	"fmt"

	"github.com/nulltea/lumenos/vdec"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/schemes/bgv"
)

const (
	Modulus = 0x3ee0001
)

func main() {
	params, err := bgv.NewParametersFromLiteral(bgv.ParametersLiteral{
		LogN:             11,
		LogQ:             []int{56},
		LogP:             []int{55, 55},
		PlaintextModulus: 0x3ee0001,
	})

	if err != nil {
		panic(err)
	}

	// Generate keys
	kgenFHE := rlwe.NewKeyGenerator(params)
	sk, _ := kgenFHE.GenKeyPairNew()

	// Crucial to use the same moduli
	qs, ps := make([]uint64, len(params.Q())), make([]uint64, len(params.P()))
	for i, qi := range params.Q() {
		qs[i] = qi
	}
	for i, pi := range params.P() {
		ps[i] = pi
	}

	server := struct {
		*bgv.Encoder
		*rlwe.Encryptor
	}{
		Encoder:   bgv.NewEncoder(params),
		Encryptor: rlwe.NewEncryptor(params, sk),
	}

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

	vdec.CallVdecProver(seed, params, sk, ct, m)
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
