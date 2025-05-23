package fhe_test

import (
	"fmt"
	"math/big"
	"testing"

	dft "github.com/nulltea/lumenos/fhe"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/schemes/bgv"
)

func TestSlotToCoeffs(t *testing.T) {
	params, err := bgv.NewParametersFromLiteral(bgv.ParametersLiteral{
		LogN:             10,
		LogQ:             []int{58, 56},
		PlaintextModulus: 0x3ee0001,
	})
	if err != nil {
		panic(err)
	}
	// SlotsToCoeffsParameters homomorphic encoding parameters
	slotsToCoeffsParameters := dft.MatrixLiteral{
		Type:     dft.HomomorphicDecode,
		LogSlots: 4,
		Scaling:  new(big.Float).SetFloat64(1),
		LevelQ:   1, // starting level
		LevelP:   0,
		Levels:   []int{1}, // Decomposition levels of the encoding matrix (this will use one one matrix in one level)
	}

	kgen := rlwe.NewKeyGenerator(params)
	sk, _ := kgen.GenKeyPairNew()

	galEls := params.GaloisElementsForTrace(0)
	galEls = append(galEls, slotsToCoeffsParameters.GaloisElements(params)...)

	evk := rlwe.NewMemEvaluationKeySet(nil, kgen.GenGaloisKeysNew(galEls, sk)...)

	server := struct {
		*bgv.Evaluator
		*rlwe.Encryptor
		*bgv.Encoder
		*rlwe.Decryptor
	}{
		Evaluator: bgv.NewEvaluator(params, evk),
		Encryptor: bgv.NewEncryptor(params, sk),
		Encoder:   bgv.NewEncoder(params),
		Decryptor: rlwe.NewDecryptor(params, sk),
	}

	m := []uint64{1}
	plaintext := bgv.NewPlaintext(params, params.MaxLevel())
	plaintext.IsBatched = true
	if err := server.Encode(m, plaintext); err != nil {
		panic(err)
	}
	ct, err := server.Encryptor.EncryptNew(plaintext)
	if err != nil {
		panic(err)
	}

	fmt.Printf("ct.MetaData: IsNTT: %v, IsBatched: %v IsMontgomery: %v\n", ct.IsNTT, ct.IsBatched, ct.IsMontgomery)

	SlotsToCoeffsMatrix, err := dft.NewMatrixFromLiteral(params, slotsToCoeffsParameters, server.Encoder)
	if err != nil {
		panic(err)
	}

	evalHDFT := dft.NewEvaluator(params, server.Evaluator)

	ct, err = evalHDFT.SlotsToCoeffsNew(ct, nil, SlotsToCoeffsMatrix)
	if err != nil {
		panic(err)
	}
	ct.IsBatched = false

	pt := server.DecryptNew(ct)

	fmt.Printf("pt: %v\n", pt)

	mCheck := make([]uint64, len(m))
	if err := server.Decode(pt, mCheck); err != nil {
		panic(err)
	}

	for i := range mCheck {
		if mCheck[i] != m[i] {
			t.Errorf("mCheck[%d] = %v, expected %v", i, mCheck[i], m[i])
		}
	}
}
