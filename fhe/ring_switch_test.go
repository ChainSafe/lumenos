package fhe_test

import (
	"fmt"
	"testing"

	"github.com/nulltea/lumenos/core"
	"github.com/nulltea/lumenos/fhe"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/schemes/bgv"
)

func TestRingSwitch(t *testing.T) {
	params, err := bgv.NewParametersFromLiteral(bgv.ParametersLiteral{
		LogN:             12,
		LogQ:             []int{58},
		PlaintextModulus: 0x3ee0001,
	})
	if err != nil {
		panic(err)
	}
	kgen := rlwe.NewKeyGenerator(params)
	sk, pk := kgen.GenKeyPairNew()

	rlk := kgen.GenRelinearizationKeyNew(sk)

	rotKeys := kgen.GenGaloisKeysNew(params.GaloisElementsForInnerSum(1, rows), sk)

	evk := rlwe.NewMemEvaluationKeySet(rlk, rotKeys...)

	ptField, err := core.NewPrimeField(params.PlaintextModulus(), cols*2)
	if err != nil {
		panic(err)
	}

	server := fhe.NewBackendBFV(&ptField, params, pk, evk)
	client := fhe.NewClientBFV(&ptField, params, sk)

	m := []uint64{1, 1}
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

	rs, err := fhe.NewRingSwitch(client, 12)
	if err != nil {
		panic(err)
	}

	client2 := rs.NewClient(client)

	ct2, err := rs.RingSwitch(ct, client)
	if err != nil {
		panic(err)
	}

	fmt.Printf("ct2.MetaData: IsNTT: %v, IsBatched: %v IsMontgomery: %v\n", ct2.IsNTT, ct2.IsBatched, ct2.IsMontgomery)

	pt2 := client2.DecryptNew(ct2)

	mCheck := make([]uint64, len(m))
	if err := client2.Decode(pt2, mCheck); err != nil {
		panic(err)
	}

	for i := range mCheck {
		if mCheck[i] != m[i] {
			t.Errorf("mCheck[%d] = %v, expected %v", i, mCheck[i], m[i])
		}
	}
}
