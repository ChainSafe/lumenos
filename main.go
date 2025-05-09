package main

import (
	"fmt"
	"math/big"
	"os"
	"strconv"
	"strings"

	"github.com/nulltea/lumenos/core"
	"github.com/nulltea/lumenos/vdec"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/schemes/bgv"
)

const (
	Modulus = 0x3ee0001
)

func main() {
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

	// Generate header file with cryptographic parameters
	if err := generateHeaderFile("vdec_ct.h", sk, ct, m, paramsFHE); err != nil {
		fmt.Printf("Failed to generate header file: %v\n", err)
	} else {
		fmt.Println("Successfully generated vdec_ct.h")
	}
}

func generateHeaderFile(fileName string, sk *rlwe.SecretKey, ct *rlwe.Ciphertext, m []uint64, params bgv.Parameters) error {
	ringQ := params.RingQ().AtLevel(sk.LevelQ())
	modQ := ringQ.ModulusAtLevel[sk.LevelQ()]
	modT := params.RingT().Modulus()

	// Convert secret key to string
	skCoeffsString := core.RingPolyToStringsCentered(ringQ, *sk.Value.Q.CopyNew(), true, true)

	// Convert ciphertext components to strings
	// fmt.Printf("ct.MetaData: %v, %v\n", ct.MetaData.IsMontgomery, ct.MetaData.IsNTT)
	ct0String := core.RingPolyToStringsCentered(ringQ, *ct.Value[0].CopyNew(), ct.MetaData.IsMontgomery, ct.MetaData.IsNTT)
	ct1String := core.RingPolyToStringsCentered(ringQ, *ct.Value[1].CopyNew(), ct.MetaData.IsMontgomery, ct.MetaData.IsNTT)

	pt := bgv.NewPlaintext(params, params.MaxLevel())
	pt.IsBatched = false
	ptPoly := ringQ.NewPoly()
	delta := params.DefaultScale()
	fmt.Printf("modQ: %v, modT: %v\n", modQ, modT)
	// delta.Value = *new(big.Float).SetMode(big.ToNearestEven).Quo(
	// 	new(big.Float).SetInt(modQ),
	// 	new(big.Float).SetInt(modT),
	// )

	delta.Value = *new(big.Float).Add(
		new(big.Float).Quo(
			new(big.Float).SetInt(modQ),
			new(big.Float).SetInt(modT),
		),
		new(big.Float).SetFloat64(0.5),
	)

	vdec.EncodeRingQ(m, params, delta, ptPoly)

	// Convert plaintext to string
	ptString := core.RingPolyToStringsCentered(ringQ, ptPoly, false, false)

	// Format the values for C header
	formatForHeader := func(values []string) string {
		var builder strings.Builder
		for i, val := range values {
			if i > 0 && i%5 == 0 {
				builder.WriteString(",\n    ")
			} else if i > 0 {
				builder.WriteString(", ")
			}
			builder.WriteString(val)
		}
		return builder.String()
	}

	modQStr := strconv.FormatUint(modQ.Uint64(), 10)
	modTStr := strconv.FormatUint(modT.Uint64(), 10)
	// Create header content
	headerContent := fmt.Sprintf(`#ifndef VDEC_CT_H
#define VDEC_CT_H
#include <stdint.h>

// Modulus Q = %s
// Modulus T = %s

static const int64_t static_sk[] = {
    %s
};
static const int64_t static_ct0[] = {
    %s
};
static const int64_t static_ct1[] = {
    %s
};
static const int64_t static_m_delta[] = {
    %s
};

#endif /* VDEC_CT_H */
`, modQStr, modTStr, formatForHeader(skCoeffsString), formatForHeader(ct0String), formatForHeader(ct1String), formatForHeader(ptString))

	// Write to file
	return os.WriteFile(fileName, []byte(headerContent), 0644)
}
