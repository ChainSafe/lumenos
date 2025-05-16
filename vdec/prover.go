package vdec

// libvdecapi.so and its dependencies (liblazer.so/a, etc.)
// must built and discoverable via LD_LIBRARY_PATH.
// Run `make libvdecapi` or `make all` in the ./c/ directory.

/*
#cgo CFLAGS: -I./c/src -I./c -I./c/lazer/src -I./c/lazer/third_party/Falcon-impl-20211101 -I./c/lazer/third_party/hexl-development/hexl/include
#cgo LDFLAGS: -L./c -lvdecapi
#cgo LDFLAGS: -L./c/lazer -llazer
#cgo LDFLAGS: -L./c/lazer/third_party/hexl-development/build/hexl/lib -lhexl
#cgo LDFLAGS: -lstdc++ -lmpfr -lgmp -lm -fopenmp

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include "c/src/vdec_wrapper.h"

// Include the wrapper header which now declares all necessary types and functions
// Matching definitions in vdec_wrapper.h

// Declare other necessary C library functions not in the wrapper header
extern void lazer_init(void);
extern void lazer_fini(void);
extern unsigned int polyring_get_deg(polyring_srcptr r);

*/
import "C"
import (
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"time"
	"unsafe"

	"github.com/nulltea/lumenos/core"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/schemes/bgv"
)

const DEGREE = 2048
const CT_COUNT = 1

// ColumnInstance is a pair of a batched ciphertext and associated decrypted column vector.
type ColumnInstance struct {
	Ct     *rlwe.Ciphertext
	Values []*core.Element
}

func ProveBfvDecBatched(instance []*ColumnInstance, witness *rlwe.SecretKey, backend *bgv.Evaluator, field *core.PrimeField, transcript *core.Transcript) error {
	cols := len(instance)
	matrixColMajor := make([][]*core.Element, cols)
	for j := range matrixColMajor {
		matrixColMajor[j] = instance[j].Values
	}

	start := time.Now()
	batchedCol, alphas, err := BatchColumns(matrixColMajor, field, transcript)
	if err != nil {
		return err
	}
	fmt.Printf("Batching decrypted columns took %s\n", time.Since(start))

	m := make([]uint64, len(batchedCol))
	for i := range batchedCol {
		m[i] = batchedCol[i].Uint64()
	}

	cts := make([]*rlwe.Ciphertext, len(instance))
	for i := range cts {
		cts[i] = instance[i].Ct
	}

	start = time.Now()
	batchCt, err := BatchCiphertexts(cts, alphas, backend)
	if err != nil {
		return err
	}
	fmt.Printf("Batching ciphertexts evaluation took %s\n", time.Since(start))
	seed := []byte{2} // TODO: use transcript random seed

	// TODO: ring and modulus switch
	levelWas := batchCt.LevelQ()
	for batchCt.LevelQ() > 0 {
		backend.Rescale(batchCt, batchCt)
	}
	if batchCt.LevelQ() < levelWas {
		fmt.Printf("rescaled batch ciphertext level Q (%d) -> %d\n", levelWas, batchCt.LevelQ())
	}

	return CallVdecProver(seed, *backend.GetParameters(), witness, batchCt, m)
}

// CallVdecProver calls the C implementation of the vdec prover.
func CallVdecProver(seed []byte, params bgv.Parameters, sk *rlwe.SecretKey, ct *rlwe.Ciphertext, m bgv.IntegerSlice) error {
	C.lazer_init()
	fmt.Println("Lazer.c initialized.")

	start := time.Now()

	// Prepare inputs
	skRingQ := params.RingQ().AtLevel(sk.LevelQ())
	ringQ := params.RingQ().AtLevel(ct.LevelQ())

	skCoeffs := core.RingPolyToCoeffsCentered(skRingQ, *sk.Value.Q.CopyNew(), true, true)
	ct0Coeffs := core.RingPolyToCoeffsCentered(ringQ, *ct.Value[0].CopyNew(), ct.MetaData.IsMontgomery, ct.MetaData.IsNTT)
	ct1Coeffs := core.RingPolyToCoeffsCentered(ringQ, *ct.Value[1].CopyNew(), ct.MetaData.IsMontgomery, ct.MetaData.IsNTT)

	pt := bgv.NewPlaintext(params, params.MaxLevel())
	pt.MetaData = ct.MetaData
	bgv.NewEncoder(params).Encode(m, pt)
	ptPoly := pt.Value

	mScaled := core.RingPolyToCoeffsCentered(ringQ, ptPoly, false, false)

	rq := C.GetRqFromVdecParams1()
	if rq == nil {
		return fmt.Errorf("failed to get Rq from params1")
	}
	proofDegree := uint32(C.polyring_get_deg(rq))
	if proofDegree == 0 {
		return fmt.Errorf("failed to get proof degree (Rq->d)")
	}
	fmt.Printf("Proof degree (Rq->d): %d\n", proofDegree)

	var seedChar [32]C.uint8_t
	for i := range seed {
		seedChar[i] = C.uint8_t(seed[i])
	}

	fheDegree := C.uint(DEGREE)

	skSign := make([]C.int8_t, DEGREE)
	for i := 0; i < DEGREE; i++ {
		skSign[i] = C.int8_t(skCoeffs[i])
	}

	numChunkPolys := DEGREE / int(proofDegree)

	skVec := C.CreatePolyvec(rq, C.uint(numChunkPolys))
	if skVec == nil {
		return fmt.Errorf("failed to create sk polyvec")
	}
	defer C.FreePolyvec(skVec)

	for i := 0; i < numChunkPolys; i++ {
		offset := i * int(proofDegree)
		if offset+int(proofDegree) > len(skCoeffs) {
			log.Fatalf(
				"error populating skVec: skCoeffs is too short for polynomial %d. need %d coefficients starting at offset %d, but len(skCoeffs) is %d.",
				i, int(proofDegree), offset, len(skCoeffs),
			)
		}
		polyCoeffsSlice := skCoeffs[offset : offset+int(proofDegree)]
		C.SetPolyvecPolyCoeffs(skVec, C.uint(i), (*C.int64_t)(unsafe.Pointer(&polyCoeffsSlice[0])), C.uint(proofDegree))
	}

	totalPolysCt := CT_COUNT * numChunkPolys

	ct0Vec := C.CreatePolyvec(rq, C.uint(totalPolysCt))
	if ct0Vec == nil {
		return fmt.Errorf("failed to create ct0 polyvec")
	}
	defer C.FreePolyvec(ct0Vec)
	for k := 0; k < CT_COUNT; k++ {
		for i := 0; i < numChunkPolys; i++ {
			polyIndexInCVec := k*numChunkPolys + i
			offset := i * int(proofDegree)
			if offset+int(proofDegree) > len(ct0Coeffs) {
				log.Fatalf("Error populating ct0Vec: ct0Coeffs is too short for component %d, polynomial %d.", k, i)
			}
			polyCoeffsSlice := ct0Coeffs[offset : offset+int(proofDegree)]
			C.SetPolyvecPolyCoeffs(ct0Vec, C.uint(polyIndexInCVec), (*C.int64_t)(unsafe.Pointer(&polyCoeffsSlice[0])), C.uint(proofDegree))
		}
	}

	ct1Vec := C.CreatePolyvec(rq, C.uint(totalPolysCt))
	if ct1Vec == nil {
		return fmt.Errorf("failed to create ct1 polyvec")
	}
	defer C.FreePolyvec(ct1Vec)
	for k := 0; k < CT_COUNT; k++ {
		for i := 0; i < numChunkPolys; i++ {
			polyIndexInCVec := k*numChunkPolys + i
			offset := i * int(proofDegree)
			if offset+int(proofDegree) > len(ct1Coeffs) {
				log.Fatalf("Error populating ct1Vec: ct1Coeffs is too short for component %d, polynomial %d.", k, i)
			}
			polyCoeffsSlice := ct1Coeffs[offset : offset+int(proofDegree)]
			C.SetPolyvecPolyCoeffs(ct1Vec, C.uint(polyIndexInCVec), (*C.int64_t)(unsafe.Pointer(&polyCoeffsSlice[0])), C.uint(proofDegree))
		}
	}

	mDeltaVec := C.CreatePolyvec(rq, C.uint(totalPolysCt))
	if mDeltaVec == nil {
		return fmt.Errorf("failed to create m_delta polyvec")
	}
	defer C.FreePolyvec(mDeltaVec)
	for k := 0; k < CT_COUNT; k++ {
		for i := 0; i < numChunkPolys; i++ {
			polyIndexInCVec := k*numChunkPolys + i
			offset := i * int(proofDegree)
			if offset+int(proofDegree) > len(mScaled) {
				return fmt.Errorf("error populating mDeltaVec: ptCoeffs is too short for component %d, polynomial %d.", k, i)
			}
			polyCoeffsSlice := mScaled[offset : offset+int(proofDegree)]
			C.SetPolyvecPolyCoeffs(mDeltaVec, C.uint(polyIndexInCVec), (*C.int64_t)(unsafe.Pointer(&polyCoeffsSlice[0])), C.uint(proofDegree))
		}
	}
	fmt.Printf("Witness generation took %s\n", time.Since(start))

	// Prove
	fmt.Println("Calling vdec_lnp_tbox...")
	start = time.Now()
	result := C.ProveVdecLnpTbox(
		&seedChar[0],
		skVec,
		&skSign[0],
		C.uint(DEGREE),
		ct0Vec,
		ct1Vec,
		mDeltaVec,
		fheDegree,
	)
	if result == 0 {
		return fmt.Errorf("generated proof is not valid")
	}
	fmt.Println("vdec_lnp_tbox call completed.")
	fmt.Printf("VDec prover time: %v\n", time.Since(start))

	C.lazer_fini()

	return nil
}

func GenerateHeaderFile(fileName string, sk *rlwe.SecretKey, ct *rlwe.Ciphertext, m bgv.IntegerSlice, params bgv.Parameters) error {
	skRingQ := params.RingQ().AtLevel(sk.LevelQ())
	ringQ := params.RingQ().AtLevel(ct.LevelQ())
	modQ := ringQ.ModulusAtLevel[ct.LevelQ()]
	modT := params.RingT().Modulus()

	skCoeffsString := core.RingPolyToStringsCentered(skRingQ, *sk.Value.Q.CopyNew(), true, true)
	ct0String := core.RingPolyToStringsCentered(ringQ, *ct.Value[0].CopyNew(), ct.MetaData.IsMontgomery, ct.MetaData.IsNTT)
	ct1String := core.RingPolyToStringsCentered(ringQ, *ct.Value[1].CopyNew(), ct.MetaData.IsMontgomery, ct.MetaData.IsNTT)

	pt := bgv.NewPlaintext(params, params.MaxLevel())
	pt.MetaData = ct.MetaData
	bgv.NewEncoder(params).Encode(m, pt)
	ptPoly := pt.Value

	ptString := core.RingPolyToStringsCentered(ringQ, ptPoly, false, false)

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

	return os.WriteFile(fileName, []byte(headerContent), 0644)
}
