package vdec

// libvdecapi.so and its dependencies (liblazer.so/a, etc.)
// must built and discoverable via LD_LIBRARY_PATH.
// Run `make libvdecapi` or `make all` in the ./c/ directory.

/*
#cgo CFLAGS: -I./c/vdec -I./c -I./c/src -I./c/third_party/Falcon-impl-20211101 -I./c/third_party/hexl-development/hexl/include
#cgo LDFLAGS: -L./c -lvdecapi -llazer
#cgo LDFLAGS: -L./c/third_party/hexl-development/build/hexl/lib -lhexl
#cgo LDFLAGS: -lstdc++ -lmpfr -lgmp -lm -fopenmp

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include "c/vdec/vdec_wrapper.h"

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
	"math/big"
	"os"
	"strconv"
	"strings"
	"time"
	"unsafe"

	"github.com/nulltea/lumenos/core"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/ring"
	"github.com/tuneinsight/lattigo/v6/schemes/bgv"
)

const DEGREE = 2048
const PROOF_DEGREE = 256
const CT_COUNT = 1

// CallVdecProver calls the C implementation of the vdec prover.
// WARNING: The returned C.VdecProof struct currently contains pointers to memory
// that is freed within the C function. Accessing these pointers from Go is unsafe
// and will likely lead to crashes. A proper memory management strategy (e.g.,
// allocating proof components on the heap in C and providing a C function to free them)
// is required before using the returned proof.
func CallVdecProver(seed []byte, params bgv.Parameters, sk *rlwe.SecretKey, ct *rlwe.Ciphertext, m bgv.IntegerSlice) {
	C.lazer_init()
	fmt.Println("Lazer initialized from Go.")

	// Prepare inputs
	ringQ := params.RingQ().AtLevel(sk.LevelQ())
	modQ := ringQ.ModulusAtLevel[sk.LevelQ()]
	modT := params.RingT().Modulus()

	skCoeffs := core.RingPolyToCoeffsCentered(ringQ, *sk.Value.Q.CopyNew(), true, true)
	ct0Coeffs := core.RingPolyToCoeffsCentered(ringQ, *ct.Value[0].CopyNew(), ct.MetaData.IsMontgomery, ct.MetaData.IsNTT)
	ct1Coeffs := core.RingPolyToCoeffsCentered(ringQ, *ct.Value[1].CopyNew(), ct.MetaData.IsMontgomery, ct.MetaData.IsNTT)

	pt := bgv.NewPlaintext(params, params.MaxLevel())
	pt.IsBatched = false
	ptPoly := ringQ.NewPoly()
	delta := params.DefaultScale()
	// delta.Value = *new(big.Float).SetMode(big.ToNearestEven).Quo(
	// 	new(big.Float).SetInt(modQ),
	// 	new(big.Float).SetInt(modT),
	// )

	// TODO: how to round to nearest even like in python `delta = round(mod/mod_t)`
	delta.Value = *new(big.Float).Add(
		new(big.Float).Quo(
			new(big.Float).SetInt(modQ),
			new(big.Float).SetInt(modT),
		),
		new(big.Float).SetFloat64(0.5),
	)

	encodeRingQMulDelta(m, params, delta, ptPoly)

	mDelta := core.RingPolyToCoeffsCentered(ringQ, ptPoly, false, false)

	rq := C.GetRqFromVdecParams1()
	if rq == nil {
		log.Fatal("Failed to get Rq from params1")
	}
	fmt.Printf("Obtained Rq: %p\n", rq)
	proofDegree := uint32(C.polyring_get_deg(rq))
	if proofDegree == 0 {
		log.Fatal("Failed to get proof degree (Rq->d)")
	}
	fmt.Printf("Proof degree (Rq->d) from C: %d\n", proofDegree)

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

	fmt.Printf("Creating sk_vec with %d polynomials...\n", numChunkPolys)
	skVec := C.CreatePolyvec(rq, C.uint(numChunkPolys))
	if skVec == nil {
		log.Fatal("Failed to create sk polyvec")
	}
	defer C.FreePolyvec(skVec)

	for i := 0; i < numChunkPolys; i++ {
		offset := i * int(proofDegree)
		if offset+int(proofDegree) > len(skCoeffs) {
			log.Fatalf("Error populating skVec: skCoeffs is too short for polynomial %d. Need %d coefficients starting at offset %d, but len(skCoeffs) is %d.",
				i, int(proofDegree), offset, len(skCoeffs))
		}
		polyCoeffsSlice := skCoeffs[offset : offset+int(proofDegree)]
		C.SetPolyvecPolyCoeffs(skVec, C.uint(i), (*C.int64_t)(unsafe.Pointer(&polyCoeffsSlice[0])), C.uint(proofDegree))
	}

	totalPolysCt := CT_COUNT * numChunkPolys

	ct0Vec := C.CreatePolyvec(rq, C.uint(totalPolysCt))
	if ct0Vec == nil {
		log.Fatal("Failed to create ct0 polyvec")
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
		log.Fatal("Failed to create ct1 polyvec")
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
		log.Fatal("Failed to create m_delta polyvec")
	}
	defer C.FreePolyvec(mDeltaVec)
	for k := 0; k < CT_COUNT; k++ {
		for i := 0; i < numChunkPolys; i++ {
			polyIndexInCVec := k*numChunkPolys + i
			offset := i * int(proofDegree)
			if offset+int(proofDegree) > len(mDelta) {
				log.Fatalf("Error populating mDeltaVec: ptCoeffs is too short for component %d, polynomial %d.", k, i)
			}
			polyCoeffsSlice := mDelta[offset : offset+int(proofDegree)]
			C.SetPolyvecPolyCoeffs(mDeltaVec, C.uint(polyIndexInCVec), (*C.int64_t)(unsafe.Pointer(&polyCoeffsSlice[0])), C.uint(proofDegree))
		}
	}

	GenerateHeaderFile("vdec_ct.h", sk, ct, m, params)

	// Prove
	fmt.Println("Calling VdecLnpTbox...")
	start := time.Now()
	C.ProveVdecLnpTbox(
		&seedChar[0],
		skVec,
		&skSign[0],
		C.uint(DEGREE),
		ct0Vec,
		ct1Vec,
		mDeltaVec,
		fheDegree,
	)
	fmt.Println("VdecLnpTbox call completed.")
	fmt.Printf("Time taken: %v\n", time.Since(start))
	// defer C.FreeVdecProof(&proofResult) // Free the proof because passing reference of proof between methods doesn't work right now

	C.lazer_fini()

	// WARNING: proofResult contains dangling pointers as explained in the function comment.
	// return proofResult
}

func encodeRingQMulDelta(values bgv.IntegerSlice, params bgv.Parameters, delta rlwe.Scale, pQ ring.Poly) (err error) {
	ecd := bgv.NewEncoder(params)
	ringT := params.RingT()
	ringQ := params.RingQ().AtLevel(params.MaxLevel())
	N := ringT.N()
	T := ringT.SubRings[0].Modulus
	BRC := ringT.SubRings[0].BRedConstant

	bufT := ringT.NewPoly()
	ptT := bufT.Coeffs[0]

	var valLen int
	switch values := values.(type) {
	case []uint64:

		if len(values) > N {
			return fmt.Errorf("cannot Encode (TimeDomain): len(values)=%d > N=%d", len(values), N)
		}

		copy(ptT, values)
		valLen = len(values)
	case []int64:

		if len(values) > N {
			return fmt.Errorf("cannot Encode (TimeDomain: len(values)=%d > N=%d", len(values), N)
		}

		var sign, abs uint64
		for i, c := range values {
			sign = uint64(c) >> 63
			abs = ring.BRedAdd(uint64(c*((int64(sign)^1)-int64(sign))), T, BRC)
			ptT[i] = sign*(T-abs) | (sign^1)*abs
		}

		valLen = len(values)
	}

	for i := valLen; i < N; i++ {
		ptT[i] = 0
	}

	fmt.Printf("delta: %v\n", delta.Uint64())

	ecd.RingT2Q(params.MaxLevel(), false, bufT, pQ)
	ringQ.MulScalar(pQ, delta.Uint64(), pQ)

	return nil
}

func GenerateHeaderFile(fileName string, sk *rlwe.SecretKey, ct *rlwe.Ciphertext, m bgv.IntegerSlice, params bgv.Parameters) error {
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

	encodeRingQMulDelta(m, params, delta, ptPoly)

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

// // CallVerifyVdecLnpTbox calls the C implementation of the vdec verifier.
// // It takes the proof generated by CallVdecProver.
// // WARNING: Assumes the pointers within the proof struct are still valid.
// // Proper memory management across the CGo boundary is required for safe usage.
// func CallVerifyVdecLnpTbox(proof *C.VdecProof) int {
// 	// Need Rq to pass to the C function
// 	rq := C.GetRqFromVdecParams1()
// 	if rq == nil {
// 		log.Fatal("CallVerifyVdecLnpTbox: Failed to get Rq from params1")
// 	}
// 	fmt.Printf("Passing Rq %p to verification\n", rq)

// 	// Call the actual C verification function directly
// 	result := C.verify_vdec_lnp_tbox(proof, rq)
// 	return int(result)
// }

// // FreeProof calls the C function to free the memory allocated for the VdecProof struct.
// func FreeProof(proof *C.VdecProof) {
// 	if proof != nil {
// 		C.FreeVdecProof(proof)
// 	}
// }
