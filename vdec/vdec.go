package vdec

// IMPORTANT: Before running, ensure libvdecapi.so and its dependencies (liblazer.so/a, etc.)
// are built and discoverable (e.g., in LD_LIBRARY_PATH or install path).
// Run `make libvdecapi` or `make all` in the ./c/ directory.

/*
#cgo CFLAGS: -I./c/vdec -I./c -I./c/src -I./c/third_party/Falcon-impl-20211101 -I./c/third_party/hexl-development/hexl/include
#cgo LDFLAGS: -L./c -lvdecapi -llazer
#cgo LDFLAGS: -L./c/third_party/hexl-development/build/hexl/lib -lhexl
#cgo LDFLAGS: -lstdc++ -lmpfr -lgmp -lm -fopenmp

#include "c/vdec/vdec_wrapper.h" // Path updated
#include "c/lazer.h" // Path updated - For lazer_init / lazer_clear, polyring_get_deg
#include <stdio.h> // for printf in C if used for debugging

extern void lazer_fini(void); // Explicit declaration for lazer_fini

void call_lazer_init() { // Helper to call from Go main once
    lazer_init();
}

void call_lazer_fini() { // Helper to call from Go main at end
    lazer_fini();
}
unsigned int get_poly_degree_from_ring(polyring_srcptr r) {
    if (r) return polyring_get_deg(r);
    return 0;
}
*/
import "C"
import (
	"fmt"
	"log"
	"math/big"
	"unsafe"

	"github.com/nulltea/lumenos/core"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/ring"
	"github.com/tuneinsight/lattigo/v6/schemes/bgv"
)

const DEGREE = 2048      // Matching #define DEGREE in vdec.c
const PROOF_DEGREE = 256 // Example, actual value from Rq->d, see lazer.h / params

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

	// paramsPoD, err := bgv.NewParametersFromLiteral(bgv.ParametersLiteral{
	// 	LogN:             10,
	// 	Q:                qs,
	// 	P:                ps,
	// 	PlaintextModulus: 0x3ee0001,
	// })
	// if err != nil {
	// 	panic(err)
	// }

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
	// plaintext.IsNTT = false
	if err := server.Encode(m, plaintext); err != nil {
		panic(err)
	}

	ct, err := server.Encryptor.EncryptNew(plaintext)
	if err != nil {
		panic(err)
	}

	ringQ := params.RingQ().AtLevel(sk.LevelQ())
	modQ := ringQ.ModulusAtLevel[sk.LevelQ()]
	modT := params.RingT().Modulus()

	// Convert secret key to string
	skCoeffs := core.RingPolyToCoeffsCentered(ringQ, *sk.Value.Q.CopyNew(), true, true)

	// Convert ciphertext components to strings
	// fmt.Printf("ct.MetaData: %v, %v\n", ct.MetaData.IsMontgomery, ct.MetaData.IsNTT)
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

	EncodeRingQ(m, params, delta, ptPoly)

	// Convert plaintext to string
	ptCoeffs := core.RingPolyToCoeffsCentered(ringQ, ptPoly, false, false)

	call_vdec_prover(skCoeffs, ct0Coeffs, ct1Coeffs, ptCoeffs)
}

func call_vdec_prover(skCoeffs, ct0Coeffs, ct1Coeffs, ptCoeffs []int64) {
	C.call_lazer_init()
	fmt.Println("Lazer initialized from Go.")

	// 1. Get Rq (ring parameters) from C
	rq := C.GetRqFromVdecParams1()
	if rq == nil {
		log.Fatal("Failed to get Rq from params1")
	}
	fmt.Printf("Obtained Rq: %p\n", rq)
	actualProofDegree := uint32(C.get_poly_degree_from_ring(rq))
	if actualProofDegree == 0 {
		log.Fatal("Failed to get proof degree (Rq->d)")
	}
	fmt.Printf("Proof degree (Rq->d) from C: %d\n", actualProofDegree)

	// 2. Prepare arguments for VdecLnpTboxWrapper
	// Seed (32 bytes)
	var seed [32]C.uchar
	for i := range seed {
		seed[i] = C.uchar(0) // Example seed data
	}

	// fhe_degree
	fheDegree := C.uint(DEGREE)

	// sk_sign (length fhe_degree)
	// skSignLen := DEGREE
	skSign := make([]C.schar, DEGREE)
	for i := 0; i < DEGREE; i++ {
		skSign[i] = C.schar(skCoeffs[i]) // Example data: -1, 0, 1
	}

	// Create and populate polyvec_t structures
	// Number of polynomials in sk, ct0, etc. (e.g., fhe_degree / proof_degree)
	fmt.Printf("DEGREE: %d, actualProofDegree: %d\n", DEGREE, actualProofDegree)
	numPolys := DEGREE / int(actualProofDegree)
	fmt.Printf("numPolys: %d\n", numPolys)

	fmt.Printf("Creating sk_vec with %d polynomials...\n", numPolys)
	skVec := C.CreatePolyvec(rq, C.uint(numPolys))
	if skVec == nil {
		log.Fatal("Failed to create sk polyvec")
	}
	defer C.FreePolyvec(skVec)

	// Populate skVec (example: fill first poly with 1s)
	// skPoly0Coeffs := make([]int64, actualProofDegree)
	// for i := range skPoly0Coeffs {
	// 	skPoly0Coeffs[i] = 1
	// }
	// C.SetPolyvecPolyCoeffs(skVec, 0, (*C.int64_t)(unsafe.Pointer(&skPoly0Coeffs[0])), C.uint(actualProofDegree))

	// Correctly populate skVec using skCoeffs, mirroring the C logic
	for i := 0; i < numPolys; i++ {
		offset := i * int(actualProofDegree)
		// Ensure skCoeffs is long enough
		if offset+int(actualProofDegree) > len(skCoeffs) {
			log.Fatalf("Error populating skVec: skCoeffs is too short for polynomial %d. Need %d coefficients starting at offset %d, but len(skCoeffs) is %d.",
				i, int(actualProofDegree), offset, len(skCoeffs))
		}
		polyCoeffsSlice := skCoeffs[offset : offset+int(actualProofDegree)]
		C.SetPolyvecPolyCoeffs(skVec, C.uint(i), (*C.int64_t)(unsafe.Pointer(&polyCoeffsSlice[0])), C.uint(actualProofDegree))
	}
	fmt.Println("sk_vec created and populated using skCoeffs.")

	// ct0, ct1, m_delta (similarly create and populate)
	// For this example, let's create them but leave them mostly zero or minimally populated
	fmt.Printf("Creating ct0_vec with %d polynomials...\n", numPolys)
	ct0Vec := C.CreatePolyvec(rq, C.uint(numPolys))
	if ct0Vec == nil {
		log.Fatal("Failed to create ct0 polyvec")
	}
	defer C.FreePolyvec(ct0Vec)
	// Populate ct0Vec (e.g. first poly with 2s)
	ct0Poly0Coeffs := make([]int64, actualProofDegree)
	for i := range ct0Poly0Coeffs {
		ct0Poly0Coeffs[i] = 2
	}
	C.SetPolyvecPolyCoeffs(ct0Vec, 0, (*C.int64_t)(unsafe.Pointer(&ct0Poly0Coeffs[0])), C.uint(actualProofDegree))
	fmt.Println("ct0_vec created.")

	fmt.Printf("Creating ct1_vec with %d polynomials...\n", numPolys)
	ct1Vec := C.CreatePolyvec(rq, C.uint(numPolys))
	if ct1Vec == nil {
		log.Fatal("Failed to create ct1 polyvec")
	}
	defer C.FreePolyvec(ct1Vec)
	fmt.Println("ct1_vec created.\n")

	fmt.Printf("Creating mDeltaVec with %d polynomials...\n", numPolys)
	mDeltaVec := C.CreatePolyvec(rq, C.uint(numPolys))
	if mDeltaVec == nil {
		log.Fatal("Failed to create m_delta polyvec")
	}
	defer C.FreePolyvec(mDeltaVec)
	fmt.Println("mDeltaVec created.")

	// 3. Call the C wrapper function
	fmt.Println("Calling VdecLnpTbox...")
	C.VdecLnpTbox(
		&seed[0],
		skVec,
		&skSign[0],
		C.uint(DEGREE),
		ct0Vec,
		ct1Vec,
		mDeltaVec,
		fheDegree,
	)
	fmt.Println("VdecLnpTbox call completed.")

	C.call_lazer_fini()
	fmt.Println("Lazer cleared/finished from Go.")
}

func EncodeRingQ(values bgv.IntegerSlice, params bgv.Parameters, delta rlwe.Scale, pQ ring.Poly) (err error) {
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
