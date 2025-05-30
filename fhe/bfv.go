package fhe

import (
	"errors"
	"fmt"
	"math/bits"

	"github.com/nulltea/lumenos/core"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/schemes/bgv"
)

type ServerBFV struct {
	ptField *core.PrimeField
	params  bgv.Parameters
	*bgv.Evaluator
	*bgv.Encoder
	*rlwe.Encryptor
	rs         *RingSwitchServer
	mulCounter int
}

func NewBackendBFV(plaintextField *core.PrimeField, params bgv.Parameters, pk *rlwe.PublicKey, evk rlwe.EvaluationKeySet) *ServerBFV {
	evaluator := bgv.NewEvaluator(params, evk) // TODO: use BFV scaleInvariant=true and use MulScaleInvariant instead of MulNew
	encoder := bgv.NewEncoder(params)
	encryptor := rlwe.NewEncryptor(params, pk)
	return &ServerBFV{plaintextField, params, evaluator, encoder, encryptor, nil, 0}
}

func (b *ServerBFV) Field() *core.PrimeField {
	return b.ptField
}

func (b *ServerBFV) Mul(op0 *rlwe.Ciphertext, op1 rlwe.Operand, opOut *rlwe.Ciphertext) (err error) {
	b.mulCounter++
	return b.Evaluator.Mul(op0, op1, opOut)
}

func (b *ServerBFV) MulNew(op0 *rlwe.Ciphertext, op1 rlwe.Operand) (opOut *rlwe.Ciphertext, err error) {
	b.mulCounter++
	return b.Evaluator.MulNew(op0, op1)
}

func (b *ServerBFV) MulCounter() int {
	return b.mulCounter
}

func (b *ServerBFV) SetRingSwitchServer(rs *RingSwitchServer) {
	b.rs = rs
}

func (b *ServerBFV) RingSwitch() *RingSwitchServer {
	return b.rs
}

func (b *ServerBFV) CopyNew() *ServerBFV {
	return &ServerBFV{b.ptField, b.params, b.Evaluator.ShallowCopy(), b.Encoder.ShallowCopy(), b.Encryptor.ShallowCopy(), b.rs, b.mulCounter}
}

type ClientBFV struct {
	ptField   *core.PrimeField
	paramsFHE bgv.Parameters
	*bgv.Encoder
	*rlwe.Encryptor
	*rlwe.Decryptor
	sk *rlwe.SecretKey
	*bgv.Evaluator
	rs *RingSwitch

	// paramsPoD *bgv.Parameters
	// pod       *ServerBFV
	// podSk     *rlwe.SecretKey
}

func NewClientBFV(plaintextField *core.PrimeField, paramsFHE bgv.Parameters, sk *rlwe.SecretKey) *ClientBFV {
	encoder := bgv.NewEncoder(paramsFHE)
	encryptor := rlwe.NewEncryptor(paramsFHE, sk)
	decryptor := rlwe.NewDecryptor(paramsFHE, sk)
	evaluator := bgv.NewEvaluator(paramsFHE, nil)
	return &ClientBFV{plaintextField, paramsFHE, encoder, encryptor, decryptor, sk, evaluator, nil}
}

func (b *ClientBFV) SecretKey() *rlwe.SecretKey {
	return b.sk
}

func (b *ClientBFV) Field() *core.PrimeField {
	return b.ptField
}

func (b *ClientBFV) GetRingSwitchEvk(paramsPoD bgv.Parameters) (*rlwe.EvaluationKey, *rlwe.SecretKey) {
	skPoD := rlwe.NewKeyGenerator(paramsPoD).GenSecretKeyNew()
	return rlwe.NewKeyGenerator(b.paramsFHE).GenEvaluationKeyNew(b.sk, skPoD), skPoD
}

func (b *ClientBFV) CopyNew() *ClientBFV {
	return &ClientBFV{b.ptField, b.paramsFHE, b.Encoder.ShallowCopy(), b.Encryptor.ShallowCopy(), b.Decryptor.ShallowCopy(), b.sk, b.Evaluator.ShallowCopy(), b.rs}
}

func (b *ClientBFV) SetRingSwitch(rs *RingSwitch) {
	b.rs = rs
}

func (b *ClientBFV) RingSwitch() *RingSwitch {
	return b.rs
}

// GenerateBGVParamsForNTT generates BGV parameter based on the NTT size
// and target security parameters based on the heuristic.
//
// Assumptions:
//   - nttSize: Must be a power of 2 and >= 2. This is assumed and not re-checked inside.
//
// Heuristics Applied:
//   - Multiplicative depth L = log2(nttSize) - 1.
//   - len(LogQ) = L + 2 = log2(nttSize) + 1 (one initial level, L levels for multiplications, one extra buffer level).
//   - LogQ prime sizes: Start with 60 bits, then use 59 bits for subsequent primes.
//   - len(LogP) = max(2, log2(nttSize)) (balances noise and key size).
//   - LogP prime sizes: Start with 60 bits.
//   - Xe, Xs: Left empty to use Lattigo defaults (Gaussian error, Ternary secret).
func GenerateBGVParamsForNTT(nttSize int, logN int, plaintextModulus uint64) (bgv.ParametersLiteral, error) {
	fmt.Printf("LogN: %v\n", logN)

	// --- Input Validation (Simplified) ---
	if nttSize < 2 {
		return bgv.ParametersLiteral{}, errors.New("nttSize must be >= 2")
	}
	if logN <= 0 {
		return bgv.ParametersLiteral{}, errors.New("logN must be positive")
	}
	// if plaintextModulus <= 1 {
	// 	return bgv.ParametersLiteral{}, errors.New("plaintextModulus must be > 1 and prime")
	// }

	// Check T = 1 (mod 2N) constraint
	ringDegreeN := uint64(1 << logN)
	modulus2N := 2 * ringDegreeN
	if plaintextModulus%modulus2N != 1 {
		return bgv.ParametersLiteral{}, fmt.Errorf("plaintextModulus T (%d) does not satisfy T = 1 (mod 2N) (2N=%d)", plaintextModulus, modulus2N)
	}

	// --- Parameter Generation based on Heuristics ---

	plaintextModulusBits := bits.Len64(plaintextModulus)
	var bufferLevels int

	if plaintextModulusBits > 45 { // Large T (e.g., >~45-50 bits)
		bufferLevels = 0
	} else { // Small T (e.g., <= 30 bits)
		bufferLevels = -2
	}

	// Calculate k = log2(size) efficiently using bit manipulation
	k := bits.TrailingZeros(uint(nttSize)) + bufferLevels

	// Determine LogQ length: k levels for computation + 1 buffer level = k+1
	// The formula k+1 works directly for k=1 (nttSize=2) as well.
	numQPrimes := k

	fmt.Println("ModQ chain length", numQPrimes)

	// Generate LogQ slice: Use [60, 59, 59, ...] pattern
	logQ := make([]int, numQPrimes)
	if numQPrimes > 0 {
		logQ[0] = 58 // First prime largest
		for i := 1; i < numQPrimes; i++ {
			logQ[i] = 56 // Subsequent primes slightly smaller
		}
	}

	// Determine LogP length: max(2, k) provides a balance.
	numPPrimes := 2 // max(2, k)

	// Generate LogP slice: Use [60, 60, ...] pattern
	logP := make([]int, numPPrimes)
	for i := 0; i < numPPrimes; i++ {
		logP[i] = 55
	}

	paramsLit := bgv.ParametersLiteral{
		LogN:             logN,
		LogQ:             logQ,
		LogP:             logP,
		PlaintextModulus: plaintextModulus,
	}

	return paramsLit, nil
}
