package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math/bits"
	"time"

	"github.com/timofey/fhe-experiments/lattigo/math"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/schemes/bgv"
	"golang.org/x/crypto/chacha20"
)

// Global counter for multiplications in NTT
var nttMultiplications int

// makeMatrix generates a matrix in both row-major and column-major format using ChaCha20
// Returns:
// 1. Row-major matrix as [][]uint64 where first index is row
// 2. Column-major matrix as [][]uint64 where first index is column
// 3. Error if any
func makeMatrix(rows, cols int, batchEncoder func([]uint64) *rlwe.Plaintext) ([][]*math.Element, []*rlwe.Plaintext, error) {
	if rows <= 0 || cols <= 0 {
		return nil, nil, fmt.Errorf("dimensions must be positive")
	}
	if rows&(rows-1) != 0 {
		return nil, nil, fmt.Errorf("rows must be a power of 2")
	}

	// Initialize ChaCha20 with seed 1 (matching Rust implementation)
	// In Rust, seed_from_u64(1) sets the first 8 bytes to 1 and rest to 0
	seed := make([]byte, 32)
	binary.LittleEndian.PutUint64(seed, 1)
	cipher, err := chacha20.NewUnauthenticatedCipher(seed, make([]byte, 12))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to initialize ChaCha20: %v", err)
	}

	// Generate row-major matrix first
	rowMatrix := make([][]*math.Element, rows)
	for i := range rowMatrix {
		rowMatrix[i] = make([]*math.Element, cols)
		// Generate random bytes for the entire row at once
		randomBytes := make([]byte, 8*cols)
		cipher.XORKeyStream(randomBytes, randomBytes)
		// Convert bytes to uint64 values and limit to 8 bits
		for j := 0; j < cols; j++ {
			// Match Rust's gen::<u64>() behavior
			rowMatrix[i][j] = math.NewElement(binary.LittleEndian.Uint64(randomBytes[j*8:(j+1)*8]) % 255)
		}
	}

	// Create column-major matrix by transposing
	colMatrix := make([]*rlwe.Plaintext, cols)
	for j := range colMatrix {
		column := make([]uint64, rows)
		for i := 0; i < rows; i++ {
			column[i] = rowMatrix[i][j].Uint64()
		}
		colMatrix[j] = batchEncoder(column)
	}

	return rowMatrix, colMatrix, nil
}

func ntt(values []*rlwe.Ciphertext, size int, field *math.PrimeField, evaluator *bgv.Evaluator) ([]*rlwe.Ciphertext, error) {
	if err := nttInner(values, size, field, evaluator); err != nil {
		return nil, err
	}
	return values, nil
}

// nttInner performs NTT on batched ciphertexts using the BGV evaluator
func nttInner(v []*rlwe.Ciphertext, size int, field *math.PrimeField, evaluator *bgv.Evaluator) error {
	switch size {
	case 0, 1:
		return nil
	case 2:
		for i := 0; i < len(v); i += 2 {
			v0, v1 := v[i].CopyNew(), v[i+1].CopyNew()
			err := evaluator.Add(v0, v1, v[i])
			if err != nil {
				return err
			}
			err = evaluator.Sub(v0, v1, v[i+1])
			if err != nil {
				return err
			}
		}
	case 4:
		for i := 0; i < len(v); i += 4 {
			// (v[0], v[2]) = (v[0] + v[2], v[0] - v[2])
			v0, v2 := v[i].CopyNew(), v[i+2].CopyNew()
			err := evaluator.Add(v0, v2, v[i])
			if err != nil {
				return err
			}
			err = evaluator.Sub(v0, v2, v[i+2])
			if err != nil {
				return err
			}

			// (v[1], v[3]) = (v[1] + v[3], v[1] - v[3])
			v1, v3 := v[i+1].CopyNew(), v[i+3].CopyNew()
			err = evaluator.Add(v1, v3, v[i+1])
			if err != nil {
				return err
			}
			err = evaluator.Sub(v1, v3, v[i+3])
			if err != nil {
				return err
			}

			err = evaluator.Mul(v[i+3], field.RootForwardUint64(4), v[i+3])
			if err != nil {
				return err
			}
			nttMultiplications++

			// (v[0], v[1]) = (v[0] + v[1], v[0] - v[1])
			v0, v1 = v[i].CopyNew(), v[i+1].CopyNew()
			err = evaluator.Add(v0, v1, v[i])
			if err != nil {
				return err
			}
			err = evaluator.Sub(v0, v1, v[i+1])
			if err != nil {
				return err
			}

			// (v[2], v[3]) = (v[2] + v[3], v[2] - v[3])
			v2, v3 = v[i+2].CopyNew(), v[i+3].CopyNew()
			err = evaluator.Add(v2, v3, v[i+2])
			if err != nil {
				return err
			}
			err = evaluator.Sub(v2, v3, v[i+3])
			if err != nil {
				return err
			}

			// (v[1], v[2]) = (v[2], v[1])
			v[i+1], v[i+2] = v[i+2], v[i+1]
		}
	case 8:
		for i := 0; i < len(v); i += 8 {
			// First level butterflies
			v0, v4 := v[i].CopyNew(), v[i+4].CopyNew()
			err := evaluator.Add(v0, v4, v[i])
			if err != nil {
				return err
			}
			err = evaluator.Sub(v0, v4, v[i+4])
			if err != nil {
				return err
			}

			v1, v5 := v[i+1].CopyNew(), v[i+5].CopyNew()
			err = evaluator.Add(v1, v5, v[i+1])
			if err != nil {
				return err
			}
			err = evaluator.Sub(v1, v5, v[i+5])
			if err != nil {
				return err
			}

			v2, v6 := v[i+2].CopyNew(), v[i+6].CopyNew()
			err = evaluator.Add(v2, v6, v[i+2])
			if err != nil {
				return err
			}
			err = evaluator.Sub(v2, v6, v[i+6])
			if err != nil {
				return err
			}

			v3, v7 := v[i+3].CopyNew(), v[i+7].CopyNew()
			err = evaluator.Add(v3, v7, v[i+3])
			if err != nil {
				return err
			}
			err = evaluator.Sub(v3, v7, v[i+7])
			if err != nil {
				return err
			}

			// Multiply by roots
			err = evaluator.Mul(v[i+5], field.RootForwardUint64(8), v[i+5])
			if err != nil {
				return err
			}
			nttMultiplications++
			err = evaluator.Mul(v[i+6], field.RootForwardUint64(4), v[i+6])
			if err != nil {
				return err
			}
			nttMultiplications++
			omega8 := field.RootForward(8)
			omega8_3 := field.Mul(omega8, field.Mul(omega8, omega8))
			err = evaluator.Mul(v[i+7], omega8_3.Uint64(), v[i+7])
			if err != nil {
				return err
			}
			nttMultiplications++

			// Second level butterflies
			v0, v2 = v[i].CopyNew(), v[i+2].CopyNew()
			err = evaluator.Add(v0, v2, v[i])
			if err != nil {
				return err
			}
			err = evaluator.Sub(v0, v2, v[i+2])
			if err != nil {
				return err
			}

			v1, v3 = v[i+1].CopyNew(), v[i+3].CopyNew()
			err = evaluator.Add(v1, v3, v[i+1])
			if err != nil {
				return err
			}
			err = evaluator.Sub(v1, v3, v[i+3])
			if err != nil {
				return err
			}

			err = evaluator.Mul(v[i+3], field.RootForwardUint64(4), v[i+3])
			if err != nil {
				return err
			}

			// Third level butterflies
			v0, v1 = v[i].CopyNew(), v[i+1].CopyNew()
			err = evaluator.Add(v0, v1, v[i])
			if err != nil {
				return err
			}
			err = evaluator.Sub(v0, v1, v[i+1])
			if err != nil {
				return err
			}

			v2, v3 = v[i+2].CopyNew(), v[i+3].CopyNew()
			err = evaluator.Add(v2, v3, v[i+2])
			if err != nil {
				return err
			}
			err = evaluator.Sub(v2, v3, v[i+3])
			if err != nil {
				return err
			}

			v4, v6 = v[i+4].CopyNew(), v[i+6].CopyNew()
			err = evaluator.Add(v4, v6, v[i+4])
			if err != nil {
				return err
			}
			err = evaluator.Sub(v4, v6, v[i+6])
			if err != nil {
				return err
			}

			v5, v7 = v[i+5].CopyNew(), v[i+7].CopyNew()
			err = evaluator.Add(v5, v7, v[i+5])
			if err != nil {
				return err
			}
			err = evaluator.Sub(v5, v7, v[i+7])
			if err != nil {
				return err
			}

			err = evaluator.Mul(v[i+7], field.RootForwardUint64(4), v[i+7])
			if err != nil {
				return err
			}

			// Fourth level butterflies
			v4, v5 = v[i+4].CopyNew(), v[i+5].CopyNew()
			err = evaluator.Add(v4, v5, v[i+4])
			if err != nil {
				return err
			}
			err = evaluator.Sub(v4, v5, v[i+5])
			if err != nil {
				return err
			}

			v6, v7 = v[i+6].CopyNew(), v[i+7].CopyNew()
			err = evaluator.Add(v6, v7, v[i+6])
			if err != nil {
				return err
			}
			err = evaluator.Sub(v6, v7, v[i+7])
			if err != nil {
				return err
			}

			// Final swaps
			v[i+1], v[i+4] = v[i+4], v[i+1]
			v[i+3], v[i+6] = v[i+6], v[i+3]
		}
	default:
		n1 := sqrtFactorPow2(size)
		n2 := size / n1
		step := field.N() / size

		// Process the input slice v in chunks of 'size'
		for chunkStart := 0; chunkStart < len(v); chunkStart += size {
			chunk := v[chunkStart : chunkStart+size]

			transpose(chunk, n1, n2)

			// Perform n2 NTTs of size n1 (on columns of original matrix)
			// Since transpose places columns into rows, we apply NTTs row-wise now.
			// The size of these NTTs is n1.
			nttInner(chunk, n1, field, evaluator) // Recursive call on the whole transposed chunk

			transpose(chunk, n2, n1)

			// Step 4: Apply twiddle factors omega_size^{ij}
			// Skip i=0 and j=0 as the twiddle factor is 1
			for i := 1; i < n1; i++ {
				step = (i * step) % field.N()
				idx := step
				for j := 1; j < n2; j++ {
					idx %= field.N()

					// Apply twiddle factor to element at (i, j) -> linear index i*n2 + j
					err := evaluator.Mul(chunk[i*n2+j], field.RootForwardUint64(idx), chunk[i*n2+j])
					if err != nil {
						return err
					}
					nttMultiplications++
					idx += step
				}
			}

			nttInner(chunk, n2, field, evaluator)
			transpose(chunk, n1, n2) // Transpose back
		}
	}
	return nil
}

// nttNofheInner performs NTT on plain uint64 values (non-FHE version for testing)
func nttNofheInner(v []*math.Element, size int, field *math.PrimeField) {
	switch size {
	case 0, 1:
		return
	case 2:
		for i := 0; i < len(v); i += 2 {
			v[i], v[i+1] = field.Add(v[i], v[i+1]), field.Sub(v[i], v[i+1])
		}
	case 4:
		for i := 0; i < len(v); i += 4 {
			// (v[0], v[2]) = (v[0] + v[2], v[0] - v[2])
			v[i], v[i+2] = field.Add(v[i], v[i+2]), field.Sub(v[i], v[i+2])

			// (v[1], v[3]) = (v[1] + v[3], v[1] - v[3])
			v[i+1], v[i+3] = field.Add(v[i+1], v[i+3]), field.Sub(v[i+1], v[i+3])

			v[i+3] = field.Mul(v[i+3], field.RootForward(4))

			// (v[0], v[1]) = (v[0] + v[1], v[0] - v[1])
			v[i], v[i+1] = field.Add(v[i], v[i+1]), field.Sub(v[i], v[i+1])

			// (v[2], v[3]) = (v[2] + v[3], v[2] - v[3])
			v[i+2], v[i+3] = field.Add(v[i+2], v[i+3]), field.Sub(v[i+2], v[i+3])

			// (v[1], v[2]) = (v[2], v[1])
			v[i+1], v[i+2] = v[i+2], v[i+1]
		}
	case 8:
		for i := 0; i < len(v); i += 8 {
			// First level butterflies
			v[i], v[i+4] = field.Add(v[i], v[i+4]), field.Sub(v[i], v[i+4])
			v[i+1], v[i+5] = field.Add(v[i+1], v[i+5]), field.Sub(v[i+1], v[i+5])
			v[i+2], v[i+6] = field.Add(v[i+2], v[i+6]), field.Sub(v[i+2], v[i+6])
			v[i+3], v[i+7] = field.Add(v[i+3], v[i+7]), field.Sub(v[i+3], v[i+7])

			// Multiply by roots
			v[i+5] = field.Mul(v[i+5], field.RootForward(8))
			v[i+6] = field.Mul(v[i+6], field.RootForward(4))
			omega8 := field.RootForward(8)
			omega8_3 := field.Mul(omega8, field.Mul(omega8, omega8))
			v[i+7] = field.Mul(v[i+7], omega8_3)

			// Second level butterflies
			v[i], v[i+2] = field.Add(v[i], v[i+2]), field.Sub(v[i], v[i+2])
			v[i+1], v[i+3] = field.Add(v[i+1], v[i+3]), field.Sub(v[i+1], v[i+3])
			v[i+3] = field.Mul(v[i+3], field.RootForward(4))

			// Third level butterflies
			v[i], v[i+1] = field.Add(v[i], v[i+1]), field.Sub(v[i], v[i+1])
			v[i+2], v[i+3] = field.Add(v[i+2], v[i+3]), field.Sub(v[i+2], v[i+3])
			v[i+4], v[i+6] = field.Add(v[i+4], v[i+6]), field.Sub(v[i+4], v[i+6])
			v[i+5], v[i+7] = field.Add(v[i+5], v[i+7]), field.Sub(v[i+5], v[i+7])
			v[i+7] = field.Mul(v[i+7], field.RootForward(4))

			// Fourth level butterflies
			v[i+4], v[i+5] = field.Add(v[i+4], v[i+5]), field.Sub(v[i+4], v[i+5])
			v[i+6], v[i+7] = field.Add(v[i+6], v[i+7]), field.Sub(v[i+6], v[i+7])

			// Final swaps
			v[i+1], v[i+4] = v[i+4], v[i+1]
			v[i+3], v[i+6] = v[i+6], v[i+3]
		}
	default:
		n1 := sqrtFactorPow2(size)
		n2 := size / n1
		step := field.N() / size

		// Process the input slice v in chunks of 'size'
		for chunkStart := 0; chunkStart < len(v); chunkStart += size {
			chunk := v[chunkStart : chunkStart+size]

			_transpose(chunk, n1, n2)

			// Perform n2 NTTs of size n1 (on columns of original matrix)
			// Since transpose places columns into rows, we apply NTTs row-wise now.
			// The size of these NTTs is n1.
			nttNofheInner(chunk, n1, field) // Recursive call on the whole transposed chunk

			_transpose(chunk, n2, n1)

			// Step 4: Apply twiddle factors omega_size^{ij}
			// Skip i=0 and j=0 as the twiddle factor is 1
			for i := 1; i < n1; i++ {
				step = (i * step) % field.N()
				idx := step
				for j := 1; j < n2; j++ {
					idx %= field.N()
					twiddle := field.RootForward(idx) // Fetch root omega_N^{index}

					// Apply twiddle factor to element at (i, j) -> linear index i*n2 + j
					chunk[i*n2+j] = field.Mul(chunk[i*n2+j], twiddle)
					idx += step
				}
			}

			nttNofheInner(chunk, n2, field)
			_transpose(chunk, n1, n2) // Transpose back
		}
	}
}

func nttNofhe(values []*math.Element, size int, field *math.PrimeField) []*math.Element {
	nttNofheInner(values, size, field)
	return values
}

// ... (keep existing makeMatrix, ntt, nttInner functions) ...

// sqrtFactorPow2 finds the integer square root if n is a power of 2.
// Returns sqrt(n) and panics if n is a power of 2, otherwise 0 and error.
func sqrtFactorPow2(n int) int {
	if n <= 0 || (n&(n-1) != 0) {
		panic(fmt.Sprintf("unsupported NTT size for generic case: input %d is not a positive power of 2", n))
	}
	log2n := bits.Len(uint(n)) - 1
	if log2n%2 != 0 {
		// This case means n is like 2, 8, 32, etc. We need n1*n2=n.
		// For simplicity in Cooley-Tukey like structures, often one factor is 2.
		// But the Rust code uses sqrt_factor which implies balanced factors.
		// For n = 2^k with k odd, sqrt is 2^(k/2). Let's return balanced factors.
		// n1 = 2^((k+1)/2), n2 = 2^((k-1)/2). We need the *largest* factor <= sqrt.
		// That would be n2 = 2^((k-1)/2). Let's return that.
		return 1 << uint((log2n-1)/2) // Return smaller factor
		// Alternatively, follow Rust's sqrt_factor more closely for powers of 2:
		// return 1 << uint(log2n/2), nil // This matches Rust's 1 << (twos/2) logic
	}
	// log2n is even, return exact sqrt
	return 1 << uint(log2n/2)
}

// transpose transposes a slice representing a matrix in row-major order.
func transpose(matrix []*rlwe.Ciphertext, rows, cols int) {
	if len(matrix) != rows*cols {
		panic("matrix size does not match rows*cols")
	}
	if rows == cols {
		for i := 0; i < rows; i++ {
			for j := i + 1; j < cols; j++ {
				matrix[i*cols+j], matrix[j*rows+i] = matrix[j*rows+i], matrix[i*cols+j]
			}
		}
	} else {
		// Create a copy for out-of-place transpose logic
		copyMatrix := make([]*rlwe.Ciphertext, len(matrix))
		for i := range matrix {
			// Need to copy the element itself if modifications happen later
			// Assuming *math.Element behaves like a value type for now
			copyMatrix[i] = matrix[i] // Shallow copy - might need deep copy if elements are modified later
		}
		for i := 0; i < rows; i++ {
			for j := 0; j < cols; j++ {
				matrix[j*rows+i] = copyMatrix[i*cols+j]
			}
		}
	}
}

// _transpose transposes a slice representing a matrix in row-major order.
func _transpose(matrix []*math.Element, rows, cols int) {
	if len(matrix) != rows*cols {
		panic("matrix size does not match rows*cols")
	}
	if rows == cols {
		for i := 0; i < rows; i++ {
			for j := i + 1; j < cols; j++ {
				matrix[i*cols+j], matrix[j*rows+i] = matrix[j*rows+i], matrix[i*cols+j]
			}
		}
	} else {
		// Create a copy for out-of-place transpose logic
		copyMatrix := make([]*math.Element, len(matrix))
		for i := range matrix {
			// Need to copy the element itself if modifications happen later
			// Assuming *math.Element behaves like a value type for now
			copyMatrix[i] = matrix[i] // Shallow copy - might need deep copy if elements are modified later
		}
		for i := 0; i < rows; i++ {
			for j := 0; j < cols; j++ {
				matrix[j*rows+i] = copyMatrix[i*cols+j]
			}
		}
	}
}

// GenerateBGVParamsForNTT generates BGV parameter literals based on the NTT size
// and target security parameters, following the discussed heuristics.
//
// Precondition:
//   - nttSize: Must be a power of 2 and >= 2. This is assumed and not re-checked inside.
//
// Parameters:
//   - nttSize: The size of the array the NTT will operate on.
//   - logN: The log2 of the polynomial ring degree N. Determines security level along with Q and P.
//   - plaintextModulus (T): The plaintext modulus. Must be prime and satisfy T = 1 (mod 2N).
//
// Returns:
//   - bgv.ParametersLiteral: The generated parameter literal struct.
//   - error: An error if inputs (logN, plaintextModulus) are invalid or constraints are not met.
//
// Heuristics Applied:
//   - Multiplicative depth L = log2(nttSize) - 1.
//   - len(LogQ) = L + 2 = log2(nttSize) + 1 (one initial level, L levels for multiplications, one extra buffer level).
//   - LogQ prime sizes: Start with 60 bits, then use 59 bits for subsequent primes.
//   - len(LogP) = max(2, log2(nttSize)) (balances noise and key size).
//   - LogP prime sizes: Start with 60 bits.
//   - Xe, Xs: Left empty to use Lattigo defaults (Gaussian error, Ternary secret).
//
// NOTE: The caller is responsible for ensuring the chosen `logN` provides adequate
// security (e.g., 128 bits) for the *generated* Q and P moduli sizes. This function
// primarily sizes Q and P based on computational depth needed for the NTT.
func GenerateBGVParamsForNTT(nttSize int, logN int, plaintextModulus uint64) (bgv.ParametersLiteral, error) {

	// --- Input Validation (Simplified) ---
	if nttSize < 2 {
		// We still check if size is at least 2, even if power-of-two is guaranteed.
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

	// Calculate k = log2(size) efficiently using bit manipulation
	k := bits.TrailingZeros(uint(nttSize))

	// Determine LogQ length: k levels for computation + 1 buffer level = k+1
	// The formula k+1 works directly for k=1 (nttSize=2) as well.
	numQPrimes := k + 2

	// Generate LogQ slice: Use [60, 59, 59, ...] pattern
	logQ := make([]int, numQPrimes)
	if numQPrimes > 0 {
		logQ[0] = 60 // First prime largest
		for i := 1; i < numQPrimes; i++ {
			logQ[i] = 59 // Subsequent primes slightly smaller
		}
	}

	// Determine LogP length: max(2, k) provides a balance.
	numPPrimes := max(2, k)

	// Generate LogP slice: Use [60, 60, ...] pattern
	logP := make([]int, numPPrimes)
	for i := 0; i < numPPrimes; i++ {
		logP[i] = 60
	}

	fmt.Printf("logQ: %v\n", logQ)
	fmt.Printf("logP: %v\n", logP)
	fmt.Printf("plaintextModulus: %d\n", plaintextModulus)

	// Construct the literal
	paramsLit := bgv.ParametersLiteral{
		LogN:             logN,
		LogQ:             logQ,
		LogP:             logP,
		PlaintextModulus: plaintextModulus,
	}

	return paramsLit, nil
}

const (
	rows = 64
	cols = 128
)

func main() {
	// Reset the multiplication counter at the start
	nttMultiplications = 0

	programStart := time.Now()
	start := time.Now()

	paramsLiteral, err := GenerateBGVParamsForNTT(cols, 15, math.Modulus)
	if err != nil {
		panic(err)
	}

	params, err := bgv.NewParametersFromLiteral(paramsLiteral)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Parameter generation took: %v\n", time.Since(start))

	// Generate keys
	start = time.Now()
	kgen := rlwe.NewKeyGenerator(params)
	sk, pk := kgen.GenKeyPairNew()
	fmt.Printf("Key generation took: %v\n", time.Since(start))

	// Initialize the necessary objects
	start = time.Now()
	encoder := bgv.NewEncoder(params)
	decryptor := rlwe.NewDecryptor(params, sk)
	encryptor := rlwe.NewEncryptor(params, pk)
	evaluator := bgv.NewEvaluator(params, nil)
	fmt.Printf("Object initialization took: %v\n", time.Since(start))

	_ = encoder   // Silence unused variable warnings for now
	_ = decryptor // These will be used in future operations
	_ = encryptor
	_ = evaluator

	start = time.Now()
	ptField, err := math.NewPrimeField(params.PlaintextModulus(), cols*2)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Prime field creation took: %v\n", time.Since(start))

	start = time.Now()
	matrix, batchedCols, err := makeMatrix(rows, cols, func(u []uint64) *rlwe.Plaintext {
		plaintext := bgv.NewPlaintext(params, params.MaxLevel())
		if err := encoder.Encode(u, plaintext); err != nil {
			panic(err)
		}
		return plaintext
	})
	if err != nil {
		panic(err)
	}
	fmt.Printf("Matrix generation and encoding took: %v\n", time.Since(start))

	// fmt.Printf("Matrix before NTT: %v\n", matrix)

	// Encrypt the batched columns
	start = time.Now()
	ciphertexts := make([]*rlwe.Ciphertext, len(batchedCols))
	for i, plaintext := range batchedCols {
		ciphertext, err := encryptor.EncryptNew(plaintext)
		if err != nil {
			panic(err)
		}
		ciphertexts[i] = ciphertext
	}
	fmt.Printf("Encryption took: %v\n", time.Since(start))

	// Apply NTT
	start = time.Now()
	result, err := ntt(ciphertexts, len(ciphertexts), &ptField, evaluator)
	if err != nil {
		panic(err)
	}
	fmt.Printf("NTT operation took: %v\n", time.Since(start))

	// Decrypt and print results
	start = time.Now()
	encodedMatrixRowMajor := make([][]*math.Element, rows)
	for i := range encodedMatrixRowMajor {
		encodedMatrixRowMajor[i] = make([]*math.Element, cols)
	}

	for j, ciphertext := range result {
		plaintext := decryptor.DecryptNew(ciphertext)
		column := make([]uint64, rows)
		if err := encoder.Decode(plaintext, column); err != nil {
			panic(err)
		}
		// Directly write column values into row-major matrix
		for i := range column {
			encodedMatrixRowMajor[i][j] = math.NewElement(column[i])
		}
	}
	fmt.Printf("Decryption and decoding took: %v\n", time.Since(start))
	// fmt.Printf("Encoded matrix: %v\n", encodedMatrixRowMajor)

	// Test NTT on plain values
	start = time.Now()
	encodedMatrixCheck := make([][]*math.Element, rows)
	for i := range matrix {
		encodedMatrixCheck[i] = nttNofhe(matrix[i], len(matrix[i]), &ptField)
	}
	fmt.Printf("Plain NTT: %v\n", time.Since(start))

	// Assert that encodedMatrixRowMajor and encodedMatrixCheck are equal
	for i := range encodedMatrixRowMajor {
		for j := range encodedMatrixRowMajor[i] {
			if !encodedMatrixRowMajor[i][j].Equal(encodedMatrixCheck[i][j]) {
				panic(fmt.Sprintf("Matrices differ at [%d][%d]: expected %v, got %v", i, j, encodedMatrixRowMajor[i][j], encodedMatrixCheck[i][j]))
			}
		}
	}

	fmt.Println("Matrices are equal")
	fmt.Printf("Total execution time: %v\n", time.Since(programStart))

	// Print the number of multiplications after NTT
	fmt.Printf("Number of multiplications in NTT: %d\n", nttMultiplications)
}
