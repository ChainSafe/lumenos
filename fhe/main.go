package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math/bits"
	"time"

	"github.com/timofey/fhe-experiments/lattigo/fhe"
	"github.com/timofey/fhe-experiments/lattigo/math"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/schemes/bgv"
	"golang.org/x/crypto/chacha20"
)

// makeMatrix generates a matrix in both row-major and column-major
func makeMatrix(rows, cols int, batchEncoder func([]uint64) *rlwe.Plaintext) ([][]*math.Element, []*rlwe.Plaintext, error) {
	if rows <= 0 || cols <= 0 {
		return nil, nil, fmt.Errorf("dimensions must be positive")
	}
	if rows&(rows-1) != 0 {
		return nil, nil, fmt.Errorf("rows must be a power of 2")
	}

	seed := make([]byte, 32)
	binary.LittleEndian.PutUint64(seed, 1)
	cipher, err := chacha20.NewUnauthenticatedCipher(seed, make([]byte, 12))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to initialize ChaCha20: %v", err)
	}

	rowMatrix := make([][]*math.Element, rows)
	for i := range rowMatrix {
		rowMatrix[i] = make([]*math.Element, cols)
		randomBytes := make([]byte, 8*cols)
		cipher.XORKeyStream(randomBytes, randomBytes)
		for j := 0; j < cols; j++ {
			rowMatrix[i][j] = math.NewElement(binary.LittleEndian.Uint64(randomBytes[j*8:(j+1)*8]) % 255)
		}
	}

	// transpose
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
	numQPrimes := k

	// Generate LogQ slice: Use [60, 59, 59, ...] pattern
	logQ := make([]int, numQPrimes)
	if numQPrimes > 0 {
		logQ[0] = 60 // First prime largest
		for i := 1; i < numQPrimes; i++ {
			logQ[i] = 55 // Subsequent primes slightly smaller
		}
	}

	// Determine LogP length: max(2, k) provides a balance.
	numPPrimes := 2 // max(2, k)

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
	rows    = 4096
	cols    = 4096
	Modulus = 0x3ee0001
	// Modulus = 288230376150630401
	// Modulus = 144115188075593729 // allows LogN >= 15
)

func main() {
	// Reset the multiplication counter at the start
	fhe.MultiplicationsCounter = 0

	programStart := time.Now()
	start := time.Now()

	paramsLiteral, err := GenerateBGVParamsForNTT(cols, 13, Modulus)
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

	ptField, err := math.NewPrimeField(params.PlaintextModulus(), cols*2)
	if err != nil {
		panic(err)
	}

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
	result, err := fhe.NTT(ciphertexts, len(ciphertexts), &ptField, evaluator)
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
		encodedMatrixCheck[i] = math.NTT(matrix[i], len(matrix[i]), &ptField)
	}
	fmt.Printf("Plain NTT: %v\n", time.Since(start))
	// fmt.Printf("Encoded matrix check: %v\n", encodedMatrixCheck)

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
	fmt.Printf("Number of multiplications in NTT: %d\n", fhe.MultiplicationsCounter)
}
