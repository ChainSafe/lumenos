package core

import (
	"encoding/binary"
	"fmt"
	"math/big"

	"github.com/tuneinsight/lattigo/v6/ring"
	"golang.org/x/crypto/chacha20"
)

func RingPolyToCoeffsCentered(ring *ring.Ring, poly ring.Poly, isMontgomery bool, isNTT bool) []int64 {
	if isMontgomery {
		ring.IMForm(poly, poly)
	}
	if isNTT {
		ring.INTT(poly, poly)
	}

	bigInts := make([]*big.Int, ring.N())
	for i := range bigInts {
		bigInts[i] = big.NewInt(0)
	}

	ring.PolyToBigintCentered(poly, 1, bigInts)

	coeffs := make([]int64, ring.N())
	for i := range coeffs {
		coeffs[i] = bigInts[i].Int64()
	}

	return coeffs
}

func RingPolyToStringsCentered(ring *ring.Ring, poly ring.Poly, isMontgomery bool, isNTT bool) []string {
	bigInts := RingPolyToCoeffsCentered(ring, poly, isMontgomery, isNTT)

	bigIntsString := make([]string, len(bigInts))
	for i, v := range bigInts {
		bigIntsString[i] = fmt.Sprintf("%d", v)
	}
	return bigIntsString
}

// RandomMatrixRowMajor generates a matrix in both row-major and column-major
func RandomMatrixRowMajor[T any](rows, cols int, modT uint64, batchEncoder func([]uint64) *T) ([][]*Element, []*T, error) {
	if rows <= 0 || cols <= 0 {
		return nil, nil, fmt.Errorf("dimensions must be positive")
	}
	// if rows&(rows-1) != 0 {
	// 	return nil, nil, fmt.Errorf("rows must be a power of 2")
	// }

	seed := make([]byte, 32)
	binary.LittleEndian.PutUint64(seed, 1)
	cipher, err := chacha20.NewUnauthenticatedCipher(seed, make([]byte, 12))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to initialize ChaCha20: %v", err)
	}

	rowMatrix := make([][]*Element, rows)
	for i := range rowMatrix {
		rowMatrix[i] = make([]*Element, cols)
		randomBytes := make([]byte, 8*cols)
		cipher.XORKeyStream(randomBytes, randomBytes)
		for j := 0; j < cols; j++ {
			rowMatrix[i][j] = NewElement(binary.LittleEndian.Uint64(randomBytes[j*8:(j+1)*8]) % modT)
		}
	}

	// transpose & encode
	encodedMatrix := make([]*T, cols)
	for j := range encodedMatrix {
		column := make([]uint64, rows)
		for i := 0; i < rows; i++ {
			column[i] = rowMatrix[i][j].Uint64()
		}
		encodedMatrix[j] = batchEncoder(column)
	}

	return rowMatrix, encodedMatrix, nil
}

func RandomMatrixColMajor[T any](rows, cols int, modT uint64, batchEncoder func([]uint64) *T) ([][]*Element, []*T, error) {
	rowMatrix, encodedMatrix, err := RandomMatrixRowMajor(rows, cols, modT, batchEncoder)
	if err != nil {
		return nil, nil, err
	}

	colMatrixRowMajor := make([][]*Element, cols)
	for i := range colMatrixRowMajor {
		colMatrixRowMajor[i] = make([]*Element, rows)
	}

	for i := range rowMatrix {
		for j := range rowMatrix[i] {
			colMatrixRowMajor[j][i] = rowMatrix[i][j]
		}
	}

	return colMatrixRowMajor, encodedMatrix, nil
}
