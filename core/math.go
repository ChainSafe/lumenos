package core

import (
	"fmt"
	"math/bits"
)

func InnerProduct(v []*Element, r []*Element, field *PrimeField) *Element {
	if len(v) != len(r) {
		panic("vector lengths do not match")
	}

	sum := Zero()

	for i := 0; i < len(v); i++ {
		product := field.Mul(v[i], r[i])
		sum = field.Add(sum, product)
	}

	return sum
}

// SqrtFactor finds the integer square root if n is a power of 2.
// Returns sqrt(n) and panics if n is a power of 2, otherwise 0 and error.
func SqrtFactor(n int) int {
	if n <= 0 || (n&(n-1) != 0) {
		panic(fmt.Sprintf("unsupported NTT size for generic case: input %d is not a positive power of 2", n))
	}
	log2n := bits.Len(uint(n)) - 1
	if log2n%2 != 0 {
		return 1 << uint((log2n-1)/2)
	}
	// log2n is even, return exact sqrt
	return 1 << uint(log2n/2)
}

// transpose transposes a slice representing a matrix in row-major order.
func Transpose[T any](matrix []T, rows, cols int) {
	if len(matrix) != rows*cols {
		panic("matrix size does not match rows*cols")
	}
	if rows == cols {
		// In-place transpose for square matrices
		for i := 0; i < rows; i++ {
			for j := i + 1; j < cols; j++ {
				matrix[i*cols+j], matrix[j*rows+i] = matrix[j*rows+i], matrix[i*cols+j]
			}
		}
	} else {
		// Out-of-place transpose for non-square matrices
		copyMatrix := make([]T, len(matrix))
		copy(copyMatrix, matrix)

		for i := 0; i < rows; i++ {
			for j := 0; j < cols; j++ {
				matrix[j*rows+i] = copyMatrix[i*cols+j]
			}
		}
	}
}
