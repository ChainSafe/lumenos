package math

import (
	"fmt"
	"math/bits"
)

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
