package core

import (
	"fmt"
	"math/big"

	"github.com/tuneinsight/lattigo/v6/ring"
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
