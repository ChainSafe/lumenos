package core

import (
	"math/big"

	"github.com/tuneinsight/lattigo/v6/ring"
)

func RingPolyToBigintCentered(ring *ring.Ring, poly ring.Poly, isMontgomery bool, isNTT bool) []string {
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

	bigIntsString := make([]string, len(bigInts))
	for i, v := range bigInts {
		bigIntsString[i] = v.String()
	}
	return bigIntsString
}
