package fhe

import (
	"fmt"
	"math"
	"math/bits"

	"github.com/timofey/fhe-experiments/lattigo/core"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
)

// LigeroCommitter holds the parameters for the Ligero commitment scheme.
type LigeroCommitter struct {
	Rows         int
	Cols         int
	rhoInv       int
	Queries      int
	Combinations int
}

// LigeroCommitment holds the commitment data.
type LigeroCommitment struct {
	Committer *LigeroCommitter
	Matrix    []*rlwe.Ciphertext
}

// NewLigeroCommitter creates a new LigeroCommitter based on security bits and size.
func NewLigeroCommitter(securityBits float64, size int) (*LigeroCommitter, error) {
	if size <= 0 {
		return nil, fmt.Errorf("size must be positive")
	}
	if securityBits <= 0 {
		return nil, fmt.Errorf("securityBits must be positive")
	}

	expansion := 2.0

	// Calculate queries
	queriesLogTerm := math.Log2(1.0 + 1.0/expansion)
	if 1.0-queriesLogTerm <= 0 {
		return nil, fmt.Errorf("invalid parameters: log term calculation resulted in non-positive denominator")
	}
	queries := int(math.Ceil(securityBits / (1.0 - queriesLogTerm)))
	if queries <= 0 {
		return nil, fmt.Errorf("calculated queries must be positive, got %d", queries)
	}

	// Pick matrix aspect ratio to minimize proof size.
	targetRows := int(math.Sqrt(2.0 * float64(size) / float64(queries)))
	rows := divisorCloseTo(targetRows)
	if rows == 0 || size%rows != 0 {
		return nil, fmt.Errorf("could not find a valid row divisor for size %d near target %d", size, targetRows)
	}
	cols := size / rows
	if rows*cols != size {
		return nil, fmt.Errorf("internal error: rows * cols != size (%d * %d != %d)", rows, cols, size)
	}

	code := int(expansion * float64(cols))

	// Calculate combinations
	// TODO: Adjust 253.6 for field prime
	const log2FieldApprox = 253.6
	log2Code := math.Log2(float64(code))
	combinationsDenominator := log2FieldApprox - log2Code
	if combinationsDenominator <= 0 {
		return nil, fmt.Errorf("invalid parameters: combinations calculation resulted in non-positive denominator")
	}
	combinations := 1 + int(math.Floor((securityBits-1.0)/combinationsDenominator))

	if combinations != 1 {
		return nil, fmt.Errorf("multiple combinations (%d) are not supported or expected at this field size", combinations)
	}

	return &LigeroCommitter{
		Rows:         rows,
		Cols:         cols,
		rhoInv:       code,
		Queries:      queries,
		Combinations: combinations,
	}, nil
}

func (c *LigeroCommitter) Commit(matrix []*rlwe.Ciphertext, field *core.PrimeField, backend *BackendBFV) (*LigeroCommitment, error) {
	encoded, err := Encode(matrix, c.Rows, c.rhoInv, field, backend)
	if err != nil {
		return nil, err
	}

	// TODO: Merkle tree commitment

	return &LigeroCommitment{
		Committer: c,
		Matrix:    encoded,
	}, nil
}

// divisorCloseTo finds the largest power of two less than or equal to target.
// Assumes target > 0.
func divisorCloseTo(target int) int {
	if target <= 0 {
		panic("target must be positive")
	}
	utarget := uint(target)
	powerOfTwo := uint(1) << (bits.Len(utarget) - 1)
	return int(powerOfTwo)
}
