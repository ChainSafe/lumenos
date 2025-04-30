package fhe

import (
	"fmt"
	"math"

	"github.com/timofey/fhe-experiments/lattigo/core"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/schemes/bgv"
)

// LigeroCommitter holds the parameters for the Ligero commitment scheme.
type LigeroCommitter struct {
	Rows    int
	Cols    int
	RhoInv  int
	Queries int
}

// LigeroCommitment holds the commitment data.
type LigeroCommitment struct {
	Committer     *LigeroCommitter
	Matrix        []*rlwe.Ciphertext
	EncodedMatrix []*rlwe.Ciphertext
}

// NewLigeroCommitter creates a new LigeroCommitter based on security bits and size.
func NewLigeroCommitter(securityBits float64, size int, rhoInv int) (*LigeroCommitter, error) {
	if size <= 0 {
		return nil, fmt.Errorf("size must be positive")
	}
	if securityBits <= 0 {
		return nil, fmt.Errorf("securityBits must be positive")
	}

	// Calculate queries
	queriesLogTerm := math.Log2(1.0 + 1.0/float64(rhoInv))
	if 1.0-queriesLogTerm <= 0 {
		return nil, fmt.Errorf("invalid parameters: log term calculation resulted in non-positive denominator")
	}
	queries := int(math.Ceil(securityBits / (1.0 - queriesLogTerm)))
	if queries <= 0 {
		return nil, fmt.Errorf("calculated queries must be positive, got %d", queries)
	}

	// Pick matrix aspect ratio to minimize proof size.
	cols := math.Ceil(math.Sqrt(float64(size)))
	rows := math.Ceil(float64(size) / cols)

	return &LigeroCommitter{
		Rows:    int(rows),
		Cols:    int(cols),
		RhoInv:  rhoInv,
		Queries: queries,
	}, nil
}

func (c *LigeroCommitter) Commit(matrix []*rlwe.Ciphertext, backend *BackendBFV, transcript *core.Transcript) (*LigeroCommitment, error) {
	encoded, err := Encode(matrix, c.Rows, c.RhoInv, backend)
	if err != nil {
		return nil, err
	}

	// TODO: Merkle tree commitment

	return &LigeroCommitment{
		Committer:     c,
		Matrix:        matrix,
		EncodedMatrix: encoded,
	}, nil
}

func (c *LigeroCommitment) Prove(backend *BackendBFV, transcript *core.Transcript) ([]*rlwe.Ciphertext, error) {
	r := make([]uint64, c.Committer.Rows)
	transcript.SampleUints("r", r)

	rPt := bgv.NewPlaintext(backend.params, backend.params.MaxLevel())
	if err := backend.Encode(r, rPt); err != nil {
		return nil, err
	}

	vMat := make([]*rlwe.Ciphertext, c.Committer.Cols)
	fmt.Printf("matrix cols: %d\n", len(c.Matrix))
	fmt.Printf("cols: %d\n", c.Committer.Cols)
	for i := range c.Matrix {
		t, err := backend.MulNew(c.Matrix[i], rPt)
		if err != nil {
			return nil, err
		}

		vMat[i] = t

		if err := backend.InnerSum(t, 1, c.Committer.Rows, vMat[i]); err != nil {
			return nil, err
		}
	}

	return vMat, nil
}
