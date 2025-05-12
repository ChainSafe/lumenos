package fhe

import (
	"fmt"
	"math"

	"github.com/nulltea/lumenos/core"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/schemes/bgv"
)

type LigeroMetadata struct {
	Rows    int
	Cols    int
	RhoInv  int
	Queries int
}

// LigeroCommitter holds the parameters for the Ligero commitment scheme.
type LigeroCommitter struct {
	LigeroMetadata
}

// LigeroProver holds the commitment data.
type LigeroProver struct {
	Committer     *LigeroCommitter
	Matrix        []*rlwe.Ciphertext
	EncodedMatrix []*rlwe.Ciphertext
	Tree          *core.MerkleTree
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
		LigeroMetadata: LigeroMetadata{
			Rows:    int(rows),
			Cols:    int(cols),
			RhoInv:  rhoInv,
			Queries: queries,
		},
	}, nil
}

func (c *LigeroCommitter) Commit(matrix []*rlwe.Ciphertext, backend *ServerBFV) (*LigeroProver, []byte, error) {
	encoded, err := Encode(matrix, c.Rows, c.RhoInv, backend)
	if err != nil {
		return nil, nil, err
	}

	leafs := make([]core.Leaf, len(encoded))
	for i := range encoded {
		leafs[i] = encoded[i].CopyNew()
	}

	// TODO: Merkle tree with leafs -- inner prouducts of columns and some random vector, cheaper?
	tree, err := core.NewTree(leafs)
	if err != nil {
		return nil, nil, err
	}

	return &LigeroProver{
		Committer:     c,
		Matrix:        matrix,
		EncodedMatrix: encoded,
		Tree:          tree,
	}, tree.MerkleRoot(), nil
}

type Proof struct {
	Metadata    LigeroMetadata
	Root        []byte
	MatR        []*rlwe.Ciphertext
	MatZ        []*rlwe.Ciphertext
	QueriedCols []*rlwe.Ciphertext
	MerklePaths []core.MerklePath
}

func (c *LigeroProver) Prove(point *core.Element, backend *ServerBFV, transcript *core.Transcript) (*Proof, error) {
	cols := c.Committer.Cols
	rows := c.Committer.Rows

	transcript.AppendBytes("root", c.Tree.MerkleRoot())

	r := make([]uint64, rows)
	transcript.SampleUints("r", r)
	rPt := bgv.NewPlaintext(backend.params, backend.params.MaxLevel())
	if err := backend.Encode(r, rPt); err != nil {
		return nil, err
	}

	matR := make([]*rlwe.Ciphertext, len(c.Matrix))
	for i := range c.Matrix {
		colR, err := backend.MulNew(c.Matrix[i], rPt)
		if err != nil {
			return nil, err
		}

		if err := backend.InnerSum(colR, 1, c.Committer.Rows, colR); err != nil {
			return nil, err
		}

		matR[i] = colR
	}

	transcript.AppendField("point", point)

	// Generate vector `b = [1, z^m, z^(2m), ..., z^((m-1)m)]`
	b := make([]uint64, rows)
	zPow := backend.Field().Pow(uint64(cols), point)
	powB := core.One()
	for i := range b {
		b[i] = powB.Uint64()
		backend.Field().MulAssign(powB, zPow, powB)
	}

	bPt := bgv.NewPlaintext(backend.params, backend.params.MaxLevel())
	if err := backend.Encode(b, bPt); err != nil {
		return nil, err
	}

	matZ := make([]*rlwe.Ciphertext, len(c.Matrix))
	for i := range c.Matrix {
		colZ, err := backend.MulNew(c.Matrix[i], bPt)
		if err != nil {
			return nil, err
		}

		if err := backend.InnerSum(colZ, 1, c.Committer.Rows, colZ); err != nil {
			return nil, err
		}

		matZ[i] = colZ
	}

	extCols := c.Committer.Cols * c.Committer.RhoInv
	queryIndices := sampleQueryIndices(transcript, c.Committer.Queries, extCols)

	queriedCols := make([]*rlwe.Ciphertext, c.Committer.Queries)
	merklePaths := make([]core.MerklePath, c.Committer.Queries)

	for i, queryColIdx := range queryIndices {
		var err error
		queriedCols[i] = c.EncodedMatrix[queryColIdx]
		merklePaths[i], err = c.Tree.GetMerklePath(uint(queryColIdx))
		if err != nil {
			return nil, err
		}
	}

	proof := &Proof{
		Metadata:    c.Committer.LigeroMetadata,
		Root:        c.Tree.MerkleRoot(),
		MatR:        matR,
		MatZ:        matZ,
		QueriedCols: queriedCols,
		MerklePaths: merklePaths,
	}

	return proof, nil
}

func (p *Proof) Verify(point *core.Element, value *core.Element, backend *ClientBFV, transcript *core.Transcript) error {
	rows := p.Metadata.Rows
	cols := p.Metadata.Cols
	root := p.Root

	transcript.AppendBytes("root", root)

	r := make([]*core.Element, rows)
	transcript.SampleFields("r", r)

	// Decrypt queried columns
	queriedCols := make([][]*core.Element, len(p.QueriedCols))
	for j, col := range p.QueriedCols {
		plaintext := backend.DecryptNew(col)
		column := make([]uint64, rows)
		if err := backend.Decode(plaintext, column); err != nil {
			return err
		}

		queriedCols[j] = make([]*core.Element, rows)
		for i := range column {
			queriedCols[j][i] = core.NewElement(column[i])
		}
	}

	// Decrypt and encode
	matR := make([]*core.Element, len(p.MatR))
	for i, colR := range p.MatR {
		pt := backend.DecryptNew(colR) // TODO: can descrypt just first slot?
		column := make([]uint64, rows)
		if err := backend.Decode(pt, column); err != nil {
			return err
		}
		matR[i] = core.NewElement(column[0])
	}

	encodedMatR := core.Encode(matR, p.Metadata.RhoInv, backend.Field())

	matZ := make([]*core.Element, len(p.MatZ))
	for i, colZ := range p.MatZ {
		pt := backend.DecryptNew(colZ) // TODO: can descrypt just first slot?
		column := make([]uint64, rows)
		if err := backend.Decode(pt, column); err != nil {
			return err
		}
		matZ[i] = core.NewElement(column[0])
	}

	encodedMatZ := core.Encode(matZ, p.Metadata.RhoInv, backend.Field())

	transcript.AppendField("point", point)

	// Compute a = [1, z, z^2, ..., z^(n_cols_1)]
	a := make([]*core.Element, cols)
	powA := core.One()
	for i := range cols {
		a[i] = powA
		backend.Field().MulAssign(powA, point, powA)
	}

	// Generate vector `b = [1, z^m, z^(2m), ..., z^((m-1)m)]`
	b := make([]*core.Element, rows)
	zPow := backend.Field().Pow(uint64(cols), point)
	if zPow.NotEqual(powA) {
		panic("zPow is not equal to powA")
	}
	powB := core.One()
	for i := range b {
		b[i] = powB
		backend.Field().MulAssign(powB, zPow, powB)
	}

	extCols := cols * p.Metadata.RhoInv
	queryIndices := sampleQueryIndices(transcript, p.Metadata.Queries, extCols)

	for i, queryColIdx := range queryIndices {
		extColCt := p.QueriedCols[i]

		if ok, err := core.VerifyMerklePath(extColCt, p.MerklePaths[i], root, uint(queryColIdx)); err != nil || !ok {
			return fmt.Errorf("failed to verify merkle path for column %d", queryColIdx)
		}

		if innerProduct(queriedCols[i], r, backend.Field()).NotEqual(encodedMatR[queryColIdx]) {
			return fmt.Errorf("well-formedness R check failed for column %d", queryColIdx)
		}

		if innerProduct(queriedCols[i], b, backend.Field()).NotEqual(encodedMatZ[queryColIdx]) {
			return fmt.Errorf("well-formedness B check failed for column %d", queryColIdx)
		}
	}

	if innerProduct(matZ, a, backend.Field()).NotEqual(value) {
		return fmt.Errorf(" claimed value does not match the evaluation of the committed polynomial")
	}

	return nil
}

func sampleQueryIndices(transcript *core.Transcript, queries int, extCols int) []int {
	queryIndices := make([]int, queries)
	for i := range queryIndices {
		queryIndices[i] = int(transcript.SampleUint64("query") % uint64(extCols))
	}
	return queryIndices
}

func innerProduct(v []*core.Element, r []*core.Element, field *core.PrimeField) *core.Element {
	if len(v) != len(r) {
		panic("vector lengths do not match")
	}

	sum := core.Zero()

	for i := 0; i < len(v); i++ {
		product := field.Mul(v[i], r[i])
		sum = field.Add(sum, product)
	}

	return sum
}
