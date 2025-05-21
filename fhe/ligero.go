package fhe

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math"
	"math/bits"
	"runtime"
	"sync"

	"github.com/nulltea/lumenos/core"
	"github.com/nulltea/lumenos/vdec"
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
func NewLigeroCommitter(securityBits float64, rows int, cols int, rhoInv int) (*LigeroCommitter, error) {
	size := rows * cols
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
	// cols := math.Ceil(math.Sqrt(float64(size)))
	// rows := math.Ceil(float64(size) / cols)

	return &LigeroCommitter{
		LigeroMetadata: LigeroMetadata{
			Rows:    int(rows),
			Cols:    int(cols),
			RhoInv:  rhoInv,
			Queries: queries,
		},
	}, nil
}

func (c *LigeroCommitter) Commit(matrix []*rlwe.Ciphertext, backend *ServerBFV, ctx *core.Span) (*LigeroProver, []byte, error) {
	encoded, err := func() ([]*rlwe.Ciphertext, error) {
		span := core.StartSpan("Encode", ctx)
		defer span.End()
		return Encode(matrix, c.Rows, c.RhoInv, backend)
	}()
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

type EncryptedProof struct {
	Metadata    LigeroMetadata
	MatR        []*rlwe.Ciphertext
	MatZ        []*rlwe.Ciphertext
	QueriedCols []*rlwe.Ciphertext
	MerklePaths []core.MerklePath
	Root        []byte
}

func (c *LigeroProver) Prove(point *core.Element, backend *ServerBFV, transcript *core.Transcript, ctx *core.Span) (*EncryptedProof, error) {
	cols := c.Committer.Cols
	rows := c.Committer.Rows

	transcript.AppendBytes("root", c.Tree.MerkleRoot())

	// Encode r vector
	r := make([]uint64, rows)
	transcript.SampleUints("r", r)
	rPt := bgv.NewPlaintext(backend.params, backend.params.MaxLevel())
	if err := backend.Encode(r, rPt); err != nil {
		return nil, err
	}

	// Generate vector b
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

	// Run Matrix R and Matrix Z operations concurrently
	matrixRSpan := core.StartSpan("InnerProduct(Matrix, r)", ctx)
	matrixZSpan := core.StartSpan("InnerProduct(Matrix, b)", ctx)

	matRChan := make(chan matrixOperationResult, 1)
	matZChan := make(chan matrixOperationResult, 1)

	// Matrix R operations
	go func() {
		result := matrixInnerSumEval(c.Matrix, rPt, c.Committer.Rows, backend.CopyNew(), matrixRSpan)
		matrixRSpan.End()
		matRChan <- result
	}()

	// Matrix Z operations
	go func() {
		result := matrixInnerSumEval(c.Matrix, bPt, c.Committer.Rows, backend.CopyNew(), matrixZSpan)
		matrixZSpan.End()
		matZChan <- result
	}()

	// Collect results
	matRResult := <-matRChan
	if matRResult.err != nil {
		matrixRSpan.End()
		return nil, matRResult.err
	}

	matZResult := <-matZChan
	if matZResult.err != nil {
		return nil, matZResult.err
	}

	matR := matRResult.matrix
	matZ := matZResult.matrix

	transcript.AppendField("point", point)

	// Query operations
	queriedCols := make([]*rlwe.Ciphertext, c.Committer.Queries)
	merklePaths := make([]core.MerklePath, c.Committer.Queries)
	extCols := c.Committer.Cols * c.Committer.RhoInv
	queryIndices := sampleQueryIndices(transcript, c.Committer.Queries, extCols)

	for i, queryColIdx := range queryIndices {
		queriedCols[i] = c.EncodedMatrix[queryColIdx]
		var err error
		merklePaths[i], err = c.Tree.GetMerklePath(uint(queryColIdx))
		if err != nil {
			return nil, err
		}
	}

	proof := &EncryptedProof{
		Metadata:    c.Committer.LigeroMetadata,
		Root:        c.Tree.MerkleRoot(),
		MatR:        matR,
		MatZ:        matZ,
		QueriedCols: queriedCols,
		MerklePaths: merklePaths,
	}

	return proof, nil
}

// matrixOperationResult holds the result of a matrix operation
type matrixOperationResult struct {
	matrix []*rlwe.Ciphertext
	err    error
}

func matrixInnerSumEval(matrix []*rlwe.Ciphertext, plaintext *rlwe.Plaintext, rows int, backend *ServerBFV, span *core.Span) matrixOperationResult {
	result := make([]*rlwe.Ciphertext, len(matrix))
	type matrixElementResult struct {
		index int
		col   *rlwe.Ciphertext
		err   error
	}
	resultChan := make(chan matrixElementResult, len(matrix))

	numWorkers := determineOptimalWorkers(len(matrix))
	workChan := make(chan int, len(matrix))

	// Start workers
	var wg sync.WaitGroup
	for w := 0; w < numWorkers; w++ {
		wg.Add(1)
		backend := backend.CopyNew()
		go func() {
			defer wg.Done()
			for i := range workChan {
				col, err := backend.MulNew(matrix[i], plaintext)
				if err != nil {
					resultChan <- matrixElementResult{index: i, err: err}
					continue
				}

				if err := backend.InnerSum(col, 1, rows, col); err != nil {
					resultChan <- matrixElementResult{index: i, err: err}
					continue
				}

				resultChan <- matrixElementResult{index: i, col: col}
			}
		}()
	}

	for i := range matrix {
		workChan <- i
	}
	close(workChan)

	go func() {
		wg.Wait()
		close(resultChan)
	}()

	for res := range resultChan {
		if res.err != nil {
			span.End()
			return matrixOperationResult{nil, res.err}
		}
		result[res.index] = res.col
	}

	// TODO: aggregate multiplication counts

	return matrixOperationResult{result, nil}
}

type Proof struct {
	Metadata    LigeroMetadata
	Root        []byte
	MatR        []*core.Element
	MatZ        []*core.Element
	QueriedCols []*vdec.ColumnInstance
	MerklePaths []core.MerklePath
}

func (p *EncryptedProof) Decrypt(client *ClientBFV, verifiable bool, ctx *core.Span) (*Proof, error) {
	rows := p.Metadata.Rows

	// Decrypt queried columns
	span := core.StartSpan("Decrypt queried columns", ctx)
	queriedCols := make([][]*core.Element, len(p.QueriedCols))

	for j, col := range p.QueriedCols {
		plaintext := client.DecryptNew(col)
		column := make([]uint64, rows)
		if err := client.Decode(plaintext, column); err != nil {
			return nil, err
		}

		queriedCols[j] = make([]*core.Element, rows)
		for i := range column {
			queriedCols[j][i] = core.NewElement(column[i])
		}
	}

	queriedColsPairs := make([]*vdec.ColumnInstance, len(p.QueriedCols))
	for i := range p.QueriedCols {
		queriedColsPairs[i] = &vdec.ColumnInstance{
			Ct:     p.QueriedCols[i],
			Values: queriedCols[i],
		}
	}
	span.End()

	if verifiable {
		span = core.StartSpan("Verifiable decrypt", ctx, "Verifiable decrypt...")
		transcript := core.NewTranscript("vdec")

		err := vdec.ProveBfvDecBatched(queriedColsPairs, client.SecretKey(), client.Evaluator, client.Field(), transcript, span)
		if err != nil {
			span.End()
			return nil, err
		}
		span.End()
	}

	// Decrypt row inner products concurrently
	span = core.StartSpan("Decrypt row inner products", ctx)

	// Create channels for concurrent decryption
	matRChan := make(chan struct {
		matR []*core.Element
		err  error
	}, 1)
	matZChan := make(chan struct {
		matZ []*core.Element
		err  error
	}, 1)

	// Start concurrent decryption of MatR
	go func() {
		matR, err := decryptMatrixInnerProduct(p.MatR, client, rows, span)
		matRChan <- struct {
			matR []*core.Element
			err  error
		}{matR, err}
	}()

	// Start concurrent decryption of MatZ
	go func() {
		matZ, err := decryptMatrixInnerProduct(p.MatZ, client, rows, span)
		matZChan <- struct {
			matZ []*core.Element
			err  error
		}{matZ, err}
	}()

	// Collect results
	matRResult := <-matRChan
	if matRResult.err != nil {
		span.End()
		return nil, matRResult.err
	}

	matZResult := <-matZChan
	if matZResult.err != nil {
		span.End()
		return nil, matZResult.err
	}

	span.End()

	proof := &Proof{
		Metadata:    p.Metadata,
		Root:        p.Root,
		MatR:        matRResult.matR,
		MatZ:        matZResult.matZ,
		QueriedCols: queriedColsPairs,
		MerklePaths: p.MerklePaths,
	}

	return proof, nil
}

func decryptMatrixInnerProduct(matrix []*rlwe.Ciphertext, client *ClientBFV, rows int, span *core.Span) ([]*core.Element, error) {
	result := make([]*core.Element, len(matrix))
	type decryptionResult struct {
		index int
		value *core.Element
		err   error
	}
	resultChan := make(chan decryptionResult, len(matrix))

	numWorkers := determineOptimalWorkers(len(matrix))
	workChan := make(chan int, len(matrix))

	var wg sync.WaitGroup
	for w := 0; w < numWorkers; w++ {
		wg.Add(1)
		client := client.CopyNew()
		go func() {
			defer wg.Done()
			for i := range workChan {
				pt := client.DecryptNew(matrix[i]) // TODO: can descrypt just first slot?
				column := make([]uint64, rows)
				if err := client.Decode(pt, column); err != nil {
					resultChan <- decryptionResult{index: i, err: err}
					continue
				}
				resultChan <- decryptionResult{
					index: i,
					value: core.NewElement(column[0]),
				}
			}
		}()
	}

	for i := range matrix {
		workChan <- i
	}
	close(workChan)

	go func() {
		wg.Wait()
		close(resultChan)
	}()

	for res := range resultChan {
		if res.err != nil {
			span.End()
			return nil, res.err
		}
		result[res.index] = res.value
	}

	return result, nil
}

func (p *Proof) Verify(point *core.Element, value *core.Element, client *ClientBFV, transcript *core.Transcript) error {
	rows := p.Metadata.Rows
	cols := p.Metadata.Cols
	root := p.Root

	transcript.AppendBytes("root", root)

	r := make([]*core.Element, rows)
	transcript.SampleFields("r", r)

	// Encode row inner products
	encodedMatR := core.Encode(p.MatR, p.Metadata.RhoInv, client.Field())

	encodedMatZ := core.Encode(p.MatZ, p.Metadata.RhoInv, client.Field())

	transcript.AppendField("point", point)

	// Compute a = [1, z, z^2, ..., z^(n_cols_1)]
	a := make([]*core.Element, cols)
	powA := core.One()
	for i := range cols {
		a[i] = powA
		client.Field().MulAssign(powA, point, powA)
	}

	// Generate vector `b = [1, z^m, z^(2m), ..., z^((m-1)m)]`
	b := make([]*core.Element, rows)
	zPow := client.Field().Pow(uint64(cols), point)
	if zPow.NotEqual(powA) {
		panic("zPow is not equal to powA")
	}
	powB := core.One()
	for i := range b {
		b[i] = powB
		client.Field().MulAssign(powB, zPow, powB)
	}

	extCols := cols * p.Metadata.RhoInv
	queryIndices := sampleQueryIndices(transcript, p.Metadata.Queries, extCols)

	for i, queryColIdx := range queryIndices {
		if ok, err := core.VerifyMerklePath(p.QueriedCols[i].Ct, p.MerklePaths[i], root, uint(queryColIdx)); err != nil || !ok {
			return fmt.Errorf("failed to verify merkle path for column %d", queryColIdx)
		}

		if core.InnerProduct(p.QueriedCols[i].Values, r, client.Field()).NotEqual(encodedMatR[queryColIdx]) {
			fmt.Println("well-formedness R check failed for column expected", encodedMatR[queryColIdx], "got", core.InnerProduct(p.QueriedCols[i].Values, r, client.Field()))
			return fmt.Errorf("well-formedness R check failed for column %d", queryColIdx)
		}

		if core.InnerProduct(p.QueriedCols[i].Values, b, client.Field()).NotEqual(encodedMatZ[queryColIdx]) {
			return fmt.Errorf("well-formedness B check failed for column %d", queryColIdx)
		}
	}

	if core.InnerProduct(p.MatZ, a, client.Field()).NotEqual(value) {
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

func (p *EncryptedProof) MarshalBinary() ([]byte, error) {
	buf := bytes.NewBuffer(nil)
	if err := p.WriteTo(buf); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (p *EncryptedProof) UnmarshalBinary(data []byte, params *bgv.Parameters) error {
	buf := bytes.NewBuffer(data)
	return p.ReadFrom(buf, params)
}

func (p *EncryptedProof) WriteTo(buf *bytes.Buffer) error {
	if err := p.Metadata.WriteTo(buf); err != nil {
		return err
	}

	for i := range p.MatR {
		if _, err := p.MatR[i].WriteTo(buf); err != nil {
			return err
		}
	}

	for i := range p.MatZ {
		if _, err := p.MatZ[i].WriteTo(buf); err != nil {
			return err
		}
	}

	for i := range p.QueriedCols {
		if _, err := p.QueriedCols[i].WriteTo(buf); err != nil {
			return err
		}
	}

	for i := range p.MerklePaths {
		if err := p.MerklePaths[i].WriteTo(buf); err != nil {
			return err
		}
	}

	if _, err := buf.Write(p.Root); err != nil {
		return err
	}

	return nil
}

func (p *EncryptedProof) ReadFrom(buf *bytes.Buffer, params *bgv.Parameters) error {
	if err := p.Metadata.ReadFrom(buf); err != nil {
		return err
	}

	p.MatR = make([]*rlwe.Ciphertext, p.Metadata.Cols)
	for i := range p.MatR {
		p.MatR[i] = rlwe.NewCiphertext(params, params.MaxLevel())
		if _, err := p.MatR[i].ReadFrom(buf); err != nil {
			return err
		}
	}

	p.MatZ = make([]*rlwe.Ciphertext, p.Metadata.Cols)
	for i := range p.MatZ {
		p.MatZ[i] = rlwe.NewCiphertext(params, params.MaxLevel())
		if _, err := p.MatZ[i].ReadFrom(buf); err != nil {
			return err
		}
	}

	p.QueriedCols = make([]*rlwe.Ciphertext, p.Metadata.Queries)
	for i := range p.QueriedCols {
		p.QueriedCols[i] = rlwe.NewCiphertext(params, params.MaxLevel())
		if _, err := p.QueriedCols[i].ReadFrom(buf); err != nil {
			return err
		}
	}

	p.MerklePaths = make([]core.MerklePath, p.Metadata.Queries)
	merkleLen := (p.Metadata.Cols * p.Metadata.RhoInv)
	nextPow2 := 1 << (64 - bits.LeadingZeros64(uint64(merkleLen-1)))
	merkleDepth := int(math.Log2(float64(nextPow2)))
	for i := range p.MerklePaths {
		p.MerklePaths[i] = make(core.MerklePath, merkleDepth)
		if err := p.MerklePaths[i].ReadFrom(buf); err != nil {
			return err
		}
	}

	p.Root = make([]byte, 32)
	if _, err := buf.Read(p.Root); err != nil {
		return err
	}

	return nil
}

func (p *LigeroMetadata) WriteTo(buf *bytes.Buffer) error {
	binary.Write(buf, binary.LittleEndian, uint32(p.Rows))
	binary.Write(buf, binary.LittleEndian, uint32(p.Cols))
	binary.Write(buf, binary.LittleEndian, uint8(p.RhoInv))
	binary.Write(buf, binary.LittleEndian, uint16(p.Queries))
	return nil
}

func (p *LigeroMetadata) ReadFrom(buf *bytes.Buffer) error {
	var rows, cols uint32
	var rhoInv uint8
	var queries uint16

	binary.Read(buf, binary.LittleEndian, &rows)
	binary.Read(buf, binary.LittleEndian, &cols)
	binary.Read(buf, binary.LittleEndian, &rhoInv)
	binary.Read(buf, binary.LittleEndian, &queries)

	p.Rows = int(rows)
	p.Cols = int(cols)
	p.RhoInv = int(rhoInv)
	p.Queries = int(queries)
	return nil
}

// determineOptimalWorkers calculates the optimal number of workers based on system resources and workload
func determineOptimalWorkers(matrixSize int) int {
	numCPU := runtime.NumCPU()

	// For small matrices, use fewer workers to avoid overhead
	if matrixSize < numCPU {
		return matrixSize
	}

	// For medium matrices, use number of CPU cores
	if matrixSize <= numCPU*4 {
		return numCPU
	}

	// For large matrices, use more workers but cap at 2x CPU cores
	// to avoid excessive context switching
	return min(numCPU*2, matrixSize)
}
