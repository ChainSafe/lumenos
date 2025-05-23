package fhe

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math"
	"math/bits"
	"runtime"
	"sync"

	"github.com/dustin/go-humanize"
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

	span := core.StartSpan("Merkle tree built", ctx)
	leafs, err := processLeafParallel(encoded, backend)
	if err != nil {
		return nil, nil, err
	}

	// TODO: Merkle tree with leafs -- inner prouducts of columns and some random vector, cheaper?
	tree, err := core.NewTree(leafs)
	if err != nil {
		return nil, nil, err
	}
	span.End()

	return &LigeroProver{
		Committer:     c,
		Matrix:        matrix,
		EncodedMatrix: encoded,
		Tree:          tree,
	}, tree.MerkleRoot(), nil
}

func processLeafParallel(encoded []*rlwe.Ciphertext, backend *ServerBFV) ([]core.Leaf, error) {
	type leafResult struct {
		index int
		leaf  core.Leaf
		err   error
	}

	leafs := make([]core.Leaf, len(encoded))
	resultChan := make(chan leafResult, len(encoded))

	numWorkers := determineOptimalWorkers(len(encoded))
	workChan := make(chan int, len(encoded))

	var wg sync.WaitGroup
	for w := 0; w < numWorkers; w++ {
		wg.Add(1)
		backend := backend.CopyNew()
		go func() {
			defer wg.Done()
			for i := range workChan {
				ct := encoded[i].CopyNew()

				// Mod switch
				for ct.Level() > 1 {
					if err := backend.Rescale(ct, ct); err != nil {
						resultChan <- leafResult{index: i, err: err}
						return
					}
				}

				buf := bytes.NewBuffer(nil)
				ct.WriteTo(buf)

				resultChan <- leafResult{index: i, leaf: buf}
			}
		}()
	}

	for i := range encoded {
		workChan <- i
	}
	close(workChan)

	go func() {
		wg.Wait()
		close(resultChan)
	}()

	for i := 0; i < len(encoded); i++ {
		res := <-resultChan
		if res.err != nil {
			return nil, res.err
		}
		leafs[res.index] = res.leaf
	}

	return leafs, nil
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

	// don't write root to transcript for compatability with LigeroProveReference
	// transcript.AppendBytes("root", c.Tree.MerkleRoot())

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
	querySpan := core.StartSpan("Query columns", ctx)
	queriedCols := make([]*rlwe.Ciphertext, c.Committer.Queries)
	merklePaths := make([]core.MerklePath, c.Committer.Queries)
	extCols := c.Committer.Cols * c.Committer.RhoInv
	queryIndices := sampleQueryIndices(transcript, c.Committer.Queries, extCols)

	for i, queryColIdx := range queryIndices {
		queriedCols[i] = c.EncodedMatrix[queryColIdx]
		// Mod switch
		for queriedCols[i].Level() > 1 {
			backend.Rescale(queriedCols[i], queriedCols[i])
		}
		var err error
		merklePaths[i], err = c.Tree.GetMerklePath(uint(queryColIdx))
		if err != nil {
			return nil, err
		}
	}
	querySpan.End()
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

				// Mod switch
				for col.Level() > 1 {
					backend.Rescale(col, col)
				}

				// TODO: ring switch to discard garbage slots
				if backend.RingSwitch() != nil {
					col, err = backend.RingSwitch().RingSwitchNew(col, backend)
					if err != nil {
						resultChan <- matrixElementResult{index: i, err: err}
						continue
					}
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
	queriedColsResult, err := decryptBatchedParallel(
		p.QueriedCols,
		client,
		func(encoder *bgv.Encoder, pt *rlwe.Plaintext) ([]*core.Element, error) {
			column := make([]uint64, rows)
			if err := encoder.Decode(pt, column); err != nil {
				return nil, err
			}

			result := make([]*core.Element, rows)
			for i := range column {
				result[i] = core.NewElement(column[i])
			}
			return result, nil
		},
		span,
	)
	if err != nil {
		span.End()
		return nil, err
	}
	queriedColsPairs := make([]*vdec.ColumnInstance, len(p.QueriedCols))
	for i := range p.QueriedCols {
		queriedColsPairs[i] = &vdec.ColumnInstance{
			Ct:     p.QueriedCols[i],
			Values: queriedColsResult[i],
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

	// rs, err := NewRingSwitch(client, client.GetParameters().LogN()-1)
	// if err != nil {
	// 	return nil, err
	// }

	// for i := range p.MatR {
	// 	ct, err := rs.RingSwitch(p.MatR[i], client)
	// 	if err != nil {
	// 		return nil, err
	// 	}
	// 	p.MatR[i] = ct
	// }

	// for i := range p.MatZ {
	// 	ct, err := rs.RingSwitch(p.MatZ[i], client)
	// 	if err != nil {
	// 		return nil, err
	// 	}
	// 	p.MatZ[i] = ct
	// }

	// client = rs.NewClient(client)

	// Decrypt row inner products concurrently
	span = core.StartSpan("Decrypt row inner products", ctx)

	matRChan := make(chan struct {
		matR []*core.Element
		err  error
	}, 1)
	matZChan := make(chan struct {
		matZ []*core.Element
		err  error
	}, 1)

	decodeSingleElement := func(encoder *bgv.Encoder, pt *rlwe.Plaintext) (*core.Element, error) {
		column := make([]uint64, 1)
		if err := encoder.Decode(pt, column); err != nil {
			return nil, err
		}
		return core.NewElement(column[0]), nil
	}

	// Concurrent decryption of MatR and MatZ
	go func() {
		useClient := client.CopyNew()
		if client.RingSwitch() != nil {
			useClient = client.RingSwitch().NewClient(client)
		}

		matR, err := decryptBatchedParallel(
			p.MatR,
			useClient,
			func(encoder *bgv.Encoder, pt *rlwe.Plaintext) (*core.Element, error) {
				return decodeSingleElement(encoder, pt)
			},
			span,
		)
		matRChan <- struct {
			matR []*core.Element
			err  error
		}{matR, err}
	}()

	go func() {
		useClient := client.CopyNew()
		if client.RingSwitch() != nil {
			useClient = client.RingSwitch().NewClient(client)
		}

		matZ, err := decryptBatchedParallel(
			p.MatZ,
			useClient,
			func(encoder *bgv.Encoder, pt *rlwe.Plaintext) (*core.Element, error) {
				return decodeSingleElement(encoder, pt)
			},
			span,
		)
		matZChan <- struct {
			matZ []*core.Element
			err  error
		}{matZ, err}
	}()

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

func (p *Proof) Verify(point *core.Element, value *core.Element, field *core.PrimeField, transcript *core.Transcript) error {
	rows := p.Metadata.Rows
	cols := p.Metadata.Cols
	root := p.Root

	r := make([]*core.Element, rows)
	transcript.SampleFields("r", r)

	// Encode row inner products
	encodedMatR := core.Encode(p.MatR, p.Metadata.RhoInv, field)
	encodedMatZ := core.Encode(p.MatZ, p.Metadata.RhoInv, field)

	transcript.AppendField("point", point)

	// Compute a = [1, z, z^2, ..., z^(n_cols_1)]
	a := make([]*core.Element, cols)
	powA := core.One()
	for i := range cols {
		a[i] = powA
		field.MulAssign(powA, point, powA)
	}

	// Generate vector `b = [1, z^m, z^(2m), ..., z^((m-1)m)]`
	b := make([]*core.Element, rows)
	zPow := field.Pow(uint64(cols), point)
	if zPow.NotEqual(powA) {
		panic("zPow is not equal to powA")
	}
	powB := core.One()
	for i := range b {
		b[i] = powB
		field.MulAssign(powB, zPow, powB)
	}

	extCols := cols * p.Metadata.RhoInv
	queryIndices := sampleQueryIndices(transcript, p.Metadata.Queries, extCols)

	for i, queryColIdx := range queryIndices {
		if ok, err := core.VerifyMerklePath(p.QueriedCols[i].Ct, p.MerklePaths[i], root, uint(queryColIdx)); err != nil || !ok {
			return fmt.Errorf("failed to verify merkle path for column %d", queryColIdx)
		}

		if core.InnerProduct(p.QueriedCols[i].Values, r, field).NotEqual(encodedMatR[queryColIdx]) {
			fmt.Println("well-formedness R check failed for column expected", encodedMatR[queryColIdx], "got", core.InnerProduct(p.QueriedCols[i].Values, r, field))
			return fmt.Errorf("well-formedness R check failed for column %d", queryColIdx)
		}

		if core.InnerProduct(p.QueriedCols[i].Values, b, field).NotEqual(encodedMatZ[queryColIdx]) {
			return fmt.Errorf("well-formedness B check failed for column %d", queryColIdx)
		}
	}

	if core.InnerProduct(p.MatZ, a, field).NotEqual(value) {
		return fmt.Errorf(" claimed value does not match the evaluation of the committed polynomial")
	}

	return nil
}

// decryptBatchedParallel decrypts ciphertexts in parallel using the provided decoder function
func decryptBatchedParallel[T any](
	matrix []*rlwe.Ciphertext,
	client *ClientBFV,
	decoder func(*bgv.Encoder, *rlwe.Plaintext) (T, error),
	span *core.Span,
) ([]T, error) {
	type decryptionResult[T any] struct {
		index int
		value T
		err   error
	}

	result := make([]T, len(matrix))
	resultChan := make(chan decryptionResult[T], len(matrix))

	numWorkers := determineOptimalWorkers(len(matrix))
	workChan := make(chan int, len(matrix))

	var wg sync.WaitGroup
	for w := 0; w < numWorkers; w++ {
		wg.Add(1)
		client := client.CopyNew()
		go func() {
			defer wg.Done()
			for i := range workChan {
				pt := client.DecryptNew(matrix[i])
				value, err := decoder(client.Encoder, pt)
				if err != nil {
					resultChan <- decryptionResult[T]{index: i, err: err}
					continue
				}

				resultChan <- decryptionResult[T]{
					index: i,
					value: value,
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

	matRSize := 0
	for i := range p.MatR {
		n, err := p.MatR[i].WriteTo(buf)
		if err != nil {
			return err
		}
		matRSize += int(n)
	}
	fmt.Printf("Marshaled MatR: %s\n", humanize.Bytes(uint64(matRSize)))

	matZSize := 0
	for i := range p.MatZ {
		n, err := p.MatZ[i].WriteTo(buf)
		if err != nil {
			return err
		}
		matZSize += int(n)
	}
	fmt.Printf("Marshaled MatZ: %s\n", humanize.Bytes(uint64(matZSize)))

	queriedColsSize := 0
	for i := range p.QueriedCols {
		n, err := p.QueriedCols[i].WriteTo(buf)
		if err != nil {
			return err
		}
		queriedColsSize += int(n)
	}
	fmt.Printf("Marshaled QueriedCols: %s\n", humanize.Bytes(uint64(queriedColsSize)))

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

func (c *LigeroCommitter) LigeroProveReference(matrix [][]*core.Element, point *core.Element, field *core.PrimeField, transcript *core.Transcript, parentSpan *core.Span) (*Proof, error) {
	rows := c.Rows
	cols := c.Cols
	rhoInv := c.RhoInv
	queries := c.Queries

	commitSpan := core.StartSpan("Ligero commit", parentSpan, "Ligero commit")
	// Commit
	encoded, err := func() ([][]*core.Element, error) {
		span := core.StartSpan("Encode", commitSpan)
		defer span.End()
		encodedMatrix := make([][]*core.Element, rows)
		for i := range matrix {
			encodedMatrix[i] = core.Encode(matrix[i], rhoInv, field)
		}

		encodedMatrixColMajor := make([][]*core.Element, cols*rhoInv)
		for i := range encodedMatrixColMajor {
			encodedMatrixColMajor[i] = make([]*core.Element, rows)
		}
		for i := range encodedMatrixColMajor {
			for j := range encodedMatrixColMajor[i] {
				encodedMatrixColMajor[i][j] = encodedMatrix[j][i]
			}
		}
		return encodedMatrixColMajor, nil
	}()
	if err != nil {
		return nil, err
	}

	span := core.StartSpan("Merkle tree", commitSpan)
	leafs := make([]core.Leaf, len(encoded))
	for i := range encoded {
		buf := bytes.NewBuffer(nil)
		for j := range encoded[i] {
			binary.Write(buf, binary.LittleEndian, encoded[i][j])
		}
		leafs[i] = buf
	}

	tree, err := core.NewTree(leafs)
	if err != nil {
		return nil, err
	}
	span.End()

	proveSpan := core.StartSpan("Ligero prove", parentSpan, "Ligero prove")
	span = core.StartSpan("Compute inner products R", proveSpan)

	r := make([]*core.Element, rows)
	transcript.SampleFields("r", r)
	// Compute inner products of each row with r
	matR := make([]*core.Element, cols)

	for j := 0; j < cols; j++ {
		sum := core.Zero()
		for i := 0; i < rows; i++ {
			// multiply matrix[i][j] by r[i] and add to sum
			product := field.Mul(matrix[i][j], r[i])
			sum = field.Add(sum, product)
		}
		matR[j] = sum
	}
	span.End()

	span = core.StartSpan("Compute inner products B", proveSpan)
	b := make([]*core.Element, rows)
	zPow := field.Pow(uint64(cols), point)
	powB := core.One()
	for i := range b {
		b[i] = powB
		field.MulAssign(powB, zPow, powB)
	}

	matZ := make([]*core.Element, cols)
	for j := 0; j < cols; j++ {
		sum := core.Zero()
		for i := 0; i < rows; i++ {
			// multiply matrix[i][j] by r[i] and add to sum
			product := field.Mul(matrix[i][j], b[i])
			sum = field.Add(sum, product)
		}
		matZ[j] = sum
	}
	span.End()

	transcript.AppendField("point", point)

	span = core.StartSpan("Query columns", proveSpan)
	queriedCols := make([]*vdec.ColumnInstance, queries)
	merklePaths := make([]core.MerklePath, queries)
	extCols := cols * rhoInv
	queryIndices := sampleQueryIndices(transcript, queries, extCols)

	for i, queryColIdx := range queryIndices {
		queriedCols[i] = &vdec.ColumnInstance{
			Values: encoded[queryColIdx],
		}
		var err error
		merklePaths[i], err = tree.GetMerklePath(uint(queryColIdx))
		if err != nil {
			return nil, err
		}
	}
	span.End()
	proveSpan.End()

	proof := &Proof{
		Metadata:    c.LigeroMetadata,
		Root:        tree.MerkleRoot(),
		MatR:        matR,
		MatZ:        matZ,
		QueriedCols: queriedCols,
		MerklePaths: merklePaths,
	}
	return proof, nil
}
