// Package dft implements a homomorphic DFT circuit for the CKKS scheme.
package fhe

import (
	"encoding/json"
	"fmt"
	"math"
	"math/big"
	"slices"

	"github.com/nulltea/lumenos/core"
	ltcommon "github.com/tuneinsight/lattigo/v6/circuits/bgv/lintrans"
	"github.com/tuneinsight/lattigo/v6/circuits/common/lintrans"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/ring"
	"github.com/tuneinsight/lattigo/v6/schemes/bgv"
	"github.com/tuneinsight/lattigo/v6/utils"
	"github.com/tuneinsight/lattigo/v6/utils/bignum"
)

// Type is a type used to distinguish between different discrete Fourier transformations.
type Type int

// HomomorphicEncode (IDFT) and HomomorphicDecode (DFT) are two available linear transformations for homomorphic encoding and decoding.
const (
	HomomorphicEncode = Type(0) // Homomorphic Encoding (IDFT)
	HomomorphicDecode = Type(1) // Homomorphic Decoding (DFT)
)

// Format is a type used to distinguish between the
// different input/output formats of the Homomorphic DFT.
type Format int

const (
	// Standard: designates the regular DFT.
	// Example: [a+bi, c+di] -> DFT([a+bi, c+di])
	Standard = Format(0)
	// SplitRealAndImag: HomomorphicEncode will return the real and
	// imaginary part into separate ciphertexts, both as real vectors.
	// Example: [a+bi, c+di] -> DFT([a, c]) and DFT([b, d])
	SplitRealAndImag = Format(1)
	// RepackImagAsReal: behaves the same as SplitRealAndImag except that
	// if the ciphertext is sparsely packed (at most N/4 slots), HomomorphicEncode
	// will repacks the real part into the left N/2 slots and the imaginary part
	// into the right N/2 slots. HomomorphicDecode must be specified with the same
	// format for correctness.
	// Example: [a+bi, 0, c+di, 0] -> [DFT([a, b]), DFT([b, d])]
	RepackImagAsReal = Format(2)
)

// Matrix is a struct storing the factorized IDFT, DFT matrices, which are
// used to homomorphically encode and decode a ciphertext respectively.
type Matrix struct {
	MatrixLiteral
	Matrices []ltcommon.LinearTransformation
}

// MatrixLiteral is a struct storing the parameters to generate the factorized DFT/IDFT matrices.
// This struct has mandatory and optional fields.
//
// Mandatory:
//   - Type: HomomorphicEncode (a.k.a. CoeffsToSlots) or HomomorphicDecode (a.k.a. SlotsToCoeffs)
//   - LogSlots: log2(slots)
//   - LevelQ: starting level of the linear transformation
//   - LevelP: number of auxiliary primes used during the automorphisms. User must ensure that this
//     value is the same as the one used to generate the Galois keys.
//   - Levels: depth of the linear transform (i.e. the degree of factorization of the encoding matrix)
//
// Optional:
//   - Format: which post-processing (if any) to apply to the DFT.
//   - Scaling: constant by which the matrix is multiplied
//   - BitReversed: if true, then applies the transformation bit-reversed and expects bit-reversed inputs
//   - LogBSGSRatio: log2 of the ratio between the inner and outer loop of the baby-step giant-step algorithm
type MatrixLiteral struct {
	// Mandatory
	Type     Type
	LogSlots int
	LevelQ   int
	LevelP   int
	Levels   []int
	// Optional
	Format       Format     // Default: standard.
	Scaling      *big.Float // Default 1.0.
	BitReversed  bool       // Default: False.
	LogBSGSRatio int        // Default: 0.
}

// Depth returns the number of levels allocated to the linear transform.
// If actual == true then returns the number of moduli consumed, else
// returns the factorization depth.
func (d MatrixLiteral) Depth(actual bool) (depth int) {
	if actual {
		depth = len(d.Levels)
	} else {
		for _, d := range d.Levels {
			depth += d
		}
	}
	return
}

// GaloisElements returns the list of rotations performed during the CoeffsToSlot operation.
func (d MatrixLiteral) GaloisElements(params bgv.Parameters) (galEls []uint64) {
	rotations := []int{}

	imgRepack := d.Format == RepackImagAsReal

	logSlots := d.LogSlots
	logN := params.LogN()
	slots := 1 << logSlots
	dslots := slots
	if logSlots < logN-1 && imgRepack {
		dslots <<= 1
		if d.Type == HomomorphicEncode {
			rotations = append(rotations, slots)
		}
	}

	indexCtS := d.computeBootstrappingDFTIndexMap(logN)

	// Coeffs to Slots rotations
	for i, pVec := range indexCtS {
		N1 := lintrans.FindBestBSGSRatio(utils.GetKeys(pVec), dslots, d.LogBSGSRatio)
		rotations = addMatrixRotToList(pVec, rotations, N1, slots, d.Type == HomomorphicDecode && logSlots < logN-1 && i == 0 && imgRepack)
	}

	return params.GaloisElements(rotations)
}

// MarshalBinary returns a JSON representation of the the target [MatrixLiteral] on a slice of bytes.
// See `Marshal` from the `encoding/json` package.
func (d MatrixLiteral) MarshalBinary() (data []byte, err error) {
	return json.Marshal(d)
}

// UnmarshalBinary reads a JSON representation on the target [MatrixLiteral] struct.
// See `Unmarshal` from the `encoding/json` package.
func (d *MatrixLiteral) UnmarshalBinary(data []byte) error {
	return json.Unmarshal(data, d)
}

// Evaluator is an evaluator providing an API for homomorphic DFT.
// All fields of this struct are public, enabling custom instantiations.
type Evaluator struct {
	*bgv.Evaluator
	LTEvaluator *ltcommon.Evaluator
	parameters  bgv.Parameters
}

// NewEvaluator instantiates a new [Evaluator] from a [ckks.Evaluator].
func NewEvaluator(params bgv.Parameters, eval *bgv.Evaluator) *Evaluator {
	dfteval := new(Evaluator)
	dfteval.Evaluator = eval
	dfteval.LTEvaluator = ltcommon.NewEvaluator(eval)
	dfteval.parameters = params
	return dfteval
}

// NewMatrixFromLiteral generates the factorized DFT/IDFT matrices for the homomorphic encoding/decoding.
func NewMatrixFromLiteral(params bgv.Parameters, d MatrixLiteral, encoder *bgv.Encoder) (Matrix, error) {

	logSlots := d.LogSlots
	logdSlots := logSlots
	if maxLogSlots := params.LogMaxDimensions().Cols; logdSlots < maxLogSlots && d.Format == RepackImagAsReal {
		logdSlots++
	}

	// CoeffsToSlots vectors
	matrices := []ltcommon.LinearTransformation{}
	pVecDFT := d.GenMatrices(params.LogN(), params)

	// For BGV, we use a fixed number of moduli per rescaling
	nbModuliPerRescale := 1

	level := d.LevelQ
	var idx int
	for i := range d.Levels {

		scale := rlwe.NewScale(params.Q()[level])

		for j := 1; j < nbModuliPerRescale; j++ {
			scale = scale.Mul(rlwe.NewScale(params.Q()[level-j]))
		}

		if d.Levels[i] > 1 {
			y := new(big.Float).SetPrec(scale.Value.Prec()).SetInt64(1)
			y.Quo(y, new(big.Float).SetPrec(scale.Value.Prec()).SetInt64(int64(d.Levels[i])))

			scale.Value = *bignum.Pow(&scale.Value, y)
		}

		for j := 0; j < d.Levels[i]; j++ {

			ltparams := ltcommon.Parameters{
				DiagonalsIndexList:        pVecDFT[idx].DiagonalsIndexList(),
				LevelQ:                    d.LevelQ,
				LevelP:                    d.LevelP,
				Scale:                     scale,
				LogDimensions:             ring.Dimensions{Rows: 0, Cols: logdSlots},
				LogBabyStepGiantStepRatio: d.LogBSGSRatio,
			}

			mat := ltcommon.NewLinearTransformation(params, ltparams)

			if err := ltcommon.Encode(encoder, pVecDFT[idx], mat); err != nil {
				return Matrix{}, fmt.Errorf("cannot NewDFTMatrixFromLiteral: %w", err)
			}

			matrices = append(matrices, mat)
			idx++
		}

		level -= nbModuliPerRescale
	}

	return Matrix{MatrixLiteral: d, Matrices: matrices}, nil
}

// CoeffsToSlotsNew applies the homomorphic encoding and returns the result on new ciphertexts.
// Homomorphically encodes a complex vector vReal + i*vImag.
// Given n = current number of slots and N/2 max number of slots (half the ring degree):
// If the packing is sparse (n < N/2), then returns ctReal = Ecd(vReal || vImag) and ctImag = nil.
// If the packing is dense (n == N/2), then returns ctReal = Ecd(vReal) and ctImag = Ecd(vImag).
func (eval *Evaluator) CoeffsToSlotsNew(ctIn *rlwe.Ciphertext, ctsMatrices Matrix) (ctReal, ctImag *rlwe.Ciphertext, err error) {
	ctReal = bgv.NewCiphertext(eval.parameters, 1, ctsMatrices.LevelQ)

	if ctsMatrices.LogSlots == eval.parameters.LogMaxSlots() {
		ctImag = bgv.NewCiphertext(eval.parameters, 1, ctsMatrices.LevelQ)
	}

	return ctReal, ctImag, eval.CoeffsToSlots(ctIn, ctsMatrices, ctReal, ctImag)
}

// CoeffsToSlots applies the homomorphic encoding and returns the results on the provided ciphertexts.
// Homomorphically encodes a complex vector vReal + i*vImag of size n on a real vector of size 2n.
// If the packing is sparse (n < N/2), then returns ctReal = Ecd(vReal || vImag) and ctImag = nil.
// If the packing is dense (n == N/2), then returns ctReal = Ecd(vReal) and ctImag = Ecd(vImag).
func (eval *Evaluator) CoeffsToSlots(ctIn *rlwe.Ciphertext, ctsMatrices Matrix, ctReal, ctImag *rlwe.Ciphertext) (err error) {
	// For BGV, only implementing the standard format case
	if err = eval.dft(ctIn, ctsMatrices.Matrices, ctReal); err != nil {
		return fmt.Errorf("cannot CoeffsToSlots: %w", err)
	}
	return
}

// SlotsToCoeffsNew applies the homomorphic decoding and returns the result on a new ciphertext.
// For BGV, this performs a homomorphic DFT to transform from slot to coefficient representation.
func (eval *Evaluator) SlotsToCoeffsNew(ctReal, ctImag *rlwe.Ciphertext, stcMatrices Matrix) (opOut *rlwe.Ciphertext, err error) {
	if ctReal.Level() < stcMatrices.LevelQ || (ctImag != nil && ctImag.Level() < stcMatrices.LevelQ) {
		return nil, fmt.Errorf("ctReal.Level() or ctImag.Level() < DFTMatrix.LevelQ")
	}

	opOut = bgv.NewCiphertext(eval.parameters, 1, stcMatrices.LevelQ)
	return opOut, eval.SlotsToCoeffs(ctReal, ctImag, stcMatrices, opOut)
}

// SlotsToCoeffs applies the homomorphic decoding and returns the result on the provided ciphertext.
// For BGV, this performs a homomorphic DFT to transform from slot to coefficient representation.
func (eval *Evaluator) SlotsToCoeffs(ctReal, ctImag *rlwe.Ciphertext, stcMatrices Matrix, opOut *rlwe.Ciphertext) (err error) {
	// For BGV, we only support the standard format (not RepackImagAsReal or SplitRealAndImag)
	// So we expect ctImag to be nil
	if ctImag != nil {
		return fmt.Errorf("BGV SlotsToCoeffs currently only supports standard format (ctImag must be nil)")
	}

	// Apply the DFT matrices to perform the homomorphic decoding
	if err = eval.dft(ctReal, stcMatrices.Matrices, opOut); err != nil {
		return fmt.Errorf("cannot SlotsToCoeffs: %w", err)
	}

	return nil
}

// dft evaluates a series of [lintrans.LinearTransformation] sequentially on the ctIn and stores the result in opOut.
func (eval *Evaluator) dft(ctIn *rlwe.Ciphertext, matrices []ltcommon.LinearTransformation, opOut *rlwe.Ciphertext) (err error) {

	inputLogSlots := ctIn.LogDimensions

	// Sequentially multiplies w with the provided dft matrices.
	if err = eval.LTEvaluator.EvaluateSequential(ctIn, matrices, opOut); err != nil {
		return
	}

	// Encoding matrices are a special case of `fractal` linear transform
	// that doesn't change the underlying plaintext polynomial Y = X^{N/n}
	// of the input ciphertext.
	opOut.LogDimensions = inputLogSlots

	return
}

// fftPlainVecBGV performs the FFT computation for BGV using finite field arithmetic
// It returns three matrices (a, b, c) of finite field elements for use in the DFT
func fftPlainVecBGV(logN, dslots int, field *core.PrimeField, pow5 []int) (a, b, c [][]uint64) {
	var N, m, index, tt, gap, k, mask, idx1, idx2 int

	N = 1 << logN

	a = make([][]uint64, logN)
	b = make([][]uint64, logN)
	c = make([][]uint64, logN)

	var size int
	if 2*N == dslots {
		size = 2
	} else {
		size = 1
	}

	index = 0
	for m = 2; m <= N; m <<= 1 {
		aM := make([]uint64, dslots)
		bM := make([]uint64, dslots)
		cM := make([]uint64, dslots)

		tt = m >> 1

		for i := 0; i < N; i += m {
			gap = N / m
			mask = (m << 2) - 1

			for j := 0; j < m>>1; j++ {
				k = (pow5[j] & mask) * gap

				idx1 = i + j
				idx2 = i + j + tt

				for u := 0; u < size; u++ {
					// Set values using finite field operations
					aM[idx1+u*N] = 1                                            // Identity element in the field
					aM[idx2+u*N] = field.Modulus() - field.RootForwardUint64(k) // Negation in the field
					bM[idx1+u*N] = field.RootForwardUint64(k)
					cM[idx2+u*N] = 1 // Identity element in the field
				}
			}
		}

		a[index] = aM
		b[index] = bM
		c[index] = cM

		index++
	}

	return
}

// ifftPlainVecBGV performs the inverse FFT computation for BGV using finite field arithmetic
func ifftPlainVecBGV(logN, dslots int, field *core.PrimeField, pow5 []int) (a, b, c [][]uint64) {
	var N, m, index, tt, gap, k, mask, idx1, idx2 int

	N = 1 << logN

	a = make([][]uint64, logN)
	b = make([][]uint64, logN)
	c = make([][]uint64, logN)

	var size int
	if 2*N == dslots {
		size = 2
	} else {
		size = 1
	}

	index = 0
	for m = N; m >= 2; m >>= 1 {
		aM := make([]uint64, dslots)
		bM := make([]uint64, dslots)
		cM := make([]uint64, dslots)

		tt = m >> 1

		for i := 0; i < N; i += m {
			gap = N / m
			mask = (m << 2) - 1

			for j := 0; j < m>>1; j++ {
				k = ((m << 2) - (pow5[j] & mask)) * gap

				idx1 = i + j
				idx2 = i + j + tt

				for u := 0; u < size; u++ {
					// Set values using finite field operations
					aM[idx1+u*N] = 1                                            // Identity element in the field
					aM[idx2+u*N] = field.Modulus() - field.RootForwardUint64(k) // Negation in the field
					bM[idx1+u*N] = 1                                            // Identity element in the field
					cM[idx2+u*N] = field.RootForwardUint64(k)
				}
			}
		}

		a[index] = aM
		b[index] = bM
		c[index] = cM

		index++
	}

	return
}

func addMatrixRotToList(pVec map[int]bool, rotations []int, N1, slots int, repack bool) []int {

	if len(pVec) < 3 {
		for j := range pVec {
			if !slices.Contains(rotations, j) {
				rotations = append(rotations, j)
			}
		}
	} else {
		var index int
		for j := range pVec {

			index = (j / N1) * N1

			if repack {
				// Sparse repacking, occurring during the first DFT matrix of the CoeffsToSlots.
				index &= (2*slots - 1)
			} else {
				// Other cases
				index &= (slots - 1)
			}

			if index != 0 && !slices.Contains(rotations, index) {
				rotations = append(rotations, index)
			}

			index = j & (N1 - 1)

			if index != 0 && !slices.Contains(rotations, index) {
				rotations = append(rotations, index)
			}
		}
	}

	return rotations
}

func (d MatrixLiteral) computeBootstrappingDFTIndexMap(logN int) (rotationMap []map[int]bool) {

	logSlots := d.LogSlots
	ltType := d.Type
	repacki2r := d.Format == RepackImagAsReal
	bitreversed := d.BitReversed
	maxDepth := d.Depth(false)

	var level, depth, nextLevel int

	level = logSlots

	rotationMap = make([]map[int]bool, maxDepth)

	// We compute the chain of merge in order or reverse order depending if its DFT or InvDFT because
	// the way the levels are collapsed has an impact on the total number of rotations and keys to be
	// stored. Ex. instead of using 255 + 64 plaintext vectors, we can use 127 + 128 plaintext vectors
	// by reversing the order of the merging.
	merge := make([]int, maxDepth)
	for i := 0; i < maxDepth; i++ {

		depth = int(math.Ceil(float64(level) / float64(maxDepth-i)))

		if ltType == HomomorphicEncode {
			merge[i] = depth
		} else {
			merge[len(merge)-i-1] = depth

		}

		level -= depth
	}

	level = logSlots
	for i := 0; i < maxDepth; i++ {

		if logSlots < logN-1 && ltType == HomomorphicDecode && i == 0 && repacki2r {

			// Special initial matrix for the repacking before Decode
			rotationMap[i] = genWfftRepackIndexMap(logSlots, level)

			// Merges this special initial matrix with the first layer of Decode DFT
			rotationMap[i] = nextLevelfftIndexMap(rotationMap[i], logSlots, 2<<logSlots, level, ltType, bitreversed)

			// Continues the merging with the next layers if the total depth requires it.
			nextLevel = level - 1
			for j := 0; j < merge[i]-1; j++ {
				rotationMap[i] = nextLevelfftIndexMap(rotationMap[i], logSlots, 2<<logSlots, nextLevel, ltType, bitreversed)
				nextLevel--
			}

		} else {

			// First layer of the i-th level of the DFT
			rotationMap[i] = genWfftIndexMap(logSlots, level, ltType, bitreversed)

			// Merges the layer with the next levels of the DFT if the total depth requires it.
			nextLevel = level - 1
			for j := 0; j < merge[i]-1; j++ {
				rotationMap[i] = nextLevelfftIndexMap(rotationMap[i], logSlots, 1<<logSlots, nextLevel, ltType, bitreversed)
				nextLevel--
			}
		}

		level -= merge[i]
	}

	return
}

func genWfftIndexMap(logL, level int, ltType Type, bitreversed bool) (vectors map[int]bool) {

	var rot int

	if ltType == HomomorphicEncode && !bitreversed || ltType == HomomorphicDecode && bitreversed {
		rot = 1 << (level - 1)
	} else {
		rot = 1 << (logL - level)
	}

	vectors = make(map[int]bool)
	vectors[0] = true
	vectors[rot] = true
	vectors[(1<<logL)-rot] = true
	return
}

func genWfftRepackIndexMap(logL, level int) (vectors map[int]bool) {
	vectors = make(map[int]bool)
	vectors[0] = true
	vectors[(1 << logL)] = true
	return
}

func nextLevelfftIndexMap(vec map[int]bool, logL, N, nextLevel int, ltType Type, bitreversed bool) (newVec map[int]bool) {

	var rot int

	newVec = make(map[int]bool)

	if ltType == HomomorphicEncode && !bitreversed || ltType == HomomorphicDecode && bitreversed {
		rot = (1 << (nextLevel - 1)) & (N - 1)
	} else {
		rot = (1 << (logL - nextLevel)) & (N - 1)
	}

	for i := range vec {
		newVec[i] = true
		newVec[(i+rot)&(N-1)] = true
		newVec[(i-rot)&(N-1)] = true
	}

	return
}

// genFFTDiagMatrixBGV generates the diagonal FFT matrix for BGV using finite field arithmetic
func genFFTDiagMatrixBGV(logL, fftLevel int, a, b, c []uint64, field *core.PrimeField, ltType Type, bitreversed bool) (vectors map[int][]uint64) {
	var rot int

	if ltType == HomomorphicEncode && !bitreversed || ltType == HomomorphicDecode && bitreversed {
		rot = 1 << (fftLevel - 1)
	} else {
		rot = 1 << (logL - fftLevel)
	}

	vectors = make(map[int][]uint64)

	if bitreversed {
		utils.BitReverseInPlaceSlice(a, 1<<logL)
		utils.BitReverseInPlaceSlice(b, 1<<logL)
		utils.BitReverseInPlaceSlice(c, 1<<logL)

		if len(a) > 1<<logL {
			utils.BitReverseInPlaceSlice(a[1<<logL:], 1<<logL)
			utils.BitReverseInPlaceSlice(b[1<<logL:], 1<<logL)
			utils.BitReverseInPlaceSlice(c[1<<logL:], 1<<logL)
		}
	}

	addToDiagMatrixBGV(vectors, 0, a)
	addToDiagMatrixBGV(vectors, rot, b)
	addToDiagMatrixBGV(vectors, (1<<logL)-rot, c)

	return
}

// addToDiagMatrixBGV adds a vector to the diagonal matrix for BGV
func addToDiagMatrixBGV(diagMat map[int][]uint64, index int, vec []uint64) {
	if diagMat[index] == nil {
		diagMat[index] = make([]uint64, len(vec))
		copy(diagMat[index], vec)
	} else {
		addBGV(diagMat[index], vec, diagMat[index])
	}
}

// addBGV adds two uint64 vectors modulo q
func addBGV(a, b, c []uint64, modulus ...uint64) {
	for i := 0; i < len(a); i++ {
		if len(modulus) > 0 {
			c[i] = ring.CRed(a[i]+b[i], modulus[0])
		} else {
			c[i] = a[i] + b[i]
		}
	}
}

// rotateAndMulNewBGV rotates and multiplies vectors in the finite field
func rotateAndMulNewBGV(a []uint64, k int, b []uint64, field *core.PrimeField) (c []uint64) {
	c = make([]uint64, len(a))
	copy(c, b)

	mask := int(len(a) - 1)

	for i := 0; i < len(a); i++ {
		c[i] = ring.BRed(c[i], a[(i+k)&mask], field.Modulus(), field.BRedConstant())
	}

	return
}

// multiplyFFTMatrixWithNextFFTLevelBGV multiplies the FFT matrix with the next level for BGV
func multiplyFFTMatrixWithNextFFTLevelBGV(vec map[int][]uint64, logL, N, nextLevel int, a, b, c []uint64, field *core.PrimeField, ltType Type, bitreversed bool) (newVec map[int][]uint64) {
	var rot int

	newVec = make(map[int][]uint64)

	if ltType == HomomorphicEncode && !bitreversed || ltType == HomomorphicDecode && bitreversed {
		rot = (1 << (nextLevel - 1)) & (N - 1)
	} else {
		rot = (1 << (logL - nextLevel)) & (N - 1)
	}

	if bitreversed {
		utils.BitReverseInPlaceSlice(a, 1<<logL)
		utils.BitReverseInPlaceSlice(b, 1<<logL)
		utils.BitReverseInPlaceSlice(c, 1<<logL)

		if len(a) > 1<<logL {
			utils.BitReverseInPlaceSlice(a[1<<logL:], 1<<logL)
			utils.BitReverseInPlaceSlice(b[1<<logL:], 1<<logL)
			utils.BitReverseInPlaceSlice(c[1<<logL:], 1<<logL)
		}
	}

	for i := range vec {
		addToDiagMatrixBGV(newVec, i, rotateAndMulNewBGV(vec[i], 0, a, field))
		addToDiagMatrixBGV(newVec, (i+rot)&(N-1), rotateAndMulNewBGV(vec[i], rot, b, field))
		addToDiagMatrixBGV(newVec, (i-rot)&(N-1), rotateAndMulNewBGV(vec[i], -rot, c, field))
	}

	return
}

// genRepackMatrixBGV generates a repack matrix for BGV
func genRepackMatrixBGV(logL int, field *core.PrimeField, bitreversed bool) (vectors map[int][]uint64) {
	vectors = make(map[int][]uint64)

	a := make([]uint64, 2<<logL)
	b := make([]uint64, 2<<logL)

	for i := 0; i < 1<<logL; i++ {
		a[i] = 1 // Set to identity element in the field
		a[i+(1<<logL)] = 0

		b[i] = 0
		b[i+(1<<logL)] = 1 // Set to identity element in the field
	}

	addToDiagMatrixBGV(vectors, 0, a)
	addToDiagMatrixBGV(vectors, (1 << logL), b)

	return
}

// Update the GenMatrices function to use the new BGV-specific functions
func (d MatrixLiteral) GenMatrices(LogN int, params bgv.Parameters) (plainVector []ltcommon.Diagonals[uint64]) {
	logSlots := d.LogSlots
	slots := 1 << logSlots
	maxDepth := d.Depth(false)
	ltType := d.Type
	bitreversed := d.BitReversed
	imagRepack := d.Format == RepackImagAsReal

	logdSlots := logSlots
	if logdSlots < LogN-1 && imagRepack {
		logdSlots++
	}

	// Create field for finite field operations
	field, err := core.NewPrimeField(params.RingT().SubRings[0].Modulus, params.RingT().SubRings[0].N*2)
	if err != nil {
		panic(fmt.Errorf("failed to create prime field: %w", err))
	}

	pow5 := make([]int, (slots<<1)+1)
	pow5[0] = 1
	for i := 1; i < (slots<<1)+1; i++ {
		pow5[i] = pow5[i-1] * 5
		pow5[i] &= (slots << 2) - 1
	}

	var fftLevel, depth, nextfftLevel int
	fftLevel = logSlots

	var a, b, c [][]uint64
	if ltType == HomomorphicEncode {
		a, b, c = ifftPlainVecBGV(logSlots, 1<<logdSlots, &field, pow5)
	} else {
		a, b, c = fftPlainVecBGV(logSlots, 1<<logdSlots, &field, pow5)
	}

	plainVector = make([]ltcommon.Diagonals[uint64], maxDepth)

	// We compute the chain of merge in order or reverse order depending if its DFT or InvDFT
	merge := make([]int, maxDepth)
	for i := 0; i < maxDepth; i++ {
		depth = int(math.Ceil(float64(fftLevel) / float64(maxDepth-i)))

		if ltType == HomomorphicEncode {
			merge[i] = depth
		} else {
			merge[len(merge)-i-1] = depth
		}

		fftLevel -= depth
	}

	fftLevel = logSlots
	for i := 0; i < maxDepth; i++ {
		if logSlots != logdSlots && ltType == HomomorphicDecode && i == 0 && imagRepack {
			// Special initial matrix for the repacking before DFT
			plainVector[i] = genRepackMatrixBGV(logSlots, &field, bitreversed)

			// Merges this special initial matrix with the first layer of DFT
			plainVector[i] = multiplyFFTMatrixWithNextFFTLevelBGV(plainVector[i], logSlots, 2*slots, fftLevel, a[logSlots-fftLevel], b[logSlots-fftLevel], c[logSlots-fftLevel], &field, ltType, bitreversed)

			// Continues the merging with the next layers if the total depth requires it.
			nextfftLevel = fftLevel - 1
			for j := 0; j < merge[i]-1; j++ {
				plainVector[i] = multiplyFFTMatrixWithNextFFTLevelBGV(plainVector[i], logSlots, 2*slots, nextfftLevel, a[logSlots-nextfftLevel], b[logSlots-nextfftLevel], c[logSlots-nextfftLevel], &field, ltType, bitreversed)
				nextfftLevel--
			}
		} else {
			// First layer of the i-th level of the DFT
			plainVector[i] = genFFTDiagMatrixBGV(logSlots, fftLevel, a[logSlots-fftLevel], b[logSlots-fftLevel], c[logSlots-fftLevel], &field, ltType, bitreversed)

			// Merges the layer with the next levels of the DFT if the total depth requires it.
			nextfftLevel = fftLevel - 1
			for j := 0; j < merge[i]-1; j++ {
				plainVector[i] = multiplyFFTMatrixWithNextFFTLevelBGV(plainVector[i], logSlots, slots, nextfftLevel, a[logSlots-nextfftLevel], b[logSlots-nextfftLevel], c[logSlots-nextfftLevel], &field, ltType, bitreversed)
				nextfftLevel--
			}
		}

		fftLevel -= merge[i]
	}

	// Repacking after the IDFT (we multiply the last matrix with the vector [1, 1, ..., 1, 1, 0, 0, ..., 0, 0]).
	if logSlots != logdSlots && ltType == HomomorphicEncode && imagRepack {
		for j := range plainVector[maxDepth-1] {
			v := plainVector[maxDepth-1][j]
			for x := 0; x < slots; x++ {
				v[x+slots] = 0
			}
		}
	}

	// Apply scaling factor
	// Use a fixed precision for scaling calculations
	const precision uint = 256
	scaling := new(big.Float).SetPrec(precision)
	if d.Scaling == nil {
		scaling.SetFloat64(1)
	} else {
		scaling.Set(d.Scaling)
	}

	// If DFT matrix, rescale by 1/N
	if ltType == HomomorphicEncode {
		// Real/Imag extraction 1/2 factor
		if d.Format == RepackImagAsReal || d.Format == SplitRealAndImag {
			scaling.Quo(scaling, new(big.Float).SetFloat64(float64(2*slots)))
		} else {
			scaling.Quo(scaling, new(big.Float).SetFloat64(float64(slots)))
		}
	}

	// Convert the scaling factor to a field element
	var scalingInt uint64
	if scaling.Cmp(new(big.Float).SetInt64(1)) == 0 {
		scalingInt = 1 // No scaling needed
	} else {
		// Convert float to field element - this is a simplification
		// In practice, you would need proper scaling based on the field characteristics
		scalingFloat, _ := scaling.Float64()
		scalingInt = uint64(scalingFloat * float64(field.Modulus()))
		scalingInt %= field.Modulus()
	}

	// Apply scaling to all matrices if not identity
	if scalingInt != 1 {
		for j := range plainVector {
			for x := range plainVector[j] {
				v := plainVector[j][x]
				for i := range v {
					v[i] = ring.BRed(v[i], scalingInt, field.Modulus(), field.BRedConstant())
				}
			}
		}
	}

	return
}
