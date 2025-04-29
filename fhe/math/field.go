package math

import (
	"fmt"
	"math/bits"

	"github.com/tuneinsight/lattigo/v6/ring"
	"github.com/tuneinsight/lattigo/v6/utils"
)

// Element represents a field element stored on 1 words (uint64)
//
// Element are assumed to be in Montgomery form in all methods.
//
// Modulus q =
//
//	q[base10] = 288230376150630401
//	q[base16] = 0x3FFFFFFFFEF8001
//
// # Warning
//
// This code has not been audited and is provided as-is. In particular, there is no security guarantees such as constant time implementation or side-channel attack resistance.
type PrimeField struct {
	r *ring.SubRing
}

func NewPrimeField(modulus uint64, N int) (PrimeField, error) {
	r, err := ring.NewSubRing(N, modulus)
	if err != nil {
		return PrimeField{}, err
	}

	field := PrimeField{r}
	if err := field.generateNTTConstants(); err != nil {
		return PrimeField{}, err
	}
	return field, nil
}

func (f *PrimeField) N() int {
	return f.r.N
}

func (f *PrimeField) RootForward(i int) *Element {
	return NewElement(f.r.RootsForward[i])
}

func (f *PrimeField) RootForwardUint64(i int) uint64 {
	return f.r.RootsForward[i]
}

// Mul z = x * y (mod q)
func (f *PrimeField) Mul(x, y *Element) *Element {
	z := Zero()
	f.MulAssign(x, y, z)
	return z
}

func (f *PrimeField) MulAssign(x, y, z *Element) {
	z[0] = ring.BRed(x[0], y[0], f.r.Modulus, f.r.BRedConstant)
}

// Add z = x + y (mod q)
func (f *PrimeField) Add(x, y *Element) *Element {
	z := Zero()
	f.AddAssign(x, y, z)
	return z
}

func (f *PrimeField) AddAssign(x, y, z *Element) {
	z[0] = ring.CRed(x[0]+y[0], f.r.Modulus)
}

// Double z = x + x (mod q), aka Lsh 1
func (f *PrimeField) Double(x *Element) *Element {
	z := Zero()
	f.AddAssign(x, x, z)
	return z
}

// Sub z = x - y (mod q)
func (f *PrimeField) Sub(x, y *Element) *Element {
	z := Zero()
	f.SubAssign(x, y, z)
	return z
}

func (f *PrimeField) SubAssign(x, y, z *Element) {
	z[0] = ring.CRed(x[0]+f.r.Modulus-y[0], f.r.Modulus)
}

// Neg z = q - x
func (f *PrimeField) Neg(x *Element) *Element {
	z := Zero()
	f.NegAssign(x, z)
	return z
}

func (f *PrimeField) NegAssign(x, z *Element) {
	z[0] = f.r.Modulus - x[0]
}

func (f *PrimeField) Select(c int, x0 *Element, x1 *Element) *Element {
	cC := uint64((int64(c) | -int64(c)) >> 63) // "canonicized" into: 0 if c=0, -1 otherwise
	z := Zero()
	z[0] = x0[0] ^ cC&(x0[0]^x1[0])
	return z
}

func (f *PrimeField) generateNTTConstants() (err error) {
	if f.r.N == 0 || f.r.Modulus == 0 {
		return fmt.Errorf("invalid t parameters (missing)")
	}

	Modulus := f.r.Modulus
	NthRoot := f.r.NthRoot

	// Checks if each qi is prime and equal to 1 mod NthRoot
	if !ring.IsPrime(Modulus) {
		return fmt.Errorf("invalid modulus: %d is not prime)", Modulus)
	}

	if Modulus&(NthRoot-1) != 1 {
		return fmt.Errorf("invalid modulus: %d != 1 mod NthRoot)", Modulus)
	}

	// It is possible to manually set the primitive root along with the factors of q-1.
	// This is notably useful when marshalling the SubRing, to avoid re-factoring q-1.
	// If both are set, then checks that that the root is indeed primitive.
	// Else, factorize q-1 and finds a primitive root.
	if f.r.PrimitiveRoot != 0 && f.r.Factors != nil {
		if err = ring.CheckPrimitiveRoot(f.r.PrimitiveRoot, f.r.Modulus, f.r.Factors); err != nil {
			return
		}
	} else {
		if f.r.PrimitiveRoot, f.r.Factors, err = ring.PrimitiveRoot(Modulus, f.r.Factors); err != nil {
			return
		}
	}

	logNthRoot := int(bits.Len64(NthRoot>>1) - 1)

	// 1.1 Computes N^(-1) mod Q in Montgomery form
	f.r.NInv = ring.MForm(ring.ModExp(NthRoot>>1, Modulus-2, Modulus), Modulus, f.r.BRedConstant)

	// 1.2 Computes Psi and PsiInv in Montgomery form

	// Computes Psi and PsiInv in Montgomery form
	PsiMont := ring.MForm(ring.ModExp(f.r.PrimitiveRoot, (Modulus-1)/NthRoot, Modulus), Modulus, f.r.BRedConstant)
	PsiInvMont := ring.MForm(ring.ModExp(f.r.PrimitiveRoot, Modulus-((Modulus-1)/NthRoot)-1, Modulus), Modulus, f.r.BRedConstant)

	f.r.RootsForward = make([]uint64, NthRoot>>1)
	f.r.RootsBackward = make([]uint64, NthRoot>>1)

	f.r.RootsForward[0] = ring.MForm(1, Modulus, f.r.BRedConstant)
	f.r.RootsBackward[0] = ring.MForm(1, Modulus, f.r.BRedConstant)

	// Computes nttPsi[j] = nttPsi[j-1]*Psi and RootsBackward[j] = RootsBackward[j-1]*PsiInv
	for j := uint64(1); j < NthRoot>>1; j++ {

		indexReversePrev := utils.BitReverse64(j-1, logNthRoot)
		indexReverseNext := utils.BitReverse64(j, logNthRoot)

		f.r.RootsForward[indexReverseNext] = ring.MRed(f.r.RootsForward[indexReversePrev], PsiMont, Modulus, f.r.MRedConstant)
		f.r.RootsBackward[indexReverseNext] = ring.MRed(f.r.RootsBackward[indexReversePrev], PsiInvMont, Modulus, f.r.MRedConstant)
	}

	return
}
