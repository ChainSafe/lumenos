package math

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/big"
	"math/bits"
	"reflect"
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
type Element [1]uint64

const (
	Limbs = 1  // number of 64 bits words needed to represent a Element
	Bits  = 64 // number of bits needed to represent a Element
	Bytes = 8  // number of bytes needed to represent a Element
)

// Field modulus q
const (
	// Modulus = 144115188075593729
	// Modulus = 288230376150630401
	Modulus = 0x3ee0001
	q       = Modulus
)

const qInvNeg = 64

// NewElement returns a new Element from a uint64 value
//
// it is equivalent to
//
//	var v Element
//	v.SetUint64(...)
func NewElement(v uint64) *Element {
	z := &Element{v}
	return z
}

// SetUint64 sets z to v and returns z
func (z *Element) SetUint64(v uint64) *Element {
	//  sets z LSB to v (non-Montgomery form) and convert z to Montgomery form
	*z = Element{v}
	return z
}

// SetInt64 sets z to v and returns z
func (z *Element) SetInt64(v int64) *Element {

	// absolute value of v
	m := v >> 63
	z.SetUint64(uint64((v ^ m) - m))

	if m != 0 {
		// v is negative
		z.Neg(z)
	}

	return z
}

// Set z = x and returns z
func (z *Element) Set(x *Element) *Element {
	z[0] = x[0]
	return z
}

// SetInterface converts provided interface into Element
// returns an error if provided type is not supported
// supported types:
//
//	Element
//	*Element
//	uint64
//	int
//	string (see SetString for valid formats)
//	*big.Int
//	big.Int
//	[]byte
func (z *Element) SetInterface(i1 interface{}) (*Element, error) {
	if i1 == nil {
		return nil, errors.New("can't set goldilocks.Element with <nil>")
	}

	switch c1 := i1.(type) {
	case Element:
		return z.Set(&c1), nil
	case *Element:
		if c1 == nil {
			return nil, errors.New("can't set goldilocks.Element with <nil>")
		}
		return z.Set(c1), nil
	case uint8:
		return z.SetUint64(uint64(c1)), nil
	case uint16:
		return z.SetUint64(uint64(c1)), nil
	case uint32:
		return z.SetUint64(uint64(c1)), nil
	case uint:
		return z.SetUint64(uint64(c1)), nil
	case uint64:
		return z.SetUint64(c1), nil
	case int8:
		return z.SetInt64(int64(c1)), nil
	case int16:
		return z.SetInt64(int64(c1)), nil
	case int32:
		return z.SetInt64(int64(c1)), nil
	case int64:
		return z.SetInt64(c1), nil
	case int:
		return z.SetInt64(int64(c1)), nil
	// case string:
	// 	return z.SetString(c1)
	// case *big.Int:
	// 	if c1 == nil {
	// 		return nil, errors.New("can't set goldilocks.Element with <nil>")
	// 	}
	// 	return z.SetBigInt(c1), nil
	// case big.Int:
	// 	return z.SetBigInt(&c1), nil
	// case []byte:
	// 	return z.SetBytes(c1), nil
	default:
		return nil, errors.New("can't set goldilocks.Element from type " + reflect.TypeOf(i1).String())
	}
}

func Zero() *Element {
	return &Element{0}
}

// SetZero z = 0
func (z *Element) SetZero() *Element {
	z[0] = 0
	return z
}

// SetOne z = 1
func (z *Element) SetOne() *Element {
	z[0] = 1
	return z
}

// Div z = x*y⁻¹ (mod q)
// func (z *Element) Div(x, y *Element) *Element {
// 	var yInv Element
// 	yInv.Inverse(y)
// 	z.Mul(x, &yInv)
// 	return z
// }

// Equal returns z == x; constant-time
func (z *Element) Equal(x *Element) bool {
	return z.NotEqual(x) == 0
}

// NotEqual returns 0 if and only if z == x; constant-time
func (z *Element) NotEqual(x *Element) uint64 {
	return (z[0] ^ x[0])
}

// IsZero returns z == 0
func (z *Element) IsZero() bool {
	return (z[0]) == 0
}

// IsOne returns z == 1
func (z *Element) IsOne() bool {
	return z[0] == 1
}

// IsUint64 reports whether z can be represented as an uint64.
func (z *Element) IsUint64() bool {
	return true
}

// Uint64 returns the uint64 representation of x. If x cannot be represented in a uint64, the result is undefined.
func (z *Element) Uint64() uint64 {
	return z.Bits()[0]
}

// FitsOnOneWord reports whether z words (except the least significant word) are 0
//
// It is the responsibility of the caller to convert from Montgomery to Regular form if needed.
func (z *Element) FitsOnOneWord() bool {
	return true
}

// Cmp compares (lexicographic order) z and x and returns:
//
//	-1 if z <  x
//	 0 if z == x
//	+1 if z >  x
func (z *Element) Cmp(x *Element) int {
	_z := z.Bits()
	_x := x.Bits()
	if _z[0] > _x[0] {
		return 1
	} else if _z[0] < _x[0] {
		return -1
	}
	return 0
}

// SetRandom sets z to a uniform random value in [0, q).
//
// This might error only if reading from crypto/rand.Reader errors,
// in which case, value of z is undefined.
func (z *Element) SetRandom() (*Element, error) {
	// this code is generated for all modulus
	// and derived from go/src/crypto/rand/util.go

	// l is number of limbs * 8; the number of bytes needed to reconstruct 1 uint64
	const l = 8

	// bitLen is the maximum bit length needed to encode a value < q.
	const bitLen = 64

	// k is the maximum byte length needed to encode a value < q.
	const k = (bitLen + 7) / 8

	// b is the number of bits in the most significant byte of q-1.
	b := uint(bitLen % 8)
	if b == 0 {
		b = 8
	}

	var bytes [l]byte

	for {
		// note that bytes[k:l] is always 0
		if _, err := io.ReadFull(rand.Reader, bytes[:k]); err != nil {
			return nil, err
		}

		// Clear unused bits in in the most significant byte to increase probability
		// that the candidate is < q.
		bytes[k-1] &= uint8(int(1<<b) - 1)
		z[0] = binary.LittleEndian.Uint64(bytes[0:8])

		if !z.smallerThanModulus() {
			continue // ignore the candidate and re-sample
		}

		return z, nil
	}
}

// MustSetRandom sets z to a uniform random value in [0, q).
//
// It panics if reading from crypto/rand.Reader errors.
func (z *Element) MustSetRandom() *Element {
	if _, err := z.SetRandom(); err != nil {
		panic(err)
	}
	return z
}

// smallerThanModulus returns true if z < q
// This is not constant time
func (z *Element) smallerThanModulus() bool {
	return z[0] < q
}

// One returns 1
func One() Element {
	var one Element
	one.SetOne()
	return one
}

// Halve sets z to z / 2 (mod q)
func (z *Element) Halve() {
	var carry uint64

	if z[0]&1 == 1 {
		// z = z + q
		z[0], carry = bits.Add64(z[0], Modulus, 0)

	}
	// z = z >> 1
	z[0] >>= 1

	if carry != 0 {
		// when we added q, the result was larger than our available limbs
		// when we shift right, we need to set the highest bit
		z[0] |= (1 << 63)
	}

}

// Mul z = x * y (mod q)
func (z *Element) Mul(x, y *Element) *Element {
	hi, lo := bits.Mul64(x[0], y[0])
	if lo != 0 {
		hi++ // x[0] * y[0] ≤ 2¹²⁸ - 2⁶⁵ + 1, meaning hi ≤ 2⁶⁴ - 2 so no need to worry about overflow
	}
	m := lo * qInvNeg
	hi2, _ := bits.Mul64(m, q)
	r, carry := bits.Add64(hi2, hi, 0)
	if carry != 0 || r >= q {
		// we need to reduce
		r -= q
	}
	z[0] = r

	return z
}

// Add z = x + y (mod q)
func (z *Element) Add(x, y *Element) *Element {
	var carry uint64
	z[0], carry = bits.Add64(x[0], y[0], 0)
	if carry != 0 || z[0] >= q {
		z[0] -= q
	}
	return z
}

// Double z = x + x (mod q), aka Lsh 1
func (z *Element) Double(x *Element) *Element {
	if x[0]&(1<<63) == (1 << 63) {
		// if highest bit is set, then we have a carry to x + x, we shift and subtract q
		z[0] = (x[0] << 1) - q
	} else {
		// highest bit is not set, but x + x can still be >= q
		z[0] = (x[0] << 1)
		if z[0] >= q {
			z[0] -= q
		}
	}
	return z
}

// Sub z = x - y (mod q)
func (z *Element) Sub(x, y *Element) *Element {
	var b uint64
	z[0], b = bits.Sub64(x[0], y[0], 0)
	if b != 0 {
		z[0] += q
	}
	return z
}

// Neg z = q - x
func (z *Element) Neg(x *Element) *Element {
	if x.IsZero() {
		z.SetZero()
		return z
	}
	z[0] = q - x[0]
	return z
}

// Select is a constant-time conditional move.
// If c=0, z = x0. Else z = x1
func (z *Element) Select(c int, x0 *Element, x1 *Element) *Element {
	cC := uint64((int64(c) | -int64(c)) >> 63) // "canonicized" into: 0 if c=0, -1 otherwise
	z[0] = x0[0] ^ cC&(x0[0]^x1[0])
	return z
}

func butterflyGeneric(a, b *Element) {
	t := *a
	a.Add(a, b)
	b.Sub(&t, b)
}

// BitLen returns the minimum number of bits needed to represent z
// returns 0 if z == 0
func (z *Element) BitLen() int {
	return bits.Len64(z[0])
}

// toBigInt returns z as a big.Int in Montgomery form
func (z *Element) toBigInt(res *big.Int) *big.Int {
	var b [Bytes]byte
	binary.BigEndian.PutUint64(b[0:8], z[0])

	return res.SetBytes(b[:])
}

// Bits provides access to z by returning its value as a little-endian [1]uint64 array.
// Bits is intended to support implementation of missing low-level Element
// functionality outside this package; it should be avoided otherwise.
func (z *Element) Bits() [1]uint64 {
	_z := *z
	// fromMont(&_z)
	return _z
}

// String returns the decimal representation of z as a string.
func (z Element) String() string {
	return fmt.Sprintf("%d", z[0])
}
