package core

import (
	"encoding/binary"
	"errors"
	"fmt"
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
	ElementLimbs = 1  // number of 64 bits words needed to represent a Element
	ElementBits  = 64 // number of bits needed to represent a Element
	ElementBytes = 8  // number of bytes needed to represent a Element
)

// Field modulus q
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
	return z.Limbs()[0]
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
	_z := z.Limbs()
	_x := x.Limbs()
	if _z[0] > _x[0] {
		return 1
	} else if _z[0] < _x[0] {
		return -1
	}
	return 0
}

// BitLen returns the minimum number of bits needed to represent z
// returns 0 if z == 0
func (z *Element) BitLen() int {
	return bits.Len64(z[0])
}

// toBigInt returns z as a big.Int in Montgomery form
func (z *Element) toBigInt(res *big.Int) *big.Int {
	var b [ElementBytes]byte
	binary.BigEndian.PutUint64(b[0:8], z[0])

	return res.SetBytes(b[:])
}

func (z *Element) Limbs() [1]uint64 {
	_z := *z
	return _z
}

func (z *Element) ToBytes() (res []byte) {
	binary.LittleEndian.PutUint64(res, z[0])
	return
}

// String returns the decimal representation of z as a string.
func (z Element) String() string {
	return fmt.Sprintf("%d", z[0])
}
