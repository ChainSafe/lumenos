package core

type DensePoly struct {
	Coefficients []*Element
}

func NewDensePoly(coefficients []*Element) *DensePoly {
	return &DensePoly{
		Coefficients: coefficients,
	}
}

// Evaluate computes the value of the polynomial at the given point using Horner's method
func (p *DensePoly) Evaluate(field *PrimeField, point *Element) *Element {
	// Start with zero
	result := Zero()

	// Iterate through coefficients in reverse order (Horner's method)
	for i := len(p.Coefficients) - 1; i >= 0; i-- {
		// result = result * point + coefficient
		field.MulAssign(result, point, result)
		field.AddAssign(result, p.Coefficients[i], result)
	}

	return result
}
