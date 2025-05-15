package core

type DensePoly struct {
	Coefficients []*Element
}

func NewDensePoly(coefficients []*Element) *DensePoly {
	return &DensePoly{
		Coefficients: coefficients,
	}
}

func NewDensePolyFromMatrix(matrix [][]*Element) *DensePoly {
	coefficients := flattenRowMajor(matrix)
	return &DensePoly{
		Coefficients: coefficients,
	}
}

// Evaluate computes the value of the polynomial at the given point using Horner's method
func (p *DensePoly) Evaluate(field *PrimeField, point *Element) *Element {
	result := Zero()

	for i := len(p.Coefficients) - 1; i >= 0; i-- {
		field.MulAssign(result, point, result)
		field.AddAssign(result, p.Coefficients[i], result)
	}

	return result
}

func flattenRowMajor(slices [][]*Element) []*Element {
	totalLen := 0
	for _, slice := range slices {
		totalLen += len(slice)
	}

	result := make([]*Element, 0, totalLen)

	for _, slice := range slices {
		result = append(result, slice...)
	}

	return result
}
