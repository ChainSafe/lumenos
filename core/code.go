package core

func Encode(row []*Element, rhoInv int, field *PrimeField) []*Element {
	if len(row) == 0 {
		panic("row is empty")
	}

	cols := len(row)
	encodedCols := cols * rhoInv

	encodedRow := make([]*Element, encodedCols)
	for j := range encodedRow {
		encodedRow[j] = NewElement(0)
	}

	copy(encodedRow, row)

	for j := cols; j < encodedCols; j++ {
		encodedRow[j].SetZero()
	}

	return NTT(encodedRow, encodedCols, field)
}
