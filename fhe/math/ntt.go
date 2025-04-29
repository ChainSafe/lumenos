package math

func NTT(values []*Element, size int, field *PrimeField) []*Element {
	nttInner(values, size, field)
	return values
}

// nttInner performs NTT on plain uint64 values (non-FHE version for testing)
func nttInner(v []*Element, size int, field *PrimeField) {
	switch size {
	case 0, 1:
		return
	case 2:
		for i := 0; i < len(v); i += 2 {
			v[i], v[i+1] = field.Add(v[i], v[i+1]), field.Sub(v[i], v[i+1])
		}
	case 4:
		for i := 0; i < len(v); i += 4 {
			// (v[0], v[2]) = (v[0] + v[2], v[0] - v[2])
			v[i], v[i+2] = field.Add(v[i], v[i+2]), field.Sub(v[i], v[i+2])

			// (v[1], v[3]) = (v[1] + v[3], v[1] - v[3])
			v[i+1], v[i+3] = field.Add(v[i+1], v[i+3]), field.Sub(v[i+1], v[i+3])

			v[i+3] = field.Mul(v[i+3], field.RootForward(4))

			// (v[0], v[1]) = (v[0] + v[1], v[0] - v[1])
			v[i], v[i+1] = field.Add(v[i], v[i+1]), field.Sub(v[i], v[i+1])

			// (v[2], v[3]) = (v[2] + v[3], v[2] - v[3])
			v[i+2], v[i+3] = field.Add(v[i+2], v[i+3]), field.Sub(v[i+2], v[i+3])

			// (v[1], v[2]) = (v[2], v[1])
			v[i+1], v[i+2] = v[i+2], v[i+1]
		}
	case 8:
		for i := 0; i < len(v); i += 8 {
			// First level butterflies
			v[i], v[i+4] = field.Add(v[i], v[i+4]), field.Sub(v[i], v[i+4])
			v[i+1], v[i+5] = field.Add(v[i+1], v[i+5]), field.Sub(v[i+1], v[i+5])
			v[i+2], v[i+6] = field.Add(v[i+2], v[i+6]), field.Sub(v[i+2], v[i+6])
			v[i+3], v[i+7] = field.Add(v[i+3], v[i+7]), field.Sub(v[i+3], v[i+7])

			// Multiply by roots
			v[i+5] = field.Mul(v[i+5], field.RootForward(8))
			v[i+6] = field.Mul(v[i+6], field.RootForward(4))
			omega8 := field.RootForward(8)
			omega8_3 := field.Mul(omega8, field.Mul(omega8, omega8))
			v[i+7] = field.Mul(v[i+7], omega8_3)

			// Second level butterflies
			v[i], v[i+2] = field.Add(v[i], v[i+2]), field.Sub(v[i], v[i+2])
			v[i+1], v[i+3] = field.Add(v[i+1], v[i+3]), field.Sub(v[i+1], v[i+3])
			v[i+3] = field.Mul(v[i+3], field.RootForward(4))

			// Third level butterflies
			v[i], v[i+1] = field.Add(v[i], v[i+1]), field.Sub(v[i], v[i+1])
			v[i+2], v[i+3] = field.Add(v[i+2], v[i+3]), field.Sub(v[i+2], v[i+3])
			v[i+4], v[i+6] = field.Add(v[i+4], v[i+6]), field.Sub(v[i+4], v[i+6])
			v[i+5], v[i+7] = field.Add(v[i+5], v[i+7]), field.Sub(v[i+5], v[i+7])
			v[i+7] = field.Mul(v[i+7], field.RootForward(4))

			// Fourth level butterflies
			v[i+4], v[i+5] = field.Add(v[i+4], v[i+5]), field.Sub(v[i+4], v[i+5])
			v[i+6], v[i+7] = field.Add(v[i+6], v[i+7]), field.Sub(v[i+6], v[i+7])

			// Final swaps
			v[i+1], v[i+4] = v[i+4], v[i+1]
			v[i+3], v[i+6] = v[i+6], v[i+3]
		}
	default:
		n1 := SqrtFactor(size)
		n2 := size / n1
		step := field.N() / size

		// Process the input slice v in chunks of 'size'
		for chunkStart := 0; chunkStart < len(v); chunkStart += size {
			chunk := v[chunkStart : chunkStart+size]

			_transpose(chunk, n1, n2)

			// Perform n2 NTTs of size n1 (on columns of original matrix)
			// Since transpose places columns into rows, we apply NTTs row-wise now.
			// The size of these NTTs is n1.
			nttInner(chunk, n1, field) // Recursive call on the whole transposed chunk

			_transpose(chunk, n2, n1)

			// Step 4: Apply twiddle factors omega_size^{ij}
			// Skip i=0 and j=0 as the twiddle factor is 1
			for i := 1; i < n1; i++ {
				step = (i * step) % field.N()
				idx := step
				for j := 1; j < n2; j++ {
					idx %= field.N()
					twiddle := field.RootForward(idx) // Fetch root omega_N^{index}

					// Apply twiddle factor to element at (i, j) -> linear index i*n2 + j
					chunk[i*n2+j] = field.Mul(chunk[i*n2+j], twiddle)
					idx += step
				}
			}

			nttInner(chunk, n2, field)
			_transpose(chunk, n1, n2) // Transpose back
		}
	}
}

// _transpose transposes a slice representing a matrix in row-major order.
func _transpose(matrix []*Element, rows, cols int) {
	if len(matrix) != rows*cols {
		panic("matrix size does not match rows*cols")
	}
	if rows == cols {
		for i := 0; i < rows; i++ {
			for j := i + 1; j < cols; j++ {
				matrix[i*cols+j], matrix[j*rows+i] = matrix[j*rows+i], matrix[i*cols+j]
			}
		}
	} else {
		copyMatrix := make([]*Element, len(matrix))
		copy(copyMatrix, matrix)
		for i := 0; i < rows; i++ {
			for j := 0; j < cols; j++ {
				matrix[j*rows+i] = copyMatrix[i*cols+j]
			}
		}
	}
}
