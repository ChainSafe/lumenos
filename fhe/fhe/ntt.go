package fhe

import (
	"github.com/timofey/fhe-experiments/lattigo/core"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
)

// counter for multiplications in NTT
var MultiplicationsCounter int

func NTT(values []*rlwe.Ciphertext, size int, backend *BackendBFV) ([]*rlwe.Ciphertext, error) {
	if err := nttInner(values, size, backend); err != nil {
		return nil, err
	}
	return values, nil
}

// nttInner performs NTT on batched ciphertexts using the BGV evaluator
func nttInner(v []*rlwe.Ciphertext, size int, backend *BackendBFV) error {
	switch size {
	case 0, 1:
		return nil
	case 2:
		for i := 0; i < len(v); i += 2 {
			v0, v1 := v[i].CopyNew(), v[i+1].CopyNew()
			err := backend.Add(v0, v1, v[i])
			if err != nil {
				return err
			}
			err = backend.Sub(v0, v1, v[i+1])
			if err != nil {
				return err
			}
		}
	case 4:
		for i := 0; i < len(v); i += 4 {
			// (v[0], v[2]) = (v[0] + v[2], v[0] - v[2])
			v0, v2 := v[i].CopyNew(), v[i+2].CopyNew()
			err := backend.Add(v0, v2, v[i])
			if err != nil {
				return err
			}
			err = backend.Sub(v0, v2, v[i+2])
			if err != nil {
				return err
			}

			// (v[1], v[3]) = (v[1] + v[3], v[1] - v[3])
			v1, v3 := v[i+1].CopyNew(), v[i+3].CopyNew()
			err = backend.Add(v1, v3, v[i+1])
			if err != nil {
				return err
			}
			err = backend.Sub(v1, v3, v[i+3])
			if err != nil {
				return err
			}

			err = backend.Mul(v[i+3], backend.Field().RootForwardUint64(4), v[i+3])
			if err != nil {
				return err
			}
			MultiplicationsCounter++

			// (v[0], v[1]) = (v[0] + v[1], v[0] - v[1])
			v0, v1 = v[i].CopyNew(), v[i+1].CopyNew()
			err = backend.Add(v0, v1, v[i])
			if err != nil {
				return err
			}
			err = backend.Sub(v0, v1, v[i+1])
			if err != nil {
				return err
			}

			// (v[2], v[3]) = (v[2] + v[3], v[2] - v[3])
			v2, v3 = v[i+2].CopyNew(), v[i+3].CopyNew()
			err = backend.Add(v2, v3, v[i+2])
			if err != nil {
				return err
			}
			err = backend.Sub(v2, v3, v[i+3])
			if err != nil {
				return err
			}

			// (v[1], v[2]) = (v[2], v[1])
			v[i+1], v[i+2] = v[i+2], v[i+1]
		}
	case 8:
		for i := 0; i < len(v); i += 8 {
			// First level butterflies
			v0, v4 := v[i].CopyNew(), v[i+4].CopyNew()
			err := backend.Add(v0, v4, v[i])
			if err != nil {
				return err
			}
			err = backend.Sub(v0, v4, v[i+4])
			if err != nil {
				return err
			}

			v1, v5 := v[i+1].CopyNew(), v[i+5].CopyNew()
			err = backend.Add(v1, v5, v[i+1])
			if err != nil {
				return err
			}
			err = backend.Sub(v1, v5, v[i+5])
			if err != nil {
				return err
			}

			v2, v6 := v[i+2].CopyNew(), v[i+6].CopyNew()
			err = backend.Add(v2, v6, v[i+2])
			if err != nil {
				return err
			}
			err = backend.Sub(v2, v6, v[i+6])
			if err != nil {
				return err
			}

			v3, v7 := v[i+3].CopyNew(), v[i+7].CopyNew()
			err = backend.Add(v3, v7, v[i+3])
			if err != nil {
				return err
			}
			err = backend.Sub(v3, v7, v[i+7])
			if err != nil {
				return err
			}

			// Multiply by roots
			err = backend.Mul(v[i+5], backend.Field().RootForwardUint64(8), v[i+5])
			if err != nil {
				return err
			}
			MultiplicationsCounter++
			err = backend.Mul(v[i+6], backend.Field().RootForwardUint64(4), v[i+6])
			if err != nil {
				return err
			}
			MultiplicationsCounter++
			omega8 := backend.Field().RootForward(8)
			omega8_3 := backend.Field().Mul(omega8, backend.Field().Mul(omega8, omega8))
			err = backend.Mul(v[i+7], omega8_3.Uint64(), v[i+7])
			if err != nil {
				return err
			}
			MultiplicationsCounter++

			// Second level butterflies
			v0, v2 = v[i].CopyNew(), v[i+2].CopyNew()
			err = backend.Add(v0, v2, v[i])
			if err != nil {
				return err
			}
			err = backend.Sub(v0, v2, v[i+2])
			if err != nil {
				return err
			}

			v1, v3 = v[i+1].CopyNew(), v[i+3].CopyNew()
			err = backend.Add(v1, v3, v[i+1])
			if err != nil {
				return err
			}
			err = backend.Sub(v1, v3, v[i+3])
			if err != nil {
				return err
			}

			err = backend.Mul(v[i+3], backend.Field().RootForwardUint64(4), v[i+3])
			if err != nil {
				return err
			}

			// Third level butterflies
			v0, v1 = v[i].CopyNew(), v[i+1].CopyNew()
			err = backend.Add(v0, v1, v[i])
			if err != nil {
				return err
			}
			err = backend.Sub(v0, v1, v[i+1])
			if err != nil {
				return err
			}

			v2, v3 = v[i+2].CopyNew(), v[i+3].CopyNew()
			err = backend.Add(v2, v3, v[i+2])
			if err != nil {
				return err
			}
			err = backend.Sub(v2, v3, v[i+3])
			if err != nil {
				return err
			}

			v4, v6 = v[i+4].CopyNew(), v[i+6].CopyNew()
			err = backend.Add(v4, v6, v[i+4])
			if err != nil {
				return err
			}
			err = backend.Sub(v4, v6, v[i+6])
			if err != nil {
				return err
			}

			v5, v7 = v[i+5].CopyNew(), v[i+7].CopyNew()
			err = backend.Add(v5, v7, v[i+5])
			if err != nil {
				return err
			}
			err = backend.Sub(v5, v7, v[i+7])
			if err != nil {
				return err
			}

			err = backend.Mul(v[i+7], backend.Field().RootForwardUint64(4), v[i+7])
			if err != nil {
				return err
			}

			// Fourth level butterflies
			v4, v5 = v[i+4].CopyNew(), v[i+5].CopyNew()
			err = backend.Add(v4, v5, v[i+4])
			if err != nil {
				return err
			}
			err = backend.Sub(v4, v5, v[i+5])
			if err != nil {
				return err
			}

			v6, v7 = v[i+6].CopyNew(), v[i+7].CopyNew()
			err = backend.Add(v6, v7, v[i+6])
			if err != nil {
				return err
			}
			err = backend.Sub(v6, v7, v[i+7])
			if err != nil {
				return err
			}

			// Final swaps
			v[i+1], v[i+4] = v[i+4], v[i+1]
			v[i+3], v[i+6] = v[i+6], v[i+3]
		}
	default:
		n1 := core.SqrtFactor(size)
		n2 := size / n1
		step := backend.Field().N() / size

		// Process the input slice v in chunks of 'size'
		for chunkStart := 0; chunkStart < len(v); chunkStart += size {
			chunk := v[chunkStart : chunkStart+size]

			core.Transpose(chunk, n1, n2)

			// Perform n2 NTTs of size n1 (on columns of original matrix)
			// Since math.Transpose places columns into rows, we apply NTTs row-wise now.
			// The size of these NTTs is n1.
			nttInner(chunk, n1, backend) // Recursive call on the whole math.Transposed chunk

			core.Transpose(chunk, n2, n1)

			// Step 4: Apply twiddle factors omega_size^{ij}
			// Skip i=0 and j=0 as the twiddle factor is 1
			for i := 1; i < n1; i++ {
				step = (i * step) % backend.Field().N()
				idx := step
				for j := 1; j < n2; j++ {
					idx %= backend.Field().N()

					// Apply twiddle factor to element at (i, j) -> linear index i*n2 + j
					err := backend.Mul(chunk[i*n2+j], backend.Field().RootForwardUint64(idx), chunk[i*n2+j])
					if err != nil {
						return err
					}
					MultiplicationsCounter++
					idx += step
				}
			}

			nttInner(chunk, n2, backend)
			core.Transpose(chunk, n1, n2) // math.Transpose back
		}
	}
	return nil
}
