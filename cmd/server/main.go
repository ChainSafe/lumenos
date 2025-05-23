package main

import (
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"time"

	"github.com/dustin/go-humanize"
	"github.com/nulltea/lumenos/core"
	"github.com/nulltea/lumenos/fhe"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/schemes/bgv"
)

const (
	Modulus = 144115188075593729
	RhoInv  = 2
)

type KeysRequest struct {
	PublicKey          []byte                 `json:"public_key"`
	RelinearizationKey []byte                 `json:"relinearization_key"`
	RotationKeys       [][]byte               `json:"rotation_keys"`
	RingSwitchEvk      []byte                 `json:"ring_switch_evk"`
	ParamsLit          *bgv.ParametersLiteral `json:"params_lit"`
}

type ProveResponse struct {
	EncryptedProof []byte `json:"encrypted_proof"`
	Value          uint64 `json:"value"`
}

func main() {
	port := flag.Int("port", 8080, "Port to listen on")
	rows := flag.Int("rows", 2048, "Number of rows in the matrix")
	cols := flag.Int("cols", 1024, "Number of columns in the matrix")
	logN := flag.Int("logN", 13, "LogN")
	benchMode := flag.Bool("benchMode", false, "Benchmark mode") // stops server after proving
	flag.Parse()

	paramsLiteral, err := fhe.GenerateBGVParamsForNTT(*cols, *logN, Modulus)
	if err != nil {
		panic(err)
	}

	params, err := bgv.NewParametersFromLiteral(paramsLiteral)
	if err != nil {
		panic(err)
	}

	ptField, err := core.NewPrimeField(params.PlaintextModulus(), *cols*2)
	if err != nil {
		panic(err)
	}

	// Initialize the server
	var server *fhe.ServerBFV

	// Create HTTP server
	http.HandleFunc("/keys", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var req KeysRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}

		pk := rlwe.NewPublicKey(params)
		if err := pk.UnmarshalBinary(req.PublicKey); err != nil {
			http.Error(w, "Invalid public key", http.StatusBadRequest)
			return
		}

		rlk := rlwe.NewRelinearizationKey(params)
		if err := rlk.UnmarshalBinary(req.RelinearizationKey); err != nil {
			http.Error(w, "Invalid relinearization key", http.StatusBadRequest)
			return
		}

		rotKeys := make([]*rlwe.GaloisKey, len(req.RotationKeys))
		for i, key := range req.RotationKeys {
			rotKeys[i] = rlwe.NewGaloisKey(params)
			if err := rotKeys[i].UnmarshalBinary(key); err != nil {
				http.Error(w, "Invalid rotation key", http.StatusBadRequest)
				return
			}
		}

		evk := rlwe.NewMemEvaluationKeySet(rlk, rotKeys...)

		server = fhe.NewBackendBFV(&ptField, params, pk, evk)

		if req.ParamsLit != nil {
			fmt.Printf("Using ring switch to LogN: %d\n", req.ParamsLit.LogN)

			ringSwitchEvk := rlwe.NewEvaluationKey(params)
			if err := ringSwitchEvk.UnmarshalBinary(req.RingSwitchEvk); err != nil {
				http.Error(w, "Invalid ring switch evaluation key", http.StatusBadRequest)
				return
			}

			rs, err := fhe.NewRingSwitchServer(ringSwitchEvk, *req.ParamsLit)
			if err != nil {
				http.Error(w, "Failed to create ring switch server", http.StatusInternalServerError)
				return
			}

			server.SetRingSwitchServer(rs)
		}

		w.WriteHeader(http.StatusOK)
	})

	http.HandleFunc("/prove", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		if server == nil {
			http.Error(w, "Server not initialized; call POST /keys first", http.StatusBadRequest)
			return
		}

		pointStr := r.URL.Query().Get("point")
		if pointStr == "" {
			http.Error(w, "Missing required query parameter: point", http.StatusBadRequest)
			return
		}

		point, err := strconv.ParseUint(pointStr, 10, 64)
		if err != nil {
			http.Error(w, "Invalid point value", http.StatusBadRequest)
			return
		}

		z := core.NewElement(point)
		value, payload, err := generateLigeroProofFHE(params, server, z, *rows, *cols)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// Send raw bytes: [8 bytes for value][rest for payload]
		w.Header().Set("Content-Type", "application/octet-stream")

		// Write value as uint64 (8 bytes)
		if err := binary.Write(w, binary.LittleEndian, value); err != nil {
			fmt.Printf("Failed to write value: %v\n", err)
			return
		}

		// Write payload
		if _, err := w.Write(payload); err != nil {
			fmt.Printf("Failed to write payload: %v\n", err)
			return
		}
		w.(http.Flusher).Flush()

		if *benchMode {
			go func() {
				time.Sleep(100 * time.Millisecond)
				fmt.Println("Benchmark completed, exiting...")
				os.Exit(0)
			}()
		}
	})

	fmt.Printf("FHE Server started on :%d (rows=%d, cols=%d, logN=%d)...\n", *port, *rows, *cols, *logN)
	if err := http.ListenAndServe(fmt.Sprintf(":%d", *port), nil); err != nil {
		panic(err)
	}
}

func generateLigeroProofFHE(params bgv.Parameters, server *fhe.ServerBFV, z *core.Element, rows, cols int) (uint64, []byte, error) {
	matrix, batchedCols, err := core.RandomMatrixRowMajor(rows, cols, Modulus, func(u []uint64) *rlwe.Plaintext {
		plaintext := bgv.NewPlaintext(params, params.MaxLevel())
		if err := server.Encode(u, plaintext); err != nil {
			panic(err)
		}
		return plaintext
	})
	if err != nil {
		return 0, nil, err
	}

	span := core.StartSpan("Encrypt matrix", nil)
	ciphertexts := make([]*rlwe.Ciphertext, len(batchedCols))
	for i, plaintext := range batchedCols {
		ciphertext, err := server.EncryptNew(plaintext)
		if err != nil {
			return 0, nil, err
		}
		ciphertexts[i] = ciphertext
	}
	span.End()

	// Clean up batchedCols as it's no longer needed
	batchedCols = nil
	runtime.GC() // Request garbage collection

	ligero, err := fhe.NewLigeroCommitter(128, rows, cols, RhoInv)
	if err != nil {
		return 0, nil, err
	}

	println("Number of queried columns:", ligero.Queries)

	span = core.StartSpan("Commit FHE evaluation", nil, "Commit FHE evaluation...")
	comm, _, err := ligero.Commit(ciphertexts, server, span)
	if err != nil {
		panic(err)
	}
	span.EndWithNewline()

	// Clean up ciphertexts as they're no longer needed
	ciphertexts = nil
	runtime.GC() // Request garbage collection

	transcript := core.NewTranscript("demo")
	span = core.StartSpan("Prove FHE evaluation", nil, "Prove FHE evaluation...")
	encryptedProof, err := comm.Prove(z, server, transcript, span)
	if err != nil {
		panic(err)
	}
	span.EndWithNewline()

	// Clean up comm as it's no longer needed
	comm = nil
	runtime.GC() // Request garbage collection

	span = core.StartSpan("Marshal proof", nil)
	marshaled, err := encryptedProof.MarshalBinary()
	if err != nil {
		return 0, nil, err
	}
	span.EndWithNewline()
	fmt.Printf("Marshaled encrypted proof length: %s\n", humanize.Bytes(uint64(len(marshaled))))

	encryptedProof = nil
	runtime.GC()

	span = core.StartSpan("Evaluate polynomial", nil)
	poly := core.NewDensePolyFromMatrix(matrix)
	value := poly.Evaluate(server.Field(), z)
	span.EndWithNewline()

	// Clean up matrix and poly as they're no longer needed
	matrix = nil
	poly = nil
	runtime.GC()

	return value.Uint64(), marshaled, nil
}
