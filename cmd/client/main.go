package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"runtime"
	"runtime/debug"

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
	serverURL := flag.String("server", "http://localhost:8080", "URL of the FHE server")
	point := flag.Uint64("point", 1, "Point value for proof generation")
	rows := flag.Int("rows", 2048, "Number of rows in the matrix")
	cols := flag.Int("cols", 1024, "Number of columns in the matrix")
	logN := flag.Int("logN", 13, "LogN")
	ringSwitchLogN := flag.Int("ringSwitchLogN", -1, "Ring switch logN (optional)")
	vdec := flag.Bool("vdec", false, "Use vdec")
	flag.Parse()

	fmt.Printf("Starting client for matrix: %d x %d, logN: %d\n", *rows, *cols, *logN)

	z := core.NewElement(*point)

	ptField, err := core.NewPrimeField(Modulus, *cols*2)
	if err != nil {
		panic(err)
	}

	// Create a custom HTTP client with increased timeouts
	client := &http.Client{
		Timeout: 0,
	}

	paramsLiteral, err := fhe.GenerateBGVParamsForNTT(*cols, *logN, Modulus)
	if err != nil {
		panic(err)
	}

	params, err := bgv.NewParametersFromLiteral(paramsLiteral)
	if err != nil {
		panic(err)
	}

	// Generate keys
	kgen := rlwe.NewKeyGenerator(params)
	sk, pk := kgen.GenKeyPairNew()

	// Generate relinearization key
	rlk := kgen.GenRelinearizationKeyNew(sk)

	rotKeys := kgen.GenGaloisKeysNew(params.GaloisElementsForInnerSum(1, *rows), sk)

	// Initialize the client
	clientBFV := fhe.NewClientBFV(&ptField, params, sk)

	// Send keys to server
	pkBytes, err := pk.MarshalBinary()
	if err != nil {
		panic(err)
	}

	rlkBytes, err := rlk.MarshalBinary()
	if err != nil {
		panic(err)
	}

	rotKeysBytes := make([][]byte, len(rotKeys))
	for i, key := range rotKeys {
		rotKeysBytes[i], err = key.MarshalBinary()
		if err != nil {
			panic(err)
		}
	}

	keysReq := KeysRequest{
		PublicKey:          pkBytes,
		RelinearizationKey: rlkBytes,
		RotationKeys:       rotKeysBytes,
	}

	// Check if ringSwitchLogN was set
	if *ringSwitchLogN != -1 {
		rs, err := fhe.NewRingSwitchClient(clientBFV, *ringSwitchLogN)
		if err != nil {
			panic(err)
		}

		clientBFV.SetRingSwitch(rs)

		fmt.Printf("Request to use ring switch to LogN: %d\n", *ringSwitchLogN)

		ringSwitchEvkBytes, err := rs.RingSwitchEvk.MarshalBinary()
		if err != nil {
			panic(err)
		}

		keysReq.RingSwitchEvk = ringSwitchEvkBytes
		keysReq.ParamsLit = &rs.ParamsLit
	}

	reqBody, err := json.Marshal(keysReq)
	if err != nil {
		panic(err)
	}

	fmt.Println("Marshaled keys length:", humanize.Bytes(uint64(len(reqBody))))

	resp, err := client.Post(*serverURL+"/keys", "application/json", bytes.NewBuffer(reqBody))
	if err != nil {
		panic(fmt.Sprintf("Failed to send keys: %v", err))
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		panic(fmt.Sprintf("Server returned error status: %d", resp.StatusCode))
	}

	fmt.Println("FHE keys sent to server")

	// sk = nil
	pk = nil
	rlk = nil
	rotKeys = nil
	clear(reqBody)
	reqBody = nil
	runtime.GC()

	fmt.Println("Requesting proof evaluation...")
	resp, err = client.Get(fmt.Sprintf("%s/prove?point=%d", *serverURL, *point))
	if err != nil {
		panic(fmt.Sprintf("Failed to call prove endpoint: %v", err))
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		panic(fmt.Sprintf("Server returned error status: %d", resp.StatusCode))
	}

	// Read value (first 8 bytes)
	var value uint64
	if err := binary.Read(resp.Body, binary.LittleEndian, &value); err != nil {
		panic(fmt.Sprintf("Failed to read value: %v", err))
	}

	// Read the rest as payload
	payload, err := io.ReadAll(resp.Body)
	if err != nil {
		panic(fmt.Sprintf("Failed to read payload: %v", err))
	}

	encryptedProof := fhe.EncryptedProof{}
	if err := encryptedProof.UnmarshalBinary(payload, &params); err != nil {
		panic(fmt.Sprintf("Failed to unmarshal encrypted proof: %v", err))
	}

	fmt.Printf("Received encrypted proof for P(x=%d)=%d | size: %s\n", *point, value, humanize.Bytes(uint64(len(payload))))

	clear(payload)
	payload = nil
	runtime.GC()

	span := core.StartSpan("Decrypt proof", nil, "Decrypting proof...")
	proof, err := encryptedProof.Decrypt(clientBFV, span)
	if err != nil {
		panic(fmt.Sprintf("Failed to decrypt proof: %v", err))
	}

	encryptedProof = fhe.EncryptedProof{}
	runtime.GC()
	debug.FreeOSMemory()
	runtime.GC()

	if *vdec {
		err = proof.ProveDecrypt(clientBFV, span)
		if err != nil {
			panic(fmt.Sprintf("Failed to prove decrypt: %v", err))
		}
	}

	if clientBFV.RingSwitch() != nil {
		fmt.Println("Ring switch is unstable, proof verification will fail")
		fmt.Println()
	} else {
		valueElem := core.NewElement(value)
		transcript := core.NewTranscript("demo")
		span = core.StartSpan("Verify proof", nil)
		if err := proof.Verify(z, valueElem, clientBFV.Field(), transcript); err != nil {
			panic(fmt.Sprintf("Failed to verify proof: %v", err))
		}
		span.EndWithNewline()
	}

	proof = nil
	encryptedProof = fhe.EncryptedProof{}
	clientBFV = nil
	runtime.GC()
	debug.FreeOSMemory()
	runtime.GC()

	matrix, _, err := core.RandomMatrixRowMajor(*rows, *cols, Modulus, func(u []uint64) *rlwe.Plaintext {
		return nil
	})
	if err != nil {
		panic(err)
	}

	ligero, err := fhe.NewLigeroCommitter(128, *rows, *cols, RhoInv)
	if err != nil {
		panic(err)
	}
	localSpan := core.StartSpan("Ligero local generation", nil, "Ligero local generation...")
	referenceTranscript := core.NewTranscript("test")
	_, err = ligero.LigeroProveReference(matrix, z, &ptField, referenceTranscript, localSpan)
	if err != nil {
		panic(err)
	}
	localSpan.End()
}
