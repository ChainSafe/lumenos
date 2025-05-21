package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"time"

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
	PublicKey          []byte   `json:"public_key"`
	RelinearizationKey []byte   `json:"relinearization_key"`
	RotationKeys       [][]byte `json:"rotation_keys"`
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
	flag.Parse()

	// Create a custom HTTP client with increased timeouts
	client := &http.Client{
		Timeout: 5 * time.Minute, // Increase timeout for large responses
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

	ptField, err := core.NewPrimeField(params.PlaintextModulus(), *cols*2)
	if err != nil {
		panic(err)
	}

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

	reqBody, err := json.Marshal(keysReq)
	if err != nil {
		panic(err)
	}

	resp, err := client.Post(*serverURL+"/keys", "application/json", bytes.NewBuffer(reqBody))
	if err != nil {
		panic(fmt.Sprintf("Failed to send keys: %v", err))
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		panic(fmt.Sprintf("Server returned error status: %d", resp.StatusCode))
	}

	fmt.Println("FHE keys sent to server")

	z := core.NewElement(*point)

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

	fmt.Printf("Received encrypted proof for P(x=%d)=%d\n", *point, value)

	span := core.StartSpan("Decrypt proof", nil, "Decrypting proof...")
	proof, err := encryptedProof.Decrypt(clientBFV, false, span)
	if err != nil {
		panic(fmt.Sprintf("Failed to decrypt proof: %v", err))
	}
	span.EndWithNewline()

	valueElem := core.NewElement(value)

	transcript := core.NewTranscript("demo")
	span = core.StartSpan("Verify proof", nil)
	if err := proof.Verify(z, valueElem, clientBFV, transcript); err != nil {
		panic(fmt.Sprintf("Failed to verify proof: %v", err))
	}
	span.EndWithNewline()
}
