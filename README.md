# LUMENOS: Private Proof Delegation with FHE-SNARKs

This project aims to develop and validate Private Proof Delegation via server-side FHE-evaluated SNARKs over encrypted single-client or private shared witness and untrusted public verifiability.

## Requirements

- Linux amd64 / x86-64 system
- avx512 and aes instruction set extensions
- kernel version >= 4.18
- Go 1.23
- gcc compiler >= 13.2
- make >= 4.2, cmake >= 3.26

## Run

### Build

```bash
make build
export LD_LIBRARY_PATH=./vdec/c
```

### Test

```bash
go test -v -run TestLigeroE2E github.com/nulltea/lumenos/fhe
```

## Documentation
- Analysis ["SNARK-FHE vs FHE-SNARK for Private Proof Delegation"](https://hackmd.io/@timofey/r1FuxwVsJg)
- Proposal ["PPD via FHE-SNARK"](https://hackmd.io/@timofey/rJbH6Ex3yg)
