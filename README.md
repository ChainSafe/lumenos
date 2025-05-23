# LUMENOS: Private Proof Delegation with FHE-SNARKs

This project aims to develop and validate Private Proof Delegation via server-side FHE-evaluated SNARKs over encrypted single-client or private shared witness and untrusted public verifiability.

## Requirements

- Linux amd64 / x86-64 system
- avx512 and aes instruction set extensions
- Go 1.23
- gcc g++ make cmake libgmp-dev libmpfr-dev unzip

## Run

### Build

```bash
git submodule update --init --recursive
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
