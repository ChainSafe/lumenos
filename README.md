# LUMENOS: Private Proof Delegation with FHE-SNARKs

This project aims to develop and validate Private Proof Delegation via server-side FHE-evaluated SNARKs over encrypted single-client or private shared witness and untrusted public verifiability.

## Documentation
- Analysis ["SNARK-FHE vs FHE-SNARK for Private Proof Delegation"](https://hackmd.io/@timofey/r1FuxwVsJg)
- Proposal ["PPD via FHE-SNARK"](https://hackmd.io/@timofey/rJbH6Ex3yg)

## Requirements

- Linux amd64 / x86-64 system
- avx512 and aes instruction set extensions
- Go 1.23
- gcc g++ make cmake libgmp-dev libmpfr-dev unzip

## Run

### Build

```bash
make init-submodules build
export LD_LIBRARY_PATH=./vdec/c
```

### Test

```bash
go test -v -run TestLigeroPPD github.com/nulltea/lumenos/fhe
```

### Demo

Run server:

```bash
make server
```

Run client
```
make client REMOTE_SERVER_URL=http://<IP>:8080
```

## Benchmarks

- BGV params based on [`GenerateBGVParamsForNTT`](https://github.com/ChainSafe/lumenos/blob/ccaafb29b205f5e8d2c44f11761684303a3d7f2b/fhe/bfv.go#L121-L188) heuristic
  - Target 128bit security
  - Plaintext prime: `144115188075593729` ($2^{57} – 2^{18} + 1$, $57$ bits)
  - LogN `max(12, log2(ROWS))` (see table)
  - LogQ `len([58, 56, 56, ... ])=log2(nttSize)`
  - LogP `[55,55]`
- Number of queries `306` (according to ref. [implementation](https://github.com/reilabs/ProveKit/blob/ea95eb6494da2514c573c73bd0449cd2c3d39526/delegated-spartan/src/pcs/ligero.rs#L33-L34))

### Server

### Server

| **Dimension**                         | 2048x1024 | 4096x2048 | 8192x4096 |
| :------------------------------------ | :-------- | :-------- | :-------- |
| **LogN**                              | 14        | 15        | 15        |
| **Encode eval**                       | 24.67s    | 2m 1.85s  | 4m 45.86s |
| **Commit eval**                       | 3.85s     | 17.57s    | 40.02s    |
| **Inner product eval**                | 34.47s    | 3m 16.28s | 8m 17.11s |
| **Query cols eval**                   | 4.69s     | 12.64s    | 15.76s    |
| **Prove eval total**                  | 39.36s    | 3m 28.99s | 8m 33.06s |
| **$ct[\langle r_i,M_{i,j}\rangle]$**  | 537 MB    | 2.1 GB    | 4.3 GB    |
| **$ct[\hat{M}_{i,j}] i \in \lambda$** | 162 MB    | 324 MB    | 324 MB    |
| **Proof size**                        | 1.2 GB    | 4.6 GB    | 8.9 GB    |
| **Peak RAM (GB)**                     | 23.18 GB  | 84.24 GB  | 156.11 GB |

Hardware: r7i.8xlarge, 32 vCPUs 256GB RAM


### Client

| **Dimension**                                 | 2048x1024 | 4096x2048 | 8192x4096 |
| :-------------------------------------------- | :-------- | :-------- | :-------- |
| **LogN**                                      | 14        | 15        | 15        |
| **Keys**                                      | 277 MB    | 772 MB    | 891 MB    |
| **Encrypted proof size**                      | 1.2 GB    | 4.6 GB    | 8.9 GB    |
| **Decrypt $ct[\hat{M}_{i,j}] i \in \lambda$** | 369.15ms  | 863.68ms  | 21.28s    |
| **Decrypt $ct[\langle r_i,M_{i,j}\rangle]$**  | 2.29s     | 56.01s    | 4m 5.22s  |
| **Decrypt total**                             | 2.66s     | 56.89s    | 4m 26.54s |
| **Batch ciphertexts**                         | 1.06s     | 2.52s     | 2.68s     |
| **PoD prover**                                | 22.97s    | 22.97s    | 23.00s    |
| **Public verifier**                           | 468.07ms  | 994.93ms  | 1.06s     |
| **Ligero local**                              | 4.03s     | 16.37s    | 1m 15.61s |
| **Peak RAM (GB)**                             | 3.87 GB   | 7.20 GB   | 7.16 GB   |

Hardware: m6i.large, 2 vCPUs 8GB RAM

### Experimental

- Same hardware as above.
- Server performs ring switch to LogN: 10 for inner product ciphertexts $ct[\langle r_i,M_{i,j}\rangle]$.
  - Note: correct deployment requires SlotsToCoeff ("unbatching") before ring switch which is not yet implemented for BFV. Verification is skipped because of this.
- PoD prover runs optimized GBFV version [vdec_gbfv.c](https://github.com/ChainSafe/lumenos/blob/main/vdec/c/src/vdec_gbfv.c)
  - Note: Lattigo currently does not support GBFV. So final PoD is partially invalid ([h_our coeff](https://github.com/ChainSafe/lumenos/blob/main/vdec/c/src/vdec_gbfv.c#L915) check fails).

#### Server

### Server

| **Dimension**                         | 2048x1024 | 4096x2048 | 8192x4096 | 16384x4096 |
| :------------------------------------ | :-------- | :-------- | :-------- | :--------- |
| **LogN**                              | 14        | 15        | 15        | 15         |
| **Encode eval**                       | 24.84s    | 2m 1.65s  | 4m 46.92s | 4m 51.69s  |
| **Commit eval**                       | 4.13s     | 18.79s    | 39.44s    | 39.37s     |
| **Inner product eval**                | 37.79s    | 3m 33.09s | 8m 18.92s | 8m 49.02s  |
| **Query cols eval**                   | 4.81s     | 13.04s    | 15.85s    | 15.96s     |
| **Prove eval total**                  | 42.79s    | 3m 46.18s | 8m 34.78s | 9m 5.05s   |
| **$ct[\langle r_i,M_{i,j}\rangle]$**  | 17 MB     | 34 MB     | 68 MB     | 68 MB      |
| **$ct[\hat{M}_{i,j}] i \in \lambda$** | 162 MB    | 324 MB    | 324 MB    | 324 MB     |
| **Proof size**                        | 196 MB    | 393 MB    | 461 MB    | 461 MB     |
| **Peak RAM (GB)**                     | 21.42 GB  | 74.50 GB  | 147.19 GB | 148.57 GB  |

#### Client

### Client

| **Dimension**                                 | 2048x1024 | 4096x2048 | 8192x4096 | 16384x4096 |
| :-------------------------------------------- | :-------- | :-------- | :-------- | :--------- |
| **LogN**                                      | 14        | 15        | 15        | 15         |
| **Keys**                                      | 298 MB    | 827 MB    | 949 MB    | 1.0 GB     |
| **Encrypted proof size**                      | 196 MB    | 393 MB    | 461 MB    | 461 MB     |
| **Decrypt $ct[\hat{M}_{i,j}] i \in \lambda$** | 391.54ms  | 808.20ms  | 827.74ms  | 890.91ms   |
| **Decrypt $ct[\langle r_i,M_{i,j}\rangle]$**  | 73.46ms   | 146.35ms  | 288.97ms  | 289.21ms   |
| **Decrypt total**                             | 465.13ms  | 954.68ms  | 1.12s     | 1.18s      |
| **Batch ciphertexts**                         | 1.11s     | 2.53s     | 2.71s     | 2.69s      |
| **PoD prover**                                | 3.27s     | 3.06s     | 3.06s     | 3.08s      |
| **Public verifier**                           | N/A       | N/A       | N/A       | N/A        |
| **Ligero local**                              | 4.12s     | 17.07s    | 1m 28.03s | 9m 42.95s  |
| **Peak RAM (GB)**                             | 1.88 GB   | 4.79 GB   | 5.76 GB   | 7.09 GB    |

### Run yourself

Run the server:
```bash
./scripts/benchmark_server.sh
```

Run the client:
```bash
REMOTE_SERVER_URL=http://<IP>:8080 ./scripts/benchmark_client.sh
```

Run the client with ring switch and GBFV (experimental):
```bash
RING_SWITCH_LOGN=10 IS_GBFV=true REMOTE_SERVER_URL=http://<IP>:8080 \ 
./scripts/benchmark_client.sh -ringSwitchLogN 10
```
