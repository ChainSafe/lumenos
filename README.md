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
make init-submodules build
export LD_LIBRARY_PATH=./vdec/c
```

### Test

```bash
go test -v -run TestLigeroE2E github.com/nulltea/lumenos/fhe
```

## Benchmarks

Plaintext prime: `144115188075593729` ($2^{57} – 2^{18} + 1$, $57$ bits)

### Server

| Dimension        | LogN | $\gamma$ queries | Encode eval    | Commit eval   | Inner product eval | Query cols eval | Prove eval total |  $ct[\langle r_i,M_{i,j}\rangle]$ | $ct[\hat{M}_{i,j}]_{j \in \gamma}$ | Proof size | Peak RAM (GB) |
| :--------------- | :--- | :------ | :-------- | :------- | :------------ | :--------- | :---------- | :-------- | :----------- | :--------- | :------------ |
| 2048 x 1024    | 12   | 309     | 5.17s     | 1.03s    | 8.51s         | 1.10s      | 9.61s       | 135 MB    | 41 MB        | 310 MB     | 5.74          |
| 4096 x 2048    | 12   | 309     | 12.63s    | 2.04s    | 22.74s        | 1.42s      | 24.17s      | 269 MB    | 41 MB        | 579 MB     | 10.79         | 
| 8192 x 4096    | 13   | 309     | 1m 6.78s  | 9.17s    | 1m 49.60s     | 3.55s      | 1m 53.16s   | 1.1 GB    | 81 MB        | 2.2 GB     | 41.23         |
| 16384 x 4096   | 14   | 309     | 2m 22.73s | 18.79s   | 4m 7.48s      | 7.63s      | 4m 15.12s   | 2.1 GB    | 162 MB       | 4.5 GB     | 79.43         |

Hardware: m7i.8xlarge, 32 vCPUs 128GB RAM

### Client


| Dimension        | LogN | Keys   | Encrypted proof size | $\text{Dec}(ct[\hat{M}_{i,j}]_{j \in \gamma})$ | $\text{Dec}(ct[\langle r_i,M_{i,j}\rangle])$ | Batch ciphertexts | PoD prover | Public verifier | Ligero local | Peak RAM (GB) |
| :--------------- | :--- | :----- | :------------------- | :----------------- | :--------------------- | :------------------- | :--------- | :----------- | :----------- | :------------ |
| 2048 x 1024    | 12   | 69 MB  | 310 MB               | 95.85ms            | 531.57ms               | 239.94ms             | 22.96s     | 151.94ms     | 3.89s        | 1.05          |
| 4096 x 2048    | 12   | 103 MB | 579 MB               | 107.73ms           | 1.05s                  | 261.73ms             | 22.82s     | 197.06ms     | 16.81s       | 1.83          |
| 8192 x 4096    | 13   | 237 MB | 2.2 GB               | 220.10ms           | 4.32s                  | 593.67ms             | 22.82s     | 389.39ms     | 1m 20.69s    | 6.34          |
| 16384 x 4096   | 14   | 504 MB | 4.5 GB               | 513.26ms           | 47.53s                 | 1.32s                | 22.70s     | 804.64ms     | 14m 21.94s   | 7.18          |

Hardware: m7i.8xlarge, 2 vCPUs 8GB RAM

### Experimental

- Same hardware as above.
- Server performs ring switch to LogN: 10 for inner product ciphertexts $ct[\langle r_i,M_{i,j}\rangle]$.
  - Note: correct deployment requires SlotsToCoeff ("unbatching") before ring switch which is not yet implemented for BFV. Verification is skipped because of this.
- PoD prover runs optimized GBFV version [vdec_gbfv.c](https://github.com/ChainSafe/lumenos/blob/main/vdec/c/src/vdec_gbfv.c)
  - Note: Lattigo currently does not support GBFV. So final PoD is partially invalid ([h_our coeff](https://github.com/ChainSafe/lumenos/blob/main/vdec/c/src/vdec_gbfv.c#L915) check fails).

#### Server

| Dimension    | LogN   | $\gamma$ queries | Encode eval   | Commit eval   | Inner product eval | Query cols eval | Prove eval total | $ct[\langle r_i,M_{i,j}\rangle]$ | $ct[\hat{M}_{i,j}]_{j \in \gamma}$ | Proof size | Peak RAM (GB) |
|--------------|--------|------------------|---------------|---------------|--------------------|-----------------|------------------|-----------------------------------|------------------------------------------|------------|---------------|
| 2048x1024    | 12     | 309              | 5.16s         | 1.03s         | 8.51s              | 1.10s           | 9.67s            | 17 MB                             | 41 MB                                    | 75 MB      | 5.40 GB       |
| 4096x2048    | 12     | 309              | 12.72s        | 2.04s         | 22.65s             | 1.41s           | 24.32s           | 34 MB                             | 41 MB                                    | 109 MB     | 10.78 GB      |
| 8192x4096    | 13     | 309              | 1m 6.39s      | 9.18s         | 1m 50.17s          | 3.55s           | 1m 53.73s        | 68 MB                             | 81 MB                                    | 218 MB     | 41.90 GB      |
| 16384x4096   | 14     | 309              | 2m 23.12s     | 18.80s        | 4m 8.44s           | 7.63s           | 4m 16.12s        | 68 MB                             | 162 MB                                   | 299 MB     | 79.26 GB      |

#### Client

| Dimension    | LogN   | Keys   | Encrypted proof size | $\text{Dec}(ct[\hat{M}_{i,j}]_{j \in \gamma})$ | $\text{Dec}(ct[\langle r_i,M_{i,j}\rangle])$ | Batch ciphertexts | PoD prover | Public verifier | Ligero local   | Peak RAM (GB) |
|--------------|--------|--------|----------------------|-----------------------------------------------|----------------------------------------------|-------------------|------------|-----------------|----------------|---------------|
| 2048x1024    | 12     | 74 MB  | 75 MB                | 98.15ms                                       | 72.35ms                                      | 243.19ms          | 3.21s      | N/A           | 3.99s          | 0.56 GB       |
| 4096x2048    | 12     | 110 MB | 109 MB               | 107.52ms                                      | 146.75ms                                     | 269.33ms          | 3.05s      | N/A           | 16.66s         | 1.40 GB       |
| 8192x4096    | 13     | 252 MB | 218 MB               | 223.39ms                                      | 284.23ms                                     | 595.06ms          | 3.20s      | N/A           | 1m 20.11s      | 5.39 GB       |
| 16384x4096   | 14     | 533 MB | 299 MB               | 483.88ms                                      | 287.14ms                                     | 1.26s             | 3.20s      | N/A           | 10m 15.22s     | 7.05 GB       |

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


## Documentation
- Analysis ["SNARK-FHE vs FHE-SNARK for Private Proof Delegation"](https://hackmd.io/@timofey/r1FuxwVsJg)
- Proposal ["PPD via FHE-SNARK"](https://hackmd.io/@timofey/rJbH6Ex3yg)
