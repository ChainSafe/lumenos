# Benchmarks

## 8192x4096 LogN=13

### Server
```
LogN: 13
ModQ chain length 12
FHE Server started on :8080 (rows=8192, cols=4096, logN=13)...
Encrypt matrix (31.275540876s)
Number of queried columns: 309
Commit FHE evaluation...
  Encode (1m5.001533435s)
  Merkle tree built (8.297193579s)
Commit FHE evaluation (1m13.298799683s)

Prove FHE evaluation...
  InnerProduct(Matrix, r) (1m37.560293801s)
  InnerProduct(Matrix, b) (1m37.65799811s)
  Query columns (3.469512947s)
Prove FHE evaluation (1m41.134834264s)

Marshaled MatR: 1.1 GB
Marshaled MatZ: 1.1 GB
Marshaled QueriedCols: 81 MB
Marshal proof (1.086942531s)

Marshaled encrypted proof length: 2.2 GB
Evaluate polynomial (299.21961ms)
```
### Client
```
Starting client for matrix: 8192 x 4096, logN: 13
LogN: 13
ModQ chain length 12
Marshaled keys length: 237 MB
FHE keys sent to server
Requesting proof evaluation...
Received encrypted proof for P(x=1)=125815544481056462 | size: 2.2 GB
Decrypting proof...
  Decrypt queried columns (220.697165ms)
  Decrypt row inner products (4.31953915s)
Decrypt proof (4.540316834s)
Verifiable decrypt...
  Batching decrypted columns (2.029570388s)
  Batching ciphertexts (594.419165ms)
  Witness generation (20.570826ms)
  Proof generation (23.258752405s)
Verifiable decrypt (25.906421s)
Verify proof (392.399256ms)

Ligero local generation...
  Ligero commit
    Encode (46.422465339s)
    Merkle tree (16.230915822s)
  Ligero prove
    Compute inner products R (7.004561034s)
    Compute inner products B (3.941450901s)
    Query columns (777.176µs)
  Ligero prove (10.946880729s)
Ligero local generation (1m13.600635957s)
```

# 16384x4096 LogN=14

### Server
```
LogN: 14
ModQ chain length 12
FHE Server started on :8080 (rows=16384, cols=4096, logN=14)...
Encrypt matrix (1m5.000770649s)
Number of queried columns: 309
Commit FHE evaluation...
  Encode (2m17.005502431s)
  Merkle tree built (17.019858434s)
Commit FHE evaluation (2m34.025428912s)

Prove FHE evaluation...
  InnerProduct(Matrix, b) (3m40.437926644s)
  InnerProduct(Matrix, r) (3m40.543153258s)
  Query columns (7.410433171s)
Prove FHE evaluation (3m47.967564418s)

Marshaled MatR: 2.1 GB
Marshaled MatZ: 2.1 GB
Marshaled QueriedCols: 162 MB
Marshal proof (2.134706422s)

Marshaled encrypted proof length: 4.5 GB
Evaluate polynomial (600.172623ms)
```

### Client
```
Starting client for matrix: 16384 x 4096, logN: 14
LogN: 14
ModQ chain length 12
Marshaled keys length: 504 MB
FHE keys sent to server
Requesting proof evaluation...
signal: killed
make: *** [Makefile:45: client] Error 1
```
> Out of memory

# Experimental

## 8192x4096 LogN=13 RingSwitchLogN=10 vDec/isGBFV=true

### Server
```
LogN: 13
ModQ chain length 12
FHE Server started on :8080 (rows=8192, cols=4096, logN=13)...
Using ring switch to LogN: 10
Encrypt matrix (31.26719848s)
Number of queried columns: 309
Commit FHE evaluation...
  Encode (1m4.707140034s)
  Merkle tree built (8.265630902s)
Commit FHE evaluation (1m12.972849678s)

Prove FHE evaluation...
  InnerProduct(Matrix, b) (1m38.042510113s)
  InnerProduct(Matrix, r) (1m38.086000902s)
  Query columns (3.468494047s)
Prove FHE evaluation (1m41.561695401s)

Marshaled MatR: 68 MB
Marshaled MatZ: 68 MB
Marshaled QueriedCols: 81 MB
Marshal proof (165.580175ms)

Marshaled encrypted proof length: 218 MB
Evaluate polynomial (304.186295ms)
```
### Client
```
Starting client for matrix: 8192 x 4096, logN: 13
LogN: 13
ModQ chain length 12
Request to use ring switch to LogN: 10
Marshaled keys length: 252 MB
FHE keys sent to server
Requesting proof evaluation...
Received encrypted proof for P(x=1)=125815544481056462 | size: 218 MB
Decrypting proof...
  Decrypt queried columns (221.550466ms)
  Decrypt row inner products (285.817666ms)
Decrypt proof (507.456169ms)

Verifiable decrypt...
  Batching decrypted columns (1.994623308s)
  Batching ciphertexts (594.320484ms)
  Witness generation (20.872332ms)
    zv bound verification result: 1
    h_our coeff verification result: 0, 0
    quad_many verification result: 1
  Proof generation (3.231473781s)
Verifiable decrypt (5.881487691s)
Ring switch is unstable, proof verification will fail

Ligero local generation...
  Ligero commit
    Encode (45.787574124s)
    Merkle tree (18.107926521s)
  Ligero prove
    Compute inner products R (8.0539351s)
    Compute inner products B (5.434796674s)
    Query columns (753.492µs)
  Ligero prove (13.489581001s)
Ligero local generation (1m17.385234048s)
```

## 16384x4096 LogN=14 RingSwitchLogN=13 vDec/isGBFV=true

### Server
```
LogN: 14
ModQ chain length 12
FHE Server started on :8080 (rows=16384, cols=4096, logN=14)...
Using ring switch to LogN: 10
Encrypt matrix (1m4.984834876s)
Number of queried columns: 309
Commit FHE evaluation...
  Encode (2m17.222694339s)
  Merkle tree built (17.088947538s)
Commit FHE evaluation (2m34.311708067s)

Prove FHE evaluation...
  InnerProduct(Matrix, b) (3m42.498348232s)
  InnerProduct(Matrix, r) (3m42.505175573s)
  Query columns (7.372823162s)
Prove FHE evaluation (3m49.892091344s)

Marshaled MatR: 68 MB
Marshaled MatZ: 68 MB
Marshaled QueriedCols: 162 MB
Marshal proof (221.651782ms)

Marshaled encrypted proof length: 299 MB
Evaluate polynomial (623.316898ms)
```

### Client
```
Starting client for matrix: 16384 x 4096, logN: 14
LogN: 14
ModQ chain length 12
Request to use ring switch to LogN: 10
Marshaled keys length: 533 MB
FHE keys sent to server
Requesting proof evaluation...
Received encrypted proof for P(x=1)=5538402014578059 | size: 299 MB
Decrypting proof...
  Decrypt queried columns (478.332884ms)
  Decrypt row inner products (289.583279ms)
Decrypt proof (768.008005ms)

Verifiable decrypt...
  Batching decrypted columns (3.984807997s)
  Batching ciphertexts (1.25193319s)
  Witness generation (41.302924ms)
```
