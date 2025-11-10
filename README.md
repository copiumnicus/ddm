# ddm

```bash
go install github.com/consensys/gnark/cmd/gnark@v0.14.0
```

```text
./gnarking/circuit/settlement.go
N (number of micropayments in zk batch)

=== Economics report (N = 4, cores = 12) ===
Prove time: 110.268958ms, cores: 12 → CPU-seconds: 1.32
CPU price: $0.0500 / core-hour → cost per proof: $0.000018
Batch value (min tx $0.0050): $0.0200
Proof cost / batch value: 0.09%
Throughput at full load: $652.95 /h, $15670.77 /day, $5719833 /year

=== Economics report (N = 8, cores = 12) ===
Prove time: 217.833541ms, cores: 12 → CPU-seconds: 2.61
CPU price: $0.0500 / core-hour → cost per proof: $0.000036
Batch value (min tx $0.0050): $0.0400
Proof cost / batch value: 0.09%
Throughput at full load: $661.06 /h, $15865.33 /day, $5790844 /year

=== Economics report (N = 16, cores = 12) ===
Prove time: 414.81275ms, cores: 12 → CPU-seconds: 4.98
CPU price: $0.0500 / core-hour → cost per proof: $0.000069
Batch value (min tx $0.0050): $0.0800
Proof cost / batch value: 0.09%
Throughput at full load: $694.29 /h, $16662.94 /day, $6081973 /year

=== Economics report (N = 32, cores = 12) ===
Prove time: 745.3405ms, cores: 12 → CPU-seconds: 8.94
CPU price: $0.0500 / core-hour → cost per proof: $0.000124
Batch value (min tx $0.0050): $0.1600
Proof cost / batch value: 0.08%
Throughput at full load: $772.80 /h, $18547.23 /day, $6769738 /year

=== Economics report (N = 64, cores = 12) ===
Prove time: 1.512657167s, cores: 12 → CPU-seconds: 18.15
CPU price: $0.0500 / core-hour → cost per proof: $0.000252
Batch value (min tx $0.0050): $0.3200
Proof cost / batch value: 0.08%
Throughput at full load: $761.57 /h, $18277.77 /day, $6671386 /year

=== Economics report (N = 128, cores = 12) ===
Prove time: 2.827092042s, cores: 12 → CPU-seconds: 33.93
CPU price: $0.0500 / core-hour → cost per proof: $0.000471
Batch value (min tx $0.0050): $0.6400
Proof cost / batch value: 0.07%
Throughput at full load: $814.97 /h, $19559.32 /day, $7139152 /year

=== Economics report (N = 256, cores = 12) ===
Prove time: 5.623874666s, cores: 12 → CPU-seconds: 67.49
CPU price: $0.0500 / core-hour → cost per proof: $0.000937
Batch value (min tx $0.0050): $1.2800
Proof cost / batch value: 0.07%
Throughput at full load: $819.36 /h, $19664.73 /day, $7177628 /year

Finally 512 (pushing limits for small vms):

Proving key size (N = 512) (serialized): 951.99 MB (998234331 bytes)
=== Compression report (N = 512) ===
Field element size: 32 bytes (BN254 scalar field)
Per-tx naive payload (Recipient, Size, Nonce, ChainID, Signature):
  preimage fields: 4 × 32 B = 128 B
  signature: 96 B
  → total per tx: 224 bytes
Total naive calldata for 512 txs: 114688 bytes
Groth16 proof size: 164 bytes
Calldata/proof ratio: 699.32x

=== Economics report (N = 512, cores = 12) ===
Prove time: 11.254604542s, cores: 12 → CPU-seconds: 135.06
CPU price: $0.0500 / core-hour → cost per proof: $0.001876
Batch value (min tx $0.0050): $2.5600
Proof cost / batch value: 0.07%
Throughput at full load: $818.86 /h, $19652.76 /day, $7173256 /year
```