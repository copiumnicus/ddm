package main

import (
	"crypto/rand"
	"runtime"
	"fmt"
	"math/big"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	bnMimc "github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
	te "github.com/consensys/gnark-crypto/ecc/twistededwards"
	nativeEddsa "github.com/consensys/gnark-crypto/signature/eddsa"

	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"

	"gnarking/circuit"
)

type countingWriter struct {
	n int64
}

func (w *countingWriter) Write(p []byte) (int, error) {
	w.n += int64(len(p))
	return len(p), nil
}

func reportEconomics(N int, proveTime time.Duration) {
	const (
		cpuPricePerHour   = 0.05      // $/core-hour
		minTxUSD          = 0.005     // $ per smallest tx
		hoursPerDay       = 24
		daysPerYear       = 365
	)
	cores := runtime.NumCPU()

	proveSeconds := proveTime.Seconds()
	cpuSeconds := proveSeconds * float64(cores)

	// cost per proof in $
	costPerProof := float64(cores) * cpuPricePerHour * (proveSeconds / 3600.0)

	// value secured per proof
	batchValue := float64(N) * minTxUSD

	// percentage cost vs value
	percentCost := (costPerProof / batchValue) * 100

	// throughput at full blast
	proofsPerHour := 3600.0 / proveSeconds
	usdPerHour := batchValue * proofsPerHour
	usdPerDay := usdPerHour * hoursPerDay
	usdPerYear := usdPerDay * daysPerYear

	fmt.Printf("\n=== Economics report (N = %d, cores = %d) ===\n", N, cores)
	fmt.Printf("Prove time: %s, cores: %d → CPU-seconds: %.2f\n", proveTime, cores, cpuSeconds)
	fmt.Printf("CPU price: $%.4f / core-hour → cost per proof: $%.6f\n", cpuPricePerHour, costPerProof)
	fmt.Printf("Batch value (min tx $%.4f): $%.4f\n", minTxUSD, batchValue)
	fmt.Printf("Proof cost / batch value: %.2f%%\n", percentCost)
	fmt.Printf("Throughput at full load: $%.2f /h, $%.2f /day, $%.0f /year\n",
		usdPerHour, usdPerDay, usdPerYear)
}

// proofBytes: serialized Groth16 proof size (from proof.WriteTo)
func reportCompression(proofBytes int64) {
	feBytes := len(ecc.BN254.ScalarField().Bytes()) // 32 bytes on BN254

	sigBytes := 3 * feBytes         // R.X, R.Y, S
	preimageFields := 4             // Recipient, Size, Nonce, ChainID
	tuplePerTxBytes := preimageFields*feBytes + sigBytes

	totalTupleBytes := int64(circuit.N) * int64(tuplePerTxBytes)
	ratio := float64(totalTupleBytes) / float64(proofBytes)

	fmt.Printf("\n=== Compression report (N = %d) ===\n", circuit.N)
	fmt.Printf("Field element size: %d bytes (BN254 scalar field)\n", feBytes)
	fmt.Printf("Per-tx naive payload (Recipient, Size, Nonce, ChainID, Signature):\n")
	fmt.Printf("  preimage fields: %d × %d B = %d B\n", preimageFields, feBytes, preimageFields*feBytes)
	fmt.Printf("  signature: %d B\n", sigBytes)
	fmt.Printf("  → total per tx: %d bytes\n", tuplePerTxBytes)
	fmt.Printf("Total naive calldata for %d txs: %d bytes\n", circuit.N, totalTupleBytes)
	fmt.Printf("Groth16 proof size: %d bytes\n", proofBytes)
	fmt.Printf("Calldata/proof ratio: %.2fx\n", ratio)
}


func main() {
	// 1) Compile the SettlementCircuit
	var c circuit.SettlementCircuit
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &c)
	if err != nil {
		panic(err)
	}

	// 2) Groth16 setup
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		panic(err)
	}
	cw := &countingWriter{}
	if _, err := pk.WriteTo(cw); err != nil {
		panic(err)
	}
	fmt.Printf("Proving key size (N = %d) (serialized): %.2f MB (%d bytes)\n", circuit.N, float64(cw.n)/1024/1024, cw.n)

	// 3) EdDSA keypair on BN254 twisted Edwards
	priv, err := nativeEddsa.New(te.BN254, rand.Reader)
	if err != nil {
		panic(err)
	}
	pub := priv.Public()
	pkBytes := pub.Bytes()

	// 4) Build a valid witness
	var w circuit.SettlementCircuit

	recipient := big.NewInt(42)
	chainID := big.NewInt(1)
	kOld := big.NewInt(0)

	w.Recipient = recipient
	w.ChainID = chainID
	w.KOld = kOld

	total := big.NewInt(0)

	for i := 0; i < circuit.N; i++ {
		size := big.NewInt(1)
		nonce := big.NewInt(int64(i + 1)) // 1,2,...,N

		w.Size[i] = new(big.Int).Set(size)
		w.Nonce[i] = new(big.Int).Set(nonce)

		// msg_i = MiMC(domainSep, Recipient, Size[i], Nonce[i], ChainID)
		msgBytes := circuit.MimcMsg(recipient, size, nonce, chainID)

		// sign with EdDSA using MiMC as internal hash
		sigBytes, err := priv.Sign(msgBytes, bnMimc.NewMiMC())
		if err != nil {
			panic(err)
		}

		// assign signature into circuit witness
		w.Sig[i].Assign(te.BN254, sigBytes)

		total.Add(total, size)
	}

	w.TotalSettle = total
	w.M = big.NewInt(int64(circuit.N)) // last nonce
	w.Pk.Assign(te.BN254, pkBytes)

	// 5) Build full and public witnesses
	witness, err := frontend.NewWitness(&w, ecc.BN254.ScalarField())
	if err != nil {
		panic(err)
	}
	publicWitness, err := witness.Public()
	if err != nil {
		panic(err)
	}

	// 6) Prove
	start := time.Now()
	proof, err := groth16.Prove(ccs, pk, witness)
	if err != nil {
		panic(err)
	}
	proveTime := time.Since(start)
	fmt.Printf("Settlement prover took %s\n", proveTime)

	// 7) Verify
	start = time.Now()
	if err := groth16.Verify(proof, vk, publicWitness); err != nil {
		panic(err)
	}
	fmt.Printf("Settlement verifier took %s\n", time.Since(start))

	fmt.Println("Groth16 settlement proof verified ✅")

	cwProof := &countingWriter{}
	if _, err := proof.WriteTo(cwProof); err != nil {
		panic(err)
	}
	reportCompression(cwProof.n)
	reportEconomics(circuit.N, proveTime)
}
