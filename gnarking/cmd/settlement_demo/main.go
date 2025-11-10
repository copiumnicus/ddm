package main

import (
	"crypto/rand"
	"path/filepath"
	// "encoding/binary"
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	fr_bn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"io"
	"math/big"
	"os"
	"runtime"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	bnMimc "github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
	te "github.com/consensys/gnark-crypto/ecc/twistededwards"
	nativeEddsa "github.com/consensys/gnark-crypto/signature/eddsa"

	"github.com/consensys/gnark/backend/groth16"
	groth16_bn254 "github.com/consensys/gnark/backend/groth16/bn254"
	cs_bn254 "github.com/consensys/gnark/constraint/bn254"
	// "github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"

	// "github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/backend/witness"

	"flag"
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
		cpuPricePerHour = 0.05  // $/core-hour
		minTxUSD        = 0.005 // $ per smallest tx
		hoursPerDay     = 24
		daysPerYear     = 365
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

	sigBytes := 3 * feBytes // R.X, R.Y, S
	preimageFields := 4     // Recipient, Size, Nonce, ChainID
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

func check(e error) {
	if e != nil {
		panic(e)
	}
}

func dump(f string, w io.WriterTo) {
	g, err := os.Create(f)
	check(err)
	defer g.Close()
	_, err = w.WriteTo(g)
	check(err)
}
func read(fName string, r io.ReaderFrom) {
	f, err := os.Open(fName)
	check(err)
	defer f.Close()
	_, err = r.ReadFrom(f)
	check(err)
}

type PublicInputsHex []string

var _ io.WriterTo = (*PublicInputsHex)(nil)

func NewPublicInputsHexFromWitness(w witness.Witness) (PublicInputsHex, error) {
	raw := w.Vector()
	vec, ok := raw.(fr_bn254.Vector)
	if !ok {
		return nil, fmt.Errorf("unexpected witness vector type %T", raw)
	}

	out := make([]string, len(vec))
	for i := range vec {
		b := vec[i].BigInt(new(big.Int))   // fr.Element -> *big.Int
		out[i] = fmt.Sprintf("0x%064x", b) // 32-byte, 0x-prefixed
	}

	return out, nil
}
func (p *PublicInputsHex) WriteTo(w io.Writer) (int64, error) {
	b, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return 0, err
	}
	return bytes.NewReader(b).WriteTo(w)
}

type ProofWrap [8]string

func NewProofWrap(g *groth16_bn254.Proof) (ProofWrap, error) {
	raw := g.MarshalSolidity()
	if len(raw) != 8*32 {
		return ProofWrap{}, fmt.Errorf("invalid proof length: got %d", len(raw))
	}

	var w ProofWrap
	for i := 0; i < 8; i++ {
		w[i] = "0x" + hex.EncodeToString(raw[i*32:(i+1)*32])
	}
	return w, nil
}

var _ io.WriterTo = (*ProofWrap)(nil)
var _ io.ReaderFrom = (*ProofWrap)(nil)

func (p *ProofWrap) WriteTo(w io.Writer) (int64, error) {
	b, err := json.MarshalIndent(p, "", "\t")
	if err != nil {
		return 0, err
	}
	return bytes.NewReader(b).WriteTo(w)
}

func (p *ProofWrap) ReadFrom(r io.Reader) (int64, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return 0, err
	}
	if err := json.Unmarshal(data, p); err != nil {
		return int64(len(data)), err
	}
	return int64(len(data)), nil
}

// DeleteMatchingFiles removes all files in dir matching pattern
func DeleteMatchingFiles(dir string, patter string) error {
	pattern := filepath.Join(dir, patter)

	matches, err := filepath.Glob(pattern)
	if err != nil {
		return fmt.Errorf("invalid pattern: %w", err)
	}

	for _, path := range matches {
		info, err := os.Stat(path)
		if err != nil {
			return err
		}
		if !info.IsDir() {
			if err := os.Remove(path); err != nil {
				return err
			}
		}
	}
	return nil
}

func main() {
	var (
		pkName            = fmt.Sprintf("./artifact/pk_%d.groth16", circuit.N)
		ccsName           = fmt.Sprintf("./artifact/ccs_%d.groth16", circuit.N)
		vkName            = fmt.Sprintf("./artifact/vk_%d.groth16", circuit.N)
		proofName         = fmt.Sprintf("./artifact/proof_%d.groth16", circuit.N)
		proofJsonName     = fmt.Sprintf("./artifact/proof_%d.json", circuit.N)
		publicName        = fmt.Sprintf("./artifact/public_%d.json", circuit.N)
		publicSolJsonName = fmt.Sprintf("./artifact/public_sol_%d.json", circuit.N)
		verifyName        = fmt.Sprintf("./artifact/settlement_verifier_%d.sol", circuit.N)
	)

	setup := flag.Bool("setup", false, "run circuit setup (compile + generate keys)")
	prove := flag.Bool("prove", false, "generate a proof using existing proving key")
	verify := flag.Bool("verify", false, "verify an existing proof")
	flag.Parse()

	if *setup {
		fmt.Println("Deleting old artifacts")
		check(DeleteMatchingFiles("./artifact", "*_8.*"))
		fmt.Println("Setting up N = %d", circuit.N)
		var c circuit.SettlementCircuit
		ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &c)
		check(err)
		pk, vk, err := groth16.Setup(ccs)
		check(err)
		dump(ccsName, ccs)
		dump(pkName, pk)
		dump(vkName, vk)
		{
			vkFile, err := os.Create(verifyName)
			check(err)
			defer vkFile.Close()
			check(vk.ExportSolidity(vkFile))
			fmt.Println("Solidity verifier exported to settlement_verifier.sol")
		}
		cw := &countingWriter{}
		_, err = pk.WriteTo(cw)
		check(err)
		fmt.Printf("Proving key size (N = %d) (serialized): %.2f MB (%d bytes)\n", circuit.N, float64(cw.n)/1024/1024, cw.n)
	}
	if *prove {
		// have to init to read ...
		var (
			ccs cs_bn254.R1CS
			pk  groth16_bn254.ProvingKey
		)
		read(pkName, &pk)
		read(ccsName, &ccs)

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

		w.P.Recipient = recipient
		w.P.ChainID = chainID
		w.P.KOld = kOld

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

		w.P.TotalSettle = total
		w.P.M = big.NewInt(int64(circuit.N)) // last nonce
		w.P.Pk.Assign(te.BN254, pkBytes)

		// 5) Build full and public witnesses
		witness, err := frontend.NewWitness(&w, ecc.BN254.ScalarField())
		if err != nil {
			panic(err)
		}

		// 6) Prove
		start := time.Now()
		proof, err := groth16_bn254.Prove(&ccs, &pk, witness)
		if err != nil {
			panic(err)
		}
		proveTime := time.Since(start)
		fmt.Printf("Settlement prover took %s\n", proveTime)

		reportEconomics(circuit.N, proveTime)

		wit, err := witness.Public()
		check(err)
		pubHex, err := NewPublicInputsHexFromWitness(wit)
		check(err)
		dump(publicSolJsonName, &pubHex)
		var pj ProofWrap
		pj, _ = NewProofWrap(proof)
		dump(proofJsonName, &pj)
		dump(proofName, proof)
		dump(publicName, &w.P)
	}
	if *verify {
		var (
			proof         groth16_bn254.Proof
			publicWitness circuit.SettlementCircuitPublic
			vk            groth16_bn254.VerifyingKey
		)
		read(proofName, &proof)
		read(vkName, &vk)
		read(publicName, &publicWitness)
		// create the circuit assignment
		assignment := &circuit.SettlementCircuit{
			P: publicWitness,
		}
		pubWit, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField(), frontend.PublicOnly())
		check(err)
		// 7) Verify
		start := time.Now()
		if err := groth16.Verify(&proof, &vk, pubWit); err != nil {
			panic(err)
		}
		fmt.Printf("Settlement verifier took %s\n", time.Since(start))
		fmt.Println("Groth16 settlement proof verified")

		cwProof := &countingWriter{}
		if _, err := proof.WriteTo(cwProof); err != nil {
			panic(err)
		}
		reportCompression(cwProof.n)
	}

}
