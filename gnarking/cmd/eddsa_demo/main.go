// cmd/eddsa_demo/main.go
package main

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	te "github.com/consensys/gnark-crypto/ecc/twistededwards"
	"github.com/consensys/gnark-crypto/hash"
	nativeEddsa "github.com/consensys/gnark-crypto/signature/eddsa"

	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"

	"gnarking/circuit"
)

func main() {
	// Use the BN254 twisted Edwards curve for EdDSA
	curveID := te.BN254

	// 1) Native keygen
	priv, err := nativeEddsa.New(curveID, rand.Reader)
	if err != nil {
		panic(err)
	}
	pub := priv.Public()

	// 2) Message as a field element
	msgBytes := []byte("hello zk-eddsa+mimc")
	msgInt := new(big.Int).SetBytes(msgBytes)

	// Pad message bytes to the BN254 scalar field size
	snarkField := ecc.BN254.ScalarField()
	msgBuf := make([]byte, len(snarkField.Bytes()))
	raw := msgInt.Bytes()
	copy(msgBuf[len(msgBuf)-len(raw):], raw)

	// 3) Native sign + verify with MiMC
	sig, err := priv.Sign(msgBuf, hash.MIMC_BN254.New())
	if err != nil {
		panic(err)
	}
	ok, err := pub.Verify(sig, msgBuf, hash.MIMC_BN254.New())
	if err != nil || !ok {
		panic("native EdDSA verification failed")
	}

	// 4) Compile the circuit
	var c circuit.EdDSAMiMCCircuit
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &c)
	if err != nil {
		panic(err)
	}

	// 5) Groth16 setup
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		panic(err)
	}

	// 6) Build witness: same msg/pk/sig as native side
	var w circuit.EdDSAMiMCCircuit
	w.Msg = msgInt
	w.Pk.Assign(curveID, pub.Bytes())
	w.Sig.Assign(curveID, sig)

	witness, err := frontend.NewWitness(&w, ecc.BN254.ScalarField())
	if err != nil {
		panic(err)
	}
	publicWitness, err := witness.Public()
	if err != nil {
		panic(err)
	}

	start := time.Now()
	// 7) Prove
	proof, err := groth16.Prove(ccs, pk, witness)
	if err != nil {
		panic(err)
	}
	elapsed := time.Since(start)
	fmt.Printf("Prover took %s\n", elapsed)

	// 8) Verify
	if err := groth16.Verify(proof, vk, publicWitness); err != nil {
		panic(err)
	}

	fmt.Println("Groth16 proof verified")
}
