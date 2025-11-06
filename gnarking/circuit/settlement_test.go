package circuit

import (
	"crypto/rand"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	bnMimc "github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
	te "github.com/consensys/gnark-crypto/ecc/twistededwards"
	nativeEddsa "github.com/consensys/gnark-crypto/signature/eddsa"

	"github.com/consensys/gnark/test"
)

func TestSettlementCircuit_EdDSA(t *testing.T) {
	assert := test.NewAssert(t)

	// 1. EdDSA keypair on BN254 babyjubjub
	priv, err := nativeEddsa.New(te.BN254, rand.Reader)
	assert.NoError(err)

	pub := priv.Public()
	pkBytes := pub.Bytes()

	// Public parameters
	recipient := big.NewInt(42)
	chainID := big.NewInt(1)
	kOld := big.NewInt(0)

	// --------------------
	// Build VALID witness
	// --------------------
	var valid SettlementCircuit

	valid.Recipient = recipient
	valid.ChainID = chainID
	valid.KOld = kOld

	total := big.NewInt(0)

	for i := 0; i < N; i++ {
		size := big.NewInt(1)
		nonce := big.NewInt(int64(i + 1)) // 1,2,...,N

		valid.Size[i] = new(big.Int).Set(size)
		valid.Nonce[i] = new(big.Int).Set(nonce)

		// msg_i = MiMC(domainSep, Recipient, Size[i], Nonce[i], ChainID)
		msgBytes := MimcMsg(recipient, size, nonce, chainID)

		// sign msg_i with EdDSA using MiMC_BN254 as internal hash
		sigBytes, err := priv.Sign(msgBytes, bnMimc.NewMiMC())
		assert.NoError(err)

		// sanity-check native verification
		ok, err := pub.Verify(sigBytes, msgBytes, bnMimc.NewMiMC())
		assert.NoError(err)
		assert.True(ok, "native EdDSA verification failed")

		// assign signature to circuit witness
		valid.Sig[i].Assign(te.BN254, sigBytes)

		total.Add(total, size)
	}

	valid.TotalSettle = total
	valid.M = big.NewInt(int64(N)) // last nonce
	valid.Pk.Assign(te.BN254, pkBytes)

	// Circuit template
	var c SettlementCircuit

	// Valid witness should succeed
	assert.ProverSucceeded(
		&c,
		&valid,
		test.WithCurves(ecc.BN254),
	)

	// --------------------
	// INVALID 1: wrong TotalSettle
	// --------------------
	invalidSum := valid
	invalidSum.TotalSettle = new(big.Int).Add(total, big.NewInt(1))

	assert.ProverFailed(
		&c,
		&invalidSum,
		test.WithCurves(ecc.BN254),
	)

	// --------------------
	// INVALID 2: break nonce ordering (nonce[5] == nonce[4])
	// --------------------
	invalidNonce := valid
	invalidNonce.Nonce[5] = invalidNonce.Nonce[4]

	assert.ProverFailed(
		&c,
		&invalidNonce,
		test.WithCurves(ecc.BN254),
	)

	// --------------------
	// INVALID 3: wrong public key (signatures no longer match Pk)
	// --------------------
	otherPriv, err := nativeEddsa.New(te.BN254, rand.Reader)
	assert.NoError(err)
	otherPub := otherPriv.Public()
	otherPkBytes := otherPub.Bytes()

	invalidPk := valid
	invalidPk.Pk.Assign(te.BN254, otherPkBytes)

	assert.ProverFailed(
		&c,
		&invalidPk,
		test.WithCurves(ecc.BN254),
	)
}
