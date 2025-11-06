package circuit

import (
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/native/twistededwards"
	stdMimc "github.com/consensys/gnark/std/hash/mimc"
	stdEddsa "github.com/consensys/gnark/std/signature/eddsa"

	te "github.com/consensys/gnark-crypto/ecc/twistededwards"
)

const N = 8

// SettlementCircuit:
// - batch constraints (TotalSettle, nonce ordering, M == max nonce)
// - public Recipient and ChainID
// - N EdDSA+MiMC signatures from the same public key Pk
//   over msg_i = MiMC(domainSep, Recipient, Size[i], Nonce[i], ChainID)
type SettlementCircuit struct {
	// public settlement parameters
	Recipient   frontend.Variable  `gnark:",public"`
	KOld        frontend.Variable  `gnark:",public"`
	M           frontend.Variable  `gnark:",public"`
	TotalSettle frontend.Variable  `gnark:",public"`
	ChainID     frontend.Variable  `gnark:",public"`

	// public signer key (same for all rows)
	Pk stdEddsa.PublicKey `gnark:",public"`

	// per-row fields (witnesses)
	Size  [N]frontend.Variable
	Nonce [N]frontend.Variable
	Sig   [N]stdEddsa.Signature
}

func (c *SettlementCircuit) Define(api frontend.API) error {
	// 1. SUM(Size[i]) == TotalSettle
	sum := frontend.Variable(0)
	for i := 0; i < N; i++ {
		sum = api.Add(sum, c.Size[i])
	}
	api.AssertIsEqual(sum, c.TotalSettle)

	// 2. Nonce[i] > KOld for all i (strict)
	for i := 0; i < N; i++ {
		api.AssertIsLessOrEqual(c.KOld, c.Nonce[i]) // Nonce[i] >= KOld
		api.AssertIsDifferent(c.KOld, c.Nonce[i])   // Nonce[i] != KOld
	}

	// 3. Nonce[i+1] > Nonce[i] (strictly increasing)
	for i := 0; i < N-1; i++ {
		api.AssertIsLessOrEqual(c.Nonce[i], c.Nonce[i+1]) // Nonce[i+1] >= Nonce[i]
		api.AssertIsDifferent(c.Nonce[i], c.Nonce[i+1])   // Nonce[i+1] != Nonce[i]
	}

	// 4. M == last nonce
	api.AssertIsEqual(c.M, c.Nonce[N-1])

	// SNARK-friendly Edwards curve on BN254 for EdDSA
	curve, err := twistededwards.NewEdCurve(api, te.BN254)
	if err != nil {
		return err
	}
	// domain separator: 8 bytes "msettle1" as a field element constant
	dsBig := new(big.Int).SetBytes(DOMAIN)
	domainSep := frontend.Variable(dsBig)
	// 5. For each row: verify EdDSA signature over
	//    msg_i = MiMC(domainSep, Recipient, Size[i], Nonce[i], ChainID)
	//    with the same public key c.Pk
	for i := 0; i < N; i++ {
		// outer MiMC for message hash
		hMsg, err := stdMimc.NewMiMC(api)
		if err != nil {
			return err
		}
		// hash the tuple (domain_separator, recipient, size, nonce, chain_id)
		hMsg.Write(domainSep, c.Recipient, c.Size[i], c.Nonce[i], c.ChainID)
		msg := hMsg.Sum()

		// MiMC instance for EdDSA (H(R, A, msg))
		hSig, err := stdMimc.NewMiMC(api)
		if err != nil {
			return err
		}

		// verify Sig[i] on msg with public key Pk
		if err := stdEddsa.Verify(curve, c.Sig[i], msg, c.Pk, &hSig); err != nil {
			return err
		}
	}

	return nil
}
