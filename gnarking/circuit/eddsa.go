package circuit

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/native/twistededwards"
	stdMimc "github.com/consensys/gnark/std/hash/mimc"
	stdEddsa "github.com/consensys/gnark/std/signature/eddsa"

	te "github.com/consensys/gnark-crypto/ecc/twistededwards"
)

// EdDSAMiMCCircuit verifies an EdDSA signature with MiMC on the BN254 Edwards curve.
type EdDSAMiMCCircuit struct {
	Msg frontend.Variable  `gnark:",public"` // message as field element
	Pk  stdEddsa.PublicKey `gnark:",public"` // public key
	Sig stdEddsa.Signature                    // signature (R, S)
}

func (c *EdDSAMiMCCircuit) Define(api frontend.API) error {
	// SNARK-friendly twisted Edwards curve living over BN254
	curve, err := twistededwards.NewEdCurve(api, te.BN254)
	if err != nil {
		return err
	}

	// MiMC hash used inside EdDSA verifier
	h, err := stdMimc.NewMiMC(api)
	if err != nil {
		return err
	}

	// Check Sig is a valid EdDSA signature on Msg under Pk using MiMC
	return stdEddsa.Verify(curve, c.Sig, c.Msg, c.Pk, &h)
}
