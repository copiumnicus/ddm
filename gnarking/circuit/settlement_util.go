package circuit

import (
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
	bnMimc "github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
)

// encode a big.Int into a BN254 field element (32 bytes, big-endian)
func encodeFieldElement(x *big.Int) []byte {
	fieldMod := ecc.BN254.ScalarField()
	fieldLen := len(fieldMod.Bytes())

	r := new(big.Int).Mod(x, fieldMod)
	b := r.Bytes()

	out := make([]byte, fieldLen)
	copy(out[fieldLen-len(b):], b)
	return out
}

var (
	DOMAIN = []byte("msettle1")
)

// msg_i = MiMC("msettle1", Recipient, Size[i], Nonce[i], ChainID)
// exactly matching what the circuit does with std/hash/mimc.
func MimcMsg(recipient, size, nonce, chainID *big.Int) []byte {
	dsBig := new(big.Int).SetBytes(DOMAIN)

	fieldMod := ecc.BN254.ScalarField()
	fieldLen := len(fieldMod.Bytes())
	_ = fieldMod

	pre := make([]byte, 0, fieldLen*5)
	pre = append(pre, encodeFieldElement(dsBig)...)
	pre = append(pre, encodeFieldElement(recipient)...)
	pre = append(pre, encodeFieldElement(size)...)
	pre = append(pre, encodeFieldElement(nonce)...)
	pre = append(pre, encodeFieldElement(chainID)...)

	h := bnMimc.NewMiMC()
	h.Write(pre)
	return h.Sum(nil)
}