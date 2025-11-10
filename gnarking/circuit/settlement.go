package circuit

import (
	"math/big"
	"io"
	"bytes"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/native/twistededwards"
	stdMimc "github.com/consensys/gnark/std/hash/mimc"
	stdEddsa "github.com/consensys/gnark/std/signature/eddsa"

	te "github.com/consensys/gnark-crypto/ecc/twistededwards"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

const N = 8

// SettlementCircuitPublic is your circuit-level public inputs.
type SettlementCircuitPublic struct {
	Recipient   frontend.Variable  `gnark:",public"`
	KOld        frontend.Variable  `gnark:",public"`
	M           frontend.Variable  `gnark:",public"`
	TotalSettle frontend.Variable  `gnark:",public"`
	ChainID     frontend.Variable  `gnark:",public"`
	Pk          stdEddsa.PublicKey `gnark:",public"`
}

// JSON form — the same fields but ready for JSON.
type SettlementCircuitPublicJSON struct {
	Recipient   string `json:"recipient"`     // hex
	KOld        uint64 `json:"k_old"`
	M           uint64 `json:"m"`
	TotalSettle uint64 `json:"total_settle"`
	ChainID     uint64 `json:"chain_id"`
	PkX         string `json:"pk_x"`         // hex
	PkY         string `json:"pk_y"`         // hex
}

func (s *SettlementCircuitPublic) WriteTo(w io.Writer) (int64, error) {
	b, err := json.MarshalIndent(s, "", "	")
    if err != nil {
        return 0, err
    }
    return bytes.NewReader(b).WriteTo(w)
}

func (s *SettlementCircuitPublic) ReadFrom(r io.Reader) (int64, error) {
    data, err := io.ReadAll(r)
    if err != nil {
        return 0, err
    }
    if err := s.UnmarshalJSON(data); err != nil {
        return int64(len(data)), err
    }
    return int64(len(data)), nil
}

var _ io.WriterTo = (*SettlementCircuitPublic)(nil)
var _ io.ReaderFrom = (*SettlementCircuitPublic)(nil)

// MarshalJSON encodes public inputs (BN254 only).
func (s SettlementCircuitPublic) MarshalJSON() ([]byte, error) {
	toU64 := func(v frontend.Variable) (uint64, error) {
		switch x := v.(type) {
		case *big.Int:
			return x.Uint64(), nil
		case big.Int:
			return (&x).Uint64(), nil
		default:
			return 0, fmt.Errorf("unexpected type %T", v)
		}
	}

	var js SettlementCircuitPublicJSON

	// encode address
	switch x := s.Recipient.(type) {
	case *big.Int:
		js.Recipient = "0x" + hex.EncodeToString(x.Bytes())
	case big.Int:
		js.Recipient = "0x" + hex.EncodeToString(x.Bytes())
	default:
		return nil, fmt.Errorf("unexpected Recipient type %T", s.Recipient)
	}

	var err error
	if js.KOld, err = toU64(s.KOld); err != nil {
		return nil, err
	}
	if js.M, err = toU64(s.M); err != nil {
		return nil, err
	}
	if js.TotalSettle, err = toU64(s.TotalSettle); err != nil {
		return nil, err
	}
	if js.ChainID, err = toU64(s.ChainID); err != nil {
		return nil, err
	}

	// pk.A.X
	switch x := s.Pk.A.X.(type) {
	case []byte:
		js.PkX = hex.EncodeToString(x)
	case *big.Int:
		js.PkX = hex.EncodeToString(x.Bytes())
	case big.Int:
		js.PkX = hex.EncodeToString(x.Bytes())
	default:
		return nil, fmt.Errorf("unexpected pk.A.X type %T", s.Pk.A.X)
	}

	// pk.A.Y
	switch y := s.Pk.A.Y.(type) {
	case []byte:
		js.PkY = hex.EncodeToString(y)
	case *big.Int:
		js.PkY = hex.EncodeToString(y.Bytes())
	case big.Int:
		js.PkY = hex.EncodeToString(y.Bytes())
	default:
		return nil, fmt.Errorf("unexpected pk.A.Y type %T", s.Pk.A.Y)
	}

	return json.Marshal(js)
}

// UnmarshalJSON decodes JSON into gnark frontend variables.
func (s *SettlementCircuitPublic) UnmarshalJSON(data []byte) error {
	var js SettlementCircuitPublicJSON
	if err := json.Unmarshal(data, &js); err != nil {
		return err
	}

	// Recipient
	rHex := js.Recipient
	if len(rHex) >= 2 && (rHex[:2] == "0x" || rHex[:2] == "0X") {
		rHex = rHex[2:]
	}
	rBytes, err := hex.DecodeString(rHex)
	if err != nil {
		return fmt.Errorf("invalid recipient hex: %w", err)
	}
	s.Recipient = new(big.Int).SetBytes(rBytes)
	s.KOld = new(big.Int).SetUint64(js.KOld)
	s.M = new(big.Int).SetUint64(js.M)
	s.TotalSettle = new(big.Int).SetUint64(js.TotalSettle)
	s.ChainID = new(big.Int).SetUint64(js.ChainID)

	// Public key coords
	xBytes, err := hex.DecodeString(js.PkX)
	if err != nil {
		return fmt.Errorf("invalid pk_x hex: %w", err)
	}
	yBytes, err := hex.DecodeString(js.PkY)
	if err != nil {
		return fmt.Errorf("invalid pk_y hex: %w", err)
	}
	s.Pk.A.X = new(big.Int).SetBytes(xBytes)
	s.Pk.A.Y = new(big.Int).SetBytes(yBytes)

	return nil
}

// SettlementCircuit:
//   - batch constraints (TotalSettle, nonce ordering, M == max nonce)
//   - public Recipient and ChainID
//   - N EdDSA+MiMC signatures from the same public key Pk
//     over msg_i = MiMC(domainSep, Recipient, Size[i], Nonce[i], ChainID)
type SettlementCircuit struct {
	P SettlementCircuitPublic
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
	api.AssertIsEqual(sum, c.P.TotalSettle)

	// 2. Nonce[i] > KOld for all i (strict)
	for i := 0; i < N; i++ {
		api.AssertIsLessOrEqual(c.P.KOld, c.Nonce[i]) // Nonce[i] >= KOld
		api.AssertIsDifferent(c.P.KOld, c.Nonce[i])   // Nonce[i] != KOld
	}

	// 3. Nonce[i+1] > Nonce[i] (strictly increasing)
	for i := 0; i < N-1; i++ {
		api.AssertIsLessOrEqual(c.Nonce[i], c.Nonce[i+1]) // Nonce[i+1] >= Nonce[i]
		api.AssertIsDifferent(c.Nonce[i], c.Nonce[i+1])   // Nonce[i+1] != Nonce[i]
	}

	// 4. M == last nonce
	api.AssertIsEqual(c.P.M, c.Nonce[N-1])

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
		hMsg.Write(domainSep, c.P.Recipient, c.Size[i], c.Nonce[i], c.P.ChainID)
		msg := hMsg.Sum()

		// MiMC instance for EdDSA (H(R, A, msg))
		hSig, err := stdMimc.NewMiMC(api)
		if err != nil {
			return err
		}

		// verify Sig[i] on msg with public key Pk
		if err := stdEddsa.Verify(curve, c.Sig[i], msg, c.P.Pk, &hSig); err != nil {
			return err
		}
	}

	return nil
}
