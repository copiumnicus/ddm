use tiny_keccak::Hasher;

/// serialization does not need to be efficient
pub struct InputToSer {
    pub state_deltas: u32,
    pub fee_atoms: u16, // the fee charged for batching, enforced onchain, but modifiable
    pub fee_recipient: [u8; 20], // fee recipient, the batch contract itself, enforced onchain
    pub tx: Vec<TxToSer>,
}

impl InputToSer {
    pub fn ser(&self) -> Vec<u8> {
        let mut out = vec![];
        out.extend_from_slice(&self.state_deltas.to_be_bytes());
        out.extend_from_slice(&self.fee_atoms.to_be_bytes());
        out.extend_from_slice(&self.fee_recipient);
        let txs = self.tx.len() as u32;
        out.extend_from_slice(&txs.to_be_bytes());
        for tx in &self.tx {
            out.extend_from_slice(&tx.ser());
        }

        out
    }
}

/// to be as efficient as possible we will borrow everything from the input vector
pub struct Input<'a> {
    /// the entire input buffer
    /// state_deltas_u32 would give 2**31 max txs worst case
    /// (state_deltas_u32, total_tx_u32, txs[])
    pub v: &'a [u8],
}
impl<'a> Input<'a> {
    pub const HEADER_SIZE: usize = 4 + 2 + 20 + 4; // 30
    pub fn new(v: &'a [u8]) -> Self {
        Self { v }
    }
    pub fn state_deltas(&self) -> u32 {
        u32::from_be_bytes(self.v[..4].try_into().unwrap())
    }
    pub fn fee_atoms(&self) -> u16 {
        u16::from_be_bytes(self.v[4..6].try_into().unwrap())
    }
    pub fn fee_recipient(&self) -> &'a [u8] {
        &self.v[6..26]
    }
    pub fn total_tx(&self) -> u32 {
        u32::from_be_bytes(self.v[26..Self::HEADER_SIZE].try_into().unwrap())
    }
    pub fn tx_at(&self, idx: u32) -> Tx<'a> {
        let idx = idx as usize;
        let start = idx * TxToSer::SIZE;
        let end = start + TxToSer::SIZE;
        let region = &self.v[Self::HEADER_SIZE..];
        Tx {
            v: &region[start..end],
        }
    }
}

/// want to make it eip-712 compatible for ez integration
/// sign(keccak256("\x19\x01" ‖ domainSeparator ‖ hashStruct(message)))
#[derive(Clone)]
pub struct TxToSer {
    pub to: [u8; 20],
    /// max payment size is 2**63, type is kept as i64 to add to sub in state deltas,
    /// non positive values are invalid and are asserted in the program
    pub atoms: i64,
    pub nonce: u64,
    pub sig_r: [u8; 32],
    pub sig_s: [u8; 32],
    pub v: u8,

    /// helpers for the program to idx the state diff arr
    pub from_idx: u32,
    pub to_idx: u32,
}

impl TxToSer {
    pub const SIZE: usize = 20 + 8 + 8 + 32 + 32 + 1 + 4 + 4;

    pub fn ser(&self) -> Vec<u8> {
        let mut out = vec![];
        out.extend_from_slice(&self.to);
        out.extend_from_slice(&self.atoms.to_be_bytes());
        out.extend_from_slice(&self.nonce.to_be_bytes());
        out.extend_from_slice(&self.sig_r);
        out.extend_from_slice(&self.sig_s);
        out.push(self.v);
        // helpers
        out.extend_from_slice(&self.from_idx.to_be_bytes());
        out.extend_from_slice(&self.to_idx.to_be_bytes());
        out
    }

    pub fn keccak(&self) -> [u8; 32] {
        let mut s = tiny_keccak::Keccak::v256();
        s.update(&self.to);
        s.update(&self.atoms.to_be_bytes());
        s.update(&self.nonce.to_be_bytes());
        let mut out = [0; 32];
        s.finalize(&mut out);
        out
    }
}

pub struct Tx<'a> {
    pub v: &'a [u8],
}
impl<'a> Tx<'a> {
    pub fn to(&self) -> &'a [u8] {
        &self.v[0..20]
    }

    pub fn atoms_slice(&self) -> &'a [u8] {
        &self.v[20..28]
    }
    pub fn atoms(&self) -> i64 {
        let bytes: [u8; 8] = self.atoms_slice().try_into().unwrap();
        i64::from_be_bytes(bytes)
    }
    pub fn nonce_slice(&self) -> &'a [u8] {
        &self.v[28..36]
    }
    pub fn nonce(&self) -> u64 {
        let bytes: [u8; 8] = self.nonce_slice().try_into().unwrap();
        u64::from_be_bytes(bytes)
    }

    pub fn sig_r(&self) -> [u8; 32] {
        self.v[36..68].try_into().unwrap()
    }

    pub fn sig_s(&self) -> [u8; 32] {
        self.v[68..100].try_into().unwrap()
    }

    pub fn v(&self) -> u8 {
        self.v[100]
    }

    pub fn from_idx(&self) -> u32 {
        u32::from_be_bytes(self.v[101..105].try_into().unwrap())
    }
    pub fn to_idx(&self) -> u32 {
        u32::from_be_bytes(self.v[105..109].try_into().unwrap())
    }

    pub fn keccak(&self, out: &mut [u8; 32]) {
        let mut s = tiny_keccak::Keccak::v256();
        s.update(self.to());
        s.update(self.atoms_slice());
        s.update(self.nonce_slice());
        s.finalize(out);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper to create a test TxToSer with known values
    fn create_test_tx() -> TxToSer {
        TxToSer {
            to: [1u8; 20],
            atoms: 1000,
            nonce: 42,
            sig_r: [2u8; 32],
            sig_s: [3u8; 32],
            v: 27,
            from_idx: 5,
            to_idx: 10,
        }
    }

    /// Helper to create a test TxToSer with max values
    fn create_max_tx() -> TxToSer {
        TxToSer {
            to: [0xFF; 20],
            atoms: i64::MAX,
            nonce: u64::MAX,
            sig_r: [0xFF; 32],
            sig_s: [0xFF; 32],
            v: 255,
            from_idx: u32::MAX,
            to_idx: u32::MAX,
        }
    }

    /// Helper to create a test TxToSer with min values
    fn create_min_tx() -> TxToSer {
        TxToSer {
            to: [0u8; 20],
            atoms: 1, // positive non-zero as per the requirement
            nonce: 0,
            sig_r: [0u8; 32],
            sig_s: [0u8; 32],
            v: 0,
            from_idx: 0,
            to_idx: 0,
        }
    }

    #[test]
    fn test_tx_size_constant() {
        // Verify SIZE constant matches actual serialization
        let tx = create_test_tx();
        let serialized = tx.ser();
        assert_eq!(
            serialized.len(),
            TxToSer::SIZE,
            "TxToSer::SIZE constant should match actual serialized size"
        );
        assert_eq!(
            TxToSer::SIZE,
            109,
            "TxToSer::SIZE should be 109 bytes (20+8+8+32+32+1+4+4)"
        );
    }

    #[test]
    fn test_tx_round_trip() {
        let original = create_test_tx();
        let serialized = original.ser();
        let tx = Tx { v: &serialized };

        // Verify all fields round-trip correctly
        assert_eq!(tx.to(), &original.to, "to field should match");
        assert_eq!(tx.atoms(), original.atoms, "atoms field should match");
        assert_eq!(tx.nonce(), original.nonce, "nonce field should match");
        assert_eq!(tx.sig_r(), original.sig_r, "sig_r field should match");
        assert_eq!(tx.sig_s(), original.sig_s, "sig_s field should match");
        assert_eq!(tx.v(), original.v, "v field should match");
        assert_eq!(
            tx.from_idx(),
            original.from_idx,
            "from_idx field should match"
        );
        assert_eq!(tx.to_idx(), original.to_idx, "to_idx field should match");
    }

    #[test]
    fn test_tx_max_values() {
        let original = create_max_tx();
        let serialized = original.ser();
        let tx = Tx { v: &serialized };

        assert_eq!(tx.atoms(), i64::MAX, "should handle max i64 value");
        assert_eq!(tx.nonce(), u64::MAX, "should handle max u64 value");
        assert_eq!(
            tx.from_idx(),
            u32::MAX,
            "should handle max u32 for from_idx"
        );
        assert_eq!(tx.to_idx(), u32::MAX, "should handle max u32 for to_idx");
        assert_eq!(tx.v(), 255, "should handle max u8 value");
    }

    #[test]
    fn test_tx_min_values() {
        let original = create_min_tx();
        let serialized = original.ser();
        let tx = Tx { v: &serialized };

        assert_eq!(tx.atoms(), 1, "should handle min positive atoms value");
        assert_eq!(tx.nonce(), 0, "should handle zero nonce");
        assert_eq!(tx.from_idx(), 0, "should handle zero from_idx");
        assert_eq!(tx.to_idx(), 0, "should handle zero to_idx");
        assert_eq!(tx.v(), 0, "should handle zero v value");
    }

    #[test]
    fn test_tx_negative_atoms() {
        let mut tx = create_test_tx();
        tx.atoms = -500;
        let serialized = tx.ser();
        let deserialized = Tx { v: &serialized };

        assert_eq!(
            deserialized.atoms(),
            -500,
            "should correctly serialize/deserialize negative atoms"
        );
    }

    #[test]
    fn test_tx_keccak_consistency() {
        let tx_to_ser = create_test_tx();
        let hash1 = tx_to_ser.keccak();

        let serialized = tx_to_ser.ser();
        let tx = Tx { v: &serialized };
        let mut hash2 = [0u8; 32];
        tx.keccak(&mut hash2);

        assert_eq!(
            hash1, hash2,
            "Keccak hash should be identical between TxToSer and Tx"
        );
    }

    #[test]
    fn test_tx_keccak_deterministic() {
        let tx = create_test_tx();
        let hash1 = tx.keccak();
        let hash2 = tx.keccak();

        assert_eq!(hash1, hash2, "Keccak hash should be deterministic");
    }

    #[test]
    fn test_tx_keccak_different_for_different_tx() {
        let tx1 = create_test_tx();
        let mut tx2 = create_test_tx();
        tx2.nonce = 43; // Change one field

        let hash1 = tx1.keccak();
        let hash2 = tx2.keccak();

        assert_ne!(
            hash1, hash2,
            "Different transactions should produce different hashes"
        );
    }

    #[test]
    fn test_input_header_size_constant() {
        let input = InputToSer {
            state_deltas: 10,
            fee_atoms: 100,
            fee_recipient: [4u8; 20],
            tx: vec![],
        };
        let serialized = input.ser();
        let header_size = serialized.len(); // No transactions, just header

        assert_eq!(
            header_size,
            Input::HEADER_SIZE,
            "Input::HEADER_SIZE should match actual header size"
        );
        assert_eq!(
            Input::HEADER_SIZE,
            30,
            "Input::HEADER_SIZE should be 30 bytes (4+2+20+4)"
        );
    }

    #[test]
    fn test_input_round_trip_no_tx() {
        let original = InputToSer {
            state_deltas: 10,
            fee_atoms: 100,
            fee_recipient: [4u8; 20],
            tx: vec![],
        };

        let serialized = original.ser();
        let input = Input::new(&serialized);

        assert_eq!(
            input.state_deltas(),
            original.state_deltas,
            "state_deltas should match"
        );
        assert_eq!(
            input.fee_atoms(),
            original.fee_atoms,
            "fee_atoms should match"
        );
        assert_eq!(
            input.fee_recipient(),
            &original.fee_recipient,
            "fee_recipient should match"
        );
        assert_eq!(
            input.total_tx(),
            0,
            "total_tx should be 0 for empty transaction list"
        );
    }

    #[test]
    fn test_input_round_trip_single_tx() {
        let tx = create_test_tx();
        let original = InputToSer {
            state_deltas: 5,
            fee_atoms: 50,
            fee_recipient: [7u8; 20],
            tx: vec![tx],
        };

        let serialized = original.ser();
        let input = Input::new(&serialized);

        assert_eq!(input.state_deltas(), 5);
        assert_eq!(input.fee_atoms(), 50);
        assert_eq!(input.fee_recipient(), &[7u8; 20]);
        assert_eq!(input.total_tx(), 1);

        let tx0 = input.tx_at(0);
        let original_tx = &original.tx[0];
        assert_eq!(tx0.to(), &original_tx.to);
        assert_eq!(tx0.atoms(), original_tx.atoms);
        assert_eq!(tx0.nonce(), original_tx.nonce);
        assert_eq!(tx0.sig_r(), original_tx.sig_r);
        assert_eq!(tx0.sig_s(), original_tx.sig_s);
        assert_eq!(tx0.v(), original_tx.v);
        assert_eq!(tx0.from_idx(), original_tx.from_idx);
        assert_eq!(tx0.to_idx(), original_tx.to_idx);
    }

    #[test]
    fn test_input_round_trip_multiple_tx() {
        let tx1 = create_test_tx();
        let mut tx2 = create_test_tx();
        tx2.nonce = 100;
        tx2.atoms = 5000;
        let mut tx3 = create_min_tx();
        tx3.from_idx = 2;

        let original = InputToSer {
            state_deltas: 20,
            fee_atoms: 75,
            fee_recipient: [8u8; 20],
            tx: vec![tx1, tx2, tx3],
        };

        let serialized = original.ser();
        let input = Input::new(&serialized);

        assert_eq!(input.state_deltas(), 20);
        assert_eq!(input.fee_atoms(), 75);
        assert_eq!(input.total_tx(), 3);

        // Verify each transaction
        for i in 0..3 {
            let tx = input.tx_at(i as u32);
            let orig_tx = &original.tx[i];
            assert_eq!(tx.to(), &orig_tx.to, "tx{} to should match", i);
            assert_eq!(tx.atoms(), orig_tx.atoms, "tx{} atoms should match", i);
            assert_eq!(tx.nonce(), orig_tx.nonce, "tx{} nonce should match", i);
            assert_eq!(tx.sig_r(), orig_tx.sig_r, "tx{} sig_r should match", i);
            assert_eq!(tx.sig_s(), orig_tx.sig_s, "tx{} sig_s should match", i);
            assert_eq!(tx.v(), orig_tx.v, "tx{} v should match", i);
            assert_eq!(
                tx.from_idx(),
                orig_tx.from_idx,
                "tx{} from_idx should match",
                i
            );
            assert_eq!(
                tx.to_idx(),
                orig_tx.to_idx,
                "tx{} to_idx should match",
                i
            );
        }
    }

    #[test]
    fn test_input_max_values() {
        let max_tx = create_max_tx();
        let original = InputToSer {
            state_deltas: u32::MAX,
            fee_atoms: u16::MAX,
            fee_recipient: [0xFF; 20],
            tx: vec![max_tx],
        };

        let serialized = original.ser();
        let input = Input::new(&serialized);

        assert_eq!(
            input.state_deltas(),
            u32::MAX,
            "should handle max u32 state_deltas"
        );
        assert_eq!(
            input.fee_atoms(),
            u16::MAX,
            "should handle max u16 fee_atoms"
        );
        assert_eq!(input.total_tx(), 1);
    }

    #[test]
    fn test_input_serialization_size() {
        let tx1 = create_test_tx();
        let tx2 = create_min_tx();
        let original = InputToSer {
            state_deltas: 100,
            fee_atoms: 200,
            fee_recipient: [9u8; 20],
            tx: vec![tx1, tx2],
        };

        let serialized = original.ser();
        let expected_size = Input::HEADER_SIZE + (2 * TxToSer::SIZE);

        assert_eq!(
            serialized.len(),
            expected_size,
            "Serialized size should be header + (num_tx * tx_size)"
        );
    }

    #[test]
    fn test_tx_byte_order_big_endian() {
        let tx = TxToSer {
            to: [0; 20],
            atoms: 0x0102030405060708i64,
            nonce: 0x090A0B0C0D0E0F10u64,
            sig_r: [0; 32],
            sig_s: [0; 32],
            v: 0,
            from_idx: 0x11121314u32,
            to_idx: 0x15161718u32,
        };

        let serialized = tx.ser();

        // Check atoms (big-endian i64)
        assert_eq!(
            &serialized[20..28],
            &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08],
            "atoms should be big-endian"
        );

        // Check nonce (big-endian u64)
        assert_eq!(
            &serialized[28..36],
            &[0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10],
            "nonce should be big-endian"
        );

        // Check from_idx (big-endian u32)
        assert_eq!(
            &serialized[101..105],
            &[0x11, 0x12, 0x13, 0x14],
            "from_idx should be big-endian"
        );

        // Check to_idx (big-endian u32)
        assert_eq!(
            &serialized[105..109],
            &[0x15, 0x16, 0x17, 0x18],
            "to_idx should be big-endian"
        );
    }

    #[test]
    fn test_input_byte_order_big_endian() {
        let input = InputToSer {
            state_deltas: 0x01020304u32,
            fee_atoms: 0x0506u16,
            fee_recipient: [0; 20],
            tx: vec![],
        };

        let serialized = input.ser();

        // Check state_deltas (big-endian u32)
        assert_eq!(
            &serialized[0..4],
            &[0x01, 0x02, 0x03, 0x04],
            "state_deltas should be big-endian"
        );

        // Check fee_atoms (big-endian u16)
        assert_eq!(
            &serialized[4..6],
            &[0x05, 0x06],
            "fee_atoms should be big-endian"
        );

        // Check total_tx (big-endian u32)
        assert_eq!(
            &serialized[26..30],
            &[0x00, 0x00, 0x00, 0x00],
            "total_tx should be big-endian (0 txs)"
        );
    }

    #[test]
    fn test_tx_slice_accessors() {
        let tx = create_test_tx();
        let serialized = tx.ser();
        let tx_ref = Tx { v: &serialized };

        // Test slice accessors return correct slices
        assert_eq!(tx_ref.atoms_slice().len(), 8, "atoms_slice should be 8 bytes");
        assert_eq!(
            tx_ref.nonce_slice().len(),
            8,
            "nonce_slice should be 8 bytes"
        );

        // Verify slice contents match the value methods
        let atoms_from_slice = i64::from_be_bytes(tx_ref.atoms_slice().try_into().unwrap());
        assert_eq!(
            atoms_from_slice,
            tx_ref.atoms(),
            "atoms_slice should decode to same value as atoms()"
        );

        let nonce_from_slice = u64::from_be_bytes(tx_ref.nonce_slice().try_into().unwrap());
        assert_eq!(
            nonce_from_slice,
            tx_ref.nonce(),
            "nonce_slice should decode to same value as nonce()"
        );
    }

    #[test]
    fn test_many_transactions() {
        // Test with a larger number of transactions
        let mut txs = Vec::new();
        for i in 0..100 {
            let mut tx = create_test_tx();
            tx.nonce = i as u64;
            tx.atoms = 1000 + (i as i64 * 10);
            tx.from_idx = i;
            tx.to_idx = (i + 1) % 100;
            txs.push(tx);
        }

        let original = InputToSer {
            state_deltas: 200,
            fee_atoms: 10,
            fee_recipient: [0xAB; 20],
            tx: txs,
        };

        let serialized = original.ser();
        let input = Input::new(&serialized);

        assert_eq!(input.total_tx(), 100);

        // Spot check a few transactions
        for i in [0, 49, 99] {
            let tx = input.tx_at(i);
            let orig_tx = &original.tx[i as usize];
            assert_eq!(tx.nonce(), orig_tx.nonce);
            assert_eq!(tx.atoms(), orig_tx.atoms);
            assert_eq!(tx.from_idx(), orig_tx.from_idx);
            assert_eq!(tx.to_idx(), orig_tx.to_idx);
        }
    }
}
