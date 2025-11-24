use alloy_sol_types::sol;
use serde::{Deserialize, Serialize};

sol! {
    /// The public values encoded as a struct that can be easily deserialized inside Solidity.
    struct PublicValuesStruct {
        uint32 n;
        uint32 a;
        uint32 b;
    }
}

/// Compute the n'th fibonacci number (wrapping around on overflows), using normal Rust code.
pub fn fibonacci(n: u32) -> (u32, u32) {
    let mut a = 0u32;
    let mut b = 1u32;
    for _ in 0..n {
        let c = a.wrapping_add(b);
        a = b;
        b = c;
    }
    (a, b)
}

// ============================================================================
// Signature Data Structures
// ============================================================================

/// ECDSA signature data over secp256k1
/// Contains a message hash, signature, and public key as byte arrays
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EcdsaSecp256k1Data {
    /// SHA-256 hash of the message (32 bytes)
    pub message_hash: [u8; 32],
    /// ECDSA signature in compact format (64 bytes: r || s)
    pub signature: Vec<u8>,
    /// Compressed public key (33 bytes: 0x02/0x03 || x) - cheaper than uncompressed!
    pub public_key: Vec<u8>,
    /// Recovery ID for public key recovery (0-3)
    pub recovery_id: u8,
}

/// Schnorr signature data over secp256k1
/// Contains a message hash, signature, and public key as byte arrays
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SchnorrSecp256k1Data {
    /// SHA-256 hash of the message (32 bytes)
    pub message_hash: [u8; 32],
    /// Schnorr signature (64 bytes: r || s)
    pub signature: Vec<u8>,
    /// X-only public key (32 bytes)
    pub public_key: [u8; 32],
}

/// EdDSA (Ed25519) signature data
/// Contains a message, signature, and public key as byte arrays
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Ed25519Data {
    /// The message (variable length, but we'll use a fixed size for testing)
    pub message: Vec<u8>,
    /// Ed25519 signature (64 bytes: R || s)
    pub signature: Vec<u8>,
    /// Ed25519 public key (32 bytes)
    pub public_key: [u8; 32],
}

/// Composite structure containing all signature types for testing
/// This will be passed into the RISC-V VM program to test verification
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignatureTestData {
    pub ecdsa: EcdsaSecp256k1Data,
    pub schnorr: SchnorrSecp256k1Data,
    pub ed25519: Ed25519Data,
}

// ============================================================================
// Helper Functions for ECDSA
// ============================================================================

impl EcdsaSecp256k1Data {
    /// Verify the ECDSA signature using compressed public key
    pub fn verify(&self) -> bool {
        use k256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
        use k256::PublicKey;

        // Direct construction from fixed-size arrays
        let signature = Signature::from_slice(&self.signature).unwrap();

        // Use compressed key format (33 bytes) - much cheaper than uncompressed
        let public_key = PublicKey::from_sec1_bytes(&self.public_key).unwrap();
        let verifying_key = VerifyingKey::from(public_key);

        verifying_key.verify(&self.message_hash, &signature).is_ok()
    }

    /// Recover the public key from the signature (optimal pattern)
    pub fn recover(&self) -> [u8; 33] {
        use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};

        // Direct construction from fixed-size array
        let signature = Signature::from_slice(&self.signature).unwrap();
        let recovery_id = RecoveryId::from_byte(self.recovery_id).unwrap();
        let recovered_key = VerifyingKey::recover_from_prehash(&self.message_hash, &signature, recovery_id).unwrap();

        // Return compressed public key (33 bytes)
        recovered_key.to_encoded_point(true).as_bytes()[..33].try_into().unwrap()
    }
}

// ============================================================================
// Helper Functions for Schnorr
// ============================================================================

impl SchnorrSecp256k1Data {
    /// Verify the Schnorr signature using direct byte arrays
    pub fn verify(&self) -> bool {
        use k256::schnorr::{signature::Verifier, Signature, VerifyingKey};

        // Direct construction from fixed-size arrays
        let signature = Signature::try_from(&self.signature[..]).unwrap();
        let verifying_key = VerifyingKey::from_bytes(&self.public_key).unwrap();

        verifying_key.verify(&self.message_hash, &signature).is_ok()
    }

    /// Batch verify multiple Schnorr signatures
    /// NOTE: True mathematical batch verification (single multiscalar multiplication)
    /// is not yet possible due to SP1-patched k256 API limitations.
    /// This performs optimized individual verification for now.
    pub fn batch_verify(signatures: &[SchnorrSecp256k1Data]) -> usize {
        use k256::schnorr::{signature::Verifier, Signature, VerifyingKey};

        signatures
            .iter()
            .filter(|sig_data| {
                let signature = Signature::try_from(&sig_data.signature[..]).unwrap();
                let verifying_key = VerifyingKey::from_bytes(&sig_data.public_key).unwrap();
                verifying_key.verify(&sig_data.message_hash, &signature).is_ok()
            })
            .count()
    }
}

// ============================================================================
// Helper Functions for Ed25519
// ============================================================================

impl Ed25519Data {
    /// Verify Ed25519 signature using curve25519_dalek primitives
    /// Verification equation: R + H(R||A||M) * A == s * B
    pub fn verify(&self) -> bool {
        use curve25519_dalek::{
            constants::ED25519_BASEPOINT_TABLE,
            edwards::CompressedEdwardsY,
            scalar::Scalar,
        };
        use sha2::{Digest, Sha512};

        // Signature is (R, s) - split into two 32-byte arrays directly
        let r_bytes: [u8; 32] = self.signature[0..32].try_into().unwrap();
        let s_bytes: [u8; 32] = self.signature[32..64].try_into().unwrap();

        // Parse R
        let r_point = match CompressedEdwardsY(r_bytes).decompress() {
            Some(p) => p,
            None => return false,
        };

        // Parse s
        let s = Scalar::from_bytes_mod_order(s_bytes);

        // Parse public key A
        let a_point = match CompressedEdwardsY(self.public_key).decompress() {
            Some(p) => p,
            None => return false,
        };

        // Compute H(R||A||M) using SHA-512
        let mut hasher = Sha512::new();
        hasher.update(&r_bytes);
        hasher.update(&self.public_key);
        hasher.update(&self.message);
        let hash = hasher.finalize();

        // Convert hash to scalar
        let h = Scalar::from_bytes_mod_order_wide(&hash.into());

        // Verify: R + H * A == s * B
        let lhs = r_point + (h * a_point);
        let rhs = ED25519_BASEPOINT_TABLE * &s;

        lhs == rhs
    }
}

// ============================================================================
// Helper Functions for SignatureTestData
// ============================================================================

impl SignatureTestData {
    /// Verify all signatures in the test data
    pub fn verify_all(&self) -> bool {
        self.ecdsa.verify() && self.schnorr.verify() && self.ed25519.verify()
    }

    /// Serialize to bincode
    pub fn to_bincode(&self) -> Result<Vec<u8>, bincode::Error> {
        bincode::serialize(self)
    }

    /// Deserialize from bincode
    pub fn from_bincode(bytes: &[u8]) -> Result<Self, bincode::Error> {
        bincode::deserialize(bytes)
    }
}

// ============================================================================
// Test Helper Functions
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper function to create SHA-256 hash
    fn sha256(data: &[u8]) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(data);
        hasher.finalize().into()
    }

    /// Create sample ECDSA test data with a valid signature
    fn create_sample_ecdsa() -> EcdsaSecp256k1Data {
        use k256::ecdsa::{signature::Signer, SigningKey, RecoveryId, VerifyingKey};

        // Create a deterministic signing key for testing
        let secret_bytes = [0x42u8; 32];
        let signing_key = SigningKey::from_bytes(&secret_bytes.into()).unwrap();
        let verifying_key = signing_key.verifying_key();

        // Create a message and hash it
        let message = b"Hello, ECDSA over secp256k1!";
        let message_hash = sha256(message);

        // Sign the hash
        let signature: k256::ecdsa::Signature = signing_key.sign(&message_hash);

        // Get the public key in COMPRESSED format (33 bytes) - much cheaper to parse than uncompressed!
        let public_key_point = verifying_key.to_encoded_point(true);
        let public_key = public_key_point.as_bytes()[..33].to_vec();

        // Get the signature bytes (64 bytes: r || s)
        let signature: Vec<u8> = signature.to_bytes().to_vec();

        // Find the correct recovery_id by trying all possibilities
        let mut recovery_id = 0u8;
        for i in 0u8..4u8 {
            if let Some(rec_id) = RecoveryId::from_byte(i) {
                if let Ok(recovered) = VerifyingKey::recover_from_prehash(&message_hash, &k256::ecdsa::Signature::from_slice(&signature).unwrap(), rec_id) {
                    if recovered == *verifying_key {
                        recovery_id = i;
                        break;
                    }
                }
            }
        }

        EcdsaSecp256k1Data {
            message_hash,
            signature,
            public_key,
            recovery_id,
        }
    }

    /// Create sample Schnorr test data with a valid signature
    fn create_sample_schnorr() -> SchnorrSecp256k1Data {
        use k256::schnorr::{signature::Signer, SigningKey};

        // Create a deterministic signing key for testing
        let secret_bytes = [0x43u8; 32];
        let signing_key = SigningKey::from_bytes(&secret_bytes).unwrap();
        let verifying_key = signing_key.verifying_key();

        // Create a message and hash it
        let message = b"Hello, Schnorr over secp256k1!";
        let message_hash = sha256(message);

        // Sign the hash
        let signature: k256::schnorr::Signature = signing_key.sign(&message_hash);

        // Get the x-only public key (32 bytes)
        let public_key: [u8; 32] = verifying_key.to_bytes().into();

        // Get the signature bytes (64 bytes)
        let signature: Vec<u8> = signature.to_bytes().to_vec();

        SchnorrSecp256k1Data {
            message_hash,
            signature,
            public_key,
        }
    }

    /// Create sample Ed25519 test data with a valid signature
    fn create_sample_ed25519() -> Ed25519Data {
        use curve25519_dalek::{constants::ED25519_BASEPOINT_TABLE, scalar::Scalar};
        use sha2::{Digest, Sha512};

        // Create a deterministic secret scalar
        let secret_bytes = [0x44u8; 32];
        let secret_scalar = Scalar::from_bytes_mod_order(secret_bytes);

        // Compute public key A = secret * B
        let public_key_point = ED25519_BASEPOINT_TABLE * &secret_scalar;
        let public_key = public_key_point.compress().to_bytes();

        // Create a message
        let message = b"Hello, Ed25519!";

        // Generate nonce r = H(secret || message) mod L
        let mut nonce_hasher = Sha512::new();
        nonce_hasher.update(&secret_bytes);
        nonce_hasher.update(message);
        let nonce_hash = nonce_hasher.finalize();
        let r = Scalar::from_bytes_mod_order_wide(&nonce_hash.into());

        // Compute R = r * B
        let r_point = ED25519_BASEPOINT_TABLE * &r;
        let r_bytes = r_point.compress().to_bytes();

        // Compute challenge H(R || A || M)
        let mut challenge_hasher = Sha512::new();
        challenge_hasher.update(&r_bytes);
        challenge_hasher.update(&public_key);
        challenge_hasher.update(message);
        let challenge_hash = challenge_hasher.finalize();
        let h = Scalar::from_bytes_mod_order_wide(&challenge_hash.into());

        // Compute s = r + h * secret (mod L)
        let s = r + (h * secret_scalar);
        let s_bytes = s.to_bytes();

        // Signature is (R, s)
        let mut signature = Vec::with_capacity(64);
        signature.extend_from_slice(&r_bytes);
        signature.extend_from_slice(&s_bytes);

        Ed25519Data {
            message: message.to_vec(),
            signature,
            public_key,
        }
    }

    /// Create complete sample signature test data
    pub fn create_sample_signature_test_data() -> SignatureTestData {
        SignatureTestData {
            ecdsa: create_sample_ecdsa(),
            schnorr: create_sample_schnorr(),
            ed25519: create_sample_ed25519(),
        }
    }

    #[test]
    fn test_ecdsa_data() {
        let ecdsa = create_sample_ecdsa();
        assert_eq!(ecdsa.message_hash.len(), 32);
        assert_eq!(ecdsa.signature.len(), 64);
        assert_eq!(ecdsa.public_key.len(), 65);
        assert_eq!(ecdsa.public_key[0], 0x04); // Uncompressed format marker

        // Test verification
        assert!(ecdsa.verify());
    }

    #[test]
    fn test_schnorr_data() {
        let schnorr = create_sample_schnorr();
        assert_eq!(schnorr.message_hash.len(), 32);
        assert_eq!(schnorr.signature.len(), 64);
        assert_eq!(schnorr.public_key.len(), 32);

        // Test verification
        assert!(schnorr.verify());
    }

    #[test]
    fn test_ed25519_data() {
        let ed25519 = create_sample_ed25519();
        assert!(ed25519.message.len() > 0);
        assert_eq!(ed25519.signature.len(), 64);
        assert_eq!(ed25519.public_key.len(), 32);

        // Test verification
        assert!(ed25519.verify());
    }

    #[test]
    fn test_signature_test_data() {
        let test_data = create_sample_signature_test_data();

        // Test individual verifications
        assert!(test_data.ecdsa.verify());
        assert!(test_data.schnorr.verify());
        assert!(test_data.ed25519.verify());

        // Test verify_all
        assert!(test_data.verify_all());
    }

    #[test]
    fn test_bincode_serialization() {
        let test_data = create_sample_signature_test_data();

        // Serialize
        let serialized = test_data.to_bincode().expect("Failed to serialize");
        assert!(serialized.len() > 0);

        // Deserialize
        let deserialized =
            SignatureTestData::from_bincode(&serialized).expect("Failed to deserialize");

        // Verify they are equal
        assert_eq!(test_data, deserialized);

        // Verify the deserialized data still works
        assert!(deserialized.verify_all());
    }

    #[test]
    fn test_all_signature_types() {
        let test_data = create_sample_signature_test_data();

        println!(
            "ECDSA message hash: {:?}",
            hex::encode(&test_data.ecdsa.message_hash)
        );
        println!(
            "ECDSA signature: {:?}",
            hex::encode(&test_data.ecdsa.signature)
        );
        println!(
            "ECDSA public key: {:?}",
            hex::encode(&test_data.ecdsa.public_key)
        );

        println!(
            "\nSchnorr message hash: {:?}",
            hex::encode(&test_data.schnorr.message_hash)
        );
        println!(
            "Schnorr signature: {:?}",
            hex::encode(&test_data.schnorr.signature)
        );
        println!(
            "Schnorr public key: {:?}",
            hex::encode(&test_data.schnorr.public_key)
        );

        println!(
            "\nEd25519 message: {:?}",
            String::from_utf8_lossy(&test_data.ed25519.message)
        );
        println!(
            "Ed25519 signature: {:?}",
            hex::encode(&test_data.ed25519.signature)
        );
        println!(
            "Ed25519 public key: {:?}",
            hex::encode(&test_data.ed25519.public_key)
        );

        // Verify all signatures
        assert!(test_data.verify_all(), "All signatures should verify");
    }
}

// Make the sample data creation function public for use in other crates
#[cfg(not(test))]
pub fn create_sample_signature_test_data() -> SignatureTestData {
    use k256::ecdsa::{signature::Signer as EcdsaSigner, SigningKey as EcdsaSigningKey};
    use k256::elliptic_curve::sec1::ToEncodedPoint;
    use k256::schnorr::{signature::Signer as SchnorrSigner, SigningKey as SchnorrSigningKey};
    use sha2::{Digest, Sha256, Sha512};

    fn sha256(data: &[u8]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(data);
        hasher.finalize().into()
    }

    // ECDSA
    let ecdsa_secret = [0x42u8; 32];
    let ecdsa_signing_key = EcdsaSigningKey::from_bytes(&ecdsa_secret.into()).unwrap();
    let ecdsa_verifying_key = ecdsa_signing_key.verifying_key();
    let ecdsa_message = b"Hello, ECDSA over secp256k1!";
    let ecdsa_message_hash = sha256(ecdsa_message);
    let ecdsa_signature: k256::ecdsa::Signature = ecdsa_signing_key.sign(&ecdsa_message_hash);

    // Use COMPRESSED public key (33 bytes) - much cheaper to parse than uncompressed!
    let ecdsa_public_key_point = ecdsa_verifying_key.to_encoded_point(true);
    let ecdsa_public_key = ecdsa_public_key_point.as_bytes()[..33].to_vec();

    // Signature bytes (64 bytes)
    let ecdsa_signature_bytes: Vec<u8> = ecdsa_signature.to_bytes().to_vec();

    // Find the correct recovery_id
    use k256::ecdsa::{RecoveryId, VerifyingKey as EcdsaVerifyingKey};
    let mut ecdsa_recovery_id = 0u8;
    for i in 0u8..4u8 {
        if let Some(rec_id) = RecoveryId::from_byte(i) {
            if let Ok(recovered) = EcdsaVerifyingKey::recover_from_prehash(&ecdsa_message_hash, &k256::ecdsa::Signature::from_slice(&ecdsa_signature_bytes).unwrap(), rec_id) {
                if recovered == *ecdsa_verifying_key {
                    ecdsa_recovery_id = i;
                    break;
                }
            }
        }
    }

    // Schnorr
    let schnorr_secret = [0x43u8; 32];
    let schnorr_signing_key = SchnorrSigningKey::from_bytes(&schnorr_secret).unwrap();
    let schnorr_verifying_key = schnorr_signing_key.verifying_key();
    let schnorr_message = b"Hello, Schnorr over secp256k1!";
    let schnorr_message_hash = sha256(schnorr_message);
    let schnorr_signature: k256::schnorr::Signature =
        schnorr_signing_key.sign(&schnorr_message_hash);
    let schnorr_public_key: [u8; 32] = schnorr_verifying_key.to_bytes().into();
    let schnorr_signature_bytes: Vec<u8> = schnorr_signature.to_bytes().to_vec();

    // Ed25519 using curve25519-dalek
    use curve25519_dalek::{constants::ED25519_BASEPOINT_TABLE, scalar::Scalar};

    let ed25519_secret = [0x44u8; 32];
    let secret_scalar = Scalar::from_bytes_mod_order(ed25519_secret);

    // Compute public key A = secret * B
    let public_key_point = ED25519_BASEPOINT_TABLE * &secret_scalar;
    let ed25519_public_key = public_key_point.compress().to_bytes();

    let ed25519_message = b"Hello, Ed25519!";

    // Generate nonce r = H(secret || message) mod L
    let mut nonce_hasher = Sha512::new();
    nonce_hasher.update(&ed25519_secret);
    nonce_hasher.update(ed25519_message);
    let nonce_hash = nonce_hasher.finalize();
    let r = Scalar::from_bytes_mod_order_wide(&nonce_hash.into());

    // Compute R = r * B
    let r_point = ED25519_BASEPOINT_TABLE * &r;
    let r_bytes = r_point.compress().to_bytes();

    // Compute challenge H(R || A || M)
    let mut challenge_hasher = Sha512::new();
    challenge_hasher.update(&r_bytes);
    challenge_hasher.update(&ed25519_public_key);
    challenge_hasher.update(ed25519_message);
    let challenge_hash = challenge_hasher.finalize();
    let h = Scalar::from_bytes_mod_order_wide(&challenge_hash.into());

    // Compute s = r + h * secret (mod L)
    let s = r + (h * secret_scalar);
    let s_bytes = s.to_bytes();

    // Signature is (R, s)
    let mut ed25519_signature_bytes = Vec::with_capacity(64);
    ed25519_signature_bytes.extend_from_slice(&r_bytes);
    ed25519_signature_bytes.extend_from_slice(&s_bytes);

    SignatureTestData {
        ecdsa: EcdsaSecp256k1Data {
            message_hash: ecdsa_message_hash,
            signature: ecdsa_signature_bytes,
            public_key: ecdsa_public_key,
            recovery_id: ecdsa_recovery_id,
        },
        schnorr: SchnorrSecp256k1Data {
            message_hash: schnorr_message_hash,
            signature: schnorr_signature_bytes,
            public_key: schnorr_public_key,
        },
        ed25519: Ed25519Data {
            message: ed25519_message.to_vec(),
            signature: ed25519_signature_bytes,
            public_key: ed25519_public_key,
        },
    }
}
