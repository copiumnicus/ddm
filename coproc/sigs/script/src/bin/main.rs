//! An end-to-end example of using the SP1 SDK to generate a proof of a program that can be executed
//! or have a core proof generated.
//!
//! You can run this script using the following command:
//! ```shell
//! RUST_LOG=info cargo run --release -- --execute
//! ```
//! or
//! ```shell
//! RUST_LOG=info cargo run --release -- --prove
//! ```

use alloy_sol_types::SolType;
use clap::Parser;
use fibonacci_lib::{create_sample_signature_test_data, PublicValuesStruct, SignatureTestData};
use sp1_sdk::{include_elf, ProverClient, SP1Stdin};

// Cryptographic imports
use k256::{
    ecdsa::{
        signature::Signer as EcdsaSigner,
        signature::Verifier as EcdsaVerifier,
        Signature as EcdsaSignature,
        SigningKey as EcdsaSigningKey,
        VerifyingKey as EcdsaVerifyingKey,
    },
    schnorr::{
        Signature as SchnorrSignature,
        SigningKey as SchnorrSigningKey,
        VerifyingKey as SchnorrVerifyingKey,
    },
};
use ed25519_dalek::{
    Signature as EdSignature,
    SigningKey as EdSigningKey,
    VerifyingKey as EdVerifyingKey,
};
use rand_core::OsRng;
use sha2::{Digest, Sha256};
use tiny_keccak::{Hasher, Keccak};

/// The ELF (executable and linkable format) file for the Succinct RISC-V zkVM.
pub const FIBONACCI_ELF: &[u8] = include_elf!("fibonacci-program");

/// The arguments for the command.
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(long)]
    execute: bool,

    #[arg(long)]
    prove: bool,

    #[arg(long, default_value = "20")]
    n: u32,
}

fn main() {
    // Setup the logger.
    sp1_sdk::utils::setup_logger();
    dotenv::dotenv().ok();

    // Parse the command line arguments.
    let args = Args::parse();

    if args.execute == args.prove {
        eprintln!("Error: You must specify either --execute or --prove");
        std::process::exit(1);
    }

    // Setup the prover client.
    let client = ProverClient::from_env();

    // Create a vector of 10 signature test data instances
    println!("Creating 10 signature test data instances...");
    let signature_test_data: Vec<SignatureTestData> = (0..10)
        .map(|_| create_sample_signature_test_data())
        .collect();

    println!("Created {} signature test data instances", signature_test_data.len());

    // Setup the inputs - serialize the vector with bincode
    let mut stdin = SP1Stdin::new();
    stdin.write(&signature_test_data);

    if args.execute {
        // Execute the program
        println!("Executing signature verification program...");
        let (output, report) = client.execute(FIBONACCI_ELF, &stdin).run().unwrap();
        println!("Program executed successfully.");

        // The program will output cycle tracking information
        // Read the output (empty for now, but we can add public values later)
        println!("\n=== Execution Report ===");
        println!("Total instruction count: {}", report.total_instruction_count());
        println!("Total cycles: {}", report.total_instruction_count());

    } else {
        // Setup the program for proving.
        println!("Setting up program for proving...");
        let (pk, vk) = client.setup(FIBONACCI_ELF);

        // Generate the proof
        println!("Generating proof...");
        let proof = client
            .prove(&pk, &stdin)
            .run()
            .expect("failed to generate proof");

        println!("Successfully generated proof!");

        // Verify the proof.
        client.verify(&proof, &vk).expect("failed to verify proof");
        println!("Successfully verified proof!");
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Hash a message using Keccak-256
pub fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak::v256();
    let mut output = [0u8; 32];
    hasher.update(data);
    hasher.finalize(&mut output);
    output
}

/// Hash a message using SHA-256
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

// ============================================================================
// ECDSA over secp256k1
// ============================================================================

/// Generate a new ECDSA keypair
pub fn ecdsa_generate_keypair() -> (EcdsaSigningKey, EcdsaVerifyingKey) {
    let signing_key = EcdsaSigningKey::random(&mut OsRng);
    let verifying_key = *signing_key.verifying_key();
    (signing_key, verifying_key)
}

/// Sign a message using ECDSA over secp256k1
/// The message is hashed with SHA-256 before signing
pub fn ecdsa_sign(signing_key: &EcdsaSigningKey, message: &[u8]) -> EcdsaSignature {
    // Hash the message with SHA-256
    let message_hash = sha256(message);

    // Sign the hash
    signing_key.sign(&message_hash)
}

/// Sign a pre-hashed message using ECDSA over secp256k1
pub fn ecdsa_sign_prehashed(signing_key: &EcdsaSigningKey, message_hash: &[u8; 32]) -> EcdsaSignature {
    signing_key.sign(message_hash)
}

/// Verify an ECDSA signature over secp256k1
/// The message is hashed with SHA-256 before verification
pub fn ecdsa_verify(
    verifying_key: &EcdsaVerifyingKey,
    message: &[u8],
    signature: &EcdsaSignature,
) -> Result<(), Box<dyn std::error::Error>> {
    // Hash the message with SHA-256
    let message_hash = sha256(message);

    // Verify the signature
    verifying_key.verify(&message_hash, signature)
        .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)
}

/// Verify an ECDSA signature over secp256k1 with a pre-hashed message
pub fn ecdsa_verify_prehashed(
    verifying_key: &EcdsaVerifyingKey,
    message_hash: &[u8; 32],
    signature: &EcdsaSignature,
) -> Result<(), Box<dyn std::error::Error>> {
    verifying_key.verify(message_hash, signature)
        .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)
}

// ============================================================================
// Schnorr over secp256k1
// ============================================================================

/// Generate a new Schnorr keypair
pub fn schnorr_generate_keypair() -> (SchnorrSigningKey, SchnorrVerifyingKey) {
    let signing_key = SchnorrSigningKey::random(&mut OsRng);
    let verifying_key = *signing_key.verifying_key();
    (signing_key, verifying_key)
}

/// Sign a message using Schnorr signatures over secp256k1
/// The message is hashed with SHA-256 before signing
pub fn schnorr_sign(signing_key: &SchnorrSigningKey, message: &[u8]) -> SchnorrSignature {
    // Hash the message with SHA-256
    let message_hash = sha256(message);

    // Sign the hash
    signing_key.sign(&message_hash)
}

/// Sign a pre-hashed message using Schnorr signatures over secp256k1
pub fn schnorr_sign_prehashed(signing_key: &SchnorrSigningKey, message_hash: &[u8; 32]) -> SchnorrSignature {
    signing_key.sign(message_hash)
}

/// Verify a Schnorr signature over secp256k1
/// The message is hashed with SHA-256 before verification
pub fn schnorr_verify(
    verifying_key: &SchnorrVerifyingKey,
    message: &[u8],
    signature: &SchnorrSignature,
) -> Result<(), Box<dyn std::error::Error>> {
    // Hash the message with SHA-256
    let message_hash = sha256(message);

    // Verify the signature
    verifying_key.verify(&message_hash, signature)
        .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)
}

/// Verify a Schnorr signature over secp256k1 with a pre-hashed message
pub fn schnorr_verify_prehashed(
    verifying_key: &SchnorrVerifyingKey,
    message_hash: &[u8; 32],
    signature: &SchnorrSignature,
) -> Result<(), Box<dyn std::error::Error>> {
    verifying_key.verify(message_hash, signature)
        .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)
}

// ============================================================================
// EdDSA (Ed25519)
// ============================================================================

/// Generate a new Ed25519 keypair
pub fn eddsa_generate_keypair() -> (EdSigningKey, EdVerifyingKey) {
    let signing_key = EdSigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();
    (signing_key, verifying_key)
}

/// Sign a message using EdDSA (Ed25519)
/// Note: Ed25519 handles hashing internally, so we don't pre-hash
pub fn eddsa_sign(signing_key: &EdSigningKey, message: &[u8]) -> EdSignature {
    signing_key.sign(message)
}

/// Verify an EdDSA (Ed25519) signature
pub fn eddsa_verify(
    verifying_key: &EdVerifyingKey,
    message: &[u8],
    signature: &EdSignature,
) -> Result<(), Box<dyn std::error::Error>> {
    verifying_key.verify(message, signature)
        .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)
}

// ============================================================================
// Tests and Demo Functions
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ecdsa_sign_verify() {
        let (signing_key, verifying_key) = ecdsa_generate_keypair();
        let message = b"Hello, ECDSA!";

        let signature = ecdsa_sign(&signing_key, message);
        let result = ecdsa_verify(&verifying_key, message, &signature);

        assert!(result.is_ok());
    }

    #[test]
    fn test_schnorr_sign_verify() {
        let (signing_key, verifying_key) = schnorr_generate_keypair();
        let message = b"Hello, Schnorr!";

        let signature = schnorr_sign(&signing_key, message);
        let result = schnorr_verify(&verifying_key, message, &signature);

        assert!(result.is_ok());
    }

    #[test]
    fn test_eddsa_sign_verify() {
        let (signing_key, verifying_key) = eddsa_generate_keypair();
        let message = b"Hello, EdDSA!";

        let signature = eddsa_sign(&signing_key, message);
        let result = eddsa_verify(&verifying_key, message, &signature);

        assert!(result.is_ok());
    }

    #[test]
    fn test_keccak256() {
        let data = b"test data";
        let hash = keccak256(data);
        assert_eq!(hash.len(), 32);
    }

    #[test]
    fn test_sha256() {
        let data = b"test data";
        let hash = sha256(data);
        assert_eq!(hash.len(), 32);
    }
}
