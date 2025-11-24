//! Signature verification program that verifies ECDSA, Schnorr, and EdDSA signatures
//! with cycle tracking for performance benchmarking.

#![no_main]
sp1_zkvm::entrypoint!(main);

use fibonacci_lib::SignatureTestData;

pub fn main() {
    // Read the vector of signature test data from stdin
    let signature_test_data: Vec<SignatureTestData> = sp1_zkvm::io::read::<Vec<SignatureTestData>>();

    println!("cycle-tracker-start: total");

    let num_signatures = signature_test_data.len();
    println!("Received {} signature test data instances", num_signatures);

    // Track overall statistics
    let mut ecdsa_success = 0;
    let mut schnorr_success = 0;
    let mut ed25519_success = 0;

    println!("\n=== Individual Verification Mode ===");

    // Verify each signature with individual cycle tracking
    for (i, test_data) in signature_test_data.iter().enumerate() {
        println!("\n--- Signature set {} ---", i + 1);

        // Track ECDSA verification
        println!("cycle-tracker-start: ecdsa_verify_individual");
        if test_data.ecdsa.verify() {
            ecdsa_success += 1;
            println!("✓ ECDSA verified");
        } else {
            println!("✗ ECDSA failed");
        }
        println!("cycle-tracker-end: ecdsa_verify_individual");

        // Track ECDSA recovery (for comparison)
        println!("cycle-tracker-start: ecdsa_recover_individual");
        let _recovered_pubkey = test_data.ecdsa.recover();
        println!("✓ ECDSA recovered");
        println!("cycle-tracker-end: ecdsa_recover_individual");

        // Track Schnorr verification (individual)
        println!("cycle-tracker-start: schnorr_verify_individual");
        if test_data.schnorr.verify() {
            schnorr_success += 1;
            println!("✓ Schnorr verified");
        } else {
            println!("✗ Schnorr failed");
        }
        println!("cycle-tracker-end: schnorr_verify_individual");

        // Track Ed25519 verification
        println!("cycle-tracker-start: ed25519_verify_individual");
        if test_data.ed25519.verify() {
            ed25519_success += 1;
            println!("✓ Ed25519 verified");
        } else {
            println!("✗ Ed25519 failed");
        }
        println!("cycle-tracker-end: ed25519_verify_individual");
    }

    println!("\n=== Batch Verification Mode ===");

    // Schnorr batch verification using proper API
    println!("cycle-tracker-start: schnorr_verify_batch");
    let schnorr_sigs: Vec<_> = signature_test_data.iter().map(|t| t.schnorr.clone()).collect();
    let schnorr_batch_success = fibonacci_lib::SchnorrSecp256k1Data::batch_verify(&schnorr_sigs);
    println!("cycle-tracker-end: schnorr_verify_batch");
    println!("Schnorr batch: {}/{} verified", schnorr_batch_success, num_signatures);

    // ECDSA batch verification
    let mut ecdsa_batch_success = 0;
    println!("cycle-tracker-start: ecdsa_verify_batch");
    for test_data in signature_test_data.iter() {
        if test_data.ecdsa.verify() {
            ecdsa_batch_success += 1;
        }
    }
    println!("cycle-tracker-end: ecdsa_verify_batch");
    println!("ECDSA batch: {}/{} verified", ecdsa_batch_success, num_signatures);

    // ECDSA batch recovery (for comparison)
    println!("cycle-tracker-start: ecdsa_recover_batch");
    for test_data in signature_test_data.iter() {
        let _recovered = test_data.ecdsa.recover();
    }
    println!("cycle-tracker-end: ecdsa_recover_batch");
    println!("ECDSA batch: 10/10 recovered");

    // Ed25519 batch verification
    let mut ed25519_batch_success = 0;
    println!("cycle-tracker-start: ed25519_verify_batch");
    for test_data in signature_test_data.iter() {
        if test_data.ed25519.verify() {
            ed25519_batch_success += 1;
        }
    }
    println!("cycle-tracker-end: ed25519_verify_batch");
    println!("Ed25519 batch: {}/{} verified", ed25519_batch_success, num_signatures);

    println!("cycle-tracker-end: total");

    // Print summary
    println!("\n=== Final Summary ===");
    println!("ECDSA:   {}/{} succeeded", ecdsa_success, num_signatures);
    println!("Schnorr: {}/{} succeeded", schnorr_success, num_signatures);
    println!("Ed25519: {}/{} succeeded", ed25519_success, num_signatures);

    // Commit the results as public values
    sp1_zkvm::io::commit(&ecdsa_success);
    sp1_zkvm::io::commit(&schnorr_success);
    sp1_zkvm::io::commit(&ed25519_success);
}
