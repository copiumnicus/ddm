use bellman::groth16;
use bls12_381::{Bls12, Scalar};
use ddm::N;
use ddm::SettlementCircuit;
use ff::Field;
use rand::thread_rng;
use std::time::Instant;

fn fr(x: u64) -> Scalar {
    Scalar::from(x)
}

// Helper: [None; N] for Option<Scalar>
fn none_array() -> [Option<Scalar>; N] {
    std::array::from_fn(|_| None)
}

fn main() {
    let mut rng = thread_rng();

    // ------------------------------
    // 1. Setup (trusted ceremony)
    // ------------------------------
    // We run parameter generation on a circuit with no assignments (all None).
    let empty_circuit = SettlementCircuit::<Scalar> {
        recipient: None,
        k_old: None,
        m: None,
        total_settle: None,
        to: none_array(),
        size: none_array(),
        nonce: none_array(),
    };

    let params = groth16::generate_random_parameters::<Bls12, _, _>(empty_circuit, &mut rng)
        .expect("parameter generation should succeed");

    let pvk = groth16::prepare_verifying_key(&params.vk);

    // ------------------------------
    // 2. Build a concrete witness
    // ------------------------------
    let offset = 11;
    let recipient_val = fr(42);
    let k_old_val = fr(10);
    let size_val_u64 = 5u64;
    let total_settle_val = fr(size_val_u64 * N as u64);
    let m_val = fr((N + offset) as u64); // max nonce

    // Fill arrays of Option<Scalar>
    let mut to = none_array();
    let mut size = none_array();
    let mut nonce = none_array();

    for i in 0..N {
        to[i] = Some(recipient_val);
        size[i] = Some(fr(size_val_u64));
        nonce[i] = Some(fr((i + offset) as u64));
    }

    // This is the circuit WITH a concrete assignment
    let circuit = SettlementCircuit::<Scalar> {
        recipient: Some(recipient_val),
        k_old: Some(k_old_val),
        m: Some(m_val),
        total_settle: Some(total_settle_val),
        to,
        size,
        nonce,
    };

    let _k = Instant::now();
    // ------------------------------
    // 3. Prove
    // ------------------------------
    let proof = groth16::create_random_proof(circuit, &params, &mut rng)
        .expect("proof generation should succeed");

    println!("proof gen {:?}", _k.elapsed());

    // ------------------------------
    // 4. Verify
    // ------------------------------
    //
    // IMPORTANT: public inputs must be in the SAME ORDER as you called
    // `inputize` in `synthesize`:
    //
    //   recipient.inputize(...)   => index 0
    //   k_old.inputize(...)       => index 1
    //   m.inputize(...)           => index 2
    //   total_settle.inputize(...)=> index 3
    //
    let public_inputs = [recipient_val, k_old_val, m_val, total_settle_val];
    let wrong_inputs = [k_old_val, m_val, total_settle_val, recipient_val];

    groth16::verify_proof(&pvk, &proof, &public_inputs).expect("verification should not error");

    // should fail
    assert!(groth16::verify_proof(&pvk, &proof, &wrong_inputs).is_err());
}
