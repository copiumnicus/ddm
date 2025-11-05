use bellman::{gadgets::multipack, groth16};
use blake2::{Blake2s256, Digest};
use bls12_381::Bls12;
use ddm::hash::Blake2sScalarHashCircuit;
use ff::PrimeField;
use rand::rngs::OsRng;

fn main() {
    // 1. Setup
    let params = {
        let c = Blake2sScalarHashCircuit::<bls12_381::Scalar> { input_scalar: None };
        groth16::generate_random_parameters::<Bls12, _, _>(c, &mut OsRng).unwrap()
    };
    let pvk = groth16::prepare_verifying_key(&params.vk);

    // 2. Choose a scalar preimage
    let x = bls12_381::Scalar::from(42u64); // whatever

    // 3. Compute BLAKE2s(preimage_bytes) with the *same* personalization
    let repr = x.to_repr(); // canonical 32-byte repr

    let mut hasher = Blake2s256::new();
    hasher.update(&repr);
    let hash_bytes = hasher.finalize().to_vec();

    // 4. Convert hash bytes → bits → public inputs (scalars)
    let hash_bits = multipack::bytes_to_bits_le(&hash_bytes);
    let public_inputs = multipack::compute_multipacking(&hash_bits);

    // 5. Prove
    let circuit = Blake2sScalarHashCircuit {
        input_scalar: Some(x),
    };
    let proof = groth16::create_random_proof(circuit, &params, &mut OsRng).unwrap();

    // 6. Verify: public_inputs is your “hashed_scalar” vector
    assert!(groth16::verify_proof(&pvk, &proof, &public_inputs).is_ok());
    println!("Proof verified!");
}
