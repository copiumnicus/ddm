use bellman::groth16;
use bls12_381::{Bls12, Scalar};
use ddm::N;
use ddm::SettlementCircuit;
use ff::Field;
use rand::thread_rng;
use std::fmt;
use std::time::Duration;
use std::time::Instant;

fn fr(x: u64) -> Scalar {
    Scalar::from(x)
}

// Helper: [None; N] for Option<Scalar>
fn none_array() -> [Option<Scalar>; N] {
    std::array::from_fn(|_| None)
}

#[derive(Debug)]
pub struct ProofMetrics {
    pub cost_per_proof: f64,     // $
    pub cost_per_signature: f64, // $
    pub sigs_per_second: f64,    // sig/s
    pub core_seconds_per_proof: f64,
    pub core_seconds_per_sig: f64,
}

impl fmt::Display for ProofMetrics {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "=== Proof Metrics ===")?;
        writeln!(f, "sigs/sec              : {:>10.2}", self.sigs_per_second)?;
        writeln!(
            f,
            "core-sec / proof      : {:>10.4}",
            self.core_seconds_per_proof
        )?;
        writeln!(
            f,
            "core-sec / sig        : {:>10.6}",
            self.core_seconds_per_sig
        )?;
        writeln!(f, "cost / proof (USD)    : ${:>10.8}", self.cost_per_proof)?;
        writeln!(
            f,
            "cost / signature (USD): ${:>10.8}",
            self.cost_per_signature
        )?;
        Ok(())
    }
}

pub fn compute_metrics(
    n_sigs: usize,
    proof_time: Duration,
    cpu_cores_used: usize,
    cpu_core_cost_per_hour: f64, // $ per core-hour
) -> ProofMetrics {
    let t_sec = proof_time.as_secs_f64();
    let n = n_sigs as f64;
    let cores = cpu_cores_used as f64;

    // total CPU time
    let core_seconds_per_proof = t_sec * cores;
    let core_seconds_per_sig = core_seconds_per_proof / n;

    // cost
    let core_hours_per_proof = core_seconds_per_proof / 3600.0;
    let cost_per_proof = core_hours_per_proof * cpu_core_cost_per_hour;
    let cost_per_signature = cost_per_proof / n;

    // throughput
    let proofs_per_second = 1.0 / t_sec;
    let sigs_per_second = proofs_per_second * n;

    ProofMetrics {
        cost_per_proof,
        cost_per_signature,
        sigs_per_second,
        core_seconds_per_proof,
        core_seconds_per_sig,
    }
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
    let m_val = fr((N - 1 + offset) as u64); // max nonce

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

    let k = Instant::now();
    // ------------------------------
    // 3. Prove
    // ------------------------------
    let proof = groth16::create_random_proof(circuit, &params, &mut rng)
        .expect("proof generation should succeed");

    println!("proof gen {:?}", k.elapsed());
    println!("{}", compute_metrics(N, k.elapsed(), num_cpus::get(), 0.05));

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
