pub mod hash;
pub mod pay;
use bellman::{
    Circuit, ConstraintSystem, LinearCombination, SynthesisError,
    gadgets::{boolean::Boolean, num::AllocatedNum},
    groth16,
};
use bls12_381::Bls12;
use ff::{Field, PrimeField, PrimeFieldBits};
use rand::{Rng, thread_rng};
use rand_xorshift::XorShiftRng;

// Choose your batch size at compile time for this parameter set.
pub const N: usize = 32;

pub struct SettlementCircuit<Scalar: PrimeField> {
    /// payment recipient
    pub recipient: Option<Scalar>,
    /// old nonce on contract
    pub k_old: Option<Scalar>,
    /// max nonce used in the proof
    pub m: Option<Scalar>,
    /// sum of all sizes
    pub total_settle: Option<Scalar>,

    pub to: [Option<Scalar>; N],
    pub size: [Option<Scalar>; N],
    pub nonce: [Option<Scalar>; N],
}

impl<Scalar: PrimeField + PrimeFieldBits> Circuit<Scalar> for SettlementCircuit<Scalar> {
    fn synthesize<CS: ConstraintSystem<Scalar>>(self, cs: &mut CS) -> Result<(), SynthesisError> {
        // --------------------
        // 1. Allocate PUBLIC inputs
        // --------------------

        // recipient A
        let recipient = AllocatedNum::alloc(cs.namespace(|| "recipient"), || {
            self.recipient.ok_or(SynthesisError::AssignmentMissing)
        })?;
        recipient.inputize(cs.namespace(|| "recipient input"))?;

        // K_old
        let k_old = AllocatedNum::alloc(cs.namespace(|| "k_old"), || {
            self.k_old.ok_or(SynthesisError::AssignmentMissing)
        })?;
        k_old.inputize(cs.namespace(|| "k_old input"))?;

        // M (max nonce)
        let m = AllocatedNum::alloc(cs.namespace(|| "m"), || {
            self.m.ok_or(SynthesisError::AssignmentMissing)
        })?;
        m.inputize(cs.namespace(|| "m input"))?;

        // total settlement amount X
        let total_settle = AllocatedNum::alloc(cs.namespace(|| "total_settle"), || {
            self.total_settle.ok_or(SynthesisError::AssignmentMissing)
        })?;
        total_settle.inputize(cs.namespace(|| "total_settle input"))?;

        // --------------------
        // 2. Allocate per-signature witnesses
        // --------------------
        let mut sizes: Vec<AllocatedNum<Scalar>> = Vec::with_capacity(N);
        let mut nonces: Vec<AllocatedNum<Scalar>> = Vec::with_capacity(N);

        for i in 0..N {
            // to_i
            let to_i = AllocatedNum::alloc(cs.namespace(|| format!("to_{}", i)), || {
                self.to[i].ok_or(SynthesisError::AssignmentMissing)
            })?;

            // Enforce recipient consistency: to_i == recipient
            // (to_i - recipient) * 1 = 0
            cs.enforce(
                || format!("recipient consistency {}", i),
                |lc| lc + to_i.get_variable() - recipient.get_variable(),
                |lc| lc + CS::one(),
                |lc| lc,
            );

            // size_i
            let size_i = AllocatedNum::alloc(cs.namespace(|| format!("size_{}", i)), || {
                self.size[i].ok_or(SynthesisError::AssignmentMissing)
            })?;
            sizes.push(size_i);

            // nonce_i
            let nonce_i = AllocatedNum::alloc(cs.namespace(|| format!("nonce_{}", i)), || {
                self.nonce[i].ok_or(SynthesisError::AssignmentMissing)
            })?;
            nonces.push(nonce_i);
        }

        // 3. SUM_SIZES = TOTAL_SETTLE
        let mut sum_lc = LinearCombination::<Scalar>::zero();
        for (i, size_i) in sizes.iter().enumerate() {
            let ns = cs.namespace(|| format!("add size {}", i));
            let _ = ns;
            sum_lc = sum_lc + size_i.get_variable();
        }
        // Enforce sum_lc == total_settle
        cs.enforce(
            || "sum equals total_settle",
            |_| sum_lc,
            |lc| lc + CS::one(),
            |lc| lc + total_settle.get_variable(),
        );

        let mut nonce_bits: Vec<Vec<Boolean>> = Vec::with_capacity(N);
        for (i, nonce_i) in nonces.iter().enumerate() {
            let bits = nonce_i.to_bits_le_strict(cs.namespace(|| format!("nonce_bits_{}", i)))?;
            nonce_bits.push(bits);
        }

        // 4. ENFORCE: ALL_NONCE > K_OLD
        let k_old_bits = k_old.to_bits_le_strict(cs.namespace(|| "k_old_bits"))?;
        for i in 0..N {
            enforce_greater_than::<Scalar, _>(
                cs.namespace(|| format!("nonce_{}_gt_k_old", i)),
                &nonce_bits[i],
                &k_old_bits,
            )?;
        }

        // 5. ENFORCE: there is an ordering of nonces such that they are strictly increasing: nonce_i+1 > nonce_i
        for i in 0..(N - 1) {
            enforce_greater_than::<Scalar, _>(
                cs.namespace(|| format!("nonce_{}_gt_prev", i + 1)),
                &nonce_bits[i + 1],
                &nonce_bits[i],
            )?;
        }

        // 6. M (max_nonce) must equal last nonce
        cs.enforce(
            || "m_equals_last_nonce",
            |lc| lc + m.get_variable() - nonces[N - 1].get_variable(),
            |lc| lc + CS::one(),
            |lc| lc, // = 0
        );

        Ok(())
    }
}

/// (x > y) ?
fn enforce_greater_than<Scalar, CS>(
    mut cs: CS,
    le_x_bits: &[Boolean],
    le_y_bits: &[Boolean],
) -> Result<(), SynthesisError>
where
    Scalar: PrimeField + PrimeFieldBits,
    CS: ConstraintSystem<Scalar>,
{
    assert_eq!(le_x_bits.len(), le_y_bits.len());

    // We track:
    //   eq = have all more-significant bits been equal so far?
    //   gt = have we already determined x > y from a more-significant bit?
    let mut eq = Boolean::constant(true);
    let mut gt = Boolean::constant(false);

    // Walk from MSB down to LSB
    for i in (0..le_x_bits.len()).rev() {
        let x = &le_x_bits[i];
        let y = &le_y_bits[i];

        // x_i > y_i
        let xi_gt_yi = Boolean::and(cs.namespace(|| format!("cmp_x_gt_y_{}", i)), x, &y.not())?;
        // this bit is decisive and says x>y
        let eq_and_gt = Boolean::and(
            cs.namespace(|| format!("cmp_eq_and_gt_{}", i)),
            &eq,
            &xi_gt_yi,
        )?;
        // once true, stays true gt || eq_and_gt
        let new_gt = boolean_or(cs.namespace(|| format!("cmp_or_{}", i)), &gt, &eq_and_gt)?;

        // equality chain
        let new_eq = {
            // if x and y are different = 1
            let xor = Boolean::xor(cs.namespace(|| format!("cmp_xor_{}", i)), x, y)?;
            // if x and y are eq = 1
            let eq_bit = xor.not();
            // if prev eq and now eq is eq
            Boolean::and(cs.namespace(|| format!("cmp_eq_new_{}", i)), &eq, &eq_bit)?
        };

        gt = new_gt;
        eq = new_eq;
    }

    // Enforce gt == true
    Boolean::enforce_equal(
        cs.namespace(|| "enforce_gt_true"),
        &gt,
        &Boolean::constant(true),
    )
}

pub fn boolean_or<F: PrimeField, CS: ConstraintSystem<F>>(
    mut cs: CS,
    a: &Boolean,
    b: &Boolean,
) -> Result<Boolean, SynthesisError> {
    // if different
    let xord = Boolean::xor(cs.namespace(|| "xor'd".to_string()), a, b)?;
    // both true
    let andd = Boolean::and(cs.namespace(|| "and'd".to_string()), a, b)?;
    // is_diff, both_tru, result
    //    0        1       1
    //    1        0       1
    //    0        0       0
    Boolean::xor(cs.namespace(|| "or'd".to_string()), &xord, &andd)
}
