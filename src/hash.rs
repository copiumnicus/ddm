use bellman::{
    Circuit, ConstraintSystem, SynthesisError,
    gadgets::{blake2s::blake2s, boolean::Boolean, multipack, num::AllocatedNum},
};
use ff::{PrimeField, PrimeFieldBits};

pub struct Blake2sScalarHashCircuit<F: PrimeField + PrimeFieldBits> {
    /// Private preimage (scalar)
    pub input_scalar: Option<F>,
}

impl<F: PrimeField + PrimeFieldBits> Circuit<F> for Blake2sScalarHashCircuit<F> {
    fn synthesize<CS: ConstraintSystem<F>>(self, cs: &mut CS) -> Result<(), SynthesisError> {
        // 1. Allocate the scalar preimage as a private witness
        let input = AllocatedNum::alloc(cs.namespace(|| "input_scalar"), || {
            self.input_scalar.ok_or(SynthesisError::AssignmentMissing)
        })?;

        // 2. Turn it into bits (little-endian)
        let mut input_bits = input.to_bits_le_strict(cs.namespace(|| "input_scalar_bits"))?;
        // this returns 255 bits because thats the size of the field
        // now pad to 256 bits (the missing MSB is known to be 0)
        input_bits.push(Boolean::constant(false));

        println!("input_bits len {}", input_bits.len());
        // 3. Compute BLAKE2s(input_bits) inside the circuit
        let hash_bits = blake2s(
            cs.namespace(|| "blake2s(input_scalar)"),
            &input_bits,
            &[0; 8],
        )?;

        // 4. Pack hash_bits into field elements and expose them as *public inputs*
        //
        //    This will create as many public inputs as needed
        //    (for BLS12-381 you’ll get 2 scalars for 256 bits).
        multipack::pack_into_inputs(cs.namespace(|| "pack_hash_into_public_inputs"), &hash_bits)?;

        Ok(())
    }
}
