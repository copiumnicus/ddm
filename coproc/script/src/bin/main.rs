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
use fibonacci_lib::{Input, PublicValuesStruct, Sig};
use k256::{
    ecdsa::{RecoveryId, SigningKey, VerifyingKey},
    elliptic_curve::{rand_core, sec1::ToEncodedPoint, FieldBytes, PublicKey},
    Secp256k1,
};
use sp1_sdk::{include_elf, ProverClient, SP1Stdin};
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

fn keccak256(slice: &[u8]) -> [u8; 32] {
    let mut h = Keccak::v256();
    h.update(slice);
    let mut first_key = [0; 32];
    h.finalize(&mut first_key);
    first_key
}

fn pubk_to_adr(pubk: &[u8]) -> [u8; 20] {
    debug_assert_eq!(pubk[0], 0x04);
    let hash = keccak256(&pubk[1..]);
    hash[12..].try_into().expect("must be 20 bytes")
}

fn sk_to_adr(sk: &SigningKey) -> [u8; 20] {
    let pubk = PublicKey::from_secret_scalar(sk.as_nonzero_scalar());
    let pubk = pubk.to_encoded_point(/* compress = */ false);
    pubk_to_adr(pubk.as_bytes())
}

fn sign(sk: &SigningKey, hash: [u8; 32]) -> Sig {
    let (sig, recovery_id) = sk.sign_prehash_recoverable(hash.as_ref()).unwrap();
    // Low-S normalize per BIP 0062: Dealing with Malleability:
    // <https://github.com/bitcoin/bips/blob/master/bip-0062.mediawiki>
    let sig = sig.normalize_s().unwrap_or(sig);

    let r_bytes: FieldBytes<Secp256k1> = sig.r().into();
    let s_bytes: FieldBytes<Secp256k1> = sig.s().into();

    (r_bytes.into(), s_bytes.into(), recovery_id.into())
}

fn recover(sig: &Sig, hash: &[u8; 32]) -> [u8; 20] {
    let rec = sig.2;
    let s = k256::ecdsa::Signature::from_scalars(sig.0, sig.1).unwrap();
    let rec =
        VerifyingKey::recover_from_prehash(hash, &s, RecoveryId::from_byte(rec).unwrap()).unwrap();
    let pubk = rec.to_encoded_point(false);
    pubk_to_adr(pubk.as_bytes())
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

    let sk = SigningKey::random(&mut rand_core::OsRng);
    let addr = sk_to_adr(&sk);
    println!("addr {:?}", addr);

    let mut pre = vec![];
    pre.extend_from_slice(&addr);
    let digest = keccak256(&pre);

    let sig = sign(&sk, digest);
    assert!(recover(&sig, &digest) == addr, "sig addr match");

    // Setup the inputs.

    let mut inp: Input = (
        2,
        vec![
            (addr, [1; 20], 10, 0, 1, sig),
            // ([0; 20], [2; 20], 15, 0, 2),
            // ([0; 20], [2; 20], 15, 0, 2),
        ],
    );
    // 220 sec for 6k `tx`
    // for _ in 0..6000 {
    //     inp.1.push(([0; 20], [2; 20], 15, 0, 2));
    // }
    let client = ProverClient::from_env();
    let mut stdin = SP1Stdin::new();
    stdin.write(&inp);

    println!("n: {}", args.n);

    if args.execute {
        // Execute the program
        let (output, report) = client.execute(FIBONACCI_ELF, &stdin).run().unwrap();
        println!("Program executed successfully.");

        // Read the output.
        let decoded = PublicValuesStruct::abi_decode(output.as_slice()).unwrap();
        let PublicValuesStruct { n } = decoded;
        println!("{:?}", n);
        // let a = n[1];
        // let b = n[2];
        // let n = n[0];
        // println!("n: {}", n);
        // println!("a: {}", a);
        // println!("b: {}", b);

        // let (expected_a, expected_b) = fibonacci_lib::fibonacci(n);
        // assert_eq!(a, expected_a);
        // assert_eq!(b, expected_b);
        // println!("Values are correct!");

        // Record the number of cycles executed.
        println!("Number of cycles: {}", report.total_instruction_count());
    } else {
        // Setup the program for proving.
        let (pk, vk) = client.setup(FIBONACCI_ELF);

        // Generate the proof
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
