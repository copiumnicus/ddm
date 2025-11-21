//! A simple program that takes a number `n` as input, and writes the `n-1`th and `n`th fibonacci
//! number as an output.

// These two lines are necessary for the program to properly compile.
//
// Under the hood, we wrap your main function with some extra code so that it behaves properly
// inside the zkVM.
#![no_main]
sp1_zkvm::entrypoint!(main);

use alloy_sol_types::SolType;
use fibonacci_lib::{ds::*, process_txs, PublicValuesStruct};

pub fn main() {
    // Read an input to the program.
    //
    // Behind the scenes, this compiles down to a custom system call which handles reading inputs
    // from the prover.
    println!("cycle-tracker-start: read_input");
    let inp = sp1_zkvm::io::read_vec();
    println!("cycle-tracker-end: read_input");
    // let inp = deserialize::<Input, Error>(&input).unwrap();

    // program gets some weird 8 bytes lead on the input
    println!("cycle-tracker-start: process_tx");
    let r = process_txs(&inp[8..]);
    println!("cycle-tracker-end: process_tx");

    // Encode the public values of the program.
    println!("cycle-tracker-start: ser_output");
    let bytes = PublicValuesStruct::abi_encode(&PublicValuesStruct { n: r });
    println!("cycle-tracker-end: ser_output");
    // let bytes = vec![];

    // Commit to the public values of the program. The final proof will have a commitment to all the
    // bytes that were committed to.
    sp1_zkvm::io::commit_slice(&bytes);
}
