pub mod ds;
use crate::ds::*;
use alloy_sol_types::sol;
use k256::ecdsa::{RecoveryId, VerifyingKey};
use tiny_keccak::{Hasher, Keccak};

sol! {
    #[derive(Debug)]
    struct StateDelta {
        address v;
        bool is_sender; // if is sender on-chain checks nonces
        uint64 start_nonce; // nonce of first seen tx
        uint64 end_nonce; // nonce of last seen tx (all prev enforced from start_nonce)
        int64 delta;
    }
    /// The public values encoded as a struct that can be easily deserialized inside Solidity.
    struct PublicValuesStruct {
        StateDelta[] n;
    }
}

pub struct StateDiff {
    pub a: Option<[u8; 20]>,
    pub nonces: Option<(u64, u64)>,
    pub v: i64,
}

fn pubk_to_adr(pubk: &[u8]) -> [u8; 20] {
    debug_assert_eq!(pubk[0], 0x04);
    let mut s = tiny_keccak::Keccak::v256();
    s.update(&pubk[1..]);
    let mut out = [0; 32];
    s.finalize(&mut out);
    out[12..].try_into().expect("must be 20 bytes")
}

fn recover<'a>(tx: &Tx<'a>, digest: &[u8; 32]) -> [u8; 20] {
    let s = k256::ecdsa::Signature::from_scalars(tx.sig_r(), tx.sig_s()).unwrap();
    let rec =
        VerifyingKey::recover_from_prehash(digest, &s, RecoveryId::from_byte(tx.v()).unwrap())
            .unwrap();
    let pubk = rec.to_encoded_point(false);
    pubk_to_adr(pubk.as_bytes())
}

fn apply_delta(deltas: &mut [StateDiff], idx: u32, addr: [u8; 20], atoms_delta: i64) {
    let delta = &mut deltas[idx as usize];
    match delta.a {
        None => {
            // first time touching this delta
            delta.a = Some(addr);
            delta.v = atoms_delta;
        }
        Some(d) => {
            assert!(d == addr); // need to be modifying same
            delta.v += atoms_delta;
        }
    }
}

fn apply_sender_delta(
    deltas: &mut [StateDiff],
    idx: u32,
    addr: [u8; 20],
    nonce: u64,
    atoms_delta: i64,
) {
    let delta = &mut deltas[idx as usize];
    match delta.a {
        None => {
            // first time touching this delta
            delta.a = Some(addr);
            delta.nonces = Some((nonce, nonce));
            delta.v = atoms_delta;
        }
        Some(d) => {
            // need to be modifying same
            assert!(d == addr);
            // ex. alice received some payment so addr is set,
            // but then alice sent something so nonces are not set yet
            match &mut delta.nonces {
                Some((_, end)) => {
                    // enforce strict +1 increments
                    assert!((*end + 1) == nonce);
                    *end = nonce;
                }
                None => {
                    delta.nonces = Some((nonce, nonce));
                }
            }
            delta.v += atoms_delta;
        }
    }
}

pub fn process_txs(v: &[u8]) -> Vec<StateDelta> {
    let inp = Input { v };
    let sdl = inp.state_deltas() as usize;
    let mut deltas = Vec::with_capacity(sdl);
    let fee_recipient: [u8; 20] = inp.fee_recipient().try_into().unwrap();
    // first state diff is fee sink
    deltas.push(StateDiff {
        a: Some(fee_recipient),
        nonces: None,
        v: 0,
    });
    for _ in 1..sdl {
        deltas.push(StateDiff {
            a: None,
            nonces: None,
            v: 0,
        });
    }

    let mut digest = [0; 32]; // reuse buff
    let fee_atoms = inp.fee_atoms() as i64;
    assert!(fee_atoms >= 0);
    let total_tx = inp.total_tx();
    for offset in 0..total_tx {
        let tx = inp.tx_at(offset);
        // 1. hash the tx
        // 2. recover sig addr
        tx.keccak(&mut digest);
        let from = recover(&tx, &digest);
        let atoms = tx.atoms();
        assert!(atoms > fee_atoms);
        let to_recipient = atoms - fee_atoms;
        let to_fee_sink = fee_atoms;
        let to = tx.to().try_into().unwrap();
        apply_sender_delta(&mut deltas, tx.from_idx(), from, tx.nonce(), -atoms);
        apply_delta(&mut deltas, tx.to_idx(), to, to_recipient);
        apply_delta(&mut deltas, 0, fee_recipient, to_fee_sink);
    }

    deltas
        .into_iter()
        .map(|x| {
            if let Some((start, end)) = x.nonces {
                StateDelta {
                    v: x.a.unwrap().into(),
                    is_sender: true,
                    start_nonce: start,
                    end_nonce: end,
                    delta: x.v,
                }
            } else {
                StateDelta {
                    v: x.a.unwrap().into(),
                    is_sender: false,
                    start_nonce: 0,
                    end_nonce: 0,
                    delta: x.v,
                }
            }
        })
        .collect()
}
