use alloy_sol_types::sol;
use k256::ecdsa::{RecoveryId, VerifyingKey};
use tiny_keccak::{Hasher, Keccak};

sol! {
    #[derive(Debug)]
    struct StateDelta {
        address v;
        int64 delta;
    }
    /// The public values encoded as a struct that can be easily deserialized inside Solidity.
    struct PublicValuesStruct {
        StateDelta[] n;
    }
}

// #[derive(Archive, Serialize, Deserialize)]
// pub struct Tx {
//     pub from: [u8; 20],
//     pub to: [u8; 20],
//     pub atoms: i64,

//     pub frm_idx: u32,
//     pub to_idx: u32,
// }

pub type Sig = ([u8; 32], [u8; 32], u8);
/// (from, to, atoms, frm_idx, to_idx)
pub type Tx = ([u8; 20], [u8; 20], i64, u32, u32, Sig);
/// (state_diffs, txs)
pub type Input = (u32, Vec<Tx>);

fn keccak(tx: &Tx) -> [u8; 32] {
    let mut s = tiny_keccak::Keccak::v256();
    s.update(&tx.0);
    // s.update(&tx.1);
    // s.update(&tx.2.to_be_bytes());
    let mut out = [0; 32];
    s.finalize(&mut out);
    out
}

pub struct StateDiff {
    pub a: Option<[u8; 20]>,
    pub v: i64,
}

// #[derive(Archive, Serialize, Deserialize)]
// pub struct Input {
//     /// size
//     pub state_diffs: u32,
//     /// txs
//     pub txs: Vec<Tx>,
// }

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
fn pubk_to_adr(pubk: &[u8]) -> [u8; 20] {
    debug_assert_eq!(pubk[0], 0x04);
    let mut s = tiny_keccak::Keccak::v256();
    s.update(&pubk[1..]);
    let mut out = [0; 32];
    s.finalize(&mut out);
    out[12..].try_into().expect("must be 20 bytes")
}

fn recover(sig: &Sig, hash: &[u8; 32]) -> [u8; 20] {
    let rec = sig.2;
    let s = k256::ecdsa::Signature::from_scalars(sig.0, sig.1).unwrap();
    let rec =
        VerifyingKey::recover_from_prehash(hash, &s, RecoveryId::from_byte(rec).unwrap()).unwrap();
    let pubk = rec.to_encoded_point(false);
    pubk_to_adr(pubk.as_bytes())
}

pub fn process_txs(inp: Input) -> Vec<StateDelta> {
    let (state_diffs, txs) = inp;
    let mut deltas = Vec::with_capacity(state_diffs as usize);
    for _ in 0..state_diffs {
        deltas.push(StateDiff { a: None, v: 0 });
    }

    for tx in txs {
        // verify(tx)
        let hash = keccak(&tx);
        let (from, to, atoms, frm_idx, to_idx, sig) = tx;

        assert!(recover(&sig, &hash) == from);
        assert!(atoms > 0);
        apply_delta(&mut deltas, frm_idx, from, -atoms);
        apply_delta(&mut deltas, to_idx, to, atoms);
    }

    deltas
        .into_iter()
        .map(|x| StateDelta {
            v: x.a.unwrap().into(),
            delta: x.v,
        })
        .collect()
}
