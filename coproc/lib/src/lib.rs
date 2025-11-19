use alloy_sol_types::sol;

sol! {
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

/// (from, to, atoms, frm_idx, to_idx)
pub type Tx = ([u8; 20], [u8; 20], i64, u32, u32);
/// (state_diffs, txs)
pub type Input = (u32, Vec<Tx>);

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

pub fn process_txs(inp: Input) -> Vec<StateDiff> {
    let (state_diffs, txs) = inp;
    let mut deltas = Vec::with_capacity(state_diffs as usize);
    for _ in 0..state_diffs {
        deltas.push(StateDiff { a: None, v: 0 });
    }

    for (from, to, atoms, frm_idx, to_idx) in txs {
        // verify(tx)
        assert!(atoms > 0);
        apply_delta(&mut deltas, frm_idx, from, -atoms);
        apply_delta(&mut deltas, to_idx, to, atoms);
    }

    vec![]
}
