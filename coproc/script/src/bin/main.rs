use alloy_sol_types::SolType;
use clap::Parser;
use fibonacci_lib::{
    ds::{InputToSer, TxToSer},
    PublicValuesStruct,
};
use k256::{
    ecdsa::{RecoveryId, SigningKey, VerifyingKey},
    elliptic_curve::{
        rand_core::{self, CryptoRng, RngCore},
        sec1::ToEncodedPoint,
        FieldBytes, PublicKey,
    },
    Secp256k1,
};
use rand::{rngs::StdRng, SeedableRng};
use serde::Deserialize;
use sp1_sdk::{include_elf, ProverClient, SP1Stdin};
use std::collections::{HashMap, HashSet};
use std::fs;
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

    /// Path to USDC transfers JSON file for benchmarking with real data
    #[arg(long)]
    usdc_json: Option<String>,
}

#[derive(Debug, Deserialize)]
struct Transfer {
    from: String,
    to: String,
    atoms: i64,
}

#[derive(Debug, Deserialize)]
struct TransfersData {
    transfers: Vec<Transfer>,
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

pub type Sig = ([u8; 32], [u8; 32], u8);

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

/// Wrapper to make any RngCore implement CryptoRng for deterministic key generation.
/// This is a hack for testing purposes - do not use in production!
struct CryptoRngWrapper<R: RngCore>(R);

impl<R: RngCore> RngCore for CryptoRngWrapper<R> {
    fn next_u32(&mut self) -> u32 {
        self.0.next_u32()
    }

    fn next_u64(&mut self) -> u64 {
        self.0.next_u64()
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.0.fill_bytes(dest)
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.0.try_fill_bytes(dest)
    }
}

impl<R: RngCore> CryptoRng for CryptoRngWrapper<R> {}

struct MockAcc {
    sk: SigningKey,
    nonce: u64,
    addr: [u8; 20],
}

impl MockAcc {
    pub fn new<R: RngCore>(rng: &mut R) -> Self {
        let mut crypto_rng = CryptoRngWrapper(rng);
        let sk = SigningKey::random(&mut crypto_rng);
        let addr = sk_to_adr(&sk);
        let nonce = crypto_rng.0.next_u64();
        Self { sk, addr, nonce }
    }

    pub fn signed_tx(&mut self, to: [u8; 20], atoms: i64) -> TxToSer {
        self.nonce += 1;
        let mut tx = TxToSer {
            to,
            atoms,
            nonce: self.nonce,
            sig_r: [0; 32],
            sig_s: [0; 32],
            v: 0,
            from_idx: 0,
            to_idx: 0,
        };
        let digest = tx.keccak();
        let sig = sign(&self.sk, digest);
        tx.sig_r = sig.0;
        tx.sig_s = sig.1;
        tx.v = sig.2;
        tx
    }
    pub fn tx(&mut self, to: &Self, atoms: i64) -> TxToSer {
        self.signed_tx(to.addr, atoms)
    }
}

fn rec(tx: &TxToSer) -> [u8; 20] {
    recover(&(tx.sig_r, tx.sig_s, tx.v), &tx.keccak())
}

struct InputBuilder {
    fee_atoms: u16,
    state_deltas: HashSet<[u8; 20]>,
    fee_recipient: [u8; 20],
    txs: Vec<TxToSer>,
}
impl InputBuilder {
    pub fn new(fee_atoms: u16, fee_recipient: [u8; 20]) -> Self {
        Self {
            fee_atoms,
            fee_recipient,
            txs: vec![],
            state_deltas: HashSet::new(),
        }
    }
    pub fn add(mut self, tx: TxToSer) -> Self {
        let from = rec(&tx);
        self.state_deltas.insert(from);
        self.state_deltas.insert(tx.to);
        self.txs.push(tx);
        self
    }
    pub fn ser(&self) -> InputToSer {
        let mut txs = vec![];
        let idx: HashMap<_, _> = self
            .state_deltas
            .iter()
            .enumerate()
            .map(|(x, y)| (*y, (x + 1) as u32))
            .collect();
        for mut tx in self.txs.clone() {
            let from = rec(&tx);
            tx.from_idx = idx[&from];
            tx.to_idx = idx[&tx.to];
            txs.push(tx);
        }
        InputToSer {
            fee_atoms: self.fee_atoms,
            fee_recipient: self.fee_recipient,
            state_deltas: self.state_deltas.len() as u32 + 1,
            tx: txs,
        }
    }
}

fn hex_to_addr(hex: &str) -> Result<[u8; 20], String> {
    let hex = hex.strip_prefix("0x").unwrap_or(hex);
    if hex.len() != 40 {
        return Err(format!("Invalid address length: {}", hex.len()));
    }
    let mut addr = [0u8; 20];
    hex::decode_to_slice(hex, &mut addr).map_err(|e| format!("Failed to decode hex: {}", e))?;
    Ok(addr)
}

fn load_usdc_transfers(path: &str) -> Result<Vec<Transfer>, Box<dyn std::error::Error>> {
    let content = fs::read_to_string(path)?;
    let data: TransfersData = serde_json::from_str(&content)?;
    Ok(data.transfers)
}

fn build_batch_from_usdc_transfers(
    transfers: Vec<Transfer>,
    limit: usize,
    rng: &mut StdRng,
) -> InputBuilder {
    println!("Building batch from {} USDC transfers", transfers.len());

    // Create a HashMap to map real addresses to MockAcc
    let mut addr_to_mock: HashMap<[u8; 20], MockAcc> = HashMap::new();

    // Create fee sink
    let fee_sink = MockAcc::new(rng);
    let mut batch = InputBuilder::new(20, fee_sink.addr);

    // Process each transfer
    for (idx, transfer) in transfers.iter().enumerate() {
        if transfer.atoms < batch.fee_atoms as i64 {
            continue;
        }
        if batch.txs.len() >= limit {
            break;
        }
        // Parse addresses
        let from_addr = match hex_to_addr(&transfer.from) {
            Ok(a) => a,
            Err(e) => {
                eprintln!("Skipping transfer {}: {}", idx, e);
                continue;
            }
        };
        let to_addr = match hex_to_addr(&transfer.to) {
            Ok(a) => a,
            Err(e) => {
                eprintln!("Skipping transfer {}: {}", idx, e);
                continue;
            }
        };

        // Get or create mock accounts for from and to addresses
        addr_to_mock
            .entry(from_addr)
            .or_insert_with(|| MockAcc::new(rng));
        addr_to_mock
            .entry(to_addr)
            .or_insert_with(|| MockAcc::new(rng));

        // Create signed transaction from sender to receiver
        let to_addr = addr_to_mock.get(&to_addr).unwrap().addr;
        let from_mock = addr_to_mock.get_mut(&from_addr).unwrap();

        let tx = from_mock.signed_tx(to_addr, transfer.atoms);

        batch = batch.add(tx);

        if (idx + 1) % 1000 == 0 {
            println!("  Processed {}/{} transfers", idx + 1, transfers.len());
        }
    }

    println!("Created {} unique mock accounts", addr_to_mock.len());
    batch
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

    let limit = 100;

    // Create deterministic RNG with fixed seed for consistent cycle counts
    let mut rng = StdRng::seed_from_u64(42);

    // Build the batch based on whether we're using USDC transfers or the default scenario
    let batch = if let Some(json_path) = &args.usdc_json {
        println!("Loading USDC transfers from: {}", json_path);
        match load_usdc_transfers(json_path) {
            Ok(transfers) => build_batch_from_usdc_transfers(transfers, limit, &mut rng),
            Err(e) => {
                eprintln!("Error loading USDC transfers: {}", e);
                std::process::exit(1);
            }
        }
    } else {
        // Default scenario with alice, bob, charlie
        let mut alice = MockAcc::new(&mut rng);
        let mut bob = MockAcc::new(&mut rng);
        let mut charlie = MockAcc::new(&mut rng);

        let fee_sink = MockAcc::new(&mut rng);

        let batch = InputBuilder::new(20, fee_sink.addr);
        batch
            .add(alice.tx(&bob, 1000))
            .add(alice.tx(&bob, 100))
            .add(alice.tx(&bob, 2000))
            .add(alice.tx(&charlie, 1000))
            .add(bob.tx(&alice, 1000))
            .add(charlie.tx(&bob, 1000))
    };

    let client = ProverClient::from_env();
    let mut stdin = SP1Stdin::new();
    let ser = batch.ser();
    println!("state_deltas={} txs={}", ser.state_deltas, ser.tx.len());
    let ser = ser.ser();
    println!("input size: {}", ser.len());
    stdin.write(&ser);

    if args.execute {
        // Execute the program
        let (output, report) = client.execute(FIBONACCI_ELF, &stdin).run().unwrap();
        println!("Program executed successfully.");

        // Read the output.
        let decoded = PublicValuesStruct::abi_decode(output.as_slice()).unwrap();
        let PublicValuesStruct { n } = decoded;
        // println!("{:#?}", n);

        // Record the number of cycles executed.
        println!("Number of cycles: {:.3}M", report.total_instruction_count() as f64 / 1e6);
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
