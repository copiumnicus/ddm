/// payments we batch over
pub struct GPayment<A, N, C, P, AM, S> {
    pub vendor: A,
    pub nonce: N,
    pub chain_id: C,
    pub product_id: P,
    pub amount: AM,
    pub signature: S,
}

/// We want to batch streams primarly, such that:
/// In batch:
/// for all P => 
/// P_i(chain_id, product_id, vendor, signer(sig))==P_j(chain_id, product_id, vendor, signer(sig))
/// which translates to: 
/// vendor gets paid for multiple smaller payments in one chunk for one product from one client
/// 
/// It would be nice to be able to batch somehow such that:
/// for all P => 
/// P_i(chain_id, vendor)==P_j(chain_id, vendor)
/// which translates to: 
/// vendor gets paid for multiple smaller payments 
/// in one chunk from multiple products, from multiple clients
/// 
/// That would mean that the verifying smart contract either receives a list of payment sources
/// OR that the payments sources are somehow abstracted and everything is paid out from one 'pot'

pub type TestNoSigPayment = GPayment<u64, u64, u64, u64, u64, ()>;
