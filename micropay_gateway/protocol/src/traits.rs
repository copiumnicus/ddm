use thiserror::Error;

/// The proxy receives the voucher. What does it need to do?
/// - verify that the signature is valid
/// TODO
pub trait Voucher<U, K>: Clone {
    const DECIMALS: u32;
    /// returns `true` if the cryptographic signature on the voucher is valid
    fn is_valid_signature(&self) -> bool;
    /// nonce of the voucher, this value increases with each next voucher signed
    /// like a blockchain transaction
    fn nonce(&self) -> u64;
    /// the atoms the voucher is signed for
    fn voucher_atoms(&self) -> u64;
    /// returns user identifier for current protocol implementation
    /// example is erc20 address or public key on eddsa
    fn client_identifier(&self) -> U;
    fn vendor_identifier(&self) -> K;
}

/// maintains an order of vouchers nonce increasing
/// and a nonce marker which indicates what vouchers are already 'spent'
/// where user cannot use their atoms anymore
///
/// spent_nonce=2
///
/// [V0, V1, V2(spent), V3, V4
///
/// unspent = [V3, V4]
///
/// first_unspent = V3
///
/// latest_voucher = V4
pub trait VoucherTracker<V, U> {
    /// return the last stored nonce for a voucher sent by a user
    fn get_latest_voucher_nonce(&self, ci: &U) -> Result<u64, VTrackErr>;
    fn get_first_unspent_voucher(&self, ci: &U) -> Result<V, VTrackErr>;
    /// insert a previously not seen voucher from the user
    fn insert_voucher(&self, v: V) -> Result<(), VTrackErr>;
    /// mark all vouchers spent up to the given nonce inclusive
    fn mark_spent(&self, ci: &U, nonce: u64);
    /// return the sum of all vouchers nonce > marked_nonce
    fn get_unspent_atoms(&self, ci: &U) -> Result<u64, VTrackErr>;
}

#[derive(Debug, Error)]
pub enum VTrackErr {
    #[error("No known voucher")]
    NoVoucher,
    #[error("Failed to retrieve vouchers")]
    InternalFailure,
}

/// has to track the current unmarked cost for user
/// if the unmarked_cost > first_unspent_voucher.atoms
/// we can mark the unspent voucher as spent and reduce unmarked cost
pub trait UnmarkedCostTracker<U> {
    fn unmarked_cost(&self, ci: &U) -> u64;
    fn locked_cost(&self, ci: &U) -> u64;
    fn lock(&self, ci: &U, atoms: u64);
    fn unlock(&self, ci: &U, atoms: u64);
    fn reduce(&self, ci: &U, atoms: u64);
    fn add_cost(&self, ci: &U, atoms: u64);
}

#[derive(Debug, Error)]
pub enum OracleErr {
    #[error("Oracle data stale {seconds}")]
    OracleStale { seconds: u64 },
    #[error("VTrack {0}")]
    VTrack(#[from] VTrackErr),
}

pub trait ChainOracle<U, K> {
    fn get_client_collateral(&self, client: &U) -> Result<u64, OracleErr>;
    fn get_total_subscribed(&self, client: &U) -> Result<u64, OracleErr>;
    fn is_client_subscribed(&self, client: &U, vendor: &K) -> Result<bool, OracleErr>;
}
