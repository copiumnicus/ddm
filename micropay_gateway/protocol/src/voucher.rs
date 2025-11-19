use std::marker::PhantomData;

/// Abstraction over a voucher
/// Ci = ClientId, Vi = VendorId
pub trait Voucher<Ci, Vi>: Clone {
    /// returns `true` if the cryptographic signature on the voucher is valid
    fn is_valid_signature(&self) -> bool;
    /// nonce of the voucher, this value increases with each next voucher signed
    /// like a blockchain transaction
    fn nonce(&self) -> u64;
    /// the atoms the voucher is signed for
    fn voucher_atoms(&self) -> u64;
    /// returns user identifier for current protocol implementation
    /// example is erc20 address or public key on eddsa
    fn client_identifier(&self) -> Ci;
    fn vendor_identifier(&self) -> Vi;
}

/// NEEDS TO STORE NEW VOUCHERS IN DB
/// For storing in db this is good as we can keep only the few unspent vouchers in mem while all others are archived
/// For retrieval we only need to know the spent voucher nonce which is also stored.
/// All vouchers:
/// [V, V, V, V, unspent(V, V, V, V, V)] (ordered nonce asc)
/// unspent_nonce=x
pub trait UnspentVouchersOp<Ci, Vi, V: Voucher<Ci, Vi>> {
    /// NOTE: THE UNSPENT VOUCHERS HAVE TO BE ORDERED ASCENDING ORDER BY NONCE
    fn rw_on_unspent_vouchers<F, R>(
        &self,
        ci: &Ci,
        f: F,
    ) -> impl std::future::Future<Output = Result<R, std::io::Error>> + Send
    where
        F: FnOnce(&mut ClientUnspentVouchers<Ci, Vi, V>) -> R;
}

#[derive(Debug, Clone)]
pub struct ClientUnspentVouchers<Ci, Vi, V> {
    /// only a temporary buffer when we move unspent_vouchers to spent vouchers
    /// (to not delete data from ds, only show where it is supposed to go)
    /// spent vouchers should be flushed away and emptied to db
    pub spent_vouchers: Vec<V>,
    /// Only vouchers that were not spent yet by the client
    pub unspent_vouchers: Vec<V>,
    /// None if this client has never been interacted with
    pub last_known_nonce: Option<u64>,

    pub _ci: PhantomData<Ci>,
    pub _vi: PhantomData<Vi>,
}

impl<Ci, Vi, V: Voucher<Ci, Vi>> ClientUnspentVouchers<Ci, Vi, V> {
    /// first_unspent <= v.nonce() <= last+1
    pub(crate) fn is_unspent_nonce_range(&self, v: &V) -> bool {
        if self.unspent_vouchers.len() > 0 {
            let first = &self.unspent_vouchers[0];
            if v.nonce() < first.nonce() {
                return false;
            }
            let last = &self.unspent_vouchers[self.unspent_vouchers.len() - 1];
            if v.nonce() > (last.nonce() + 1) {
                return false;
            }
        }
        true
    }
}

pub struct UnspentVoucherTracker<Ci, Vi, V, T> {
    pub(crate) b: T,
    _ci: PhantomData<Ci>,
    _vi: PhantomData<Vi>,
    _v: PhantomData<V>,
}

impl<Ci, Vi, V, T> UnspentVoucherTracker<Ci, Vi, V, T> {
    pub fn new(b: T) -> Self {
        Self {
            b,
            _ci: PhantomData,
            _vi: PhantomData,
            _v: PhantomData,
        }
    }
}
