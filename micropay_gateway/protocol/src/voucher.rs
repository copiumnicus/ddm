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

pub trait UnspentVouchersOp<Ci, Vi, V: Voucher<Ci, Vi>> {
    /// NOTE: THE UNSPENT VOUCHERS HAVE TO BE ORDERED ASCENDING ORDER BY NONCE
    fn rw_on_unspent_vouchers<F, R>(
        &self,
        ci: &Ci,
        f: F,
    ) -> impl std::future::Future<Output = Result<R, std::io::Error>> + Send
    where
        F: FnOnce(&mut ClientUnspentVouchers<V>) -> R;
    fn mark_spent(
        &self,
        ci: &Ci,
        nonce: u64,
    ) -> impl std::future::Future<Output = Result<(), std::io::Error>> + Send;
}

#[derive(Debug, Clone)]
pub struct ClientUnspentVouchers<V> {
    /// Only vouchers that were not spent yet by the client
    pub unspent_vouchers: Vec<V>,
    /// None if this client has never been interacted with
    pub last_known_nonce: Option<u64>,
}

pub struct UnspentVoucherTracker<Ci, Vi, V, T> {
    pub(crate) b: T,
    _ci: PhantomData<Ci>,
    _vi: PhantomData<Vi>,
    _v: PhantomData<V>,
}

impl<Ci, Vi, V: Voucher<Ci, Vi>, T: UnspentVouchersOp<Ci, Vi, V>>
    UnspentVoucherTracker<Ci, Vi, V, T>
{
    /// first_unspent <= v.nonce() <= last+1
    /// using self. to just bind the generics...
    pub(crate) fn is_unspent_nonce_range(&self, v: &V, r: &ClientUnspentVouchers<V>) -> bool {
        if r.unspent_vouchers.len() > 0 {
            let first = &r.unspent_vouchers[0];
            if v.nonce() < first.nonce() {
                return false;
            }
            let last = &r.unspent_vouchers[r.unspent_vouchers.len() - 1];
            if v.nonce() > (last.nonce() + 1) {
                return false;
            }
        }
        true
    }
    pub fn new(b: T) -> Self {
        Self {
            b,
            _ci: PhantomData,
            _vi: PhantomData,
            _v: PhantomData,
        }
    }
}
