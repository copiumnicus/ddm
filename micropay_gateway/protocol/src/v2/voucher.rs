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
    async fn rw_on_unspent_vouchers<F, R>(&self, ci: &Ci, f: F) -> Result<R, std::io::Error>
    where
        F: FnOnce(&mut ClientUnspentVouchers<V>) -> R;
    async fn mark_spent(&self, ci: &Ci, nonce: u64) -> Result<(), std::io::Error>;
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
    pub fn new(b: T) -> Self {
        Self {
            b,
            _ci: PhantomData,
            _vi: PhantomData,
            _v: PhantomData,
        }
    }

    pub async fn last_known_nonce(&self, ci: &Ci) -> Result<Option<u64>, std::io::Error> {
        self.b
            .rw_on_unspent_vouchers(ci, |v| v.last_known_nonce.clone())
            .await
    }
    /// returns true if successful inserting
    /// new voucher can only be last_known_global_nonce_for_vendor+1
    pub async fn insert_voucher(&self, v: V) -> Result<bool, std::io::Error> {
        self.b
            .rw_on_unspent_vouchers(&v.client_identifier(), |r| {
                // to prevent race conditions:
                if let Some(ln) = &r.last_known_nonce {
                    if v.nonce() != (ln + 1) {
                        return false;
                    }
                } else if v.nonce() != 0 {
                    return false;
                }
                // with checks out of the way:
                r.last_known_nonce = Some(v.nonce());
                r.unspent_vouchers.push(v);
                true
            })
            .await
    }
}
