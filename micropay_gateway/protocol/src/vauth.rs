use crate::traits::*;
use std::marker::PhantomData;

/// Answers the question:
/// Given the client voucher, are we willing to continue processing the request?
pub struct VoucherAuth<V, U, K> {
    pub vt: Box<dyn VoucherTracker<V, U>>,
    pub o: Box<dyn ChainOracle<U, K>>,
    /// the identity of this vendor
    pub vendor: K,
    _u: PhantomData<U>,
    _k: PhantomData<K>,
}

impl<U, K: Eq, V: Voucher<U, K>> VoucherAuth<V, U, K> {
    /// Vouchers are both authentication and payment.
    /// The voucher is valid if:
    /// - insert voucher if next in seq
    /// STATIC:
    /// - the voucher sig is valid
    /// - the voucher is in the name of the vendor
    /// VOLATILE:
    /// - the voucher is unspent (subject to change based on usage)
    /// - the client is subscribed to vendor (subject to change based on client changes)
    /// - the client collateral is >= voucher size
    ///     (subject to change on client withdrawing or settling against other vendors)
    pub fn is_auth(&self, v: &V) -> bool {
        if !self.is_auth_static(v) {
            return false;
        }
        if !self.is_auth_volatile(v) {
            return false;
        }
        // finally if voucher is new
        let ln = self.vt.get_latest_voucher_nonce(&v.client_identifier());
        if v.nonce() > (ln + 1) {
            // not increasing by 1
            return false;
        }
        if v.nonce() == (ln + 1) {
            // insert new
            self.vt.insert_voucher(v.clone());
        }
        true
    }

    /// Called whenever new voucher is seen.
    pub fn is_auth_static(&self, v: &V) -> bool {
        if !v.is_valid_signature() {
            return false;
        }
        if v.voucher_atoms() == 0 {
            return false;
        }
        let vi = v.vendor_identifier();
        if vi != self.vendor {
            // the vendor is different
            return false;
        }
        // static part true
        true
    }

    /// Called on each packet from client (since the env can change)
    pub fn is_auth_volatile(&self, v: &V) -> bool {
        let ci = v.client_identifier();
        let unspent_nonce = self.vt.get_first_unspent_voucher_nonce(&ci);
        if unspent_nonce > v.nonce() {
            // no longer valid auth, the voucher has no value to vendor
            return false;
        }
        let vi = v.vendor_identifier();
        let is_sub = self.o.is_client_subscribed(&ci, &vi);
        if !is_sub {
            // client is not subscribed
            return false;
        }
        let collat = self.o.get_client_collateral(&ci);
        if collat < v.voucher_atoms() {
            // client can't pay as far as we know
            return false;
        }
        // volatile part true
        true
    }
}
