use crate::traits::*;
use std::marker::PhantomData;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum StaticVAuthErr {
    #[error("Voucher signature invalid")]
    InvalidSig,
    #[error("Voucher has zero atoms. It has no value")]
    VoucherHasZeroAtoms,
    #[error("Voucher is signed for a different vendor")]
    InvalidVendor,
}

#[derive(Debug, Error)]
pub enum VolatileVAuthErr {
    #[error("Voucher {0}")]
    VTrack(#[from] VTrackErr),
    #[error("Oracle {0}")]
    Oracle(#[from] OracleErr),
    #[error("This voucher is used up. Use an unspent one")]
    VoucherUsedUp,
    #[error("The client does not have a subscription to this vendor")]
    ClientIsNotSubscribed,
    #[error("The client has balance={seen_balance} but voucher is bigger value={voucher_atoms}")]
    ClientHasInsufficientBalance {
        seen_balance: u64,
        voucher_atoms: u64,
    },
}

#[derive(Debug, Error)]
pub enum VAuthErr {
    #[error("Static {0}")]
    Static(#[from] StaticVAuthErr),
    #[error("Volatile {0}")]
    Volatile(#[from] VolatileVAuthErr),
    #[error("VTrack {0}")]
    VTrack(#[from] VTrackErr),
    #[error(
        "Each new voucher nonce needs to be +1 of previous signed_nonce={signed_voucher} known={last_known_voucher}"
    )]
    InvalidNonce {
        signed_voucher: u64,
        last_known_voucher: u64,
    },
    #[error("First voucher nonce needs to be 0")]
    FirstVoucherNonceInvalid,
    #[error("Internal failure in auth")]
    InternalFailure,
}

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
    pub fn new(
        vendor: K,
        vt: Box<dyn VoucherTracker<V, U>>,
        o: Box<dyn ChainOracle<U, K>>,
    ) -> Self {
        Self {
            vendor,
            o,
            vt,
            _u: PhantomData,
            _k: PhantomData,
        }
    }
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
    pub fn is_auth(&self, v: &V) -> Result<(), VAuthErr> {
        self.is_auth_static(v)?;
        self.is_auth_volatile(v)?;
        // finally if voucher is new
        match self.vt.get_latest_voucher_nonce(&v.client_identifier()) {
            Ok(ln) => {
                if v.nonce() > (ln + 1) {
                    // not increasing by 1
                    return Err(VAuthErr::InvalidNonce {
                        signed_voucher: v.nonce(),
                        last_known_voucher: ln,
                    });
                }
                if v.nonce() == (ln + 1) {
                    // insert new
                    self.vt.insert_voucher(v.clone())?;
                }
            }
            Err(VTrackErr::NoVoucher) => {
                if v.nonce() != 0 {
                    return Err(VAuthErr::FirstVoucherNonceInvalid);
                }
                self.vt.insert_voucher(v.clone())?;
            }
            Err(VTrackErr::InternalFailure) => {
                return Err(VAuthErr::InternalFailure);
            }
        }

        Ok(())
    }

    /// Called whenever new voucher is seen.
    pub fn is_auth_static(&self, v: &V) -> Result<(), StaticVAuthErr> {
        if !v.is_valid_signature() {
            return Err(StaticVAuthErr::InvalidSig);
        }
        if v.voucher_atoms() == 0 {
            return Err(StaticVAuthErr::VoucherHasZeroAtoms);
        }
        let vi = v.vendor_identifier();
        if vi != self.vendor {
            // the vendor is different
            return Err(StaticVAuthErr::InvalidVendor);
        }
        // static part true
        Ok(())
    }

    /// Called on each packet from client (since the env can change)
    pub fn is_auth_volatile(&self, v: &V) -> Result<(), VolatileVAuthErr> {
        let ci = v.client_identifier();
        match self.vt.get_first_unspent_voucher(&ci).map(|x| x.nonce()) {
            Ok(unspent_nonce) => {
                if unspent_nonce > v.nonce() {
                    return Err(VolatileVAuthErr::VoucherUsedUp);
                }
            }
            Err(VTrackErr::NoVoucher) => {} //ok
            Err(e) => return Err(e.into()),
        };

        let vi = v.vendor_identifier();
        let is_sub = self.o.is_client_subscribed(&ci, &vi)?;
        if !is_sub {
            return Err(VolatileVAuthErr::ClientIsNotSubscribed);
        }
        let collat = self.o.get_client_collateral(&ci)?;
        let va = v.voucher_atoms();
        if collat < va {
            // client can't pay as far as we know
            return Err(VolatileVAuthErr::ClientHasInsufficientBalance {
                seen_balance: collat,
                voucher_atoms: va,
            });
        }
        // volatile part true
        Ok(())
    }
}
