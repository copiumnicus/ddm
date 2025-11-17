use super::coracle::*;
use super::voucher::*;
use std::marker::PhantomData;
use thiserror::Error;

/// Answers the question:
/// Given the client voucher, are we willing to continue processing the request?
/// Vouchers are both authentication and payment.
///
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
pub struct VoucherAuth<Ci, Vi, V, COR, T0, T1> {
    pub vt: UnspentVoucherTracker<Ci, Vi, V, T0>,
    pub o: ClientOracle<Ci, Vi, COR, T1>,
    /// the identity of this vendor
    vendor: Vi,
}

impl<Ci, Vi: Eq, V: Voucher<Ci, Vi>, COR: ClientOracleRecord<Vi>, T0, T1>
    VoucherAuth<Ci, Vi, V, COR, T0, T1>
where
    T0: UnspentVouchersOp<Ci, Vi, V>,
    T1: ClientOracleRead<Ci, Vi, COR>,
{
    pub fn new(
        vendor: Vi,
        vt: UnspentVoucherTracker<Ci, Vi, V, T0>,
        o: ClientOracle<Ci, Vi, COR, T1>,
    ) -> Self {
        Self { vendor, o, vt }
    }

    /// assert auth and start session (whenever new voucher is seen or changed)
    /// insert voucher if new
    pub async fn is_auth_start_session(&self, v: &V) -> Result<(), VAuthErr> {
        self.is_auth_static(v)?;
        self.check_oracle(v).await?;
        self.vt
            .b
            .rw_on_unspent_vouchers(&v.client_identifier(), |r| {
                if !self.vt.is_unspent_nonce_range(v, r) {
                    return Err(VAuthErr::VoucherSpentOrNonceTooHigh);
                }
                // figure out if need to insert new
                match r.last_known_nonce {
                    Some(ln) => {
                        if v.nonce() == (ln + 1) {
                            // need to insert new voucher
                            r.last_known_nonce = Some(v.nonce());
                            r.unspent_vouchers.push(v.clone());
                        }
                    }
                    None => {
                        if v.nonce() != 0 {
                            return Err(VAuthErr::FirstVoucherNonceInvalid);
                        }
                        // need to insert first ever voucher
                        r.last_known_nonce = Some(v.nonce());
                        r.unspent_vouchers.push(v.clone());
                    }
                }
                Ok(())
            })
            .await??;
        Ok(())
    }

    /// check volatile parts of the voucher
    pub async fn is_auth_start_query(&self, v: &V) -> Result<(), VAuthErr> {
        self.is_auth_static(v)?;
        self.check_oracle(v).await?;
        // within the session just check if the provided voucher is still unspent
        self.vt
            .b
            .rw_on_unspent_vouchers(&v.client_identifier(), |r| {
                if !self.vt.is_unspent_nonce_range(v, r) {
                    return Err(VAuthErr::VoucherSpentOrNonceTooHigh);
                }
                Ok(())
            })
            .await??;
        Ok(())
    }

    async fn check_oracle(&self, v: &V) -> Result<(), VAuthErr> {
        self.o
            .b
            .r_on_client_oracle(&v.client_identifier(), |r| {
                if !r.is_subscribed(&self.vendor) {
                    return Err(VolatileVAuthErr::ClientIsNotSubscribed);
                }
                let collat = r.collateral();
                let va = v.voucher_atoms();
                if collat < va {
                    // client can't pay as far as we know
                    return Err(VolatileVAuthErr::ClientHasInsufficientBalance {
                        seen_balance: collat,
                        voucher_atoms: va,
                    });
                }
                Ok(())
            })
            .await??; // notice unwrap both errs
        Ok(())
    }

    /// Called whenever new voucher is seen.
    fn is_auth_static(&self, v: &V) -> Result<(), StaticVAuthErr> {
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
}

#[derive(Debug, Error)]
pub enum VAuthErr {
    #[error("Voucher is either spent or nonce is higher than last_known_nonce+1")]
    VoucherSpentOrNonceTooHigh,
    #[error("Race err when inserting voucher")]
    NewVoucherRace,
    #[error("IO {0}")]
    IO(#[from] std::io::Error),
    #[error("Static {0}")]
    Static(#[from] StaticVAuthErr),
    #[error("Volatile {0}")]
    Volatile(#[from] VolatileVAuthErr),
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
    #[error("IO {0}")]
    IO(#[from] std::io::Error),
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
