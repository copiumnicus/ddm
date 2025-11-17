use super::coracle::*;
use super::voucher::*;
use std::marker::PhantomData;
use thiserror::Error;

/// Answers the question:
/// Given the client voucher, are we willing to continue processing the request?
pub struct VoucherAuth<Ci, Vi, V, COR, T0, T1> {
    pub vt: UnspentVoucherTracker<Ci, Vi, V, T0>,
    pub o: ClientOracle<Ci, Vi, COR, T1>,
    /// the identity of this vendor
    pub vendor: Vi,
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
    pub async fn is_auth(&self, v: &V) -> Result<(), VAuthErr> {
        self.is_auth_static(v).await?;
        self.is_auth_volatile(v).await?;

        let mby_voucher_nonce = self.vt.last_known_nonce(&v.client_identifier()).await?;
        // finally if voucher is new
        match mby_voucher_nonce {
            Some(ln) => {
                if v.nonce() > (ln + 1) {
                    // not increasing by 1
                    return Err(VAuthErr::InvalidNonce {
                        signed_voucher: v.nonce(),
                        last_known_voucher: ln,
                    });
                }
                if v.nonce() == (ln + 1) {
                    // insert new
                    if !self.vt.insert_voucher(v.clone()).await? {
                        return Err(VAuthErr::NewVoucherRace);
                    }
                }
            }
            // no
            None => {
                if v.nonce() != 0 {
                    return Err(VAuthErr::FirstVoucherNonceInvalid);
                }
                if !self.vt.insert_voucher(v.clone()).await? {
                    return Err(VAuthErr::NewVoucherRace);
                }
            }
        }

        Ok(())
    }

    /// Called whenever new voucher is seen.
    pub async fn is_auth_static(&self, v: &V) -> Result<(), StaticVAuthErr> {
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
    pub async fn is_auth_volatile(&self, v: &V) -> Result<(), VolatileVAuthErr> {
        let ci = v.client_identifier();
        let mby_first_unspent = self
            .vt
            .b
            .rw_on_unspent_vouchers(&ci, |r| r.unspent_vouchers.first().map(|x| x.nonce()))
            .await?;
        if let Some(first_unspent) = mby_first_unspent {
            if first_unspent > v.nonce() {
                // `v` is not redeemable or used up
                return Err(VolatileVAuthErr::VoucherUsedUp);
            }
        }
        let vi = v.vendor_identifier();

        self.o
            .b
            .r_on_client_oracle(&ci, |r| {
                if !r.is_subscribed(&vi) {
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

        // volatile part true
        Ok(())
    }
}

#[derive(Debug, Error)]
pub enum VAuthErr {
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
