use crate::voucher::Voucher;
use std::{fmt::Debug, marker::PhantomData};

pub trait SettleVouchersOp<Ci, Vi, V: Voucher<Ci, Vi>> {
    /// NOTE: THE VOUCHERS HAVE TO BE ORDERED ASCENDING ORDER BY NONCE
    fn rw_on_settle_vouchers<F, R>(
        &self,
        ci: &Ci,
        f: F,
    ) -> impl std::future::Future<Output = Result<R, std::io::Error>> + Send
    where
        F: FnOnce(&mut ClientSettleVouchers<Ci, Vi, V>) -> R;
}

pub struct SettleVouchers<Ci, Vi, V, T> {
    pub(crate) b: T,
    _ci: PhantomData<Ci>,
    _vi: PhantomData<Vi>,
    _v: PhantomData<V>,
    _t: PhantomData<T>,
}
impl<Ci, Vi, V: Voucher<Ci, Vi>, T: SettleVouchersOp<Ci, Vi, V>> SettleVouchers<Ci, Vi, V, T> {}

/// an interface to some async job which may run a few seconds
/// and we don't want to spawn multiple instances of
pub trait SettleJob {
    fn is_finished(&self) -> bool;
    fn is_successful(&self) -> bool;
    fn up_to_incl_nonce(&self) -> u64;
    fn reference(&self) -> String;
}

pub struct SettledVoucher<V> {
    pub v: V,
    pub reference: String,
}

pub struct ClientSettleVouchers<Ci, Vi, V> {
    pub unsettled_vouchers: Vec<V>,
    pub settled_vouchers: Vec<SettledVoucher<V>>,
    pub job: Option<Box<dyn SettleJob>>,
    pub _ci: PhantomData<Ci>,
    pub _vi: PhantomData<Vi>,
}

impl<Ci, Vi, V: Voucher<Ci, Vi>> ClientSettleVouchers<Ci, Vi, V> {
    /// ops on this ds might trigger a settle job (sending tx to chain)
    /// once the job is acknowledged the vouchers can move to 'settled_vouchers' with the appropriate reference tx
    /// return true if some job finished successfuly
    pub fn try_cleanup_job(&mut self) -> bool {
        let job_finished = self.job.as_ref().map(|x| x.is_finished()).unwrap_or(false);
        if job_finished {
            if let Some(j) = self.job.take() {
                // if not successful nothing happens
                if j.is_successful() {
                    let r = j.reference();
                    let up_to_incl_nonce = j.up_to_incl_nonce();
                    for u in &self.unsettled_vouchers {
                        if u.nonce() > up_to_incl_nonce {
                            break;
                        }
                        self.settled_vouchers.push(SettledVoucher {
                            v: u.clone(),
                            reference: r.clone(),
                        });
                    }
                    self.unsettled_vouchers = std::mem::take(&mut self.unsettled_vouchers)
                        .into_iter()
                        .filter(|x| x.nonce() > up_to_incl_nonce)
                        .collect();
                    return true;
                }
            }
        }
        false
    }
}
