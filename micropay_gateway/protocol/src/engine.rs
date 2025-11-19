use super::{coracle::*, obalance::*, vauth::*, voucher::*};
use crate::settle::{SettleVouchers, SettleVouchersOp};
use thiserror::Error;

/// settle will hold the settlement off until most profitable i.e max_settle_count
/// but will settle at less profit if:
/// => our unsettled is above configured risk (bcs client queued withdrawal or unsub)
/// for that we need to know:
/// - the actual client balance now
/// - the soon to be balance after client queued actions (if unsub 0 if withdrawal some cur-x)
pub struct SettleConfig {
    /// HAS TO BE SMALLER THAN `do_settle_size` and `max_settle_count`*`client_risk.min_voucher_size_atoms`
    pub min_settle_size: u64,
    /// even though there could be few vouchers,
    /// the value might be big, this is the threshold for settling in that case
    pub do_settle_size: u64,
    pub max_settle_count: usize,
}

/// this can be running on a different machine
pub struct CronEngine<Ci, Vi, V, COR, T1, T3> {
    settle: SettleConfig,
    vendor: Vi,
    cr: ClientRiskConfig,
    o: ClientOracle<Ci, Vi, COR, T1>,
    s: SettleVouchers<Ci, Vi, V, T3>,
}

impl<Ci, Vi, V: Voucher<Ci, Vi>, COR: ClientOracleRecord<Vi>, T1, T3>
    CronEngine<Ci, Vi, V, COR, T1, T3>
where
    T1: ClientOracleRead<Ci, Vi, COR>,
    T3: SettleVouchersOp<Ci, Vi, V>,
{
    /// mby try to settle clients unsettled vouchers
    pub async fn mby_start_settle_job(&self, ci: &Ci) -> Result<(), EngineErr> {
        let (unsettled, count, job_running) = self
            .s
            .b
            .rw_on_settle_vouchers(ci, |x| {
                x.try_cleanup_job();
                if x.job.is_some() {
                    return (0, 0, true);
                }
                let mut unsettled = 0u64;
                for u in &x.unsettled_vouchers {
                    unsettled += u.voucher_atoms();
                }
                (unsettled, x.unsettled_vouchers.len(), false)
            })
            .await?;
        if job_running || unsettled < self.settle.min_settle_size {
            return Ok(());
        }
        // if unsettled > min size and no job running
        // do some checks:
        let (actual_balance, balance_to_be, subs) = self
            .o
            .b
            .r_on_client_oracle(ci, |r| {
                let actual_balance = r.collateral_now();
                let subs = r.subscriptions_now();
                if !r.is_subscribed_to_be(&self.vendor) {
                    return (actual_balance, 0, subs);
                }
                (actual_balance, r.collateral_to_be(), subs)
            })
            .await?;
        let safe_cap_to_be = self.cr.get_client_risk_adj_collateral(balance_to_be, subs);
        let over_risk = unsettled >= safe_cap_to_be;
        let max_count = count >= self.settle.max_settle_count;
        let over_do_size = unsettled >= self.settle.do_settle_size;
        // these 3 are the possible triggers for a settle job
        let trigger = over_risk || max_count || over_do_size;
        if !trigger {
            return Ok(());
        }
        // rip
        if actual_balance < self.settle.min_settle_size {
            return Ok(());
        }
        let max_settle = actual_balance.min(unsettled);
        // now pick out the vouchers to use
        let to_settle = self
            .s
            .b
            .rw_on_settle_vouchers(ci, |x| {
                let mut res = Vec::new();
                let mut sm = 0;
                for u in &x.unsettled_vouchers {
                    let new = sm + u.voucher_atoms();
                    if new > max_settle {
                        break;
                    }
                    sm = new;
                    res.push(u.clone())
                }
                res
            })
            .await?;

        Ok(())
    }
}

pub struct ApiEngine<Ci, Vi, V, COR, OBR, T0, T1, T2> {
    va: VoucherAuth<Ci, Vi, V, COR, T0, T1>,
    ob: OutstandingBalanceTracker<T2, Ci, OBR>,
    cr: ClientRiskConfig,
}

#[derive(Debug, Error)]
pub enum EngineErr {
    #[error("Auth {0}")]
    VAuth(#[from] VAuthErr),
    #[error("IO {0}")]
    IO(#[from] std::io::Error),
}

#[derive(Debug)]
pub struct QueryCont {
    /// we lock the approx cost of query so user can't parallel call for the same atoms
    locked_cost: u64,
    /// if the cost checks passed and should continue
    pub should_continue: bool,
}
/// accounts for the client burst subscribing to 5 new vendors
pub const DEFAULT_VENDOR_CLIENT_EXPAND_RISK: u64 = 5;
/// usdc decimals is 6 this is 0.5cent
pub const DEFAULT_MIN_VOUCHER_SIZE: u64 = 5000;

#[derive(Clone)]
pub struct ClientRiskConfig {
    vendor_client_expand_risk: u64,
    min_voucher_size_atoms: u64,
}

impl ClientRiskConfig {
    pub fn new() -> Self {
        Self {
            min_voucher_size_atoms: DEFAULT_MIN_VOUCHER_SIZE,
            vendor_client_expand_risk: DEFAULT_VENDOR_CLIENT_EXPAND_RISK,
        }
    }
    pub fn min_voucher(mut self, atoms: u64) -> Self {
        self.min_voucher_size_atoms = atoms;
        self
    }
    pub fn expand_risk(mut self, client_expand_risk: u64) -> Self {
        self.vendor_client_expand_risk = client_expand_risk;
        self
    }
    pub fn get_client_risk_adj_collateral(&self, ci_collateral: u64, ci_subscriptions: u64) -> u64 {
        let sm = ci_subscriptions + self.vendor_client_expand_risk;
        if sm == 0 {
            return ci_collateral;
        }
        let unspent_per_vendor_safe = ci_collateral / sm;
        unspent_per_vendor_safe
    }
}

impl<
    Ci,
    Vi: Eq,
    V: Voucher<Ci, Vi>,
    COR: ClientOracleRecord<Vi>,
    OBR: OutstandingBalanceRecord,
    T0,
    T1,
    T2,
> ApiEngine<Ci, Vi, V, COR, OBR, T0, T1, T2>
where
    T0: UnspentVouchersOp<Ci, Vi, V>,
    T1: ClientOracleRead<Ci, Vi, COR>,
    T2: ClientOutstandingBalanceOp<Ci, OBR>,
{
    pub async fn accept_session(&self, v: &V) -> Result<(), EngineErr> {
        Ok(self
            .va
            .is_auth_start_session(v, self.cr.min_voucher_size_atoms)
            .await?)
    }
    pub async fn accept_query(&self, v: &V) -> Result<(), EngineErr> {
        Ok(self.va.is_auth_start_query(v).await?)
    }
    /// within a session:
    pub async fn query(&self, ci: &Ci, aprx_cost: u64) -> Result<QueryCont, EngineErr> {
        // in order of rate of updates get data to calculate the safe credit for client
        let (ci_collat, ci_sub) = self
            .va
            .o
            .b
            .r_on_client_oracle(ci, |x| (x.collateral_to_be(), x.subscriptions_now()))
            .await?;
        // oracle guided amt that client can spend that we can settle in reasonable time without them withdrawing
        // or spending somewhere else
        let safe_cap = self.cr.get_client_risk_adj_collateral(ci_collat, ci_sub);
        let unspent: u64 = self
            .va
            .vt
            .b
            .rw_on_unspent_vouchers(ci, |x| {
                x.unspent_vouchers.iter().map(|x| x.voucher_atoms()).sum()
            })
            .await?;

        let mut qc = QueryCont {
            locked_cost: 0,
            should_continue: false,
        };
        self.ob
            .b
            .rw_on_client_o_balance(ci, |r| {
                let safe_avb = unspent
                    .saturating_sub(*r.outstanding())
                    .saturating_sub(*r.lock_value())
                    .min(safe_cap);
                if aprx_cost > safe_avb {
                    return Ok(qc);
                }
                *r.lock_value() += aprx_cost;
                qc.locked_cost = aprx_cost;
                qc.should_continue = true;
                Ok(qc)
            })
            .await?
    }
    pub async fn settle_query(
        &self,
        ci: &Ci,
        q: &QueryCont,
        actual_cost: u64,
    ) -> Result<(), EngineErr> {
        if !q.should_continue {
            return Ok(());
        }
        let outstanding_bal = self
            .ob
            .b
            .rw_on_client_o_balance(ci, |x| {
                *x.outstanding() += actual_cost;
                *x.lock_value() = x.lock_value().saturating_sub(q.locked_cost);
                *x.outstanding()
            })
            .await?;
        let mby_mark_spent = self
            .va
            .vt
            .b
            .rw_on_unspent_vouchers(ci, |r| {
                let should_mark = r
                    .unspent_vouchers
                    .first()
                    .map(|x| outstanding_bal >= x.voucher_atoms())
                    .unwrap_or(false);
                if should_mark {
                    let first = r.unspent_vouchers.remove(0);
                    r.spent_vouchers.push(first.clone());
                    return Some(first);
                }
                None
            })
            .await?;

        if let Some(voucher) = mby_mark_spent {
            // reduce
            let atoms = voucher.voucher_atoms();
            self.ob
                .b
                .rw_on_client_o_balance(ci, |r| {
                    *r.outstanding() = r.outstanding().saturating_sub(atoms);
                })
                .await?;
        }

        Ok(())
    }
}
