use super::{coracle::*, obalance::*, vauth::*, voucher::*};
use thiserror::Error;

pub struct Engine<Ci, Vi, V, COR, OBR, T0, T1, T2> {
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
pub struct ClientRiskConfig {
    vendor_client_expand_risk: u64,
}

impl ClientRiskConfig {
    pub fn new(vendor_client_expand_risk: Option<u64>) -> Self {
        Self {
            vendor_client_expand_risk: vendor_client_expand_risk
                .unwrap_or(DEFAULT_VENDOR_CLIENT_EXPAND_RISK),
        }
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
> Engine<Ci, Vi, V, COR, OBR, T0, T1, T2>
where
    T0: UnspentVouchersOp<Ci, Vi, V>,
    T1: ClientOracleRead<Ci, Vi, COR>,
    T2: ClientOutstandingBalanceOp<Ci, OBR>,
{
    pub async fn accept_session(&self, v: &V) -> Result<(), EngineErr> {
        Ok(self.va.is_auth_start_session(v).await?)
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
            .r_on_client_oracle(ci, |x| (x.collateral(), x.subscriptions()))
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
                if let Some(first_unspent) = r.unspent_vouchers.first() {
                    if outstanding_bal >= first_unspent.voucher_atoms() {
                        return Some(first_unspent.clone());
                    }
                }
                None
            })
            .await?;

        if let Some(voucher) = mby_mark_spent {
            self.va.vt.b.mark_spent(ci, voucher.nonce()).await?;
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
