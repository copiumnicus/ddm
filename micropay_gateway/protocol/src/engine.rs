use crate::{ctrack::*, traits::*, vauth::*};
use std::time::Instant;
use thiserror::Error;

/// 1. Get user req
/// 2. Check if voucher valid
///
/// 3. Check if user_credit > aprx_cost_of_query
/// 4. reserve(aprx_cost_of_query)
/// 5. Process query OR Deny query
/// 5. Subtract (ret_data_len*data_price + time*compute_price)
/// 6. Send status of credits AND (result of query OR notice for new voucher)
///
/// Rolling, on per second basis charge for connection + check risk
pub struct Engine<V, U, K> {
    pub va: VoucherAuth<V, U, K>,
    pub ct: CreditTrack<V, U, K>,
}

#[derive(Debug)]
pub struct QueryCont {
    pub start: Instant,
    pub case: QueryCase,
}

#[derive(Debug)]
pub enum QueryCase {
    Reject {
        aprx_cost: u64,
        uc: UserCredit,
    },
    /// we lock the approx cost of query so user can't parallel call for the same atoms
    Continue {
        locked_cost: u64,
    },
}

#[derive(Debug)]
pub struct SettleQuery {
    /// per hour
    pub hour_price: f64,
    pub data_bytes: u64,
    /// per GB
    pub gb_price: f64,
}
const HOUR_SEC: f64 = 60.0 * 60.0;
const GB_BYTES: f64 = 8.0 * 1e9;

impl SettleQuery {
    pub fn cost(&self, start: Instant) -> u64 {
        let hour = start.elapsed().as_secs_f64() / HOUR_SEC;
        let giga_bytes = self.data_bytes as f64 / GB_BYTES;
        let v = (hour * self.hour_price) + (giga_bytes * self.gb_price);
        v as u64
    }
}

#[derive(Debug)]
pub struct CreditStatus {
    pub uc: UserCredit,
    pub sq: SettleQuery,
}

#[derive(Debug, Error)]
pub enum EngineErr {
    #[error("Auth {0}")]
    VAuth(#[from] VAuthErr),
    #[error("Oracle {0}")]
    Oracle(#[from] OracleErr),
    #[error("VTrack {0}")]
    VTrack(#[from] VTrackErr),
}

impl<V: Voucher<U, K>, U, K: Eq> Engine<V, U, K> {
    pub fn accept_session(&self, v: V) -> Result<(), EngineErr> {
        Ok(self.va.is_auth(&v)?)
    }
    pub fn accept_query(&self, ci: U, aprx_cost: u64) -> Result<QueryCont, EngineErr> {
        let uc = self.ct.user_credit(&ci)?;
        let start = Instant::now();
        if aprx_cost > uc.available() {
            return Ok(QueryCont {
                start,
                case: QueryCase::Reject { aprx_cost, uc },
            });
        }
        self.ct.u.lock(&ci, aprx_cost);
        Ok(QueryCont {
            start,
            case: QueryCase::Continue {
                locked_cost: aprx_cost,
            },
        })
    }
    pub fn settle_query(
        &self,
        ci: &U,
        q: &QueryCont,
        sq: SettleQuery,
    ) -> Result<CreditStatus, EngineErr> {
        let cost = sq.cost(q.start);
        match q.case {
            QueryCase::Reject { .. } => {}
            QueryCase::Continue { locked_cost } => {
                self.ct.u.unlock(ci, locked_cost);
            }
        }
        self.ct.u.add_cost(ci, cost);
        let first_unspent = self.va.vt.get_first_unspent_voucher(ci)?;
        let fa = first_unspent.voucher_atoms();
        if self.ct.u.unmarked_cost(ci) > fa {
            self.ct.vt.mark_spent(ci, first_unspent.nonce());
            self.ct.u.reduce(ci, fa);
        }
        let uc = self.ct.user_credit(ci)?;
        Ok(CreditStatus { uc, sq })
    }
}
