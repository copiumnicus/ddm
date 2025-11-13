use crate::{ctrack::*, traits::*, vauth::*};
use std::time::Instant;

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

pub struct QueryCont {
    pub start: Instant,
    pub case: QueryCase,
}
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

pub struct SettleQuery {
    pub time_hour: f64,
    pub time_price: f64,
    pub data_gb: f64,
    pub data_price: f64,
}

impl SettleQuery {
    pub fn cost(&self) -> u64 {
        let v = (self.time_hour * self.time_price) + (self.data_gb * self.data_price);
        v as u64
    }
}

pub struct CreditStatus {
    pub uc: UserCredit,
    pub sq: SettleQuery,
}

impl<V: Voucher<U, K>, U, K: Eq> Engine<V, U, K> {
    pub fn accept_session(&self, v: V) -> bool {
        self.va.is_auth(&v)
    }
    pub fn accept_query(&self, ci: U, aprx_cost: u64) -> QueryCont {
        let uc = self.ct.user_credit(&ci);
        let start = Instant::now();
        if aprx_cost > uc.available() {
            return QueryCont {
                start,
                case: QueryCase::Reject { aprx_cost, uc },
            };
        }
        self.ct.u.lock(&ci, aprx_cost);
        QueryCont {
            start,
            case: QueryCase::Continue {
                locked_cost: aprx_cost,
            },
        }
    }
    pub fn settle_query(&self, ci: &U, q: &QueryCont, sq: SettleQuery) -> CreditStatus {
        let cost = sq.cost();
        match q.case {
            QueryCase::Reject { .. } => {}
            QueryCase::Continue { locked_cost } => {
                self.ct.u.unlock(ci, locked_cost);
            }
        }
        self.ct.u.add_cost(ci, cost);
        let first_unspent = self.va.vt.get_first_unspent_voucher(ci);
        let fa = first_unspent.voucher_atoms();
        if self.ct.u.unmarked_cost(ci) > fa {
            self.ct.vt.mark_spent(ci, first_unspent.nonce());
            self.ct.u.reduce(ci, fa);
        }
        let uc = self.ct.user_credit(ci);
        CreditStatus { uc, sq }
    }
}
