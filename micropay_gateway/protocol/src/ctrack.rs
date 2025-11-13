use crate::traits::*;
use std::marker::PhantomData;

/// On top of what we know from the chain we need to bear in mind that
/// the client could be talking to N other vendors, so we need risk on top of that
/// to know how much credit we are willing to give to the client.
pub struct ClientRisk<U, K> {
    pub o: Box<dyn ChainOracle<U, K>>,
    pub vendor_client_expand_risk: Option<u64>,
}

/// accounts for the client burst subscribing to 5 new vendors
pub const DEFAULT_VENDOR_CLIENT_EXPAND_RISK: u64 = 5;

impl<U, K> ClientRisk<U, K> {
    pub fn get_client_risk_adj_collateral(&self, ci: &U) -> u64 {
        let collat = self.o.get_client_collateral(ci);
        let total_subs = self.o.get_total_subscribed(ci);
        let expand_risk = self
            .vendor_client_expand_risk
            .unwrap_or(DEFAULT_VENDOR_CLIENT_EXPAND_RISK);
        let unspent_per_vendor_safe = collat / (total_subs + expand_risk);
        unspent_per_vendor_safe
    }
}

/// Answers the question:
/// Given the state of the current system, how much credit are we giving to the user?
pub struct CreditTrack<V, U, K> {
    pub vt: Box<dyn VoucherTracker<V, U>>,
    pub cr: ClientRisk<U, K>,
    pub u: Box<dyn UnmarkedCostTracker<U>>,
    _u: PhantomData<U>,
    _k: PhantomData<K>,
}

/// Used to decide if we are willing to try to execute the given query
/// if query cost is high it might be bigger than user credit
#[derive(Debug, Clone)]
pub struct UserCredit {
    /// sum(unmarked_voucher.atoms)
    pub unspent: u64,
    /// dust that is smaller than first unmarked voucher
    pub unmarked: u64,
    /// cap that is to prevent burst over-consumption
    /// due vendor not having most recent on chain data
    pub cap: u64,
}

impl UserCredit {
    /// credit that user can spend
    pub fn available(&self) -> u64 {
        self.unspent.saturating_sub(self.unmarked).min(self.cap)
    }
}

impl<V, U, K> CreditTrack<V, U, K> {
    pub fn user_credit(&self, ci: &U) -> UserCredit {
        let unmarked = self.u.unmarked_cost(ci);
        let unspent = self.vt.get_unspent_atoms(ci);
        UserCredit {
            unspent,
            unmarked,
            cap: self.cr.get_client_risk_adj_collateral(ci),
        }
    }
}
