use std::{marker::PhantomData, sync::Arc};

/// The record of the on-chain data for a client
pub trait ClientOracleRecord<VendorId> {
    /// returns collateral soon to be (after queued withdrawals expire)
    fn collateral_to_be(&self) -> u64;
    /// if unsub is queued this returns false preemptively
    fn is_subscribed_to_be(&self, vi: &VendorId) -> bool;

    fn collateral_now(&self) -> u64;
    /// returns subscriptions now
    fn subscriptions_now(&self) -> u64;
}

pub trait ClientOracleRead<Ci, Vi, COR: ClientOracleRecord<Vi>> {
    fn r_on_client_oracle<F, R>(
        &self,
        ci: &Ci,
        f: F,
    ) -> impl std::future::Future<Output = Result<R, std::io::Error>> + Send
    where
        F: FnOnce(&COR) -> R;
}

#[derive(Clone)]
pub struct ClientOracle<Ci, Vi, COR, T> {
    pub(crate) b: Arc<T>,
    _ci: PhantomData<Ci>,
    _vi: PhantomData<Vi>,
    _cor: PhantomData<COR>,
}

impl<Ci, Vi, COR, T> ClientOracle<Ci, Vi, COR, T> {
    pub fn new(b: Arc<T>) -> Self {
        Self {
            b,
            _ci: PhantomData,
            _vi: PhantomData,
            _cor: PhantomData,
        }
    }
}
