use std::marker::PhantomData;

/// The record of the on-chain data for a client
pub trait ClientOracleRecord<VendorId> {
    fn collateral(&self) -> u64;
    fn subscriptions(&self) -> u64;
    fn is_subscribed(&self, vi: &VendorId) -> bool;
}

pub trait ClientOracleRead<Ci, Vi, COR: ClientOracleRecord<Vi>> {
    async fn r_on_client_oracle<F, R>(&self, ci: &Ci, f: F) -> Result<R, std::io::Error>
    where
        F: FnOnce(&COR) -> R;
}

pub struct ClientOracle<Ci, Vi, COR, T> {
    pub(crate) b: T,
    _ci: PhantomData<Ci>,
    _vi: PhantomData<Vi>,
    _cor: PhantomData<COR>,
}

impl<Ci, Vi, COR, T> ClientOracle<Ci, Vi, COR, T> {
    pub fn new(b: T) -> Self {
        Self {
            b,
            _ci: PhantomData,
            _vi: PhantomData,
            _cor: PhantomData,
        }
    }
}
