use parking_lot::Mutex;
use protocol::traits::*;
use std::collections::HashMap;
use std::sync::Arc;

pub type ClientId = u64;
pub type VendorId = u64;

#[derive(Clone, Debug)]
pub struct TestVoucher {
    pub ci: u64,
    pub vi: u64,
    pub nonce: u64,
    pub atoms: u64,
}

impl Voucher<ClientId, VendorId> for TestVoucher {
    const DECIMALS: u32 = 6;
    fn client_identifier(&self) -> ClientId {
        self.ci
    }
    fn vendor_identifier(&self) -> VendorId {
        self.vi
    }
    fn nonce(&self) -> u64 {
        self.nonce
    }
    fn is_valid_signature(&self) -> bool {
        true
    }
    fn voucher_atoms(&self) -> u64 {
        self.atoms
    }
}

#[derive(Debug, Clone)]
pub struct TestVTracker {
    /// these would be in db
    pub client_to_v: Arc<Mutex<HashMap<ClientId, ClientVouchers>>>,
}

#[derive(Default, Debug)]
pub struct ClientVouchers {
    pub vouchers: Vec<TestVoucher>,
    /// None if vouchers.len()==0
    pub spent_nonce: Option<u64>,
}

impl VoucherTracker<TestVoucher, ClientId> for TestVTracker {
    fn get_first_unspent_voucher(&self, ci: &VendorId) -> Result<TestVoucher, VTrackErr> {
        let mut g = self.client_to_v.lock();
        let e = g.entry(*ci).or_default();
        match e.spent_nonce.map(|x| x + 1) {
            Some(unspent) => {
                for v in e.vouchers.iter().rev() {
                    if v.nonce == unspent {
                        return Ok(v.clone());
                    }
                }
                Err(VTrackErr::NoVoucher)
            }
            None => {
                if e.vouchers.len() == 0 {
                    return Err(VTrackErr::NoVoucher);
                }
                Ok(e.vouchers[0].clone())
            }
        }
    }
    fn get_latest_voucher_nonce(&self, ci: &VendorId) -> Result<u64, VTrackErr> {
        let mut g = self.client_to_v.lock();
        let e = g.entry(*ci).or_default();
        e.vouchers
            .last()
            .map(|x| x.nonce())
            .ok_or(VTrackErr::NoVoucher)
    }
    fn get_unspent_atoms(&self, ci: &VendorId) -> Result<u64, VTrackErr> {
        let mut g = self.client_to_v.lock();
        let e = g.entry(*ci).or_default();
        match e.spent_nonce {
            Some(spent_nonce) => {
                let mut sm = 0;
                for v in e.vouchers.iter() {
                    if v.nonce > spent_nonce {
                        sm += v.atoms;
                    }
                }
                Ok(sm)
            }
            None => Ok(e.vouchers.iter().map(|x| x.atoms).sum()),
        }
    }
    fn insert_voucher(&self, v: TestVoucher) -> Result<(), VTrackErr> {
        let mut g = self.client_to_v.lock();
        let e = g.entry(v.ci).or_default();
        e.vouchers.push(v);
        Ok(())
    }
    fn mark_spent(&self, ci: &VendorId, nonce: u64) {
        let mut g = self.client_to_v.lock();
        let e = g.entry(*ci).or_default();
        e.spent_nonce = Some(nonce);
    }
}

pub struct CostTrack {
    pub client_to_v: Mutex<HashMap<ClientId, ClientCost>>,
}

#[derive(Default)]
pub struct ClientCost {
    pub unmarked: u64,
    pub lockv: u64,
}

impl UnmarkedCostTracker<ClientId> for CostTrack {
    fn add_cost(&self, ci: &ClientId, atoms: u64) {
        let mut g = self.client_to_v.lock();
        let e = g.entry(*ci).or_default();
        e.unmarked += atoms;
    }
    fn reduce(&self, ci: &ClientId, atoms: u64) {
        let mut g = self.client_to_v.lock();
        let e = g.entry(*ci).or_default();
        e.unmarked = e.unmarked.saturating_sub(atoms);
    }
    fn lock(&self, ci: &ClientId, atoms: u64) {
        let mut g = self.client_to_v.lock();
        let e = g.entry(*ci).or_default();
        e.lockv += atoms;
    }
    fn unlock(&self, ci: &ClientId, atoms: u64) {
        let mut g = self.client_to_v.lock();
        let e = g.entry(*ci).or_default();
        e.lockv = e.lockv.saturating_sub(atoms);
    }
    fn unmarked_cost(&self, ci: &ClientId) -> u64 {
        let mut g = self.client_to_v.lock();
        let e = g.entry(*ci).or_default();
        e.unmarked
    }
    fn locked_cost(&self, ci: &ClientId) -> u64 {
        let mut g = self.client_to_v.lock();
        let e = g.entry(*ci).or_default();
        e.lockv
    }
}

#[derive(Clone)]
pub struct Chain {}

impl ChainOracle<ClientId, VendorId> for Chain {
    fn get_client_collateral(&self, ci: &ClientId) -> Result<u64, OracleErr> {
        Ok(3 * 10u64.pow(TestVoucher::DECIMALS))
    }
    fn get_total_subscribed(&self, ci: &ClientId) -> Result<u64, OracleErr> {
        Ok(2)
    }
    fn is_client_subscribed(&self, ci: &ClientId, vi: &VendorId) -> Result<bool, OracleErr> {
        Ok(true)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use assert_matches::assert_matches;
    use protocol::*;

    const VENDOR: u64 = 42;
    const CLIENT: u64 = 30;

    fn setup() -> (TestVoucher, TestVTracker, Engine<TestVoucher, u64, u64>) {
        let vendor = 42;
        let o = Box::new(Chain {});
        let cr = ClientRisk::new(o.clone(), None);
        let vtc = TestVTracker {
            client_to_v: Arc::new(Mutex::new(HashMap::new())),
        };
        let vt = Box::new(vtc.clone());
        let u = Box::new(CostTrack {
            client_to_v: Mutex::new(HashMap::new()),
        });
        let ct = CreditTrack::new(cr, vt.clone(), u);
        let va = VoucherAuth::new(vendor, vt, o);
        let mut v = TestVoucher {
            ci: CLIENT,
            vi: VENDOR,
            nonce: 1,
            atoms: 10 * 10u64.pow(TestVoucher::DECIMALS as u32),
        };
        (v, vtc, Engine { ct, va })
    }

    #[test]
    fn test_engine() -> Result<(), EngineErr> {
        let (mut v, vt, e) = setup();

        assert_matches!(
            e.accept_session(v.clone()),
            Err(EngineErr::VAuth(VAuthErr::Volatile(
                VolatileVAuthErr::ClientHasInsufficientBalance { .. }
            )))
        );
        v.atoms = 1 * 10u64.pow(TestVoucher::DECIMALS as u32);
        assert_matches!(
            e.accept_session(v.clone()),
            Err(EngineErr::VAuth(VAuthErr::FirstVoucherNonceInvalid))
        );
        // user can sign more than they have because they haven't spent it and
        // vendor hasn't used it.
        v.nonce = 0;
        assert_matches!(e.accept_session(v.clone()), Ok(()));
        v.nonce = 1;
        assert_matches!(e.accept_session(v.clone()), Ok(()));
        v.nonce = 2;
        assert_matches!(e.accept_session(v.clone()), Ok(()));
        println!("{:#?}", vt);

        let aprx_cost = 1000;
        let qc = e.accept_query(CLIENT, aprx_cost)?;
        assert_matches!(
            qc,
            QueryCont {
                case: QueryCase::Continue { locked_cost: 1000 },
                ..
            }
        );
        println!("{:#?}", qc);
        let sq = SettleQuery {
            hour_price: 0.1 * 10f64.powf(TestVoucher::DECIMALS as f64),
            data_bytes: (1.0 * 1e3) as u64,
            gb_price: 0.2 * 10f64.powf(TestVoucher::DECIMALS as f64),
        };
        println!("sq {:?}", sq);
        println!("cost {}", sq.cost(qc.start));
        let hour = qc.start.elapsed().as_secs_f64() / 3600.0;
        let giga_bytes = sq.data_bytes as f64 / (8.0 * 1e9);
        let v = (hour * sq.hour_price) + (giga_bytes * sq.gb_price);
        println!("cost f64 {}", v);

        let res = e.settle_query(&CLIENT, &qc, sq)?;
        println!("{:#?}", res);

        Ok(())
    }
}
