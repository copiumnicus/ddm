use std::marker::PhantomData;

/// The value represented is atoms
pub trait OutstandingBalanceRecord {
    fn outstanding(&mut self) -> &mut u64;
    fn lock_value(&mut self) -> &mut u64;
}

/// to make an outstanding balance tracker, we need the means of accessing the outstanding balance of each client
pub trait ClientOutstandingBalanceOp<ClientId, OBR: OutstandingBalanceRecord> {
    fn rw_on_client_o_balance<F, R>(
        &self,
        ci: &ClientId,
        f: F,
    ) -> impl std::future::Future<Output = Result<R, std::io::Error>> + Send
    where
        F: FnOnce(&mut OBR) -> R + Send;
}

/// With the means of accessing the outstanding balance records abstracted, we can impl the tracker logic.
/// This tracker holds value that wasn't assigned to any vouchers yet, because it is 'dust', too small.
/// It also accurately tracks outstanding balance when client makes parallel calls
pub struct OutstandingBalanceTracker<T, ClientId, OBR> {
    pub b: T,
    _ci: PhantomData<ClientId>,
    _obr: PhantomData<OBR>,
}

impl<T: ClientOutstandingBalanceOp<ClientId, OBR>, ClientId, OBR: OutstandingBalanceRecord>
    OutstandingBalanceTracker<T, ClientId, OBR>
{
    pub fn new(b: T) -> Self {
        Self {
            b,
            _ci: PhantomData,
            _obr: PhantomData,
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use std::{collections::HashMap, sync::Arc};
    use tokio::sync::Mutex;

    #[derive(Clone)]
    struct OBalanceR {
        o: u64,
        l: u64,
    }
    impl OutstandingBalanceRecord for OBalanceR {
        fn lock_value(&mut self) -> &mut u64 {
            &mut self.l
        }
        fn outstanding(&mut self) -> &mut u64 {
            &mut self.o
        }
    }

    /// this is some hypothetical async object that snapshots to db with async mutexes
    struct OutstandingBalanceRecords {
        a: Arc<Mutex<HashMap<u64, OBalanceR>>>,
    }

    /// this is the means of accessing and modifying the data
    impl ClientOutstandingBalanceOp<u64, OBalanceR> for OutstandingBalanceRecords {
        async fn rw_on_client_o_balance<F, R>(&self, id: &u64, f: F) -> Result<R, std::io::Error>
        where
            F: FnOnce(&mut OBalanceR) -> R,
        {
            let mut g = self.a.lock().await;
            let a = g
                .get_mut(&id)
                .ok_or(std::io::Error::other("missing client"))?;
            let r = f(a);
            Ok(r)
        }
    }

    #[tokio::test]
    async fn test_op_outstanding_balance() {
        let mut m = HashMap::new();
        m.insert(0, OBalanceR { o: 10, l: 0 });
        let o = OutstandingBalanceRecords {
            a: Arc::new(Mutex::new(m)),
        };
        let r = o.rw_on_client_o_balance(&0, |x| x.o).await.unwrap();
        assert_eq!(r, 10);
        let r = o.rw_on_client_o_balance(&1, |x| x.o).await;
        assert!(r.is_err());
    }
}
