use std::marker::PhantomData;

/// The value represented is atoms
pub trait OutstandingBalanceRecord {
    fn outstanding(&mut self) -> &mut u64;
    fn lock_value(&mut self) -> &mut u64;
}

/// to make an outstanding balance tracker, we need the means of accessing the outstanding balance of each client
pub trait ClientOutstandingBalanceOp<ClientId, OBR: OutstandingBalanceRecord> {
    async fn rw_on_client_o_balance<F, R>(&self, ci: &ClientId, f: F) -> Result<R, std::io::Error>
    where
        F: FnOnce(&mut OBR) -> R;
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
    // pub fn credit_check_and_try_lock(&self, ci: &ClientId, aprx_cost: f64) {
    //     let mut g = self.client_to_v.lock();
    //     let e = g.entry(*ci).or_default();
    //     e.lockv += atoms;
    // }

    pub async fn add_obligation(&self, ci: &ClientId, atoms: u64) -> Result<(), std::io::Error> {
        self.b
            .rw_on_client_o_balance(ci, |x| {
                *x.outstanding() += atoms;
            })
            .await
    }
    /// unlock obligation locked for the time of the call
    pub async fn unlock(&self, ci: &ClientId, atoms: u64) -> Result<(), std::io::Error> {
        self.b
            .rw_on_client_o_balance(ci, |x| {
                *x.lock_value() = x.lock_value().saturating_sub(atoms);
            })
            .await
    }
    /// Once obligation grows to size of a voucher we can safely reduce it and mark voucher spent.
    pub async fn reduce_obligation(&self, ci: &ClientId, atoms: u64) -> Result<(), std::io::Error> {
        self.b
            .rw_on_client_o_balance(ci, |x| {
                *x.outstanding() = x.outstanding().saturating_sub(atoms);
            })
            .await
    }

    // pub fn unmarked_cost(&self, ci: &ClientId) -> u64 {
    //     let mut g = self.client_to_v.lock();
    //     let e = g.entry(*ci).or_default();
    //     e.unmarked
    // }
    // pub fn locked_cost(&self, ci: &ClientId) -> u64 {
    //     let mut g = self.client_to_v.lock();
    //     let e = g.entry(*ci).or_default();
    //     e.lockv
    // }
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

    // Helper function to create a tracker for testing
    fn create_test_tracker(
        initial_data: HashMap<u64, OBalanceR>,
    ) -> OutstandingBalanceTracker<OutstandingBalanceRecords, u64, OBalanceR> {
        let records = OutstandingBalanceRecords {
            a: Arc::new(Mutex::new(initial_data)),
        };
        OutstandingBalanceTracker::new(records)
    }

    #[tokio::test]
    async fn test_add_obligation() {
        let mut m = HashMap::new();
        m.insert(0, OBalanceR { o: 100, l: 0 });
        let tracker = create_test_tracker(m);

        // Add obligation
        tracker.add_obligation(&0, 50).await.unwrap();

        // Verify outstanding balance increased
        let records = &tracker.b;
        let result = records
            .rw_on_client_o_balance(&0, |x| *x.outstanding())
            .await
            .unwrap();
        assert_eq!(result, 150);
    }

    #[tokio::test]
    async fn test_add_obligation_multiple_times() {
        let mut m = HashMap::new();
        m.insert(0, OBalanceR { o: 100, l: 0 });
        let tracker = create_test_tracker(m);

        // Add multiple obligations
        tracker.add_obligation(&0, 50).await.unwrap();
        tracker.add_obligation(&0, 30).await.unwrap();
        tracker.add_obligation(&0, 20).await.unwrap();

        // Verify total outstanding balance
        let records = &tracker.b;
        let result = records
            .rw_on_client_o_balance(&0, |x| *x.outstanding())
            .await
            .unwrap();
        assert_eq!(result, 200);
    }

    #[tokio::test]
    async fn test_unlock() {
        let mut m = HashMap::new();
        m.insert(0, OBalanceR { o: 100, l: 50 });
        let tracker = create_test_tracker(m);

        // Unlock some locked value
        tracker.unlock(&0, 20).await.unwrap();

        // Verify lock value decreased
        let records = &tracker.b;
        let result = records
            .rw_on_client_o_balance(&0, |x| *x.lock_value())
            .await
            .unwrap();
        assert_eq!(result, 30);
    }

    #[tokio::test]
    async fn test_unlock_saturating_sub() {
        let mut m = HashMap::new();
        m.insert(0, OBalanceR { o: 100, l: 20 });
        let tracker = create_test_tracker(m);

        // Try to unlock more than locked (should saturate at 0)
        tracker.unlock(&0, 50).await.unwrap();

        // Verify lock value saturated at 0
        let records = &tracker.b;
        let result = records
            .rw_on_client_o_balance(&0, |x| *x.lock_value())
            .await
            .unwrap();
        assert_eq!(result, 0);
    }

    #[tokio::test]
    async fn test_reduce_obligation() {
        let mut m = HashMap::new();
        m.insert(0, OBalanceR { o: 100, l: 0 });
        let tracker = create_test_tracker(m);

        // Reduce obligation
        tracker.reduce_obligation(&0, 30).await.unwrap();

        // Verify outstanding balance decreased
        let records = &tracker.b;
        let result = records
            .rw_on_client_o_balance(&0, |x| *x.outstanding())
            .await
            .unwrap();
        assert_eq!(result, 70);
    }

    #[tokio::test]
    async fn test_reduce_obligation_saturating_sub() {
        let mut m = HashMap::new();
        m.insert(0, OBalanceR { o: 50, l: 0 });
        let tracker = create_test_tracker(m);

        // Try to reduce more than outstanding (should saturate at 0)
        tracker.reduce_obligation(&0, 100).await.unwrap();

        // Verify outstanding balance saturated at 0
        let records = &tracker.b;
        let result = records
            .rw_on_client_o_balance(&0, |x| *x.outstanding())
            .await
            .unwrap();
        assert_eq!(result, 0);
    }

    #[tokio::test]
    async fn test_combined_operations() {
        let mut m = HashMap::new();
        m.insert(0, OBalanceR { o: 100, l: 20 });
        let tracker = create_test_tracker(m);

        // Sequence of operations
        tracker.add_obligation(&0, 50).await.unwrap();
        tracker.unlock(&0, 10).await.unwrap();
        tracker.reduce_obligation(&0, 30).await.unwrap();

        // Verify final state
        let records = &tracker.b;
        let outstanding = records
            .rw_on_client_o_balance(&0, |x| *x.outstanding())
            .await
            .unwrap();
        let locked = records
            .rw_on_client_o_balance(&0, |x| *x.lock_value())
            .await
            .unwrap();

        assert_eq!(outstanding, 120); // 100 + 50 - 30
        assert_eq!(locked, 10); // 20 - 10
    }

    #[tokio::test]
    async fn test_concurrent_operations() {
        let mut m = HashMap::new();
        m.insert(0, OBalanceR { o: 100, l: 0 });
        let tracker = Arc::new(create_test_tracker(m));

        // Spawn multiple concurrent tasks
        let mut handles = vec![];
        for _ in 0..10 {
            let tracker_clone = Arc::clone(&tracker);
            handles.push(tokio::spawn(async move {
                tracker_clone.add_obligation(&0, 10).await.unwrap();
            }));
        }

        // Wait for all tasks to complete
        for handle in handles {
            handle.await.unwrap();
        }

        // Verify all additions were applied
        let records = &tracker.b;
        let result = records
            .rw_on_client_o_balance(&0, |x| *x.outstanding())
            .await
            .unwrap();
        assert_eq!(result, 200); // 100 + (10 * 10)
    }

    #[tokio::test]
    async fn test_concurrent_mixed_operations() {
        let mut m = HashMap::new();
        m.insert(0, OBalanceR { o: 1000, l: 500 });
        let tracker = Arc::new(create_test_tracker(m));

        // Spawn mixed concurrent operations
        let mut handles = vec![];

        // Add obligations
        for _ in 0..5 {
            let tracker_clone = Arc::clone(&tracker);
            handles.push(tokio::spawn(async move {
                tracker_clone.add_obligation(&0, 20).await.unwrap();
            }));
        }

        // Reduce obligations
        for _ in 0..3 {
            let tracker_clone = Arc::clone(&tracker);
            handles.push(tokio::spawn(async move {
                tracker_clone.reduce_obligation(&0, 10).await.unwrap();
            }));
        }

        // Unlock
        for _ in 0..4 {
            let tracker_clone = Arc::clone(&tracker);
            handles.push(tokio::spawn(async move {
                tracker_clone.unlock(&0, 50).await.unwrap();
            }));
        }

        // Wait for all tasks to complete
        for handle in handles {
            handle.await.unwrap();
        }

        // Verify final state
        let records = &tracker.b;
        let outstanding = records
            .rw_on_client_o_balance(&0, |x| *x.outstanding())
            .await
            .unwrap();
        let locked = records
            .rw_on_client_o_balance(&0, |x| *x.lock_value())
            .await
            .unwrap();

        assert_eq!(outstanding, 1070); // 1000 + (20*5) - (10*3)
        assert_eq!(locked, 300); // 500 - (50*4)
    }

    #[tokio::test]
    async fn test_error_on_missing_client() {
        let m = HashMap::new(); // Empty map
        let tracker = create_test_tracker(m);

        // Operations on non-existent client should error
        let result = tracker.add_obligation(&999, 50).await;
        assert!(result.is_err());

        let result = tracker.unlock(&999, 50).await;
        assert!(result.is_err());

        let result = tracker.reduce_obligation(&999, 50).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_multiple_clients() {
        let mut m = HashMap::new();
        m.insert(0, OBalanceR { o: 100, l: 10 });
        m.insert(1, OBalanceR { o: 200, l: 20 });
        m.insert(2, OBalanceR { o: 300, l: 30 });
        let tracker = create_test_tracker(m);

        // Operate on different clients
        tracker.add_obligation(&0, 50).await.unwrap();
        tracker.add_obligation(&1, 100).await.unwrap();
        tracker.reduce_obligation(&2, 50).await.unwrap();

        // Verify each client's state independently
        let records = &tracker.b;

        let o0 = records
            .rw_on_client_o_balance(&0, |x| *x.outstanding())
            .await
            .unwrap();
        assert_eq!(o0, 150);

        let o1 = records
            .rw_on_client_o_balance(&1, |x| *x.outstanding())
            .await
            .unwrap();
        assert_eq!(o1, 300);

        let o2 = records
            .rw_on_client_o_balance(&2, |x| *x.outstanding())
            .await
            .unwrap();
        assert_eq!(o2, 250);
    }

    #[tokio::test]
    async fn test_zero_operations() {
        let mut m = HashMap::new();
        m.insert(0, OBalanceR { o: 100, l: 50 });
        let tracker = create_test_tracker(m);

        // Operations with zero values
        tracker.add_obligation(&0, 0).await.unwrap();
        tracker.unlock(&0, 0).await.unwrap();
        tracker.reduce_obligation(&0, 0).await.unwrap();

        // Verify state unchanged
        let records = &tracker.b;
        let outstanding = records
            .rw_on_client_o_balance(&0, |x| *x.outstanding())
            .await
            .unwrap();
        let locked = records
            .rw_on_client_o_balance(&0, |x| *x.lock_value())
            .await
            .unwrap();

        assert_eq!(outstanding, 100);
        assert_eq!(locked, 50);
    }
}
