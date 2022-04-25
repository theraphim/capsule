use capsule_ffi as cffi;
use lazy_static::lazy_static;
use std::sync::atomic::AtomicU64;

#[derive(Default)]
pub(crate) struct PortRxQueueStats {
    pub(crate) cnt_burst_nonempty: AtomicU64,
    pub(crate) cnt_burst_empty: AtomicU64,
}

#[derive(Default)]
pub(crate) struct PortTxQueueStats {
    pub(crate) cnt_excess_drop: AtomicU64,
}

#[derive(Default)]
pub(crate) struct PortQueueStats {
    pub(crate) rx: PortRxQueueStats,
    pub(crate) tx: PortTxQueueStats,
}

lazy_static! {
    pub(crate) static ref PORT_QUEUE_STATS: Vec<Vec<PortQueueStats>> = {
        let mut outer_vec: Vec<Vec<PortQueueStats>> =
            Vec::with_capacity(cffi::RTE_RAWDEV_MAX_DEVS as usize);
        for _ in 0..cffi::RTE_RAWDEV_MAX_DEVS as usize {
            let mut inner_vec: Vec<PortQueueStats> =
                Vec::with_capacity(cffi::RTE_MAX_QUEUES_PER_PORT as usize);
            for _ in 0..cffi::RTE_MAX_QUEUES_PER_PORT as usize {
                inner_vec.push(PortQueueStats::default());
            }
            outer_vec.push(inner_vec);
        }
        outer_vec
    };
}
