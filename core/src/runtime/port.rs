/*
* Copyright 2019 Comcast Cable Communications Management, LLC
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
* http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*
* SPDX-License-Identifier: Apache-2.0
*/

use super::{LcoreMap, Mempool};
use crate::ffi::dpdk::{self, MbufPtr, PortId, PortQueueId};
use crate::net::MacAddr;
use crate::packets::{Mbuf, Postmark};
use crate::{debug, ensure, error, info, warn};
use anyhow::Result;
use capsule_ffi as cffi;
use std::collections::HashMap;
use std::fmt;
use thiserror::Error;
use triggered::Listener;
use std::time::Duration;
use std::thread::sleep;
#[cfg(feature = "metrics")]
use metrics::{gauge, counter};
#[cfg(feature = "metrics")]
use crate::runtime::port_metrics::{PORT_QUEUE_STATS, PortRxQueueStats, PortTxQueueStats};
#[cfg(feature = "metrics")]
use std::sync::atomic::{Ordering};

/// A PMD device port.
#[derive(PartialEq)]
pub struct Port {
    name: String,
    port_id: PortId,
    lcores: Vec<usize>,
}

impl Port {
    /// Returns the application assigned logical name of the port.
    ///
    /// For applications with more than one port, this name can be used to
    /// identifer the port.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the port ID.
    pub(crate) fn port_id(&self) -> PortId {
        self.port_id
    }

    /// Returns the assigned lcores.
    pub fn lcores(&self) -> &Vec<usize> {
        &self.lcores
    }

    /// Returns a queue ID mathematically associated with the given queue ID on another port
    pub(crate) fn associated_queue(&self, other_port: &Port, other_queue: PortQueueId) -> PortQueueId {
        let other_queue_id: usize = other_queue.into();
        ((other_queue_id as f32 * (self.lcores.len() as f32 / other_port.lcores().len() as f32)) as usize).into()
    }

    /// Returns the MAC address of the port.
    ///
    /// If fails to retrieve the MAC address, `MacAddr::default` is returned.
    pub fn mac_addr(&self) -> MacAddr {
        dpdk::eth_macaddr_get(self.port_id).unwrap_or_default()
    }

    /// Returns whether the port has promiscuous mode enabled.
    pub fn promiscuous(&self) -> bool {
        dpdk::eth_promiscuous_get(self.port_id)
    }

    /// Returns whether the port has multicast mode enabled.
    pub fn multicast(&self) -> bool {
        dpdk::eth_allmulticast_get(self.port_id)
    }

    #[cfg(feature = "metrics")]
    /// Collects/updates port and assosciated queue metrics
    pub(crate) fn collect_metrics(&self) -> Result<()> {
        let port_stats = dpdk::eth_stats_get(self.port_id)?;
        let port_gauge = |name: &'static str, value| {
            gauge!(format!("port.dpdk.{}", name), value,
                "port_id" => self.port_id.id().to_string());
        };
        port_gauge("rx_packets", port_stats.ipackets as f64);
        port_gauge("rx_packets", port_stats.ipackets as f64);
        port_gauge("tx_packets", port_stats.opackets as f64);
        port_gauge("rx_bytes", port_stats.ibytes as f64);
        port_gauge("tx_bytes", port_stats.obytes as f64);
        port_gauge("rx_missed", port_stats.imissed as f64);
        port_gauge("rx_errors", port_stats.ierrors as f64);
        port_gauge("tx_errors", port_stats.oerrors as f64);
        port_gauge("port.dpdk.rx_mbuf_errors", port_stats.rx_nombuf as f64);
        for (index, stat) in PORT_QUEUE_STATS[self.port_id.id() as usize][0..self.lcores.len()].iter().enumerate() {
            counter!("port.rx_burst_nonempty", stat.rx.cnt_burst_nonempty.swap(0, Ordering::Relaxed),
                "port_id" => self.port_id.id().to_string(), "queue_id" => index.to_string());
            counter!("port.rx_burst_empty", stat.rx.cnt_burst_empty.swap(0, Ordering::Relaxed),
                "port_id" => self.port_id.id().to_string(), "queue_id" => index.to_string());
            counter!("port.tx_excess_dropped", stat.tx.cnt_excess_drop.swap(0, Ordering::Relaxed),
                   "port_id" => self.port_id.id().to_string(), "queue_id" => index.to_string());
        }
        Ok(())
    }

    /// Spawns an infinite RX->TX pipeline with the given function and optionally a different port
    /// for TX
    pub fn spawn_rx_tx_pipeline<PipelineFn, ThreadLocalCreatorFn, ThreadLocal>(
        &self,
        lcore_map: &LcoreMap,
        pipeline_fn: PipelineFn,
        thread_local_creator_fn: ThreadLocalCreatorFn,
        mut tx_port: Option<&Port>
    ) -> Result<()>
    where
        PipelineFn: Fn(Mbuf, &mut ThreadLocal) -> Result<Postmark> + Clone + Send + Sync + 'static,
        ThreadLocalCreatorFn: Fn() -> ThreadLocal + Clone + Send + 'static,
        ThreadLocal: Send + 'static
    {
        if let Some(port) = tx_port {
            if port == self { tx_port = None }
        }

        // can't run loop without assigned cores.
        ensure!(!self.lcores.is_empty(), PortError::NoLCores);

        for (index, lcore_id) in self.lcores.iter().enumerate() {
            let lcore = lcore_map.get(*lcore_id)?;
            let pipeline_fn = pipeline_fn.clone();
            let thread_local_creator_fn = thread_local_creator_fn.clone();

            debug!(port = ?self.name, lcore = ?lcore.id(), "spawning rx/tx pipeline.");

            let rx_queue_id: PortQueueId = index.into();
            // get tx queue ID based on queue ID on the current port
            let (tx_port_id, tx_queue_id) = match tx_port {
                Some(port) => (port.port_id(), port.associated_queue(&self, rx_queue_id)),
                None => (self.port_id, rx_queue_id)
            };

            let port_id = self.port_id.clone();
            lcore.run_single(move |shutdown_listener| {
                rx_tx_pipeline_loop(
                    port_id,
                    rx_queue_id,
                    tx_port_id,
                    tx_queue_id,
                    32,
                    pipeline_fn,
                    thread_local_creator_fn,
                    shutdown_listener
                );
                Ok(None)
            })?;
        }

        Ok(())
    }

    /// Spawns an infinite TX pipeline with the given function, batch size and optional delay between batches
    /// for TX
    pub fn spawn_tx_pipeline<PipelineFn, ThreadLocalCreatorFn, ThreadLocal>(
        &self,
        lcore_map: &LcoreMap,
        batch_size: usize,
        delay: Option<Duration>,
        pipeline_fn: PipelineFn,
        thread_local_creator_fn: ThreadLocalCreatorFn,
    ) -> Result<()>
        where
            PipelineFn: Fn(Mbuf, &mut ThreadLocal) -> Result<Mbuf> + Clone + Send + Sync + 'static,
            ThreadLocalCreatorFn: Fn() -> ThreadLocal + Clone + Send + 'static,
            ThreadLocal: Send + 'static
    {
        // can't run loop without assigned cores.
        ensure!(!self.lcores.is_empty(), PortError::NoLCores);

        for (index, lcore_id) in self.lcores.iter().enumerate() {
            let lcore = lcore_map.get(*lcore_id)?;
            let pipeline_fn = pipeline_fn.clone();
            let thread_local_creator_fn = thread_local_creator_fn.clone();

            debug!(port = ?self.name, lcore = ?lcore.id(), "spawning tx pipeline.");

            let port_id = self.port_id.clone();
            let tx_queue_id: PortQueueId = index.clone().into();
            lcore.run_single(move |shutdown_listener| {
                let thread_locals = thread_local_creator_fn();
                tx_pipeline_loop(
                    port_id,
                    tx_queue_id,
                    batch_size,
                    delay,
                    pipeline_fn,
                    thread_locals,
                    shutdown_listener
                );
                Ok(None)
            })?;
        }

        Ok(())
    }

    /// Starts the port. This is the final step before packets can be
    /// received or transmitted on this port.
    ///
    /// # Errors
    ///
    /// Returns `DpdkError` if the port fails to start.
    pub(crate) fn start(&self) -> Result<()> {
        dpdk::eth_dev_start(self.port_id)?;
        info!(port = ?self.name, "port started.");
        Ok(())
    }

    /// Stops the port.
    pub(crate) fn stop(&mut self) {
        dpdk::eth_dev_stop(self.port_id);
        info!(port = ?self.name, "port stopped.");
    }
}

impl fmt::Debug for Port {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Port")
            .field("name", &self.name())
            .field("port_id", &self.port_id())
            .field("mac_addr", &format_args!("{}", self.mac_addr()))
            .field("lcores", &self.lcores)
            .field("promiscuous", &self.promiscuous())
            .field("multicast", &self.multicast())
            .finish()
    }
}

/// Port's receive queue.
pub(crate) struct PortRxQueue {
    port_id: PortId,
    queue_id: PortQueueId,
    #[cfg(feature = "metrics")]
    stats: &'static PortRxQueueStats,
}

impl PortRxQueue {
    pub(crate) fn new(port_id: PortId, queue_id: PortQueueId) -> Self {
        #[cfg(feature = "metrics")]
        return Self {
            port_id,
            queue_id,
            stats: &PORT_QUEUE_STATS[port_id.id() as usize][queue_id.id() as usize].rx
        };
        #[cfg(not(feature = "metrics"))]
        return Self {
            port_id,
            queue_id,
        };
    }

    /// Receives a burst of packets, up to the `Vec`'s capacity.
    pub(crate) fn receive(&self, mbufs: &mut Vec<MbufPtr>) {
        dpdk::eth_rx_burst(self.port_id, self.queue_id, mbufs);
        #[cfg(feature = "metrics")]
        // Record metrics for the size of the burst received to track
        // performance (if the ratio of empty to full buffers is 1, we are "maxed out")
        if mbufs.len() > 0 {
            self.stats.cnt_burst_nonempty.fetch_add(1, Ordering::Relaxed);
        } else {
            self.stats.cnt_burst_empty.fetch_add(1, Ordering::Relaxed);
        }
    }
}

fn rx_tx_pipeline_loop<PipelineFn, ThreadLocalCreatorFn, ThreadLocal>(
    rx_port_id: PortId,
    rx_queue_id: PortQueueId,
    tx_port_id: PortId,
    tx_queue_id: PortQueueId,
    batch_size: usize,
    pipeline_fn: PipelineFn,
    thread_local_creator_fn: ThreadLocalCreatorFn,
    shutdown_listener: Listener
) where
    PipelineFn: Fn(Mbuf, &mut ThreadLocal) -> Result<Postmark> + Clone + Send + Sync + 'static,
    ThreadLocalCreatorFn: Fn() -> ThreadLocal + Clone + Send + 'static,
    ThreadLocal: Send + 'static
{
    let mut thread_locals = thread_local_creator_fn();

    let rxq = PortRxQueue::new(rx_port_id, rx_queue_id);
    let txq = PortTxQueue::new(tx_port_id, tx_queue_id);

    let mut ptrs = Vec::with_capacity(batch_size);
    let mut emits = Vec::with_capacity(batch_size);
    let mut drops = Vec::with_capacity(batch_size);

    while !shutdown_listener.is_triggered() {
        rxq.receive(&mut ptrs);

        for ptr in ptrs.drain(..) {
            let mbuf = Mbuf::from_easyptr(ptr);
            match pipeline_fn(mbuf, &mut thread_locals) {
                Ok(postmark) => {
                    emits.extend(postmark.emit);
                    if let Some(drop) = postmark.drop {
                        drops.push(drop);
                    }
                },
                Err(_) => (),
            }
        }

        // Drop drops
        if !drops.is_empty() {
            Mbuf::free_bulk_ptrs(&mut drops.drain(..).map(Mbuf::into_easyptr).collect());
        }

        // Send emits
        if !emits.is_empty() {
            txq.transmit_ptrs(&mut emits.drain(..).map(Mbuf::into_easyptr).collect());
        }
    }
}

fn tx_pipeline_loop<PipelineFn, ThreadLocal>(
    tx_port_id: PortId,
    tx_queue_id: PortQueueId,
    batch_size: usize,
    delay: Option<Duration>,
    pipeline_fn: PipelineFn,
    mut thread_locals: ThreadLocal,
    shutdown_listener: Listener
) where
    PipelineFn: Fn(Mbuf, &mut ThreadLocal) -> Result<Mbuf> + Clone + Send + Sync + 'static,
    ThreadLocal: Send + 'static
{
    let txq = PortTxQueue::new(tx_port_id, tx_queue_id);

    while !shutdown_listener.is_triggered() {
        match Mbuf::alloc_bulk(batch_size) {
            Ok(mbufs) => {
                txq.transmit(
                    mbufs
                        .into_iter()
                        .map(|mbuf| -> Result<Mbuf> {
                            pipeline_fn(mbuf, &mut thread_locals)
                        })
                        .filter_map(|res| res.ok())
                        .collect()
                )
            },
            Err(e) => error!(?e)
        }
        if let Some(dur) = delay {
            sleep(dur);
        }
    }
}

/// Port's transmit queue.
pub(crate) struct PortTxQueue {
    port_id: PortId,
    queue_id: PortQueueId,
    #[cfg(feature = "metrics")]
    stats: &'static PortTxQueueStats,
}

impl PortTxQueue {
    pub(crate) fn new(port_id: PortId, queue_id: PortQueueId) -> Self {
        #[cfg(feature = "metrics")]
        return Self {
            port_id,
            queue_id,
            stats: &PORT_QUEUE_STATS[port_id.id() as usize][queue_id.id() as usize].tx
        };
        #[cfg(not(feature = "metrics"))]
        return Self {
            port_id,
            queue_id,
        };
    }

    /// Transmits a burst of packets.
    ///
    /// If the TX is full, the excess packets are dropped.
    pub(crate) fn transmit(&self, mbufs: Vec<Mbuf>) {
        let mut mbuf_ptrs: Vec<MbufPtr> = mbufs.into_iter().map(move |mbuf| mbuf.into_easyptr()).collect();
        self.transmit_ptrs(&mut mbuf_ptrs)
    }

    /// Transmits a burst of packets.
    ///
    /// If the TX is full, the excess packets are dropped.
    pub(crate) fn transmit_ptrs(&self, mbufs: &mut Vec<MbufPtr>) {
        dpdk::eth_tx_burst(self.port_id, self.queue_id, mbufs);
        if !mbufs.is_empty() {
            #[cfg(feature = "metrics")]
            // Record the number of mbufs dropped because of full TX queue
            self.stats.cnt_excess_drop.fetch_add(mbufs.len() as u64, Ordering::Relaxed);
            // tx queue is full, we have to drop the excess.
            dpdk::pktmbuf_free_bulk(mbufs);
        }
    }
}

/// Map to lookup the port by the port name.
#[derive(Debug)]
pub struct PortMap(HashMap<String, Port>);

impl PortMap {
    /// Returns the port with the assigned name.
    ///
    /// # Errors
    ///
    /// Returns `PortError::NotFound` if the port name is not found.
    pub fn get(&self, name: &str) -> Result<&Port> {
        self.0.get(name).ok_or_else(|| PortError::NotFound.into())
    }

    /// Returns a port iterator.
    pub fn iter(&self) -> impl Iterator<Item = &Port> {
        self.0.values()
    }

    /// Returns a port iterator.
    pub(crate) fn iter_mut(&mut self) -> impl Iterator<Item = &'_ mut Port> {
        self.0.values_mut()
    }
}

impl From<Vec<Port>> for PortMap {
    fn from(ports: Vec<Port>) -> Self {
        let ports = ports
            .into_iter()
            .map(|port| (port.name.clone(), port))
            .collect::<HashMap<_, _>>();
        PortMap(ports)
    }
}

/// Port related errors.
#[derive(Debug, Error)]
pub enum PortError {
    /// The port is not found.
    #[error("port not found.")]
    NotFound,

    /// The maximum number of RX queues is less than the number of queues
    /// requested.
    #[error("insufficient number of receive queues. max is {0}.")]
    InsufficientRxQueues(u16),

    /// The maximum number of TX queues is less than the number of queues
    /// requested.
    #[error("insufficient number of transmit queues. max is {0}.")]
    InsufficientTxQueues(u16),

    /// The port has no lcores
    #[error("receive not enabled on port.")]
    NoLCores,

    /// The pipeline for the port is already set.
    #[error("pipeline already set.")]
    PipelineSet,

    /// Symmetric RSS cannot be disabled
    #[error("symmetric RSS cannot be disabled")]
    SymRSSNoDisable,
}

/// Port builder.
pub(crate) struct Builder {
    name: String,
    port_id: PortId,
    port_info: cffi::rte_eth_dev_info,
    port_conf: cffi::rte_eth_conf,
    lcores: Vec<usize>,
    rxqs: usize,
    txqs: usize,
    symmetric_rss: bool
}

impl Builder {
    /// Creates a new port `Builder` with a logical name and device name.
    ///
    /// The device name can be the following
    ///   * PCIe address (domain:bus:device.function), for example `0000:02:00.0`
    ///   * DPDK virtual device name, for example `net_[pcap0|null0|tap0]`
    ///
    /// # Errors
    ///
    /// Returns `DpdkError` if the `device` is not found or failed to retrieve
    /// the contextual information for the device.
    pub(crate) fn for_device<S1: Into<String>, S2: Into<String>>(
        name: S1,
        device: S2,
    ) -> Result<Self> {
        let name: String = name.into();
        let device: String = device.into();

        let port_id = dpdk::eth_dev_get_port_by_name(&device)?;
        debug!(?name, id = ?port_id, ?device);

        let port_info = dpdk::eth_dev_info_get(port_id)?;

        Ok(Builder {
            name,
            port_id,
            port_info,
            port_conf: cffi::rte_eth_conf::default(),
            lcores: vec![],
            rxqs: port_info.rx_desc_lim.nb_min as usize,
            txqs: port_info.tx_desc_lim.nb_min as usize,
            symmetric_rss: false
        })
    }

    /// Sets the lcores to receive and send packets on.
    ///
    /// Enables receive side scaling if more than one lcore is used for RX or
    /// packet processing is offloaded to the workers.
    ///
    /// # Errors
    ///
    /// Returns `PortError` if the maximum number of RX or TX queues is less than
    /// the number of lcores assigned.
    pub(crate) fn set_lcores(&mut self, lcores: Vec<usize>) -> Result<&mut Self> {
        ensure!(
            self.port_info.max_rx_queues >= lcores.len() as u16,
            PortError::InsufficientRxQueues(self.port_info.max_rx_queues)
        );
        ensure!(
            self.port_info.max_tx_queues >= lcores.len() as u16,
            PortError::InsufficientTxQueues(self.port_info.max_tx_queues)
        );

        if lcores.len() > 1 {
            const RSS_HF: u64 =
                (cffi::ETH_RSS_IP | cffi::ETH_RSS_TCP | cffi::ETH_RSS_UDP | cffi::ETH_RSS_SCTP)
                    as u64;
            // enables receive side scaling.
            self.port_conf.rxmode.mq_mode = cffi::rte_eth_rx_mq_mode::ETH_MQ_RX_RSS;
            self.port_conf.rx_adv_conf.rss_conf.rss_hf =
                self.port_info.flow_type_rss_offloads & RSS_HF;

            debug!(
                port = ?self.name,
                rss_hf = self.port_conf.rx_adv_conf.rss_conf.rss_hf,
                "receive side scaling enabled."
            );
        }

        self.lcores = lcores;
        Ok(self)
    }

    /// Sets the capacity of each RX queue and TX queue.
    ///
    /// If the sizes are not within the limits of the device, they are adjusted
    /// to the boundaries.
    ///
    /// # Errors
    ///
    /// Returns `DpdkError` if failed to set the queue capacity.
    pub(crate) fn set_rxqs_txqs(&mut self, rxqs: usize, txqs: usize) -> Result<&mut Self> {
        let (rxqs2, txqs2) = dpdk::eth_dev_adjust_nb_rx_tx_desc(self.port_id, rxqs, txqs)?;

        info!(
            cond: rxqs2 != rxqs,
            port = ?self.name,
            before = rxqs,
            after = rxqs2,
            "rx ring size adjusted to limits.",
        );
        info!(
            cond: txqs2 != txqs,
            port = ?self.name,
            before = txqs,
            after = txqs2,
            "tx ring size adjusted to limits.",
        );

        self.rxqs = rxqs2;
        self.txqs = txqs2;
        Ok(self)
    }

    /// Sets the promiscuous mode of the port.
    ///
    /// # Errors
    ///
    /// Returns `DpdkError` if the device does not support configurable mode.
    pub(crate) fn set_promiscuous(&mut self, enable: bool) -> Result<&mut Self> {
        if enable {
            dpdk::eth_promiscuous_enable(self.port_id)?;
            debug!(port = ?self.name, "promiscuous mode enabled.");
        } else {
            dpdk::eth_promiscuous_disable(self.port_id)?;
            debug!(port = ?self.name, "promiscuous mode disabled.");
        }

        Ok(self)
    }

    /// Sets the multicast mode of the port.
    ///
    /// # Errors
    ///
    /// Returns `DpdkError` if the device does not support configurable mode.
    pub(crate) fn set_multicast(&mut self, enable: bool) -> Result<&mut Self> {
        if enable {
            dpdk::eth_allmulticast_enable(self.port_id)?;
            debug!(port = ?self.name, "multicast mode enabled.");
        } else {
            dpdk::eth_allmulticast_disable(self.port_id)?;
            debug!(port = ?self.name, "multicast mode disabled.");
        }

        Ok(self)
    }

    /// Sets symmetric receive side scaling mode for the port if RSS is enabled.
    ///
    /// # Errors
    ///
    /// Returns `PortError` if RX has not been enabled yet or an attempt is made to disable the feature
    pub(crate) fn set_symmetric_rss(&mut self, enable: bool) -> Result<&mut Self> {
        ensure!(self.lcores.len() != 0, PortError::NoLCores);
        ensure!(enable, PortError::SymRSSNoDisable);
        if self.lcores.len() > 1 {
            self.symmetric_rss = true;
            debug!(port = ?self.name, "symmetric RSS enabled.");
        } else {
            debug!(port = ?self.name, "RSS not enabled, ignoring request to enable symmetric RSS.");
        }
        Ok(self)
    }

    /// Builds the port.
    ///
    /// # Errors
    ///
    /// Returns `DpdkError` if fails to configure the device or any of the
    /// rx and tx queues.
    pub(crate) fn build(&mut self, mempool: &mut Mempool) -> Result<Port> {
        // turns on optimization for mbuf fast free.
        if self.port_info.tx_offload_capa & cffi::DEV_TX_OFFLOAD_MBUF_FAST_FREE as u64 > 0 {
            self.port_conf.txmode.offloads |= cffi::DEV_TX_OFFLOAD_MBUF_FAST_FREE as u64;
            debug!(port = ?self.name, "mbuf fast free enabled.");
        }

        // configures the device before everything else.
        dpdk::eth_dev_configure(
            self.port_id,
            self.lcores.len(),
            self.lcores.len(),
            &self.port_conf,
        )?;

        let socket = self.port_id.socket();
        warn!(
            cond: mempool.socket() != socket,
            message = "mempool socket does not match port socket.",
            mempool = ?mempool.socket(),
            port = ?socket
        );

        // configures the rx queues.
        for index in 0..self.lcores.len() {
            dpdk::eth_rx_queue_setup(
                self.port_id,
                index.into(),
                self.rxqs,
                socket,
                None,
                mempool.ptr_mut(),
            )?;
        }

        // configures the tx queues.
        for index in 0..self.lcores.len() {
            dpdk::eth_tx_queue_setup(self.port_id, index.into(), self.txqs, socket, None)?;
        }

        // configures symmetric RSS (this has to be done after configuring the port so the max queue size is known)
        if self.symmetric_rss {
            dpdk::eth_sym_rss_enable(self.port_id,
                                     self.lcores.len())?;
        }

        Ok(Port {
            name: self.name.clone(),
            port_id: self.port_id,
            lcores: self.lcores.clone()
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ffi::dpdk::SocketId;

    #[capsule::test]
    fn port_not_found() {
        assert!(Builder::for_device("test0", "notfound").is_err());
    }

    #[capsule::test]
    fn set_lcores() -> Result<()> {
        let mut builder = Builder::for_device("test0", "net_ring0")?;

        // ring port has a max rxq of 16.
        let lcores = (0..17).collect::<Vec<_>>();
        assert!(builder.set_lcores(lcores).is_err());

        let lcores = (0..16).collect::<Vec<_>>();
        assert!(builder.set_lcores(lcores.clone()).is_ok());
        assert_eq!(lcores, builder.lcores);
        assert_eq!(
            cffi::rte_eth_rx_mq_mode::ETH_MQ_RX_RSS,
            builder.port_conf.rxmode.mq_mode
        );

        Ok(())
    }

    #[capsule::test]
    fn set_rxqs_txqs() -> Result<()> {
        let mut builder = Builder::for_device("test0", "net_ring0")?;

        // unfortunately can't test boundary adjustment
        assert!(builder.set_rxqs_txqs(32, 32).is_ok());
        assert_eq!(32, builder.rxqs);
        assert_eq!(32, builder.txqs);

        Ok(())
    }

    #[capsule::test]
    fn set_promiscuous() -> Result<()> {
        let mut builder = Builder::for_device("test0", "net_tap0")?;

        assert!(builder.set_promiscuous(true).is_ok());
        assert!(builder.set_promiscuous(false).is_ok());

        Ok(())
    }

    #[capsule::test]
    fn set_multicast() -> Result<()> {
        let mut builder = Builder::for_device("test0", "net_tap0")?;

        assert!(builder.set_multicast(true).is_ok());
        assert!(builder.set_multicast(false).is_ok());

        Ok(())
    }

    #[capsule::test]
    fn build_port() -> Result<()> {
        let lcores = (0..2).collect::<Vec<_>>();
        let mut pool = Mempool::new("mp_build_port", 15, 0, SocketId::ANY)?;
        let port = Builder::for_device("test0", "net_ring0")?
            .set_lcores(lcores.clone())?
            .build(&mut pool)?;

        assert_eq!("test0", port.name());
        assert!(port.promiscuous());
        assert!(port.multicast());
        assert_eq!(lcores, port.lcores);

        Ok(())
    }

    #[capsule::test]
    fn symmetric_rss() -> Result<()> {
        let lcores = (0..2).collect::<Vec<_>>();
        let mut pool = Mempool::new("mp_build_port_sym_rss", 15, 0, SocketId::ANY)?;
        let _port = Builder::for_device("test0", "net_ring0")?
            .set_lcores(lcores.clone())?
            .set_symmetric_rss(true)?
            .build(&mut pool)?;
        Ok(())
    }

    #[capsule::test]
    fn port_rx() -> Result<()> {
        let mut pool = Mempool::new("mp_port_rx", 15, 0, SocketId::ANY)?;
        let port = Builder::for_device("test0", "net_null0")?
            .set_lcores(vec![0])?
            .build(&mut pool)?;

        let mut packets = Vec::with_capacity(4);
        assert_eq!(0, packets.len());

        let rxq = PortRxQueue::new(
            port.port_id,
            0.into(),
        );

        rxq.receive(&mut packets);
        assert_eq!(4, packets.len());
        assert_eq!(4, dpdk::mempool_in_use_count(pool.ptr_mut()));

        Ok(())
    }
}
