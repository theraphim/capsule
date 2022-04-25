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

//! Capsule runtime.

mod config;
mod lcore;
mod mempool;
#[cfg(feature = "pcap-dump")]
#[cfg_attr(docsrs, doc(cfg(feature = "pcap-dump")))]
mod pcap_dump;
mod port;
#[cfg(feature = "metrics")]
mod port_metrics;

pub use self::config::*;
pub(crate) use self::lcore::*;
pub use self::lcore::{Lcore, LcoreMap};
pub use self::mempool::Mempool;
pub(crate) use self::mempool::*;
pub use self::port::{Port, PortError, PortMap};
use std::error::Error;

use crate::ffi::dpdk::{self, LcoreId};
use crate::packets::{Mbuf, Postmark};
use crate::{debug, info};
use std::fmt;
use std::mem::ManuallyDrop;

/// The Capsule runtime.
///
/// The runtime initializes the underlying DPDK environment, and it also manages
/// the task scheduler that executes the packet processing tasks.
pub struct Runtime {
    mempool: ManuallyDrop<Mempool>,
    lcores: ManuallyDrop<LcoreMap>,
    ports: ManuallyDrop<PortMap>,
    #[cfg(feature = "pcap-dump")]
    pcap_dump: ManuallyDrop<self::pcap_dump::PcapDump>,
}

impl Runtime {
    /// Returns the mempool.
    ///
    /// For simplicity, we currently only support one global Mempool. Multi-
    /// socket support may be added in the future.
    pub fn mempool(&self) -> &Mempool {
        &self.mempool
    }

    /// Returns the lcores.
    pub fn lcores(&self) -> &LcoreMap {
        &self.lcores
    }

    /// Returns the configured ports.
    pub fn ports(&self) -> &PortMap {
        &self.ports
    }

    /// Initializes a new runtime from config settings.
    pub fn from_config(config: RuntimeConfig) -> anyhow::Result<Self> {
        info!("starting runtime.");

        debug!("initializing EAL ...");
        dpdk::eal_init(config.to_eal_args())?;

        debug!("initializing mempool ...");
        let socket = LcoreId::main().socket();
        let mut mempool = Mempool::new(
            "mempool",
            config.mempool.capacity,
            config.mempool.cache_size,
            socket,
        )?;
        debug!(?mempool);

        debug!("initializing lcore schedulers ...");
        let lcores = self::lcore_pool();

        for lcore in lcores.iter() {
            let ptr = mempool.ptr_mut().clone();
            lcore.add_mempool(ptr)?;
        }

        info!("initializing ports ...");
        let mut ports = Vec::new();
        for port in config.ports.iter() {
            let port = port::Builder::for_device(&port.name, &port.device)?
                .set_rxqs_txqs(port.rxqs, port.txqs)?
                .set_promiscuous(port.promiscuous)?
                .set_multicast(port.multicast)?
                .set_lcores(port.lcores.clone())?
                .set_symmetric_rss(config.symmetric_rss.unwrap_or(false))?
                .build(&mut mempool)?;

            debug!(?port);

            port.start()?;
            ports.push(port);
        }
        let ports: PortMap = ports.into();

        #[cfg(feature = "pcap-dump")]
        let pcap_dump = self::pcap_dump::enable_pcap_dump(&config.data_dir(), &ports, &lcores)?;

        info!("runtime ready.");

        Ok(Runtime {
            mempool: ManuallyDrop::new(mempool),
            lcores: ManuallyDrop::new(lcores),
            ports: ManuallyDrop::new(ports),
            #[cfg(feature = "pcap-dump")]
            pcap_dump: ManuallyDrop::new(pcap_dump),
        })
    }

    #[cfg(feature = "metrics")]
    /// Collects/updates metrics
    pub fn collect_metrics(&self) -> Result<(), PortError> {
        self.mempool.collect_metrics();
        for port in self.ports.iter() {
            port.collect_metrics()?;
        }
        Ok(())
    }

    /// Spawns an infinite RX->TX pipeline with the given function, thread locals and optionally a different port
    /// for TX
    pub fn spawn_rx_tx_pipeline_with_thread_locals<
        PipelineFn,
        PipelineFnError,
        ThreadLocalCreatorFn,
        ThreadLocal,
    >(
        &self,
        rx_port: &str,
        pipeline_fn: PipelineFn,
        thread_local_creator_fn: ThreadLocalCreatorFn,
        tx_port: Option<&str>,
    ) -> Result<(), PortError>
    where
        PipelineFn: Fn(Mbuf, &mut ThreadLocal) -> Result<Postmark, PipelineFnError>
            + Clone
            + Send
            + Sync
            + 'static,
        PipelineFnError: Error,
        ThreadLocalCreatorFn: Fn() -> ThreadLocal + Clone + Send + 'static,
        ThreadLocal: Send + 'static,
    {
        let rx_port_ = self.ports.get(rx_port)?;
        let tx_port_ = match tx_port {
            Some(port_name) => Some(self.ports().get(port_name)?),
            None => None,
        };
        rx_port_.spawn_rx_tx_pipeline(
            self.lcores(),
            pipeline_fn,
            thread_local_creator_fn,
            tx_port_,
        )
    }

    /// Spawns an infinite RX->TX pipeline with the given function and optionally a different port
    /// for TX
    pub fn spawn_rx_tx_pipeline<PipelineFn, PipelineFnError>(
        &self,
        rx_port: &str,
        pipeline_fn: PipelineFn,
        tx_port: Option<&str>,
    ) -> Result<(), PortError>
    where
        PipelineFn: Fn(Mbuf) -> Result<Postmark, PipelineFnError> + Clone + Send + Sync + 'static,
        PipelineFnError: Error,
    {
        self.spawn_rx_tx_pipeline_with_thread_locals(
            rx_port,
            move |mbuf, _| pipeline_fn(mbuf),
            || (),
            tx_port,
        )
    }

    /// Starts the runtime execution.
    pub fn execute(self) -> anyhow::Result<RuntimeGuard> {
        Ok(RuntimeGuard { runtime: self })
    }
}

impl fmt::Debug for Runtime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Runtime")
            .field("mempool", &self.mempool)
            .finish()
    }
}

/// The RAII guard to stop and cleanup the runtime resources on drop.
pub struct RuntimeGuard {
    runtime: Runtime,
}

impl RuntimeGuard {
    /// Get runtime
    pub fn runtime(&mut self) -> &mut Runtime {
        &mut self.runtime
    }
}

impl Drop for RuntimeGuard {
    fn drop(&mut self) {
        info!("shutting down runtime.");

        for port in self.runtime.ports.iter_mut() {
            port.stop();
        }

        unsafe {
            #[cfg(feature = "pcap-dump")]
            ManuallyDrop::drop(&mut self.runtime.pcap_dump);
            ManuallyDrop::drop(&mut self.runtime.ports);
            ManuallyDrop::drop(&mut self.runtime.lcores);
            ManuallyDrop::drop(&mut self.runtime.mempool);
        }

        debug!("freeing EAL ...");
        let _ = dpdk::eal_cleanup();
        info!("runtime shutdown.");
    }
}

impl fmt::Debug for RuntimeGuard {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RuntimeGuard")
    }
}
