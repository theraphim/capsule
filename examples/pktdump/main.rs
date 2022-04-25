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

use capsule::packets::ethernet::{EtherType, EtherTypes, Ethernet, EthernetError};
use capsule::packets::ip::v4::Ipv4;
use capsule::packets::ip::v6::Ipv6;
use capsule::packets::ip::{IpError, IpPacket};
use capsule::packets::tcp::{Tcp, Tcp4, Tcp6, TcpError};
use capsule::packets::{EnvelopeDiscardExt, Mbuf, Packet, Postmark};
use capsule::runtime::{self, Runtime};
use colored::Colorize;
use signal_hook::consts;
use signal_hook::flag;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use thiserror::Error;
use tracing::{info, Level};
use tracing_subscriber::fmt;

#[derive(Error, Debug)]
enum PktDumpError {
    #[error("ethernet packet error")]
    EthernetError(#[from] EthernetError),
    #[error("ip packet error")]
    IpError(#[from] IpError),
    #[error("tcp packet error")]
    TcpError(#[from] TcpError),
    #[error("not an Ipv4 or Ipv6 packet")]
    UnsupportedPacketType(EtherType),
}

fn dump_pkt(packet: Mbuf) -> Result<Postmark, PktDumpError> {
    let ethernet = packet.parse::<Ethernet>().discard()?;

    let fmt = format!("{:?}", ethernet).magenta().bold();
    info!("{}", fmt);

    match ethernet.ether_type() {
        EtherTypes::Ipv4 => dump_v4(&ethernet),
        EtherTypes::Ipv6 => dump_v6(&ethernet),
        type_ => Err(PktDumpError::UnsupportedPacketType(type_)),
    }?;

    Ok(Postmark::drop(ethernet))
}

fn dump_v4(ethernet: &Ethernet) -> Result<(), PktDumpError> {
    let v4 = ethernet.peek::<Ipv4>()?;
    let fmt = format!("{:?}", v4).yellow();
    info!("{}", fmt);

    let tcp = v4.peek::<Tcp4>()?;
    dump_tcp(&tcp);

    Ok(())
}

fn dump_v6(ethernet: &Ethernet) -> Result<(), PktDumpError> {
    let v6 = ethernet.peek::<Ipv6>()?;
    let fmt = format!("{:?}", v6).cyan();
    info!("{}", fmt);

    let tcp = v6.peek::<Tcp6>()?;
    dump_tcp(&tcp);

    Ok(())
}

fn dump_tcp<T: IpPacket>(tcp: &Tcp<T>) {
    let fmt = format!("{:?}", tcp).green();
    info!("{}", fmt);

    let fmt = format!("{:?}", tcp.flow()).bright_blue();
    info!("{}", fmt);
}

fn main() -> anyhow::Result<()> {
    let subscriber = fmt::Subscriber::builder()
        .with_max_level(Level::INFO)
        .finish();
    tracing::subscriber::set_global_default(subscriber)?;

    let config = runtime::load_config()?;
    let runtime = Runtime::from_config(config)?;
    runtime.spawn_rx_tx_pipeline("cap0", dump_pkt, None)?;
    runtime.spawn_rx_tx_pipeline("cap1", dump_pkt, None)?;
    let _guard = runtime.execute()?;

    let term = Arc::new(AtomicBool::new(false));
    flag::register(consts::SIGINT, Arc::clone(&term))?;
    info!("ctrl-c to quit ...");
    while !term.load(Ordering::Relaxed) {}

    Ok(())
}
