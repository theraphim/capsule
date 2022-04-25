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

use bimap::BiMap;
use capsule::net::MacAddr;
use capsule::packets::ethernet::{Ethernet, EthernetError};
use capsule::packets::ip::v4::Ipv4;
use capsule::packets::ip::v6::{Ipv6, Ipv6Packet};
use capsule::packets::ip::{IpError, ProtocolNumbers};
use capsule::packets::tcp::{Tcp4, Tcp6, TcpError};
use capsule::packets::{EnvelopeDiscardExt, Mbuf, Packet, Postmark};
use capsule::runtime::{self, Runtime};
use colored::Colorize;
use once_cell::sync::Lazy;
use signal_hook::consts;
use signal_hook::flag;
use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicBool, AtomicU16, Ordering};
use std::sync::{Arc, Mutex};
use thiserror::Error;
use tracing::{info, Level};
use tracing_subscriber::fmt;

static PORTS: Lazy<Mutex<BiMap<(Ipv6Addr, u16), u16>>> = Lazy::new(|| Mutex::new(BiMap::new()));
static MACS: Lazy<Mutex<HashMap<Ipv6Addr, MacAddr>>> = Lazy::new(|| Mutex::new(HashMap::new()));

#[derive(Error, Debug)]
enum Nat4to6PacketError {
    #[error("ethernet packet error")]
    Ethernet(#[from] EthernetError),
    #[error("ip packet error")]
    Ip(#[from] IpError),
    #[error("tcp packet error")]
    Tcp(#[from] TcpError),
}

/// Maps the destination IPv6 address to its IPv4 counterpart by stripping
/// off the 96-bit prefix.
fn map_6to4(addr: Ipv6Addr) -> Ipv4Addr {
    let segments = addr.segments();
    let mapped = (segments[6] as u32) << 16 | (segments[7] as u32);
    mapped.into()
}

/// Looks up the assigned port for an IPv6 source.
fn get_v4_port(mac: MacAddr, ip: Ipv6Addr, port: u16) -> u16 {
    static NEXT_PORT: AtomicU16 = AtomicU16::new(1025);

    let key = (ip, port);
    let mut ports = PORTS.lock().unwrap();

    if let Some(value) = ports.get_by_left(&key) {
        *value
    } else {
        let port = NEXT_PORT.fetch_add(1, Ordering::Relaxed);
        MACS.lock().unwrap().insert(ip, mac);
        ports.insert(key, port);
        port
    }
}

fn nat_6to4(packet: Mbuf) -> Result<Postmark, Nat4to6PacketError> {
    const SRC_IP: Ipv4Addr = Ipv4Addr::new(10, 100, 1, 11);
    const DST_MAC: MacAddr = MacAddr::new(0x02, 0x00, 0x00, 0xff, 0xff, 0xff);

    let ethernet = packet.parse::<Ethernet>().discard()?;
    let v6 = ethernet.parse::<Ipv6>().discard()?;

    if v6.next_header() == ProtocolNumbers::Tcp {
        let dscp = v6.dscp();
        let ecn = v6.ecn();
        let ttl = v6.hop_limit() - 1;
        let protocol = v6.next_header();
        let src_ip = v6.src();
        let dst_ip = map_6to4(v6.dst());
        let src_mac = v6.envelope().src();

        let mut ethernet = v6.remove()?;
        ethernet.swap_addresses();
        ethernet.set_dst(DST_MAC);

        let mut v4 = ethernet.push::<Ipv4>()?;
        v4.set_dscp(dscp);
        v4.set_ecn(ecn);
        v4.set_ttl(ttl);
        v4.set_protocol(protocol);
        v4.set_src(SRC_IP);
        v4.set_dst(dst_ip);

        let mut tcp = v4.parse::<Tcp4>().discard()?;
        let port = tcp.src_port();
        tcp.set_src_port(get_v4_port(src_mac, src_ip, port));
        tcp.reconcile_all();

        let fmt = format!("{:?}", tcp.envelope()).magenta();
        info!("{}", fmt);
        let fmt = format!("{:?}", tcp).bright_blue();
        info!("{}", fmt);

        Ok(Postmark::emit(tcp))
    } else {
        Ok(Postmark::drop(v6))
    }
}

/// Maps the source IPv4 address to its IPv6 counterpart with well-known
/// prefix `64:ff9b::/96`.
fn map_4to6(addr: Ipv4Addr) -> Ipv6Addr {
    let octets = addr.octets();
    Ipv6Addr::new(
        0x64,
        0xff9b,
        0x0,
        0x0,
        0x0,
        0x0,
        (octets[0] as u16) << 8 | (octets[1] as u16),
        (octets[2] as u16) << 8 | (octets[3] as u16),
    )
}

/// Looks up the IPv6 destination
fn get_v6_dst(port: u16) -> Option<(MacAddr, Ipv6Addr, u16)> {
    PORTS
        .lock()
        .unwrap()
        .get_by_right(&port)
        .and_then(|(ip, port)| MACS.lock().unwrap().get(ip).map(|mac| (*mac, *ip, *port)))
}

fn nat_4to6(packet: Mbuf) -> Result<Postmark, Nat4to6PacketError> {
    let ethernet = packet.parse::<Ethernet>().discard()?;
    let v4 = ethernet.parse::<Ipv4>().discard()?;

    if v4.protocol() == ProtocolNumbers::Tcp && v4.fragment_offset() == 0 && !v4.more_fragments() {
        let tcp = v4.peek::<Tcp4>()?;

        if let Some((dst_mac, dst_ip, port)) = get_v6_dst(tcp.dst_port()) {
            let dscp = v4.dscp();
            let ecn = v4.ecn();
            let next_header = v4.protocol();
            let hop_limit = v4.ttl() - 1;
            let src_ip = map_4to6(v4.src());

            let mut ethernet = v4.remove()?;
            ethernet.swap_addresses();
            ethernet.set_dst(dst_mac);

            let mut v6 = ethernet.push::<Ipv6>()?;
            v6.set_dscp(dscp);
            v6.set_ecn(ecn);
            v6.set_next_header(next_header);
            v6.set_hop_limit(hop_limit);
            v6.set_src(src_ip);
            v6.set_dst(dst_ip);

            let mut tcp = v6.parse::<Tcp6>().discard()?;
            tcp.set_dst_port(port);
            tcp.reconcile_all();

            let fmt = format!("{:?}", tcp.envelope()).cyan();
            info!("{}", fmt);
            let fmt = format!("{:?}", tcp).bright_blue();
            info!("{}", fmt);

            Ok(Postmark::emit(tcp))
        } else {
            Ok(Postmark::drop(v4))
        }
    } else {
        Ok(Postmark::drop(v4))
    }
}

fn main() -> anyhow::Result<()> {
    let subscriber = fmt::Subscriber::builder()
        .with_max_level(Level::INFO)
        .finish();
    tracing::subscriber::set_global_default(subscriber)?;

    let config = runtime::load_config()?;
    let runtime = Runtime::from_config(config)?;

    runtime.spawn_rx_tx_pipeline("cap0", nat_6to4, Some("cap1"))?;
    runtime.spawn_rx_tx_pipeline("cap1", nat_4to6, Some("cap0"))?;

    let _guard = runtime.execute()?;

    let term = Arc::new(AtomicBool::new(false));
    flag::register(consts::SIGINT, Arc::clone(&term))?;
    info!("ctrl-c to quit ...");
    while !term.load(Ordering::Relaxed) {}

    Ok(())
}
