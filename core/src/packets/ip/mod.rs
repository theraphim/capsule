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

//! Internet Protocol v4 and v6.

pub mod v4;
pub mod v6;

use crate::packets::checksum::PseudoHeader;
use crate::packets::ethernet::EtherType;
use crate::packets::ip::v6::Ipv6Error;
use crate::packets::{MbufError, Packet};
use std::fmt;
use std::net::{IpAddr, Ipv4Addr};
use thiserror::Error;

/// [IANA] recommended default TTL for IP.
///
/// [IANA]: https://www.iana.org/assignments/ip-parameters/ip-parameters.xml#ip-parameters-2
pub const DEFAULT_IP_TTL: u8 = 64;

/// [IANA] assigned Internet protocol number.
///
/// See [`ProtocolNumbers`] for which are current supported.
///
/// [IANA]: https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
/// [`ProtocolNumbers`]: crate::packets::ip::ProtocolNumbers
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
#[repr(C, packed)]
pub struct ProtocolNumber(pub u8);

impl ProtocolNumber {
    /// Creates a new protocol number.
    pub fn new(value: u8) -> Self {
        ProtocolNumber(value)
    }
}

/// Supported protocol numbers.
#[allow(non_snake_case)]
#[allow(non_upper_case_globals)]
pub mod ProtocolNumbers {
    use super::ProtocolNumber;

    /// Transmission Control Protocol.
    pub const Tcp: ProtocolNumber = ProtocolNumber(0x06);

    /// User Datagram Protocol.
    pub const Udp: ProtocolNumber = ProtocolNumber(0x11);

    /// Routing Header for IPv6.
    pub const Ipv6Route: ProtocolNumber = ProtocolNumber(0x2B);

    /// Fragment Header for IPv6.
    pub const Ipv6Frag: ProtocolNumber = ProtocolNumber(0x2C);

    /// Internet Control Message Protocol for IPv6.
    pub const Icmpv6: ProtocolNumber = ProtocolNumber(0x3A);

    /// Internet Control Message Protocol for IPv4.
    pub const Icmpv4: ProtocolNumber = ProtocolNumber(0x01);
}

impl fmt::Display for ProtocolNumber {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            match *self {
                ProtocolNumbers::Tcp => "TCP".to_string(),
                ProtocolNumbers::Udp => "UDP".to_string(),
                ProtocolNumbers::Ipv6Route => "IPv6 Route".to_string(),
                ProtocolNumbers::Ipv6Frag => "IPv6 Frag".to_string(),
                ProtocolNumbers::Icmpv6 => "ICMPv6".to_string(),
                ProtocolNumbers::Icmpv4 => "ICMPv4".to_string(),
                _ => format!("0x{:02x}", self.0),
            }
        )
    }
}

#[derive(Debug)]
pub enum IpVersion {
    IPv4,
    IPv6,
}

/*
   TODO
   the IpProtocolSpecificError is only done because it would be impossible without negative impls
   to restrict the IpError on the IpPacket trait as such that it cannot be implemented by errors
   up the chain using generics. this can be reverted back to being beautiful when negative impls
   are stable.
*/

/* /// Trait to distinguish IP packet error types from other errors to prevent conflicts
trait IpPacketError {} */
// TODO req negative_impl

/// Generic IP packet error
#[derive(Error, Debug)]
pub enum IpError {
    /// Error returned by the underlying mbuf
    #[error("mbuf error")]
    MbufError(#[from] MbufError),
    /// Invalid packet for this parser
    #[error("not an IP ({expected:?}) packet: {found:?}")]
    InvalidPacketType {
        found: EtherType,
        expected: EtherType,
    },
    /// Invalid source IP address version
    #[error("source address must be {expected:?}")]
    InvalidSourceAddress { expected: IpVersion },
    /// Invalid destination IP address version
    #[error("destination address must be {expected:?}")]
    InvalidDestinationAddress { expected: IpVersion },
    /// MTU too small
    #[error("MTU {found} must be greater than {expected}")]
    InvalidMtu { found: usize, expected: usize },
    /// Either IPv4 or IPv6 protocol specific error
    #[error("Protocol specific error")]
    ProtocolSpecificError(#[from] IpProtocolSpecificError),
}

/// Protocol specific error
// Weird implementation only required because of no negative_impl support
#[derive(Error, Debug)]
pub enum IpProtocolSpecificError {
    #[error("IPv6 error")]
    V6(#[from] Ipv6Error),
}

// impl IpPacketError for IpError {} // TODO req negative_impl

/// A trait implemented by IPv4, IPv6 and IPv6 extension packets.
pub trait IpPacket: Packet {
    // type IpError: Error + IpPacketError + From<IpError>; // TODO req negative_impl

    /// Returns the assigned protocol number of the packet immediately follows.
    ///
    /// For IPv4 packets, this should be the [`protocol`] field. For IPv6 and
    /// extension packets, this should be the [`next header`] field.
    ///
    /// [`protocol`]: v4::Ipv4::protocol
    /// [`next header`]: v6::Ipv6Packet::next_header
    fn next_protocol(&self) -> ProtocolNumber;

    /// Sets the protocol number of the packet immediately follows.
    ///
    /// For IPv4 packets, this should be the [`protocol`] field. For IPv6 and
    /// extension packets, this should be the [`next header`] field.
    ///
    /// [`protocol`]: v4::Ipv4::protocol
    /// [`next header`]: v6::Ipv6Packet::next_header
    fn set_next_protocol(&mut self, proto: ProtocolNumber);

    /// Returns the source IP address
    fn src(&self) -> IpAddr;

    /// Sets the source IP address
    ///
    /// This lets an upper layer packet like TCP set the source IP address.
    /// on a lower layer packet.
    fn set_src(&mut self, src: IpAddr) -> Result<(), IpError>;

    /// Returns the destination IP address
    fn dst(&self) -> IpAddr;

    /// Sets the destination IP address.
    ///
    /// This lets an upper layer packet like TCP set the destination IP address
    /// on a lower layer packet.
    fn set_dst(&mut self, dst: IpAddr) -> Result<(), IpError>;

    /// Swaps the source and destination IP addresses
    ///
    /// This lets an upper layer packet like TCP swap the IP addresses
    /// on a lower layer packet.
    fn swap_addresses(&mut self) -> Result<(), IpError> {
        let src_addr = self.src();
        self.set_src(self.dst())?;
        self.set_dst(src_addr)?;
        Ok(())
    }

    /// Returns the pseudo-header for layer 4 checksum computation.
    fn pseudo_header(&self, packet_len: u16, protocol: ProtocolNumber) -> PseudoHeader;

    /// Truncates the IP packet to MTU. The data exceeds MTU is lost.
    fn truncate(&mut self, mtu: usize) -> Result<(), IpError>;
}

/// The common attributes (5-tuple) used to identify an IP based network
/// connection.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
#[repr(C, packed)]
pub struct Flow {
    src_ip: IpAddr,
    dst_ip: IpAddr,
    src_port: u16,
    dst_port: u16,
    protocol: ProtocolNumber,
}

impl Default for Flow {
    fn default() -> Flow {
        Flow {
            src_ip: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            dst_ip: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            src_port: 0,
            dst_port: 0,
            protocol: ProtocolNumber::default(),
        }
    }
}

impl Flow {
    /// Creates a new IP flow.
    pub fn new(
        src_ip: IpAddr,
        dst_ip: IpAddr,
        src_port: u16,
        dst_port: u16,
        protocol: ProtocolNumber,
    ) -> Self {
        Flow {
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            protocol,
        }
    }

    /// Returns the source address.
    #[inline]
    pub fn src_ip(&self) -> IpAddr {
        self.src_ip
    }

    /// Sets the source address.
    #[inline]
    pub fn set_src_ip(&mut self, src_ip: IpAddr) {
        self.src_ip = src_ip
    }

    /// Returns the destination address.
    #[inline]
    pub fn dst_ip(&self) -> IpAddr {
        self.dst_ip
    }

    /// Sets the destination address.
    #[inline]
    pub fn set_dst_ip(&mut self, dst_ip: IpAddr) {
        self.dst_ip = dst_ip
    }

    /// Returns the source port.
    #[inline]
    pub fn src_port(&self) -> u16 {
        self.src_port
    }

    /// Sets the source port.
    #[inline]
    pub fn set_src_port(&mut self, src_port: u16) {
        self.src_port = src_port
    }

    /// Returns the destination port.
    #[inline]
    pub fn dst_port(&self) -> u16 {
        self.dst_port
    }

    /// Sets the destination port.
    #[inline]
    pub fn set_dst_port(&mut self, dst_port: u16) {
        self.dst_port = dst_port
    }

    /// Returns the flow protocol.
    #[inline]
    pub fn protocol(&self) -> ProtocolNumber {
        self.protocol
    }

    /// Sets the flow protocol.
    #[inline]
    pub fn set_protocol(&mut self, protocol: ProtocolNumber) {
        self.protocol = protocol
    }

    /// Reverses the flow by swapping the source and destination.
    #[inline]
    pub fn reverse(&self) -> Self {
        Flow {
            src_ip: self.dst_ip,
            dst_ip: self.src_ip,
            src_port: self.dst_port,
            dst_port: self.src_port,
            protocol: self.protocol,
        }
    }
}

impl fmt::Debug for Flow {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("flow")
            .field("src_ip", &format!("{}", self.src_ip()))
            .field("src_port", &self.src_port())
            .field("dst_ip", &format!("{}", self.dst_ip()))
            .field("dst_port", &self.dst_port())
            .field("protocol", &format!("{}", self.protocol()))
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protocol_number_to_string() {
        assert_eq!("TCP", ProtocolNumbers::Tcp.to_string());
        assert_eq!("UDP", ProtocolNumbers::Udp.to_string());
        assert_eq!("IPv6 Route", ProtocolNumbers::Ipv6Route.to_string());
        assert_eq!("ICMPv6", ProtocolNumbers::Icmpv6.to_string());
        assert_eq!("0x00", ProtocolNumber::new(0).to_string());
    }
}
