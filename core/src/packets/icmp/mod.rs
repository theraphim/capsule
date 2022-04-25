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

//! Internet Control Message Protocol for IPv4 and IPv6.

use crate::packets::ip::ProtocolNumber;
use crate::packets::MbufError;
use thiserror::Error;

pub mod v4;
pub mod v6;

#[derive(Error, Debug)]
pub enum IcmpError {
    #[error("mbuf error")]
    MbufError(#[from] MbufError),
    #[error("not an ICMP ({expected:?}) packet: {found:?}")]
    InvalidPacketType {
        found: ProtocolNumber,
        expected: ProtocolNumber,
    },
    #[error("cannot push a generic ICMP header without a message body")]
    DisallowedPush,
    #[error("the ICMP ({expected:?}) packet {found} is not {expected}")]
    IcmpTypeMismatch {
        packet_type: ProtocolNumber,
        found: u8,
        expected: u8,
    },
}
