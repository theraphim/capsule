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

use super::{AsStr, EasyPtr, ToCString, ToResult};
use crate::net::MacAddr;
use crate::{debug, error};
use anyhow::{anyhow, Result};
use capsule_ffi as cffi;
use std::fmt;
use std::mem;
use std::ops::{Deref, DerefMut};
use std::os::raw;
use std::panic::{self, AssertUnwindSafe};
use std::ptr;
use thiserror::Error;
use std::mem::MaybeUninit;
use tracing::trace;
use std::convert::{TryFrom, TryInto};
use capsule_ffi::rte_lcore_state_t::Type;
use std::os::raw::c_uint;

/// Initializes the Environment Abstraction Layer (EAL).
pub(crate) fn eal_init<S: Into<String>>(args: Vec<S>) -> Result<()> {
    let args = args
        .into_iter()
        .map(|s| Into::<String>::into(s).into_cstring())
        .collect::<Vec<_>>();
    debug!(arguments=?args);

    let mut ptrs = args
        .iter()
        .map(|s| s.as_ptr() as *mut raw::c_char)
        .collect::<Vec<_>>();
    let len = ptrs.len() as raw::c_int;

    let parsed =
        unsafe { cffi::rte_eal_init(len, ptrs.as_mut_ptr()).into_result(DpdkError::from_errno)? };
    debug!("EAL parsed {} arguments.", parsed);

    Ok(())
}

/// Cleans up the Environment Abstraction Layer (EAL).
pub(crate) fn eal_cleanup() -> Result<()> {
    unsafe { cffi::rte_eal_cleanup() }
        .into_result(DpdkError::from_errno)
        .map(|_| ())
}

/// An opaque identifier for a physical CPU socket.
///
/// A socket is also known as a NUMA node. On a multi-socket system, for best
/// performance, ensure that the cores and memory used for packet processing
/// are in the same socket as the network interface card.
#[derive(Copy, Clone, Eq, Hash, PartialEq)]
pub(crate) struct SocketId(raw::c_int);

impl SocketId {
    /// A socket ID representing any NUMA socket.
    #[allow(dead_code)]
    pub(crate) const ANY: Self = SocketId(-1);
}

impl fmt::Debug for SocketId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "socket{}", self.0)
    }
}

impl From<raw::c_int> for SocketId {
    fn from(id: raw::c_int) -> Self {
        SocketId(id)
    }
}

/// A `rte_mempool` pointer.
pub(crate) type MempoolPtr = EasyPtr<cffi::rte_mempool>;

impl Clone for MempoolPtr {
    fn clone(&self) -> Self {
        self.0.clone().into()
    }
}

// Allows the pointer to go across thread/lcore boundaries.
unsafe impl Send for MempoolPtr {}

/// Creates a mbuf pool.
pub(crate) fn pktmbuf_pool_create<S: Into<String>>(
    name: S,
    capacity: usize,
    cache_size: usize,
    socket_id: SocketId,
) -> Result<MempoolPtr> {
    let name: String = name.into();

    let ptr = unsafe {
        cffi::rte_pktmbuf_pool_create(
            name.into_cstring().as_ptr(),
            capacity as raw::c_uint,
            cache_size as raw::c_uint,
            0,
            cffi::RTE_MBUF_DEFAULT_BUF_SIZE as u16,
            socket_id.0,
        )
        .into_result(|_| DpdkError::new())?
    };

    Ok(EasyPtr(ptr))
}

/// Looks up a mempool by the name.
#[cfg(test)]
pub(crate) fn mempool_lookup<S: Into<String>>(name: S) -> Result<MempoolPtr> {
    let name: String = name.into();

    let ptr = unsafe {
        cffi::rte_mempool_lookup(name.into_cstring().as_ptr()).into_result(|_| DpdkError::new())?
    };

    Ok(EasyPtr(ptr))
}

/// Returns the number of elements which have been allocated from the mempool.
#[allow(dead_code)]
pub(crate) fn mempool_in_use_count(mp: &MempoolPtr) -> usize {
    unsafe { cffi::rte_mempool_in_use_count(mp.deref()) as usize }
}

/// Returns the number of entries in the mempool.
#[allow(dead_code)]
pub(crate) fn mempool_avail_count(mp: &MempoolPtr) -> usize {
    unsafe { cffi::rte_mempool_avail_count(mp.deref()) as usize }
}

/// Frees a mempool.
pub(crate) fn mempool_free(mp: &mut MempoolPtr) {
    unsafe { cffi::rte_mempool_free(mp.deref_mut()) };
}

/// An opaque identifier for a logical execution unit of the processor.
#[derive(Copy, Clone, Eq, Hash, PartialEq)]
pub(crate) struct LcoreId(raw::c_uint);

impl Into<raw::c_uint> for LcoreId {
    fn into(self) -> c_uint {
        self.0
    }
}

impl From<raw::c_uint> for LcoreId {
    fn from(id: c_uint) -> Self {
        LcoreId(id)
    }
}

impl LcoreId {
    /// Any lcore to indicate that no thread affinity is set.
    #[cfg(test)]
    pub(crate) const ANY: Self = LcoreId(raw::c_uint::MAX);

    /// Returns the ID of the current execution unit or `LcoreId::ANY` when
    /// called from a non-EAL thread.
    #[inline]
    pub(crate) fn current() -> LcoreId {
        unsafe { LcoreId(cffi::_rte_lcore_id()) }
    }

    /// Returns the ID of the main lcore.
    #[inline]
    pub(crate) fn main() -> LcoreId {
        unsafe { LcoreId(cffi::rte_get_main_lcore()) }
    }

    /// Returns the ID of the physical CPU socket of the lcore.
    #[allow(clippy::trivially_copy_pass_by_ref)]
    #[inline]
    pub(crate) fn socket(&self) -> SocketId {
        unsafe { (cffi::rte_lcore_to_socket_id(self.0) as raw::c_int).into() }
    }

    /// Returns the raw value.
    pub(crate) fn raw(&self) -> usize {
        self.0 as usize
    }
}

impl fmt::Debug for LcoreId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "lcore{}", self.0)
    }
}

/// Gets the next enabled lcore ID.
pub(crate) fn get_next_lcore(
    id: Option<LcoreId>,
    skip_master: bool,
    wrap: bool,
) -> Option<LcoreId> {
    let (i, wrap) = match id {
        Some(id) => (id.0, wrap as raw::c_int),
        None => (raw::c_uint::MAX, 1),
    };

    let skip_master = skip_master as raw::c_int;

    match unsafe { cffi::rte_get_next_lcore(i, skip_master, wrap) } {
        cffi::RTE_MAX_LCORE => None,
        id => Some(LcoreId(id)),
    }
}

/// The function passed to `rte_eal_remote_launch`.
unsafe extern "C" fn lcore_fn<F>(arg: *mut raw::c_void) -> raw::c_int
where
    F: FnOnce() -> Result<Option<i32>> + Send + 'static,
{
    let f = Box::from_raw(arg as *mut F);

    // in case the closure panics, let's not crash the app.
    let res = panic::catch_unwind(AssertUnwindSafe(f));
    let result = match res {
        Ok(Ok(opt)) => Ok(opt.map(|val| val.into())),
        Ok(Err(e)) => Err(e),
        Err(_) => Err(anyhow!("Panicked")),
    };

    return match result {
        Err(err) => {
            error!(lcore = ?LcoreId::current(), error = ?err, "failed to execute closure.");
            -2
        },
        Ok(None) => -1,
        Ok(Some(val)) => val
    }
}

/// Launches a function on another lcore.
pub(crate) fn eal_remote_launch<F>(worker_id: LcoreId, f: F) -> Result<()>
where
    F: FnOnce() -> Result<Option<i32>> + Send + 'static,
{
    let ptr = Box::into_raw(Box::new(f)) as *mut raw::c_void;

    unsafe {
        cffi::rte_eal_remote_launch(Some(lcore_fn::<F>), ptr, worker_id.0)
            .into_result(DpdkError::from_errno)
            .map(|_| ())
    }
}

pub(crate) enum LcoreState {
    WAIT,
    RUNNING,
}

impl TryFrom<cffi::rte_lcore_state_t::Type> for LcoreState {
    type Error = anyhow::Error;

    fn try_from(value: Type) -> std::result::Result<Self, Self::Error> {
        match value {
            cffi::rte_lcore_state_t::WAIT => Ok(LcoreState::WAIT),
            cffi::rte_lcore_state_t::RUNNING => Ok(LcoreState::RUNNING),
            _ => {
                Err(anyhow!("Not a valid LCoreState"))
            }
        }
    }
}

/// Get the state of the lcore identified by worker_id.
pub(crate) fn eal_get_lcore_state(worker_id: LcoreId) -> Result<LcoreState> {
    unsafe { cffi::rte_eal_get_lcore_state(worker_id.0) }.try_into()
}

/// Wait until an lcore finishes its job.
/// Ignores the return value.
pub(crate) fn eal_wait_lcore(worker_id: LcoreId) -> Result<Option<i32>> {
    match unsafe { cffi::rte_eal_wait_lcore(worker_id.0) }.into() {
        -2 => Err(anyhow!("LCore function returned an error")),
        -1 => Ok(None),
        val => Ok(Some(val))
    }
}

/// An opaque identifier for a PMD device port.
#[derive(Copy, Clone, PartialEq)]
pub(crate) struct PortId(u16);

impl PortId {
    /// Returns the ID of the socket the port is connected to.
    #[inline]
    pub(crate) fn socket(self) -> SocketId {
        unsafe { cffi::rte_eth_dev_socket_id(self.0).into() }
    }

    /// Returns the port ID
    pub(crate) fn id(self) -> u16 { self.0 }
}

impl fmt::Debug for PortId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "port{}", self.0)
    }
}

/// Gets the port id from device name.
pub(crate) fn eth_dev_get_port_by_name<S: Into<String>>(name: S) -> Result<PortId> {
    let name: String = name.into();
    let mut port_id = 0u16;
    unsafe {
        cffi::rte_eth_dev_get_port_by_name(name.into_cstring().as_ptr(), &mut port_id)
            .into_result(DpdkError::from_errno)?;
    }
    Ok(PortId(port_id))
}

/// Retrieves the Ethernet address of a device.
pub(crate) fn eth_macaddr_get(port_id: PortId) -> Result<MacAddr> {
    let mut addr = cffi::rte_ether_addr::default();
    unsafe {
        cffi::rte_eth_macaddr_get(port_id.0, &mut addr).into_result(DpdkError::from_errno)?;
    }
    Ok(addr.addr_bytes.into())
}

/// Retrieves the contextual information of a device.
pub(crate) fn eth_dev_info_get(port_id: PortId) -> Result<cffi::rte_eth_dev_info> {
    let mut port_info = cffi::rte_eth_dev_info::default();
    unsafe {
        cffi::rte_eth_dev_info_get(port_id.0, &mut port_info).into_result(DpdkError::from_errno)?;
    }
    Ok(port_info)
}

/// Checks that numbers of Rx and Tx descriptors satisfy descriptors limits
/// from the ethernet device information, otherwise adjust them to boundaries.
pub(crate) fn eth_dev_adjust_nb_rx_tx_desc(
    port_id: PortId,
    nb_rx_desc: usize,
    nb_tx_desc: usize,
) -> Result<(usize, usize)> {
    let mut nb_rx_desc = nb_rx_desc as u16;
    let mut nb_tx_desc = nb_tx_desc as u16;

    unsafe {
        cffi::rte_eth_dev_adjust_nb_rx_tx_desc(port_id.0, &mut nb_rx_desc, &mut nb_tx_desc)
            .into_result(DpdkError::from_errno)?;
    }

    Ok((nb_rx_desc as usize, nb_tx_desc as usize))
}

/// Returns the value of promiscuous mode for a device.
pub(crate) fn eth_promiscuous_get(port_id: PortId) -> bool {
    let mode =
        unsafe { cffi::rte_eth_promiscuous_get(port_id.0).into_result(DpdkError::from_errno) };
    // assuming port_id is valid, treats Ok(0) and Err(_) both as disabled.
    matches!(mode, Ok(1))
}

/// Enables receipt in promiscuous mode for a device.
pub(crate) fn eth_promiscuous_enable(port_id: PortId) -> Result<()> {
    unsafe {
        cffi::rte_eth_promiscuous_enable(port_id.0)
            .into_result(DpdkError::from_errno)
            .map(|_| ())
    }
}

/// Disables receipt in promiscuous mode for a device.
pub(crate) fn eth_promiscuous_disable(port_id: PortId) -> Result<()> {
    unsafe {
        cffi::rte_eth_promiscuous_disable(port_id.0)
            .into_result(DpdkError::from_errno)
            .map(|_| ())
    }
}

/// Returns the value of allmulticast mode for a device.
pub(crate) fn eth_allmulticast_get(port_id: PortId) -> bool {
    let mode =
        unsafe { cffi::rte_eth_allmulticast_get(port_id.0).into_result(DpdkError::from_errno) };
    // assuming port_id is valid, treats Ok(0) and Err(_) both as disabled.
    matches!(mode, Ok(1))
}

/// Enables the receipt of any multicast frame by a device.
pub(crate) fn eth_allmulticast_enable(port_id: PortId) -> Result<()> {
    unsafe {
        cffi::rte_eth_allmulticast_enable(port_id.0)
            .into_result(DpdkError::from_errno)
            .map(|_| ())
    }
}

/// Disables the receipt of any multicast frame by a device.
pub(crate) fn eth_allmulticast_disable(port_id: PortId) -> Result<()> {
    unsafe {
        cffi::rte_eth_allmulticast_disable(port_id.0)
            .into_result(DpdkError::from_errno)
            .map(|_| ())
    }
}

/// Creates a symmetric RSS flow rule for a device with a specific protocol match and RSS type
fn eth_sym_rss_flow_rule_create(port_id: PortId, rss_hf: u64, proto_stack: Vec<cffi::rte_flow_item_type::Type>, num_queues: usize) -> Result<&'static cffi::rte_flow> {
    trace!("Creating symmetric RSS flow rule for {:?} with rss_hf: {} and protos: {:?}", port_id, rss_hf, proto_stack);
    // Create pattern items
    let mut flow_items: Vec<cffi::rte_flow_item> = Vec::new();
    for proto in &proto_stack {
        flow_items.push(cffi::rte_flow_item {
            type_: proto.clone(),
            spec: ptr::null(),
            last: ptr::null(),
            mask: ptr::null()
        })
    }
    // Push end item
    flow_items.push(cffi::rte_flow_item {
        type_: cffi::rte_flow_item_type::RTE_FLOW_ITEM_TYPE_END,
        spec: ptr::null(),
        last: ptr::null(),
        mask: ptr::null()
    });
    // Create config for RSS action type
    let flow_action_rss_conf = cffi::rte_flow_action_rss {
        func: cffi::rte_eth_hash_function::RTE_ETH_HASH_FUNCTION_SYMMETRIC_TOEPLITZ,
        level: 0,
        types: rss_hf,
        key_len: 0,
        queue_num: num_queues as u32,
        key: ptr::null(),
        queue: ptr::null()
    };
    // Creation action items
    let flow_action_rss_conf_ptr: *const cffi::rte_flow_action_rss = &flow_action_rss_conf;
    let flow_action_rss = cffi::rte_flow_action {
        type_: cffi::rte_flow_action_type::RTE_FLOW_ACTION_TYPE_RSS,
        conf: flow_action_rss_conf_ptr as *const raw::c_void
    };
    let flow_action_end = cffi::rte_flow_action {
        type_: cffi::rte_flow_action_type::RTE_FLOW_ACTION_TYPE_END,
        conf: ptr::null()
    };
    let flow_actions = [flow_action_rss, flow_action_end];
    let flow_attr = cffi::rte_flow_attr {
        group: 0,
        priority: 0,
        _bitfield_align_1: [],
        _bitfield_1: cffi::rte_flow_attr::new_bitfield_1(1, 0, 0, 0)
    };
    let mut flow_error_uninit = MaybeUninit::<cffi::rte_flow_error>::uninit();
    match unsafe { cffi::rte_flow_create(port_id.0,
                                                          &flow_attr,
                                                          flow_items.as_ptr(),
                                                          flow_actions.as_ptr(),
                                                          flow_error_uninit.as_mut_ptr()).as_ref() } {
        Some(flow_rule) => {
            trace!("Created symmetric RSS flow rule for {:?} with rss_hf: {} and protos: {:?}", port_id, rss_hf, proto_stack);
            Ok(flow_rule)
        },
        None => {
            let rte_error = DpdkError::new();
            let flow_error = unsafe { flow_error_uninit.assume_init() };
            Err(anyhow!("Symmetric RSS flow rule for RSS type(s) '{:?}' and protocol stack '{:?}' create failed: {}, detail: {} ({})", rss_hf, proto_stack, rte_error, flow_error.message.as_str(), flow_error.type_))
        }
    }
}

/// Enables symmetric RSS for a device
pub(crate) fn eth_sym_rss_enable(port_id: PortId, num_queues: usize) -> Result<()> {
    let specs = vec![
        // IPv4 UDP
        (cffi::RTE_ETH_FLOW_NONFRAG_IPV4_UDP,
         vec![cffi::rte_flow_item_type::RTE_FLOW_ITEM_TYPE_IPV4,
              cffi::rte_flow_item_type::RTE_FLOW_ITEM_TYPE_UDP]),
        // IPv4 TCP
        (cffi::RTE_ETH_FLOW_NONFRAG_IPV4_TCP,
         vec![cffi::rte_flow_item_type::RTE_FLOW_ITEM_TYPE_IPV4,
              cffi::rte_flow_item_type::RTE_FLOW_ITEM_TYPE_TCP]),
        // IPv4
        (cffi::RTE_ETH_FLOW_FRAG_IPV4,
         vec![cffi::rte_flow_item_type::RTE_FLOW_ITEM_TYPE_IPV4]),
        (cffi::RTE_ETH_FLOW_NONFRAG_IPV4_OTHER,
         vec![cffi::rte_flow_item_type::RTE_FLOW_ITEM_TYPE_IPV4]),
        // IPv6 UDP
        (cffi::RTE_ETH_FLOW_NONFRAG_IPV6_UDP,
         vec![cffi::rte_flow_item_type::RTE_FLOW_ITEM_TYPE_IPV6,
              cffi::rte_flow_item_type::RTE_FLOW_ITEM_TYPE_UDP]),
        // IPv6 TCP
        (cffi::RTE_ETH_FLOW_NONFRAG_IPV6_TCP,
         vec![cffi::rte_flow_item_type::RTE_FLOW_ITEM_TYPE_IPV6,
              cffi::rte_flow_item_type::RTE_FLOW_ITEM_TYPE_TCP]),
        // IPv6
        (cffi::RTE_ETH_FLOW_FRAG_IPV6,
         vec![cffi::rte_flow_item_type::RTE_FLOW_ITEM_TYPE_IPV6]),
        (cffi::RTE_ETH_FLOW_NONFRAG_IPV6_OTHER,
         vec![cffi::rte_flow_item_type::RTE_FLOW_ITEM_TYPE_IPV6]),
    ];
    for (rss_hf, mut protos) in specs {
        protos.insert(0, cffi::rte_flow_item_type::RTE_FLOW_ITEM_TYPE_ETH);
        eth_sym_rss_flow_rule_create(port_id, rss_hf as u64, protos, num_queues)?;
    }
    Ok(())
}

/// Configures a device.
pub(crate) fn eth_dev_configure(
    port_id: PortId,
    nb_rx_queue: usize,
    nb_tx_queue: usize,
    eth_conf: &cffi::rte_eth_conf,
) -> Result<()> {
    unsafe {
        cffi::rte_eth_dev_configure(port_id.0, nb_rx_queue as u16, nb_tx_queue as u16, eth_conf)
            .into_result(DpdkError::from_errno)
            .map(|_| ())
    }
}

/// An opaque identifier for a port's receive queue.
#[derive(Copy, Clone)]
pub(crate) struct PortQueueId(u16);

impl PortQueueId {
    /// Returns the queue ID
    pub(crate) fn id(self) -> u16 { self.0 }
}

impl fmt::Debug for PortQueueId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "q{}", self.0)
    }
}

impl From<usize> for PortQueueId {
    fn from(id: usize) -> Self {
        PortQueueId(id as u16)
    }
}

impl Into<usize> for PortQueueId {
    fn into(self) -> usize {
        self.0.into()
    }
}

/// Allocates and sets up a receive queue for a device.
pub(crate) fn eth_rx_queue_setup(
    port_id: PortId,
    queue_id: PortQueueId,
    nb_rx_desc: usize,
    socket_id: SocketId,
    rx_conf: Option<&cffi::rte_eth_rxconf>,
    mb_pool: &mut MempoolPtr,
) -> Result<()> {
    unsafe {
        cffi::rte_eth_rx_queue_setup(
            port_id.0,
            queue_id.0,
            nb_rx_desc as u16,
            socket_id.0 as raw::c_uint,
            rx_conf.map_or(ptr::null(), |conf| conf),
            mb_pool.deref_mut(),
        )
        .into_result(DpdkError::from_errno)
        .map(|_| ())
    }
}

/// Removes an RX or TX packet callback from a given port and queue.
#[allow(dead_code)]
pub(crate) enum RxTxCallbackGuard {
    Rx(PortId, PortQueueId, *const cffi::rte_eth_rxtx_callback),
    Tx(PortId, PortQueueId, *const cffi::rte_eth_rxtx_callback),
}

impl Drop for RxTxCallbackGuard {
    fn drop(&mut self) {
        if let Err(error) = match self {
            RxTxCallbackGuard::Rx(port_id, queue_id, ptr) => {
                debug!(port = ?port_id, rxq = ?queue_id, "remove rx callback.");
                unsafe {
                    cffi::rte_eth_remove_rx_callback(port_id.0, queue_id.0, *ptr)
                        .into_result(DpdkError::from_errno)
                }
            }
            RxTxCallbackGuard::Tx(port_id, queue_id, ptr) => {
                debug!(port = ?port_id, txq = ?queue_id, "remove tx callback.");
                unsafe {
                    cffi::rte_eth_remove_tx_callback(port_id.0, queue_id.0, *ptr)
                        .into_result(DpdkError::from_errno)
                }
            }
        } {
            error!(?error);
        }
    }
}

/// Adds a callback to be called on packet RX on a given port and queue.
#[allow(dead_code)]
pub(crate) fn eth_add_rx_callback<T>(
    port_id: PortId,
    queue_id: PortQueueId,
    callback: cffi::rte_rx_callback_fn,
    user_param: &mut T,
) -> Result<RxTxCallbackGuard> {
    let ptr = unsafe {
        cffi::rte_eth_add_rx_callback(
            port_id.0,
            queue_id.0,
            callback,
            user_param as *mut T as *mut raw::c_void,
        )
        .into_result(|_| DpdkError::new())?
    };

    Ok(RxTxCallbackGuard::Rx(port_id, queue_id, ptr))
}

/// Retrieves a burst of input packets from a receive queue of a device.
pub(crate) fn eth_rx_burst(port_id: PortId, queue_id: PortQueueId, rx_pkts: &mut Vec<MbufPtr>) {
    let nb_pkts = rx_pkts.capacity();

    unsafe {
        let len = cffi::_rte_eth_rx_burst(
            port_id.0,
            queue_id.0,
            rx_pkts.as_mut_ptr() as *mut *mut cffi::rte_mbuf,
            nb_pkts as u16,
        );

        rx_pkts.set_len(len as usize);
    }
}

/// Allocates and sets up a transmit queue for a device.
pub(crate) fn eth_tx_queue_setup(
    port_id: PortId,
    queue_id: PortQueueId,
    nb_tx_desc: usize,
    socket_id: SocketId,
    tx_conf: Option<&cffi::rte_eth_txconf>,
) -> Result<()> {
    unsafe {
        cffi::rte_eth_tx_queue_setup(
            port_id.0,
            queue_id.0,
            nb_tx_desc as u16,
            socket_id.0 as raw::c_uint,
            tx_conf.map_or(ptr::null(), |conf| conf),
        )
        .into_result(DpdkError::from_errno)
        .map(|_| ())
    }
}

/// Adds a callback to be called on packet TX on a given port and queue.
#[allow(dead_code)]
pub(crate) fn eth_add_tx_callback<T>(
    port_id: PortId,
    queue_id: PortQueueId,
    callback: cffi::rte_tx_callback_fn,
    user_param: &mut T,
) -> Result<RxTxCallbackGuard> {
    let ptr = unsafe {
        cffi::rte_eth_add_tx_callback(
            port_id.0,
            queue_id.0,
            callback,
            user_param as *mut T as *mut raw::c_void,
        )
        .into_result(|_| DpdkError::new())?
    };

    Ok(RxTxCallbackGuard::Tx(port_id, queue_id, ptr))
}

/// Sends a burst of output packets on a transmit queue of a device.
pub(crate) fn eth_tx_burst(
    port_id: PortId,
    queue_id: PortQueueId,
    tx_pkts: &mut Vec<MbufPtr>,
) -> usize {
    let nb_pkts = tx_pkts.len();

    let sent = unsafe {
        cffi::_rte_eth_tx_burst(
            port_id.0,
            queue_id.0,
            tx_pkts.as_mut_ptr() as *mut *mut cffi::rte_mbuf,
            nb_pkts as u16,
        )
    } as usize;

    if nb_pkts > sent {
        // wasn't able to send everything.
        mem::forget(tx_pkts.drain(..sent));
    } else {
        unsafe {
            tx_pkts.set_len(0);
        }
    }

    sent
}

/// Starts a device.
pub(crate) fn eth_dev_start(port_id: PortId) -> Result<()> {
    unsafe {
        cffi::rte_eth_dev_start(port_id.0)
            .into_result(DpdkError::from_errno)
            .map(|_| ())
    }
}

/// Stops a device.
pub(crate) fn eth_dev_stop(port_id: PortId) {
    unsafe {
        cffi::rte_eth_dev_stop(port_id.0);
    }
}

/// Get port statistics
pub(crate) fn eth_stats_get(port_id: PortId) -> Result<cffi::rte_eth_stats> {
    let mut stats = cffi::rte_eth_stats::default();
    unsafe {
        cffi::rte_eth_stats_get(port_id.0, &mut stats)
            .into_result(DpdkError::from_errno)
            .map(|_| stats)
    }
}

/// A `rte_mbuf` pointer.
pub(crate) type MbufPtr = EasyPtr<cffi::rte_mbuf>;

// Allows the pointer to go across thread/lcore boundaries.
unsafe impl Send for MbufPtr {}

/// Allocates a new mbuf from a mempool.
pub(crate) fn pktmbuf_alloc(mp: &mut MempoolPtr) -> Result<MbufPtr> {
    let ptr =
        unsafe { cffi::_rte_pktmbuf_alloc(mp.deref_mut()).into_result(|_| DpdkError::new())? };

    Ok(EasyPtr(ptr))
}

/// Allocates a bulk of mbufs.
pub(crate) fn pktmbuf_alloc_bulk(mp: &mut MempoolPtr, mbufs: &mut Vec<MbufPtr>) -> Result<()> {
    let len = mbufs.capacity();

    unsafe {
        cffi::_rte_pktmbuf_alloc_bulk(
            mp.deref_mut(),
            mbufs.as_mut_ptr() as *mut *mut cffi::rte_mbuf,
            len as raw::c_uint,
        )
        .into_result(DpdkError::from_errno)?;

        mbufs.set_len(len);
    }

    Ok(())
}

/// Frees a packet mbuf back into its original mempool.
pub(crate) fn pktmbuf_free(mut m: MbufPtr) {
    unsafe {
        cffi::_rte_pktmbuf_free(m.deref_mut());
    }
}

/// Frees a bulk of packet mbufs back into their original mempools.
pub(crate) fn pktmbuf_free_bulk(mbufs: &mut Vec<MbufPtr>) {
    assert!(!mbufs.is_empty());

    let mut to_free = Vec::with_capacity(mbufs.len());
    let mut pool = mbufs[0].pool;

    for mbuf in mbufs.drain(..) {
        if pool == mbuf.pool {
            to_free.push(mbuf);
        } else {
            unsafe {
                let len = to_free.len();
                cffi::_rte_mempool_put_bulk(
                    pool,
                    to_free.as_ptr() as *const *mut raw::c_void,
                    len as u32,
                );
                to_free.set_len(0);
            }

            pool = mbuf.pool;
            to_free.push(mbuf);
        }
    }

    unsafe {
        let len = to_free.len();
        cffi::_rte_mempool_put_bulk(
            pool,
            to_free.as_ptr() as *const *mut raw::c_void,
            len as u32,
        );
        to_free.set_len(0);
    }
}

/// An error generated in `libdpdk`.
///
/// When an FFI call fails, the `errno` is translated into `DpdkError`.
#[derive(Debug, Error)]
#[error("{0}")]
pub(crate) struct DpdkError(String);

impl DpdkError {
    /// Returns the `DpdkError` for the most recent failure on the current
    /// thread.
    #[inline]
    pub(crate) fn new() -> Self {
        DpdkError::from_errno(-1)
    }

    /// Returns the `DpdkError` for a specific `errno`.
    #[inline]
    fn from_errno(errno: raw::c_int) -> Self {
        let errno = if errno == -1 {
            unsafe { cffi::_rte_errno() }
        } else {
            -errno
        };
        DpdkError(unsafe { cffi::rte_strerror(errno).as_str().into() })
    }
}
