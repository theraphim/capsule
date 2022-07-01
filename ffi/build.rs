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

#[cfg(not(feature = "rustdoc"))]
use std::env;
#[cfg(not(feature = "rustdoc"))]
use std::path::{Path, PathBuf};

#[cfg(not(feature = "rustdoc"))]
const RTE_CORE_LIBS: &[&str] = &[
    "rte_acl",
    "rte_bbdev",
    "rte_bitratestats",
    "rte_bpf",
    "rte_bus_dpaa",
    "rte_bus_fslmc",
    "rte_bus_ifpga",
    "rte_bus_pci",
    "rte_bus_vdev",
    "rte_bus_vmbus",
    "rte_cfgfile",
    "rte_cmdline",
    "rte_common_cpt",
    "rte_common_dpaax",
    "rte_compressdev",
    "rte_cryptodev",
    "rte_distributor",
    "rte_eal",
    "rte_efd",
    "rte_ethdev",
    "rte_eventdev",
    "rte_fib",
    "rte_flow_classify",
    "rte_gro",
    "rte_gso",
    "rte_hash",
    "rte_ip_frag",
    "rte_ipsec",
    "rte_jobstats",
    "rte_kni",
    "rte_kvargs",
    "rte_latencystats",
    "rte_lpm",
    "rte_mbuf",
    "rte_member",
    "rte_mempool",
    "rte_mempool_bucket",
    "rte_mempool_dpaa",
    "rte_mempool_dpaa2",
    "rte_mempool_octeontx",
    "rte_mempool_ring",
    "rte_mempool_stack",
    "rte_meter",
    "rte_metrics",
    "rte_net",
    "rte_pci",
    "rte_pdump",
    "rte_pipeline",
    "rte_port",
    "rte_power",
    "rte_rawdev",
    "rte_raw_dpaa2_cmdif",
    "rte_raw_dpaa2_qdma",
    "rte_raw_ntb",
    "rte_raw_skeleton",
    "rte_rcu",
    "rte_reorder",
    "rte_rib",
    "rte_ring",
    "rte_sched",
    "rte_security",
    "rte_stack",
    "rte_table",
    "rte_timer",
    "rte_vhost",
];

#[cfg(not(feature = "rustdoc"))]
const RTE_DEPS_LIBS: &[&str] = &["numa", "pcap"];

#[cfg(not(feature = "rustdoc"))]
fn bind(path: &Path) {
    cc::Build::new()
        .file("src/shim.c")
        .flag("-march=corei7-avx")
        .compile("rte_shim");

    bindgen::Builder::default()
        .header("src/bindings.h")
        .generate_comments(true)
        .generate_inline_functions(true)
        // treat as opaque as per issue w/ combining align/packed:
        // https://github.com/rust-lang/rust-bindgen/issues/1538
        .opaque_type(r"rte_arp_ipv4|rte_arp_hdr|rte_l2tpv2_combined_msg_hdr|rte_gtp_psc_generic_hdr")
        .allowlist_type(r"(rte|eth|pcap)_.*")
        .allowlist_function(r"(_rte|rte|eth|numa|pcap)_.*")
        .allowlist_var(r"(RTE|DEV|ETH|MEMPOOL|PKT|rte)_.*")
        .derive_copy(true)
        .derive_debug(true)
        .derive_default(true)
        .derive_partialeq(true)
        .default_enum_style(bindgen::EnumVariation::ModuleConsts)
        .clang_arg("-finline-functions")
        .clang_arg("-march=corei7-avx")
        .rustfmt_bindings(true)
        .generate()
        .expect("Unable to generate bindings")
        .write_to_file(path.join("bindings.rs"))
        .expect("Couldn't write bindings!");
}

#[cfg(not(feature = "rustdoc"))]
fn main() {
    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());

    bind(&out_path);

    println!("cargo:rustc-link-search=/usr/local/lib64");

    let core_linkage = match env::var("DPDK_STATIC_LINK") {
        Ok(x) if x == "1" => "static",
        _ => "dylib",
    };

    RTE_CORE_LIBS
        .iter()
        .for_each(|lib| println!("cargo:rustc-link-lib={}={}", core_linkage, lib));

    RTE_DEPS_LIBS
        .iter()
        .for_each(|lib| println!("cargo:rustc-link-lib=dylib={}", lib));

    // re-run build.rs upon changes
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=src/");
}

// Skip the build script on docs.rs
#[cfg(feature = "rustdoc")]
fn main() {}
