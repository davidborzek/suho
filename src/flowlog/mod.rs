// SPDX-License-Identifier: GPL-3.0-or-later
//! Phase-1 NFLOG-based flow log.
//!
//! When enabled (`SUHO_FLOWLOG=drops`), suho tags each default-deny rule with
//! an NFLOG prefix and asks nftables to copy dropped packets to a userspace
//! NFLOG group. A dedicated task receives those packets, resolves the source
//! and destination against the current container identity index, and emits a
//! structured JSON event per dropped flow.

mod event;
mod receiver;
mod sink;

pub use event::{FlowEvent, parse_packet, parse_prefix};
pub use receiver::{IpIndex, Receiver};
pub use sink::{FlowSink, sink_for};
