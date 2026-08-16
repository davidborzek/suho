// SPDX-License-Identifier: GPL-3.0-or-later
//! NFLOG receiver task.

use std::collections::HashMap;
use std::net::IpAddr;
use std::os::fd::{AsRawFd, OwnedFd};
use std::sync::{Arc, RwLock};
use std::time::Instant;

use anyhow::{Context, Result};
use nix::errno::Errno;
use nix::sys::socket::sockopt::RcvBuf;
use nix::sys::socket::{
    self, AddressFamily, MsgFlags, NetlinkAddr, SockFlag, SockProtocol, SockType, setsockopt,
};
use tracing::{info, warn};

use crate::config::SinkKind;
use crate::obs::Metrics;

use super::{FlowEvent, FlowSink, parse_packet, parse_prefix, sink_for};

/// Shared IP → container name index used to resolve flow endpoints.
pub type IpIndex = HashMap<IpAddr, String>;

/// NFLOG subsystem and message constants. `nfnetlink_log` is subsystem 4
/// (`NFNL_SUBSYS_ULOG`); it drives both the config messages and the packet type.
const NFNL_SUBSYS_ULOG: u16 = 4;
const NFULNL_MSG_PACKET: u8 = 0;
const NFULNL_MSG_CONFIG: u8 = 1;

const NLM_F_REQUEST: u16 = 0x0001;
const NLM_F_ACK: u16 = 0x0004;

const AF_UNSPEC: u8 = 0;

const NFULNL_CFG_CMD: u16 = 1;
const NFULNL_CFG_MODE: u16 = 2;
const NFULNL_CFG_CMD_BIND: u8 = 1;
const NFULNL_COPY_PACKET: u8 = 2;

const NFULA_PACKET_HDR: u16 = 1;
const NFULA_PAYLOAD: u16 = 9;
const NFULA_PREFIX: u16 = 10;

const NLMSG_HDRLEN: usize = 16;
const NLMSG_ERROR: u16 = 2;

/// Receive buffer. Netlink never splits a single message across reads.
const READ_BUF_BYTES: usize = 256 * 1024;

/// Netlink attribute header length.
const NLA_HDRLEN: usize = 4;

/// Flow-log receiver: owns the NFLOG socket, parses packets, resolves identity
/// and emits events through a sink.
pub struct Receiver {
    group: u16,
    sink: Box<dyn FlowSink + Send + Sync>,
    rate: u32,
    index: Arc<RwLock<IpIndex>>,
    metrics: Arc<Metrics>,
}

impl Receiver {
    /// Create a new receiver.
    pub fn new(
        group: u16,
        sink_kind: SinkKind,
        rate: u32,
        index: Arc<RwLock<IpIndex>>,
        metrics: Arc<Metrics>,
    ) -> Self {
        Self {
            group,
            sink: sink_for(sink_kind),
            rate,
            index,
            metrics,
        }
    }

    /// Run the receiver until the socket closes or an unrecoverable error
    /// occurs. This should normally be executed on a dedicated thread because
    /// the netlink `recv` call blocks.
    pub fn run(self) {
        let fd = match open_socket(self.group) {
            Ok(fd) => fd,
            Err(err) => {
                warn!(%err, "failed to open NFLOG socket; flow log disabled");
                return;
            }
        };

        info!(group = self.group, "NFLOG flow-log receiver started");

        let mut buf = vec![0u8; READ_BUF_BYTES];
        let mut limiter = RateLimiter::new(self.rate);
        loop {
            match socket::recv(fd.as_raw_fd(), &mut buf, MsgFlags::empty()) {
                Ok(0) => break,
                Ok(n) => self.scan(&buf[..n], &mut limiter),
                Err(Errno::EINTR) => continue,
                Err(err) => {
                    warn!(%err, "NFLOG recv error; stopping flow-log receiver");
                    break;
                }
            }
        }

        info!("NFLOG flow-log receiver stopped");
    }

    fn scan(&self, buf: &[u8], limiter: &mut RateLimiter) {
        let mut off = 0;
        while off + NLMSG_HDRLEN <= buf.len() {
            let len = read_u32_ne(buf, off) as usize;
            if len < NLMSG_HDRLEN || off + len > buf.len() {
                break;
            }
            let msg_type = read_u16_ne(buf, off + 4);
            let expected_type = NFNL_SUBSYS_ULOG << 8 | u16::from(NFULNL_MSG_PACKET);
            if msg_type == expected_type {
                if let Some(ev) = parse_nflog_packet(buf, off, len, &self.index) {
                    // Count every flow (ground truth); the rate limiter only
                    // throttles how many reach the log sink.
                    self.metrics.flow_event(
                        ev.verdict.clone(),
                        ev.dir.clone(),
                        ev.container.clone(),
                    );
                    if limiter.allow() {
                        self.sink.emit(&ev);
                    } else {
                        self.metrics.flow_ratelimited();
                    }
                }
            } else if msg_type == NLMSG_ERROR {
                // Acks/errors from the initial CONFIG messages — log once if
                // nonzero, otherwise ignore.
                if let Some(errno) = read_error_errno(buf, off, len) {
                    warn!(errno, "NFLOG netlink error");
                }
            }
            off += nlmsg_align(len);
        }
    }
}

fn open_socket(group: u16) -> Result<OwnedFd> {
    let sock = socket::socket(
        AddressFamily::Netlink,
        SockType::Raw,
        SockFlag::empty(),
        SockProtocol::NetlinkNetFilter,
    )
    .context("opening NFLOG socket")?;

    // Best-effort receive buffer enlargement; not fatal if it fails.
    if let Err(err) = setsockopt(&sock, RcvBuf, &(4 * 1024 * 1024)) {
        warn!(%err, "could not enlarge NFLOG receive buffer");
    }

    socket::bind(sock.as_raw_fd(), &NetlinkAddr::new(0, 0)).context("binding NFLOG socket")?;

    send_config_bind(&sock, group)?;
    send_config_mode(&sock, group)?;
    Ok(sock)
}

fn send_config_bind(sock: &OwnedFd, group: u16) -> Result<()> {
    // nfulnl_msg_config_cmd { command: u8 }
    send_config_msg(sock, group, NFULNL_CFG_CMD, &[NFULNL_CFG_CMD_BIND], 1)
}

fn send_config_mode(sock: &OwnedFd, group: u16) -> Result<()> {
    // nfulnl_msg_config_mode { copy_range: u32 BE, copy_mode: u8, _pad: u8 }
    let mut payload = Vec::with_capacity(6);
    payload.extend_from_slice(&0x0000FFFFu32.to_be_bytes());
    payload.push(NFULNL_COPY_PACKET);
    payload.push(0);
    send_config_msg(sock, group, NFULNL_CFG_MODE, &payload, 2)
}

fn send_config_msg(
    sock: &OwnedFd,
    group: u16,
    attr_type: u16,
    attr_payload: &[u8],
    seq: u32,
) -> Result<()> {
    let attr_len = NLA_HDRLEN + attr_payload.len();
    let total = NLMSG_HDRLEN + 4 + nlmsg_align(attr_len);

    let mut msg = Vec::with_capacity(total);
    // nlmsghdr
    msg.extend_from_slice(&(total as u32).to_ne_bytes());
    let msg_type = NFNL_SUBSYS_ULOG << 8 | u16::from(NFULNL_MSG_CONFIG);
    msg.extend_from_slice(&msg_type.to_ne_bytes());
    msg.extend_from_slice(&(NLM_F_REQUEST | NLM_F_ACK).to_ne_bytes());
    msg.extend_from_slice(&seq.to_ne_bytes());
    msg.extend_from_slice(&0u32.to_ne_bytes());
    // nfgenmsg
    msg.push(AF_UNSPEC);
    msg.push(0);
    msg.extend_from_slice(&group.to_be_bytes());
    // nlattr
    msg.extend_from_slice(&(attr_len as u16).to_le_bytes());
    msg.extend_from_slice(&attr_type.to_le_bytes());
    msg.extend_from_slice(attr_payload);
    // Pad to NLA_ALIGN (4).
    while msg.len() < total {
        msg.push(0);
    }

    socket::send(sock.as_raw_fd(), &msg, MsgFlags::empty()).context("sending NFLOG config")?;
    Ok(())
}

fn parse_nflog_packet(
    buf: &[u8],
    msg_off: usize,
    msg_len: usize,
    index: &Arc<RwLock<IpIndex>>,
) -> Option<FlowEvent> {
    let mut off = msg_off + NLMSG_HDRLEN + 4; // skip nlmsghdr + nfgenmsg
    let msg_end = msg_off + msg_len;

    let mut prefix = String::new();
    let mut payload = None;
    let mut _hw_protocol = None;

    while off + NLA_HDRLEN <= msg_end {
        let attr_len = read_u16_le(buf, off) as usize;
        let attr_type = read_u16_le(buf, off + 2);
        if attr_len < NLA_HDRLEN || off + attr_len > msg_end {
            break;
        }
        let payload_start = off + NLA_HDRLEN;
        let payload_end = off + attr_len;
        match attr_type {
            NFULA_PACKET_HDR => {
                if payload_end >= payload_start + 2 {
                    _hw_protocol = Some(read_u16_be(buf, payload_start));
                }
            }
            NFULA_PREFIX => {
                let bytes = &buf[payload_start..payload_end];
                let len = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
                prefix = String::from_utf8_lossy(&bytes[..len]).into_owned();
            }
            NFULA_PAYLOAD => {
                payload = Some(&buf[payload_start..payload_end]);
            }
            _ => {}
        }
        off += nlmsg_align(attr_len);
    }

    let payload = payload?;
    let (container, dir, verdict) = parse_prefix(&prefix);

    let (src, dst, proto, sport, dport) = match parse_packet(payload) {
        Ok(parsed) => parsed,
        Err(err) => {
            warn!(%err, "failed to parse NFLOG payload");
            return None;
        }
    };

    let index_guard = index.read().expect("ip index poisoned");
    let peer = match dir.as_str() {
        "egress" => index_guard.get(&dst).cloned(),
        "ingress" => index_guard.get(&src).cloned(),
        _ => None,
    };
    drop(index_guard);

    Some(FlowEvent::new(
        verdict, dir, proto, src, dst, sport, dport, container, peer,
    ))
}

fn read_error_errno(buf: &[u8], off: usize, len: usize) -> Option<i32> {
    if len >= NLMSG_HDRLEN + 4 {
        let errno = read_i32_ne(buf, off + NLMSG_HDRLEN);
        if errno != 0 {
            return Some(errno);
        }
    }
    None
}

const fn nlmsg_align(len: usize) -> usize {
    (len + 3) & !3
}

fn read_u16_ne(buf: &[u8], off: usize) -> u16 {
    u16::from_ne_bytes([buf[off], buf[off + 1]])
}

fn read_u16_le(buf: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([buf[off], buf[off + 1]])
}

fn read_u16_be(buf: &[u8], off: usize) -> u16 {
    u16::from_be_bytes([buf[off], buf[off + 1]])
}

fn read_u32_ne(buf: &[u8], off: usize) -> u32 {
    u32::from_ne_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]])
}

fn read_i32_ne(buf: &[u8], off: usize) -> i32 {
    i32::from_ne_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]])
}

/// Simple token-bucket rate limiter.
struct RateLimiter {
    rate: u32,
    tokens: f64,
    last: Instant,
}

impl RateLimiter {
    fn new(rate: u32) -> Self {
        Self {
            rate,
            tokens: rate as f64,
            last: Instant::now(),
        }
    }

    fn allow(&mut self) -> bool {
        if self.rate == 0 {
            return true;
        }
        let now = Instant::now();
        let elapsed = now.duration_since(self.last).as_secs_f64();
        self.last = now;
        self.tokens = (self.tokens + elapsed * f64::from(self.rate)).min(f64::from(self.rate));
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rate_limiter_allows_zero_as_unlimited() {
        let mut limiter = RateLimiter::new(0);
        for _ in 0..10 {
            assert!(limiter.allow());
        }
    }

    #[test]
    fn rate_limiter_allows_one_per_second() {
        let mut limiter = RateLimiter::new(1);
        assert!(limiter.allow());
        assert!(!limiter.allow());
    }

    #[test]
    fn parse_nflog_packet_fixture() {
        let mut buf = Vec::new();

        // nlmsghdr
        let prefix = "suho c=web;d=egress;v=drop";
        let payload = build_ipv4_tcp();
        let attr_len = nlmsg_align(NLA_HDRLEN + 4)
            + nlmsg_align(NLA_HDRLEN + prefix.len() + 1)
            + nlmsg_align(NLA_HDRLEN + payload.len());
        let msg_len = NLMSG_HDRLEN + 4 + attr_len;
        buf.extend_from_slice(&(msg_len as u32).to_ne_bytes());
        buf.extend_from_slice(
            &((NFNL_SUBSYS_ULOG << 8) | u16::from(NFULNL_MSG_PACKET)).to_ne_bytes(),
        );
        buf.extend_from_slice(&0u16.to_ne_bytes()); // flags
        buf.extend_from_slice(&0u32.to_ne_bytes()); // seq
        buf.extend_from_slice(&0u32.to_ne_bytes()); // pid

        // nfgenmsg
        buf.push(2); // AF_INET
        buf.push(0);
        buf.extend_from_slice(&100u16.to_be_bytes());

        // NFULA_PACKET_HDR
        buf.extend_from_slice(&((NLA_HDRLEN + 4) as u16).to_le_bytes());
        buf.extend_from_slice(&NFULA_PACKET_HDR.to_le_bytes());
        buf.extend_from_slice(&0x0800u16.to_be_bytes()); // hw_protocol
        buf.push(0); // hook
        buf.push(0); // _pad

        // NFULA_PREFIX
        let prefix_attr_len = NLA_HDRLEN + prefix.len() + 1;
        buf.extend_from_slice(&(prefix_attr_len as u16).to_le_bytes());
        buf.extend_from_slice(&NFULA_PREFIX.to_le_bytes());
        buf.extend_from_slice(prefix.as_bytes());
        buf.push(0);
        while buf.len() % 4 != 0 {
            buf.push(0);
        }

        // NFULA_PAYLOAD
        let payload_attr_len = NLA_HDRLEN + payload.len();
        buf.extend_from_slice(&(payload_attr_len as u16).to_le_bytes());
        buf.extend_from_slice(&NFULA_PAYLOAD.to_le_bytes());
        buf.extend_from_slice(&payload);

        let index = Arc::new(RwLock::new(HashMap::from([(
            IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 5)),
            "db".to_owned(),
        )])));

        let ev =
            parse_nflog_packet(&buf, 0, msg_len, &index).expect("parse_nflog_packet returned None");
        assert_eq!(ev.container, "web");
        assert_eq!(ev.dir, "egress");
        assert_eq!(ev.verdict, "drop");
        assert_eq!(ev.proto, "tcp");
        assert_eq!(ev.src, "10.0.0.2");
        assert_eq!(ev.dst, "10.0.0.5");
        assert_eq!(ev.sport, Some(12345));
        assert_eq!(ev.dport, Some(443));
        assert_eq!(ev.peer, Some("db".to_owned()));
    }

    fn build_ipv4_tcp() -> Vec<u8> {
        use etherparse::{Ipv4Header, TcpHeader, ip_number};
        let ip = Ipv4Header::new(20, 64, ip_number::TCP, [10, 0, 0, 2], [10, 0, 0, 5]).unwrap();
        let tcp = TcpHeader::new(12345, 443, 0, 20);
        let mut buf = Vec::new();
        ip.write(&mut buf).unwrap();
        tcp.write(&mut buf).unwrap();
        buf
    }
}
