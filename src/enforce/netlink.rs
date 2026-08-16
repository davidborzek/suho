// SPDX-License-Identifier: GPL-3.0-or-later
//! Sends a finalized `rustables` batch over a netlink socket we control.
//!
//! `rustables::Batch::send()` opens its socket with the default `SO_RCVBUF`
//! (`net.core.rmem_default`, ~208 KiB) and never enlarges it. A full-table
//! atomic replace makes the kernel answer with a burst of per-object acks; once
//! that burst exceeds the socket's receive queue the next `recv()` fails with
//! `ENOBUFS`. rustables exposes no hook to size the socket, but `Batch::finalize`
//! is public — so we serialize the batch, send it on our own socket with a large
//! forced receive buffer, and drain the acks ourselves.
//!
//! Forcing a 16 MiB receive buffer is exactly what `nft`, `iptables-nft` and OVS
//! do for the same reason. `SO_RCVBUFFORCE` bypasses `net.core.rmem_max` and
//! needs `CAP_NET_ADMIN`, which suho already holds to program nftables — so no
//! host sysctl tuning is required.

use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::io::RawFd;

use anyhow::{Context, Result, anyhow};
use nix::sys::socket::sockopt::{RcvBuf, RcvBufForce};
use nix::sys::socket::{
    self, AddressFamily, MsgFlags, NetlinkAddr, SockFlag, SockProtocol, SockType, setsockopt,
};
use rustables::Batch;
use tracing::warn;

/// Forced netlink receive buffer (matches `nft`'s `1 << 24`). Acks are ~36 bytes
/// each, so this covers a full-table replace of well over a hundred thousand
/// objects.
const RCVBUF_BYTES: usize = 16 * 1024 * 1024;

/// Userspace read buffer. Netlink never splits a single message across reads, so
/// this only bounds how many complete ack messages one `recv` drains at once.
const READ_BUF_BYTES: usize = 256 * 1024;

const NLMSG_HDRLEN: usize = 16;
const NLMSG_ERROR: u16 = 2;
const NLMSG_DONE: u16 = 3;

/// Sends the batch atomically and waits for the kernel's acks, surfacing the
/// first rejection (the errno names the offending object).
pub(super) fn send_batch(batch: Batch) -> Result<()> {
    let bytes = batch.finalize();
    let terminal = terminal_seq(&bytes);

    let sock = socket::socket(
        AddressFamily::Netlink,
        SockType::Raw,
        SockFlag::empty(),
        SockProtocol::NetlinkNetFilter,
    )
    .context("opening netlink socket")?;

    // Enlarge the receive buffer before any acks arrive (see module docs).
    if let Err(force_err) = setsockopt(&sock, RcvBufForce, &RCVBUF_BYTES) {
        // No CAP_NET_ADMIN? fall back to the rmem_max-capped SO_RCVBUF.
        if let Err(capped_err) = setsockopt(&sock, RcvBuf, &RCVBUF_BYTES) {
            warn!(
                force = %force_err,
                capped = %capped_err,
                "could not enlarge the netlink receive buffer; large rulesets may hit ENOBUFS"
            );
        }
    }

    // Not strictly required, but keeps strace/nlmon decoding sane.
    socket::bind(sock.as_raw_fd(), &NetlinkAddr::new(0, 0)).context("binding netlink socket")?;

    let mut sent = 0;
    while sent < bytes.len() {
        sent += socket::send(sock.as_raw_fd(), &bytes[sent..], MsgFlags::empty())
            .context("sending nftables batch")?;
    }

    drain_acks(sock.as_raw_fd(), terminal)
}

fn drain_acks(fd: RawFd, terminal: u32) -> Result<()> {
    let mut buf = vec![0u8; READ_BUF_BYTES];
    loop {
        let n = socket::recv(fd, &mut buf, MsgFlags::empty()).context("receiving nftables acks")?;
        if n == 0 {
            return Ok(());
        }
        match scan(&buf[..n], terminal) {
            Scan::Done => return Ok(()),
            Scan::Failed(errno) => {
                return Err(anyhow!(
                    "nftables rejected the ruleset: {} (errno {})",
                    io::Error::from_raw_os_error(-errno),
                    -errno
                ));
            }
            Scan::More => {}
        }
    }
}

/// The reconcile's terminating sequence number.
///
/// rustables numbers `NFNL_MSG_BATCH_BEGIN` seq 0, each object 1..=K, and
/// `NFNL_MSG_BATCH_END` seq K+1, then waits for the ack of seq K (`self.seq - 1`).
/// We recover K as `(max seq in the finalized buffer) - 1`.
fn terminal_seq(buf: &[u8]) -> u32 {
    let mut off = 0;
    let mut max = 0u32;
    while off + NLMSG_HDRLEN <= buf.len() {
        let len = read_u32(buf, off) as usize;
        if len < NLMSG_HDRLEN || off + len > buf.len() {
            break;
        }
        max = max.max(read_u32(buf, off + 8));
        off += nlmsg_align(len);
    }
    max.saturating_sub(1)
}

/// Outcome of scanning one batch of received netlink messages.
#[derive(Debug, PartialEq, Eq)]
enum Scan {
    /// Reached the terminal ack (or a DONE marker) — the apply succeeded.
    Done,
    /// No terminal ack or error yet; receive more.
    More,
    /// The kernel rejected an object with this (negative) errno.
    Failed(i32),
}

fn scan(buf: &[u8], terminal: u32) -> Scan {
    let mut off = 0;
    while off + NLMSG_HDRLEN <= buf.len() {
        let len = read_u32(buf, off) as usize;
        if len < NLMSG_HDRLEN || off + len > buf.len() {
            break;
        }
        let msg_type = read_u16(buf, off + 4);
        let seq = read_u32(buf, off + 8);
        if msg_type == NLMSG_DONE {
            return Scan::Done;
        }
        if msg_type == NLMSG_ERROR && off + NLMSG_HDRLEN + 4 <= buf.len() {
            let errno = read_i32(buf, off + NLMSG_HDRLEN);
            if errno != 0 {
                return Scan::Failed(errno);
            }
        }
        if seq >= terminal {
            return Scan::Done;
        }
        off += nlmsg_align(len);
    }
    Scan::More
}

const fn nlmsg_align(len: usize) -> usize {
    (len + 3) & !3
}

fn read_u16(buf: &[u8], off: usize) -> u16 {
    u16::from_ne_bytes([buf[off], buf[off + 1]])
}

fn read_u32(buf: &[u8], off: usize) -> u32 {
    u32::from_ne_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]])
}

fn read_i32(buf: &[u8], off: usize) -> i32 {
    i32::from_ne_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hdr(len: u32, msg_type: u16, seq: u32) -> Vec<u8> {
        let mut m = Vec::new();
        m.extend_from_slice(&len.to_ne_bytes());
        m.extend_from_slice(&msg_type.to_ne_bytes());
        m.extend_from_slice(&0u16.to_ne_bytes()); // flags
        m.extend_from_slice(&seq.to_ne_bytes());
        m.extend_from_slice(&0u32.to_ne_bytes()); // pid
        m
    }

    fn err_msg(seq: u32, errno: i32) -> Vec<u8> {
        // nlmsgerr = s32 error + the original header (we only read the errno)
        let mut m = hdr((NLMSG_HDRLEN + 4) as u32, NLMSG_ERROR, seq);
        m.extend_from_slice(&errno.to_ne_bytes());
        m
    }

    #[test]
    fn terminal_seq_is_max_minus_one() {
        // BATCH_BEGIN(0), object(1), object(2), BATCH_END(3) -> terminal 2
        let mut buf = hdr(NLMSG_HDRLEN as u32, 0x10, 0);
        buf.extend(hdr(NLMSG_HDRLEN as u32, 0x800, 1));
        buf.extend(hdr(NLMSG_HDRLEN as u32, 0x800, 2));
        buf.extend(hdr(NLMSG_HDRLEN as u32, 0x11, 3));
        assert_eq!(terminal_seq(&buf), 2);
    }

    #[test]
    fn scan_done_on_terminal_ack() {
        let buf = err_msg(2, 0); // ack (errno 0) for the terminal seq
        assert_eq!(scan(&buf, 2), Scan::Done);
    }

    #[test]
    fn scan_reports_rejection() {
        let buf = err_msg(1, -22); // EINVAL
        assert_eq!(scan(&buf, 5), Scan::Failed(-22));
    }

    #[test]
    fn scan_needs_more_before_terminal() {
        let buf = err_msg(0, 0); // ack for seq 0, terminal is 3
        assert_eq!(scan(&buf, 3), Scan::More);
    }

    #[test]
    fn scan_walks_multiple_messages() {
        let mut buf = err_msg(0, 0);
        buf.extend(err_msg(1, 0));
        buf.extend(err_msg(2, 0)); // terminal
        assert_eq!(scan(&buf, 2), Scan::Done);
    }

    #[test]
    fn scan_error_wins_over_later_terminal() {
        let mut buf = err_msg(0, 0);
        buf.extend(err_msg(1, -1)); // EPERM before the terminal ack
        assert_eq!(scan(&buf, 2), Scan::Failed(-1));
    }
}
