// SPDX-License-Identifier: GPL-3.0-or-later
//! Parsed flow event and helpers for extracting it from an NFLOG payload.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use anyhow::{Context, Result};
use serde::Serialize;

/// One structured flow event emitted by the flow-log sink.
#[derive(Debug, Clone, Serialize)]
pub struct FlowEvent {
    /// Event type discriminator.
    #[serde(rename = "event")]
    pub event: &'static str,
    /// Event timestamp (RFC3339 UTC): the kernel NFLOG timestamp when present,
    /// otherwise the receiver's wall-clock receive time.
    pub ts: String,
    /// Observed verdict (`drop` for dropped-flow logging).
    pub verdict: String,
    /// Traffic direction (`egress` or `ingress`).
    pub dir: String,
    /// IP protocol name (`tcp`, `udp`, `icmp`, ...).
    pub proto: String,
    /// Source IP address.
    pub src: String,
    /// Destination IP address.
    pub dst: String,
    /// Source L4 port, when available (TCP/UDP).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sport: Option<u16>,
    /// Destination L4 port, when available (TCP/UDP).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dport: Option<u16>,
    /// Governed container name, or `-` when the prefix cannot be parsed.
    pub container: String,
    /// Resolved name of the peer container, if its IP is known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub peer: Option<String>,
}

impl FlowEvent {
    /// Build a flow event from the pieces resolved by the receiver.
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        ts: String,
        verdict: String,
        dir: String,
        proto: String,
        src: IpAddr,
        dst: IpAddr,
        sport: Option<u16>,
        dport: Option<u16>,
        container: String,
        peer: Option<String>,
    ) -> Self {
        Self {
            event: "suho_flow",
            ts,
            verdict,
            dir,
            proto,
            src: src.to_string(),
            dst: dst.to_string(),
            sport,
            dport,
            container,
            peer,
        }
    }
}

/// Parse the NFLOG prefix `suho c=<name>;d=<dir>;v=<verdict>`.
pub fn parse_prefix(prefix: &str) -> (String, String, String) {
    let mut container = "-".to_owned();
    let mut dir = "-".to_owned();
    let mut verdict = "-".to_owned();

    for part in prefix.split(';') {
        let part = part.trim_start_matches("suho ");
        if let Some(value) = part.strip_prefix("c=") {
            container = value.to_owned();
        } else if let Some(value) = part.strip_prefix("d=") {
            dir = value.to_owned();
        } else if let Some(value) = part.strip_prefix("v=") {
            verdict = value.to_owned();
        }
    }

    (container, dir, verdict)
}

/// Parsed L3/L4 endpoint information.
pub type PacketInfo = (IpAddr, IpAddr, String, Option<u16>, Option<u16>);

/// Parse an IPv4/IPv6 payload and return (src, dst, proto, sport, dport).
#[allow(clippy::type_complexity)]
pub fn parse_packet(payload: &[u8]) -> Result<PacketInfo> {
    let headers =
        etherparse::PacketHeaders::from_ip_slice(payload).context("parsing IP packet headers")?;

    let (src, dst, proto_num) = match headers.net {
        Some(etherparse::NetHeaders::Ipv4(h, _)) => (
            IpAddr::V4(Ipv4Addr::from(h.source)),
            IpAddr::V4(Ipv4Addr::from(h.destination)),
            h.protocol.into(),
        ),
        Some(etherparse::NetHeaders::Ipv6(h, _)) => (
            IpAddr::V6(Ipv6Addr::from(h.source)),
            IpAddr::V6(Ipv6Addr::from(h.destination)),
            h.next_header.into(),
        ),
        None => anyhow::bail!("payload is not an IPv4/IPv6 packet"),
    };

    let (sport, dport) = match headers.transport {
        Some(etherparse::TransportHeader::Tcp(tcp)) => {
            (Some(tcp.source_port), Some(tcp.destination_port))
        }
        Some(etherparse::TransportHeader::Udp(udp)) => {
            (Some(udp.source_port), Some(udp.destination_port))
        }
        _ => (None, None),
    };

    Ok((src, dst, proto_name(proto_num), sport, dport))
}

fn proto_name(num: u8) -> String {
    match num {
        1 => "icmp".to_owned(),
        6 => "tcp".to_owned(),
        17 => "udp".to_owned(),
        58 => "ipv6-icmp".to_owned(),
        n => n.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_prefix_round_trip() {
        let (c, d, v) = parse_prefix("suho c=web;d=egress;v=drop");
        assert_eq!(c, "web");
        assert_eq!(d, "egress");
        assert_eq!(v, "drop");
    }

    #[test]
    fn parse_prefix_defaults_on_garbage() {
        let (c, d, v) = parse_prefix("not-a-suho-prefix");
        assert_eq!(c, "-");
        assert_eq!(d, "-");
        assert_eq!(v, "-");
    }

    #[test]
    fn parse_ipv4_tcp_packet() {
        let payload = build_ipv4_tcp();
        let (src, dst, proto, sport, dport) = parse_packet(&payload).unwrap();
        assert_eq!(src, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)));
        assert_eq!(dst, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)));
        assert_eq!(proto, "tcp");
        assert_eq!(sport, Some(12345));
        assert_eq!(dport, Some(443));
    }

    #[test]
    fn parse_ipv6_udp_packet() {
        let payload = build_ipv6_udp();
        let (src, dst, proto, sport, dport) = parse_packet(&payload).unwrap();
        assert_eq!(src, IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2)));
        assert_eq!(dst, IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 5)));
        assert_eq!(proto, "udp");
        assert_eq!(sport, Some(54321));
        assert_eq!(dport, Some(53));
    }

    #[test]
    fn flow_event_json_shape() {
        let ev = FlowEvent::new(
            "2026-01-01T00:00:00.000000Z".to_owned(),
            "drop".to_owned(),
            "egress".to_owned(),
            "tcp".to_owned(),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)),
            Some(12345),
            Some(443),
            "web".to_owned(),
            Some("db".to_owned()),
        );
        let json = serde_json::to_string(&ev).unwrap();
        assert!(
            json.contains(r#""event":"suho_flow""#),
            "missing event in {json}"
        );
        assert!(
            json.contains(r#""verdict":"drop""#),
            "missing verdict in {json}"
        );
        assert!(json.contains(r#""dir":"egress""#), "missing dir in {json}");
        assert!(
            json.contains(r#""container":"web""#),
            "missing container in {json}"
        );
        assert!(json.contains(r#""peer":"db""#), "missing peer in {json}");
        assert!(json.contains(r#""sport":12345"#), "missing sport in {json}");
        assert!(json.contains(r#""dport":443"#), "missing dport in {json}");
        assert!(
            json.contains(r#""ts":"2026-01-01T00:00:00.000000Z""#),
            "missing ts in {json}"
        );
    }

    #[test]
    fn flow_event_omits_peer_when_none() {
        let ev = FlowEvent::new(
            "2026-01-01T00:00:00.000000Z".to_owned(),
            "drop".to_owned(),
            "egress".to_owned(),
            "tcp".to_owned(),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)),
            Some(12345),
            Some(443),
            "web".to_owned(),
            None,
        );
        let json = serde_json::to_string(&ev).unwrap();
        assert!(!json.contains("peer"), "{json}");
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

    fn build_ipv6_udp() -> Vec<u8> {
        use etherparse::{Ipv6FlowLabel, Ipv6Header, UdpHeader, ip_number};
        let ip = Ipv6Header {
            traffic_class: 0,
            flow_label: Ipv6FlowLabel::ZERO,
            payload_length: 8,
            next_header: ip_number::UDP,
            hop_limit: 64,
            source: [0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2],
            destination: [0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5],
        };
        let udp = UdpHeader::without_ipv4_checksum(54321, 53, 8).unwrap();
        let mut buf = Vec::new();
        ip.write(&mut buf).unwrap();
        udp.write(&mut buf).unwrap();
        buf
    }
}
