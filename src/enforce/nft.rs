// SPDX-License-Identifier: GPL-3.0-or-later
//! nftables backend: programs suho's own `inet suho` table via `rustables`
//! (direct netlink; no `nft` binary). Every apply atomically replaces the whole
//! table (see `docs/architecture.md`), so orphaned rules never survive a reconcile.
//!
//! Kubernetes checks egress and ingress independently, so the base `forward`
//! chain jumps through two regular chains — `suho_egress` then `suho_ingress`.
//! Each stage `return`s on an allowed match and `drop`s a governed container's
//! unmatched traffic; a packet is accepted only if it clears both stages and
//! falls through to the chain's `accept` policy. Identity sets are real kernel
//! sets (`net_<network>`) referenced by a lookup.

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use anyhow::{Context, Result, anyhow};
use ipnetwork::{IpNetwork, Ipv4Network, Ipv6Network};
use rustables::expr::{
    Bitwise, Cmp, CmpOp, ConnTrackState, Conntrack, ConntrackKey, HighLevelPayload,
    IPv4HeaderField, IPv6HeaderField, Immediate, Lookup, Meta, MetaType, NetworkHeaderField,
    TCPHeaderField, TransportHeaderField, UDPHeaderField, VerdictKind,
};
use rustables::set::SetBuilder;
use rustables::{
    Batch, Chain, ChainPolicy, Hook, HookClass, MsgType, Protocol, ProtocolFamily, Rule as NftRule,
    Set, Table,
};
use tracing::info;

use super::{Cidr, Enforcer, Match, Rule, Ruleset, Verdict};
use crate::api::v1alpha1::{Port, Protocol as PolicyProto};

/// nftables family guard value for IPv4 (`NFPROTO_IPV4`).
const NFPROTO_IPV4: u8 = 2;
/// nftables family guard value for IPv6 (`NFPROTO_IPV6`).
const NFPROTO_IPV6: u8 = 10;

/// IP address family — nftables sets and matches are single-family.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[cfg_attr(test, derive(Debug))]
enum Family {
    V4,
    V6,
}

impl Family {
    fn of(ip: &IpAddr) -> Self {
        if ip.is_ipv6() { Self::V6 } else { Self::V4 }
    }

    fn nfproto(self) -> u8 {
        match self {
            Self::V4 => NFPROTO_IPV4,
            Self::V6 => NFPROTO_IPV6,
        }
    }

    /// The `ip {s,d}addr` payload load for this family.
    fn addr_payload(self, source: bool) -> HighLevelPayload {
        match self {
            Self::V4 => HighLevelPayload::Network(NetworkHeaderField::IPv4(if source {
                IPv4HeaderField::Saddr
            } else {
                IPv4HeaderField::Daddr
            })),
            Self::V6 => HighLevelPayload::Network(NetworkHeaderField::IPv6(if source {
                IPv6HeaderField::Saddr
            } else {
                IPv6HeaderField::Daddr
            })),
        }
    }
}

/// The `ipnetwork` value for a CIDR, tagged by family.
fn ip_network(cidr: &Cidr) -> Result<IpNetwork> {
    Ok(match cidr.addr {
        IpAddr::V4(a) => IpNetwork::V4(Ipv4Network::new(a, cidr.prefix).context("invalid CIDR")?),
        IpAddr::V6(a) => IpNetwork::V6(Ipv6Network::new(a, cidr.prefix).context("invalid CIDR")?),
    })
}

/// Big-endian address bytes (4 for v4, 16 for v6).
fn addr_bytes(ip: IpAddr) -> Vec<u8> {
    match ip {
        IpAddr::V4(a) => a.octets().to_vec(),
        IpAddr::V6(a) => a.octets().to_vec(),
    }
}
/// suho's own table; nothing outside it is ever touched.
const TABLE: &str = "suho";
/// Base chain, just ahead of Docker's filter FORWARD (priority 0).
const CHAIN: &str = "forward";
const EGRESS_CHAIN: &str = "suho_egress";
const INGRESS_CHAIN: &str = "suho_ingress";
const PRIORITY: i32 = -5;

/// Programs the desired ruleset into `inet suho` via netlink. Requires
/// `CAP_NET_ADMIN` (root); [`apply`](Self::apply) fails otherwise.
pub struct NftEnforcer;

impl Enforcer for NftEnforcer {
    fn apply(&mut self, ruleset: &Ruleset) -> Result<()> {
        let table = Table::new(ProtocolFamily::Inet).with_name(TABLE);
        let mut batch = Batch::new();

        // Atomic replace: ensure the table exists, delete it (cascading its
        // sets/chains/rules), then rebuild — all in one kernel transaction.
        batch.add(&table, MsgType::Add);
        batch.add(&table, MsgType::Del);
        batch.add(&table, MsgType::Add);

        // Named sets. Each needs a unique, non-zero NFTA_SET_ID and the table's
        // family (SetBuilder leaves it Unspec), or the kernel rejects NEWSET.
        // nftables sets are single-family, so each network set is split into a
        // v4 and/or v6 set (unique nft names; keyed by (name, family) here).
        let mut sets: BTreeMap<(String, Family), Set> = BTreeMap::new();
        let mut set_id: u32 = 0;
        for (name, addrs) in &ruleset.sets {
            let v4: Vec<Ipv4Addr> = addrs
                .iter()
                .filter_map(|a| {
                    if let IpAddr::V4(x) = a {
                        Some(*x)
                    } else {
                        None
                    }
                })
                .collect();
            let v6: Vec<Ipv6Addr> = addrs
                .iter()
                .filter_map(|a| {
                    if let IpAddr::V6(x) = a {
                        Some(*x)
                    } else {
                        None
                    }
                })
                .collect();
            if !v4.is_empty() {
                set_id += 1;
                let mut builder = SetBuilder::<Ipv4Addr>::new(name.clone(), &table)
                    .with_context(|| format!("building set {name}"))?;
                for a in &v4 {
                    builder.add(a);
                }
                let (set, elements) = builder.finish();
                let mut set = set.with_id(set_id);
                set.family = ProtocolFamily::Inet;
                batch.add(&set, MsgType::Add);
                batch.add(&elements, MsgType::Add);
                sets.insert((name.clone(), Family::V4), set);
            }
            if !v6.is_empty() {
                set_id += 1;
                let mut builder = SetBuilder::<Ipv6Addr>::new(format!("{name}_6"), &table)
                    .with_context(|| format!("building set {name}_6"))?;
                for a in &v6 {
                    builder.add(a);
                }
                let (set, elements) = builder.finish();
                let mut set = set.with_id(set_id);
                set.family = ProtocolFamily::Inet;
                batch.add(&set, MsgType::Add);
                batch.add(&elements, MsgType::Add);
                sets.insert((name.clone(), Family::V6), set);
            }
        }

        // Two regular stage chains plus the base chain that jumps through them.
        let egress_chain = Chain::new(&table).with_name(EGRESS_CHAIN);
        let ingress_chain = Chain::new(&table).with_name(INGRESS_CHAIN);
        let forward = Chain::new(&table)
            .with_name(CHAIN)
            .with_hook(Hook::new(HookClass::Forward, PRIORITY))
            .with_policy(ChainPolicy::Accept);
        batch.add(&egress_chain, MsgType::Add);
        batch.add(&ingress_chain, MsgType::Add);
        batch.add(&forward, MsgType::Add);

        for rule in &ruleset.egress {
            for nft_rule in expand(rule, &egress_chain, &sets)? {
                batch.add(&nft_rule, MsgType::Add);
            }
        }
        for rule in &ruleset.ingress {
            for nft_rule in expand(rule, &ingress_chain, &sets)? {
                batch.add(&nft_rule, MsgType::Add);
            }
        }
        // Stateful shortcut: reply traffic of tracked flows bypasses policy
        // (Kubernetes NetworkPolicy is stateful). Must precede the stage jumps.
        batch.add(&conntrack_established_accept(&forward)?, MsgType::Add);
        batch.add(&jump(&forward, EGRESS_CHAIN)?, MsgType::Add);
        batch.add(&jump(&forward, INGRESS_CHAIN)?, MsgType::Add);

        // `QueryError`'s Display hides the kernel errno inside `nlmsgerr`; its
        // Debug form surfaces it (e.g. `error: 22` = EINVAL).
        batch
            .send()
            .map_err(|err| anyhow!("applying nftables ruleset: {err:?}"))?;
        info!(
            sets = ruleset.sets.len(),
            egress = ruleset.egress.len(),
            ingress = ruleset.ingress.len(),
            "applied nftables ruleset to table inet {TABLE}"
        );
        Ok(())
    }
}

/// `ct state established,related accept`: reply traffic of tracked flows bypasses
/// policy, so bidirectional flows work when both ends are isolated (Kubernetes
/// NetworkPolicy is stateful). Placed ahead of the stage jumps in `forward`.
fn conntrack_established_accept(chain: &Chain) -> Result<NftRule> {
    let mut rule = NftRule::new(chain).context("creating conntrack rule")?;
    rule.add_expr(Conntrack::new(ConntrackKey::State));
    let mask = (ConnTrackState::ESTABLISHED | ConnTrackState::RELATED).bits();
    rule.add_expr(Bitwise::new(mask.to_ne_bytes(), 0u32.to_ne_bytes()).context("ct state mask")?);
    rule.add_expr(Cmp::new(CmpOp::Neq, 0u32.to_ne_bytes()));
    rule.add_expr(Immediate::new_verdict(VerdictKind::Accept));
    Ok(rule)
}

/// One matcher on a rule side.
#[cfg_attr(test, derive(Debug, PartialEq))]
enum Side {
    Any,
    Addr(IpAddr),
    Set(String),
    Cidr { cidr: Cidr, except: Vec<Cidr> },
}

fn sides(m: &Match) -> Vec<Side> {
    match m {
        Match::Any => vec![Side::Any],
        Match::Addrs(addrs) => addrs.iter().map(|a| Side::Addr(*a)).collect(),
        Match::Set(name) => vec![Side::Set(name.clone())],
        Match::Cidr { cidr, except } => vec![Side::Cidr {
            cidr: *cidr,
            except: except.clone(),
        }],
    }
}

/// Expand one IR rule into concrete nft rules in `chain` — the cartesian product
/// over source/destination matchers and ports (a set reference stays a single
/// matcher via a lookup).
fn expand(
    rule: &Rule,
    chain: &Chain,
    sets: &BTreeMap<(String, Family), Set>,
) -> Result<Vec<NftRule>> {
    let ports: Vec<Option<&Port>> = if rule.ports.is_empty() {
        vec![None]
    } else {
        rule.ports.iter().map(Some).collect()
    };
    let srcs = sides(&rule.saddr);
    let dsts = sides(&rule.daddr);

    let mut out = Vec::new();
    for src in &srcs {
        for dst in &dsts {
            for family in emit_families(src, dst, sets) {
                for port in ports.iter().copied() {
                    let mut r = NftRule::new(chain).context("creating nft rule")?;
                    r = apply_side(r, src, sets, family, true)?;
                    r = apply_side(r, dst, sets, family, false)?;
                    if let Some(port) = port {
                        r = apply_port(r, port);
                    }
                    let verdict = match rule.verdict {
                        Verdict::Return => VerdictKind::Return,
                        Verdict::Drop => VerdictKind::Drop,
                    };
                    r.add_expr(Immediate::new_verdict(verdict));
                    out.push(r);
                }
            }
        }
    }
    Ok(out)
}

/// Families to emit a rule for, given one source and one destination matcher.
/// A concrete side (address/CIDR) pins the family; set/any sides adapt. A
/// cross-family pair (v4 source, v6 destination) yields nothing. Set sides are
/// kept only for families that actually have members.
fn emit_families(src: &Side, dst: &Side, sets: &BTreeMap<(String, Family), Set>) -> Vec<Family> {
    let candidates = match (side_family(src), side_family(dst)) {
        (Some(a), Some(b)) if a == b => vec![a],
        (Some(_), Some(_)) => vec![],
        (Some(a), None) | (None, Some(a)) => vec![a],
        (None, None) => vec![Family::V4, Family::V6],
    };
    candidates
        .into_iter()
        .filter(|f| set_ok(src, *f, sets) && set_ok(dst, *f, sets))
        .collect()
}

/// The family a matcher is pinned to, if any (set/any sides are unpinned).
fn side_family(side: &Side) -> Option<Family> {
    match side {
        Side::Addr(ip) => Some(Family::of(ip)),
        Side::Cidr { cidr, .. } => Some(Family::of(&cidr.addr)),
        Side::Any | Side::Set(_) => None,
    }
}

/// Whether a set side has members in `family` (always true for non-set sides).
fn set_ok(side: &Side, family: Family, sets: &BTreeMap<(String, Family), Set>) -> bool {
    match side {
        Side::Set(name) => sets.contains_key(&(name.clone(), family)),
        _ => true,
    }
}

/// A `jump <target>` rule in `chain`.
fn jump(chain: &Chain, target: &str) -> Result<NftRule> {
    let mut rule = NftRule::new(chain).context("creating jump rule")?;
    rule.add_expr(Immediate::new_verdict(VerdictKind::Jump {
        chain: target.to_owned(),
    }));
    Ok(rule)
}

fn apply_side(
    rule: NftRule,
    side: &Side,
    sets: &BTreeMap<(String, Family), Set>,
    family: Family,
    source: bool,
) -> Result<NftRule> {
    Ok(match side {
        Side::Any => rule,
        Side::Addr(ip) => {
            if source {
                rule.saddr(*ip)
            } else {
                rule.daddr(*ip)
            }
        }
        Side::Cidr { cidr, except } => {
            let net = ip_network(cidr)?;
            let mut rule = if source {
                rule.snetwork(net).context("source network match")?
            } else {
                rule.dnetwork(net).context("destination network match")?
            };
            for ex in except {
                rule = network_neq(rule, ex, source)?;
            }
            rule
        }
        Side::Set(name) => {
            let set = sets
                .get(&(name.clone(), family))
                .with_context(|| format!("rule references unknown set {name}"))?;
            lookup_set(rule, set, family, source)?
        }
    })
}

/// `ip {s,d}addr @set` match: inet family guard + payload load + set lookup
/// (rustables has no high-level named-set match).
fn lookup_set(mut rule: NftRule, set: &Set, family: Family, source: bool) -> Result<NftRule> {
    rule.add_expr(Meta::new(MetaType::NfProto));
    rule.add_expr(Cmp::new(CmpOp::Eq, [family.nfproto()]));
    rule.add_expr(family.addr_payload(source).build());
    rule.add_expr(Lookup::new(set).context("set lookup")?);
    Ok(rule)
}

/// `ip {s,d}addr != <cidr>`: exclude a sub-block (ipBlock.except). Mirrors
/// rustables' network match but with a not-equal comparison on the same field.
fn network_neq(mut rule: NftRule, cidr: &Cidr, source: bool) -> Result<NftRule> {
    let net = ip_network(cidr)?;
    let family = Family::of(&cidr.addr);
    let mask = addr_bytes(net.mask());
    let zero = vec![0u8; mask.len()];
    rule.add_expr(Meta::new(MetaType::NfProto));
    rule.add_expr(Cmp::new(CmpOp::Eq, [family.nfproto()]));
    rule.add_expr(family.addr_payload(source).build());
    rule.add_expr(Bitwise::new(mask, zero).context("except mask")?);
    rule.add_expr(Cmp::new(CmpOp::Neq, addr_bytes(net.network())));
    Ok(rule)
}

fn apply_port(rule: NftRule, port: &Port) -> NftRule {
    let proto = match port.protocol {
        PolicyProto::Tcp => Protocol::TCP,
        PolicyProto::Udp => Protocol::UDP,
    };
    match (port.number, port.end) {
        (None, _) => rule.protocol(proto),
        (Some(number), None) => rule.dport(number, proto),
        (Some(start), Some(end)) => dport_range(rule, start, end, proto),
    }
}

/// `dport start-end`: rustables has no high-level range, so load the transport
/// destination-port payload once and bound it with two comparisons on the same
/// register — how nft compiles a range internally.
fn dport_range(mut rule: NftRule, start: u16, end: u16, proto: Protocol) -> NftRule {
    rule = rule.protocol(proto);
    let field = match proto {
        Protocol::TCP => TransportHeaderField::Tcp(TCPHeaderField::Dport),
        Protocol::UDP => TransportHeaderField::Udp(UDPHeaderField::Dport),
    };
    rule.add_expr(HighLevelPayload::Transport(field).build());
    rule.add_expr(Cmp::new(CmpOp::Gte, start.to_be_bytes()));
    rule.add_expr(Cmp::new(CmpOp::Lte, end.to_be_bytes()));
    rule
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::net::{IpAddr, Ipv4Addr};
    use std::process::Command;

    use rustables::set::SetBuilder;
    use rustables::{Chain, ProtocolFamily, Set, Table};

    use super::{Family, Side, expand, jump, sides};
    use crate::api::v1alpha1::Port;
    use crate::enforce::{Cidr, Enforcer, Match, Rule, Ruleset, Verdict};

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn addrs(list: &[&str]) -> std::collections::BTreeSet<IpAddr> {
        list.iter().copied().map(ip).collect()
    }

    fn port(s: &str) -> Port {
        s.parse().unwrap()
    }

    fn table_chain() -> (Table, Chain) {
        let table = Table::new(ProtocolFamily::Inet).with_name("suho");
        let chain = Chain::new(&table).with_name("suho_egress");
        (table, chain)
    }

    fn named_set(table: &Table, name: &str, members: &[&str]) -> Set {
        let mut builder = SetBuilder::<Ipv4Addr>::new(name.to_owned(), table).unwrap();
        for m in members {
            builder.add(&m.parse::<Ipv4Addr>().unwrap());
        }
        builder.finish().0.with_id(1u32)
    }

    #[test]
    fn sides_addrs_one_per_ip_sorted() {
        let m = Match::Addrs(addrs(&["10.0.0.9", "10.0.0.5"]));
        assert_eq!(
            sides(&m),
            vec![Side::Addr(ip("10.0.0.5")), Side::Addr(ip("10.0.0.9"))]
        );
    }

    #[test]
    fn sides_set_is_a_single_reference() {
        assert_eq!(
            sides(&Match::Set("net_db".to_owned())),
            vec![Side::Set("net_db".to_owned())]
        );
    }

    #[test]
    fn sides_any_and_cidr() {
        assert_eq!(sides(&Match::Any), vec![Side::Any]);
        let cidr: Cidr = "0.0.0.0/0".parse().unwrap();
        assert_eq!(
            sides(&Match::Cidr {
                cidr,
                except: vec![]
            }),
            vec![Side::Cidr {
                cidr,
                except: vec![]
            }]
        );
    }

    #[test]
    fn expand_set_is_one_rule_per_port() {
        // saddr 1 ip × daddr @set (one lookup) × ports{2} = 2 rules
        let (table, chain) = table_chain();
        let sets = BTreeMap::from([(
            ("g".to_owned(), Family::V4),
            named_set(&table, "g", &["10.0.0.5"]),
        )]);
        let rule = Rule {
            comment: "t".to_owned(),
            saddr: Match::Addrs(addrs(&["10.0.0.2"])),
            daddr: Match::Set("g".to_owned()),
            ports: vec![port("443/tcp"), port("80/tcp")],
            verdict: Verdict::Return,
        };
        assert_eq!(expand(&rule, &chain, &sets).unwrap().len(), 2);
    }

    #[test]
    fn expand_default_deny_one_rule_per_source_ip() {
        // saddr {2 ips} × daddr Any × no ports = 2 rules
        let (_table, chain) = table_chain();
        let rule = Rule {
            comment: "t".to_owned(),
            saddr: Match::Addrs(addrs(&["10.0.0.2", "10.0.0.3"])),
            daddr: Match::Any,
            ports: Vec::new(),
            verdict: Verdict::Drop,
        };
        assert_eq!(expand(&rule, &chain, &BTreeMap::new()).unwrap().len(), 2);
    }

    #[test]
    fn expand_port_range_is_one_rule() {
        // A range is a single matcher → one rule, not one per port.
        let (_table, chain) = table_chain();
        let rule = Rule {
            comment: "t".to_owned(),
            saddr: Match::Addrs(addrs(&["10.0.0.2"])),
            daddr: Match::Any,
            ports: vec![port("32000-32768/tcp")],
            verdict: Verdict::Return,
        };
        assert_eq!(expand(&rule, &chain, &BTreeMap::new()).unwrap().len(), 1);
    }

    #[test]
    fn expand_cidr_except_is_one_rule() {
        // cidr + except → one rule (positive network + negated sub-blocks).
        let (_table, chain) = table_chain();
        let rule = Rule {
            comment: "t".to_owned(),
            saddr: Match::Addrs(addrs(&["10.0.0.2"])),
            daddr: Match::Cidr {
                cidr: "0.0.0.0/0".parse().unwrap(),
                except: vec!["10.0.0.0/8".parse().unwrap()],
            },
            ports: Vec::new(),
            verdict: Verdict::Return,
        };
        assert_eq!(expand(&rule, &chain, &BTreeMap::new()).unwrap().len(), 1);
    }

    #[test]
    fn expand_unknown_set_yields_no_rule() {
        // A set with no members in the packet's family produces no rule.
        let (_table, chain) = table_chain();
        let rule = Rule {
            comment: "t".to_owned(),
            saddr: Match::Addrs(addrs(&["10.0.0.2"])),
            daddr: Match::Set("absent".to_owned()),
            ports: Vec::new(),
            verdict: Verdict::Return,
        };
        assert!(expand(&rule, &chain, &BTreeMap::new()).unwrap().is_empty());
    }

    #[test]
    fn jump_builds_a_rule() {
        let (_table, chain) = table_chain();
        assert!(jump(&chain, "suho_ingress").is_ok());
    }

    #[test]
    fn conntrack_rule_builds() {
        let (_table, chain) = table_chain();
        assert!(super::conntrack_established_accept(&chain).is_ok());
    }

    #[test]
    fn expand_cross_family_yields_nothing() {
        // v4 source, v6 destination CIDR: no packet can match, so no rule.
        let (_table, chain) = table_chain();
        let rule = Rule {
            comment: "t".to_owned(),
            saddr: Match::Addrs(addrs(&["10.0.0.2"])),
            daddr: Match::Cidr {
                cidr: "2001:db8::/32".parse().unwrap(),
                except: vec![],
            },
            ports: Vec::new(),
            verdict: Verdict::Return,
        };
        assert!(expand(&rule, &chain, &BTreeMap::new()).unwrap().is_empty());
    }

    #[test]
    fn expand_v6_cidr_is_one_rule() {
        let (_table, chain) = table_chain();
        let rule = Rule {
            comment: "t".to_owned(),
            saddr: Match::Addrs(addrs(&["fd00::2"])),
            daddr: Match::Cidr {
                cidr: "::/0".parse().unwrap(),
                except: vec!["fd00::/8".parse().unwrap()],
            },
            ports: vec![port("443/tcp")],
            verdict: Verdict::Return,
        };
        assert_eq!(expand(&rule, &chain, &BTreeMap::new()).unwrap().len(), 1);
    }

    /// Rootless, sandboxed end-to-end: re-exec this test inside an unprivileged
    /// user+network namespace (`unshare --map-root-user --net`) and program a
    /// representative dual-stack ruleset into that namespace's own nftables — no
    /// root, no effect on the host. Proves the kernel accepts suho's netlink
    /// (encoding, dual-stack sets, cidr/except, port ranges, chains + jumps).
    /// Ignored by default; run with `cargo test -- --ignored`.
    #[test]
    #[ignore = "rootless netns e2e; run with `cargo test -- --ignored`"]
    fn e2e_rootless_netns_apply() {
        // Inner run: already inside the namespace — do the real work.
        if std::env::var_os("SUHO_E2E_INNER").is_some() {
            let mut sets = BTreeMap::new();
            sets.insert("net_demo".to_owned(), addrs(&["10.0.0.5", "fd00::5"]));
            let ruleset = Ruleset {
                sets,
                egress: vec![
                    Rule {
                        comment: "web/egress".to_owned(),
                        saddr: Match::Addrs(addrs(&["10.0.0.2", "fd00::2"])),
                        daddr: Match::Cidr {
                            cidr: "0.0.0.0/0".parse().unwrap(),
                            except: vec!["10.0.0.0/8".parse().unwrap()],
                        },
                        ports: vec![port("443/tcp"), port("32000-32768/tcp")],
                        verdict: Verdict::Return,
                    },
                    Rule {
                        comment: "web/db".to_owned(),
                        saddr: Match::Addrs(addrs(&["10.0.0.2"])),
                        daddr: Match::Set("net_demo".to_owned()),
                        ports: vec![port("5432/tcp")],
                        verdict: Verdict::Return,
                    },
                    Rule {
                        comment: "web egress default-deny".to_owned(),
                        saddr: Match::Addrs(addrs(&["10.0.0.2", "fd00::2"])),
                        daddr: Match::Any,
                        ports: Vec::new(),
                        verdict: Verdict::Drop,
                    },
                ],
                ingress: vec![
                    Rule {
                        comment: "db/in".to_owned(),
                        saddr: Match::Cidr {
                            cidr: "::/0".parse().unwrap(),
                            except: Vec::new(),
                        },
                        daddr: Match::Addrs(addrs(&["fd00::5"])),
                        ports: vec![port("5432/tcp")],
                        verdict: Verdict::Return,
                    },
                    Rule {
                        comment: "db ingress default-deny".to_owned(),
                        saddr: Match::Any,
                        daddr: Match::Addrs(addrs(&["10.0.0.5", "fd00::5"])),
                        ports: Vec::new(),
                        verdict: Verdict::Drop,
                    },
                ],
            };

            let mut enforcer = super::NftEnforcer;
            enforcer
                .apply(&ruleset)
                .expect("kernel accepted the ruleset");
            enforcer
                .apply(&ruleset)
                .expect("kernel accepted the atomic re-apply");

            // If the nft CLI is present, sanity-check the programmed table.
            if let Ok(out) = Command::new("nft")
                .args(["list", "table", "inet", "suho"])
                .output()
            {
                if out.status.success() {
                    let listing = String::from_utf8_lossy(&out.stdout);
                    for needle in ["chain suho_egress", "chain suho_ingress", "@net_demo"] {
                        assert!(
                            listing.contains(needle),
                            "programmed table missing {needle}:\n{listing}"
                        );
                    }
                }
            }
            println!("E2E-INNER-OK");
            return;
        }

        // Outer run: probe for rootless user+net namespaces, then re-exec inside one.
        let available = Command::new("unshare")
            .args(["--user", "--map-root-user", "--net", "true"])
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if !available {
            eprintln!("SKIP: rootless user+net namespaces unavailable on this host");
            return;
        }

        let exe = std::env::current_exe().expect("current test binary");
        let output = Command::new("unshare")
            .args(["--user", "--map-root-user", "--net", "--"])
            .arg(&exe)
            .args([
                "--exact",
                "enforce::nft::tests::e2e_rootless_netns_apply",
                "--ignored",
                "--nocapture",
            ])
            .env("SUHO_E2E_INNER", "1")
            .output()
            .expect("re-exec under unshare");
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            output.status.success() && stdout.contains("E2E-INNER-OK"),
            "rootless netns e2e failed\n--- stdout ---\n{stdout}\n--- stderr ---\n{stderr}"
        );
    }

    /// Rootless, sandboxed **packet-level** e2e: build `A ↔ router ↔ B` with real
    /// veth + routing inside an unprivileged user+mount+net namespace, program
    /// suho's rules in the router, and probe with ICMP. Proves actual DROP/REACH
    /// and — because the allowed flow's reply crosses B's egress default-deny —
    /// that enforcement is stateful. Ignored by default; `cargo test -- --ignored`.
    #[test]
    #[ignore = "rootless packet-level e2e; run with `cargo test -- --ignored`"]
    fn e2e_packet_forward() {
        // Inner run: inside the sandbox — build topology, apply rules, probe.
        if std::env::var_os("SUHO_E2E_FWD_INNER").is_some() {
            let script = [
                "set -e",
                // /run is the host's (not writable by our userns-root); a private
                // tmpfs lets `ip netns` create its bind mounts.
                "mount -t tmpfs tmpfs /run",
                "ip link set lo up",
                "ip netns add A",
                "ip netns add B",
                "ip link add vetha type veth peer name inA",
                "ip link set inA netns A",
                "ip addr add 10.0.0.1/24 dev vetha",
                "ip link set vetha up",
                "ip netns exec A sh -c 'ip link set lo up; ip addr add 10.0.0.2/24 dev inA; ip link set inA up; ip route add default via 10.0.0.1'",
                "ip link add vethb type veth peer name inB",
                "ip link set inB netns B",
                "ip addr add 10.0.1.1/24 dev vethb",
                "ip link set vethb up",
                "ip netns exec B sh -c 'ip link set lo up; ip addr add 10.0.1.2/24 dev inB; ip link set inB up; ip route add default via 10.0.1.1'",
                "sysctl -wq net.ipv4.ip_forward=1",
            ]
            .join("\n");
            assert!(
                Command::new("sh")
                    .arg("-c")
                    .arg(&script)
                    .status()
                    .expect("run topology")
                    .success(),
                "topology setup failed"
            );

            // A may egress to B (any proto); everything else is default-deny. B
            // accepts A but has no egress allow — so B's reply to A only passes
            // if enforcement is stateful (established/related accept).
            let a = addrs(&["10.0.0.2"]);
            let b = addrs(&["10.0.1.2"]);
            let ruleset = Ruleset {
                sets: BTreeMap::new(),
                egress: vec![
                    Rule {
                        comment: "a->b".to_owned(),
                        saddr: Match::Addrs(a.clone()),
                        daddr: Match::Addrs(b.clone()),
                        ports: Vec::new(),
                        verdict: Verdict::Return,
                    },
                    Rule {
                        comment: "a deny".to_owned(),
                        saddr: Match::Addrs(a.clone()),
                        daddr: Match::Any,
                        ports: Vec::new(),
                        verdict: Verdict::Drop,
                    },
                    Rule {
                        comment: "b deny".to_owned(),
                        saddr: Match::Addrs(b.clone()),
                        daddr: Match::Any,
                        ports: Vec::new(),
                        verdict: Verdict::Drop,
                    },
                ],
                ingress: vec![
                    Rule {
                        comment: "b<-a".to_owned(),
                        saddr: Match::Addrs(a.clone()),
                        daddr: Match::Addrs(b.clone()),
                        ports: Vec::new(),
                        verdict: Verdict::Return,
                    },
                    Rule {
                        comment: "b deny in".to_owned(),
                        saddr: Match::Any,
                        daddr: Match::Addrs(b),
                        ports: Vec::new(),
                        verdict: Verdict::Drop,
                    },
                ],
            };
            super::NftEnforcer
                .apply(&ruleset)
                .expect("apply suho ruleset");

            let ping = |ns: &str, ip: &str| {
                Command::new("ip")
                    .args(["netns", "exec", ns, "ping", "-c1", "-W2", ip])
                    .status()
                    .map(|s| s.success())
                    .unwrap_or(false)
            };
            assert!(
                ping("A", "10.0.1.2"),
                "A->B must REACH (allowed + stateful reply)"
            );
            assert!(
                !ping("B", "10.0.0.2"),
                "B->A must BLOCK (B egress default-deny)"
            );
            println!("E2E-FWD-OK");
            return;
        }

        // Outer: need rootless user+mount+net namespaces plus ip/ping present.
        let ns_ok = Command::new("unshare")
            .args(["--user", "--map-root-user", "--mount", "--net", "true"])
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        let tools_ok = Command::new("sh")
            .arg("-c")
            .arg("command -v ip >/dev/null && command -v ping >/dev/null")
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if !ns_ok || !tools_ok {
            eprintln!("SKIP: rootless namespaces or ip/ping unavailable");
            return;
        }

        let exe = std::env::current_exe().expect("current test binary");
        let output = Command::new("unshare")
            .args(["--user", "--map-root-user", "--mount", "--net", "--"])
            .arg(&exe)
            .args([
                "--exact",
                "enforce::nft::tests::e2e_packet_forward",
                "--ignored",
                "--nocapture",
            ])
            .env("SUHO_E2E_FWD_INNER", "1")
            .output()
            .expect("re-exec under unshare");
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            output.status.success() && stdout.contains("E2E-FWD-OK"),
            "packet-level e2e failed\n--- stdout ---\n{stdout}\n--- stderr ---\n{stderr}"
        );
    }
}
