// SPDX-License-Identifier: GPL-3.0-or-later
//! The compiled desired state: named identity sets plus the ordered rules for
//! suho's `suho_egress` and `suho_ingress` chains. Produced by
//! [`crate::reconcile`], consumed by the [`super::Enforcer`] backends; rebuilt
//! from scratch every reconcile (stateless; see `docs/architecture.md`).

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::net::IpAddr;
use std::str::FromStr;

use crate::api::v1alpha1::Port;

/// Named identity sets plus the ordered rules for suho's two policy chains.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Ruleset {
    /// Named sets (`net_<network>`) → member addresses,
    /// referenced by rules via a lookup.
    pub sets: BTreeMap<String, BTreeSet<IpAddr>>,
    /// Rules for the `suho_egress` chain (source-side checks).
    pub egress: Vec<Rule>,
    /// Rules for the `suho_ingress` chain (destination-side checks).
    pub ingress: Vec<Rule>,
}

/// A single rule in suho's `forward` chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rule {
    /// Context for logs and nft comments (e.g. `web/db-access egress`).
    pub comment: String,
    /// Source-address match.
    pub saddr: Match,
    /// Destination-address match.
    pub daddr: Match,
    /// L4 ports (empty = any protocol/port).
    pub ports: Vec<Port>,
    /// Terminal verdict.
    pub verdict: Verdict,
}

/// An address matcher for `ip saddr` / `ip daddr`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Match {
    /// No constraint.
    Any,
    /// An explicit set of addresses (rendered as an anonymous set).
    Addrs(BTreeSet<IpAddr>),
    /// A reference to a named [`Ruleset::sets`] entry (`@<name>`).
    Set(String),
    /// A CIDR block, optionally excluding sub-blocks (≈ `ipBlock.except`).
    Cidr { cidr: Cidr, except: Vec<Cidr> },
}

/// An IPv4 CIDR block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cidr {
    pub addr: IpAddr,
    pub prefix: u8,
}

impl FromStr for Cidr {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (addr, prefix) = s
            .split_once('/')
            .ok_or_else(|| format!("missing '/' in CIDR {s:?}"))?;
        let addr: IpAddr = addr
            .parse()
            .map_err(|_| format!("invalid CIDR address {addr:?}"))?;
        let prefix: u8 = prefix
            .parse()
            .map_err(|_| format!("invalid CIDR prefix {prefix:?}"))?;
        let max = if addr.is_ipv6() { 128 } else { 32 };
        if prefix > max {
            return Err(format!("CIDR prefix out of range: {prefix}"));
        }
        Ok(Self { addr, prefix })
    }
}

/// Rule verdict: `Return` passes the packet to the next chain, `Drop` denies it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Return,
    Drop,
}

impl fmt::Display for Match {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Any => f.write_str("any"),
            Self::Addrs(addrs) => {
                let list: Vec<String> = addrs.iter().map(ToString::to_string).collect();
                write!(f, "{{{}}}", list.join(", "))
            }
            Self::Set(name) => write!(f, "@{name}"),
            Self::Cidr { cidr, except } => {
                write!(f, "{}/{}", cidr.addr, cidr.prefix)?;
                for ex in except {
                    write!(f, " != {}/{}", ex.addr, ex.prefix)?;
                }
                Ok(())
            }
        }
    }
}

impl Match {
    /// nft address-family keyword for this match: `ip6` when it is
    /// unambiguously IPv6-only, otherwise `ip`.
    fn family_prefix(&self) -> &'static str {
        let v6 = match self {
            Self::Addrs(addrs) => !addrs.is_empty() && addrs.iter().all(IpAddr::is_ipv6),
            Self::Cidr { cidr, .. } => cidr.addr.is_ipv6(),
            Self::Any | Self::Set(_) => false,
        };
        if v6 { "ip6" } else { "ip" }
    }
}

impl fmt::Display for Verdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Return => "return",
            Self::Drop => "drop",
        })
    }
}

impl fmt::Display for Rule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}]", self.comment)?;
        if !matches!(self.saddr, Match::Any) {
            write!(f, " {} saddr {}", self.saddr.family_prefix(), self.saddr)?;
        }
        if !matches!(self.daddr, Match::Any) {
            write!(f, " {} daddr {}", self.daddr.family_prefix(), self.daddr)?;
        }
        if !self.ports.is_empty() {
            let ports: Vec<String> = self.ports.iter().map(ToString::to_string).collect();
            write!(f, " ports {{{}}}", ports.join(", "))?;
        }
        write!(f, " {}", self.verdict)
    }
}

impl fmt::Display for Ruleset {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (name, addrs) in &self.sets {
            let members: Vec<String> = addrs.iter().map(ToString::to_string).collect();
            writeln!(f, "set {name} = {{{}}}", members.join(", "))?;
        }
        if !self.egress.is_empty() {
            writeln!(f, "chain suho_egress:")?;
            for rule in &self.egress {
                writeln!(f, "  {rule}")?;
            }
        }
        if !self.ingress.is_empty() {
            writeln!(f, "chain suho_ingress:")?;
            for rule in &self.ingress {
                writeln!(f, "  {rule}")?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_ipv6_with_ip6_prefix() {
        let rule = Rule {
            comment: "t".to_owned(),
            saddr: Match::Cidr {
                cidr: "fd00::/8".parse().unwrap(),
                except: vec![],
            },
            daddr: Match::Any,
            ports: vec![],
            verdict: Verdict::Drop,
        };
        let rendered = rule.to_string();
        assert!(rendered.contains("ip6 saddr"), "{rendered}");
    }

    #[test]
    fn renders_ipv4_with_ip_prefix() {
        let rule = Rule {
            comment: "t".to_owned(),
            saddr: Match::Cidr {
                cidr: "10.0.0.0/8".parse().unwrap(),
                except: vec![],
            },
            daddr: Match::Any,
            ports: vec![],
            verdict: Verdict::Return,
        };
        let rendered = rule.to_string();
        assert!(
            rendered.contains("ip saddr") && !rendered.contains("ip6"),
            "{rendered}"
        );
    }
}
