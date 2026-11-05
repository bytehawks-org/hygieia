//! Minimal IP network type (`192.168.0.0/16`, `2001:db8::/32`) used for trusted proxies and
//! registered client networks. `std::net` only, so it stays WASM-compatible.

use std::net::IpAddr;
use std::str::FromStr;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Cidr {
    ip: IpAddr,
    prefix: u8,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[error("invalid network {0:?}: expected ADDRESS/PREFIX")]
pub struct CidrError(pub String);

impl Cidr {
    pub fn new(ip: IpAddr, prefix: u8) -> Result<Self, CidrError> {
        let max = if ip.is_ipv4() { 32 } else { 128 };
        if prefix > max {
            return Err(CidrError(format!("{ip}/{prefix}")));
        }
        Ok(Self {
            ip: mask(ip, prefix),
            prefix,
        })
    }

    pub fn prefix(&self) -> u8 {
        self.prefix
    }

    /// Can a tenant register this network as "my clients"? Guards against turning the service into
    /// an open resolver: a private block may be registered as a whole (`10.0.0.0/8`), but anything
    /// else must be small (IPv4 public: at least a /24; IPv6 public: at least a /48; IPv6 ULA a /32).
    pub fn registrable(&self) -> Result<(), String> {
        const V4_PRIVATE: [(&str, u8); 6] = [
            ("10.0.0.0", 8),
            ("172.16.0.0", 12),
            ("192.168.0.0", 16),
            ("100.64.0.0", 10),
            ("169.254.0.0", 16),
            ("127.0.0.0", 8),
        ];
        let min = match self.ip {
            IpAddr::V4(_) => V4_PRIVATE
                .iter()
                .find(|(a, p)| {
                    Cidr::new(a.parse().unwrap(), *p)
                        .is_ok_and(|b| b.contains(self.ip) && self.prefix >= *p)
                })
                .map_or(24, |(_, p)| *p),
            IpAddr::V6(_) => {
                let ula = Cidr::new("fc00::".parse().unwrap(), 7).unwrap();
                let ll = Cidr::new("fe80::".parse().unwrap(), 10).unwrap();
                if self.prefix >= 7 && ula.contains(self.ip) {
                    32
                } else if self.prefix >= 10 && ll.contains(self.ip) {
                    64
                } else {
                    48
                }
            }
        };
        if self.prefix < min {
            return Err(format!(
                "{self} is too broad to register: use /{min} or longer"
            ));
        }
        Ok(())
    }

    pub fn contains(&self, other: IpAddr) -> bool {
        // An IPv4-mapped IPv6 peer (::ffff:a.b.c.d) is matched as IPv4.
        let other = match other {
            IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(other, IpAddr::V4),
            v4 => v4,
        };
        self.ip.is_ipv4() == other.is_ipv4() && mask(other, self.prefix) == self.ip
    }
}

fn mask(ip: IpAddr, prefix: u8) -> IpAddr {
    match ip {
        IpAddr::V4(v) => {
            let m = if prefix == 0 {
                0
            } else {
                u32::MAX << (32 - prefix)
            };
            IpAddr::V4((u32::from(v) & m).into())
        }
        IpAddr::V6(v) => {
            let m = if prefix == 0 {
                0
            } else {
                u128::MAX << (128 - prefix)
            };
            IpAddr::V6((u128::from(v) & m).into())
        }
    }
}

impl FromStr for Cidr {
    type Err = CidrError;
    fn from_str(s: &str) -> Result<Self, CidrError> {
        let bad = || CidrError(s.to_string());
        let (ip, prefix) = match s.split_once('/') {
            Some((a, p)) => (
                a.parse::<IpAddr>().map_err(|_| bad())?,
                p.parse::<u8>().map_err(|_| bad())?,
            ),
            None => {
                let ip = s.parse::<IpAddr>().map_err(|_| bad())?;
                (ip, if ip.is_ipv4() { 32 } else { 128 })
            }
        };
        Cidr::new(ip, prefix).map_err(|_| bad())
    }
}

impl std::fmt::Display for Cidr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.ip, self.prefix)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn c(s: &str) -> Cidr {
        s.parse().unwrap()
    }
    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn contains_and_normalises() {
        assert!(c("192.168.0.0/16").contains(ip("192.168.7.9")));
        assert!(!c("192.168.0.0/16").contains(ip("192.169.0.1")));
        assert_eq!(
            c("192.168.5.7/16").to_string(),
            "192.168.0.0/16",
            "host bits are cleared"
        );
        assert!(c("0.0.0.0/0").contains(ip("8.8.8.8")));
        assert!(!c("0.0.0.0/0").contains(ip("::1")), "families do not mix");
        assert!(c("10.1.2.3").contains(ip("10.1.2.3")) && !c("10.1.2.3").contains(ip("10.1.2.4")));
        assert!(c("2001:db8::/32").contains(ip("2001:db8:1::5")));
        assert!(!c("2001:db8::/32").contains(ip("2001:db9::1")));
        assert!(
            c("192.168.0.0/16").contains(ip("::ffff:192.168.1.1")),
            "v4-mapped peers match v4 networks"
        );
    }

    #[test]
    fn registrable_blocks_open_resolver_footguns() {
        for ok in [
            "10.0.0.0/8",
            "192.168.1.0/24",
            "172.16.0.0/12",
            "203.0.113.0/24",
            "203.0.113.7/32",
            "2001:db8:1::/48",
            "2001:db8:1:2::/64",
            "fd00::/32",
            "fd12:3456::/48",
        ] {
            assert!(c(ok).registrable().is_ok(), "{ok}");
        }
        for bad in [
            "0.0.0.0/0",
            "8.0.0.0/8",
            "203.0.0.0/16",
            "172.0.0.0/8",
            "11.0.0.0/8",
            "::/0",
            "2001:db8::/32",
            "fc00::/16",
            "fe80::/10",
        ] {
            assert!(c(bad).registrable().is_err(), "{bad}");
        }
        assert!(c("fe80::/64").registrable().is_ok());
    }

    #[test]
    fn rejects_garbage() {
        for bad in [
            "",
            "1.2.3.4/33",
            "::1/129",
            "1.2.3/24",
            "a.b.c.d/8",
            "1.2.3.4/x",
            "/8",
        ] {
            assert!(bad.parse::<Cidr>().is_err(), "{bad}");
        }
    }
}
