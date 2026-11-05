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
