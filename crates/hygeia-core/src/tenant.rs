//! How each component identifies the tenant for a request.
//! Single-org deployments are multi-tenant with N=1 (same code path).

use std::net::IpAddr;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TenantKey<'a> {
    /// `/dns-query/<token>` (DoH)
    DohPath(&'a str),
    /// `<tenant>.dns.example.com` (DoT SNI)
    DotSni(&'a str),
    /// Source address, matched against per-tenant CIDRs by the caller
    SrcIp(IpAddr),
    /// `Proxy-Authorization`
    ProxyAuth(&'a str),
    /// Device credential (`hyg_dev_...`) used by the extension
    ExtToken(&'a str),
}
