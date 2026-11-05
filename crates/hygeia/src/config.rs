//! Every section is optional (`#[serde(default)]`): a 0-line file is valid and
//! all missing values fall back to safe defaults.

use serde::Deserialize;

#[derive(Debug, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub api: ApiConfig,
    pub auth: AuthSection,
    pub dns: DnsSection,
    pub cloud_dns: CloudDnsSection,
    pub tls: TlsSection,
    pub lists: ListsSection,
}

#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum Environment {
    /// Break-glass is refused at startup.
    #[default]
    Production,
    /// Break-glass allowed (explicit secret required).
    Staging,
    /// Break-glass allowed; a throwaway secret is generated if none is given.
    Dev,
}

#[derive(Debug, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct AuthSection {
    pub environment: Environment,
    pub break_glass: BreakGlassSection,
    pub oidc: OidcSection,
}

#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct BreakGlassSection {
    pub enabled: bool,
    /// The credential stops working this many hours after process start (0 = no limit).
    pub ttl_hours: u64,
}
impl Default for BreakGlassSection {
    fn default() -> Self {
        Self {
            enabled: false,
            ttl_hours: 12,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct OidcSection {
    /// Empty = OIDC disabled.
    pub issuer: String,
    pub audience: String,
    /// Public client id used by the admin UI for the authorization-code + PKCE flow
    /// (empty = no SSO button). The UI sends the ID token, so `audience` must be this
    /// client id unless your IdP issues a dedicated audience.
    pub client_id: String,
    /// Extra origins the UI may call (token endpoint when it differs from the issuer origin).
    pub ui_connect_src: Vec<String>,
    pub leeway_secs: u64,
    /// Lab only.
    pub allow_insecure_http: bool,
    /// `sub` claims that are granted the platform-wide `owner` role at startup
    /// (idempotent, additive: removing an entry does not revoke the binding).
    pub bootstrap_owners: Vec<String>,
}
impl Default for OidcSection {
    fn default() -> Self {
        Self {
            issuer: String::new(),
            audience: "hygeia-api".into(),
            client_id: String::new(),
            ui_connect_src: Vec::new(),
            leeway_secs: 30,
            allow_insecure_http: false,
            bootstrap_owners: Vec::new(),
        }
    }
}

pub use hygeia_runtime::ListsSection;

#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ApiConfig {
    pub listen: String,
    /// Built admin UI (Next.js static export). Empty = `HYGEIA_WEB_DIR`, else
    /// `/usr/share/hygeia/web` if it exists, else no UI.
    pub web_dir: String,
    /// Reverse proxies whose `X-Forwarded-For` is trusted for the client address (CIDRs).
    pub trusted_proxies: Vec<String>,
    /// Serve the API and UI over HTTPS using `[tls]` (HSTS is then sent). Off: plain HTTP, put a
    /// TLS-terminating proxy in front.
    pub tls: bool,
    /// Log one line per request with credentials redacted from the path.
    pub access_log: bool,
}
impl Default for ApiConfig {
    fn default() -> Self {
        Self {
            listen: "127.0.0.1:8080".into(),
            web_dir: String::new(),
            trusted_proxies: Vec::new(),
            tls: false,
            access_log: false,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DnsSection {
    pub enabled: bool,
    pub listen: String,
    /// Plain UDP upstreams (`ip:port`). DoT upstream is not implemented yet.
    pub upstream: Vec<String>,
    /// `nxdomain` | `null_ip`
    pub block_mode: String,
}
impl Default for DnsSection {
    fn default() -> Self {
        Self {
            enabled: true,
            listen: "127.0.0.1:5353".into(),
            upstream: vec!["9.9.9.9:53".into()],
            block_mode: "nxdomain".into(),
        }
    }
}

/// Certificate and key (PEM) for HTTPS and DNS-over-TLS. The files are re-read when they change
/// (certbot, cert-manager), no restart needed.
#[derive(Debug, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct TlsSection {
    pub cert: String,
    pub key: String,
}

/// Cloud DNS over HTTPS at `/dns-query/<token>` (SaaS). Off by default. The API speaks plain HTTP:
/// put a TLS-terminating reverse proxy in front and redact the request path in its access logs
/// (the path is a credential).
#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct CloudDnsSection {
    pub enabled: bool,
    /// Recursive resolvers for allowed queries, tried in order with failover. Forms:
    /// `udp://9.9.9.9:53`, `tls://9.9.9.9:853#dns.quad9.net`, `https://dns.quad9.net/dns-query`.
    pub upstreams: Vec<String>,
    /// Single plain-UDP upstream (`ip:port`); kept for compatibility, used only if `upstreams` is empty.
    pub upstream: String,
    /// `nxdomain` | `null_ip`
    pub block_mode: String,
    /// Per token.
    pub rate_per_sec: f64,
    pub burst: f64,
    /// When no bundle is available answer anyway instead of SERVFAIL.
    pub fail_open: bool,
    /// Plain DNS for registered networks (`ip:port`, empty = off). Never answers strangers (REFUSED).
    pub udp_listen: String,
    pub tcp_listen: String,
    /// DNS over TLS (needs `[tls]`). SNI `<label>.<dot_domain>` selects a token created with `dot`.
    pub dot_listen: String,
    pub dot_domain: String,
    /// DNS over QUIC (RFC 9250, UDP; needs `[tls]`), same attribution as DoT.
    pub doq_listen: String,
    /// Per source address, across transports.
    pub ip_rate_per_sec: f64,
    pub ip_burst: f64,
}
impl Default for CloudDnsSection {
    fn default() -> Self {
        Self {
            enabled: false,
            upstreams: Vec::new(),
            upstream: String::new(),
            block_mode: "nxdomain".into(),
            rate_per_sec: 50.0,
            burst: 100.0,
            fail_open: false,
            udp_listen: String::new(),
            tcp_listen: String::new(),
            dot_listen: String::new(),
            dot_domain: String::new(),
            doq_listen: String::new(),
            ip_rate_per_sec: 100.0,
            ip_burst: 200.0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_and_partial_files_are_valid() {
        let c: Config = toml::from_str("").unwrap();
        assert!(c.dns.enabled);
        let c: Config = toml::from_str("[dns]\nlisten = \"0.0.0.0:53\"").unwrap();
        assert_eq!(c.dns.listen, "0.0.0.0:53");
        assert_eq!(c.api.listen, "127.0.0.1:8080");
        assert!(toml::from_str::<Config>("[bogus]").is_err());
        assert!(c.lists.resolve().unwrap().iter().all(|s| s.default_enabled));
    }

    #[test]
    fn auth_section() {
        let c: Config = toml::from_str("").unwrap();
        assert_eq!(c.auth.environment, Environment::Production);
        assert!(!c.auth.break_glass.enabled, "break-glass is off by default");
        let c: Config = toml::from_str(
            "[auth]\nenvironment = \"staging\"\n[auth.break_glass]\nenabled = true\nttl_hours = 4\n[auth.oidc]\nissuer = \"https://idp.example.com\"",
        )
        .unwrap();
        assert_eq!(c.auth.environment, Environment::Staging);
        assert_eq!(c.auth.break_glass.ttl_hours, 4);
        assert_eq!(c.auth.oidc.audience, "hygeia-api");
        assert!(
            toml::from_str::<Config>("[auth.break_glass]\nsecret = \"x\"").is_err(),
            "no secrets in the config file"
        );
    }

    #[test]
    fn lists_selection_and_custom() {
        let c: Config = toml::from_str(
            r#"
[lists]
sources = ["stevenblack"]

[[lists.custom]]
id = "mine"
name = "Mine"
url = "https://example.com/list.txt"
format = "domains"
license = "CC0-1.0"
attribution = "me"
network = true
"#,
        )
        .unwrap();
        let ids: Vec<_> = c
            .lists
            .resolve()
            .unwrap()
            .into_iter()
            .map(|s| s.id)
            .collect();
        assert_eq!(ids, vec!["stevenblack", "mine"]);
        let bad: Config = toml::from_str("[lists]\nsources = [\"nope\"]").unwrap();
        assert!(bad.lists.resolve().is_err());
    }
}
