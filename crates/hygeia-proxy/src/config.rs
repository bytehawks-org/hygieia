//! Node configuration. Every section is optional: an empty file is valid and yields the safe
//! defaults (loopback only, DNS off, default filter lists).

use serde::Deserialize;

pub use hygeia_runtime::ListsSection;

#[derive(Debug, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub mode: Mode,
    pub upstream: UpstreamSection,
    pub http: HttpSection,
    pub dns: DnsSection,
    pub lists: ListsSection,
}

#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    /// Own rules, own lists, own signing key.
    #[default]
    Standalone,
    /// Endpoint of a central server: relays enrolments, serves cached verified bundles.
    Connected,
}

/// Central server (connected mode only).
#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct UpstreamSection {
    /// Base URL of the central server, e.g. `https://hygeia.example.com`.
    pub url: String,
    /// Central bundle-signing public key (64 hex chars). Pinned: the node never trusts a key
    /// learned from the network.
    pub public_key: String,
    /// Permit `http://` (tests/labs only; bundles stay signed, enrolment secrets would not be
    /// protected in transit).
    pub allow_insecure_http: bool,
    pub timeout_secs: u64,
}

impl Default for UpstreamSection {
    fn default() -> Self {
        Self {
            url: String::new(),
            public_key: String::new(),
            allow_insecure_http: false,
            timeout_secs: 10,
        }
    }
}

impl UpstreamSection {
    pub fn verifying_key(&self) -> Result<ed25519_dalek::VerifyingKey, String> {
        let h = self.public_key.trim();
        if h.len() != 64 || !h.is_ascii() {
            return Err("upstream.public_key must be 64 hex characters".into());
        }
        let mut raw = [0u8; 32];
        for (i, c) in h.as_bytes().chunks(2).enumerate() {
            raw[i] = u8::from_str_radix(std::str::from_utf8(c).unwrap(), 16)
                .map_err(|_| "upstream.public_key is not hex".to_string())?;
        }
        ed25519_dalek::VerifyingKey::from_bytes(&raw)
            .map_err(|e| format!("upstream.public_key: {e}"))
    }
}

#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct HttpSection {
    /// Admin UI, admin API and the extension feed. Loopback by default.
    pub listen: String,
    /// Serving other machines is an explicit opt-in and requires `allowed_hosts`.
    pub allow_lan: bool,
    /// Extra `Host` header values accepted (host:port), for LAN use or a reverse proxy.
    pub allowed_hosts: Vec<String>,
    /// Built admin UI; empty = autodetect.
    pub web_dir: String,
}

impl Default for HttpSection {
    fn default() -> Self {
        Self {
            listen: "127.0.0.1:8470".into(),
            allow_lan: false,
            allowed_hosts: Vec::new(),
            web_dir: String::new(),
        }
    }
}

#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum DnsMode {
    /// No DNS on the node (default): nothing listens on port 53, the OS resolver is untouched.
    #[default]
    Off,
    /// Filter DNS locally with the verified bundle.
    Local,
}

#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DnsSection {
    pub mode: DnsMode,
    /// Port 53 needs privileges; 5353 works unprivileged.
    pub listen: String,
    /// Plain-UDP upstream resolvers (`ip:port`); the first is used.
    pub upstream: Vec<String>,
    /// `nxdomain` | `null_ip`
    pub block_mode: String,
}

impl Default for DnsSection {
    fn default() -> Self {
        Self {
            mode: DnsMode::Off,
            listen: "127.0.0.1:5353".into(),
            upstream: vec!["9.9.9.9:53".into()],
            block_mode: "nxdomain".into(),
        }
    }
}

impl Config {
    /// Cross-field checks that serde cannot express.
    pub fn validate(&self) -> Result<(), String> {
        if self.mode == Mode::Connected {
            let u = &self.upstream;
            if u.url.is_empty() {
                return Err("mode = \"connected\" requires upstream.url".into());
            }
            if !(u.url.starts_with("https://")
                || u.allow_insecure_http && u.url.starts_with("http://"))
            {
                return Err(
                    "upstream.url must be https:// (upstream.allow_insecure_http only for labs)"
                        .into(),
                );
            }
            u.verifying_key()?;
            if self.dns.mode == DnsMode::Local {
                return Err("dns.mode = \"local\" is not available in connected mode yet".into());
            }
        }
        let addr: std::net::SocketAddr = self
            .http
            .listen
            .parse()
            .map_err(|e| format!("http.listen {:?}: {e}", self.http.listen))?;
        if !addr.ip().is_loopback() {
            if !self.http.allow_lan {
                return Err(format!(
                    "http.listen {} is not a loopback address: set http.allow_lan = true and http.allowed_hosts to expose the node on the network",
                    self.http.listen
                ));
            }
            if self.http.allowed_hosts.is_empty() {
                return Err(
                    "http.allow_lan requires http.allowed_hosts (Host header allow-list)".into(),
                );
            }
        }
        if self.dns.mode == DnsMode::Local && self.dns.upstream.is_empty() {
            return Err("dns.upstream is empty".into());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_file_is_safe_default() {
        let c: Config = toml::from_str("").unwrap();
        c.validate().unwrap();
        assert_eq!(c.dns.mode, DnsMode::Off, "DNS is opt-in");
        assert_eq!(c.http.listen, "127.0.0.1:8470");
        assert!(!c.http.allow_lan);
    }

    #[test]
    fn lan_exposure_needs_explicit_opt_in_and_host_allow_list() {
        let c: Config = toml::from_str("[http]\nlisten = \"0.0.0.0:8470\"").unwrap();
        assert!(c.validate().unwrap_err().contains("allow_lan"));
        let c: Config =
            toml::from_str("[http]\nlisten = \"0.0.0.0:8470\"\nallow_lan = true").unwrap();
        assert!(c.validate().unwrap_err().contains("allowed_hosts"));
        let c: Config = toml::from_str("[http]\nlisten = \"0.0.0.0:8470\"\nallow_lan = true\nallowed_hosts = [\"pc.lan:8470\"]").unwrap();
        c.validate().unwrap();
    }

    #[test]
    fn connected_needs_https_upstream_and_pinned_key_and_unknown_keys_are_rejected() {
        let c: Config = toml::from_str("mode = \"connected\"").unwrap();
        assert!(c.validate().unwrap_err().contains("upstream.url"));
        let key: String = ed25519_dalek::SigningKey::from_bytes(&[1u8; 32])
            .verifying_key()
            .to_bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        let ok = |extra: &str| {
            let c: Config =
                toml::from_str(&format!("mode = \"connected\"\n[upstream]\n{extra}")).unwrap();
            c.validate()
        };
        assert!(
            ok(&format!(
                "url = \"http://c.example.com\"\npublic_key = \"{key}\""
            ))
            .unwrap_err()
            .contains("https")
        );
        assert!(
            ok("url = \"https://c.example.com\"")
                .unwrap_err()
                .contains("public_key")
        );
        assert!(
            ok(&format!(
                "url = \"https://c.example.com\"\npublic_key = \"{}\"",
                "zz".repeat(32)
            ))
            .is_err()
        );
        ok(&format!(
            "url = \"https://c.example.com\"\npublic_key = \"{key}\""
        ))
        .unwrap();
        ok(&format!(
            "url = \"http://127.0.0.1:1\"\npublic_key = \"{key}\"\nallow_insecure_http = true"
        ))
        .unwrap();
        assert!(toml::from_str::<Config>("[bogus]").is_err());
        assert!(toml::from_str::<Config>("[dns]\nmode = \"cloud\"").is_err());
    }
}
