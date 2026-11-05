//! Node configuration. Every section is optional: an empty file is valid and yields the safe
//! defaults (loopback only, DNS off, default filter lists).

use serde::Deserialize;

pub use hygeia_runtime::ListsSection;

#[derive(Debug, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub mode: Mode,
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
    /// Endpoint of a central server (not implemented in this build).
    Connected,
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
            return Err(
                "mode = \"connected\" is not implemented in this build (standalone only)".into(),
            );
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
    fn connected_and_unknown_keys_are_rejected() {
        let c: Config = toml::from_str("mode = \"connected\"").unwrap();
        assert!(c.validate().is_err());
        assert!(toml::from_str::<Config>("[bogus]").is_err());
        assert!(toml::from_str::<Config>("[dns]\nmode = \"cloud\"").is_err());
    }
}
