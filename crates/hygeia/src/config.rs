//! Every section is optional (`#[serde(default)]`): a 0-line file is valid and
//! all missing values fall back to safe defaults.

use serde::Deserialize;

#[derive(Debug, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub api: ApiConfig,
    pub dns: DnsSection,
}

#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ApiConfig {
    pub listen: String,
}
impl Default for ApiConfig {
    fn default() -> Self {
        Self {
            listen: "127.0.0.1:8080".into(),
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
    }
}
