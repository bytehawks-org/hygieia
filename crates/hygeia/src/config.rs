//! Every section is optional (`#[serde(default)]`): a 0-line file is valid and
//! all missing values fall back to safe defaults.

use serde::Deserialize;

#[derive(Debug, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub api: ApiConfig,
    pub auth: AuthSection,
    pub dns: DnsSection,
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

#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ListsSection {
    pub enabled: bool,
    pub refresh_hours: u64,
    /// Allow plain-http list URLs (lab / trusted internal mirrors only: an attacker on
    /// the path could poison list content before it is signed into a bundle).
    pub allow_insecure_http: bool,
    /// Catalogue ids to use. Unset = catalogue entries marked `default_enabled`.
    pub sources: Option<Vec<String>>,
    /// Extra sources; license + attribution are mandatory.
    pub custom: Vec<hygeia_lists::Source>,
}
impl Default for ListsSection {
    fn default() -> Self {
        Self {
            enabled: true,
            refresh_hours: 12,
            allow_insecure_http: false,
            sources: None,
            custom: Vec::new(),
        }
    }
}

impl ListsSection {
    /// Resolve the active source set. Unknown catalogue ids are an error.
    pub fn resolve(&self) -> Result<Vec<hygeia_lists::Source>, String> {
        let catalogue = hygeia_lists::builtin();
        let mut out = match &self.sources {
            None => catalogue
                .into_iter()
                .filter(|s| s.default_enabled)
                .collect(),
            Some(ids) => ids
                .iter()
                .map(|id| {
                    catalogue
                        .iter()
                        .find(|s| &s.id == id)
                        .cloned()
                        .ok_or_else(|| format!("unknown list source {id:?}"))
                })
                .collect::<Result<Vec<_>, _>>()?,
        };
        out.extend(self.custom.iter().cloned());
        Ok(out)
    }
}

#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ApiConfig {
    pub listen: String,
    /// Built admin UI (Next.js static export). Empty = `HYGEIA_WEB_DIR`, else
    /// `/usr/share/hygeia/web` if it exists, else no UI.
    pub web_dir: String,
}
impl Default for ApiConfig {
    fn default() -> Self {
        Self {
            listen: "127.0.0.1:8080".into(),
            web_dir: String::new(),
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
