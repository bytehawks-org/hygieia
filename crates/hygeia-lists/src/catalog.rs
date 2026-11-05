use hygeia_core::{ListFormat, SourceMeta};
use serde::Deserialize;

/// One downloadable list.
#[derive(Debug, Clone, Deserialize)]
pub struct Source {
    pub id: String,
    pub name: String,
    pub url: String,
    pub format: ListFormat,
    /// SPDX-style identifier or short description, REQUIRED.
    pub license: String,
    pub attribution: String,
    /// Use domain-level rules (DNS / proxy host filtering).
    #[serde(default)]
    pub network: bool,
    /// Use element-hiding and scriptlet rules (blocker).
    #[serde(default)]
    pub cosmetic: bool,
    /// Keep privileged `trusted-*` scriptlets. Off unless you fully trust the source.
    #[serde(default)]
    pub allow_trusted_scriptlets: bool,
    #[serde(default)]
    pub default_enabled: bool,
}

impl Source {
    pub fn meta(&self) -> SourceMeta {
        SourceMeta {
            id: self.id.clone(),
            name: self.name.clone(),
            url: self.url.clone(),
            license: self.license.clone(),
            attribution: self.attribution.clone(),
        }
    }

    /// Reject sources without provenance or with unsafe transport.
    pub fn validate(&self, allow_http: bool) -> Result<(), String> {
        if self.id.is_empty()
            || !self
                .id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return Err(format!("invalid source id {:?}", self.id));
        }
        if self.license.trim().is_empty() || self.attribution.trim().is_empty() {
            return Err(format!(
                "source {}: license and attribution are required",
                self.id
            ));
        }
        if !(self.network || self.cosmetic) {
            return Err(format!(
                "source {}: neither network nor cosmetic enabled",
                self.id
            ));
        }
        if !self.url.starts_with("https://") && !(allow_http && self.url.starts_with("http://")) {
            return Err(format!("source {}: only https URLs are allowed", self.id));
        }
        Ok(())
    }
}

#[allow(clippy::too_many_arguments)]
fn src(
    id: &str,
    name: &str,
    url: &str,
    format: ListFormat,
    license: &str,
    attribution: &str,
    network: bool,
    cosmetic: bool,
    default_enabled: bool,
) -> Source {
    Source {
        id: id.into(),
        name: name.into(),
        url: url.into(),
        format,
        license: license.into(),
        attribution: attribution.into(),
        network,
        cosmetic,
        allow_trusted_scriptlets: false,
        default_enabled,
    }
}

/// Built-in catalogue. Licenses as stated by each project (verified against the
/// repositories' LICENSE files where reachable); re-verify before redistribution.
pub fn builtin() -> Vec<Source> {
    use ListFormat::*;
    const UBO: &str = "uBlock Origin / uAssets contributors";
    const UBO_URL: &str = "https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters";
    vec![
        // ---- DNS / host level ----
        src(
            "hagezi-pro",
            "HaGeZi Multi PRO",
            "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/pro-onlydomains.txt",
            Domains,
            "GPL-3.0",
            "HaGeZi (github.com/hagezi/dns-blocklists)",
            true,
            false,
            true,
        ),
        src(
            "hagezi-tif",
            "HaGeZi Threat Intelligence Feeds",
            "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/tif-onlydomains.txt",
            Domains,
            "GPL-3.0",
            "HaGeZi (github.com/hagezi/dns-blocklists)",
            true,
            false,
            false,
        ),
        src(
            "stevenblack",
            "StevenBlack unified hosts",
            "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
            Hosts,
            "MIT",
            "Steven Black (github.com/StevenBlack/hosts)",
            true,
            false,
            false,
        ),
        src(
            "urlhaus",
            "abuse.ch URLhaus (malware hosts)",
            "https://urlhaus.abuse.ch/downloads/hostfile/",
            Hosts,
            "CC0-1.0",
            "abuse.ch URLhaus",
            true,
            false,
            false,
        ),
        // ---- ABP/uBO syntax: element hiding + scriptlets (+ plain domain rules) ----
        src(
            "easylist",
            "EasyList",
            "https://easylist.to/easylist/easylist.txt",
            Abp,
            "GPL-3.0-or-later OR CC-BY-SA-3.0",
            "The EasyList authors (easylist.to)",
            false,
            true,
            true,
        ),
        src(
            "easyprivacy",
            "EasyPrivacy",
            "https://easylist.to/easylist/easyprivacy.txt",
            Abp,
            "GPL-3.0-or-later OR CC-BY-SA-3.0",
            "The EasyList authors (easylist.to)",
            true,
            true,
            true,
        ),
        src(
            "ublock-filters",
            "uBlock filters",
            &format!("{UBO_URL}/filters.txt"),
            Abp,
            "GPL-3.0",
            UBO,
            false,
            true,
            true,
        ),
        src(
            "ublock-quick-fixes",
            "uBlock filters - Quick fixes",
            &format!("{UBO_URL}/quick-fixes.txt"),
            Abp,
            "GPL-3.0",
            UBO,
            false,
            true,
            true,
        ),
        src(
            "ublock-privacy",
            "uBlock filters - Privacy",
            &format!("{UBO_URL}/privacy.txt"),
            Abp,
            "GPL-3.0",
            UBO,
            true,
            true,
            true,
        ),
        src(
            "ublock-unbreak",
            "uBlock filters - Unbreak",
            &format!("{UBO_URL}/unbreak.txt"),
            Abp,
            "GPL-3.0",
            UBO,
            false,
            true,
            true,
        ),
        src(
            "ublock-annoyances-cookies",
            "uBlock filters - Cookie notices",
            &format!("{UBO_URL}/annoyances-cookies.txt"),
            Abp,
            "GPL-3.0",
            UBO,
            false,
            true,
            false,
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtin_is_valid_and_unique() {
        let b = builtin();
        let mut ids: Vec<_> = b.iter().map(|s| s.id.clone()).collect();
        ids.sort();
        ids.dedup();
        assert_eq!(ids.len(), b.len());
        for s in &b {
            s.validate(false).unwrap();
        }
    }

    #[test]
    fn rejects_missing_provenance_and_http() {
        let mut s = builtin().remove(0);
        s.license.clear();
        assert!(s.validate(false).is_err());
        let mut s = builtin().remove(0);
        s.url = "http://example.com/x".into();
        assert!(s.validate(false).is_err());
        assert!(s.validate(true).is_ok());
    }
}
