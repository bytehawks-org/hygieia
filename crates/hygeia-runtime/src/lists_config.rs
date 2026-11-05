//! `[lists]` configuration shared by the server and the standalone node.

use serde::Deserialize;

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
