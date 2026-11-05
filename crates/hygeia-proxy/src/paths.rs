//! Where the node keeps its state. Pure function of the environment so every platform's rule is
//! unit-tested on any host.

use std::path::{Path, PathBuf};

pub struct Env<'a> {
    pub get: &'a dyn Fn(&str) -> Option<String>,
    pub is_root: bool,
    pub windows: bool,
}

/// Resolution order: explicit override (flag, then `HYGEIA_PROXY_DATA_DIR`), then the platform default.
///
/// * Linux/Unix, root (service): `/var/lib/hygeia-proxy`
/// * Linux/Unix, user: `$XDG_DATA_HOME/hygeia-proxy` or `$HOME/.local/share/hygeia-proxy`
/// * Windows: `%LOCALAPPDATA%\Hygeia` (services pass an explicit directory, e.g. under `%ProgramData%`)
pub fn data_dir(explicit: Option<&Path>, env: &Env) -> Result<PathBuf, String> {
    if let Some(p) = explicit {
        return Ok(p.to_path_buf());
    }
    if let Some(p) = (env.get)("HYGEIA_PROXY_DATA_DIR").filter(|s| !s.is_empty()) {
        return Ok(PathBuf::from(p));
    }
    if env.windows {
        let base = (env.get)("LOCALAPPDATA")
            .or_else(|| (env.get)("APPDATA"))
            .ok_or("neither LOCALAPPDATA nor APPDATA is set; pass --data-dir")?;
        return Ok(PathBuf::from(base).join("Hygeia"));
    }
    if env.is_root {
        return Ok(PathBuf::from("/var/lib/hygeia-proxy"));
    }
    if let Some(x) = (env.get)("XDG_DATA_HOME").filter(|s| !s.is_empty()) {
        return Ok(PathBuf::from(x).join("hygeia-proxy"));
    }
    let home = (env.get)("HOME")
        .filter(|s| !s.is_empty())
        .ok_or("HOME is not set; pass --data-dir")?;
    Ok(PathBuf::from(home).join(".local/share/hygeia-proxy"))
}

pub fn real_env_data_dir(explicit: Option<&Path>) -> Result<PathBuf, String> {
    #[cfg(unix)]
    let is_root = unsafe { libc::geteuid() } == 0;
    #[cfg(not(unix))]
    let is_root = false;
    data_dir(
        explicit,
        &Env {
            get: &|k| std::env::var(k).ok(),
            is_root,
            windows: cfg!(windows),
        },
    )
}

#[derive(Debug, Clone)]
pub struct Paths {
    pub dir: PathBuf,
    pub config: PathBuf,
    pub state: PathBuf,
    pub signing_key: PathBuf,
    pub owner_token: PathBuf,
    /// Connected mode: node identity + known browser credentials (hashes only).
    pub node_state: PathBuf,
    /// Connected mode: verified bundles cached for offline operation.
    pub bundle_cache: PathBuf,
}

impl Paths {
    pub fn new(dir: PathBuf) -> Self {
        Self {
            config: dir.join("hygeia-proxy.toml"),
            state: dir.join("state.json"),
            signing_key: dir.join("signing.key"),
            owner_token: dir.join("owner.token"),
            node_state: dir.join("connected.json"),
            bundle_cache: dir.join("bundles"),
            dir,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn env<'a>(
        m: &'a HashMap<&'static str, &'static str>,
        is_root: bool,
        windows: bool,
        f: &'a dyn Fn(&str) -> Option<String>,
    ) -> Env<'a> {
        let _ = m;
        Env {
            get: f,
            is_root,
            windows,
        }
    }

    fn lookup(pairs: &'static [(&'static str, &'static str)]) -> impl Fn(&str) -> Option<String> {
        move |k| {
            pairs
                .iter()
                .find(|(a, _)| *a == k)
                .map(|(_, v)| v.to_string())
        }
    }

    #[test]
    fn per_platform_defaults() {
        let m = HashMap::new();
        let f = lookup(&[("HOME", "/home/u")]);
        assert_eq!(
            data_dir(None, &env(&m, false, false, &f)).unwrap(),
            PathBuf::from("/home/u/.local/share/hygeia-proxy")
        );
        let f = lookup(&[("HOME", "/home/u"), ("XDG_DATA_HOME", "/x")]);
        assert_eq!(
            data_dir(None, &env(&m, false, false, &f)).unwrap(),
            PathBuf::from("/x/hygeia-proxy")
        );
        assert_eq!(
            data_dir(None, &env(&m, true, false, &f)).unwrap(),
            PathBuf::from("/var/lib/hygeia-proxy"),
            "root = service"
        );
        let f = lookup(&[("LOCALAPPDATA", "C:\\Users\\u\\AppData\\Local")]);
        assert!(
            data_dir(None, &env(&m, false, true, &f))
                .unwrap()
                .ends_with("Hygeia")
        );
    }

    #[test]
    fn overrides_and_errors() {
        let m = HashMap::new();
        let f = lookup(&[("HYGEIA_PROXY_DATA_DIR", "/env"), ("HOME", "/h")]);
        assert_eq!(
            data_dir(None, &env(&m, false, false, &f)).unwrap(),
            PathBuf::from("/env")
        );
        assert_eq!(
            data_dir(Some(Path::new("/flag")), &env(&m, false, false, &f)).unwrap(),
            PathBuf::from("/flag"),
            "flag beats env"
        );
        let none = lookup(&[]);
        assert!(data_dir(None, &env(&m, false, false, &none)).is_err());
        assert!(data_dir(None, &env(&m, false, true, &none)).is_err());
    }
}
