//! Pieces both binaries need, kept out of `main.rs` so they are tested once.

mod lists_config;
pub use lists_config::ListsSection;

use std::io::Write;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use ed25519_dalek::SigningKey;
use hygeia_api::AppState;
use hygeia_core::{Ruleset, SignedBundle};
use hygeia_dns::{BlockMode, DnsConfig};
use hygeia_lists::Manager;

pub fn rand_hex(bytes: usize) -> String {
    let mut b = vec![0u8; bytes];
    getrandom::fill(&mut b).expect("OS randomness unavailable");
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Create `path` with owner-only permissions (0600 on Unix) and write `contents`. Fails if it exists.
pub fn create_private_file(path: &Path, contents: &str) -> std::io::Result<()> {
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(path)?;
    f.write_all(contents.as_bytes())?;
    f.sync_all()
}

/// Read a secret file, creating it with `generate()` on first use.
/// Returns `(secret, created)`. A file that exists but is unreadable or malformed is an error.
pub fn load_or_create_secret(
    path: &Path,
    generate: impl FnOnce() -> String,
) -> std::io::Result<(String, bool)> {
    match std::fs::read_to_string(path) {
        Ok(s) => Ok((s.trim().to_string(), false)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let s = generate();
            create_private_file(path, &format!("{s}\n"))?;
            Ok((s, true))
        }
        Err(e) => Err(e),
    }
}

/// The signing key must be stable: browsers pin its public half.
pub fn load_or_create_signing_key(path: &Path) -> Result<(SigningKey, bool), String> {
    let (hex, created) = load_or_create_secret(path, || rand_hex(32))
        .map_err(|e| format!("{}: {e}", path.display()))?;
    if hex.len() != 64 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(format!("{}: expected 64 hex characters", path.display()));
    }
    let mut seed = [0u8; 32];
    for (i, c) in hex.as_bytes().chunks(2).enumerate() {
        seed[i] = u8::from_str_radix(std::str::from_utf8(c).unwrap(), 16).unwrap();
    }
    Ok((SigningKey::from_bytes(&seed), created))
}

/// Download, parse and install filter lists periodically (and on demand via the API).
pub fn spawn_list_refresher(state: Arc<AppState>, manager: Manager, interval: Duration) {
    tokio::spawn(async move {
        let mut first = true;
        loop {
            let r = manager.refresh().await;
            let status = serde_json::to_value(&r.status).unwrap_or_default();
            if r.changed || first {
                match state.set_lists(r.sources, status).await {
                    Ok(()) => tracing::info!(sources = r.status.len(), "lists updated"),
                    Err(e) => tracing::error!(error = %e, "could not install refreshed lists"),
                }
            } else {
                state.set_list_status(status);
            }
            first = false;
            tokio::select! {
                _ = tokio::time::sleep(interval) => {}
                _ = state.refresh_requested.notified() => tracing::info!("list refresh requested"),
            }
        }
    });
}

/// Keep a lock-free ruleset in step with the control plane's signed bundle for one (tenant, group).
pub fn spawn_dns_follower(
    state: Arc<AppState>,
    tenant: &'static str,
    group: &'static str,
) -> Arc<ArcSwap<Ruleset>> {
    let verifying = state.signing_key.verifying_key();
    let rules = Arc::new(ArcSwap::from_pointee(Ruleset::from_data(
        &Default::default(),
    )));
    let out = rules.clone();
    tokio::spawn(async move {
        let mut current = 0u64;
        loop {
            match state.bundle_for(tenant, group).await {
                Ok(b) => {
                    if let Ok(bundle) = SignedBundle::open(&b.0, &verifying)
                        && bundle.meta.version != current
                    {
                        current = bundle.meta.version;
                        rules.store(Arc::new(Ruleset::from_data(&bundle.network)));
                        tracing::info!(version = current, "dns ruleset updated");
                    }
                }
                Err(e) => tracing::error!(error = %e, "bundle refresh failed"),
            }
            tokio::time::sleep(Duration::from_secs(5)).await;
        }
    });
    out
}

/// Bind and run the UDP DNS server in the background. `upstream` is a plain-UDP `ip:port`.
pub async fn spawn_dns_server(
    listen: &str,
    upstream: &str,
    block_mode: &str,
    rules: Arc<ArcSwap<Ruleset>>,
) -> Result<SocketAddr, Box<dyn std::error::Error + Send + Sync>> {
    let upstream: SocketAddr = upstream
        .parse()
        .map_err(|e| format!("dns upstream {upstream:?}: {e}"))?;
    let mode = match block_mode {
        "null_ip" => BlockMode::NullIp,
        _ => BlockMode::NxDomain,
    };
    let sock = tokio::net::UdpSocket::bind(listen)
        .await
        .map_err(|e| format!("dns listen {listen}: {e}"))?;
    let addr = sock.local_addr()?;
    tracing::info!(listen = %addr, "dns listening (udp)");
    let cfg = Arc::new(DnsConfig {
        upstream,
        block_mode: mode,
        upstream_timeout: Duration::from_secs(3),
    });
    tokio::spawn(async move {
        if let Err(e) = hygeia_dns::serve_udp(sock, rules, cfg).await {
            tracing::error!(error = %e, "dns server stopped");
        }
    });
    Ok(addr)
}

/// `https://host:port/path` -> `https://host:port`
pub fn origin_of(url: &str) -> Option<String> {
    let (scheme, rest) = url.split_once("://")?;
    Some(format!("{scheme}://{}", rest.split('/').next()?))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dir() -> std::path::PathBuf {
        let d =
            std::env::temp_dir().join(format!("hygeia-rt-{}-{}", std::process::id(), rand_hex(4)));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn signing_key_is_stable_and_private() {
        let d = dir();
        let p = d.join("signing.key");
        let (k1, created) = load_or_create_signing_key(&p).unwrap();
        assert!(created);
        let (k2, created) = load_or_create_signing_key(&p).unwrap();
        assert!(!created);
        assert_eq!(
            k1.to_bytes(),
            k2.to_bytes(),
            "browsers pin this key: it must survive restarts"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&p).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        std::fs::write(&p, "not hex").unwrap();
        assert!(
            load_or_create_signing_key(&p).is_err(),
            "malformed key is an error, never regenerated"
        );
    }

    #[test]
    fn origin() {
        assert_eq!(
            origin_of("https://idp.example.com/realms/x").as_deref(),
            Some("https://idp.example.com")
        );
        assert_eq!(origin_of("nope"), None);
    }
}
