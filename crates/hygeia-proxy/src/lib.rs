//! The Hygieia node: one installable process that is either a standalone local server or (later) the
//! endpoint of a central server. See `docs/architecture/node.md`.
//!
//! Standalone composition: file-backed store + signing key + local-owner credential, the same API
//! and admin UI as the server, a Host/Origin guard for the local port, and an opt-in DNS listener.

pub mod config;
pub mod connected;
pub mod guard;
pub mod paths;
pub mod service;
pub mod setup;

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use hygeia_api::{AppState, AuthConfig, DEFAULT_GROUP, DEFAULT_TENANT, LocalOwner, PublicConfig};
use hygeia_lists::{HttpFetcher, Manager};
use hygeia_store::{FileStore, Store};
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

use crate::config::{Config, DnsMode, Mode};
use crate::paths::Paths;

type BoxErr = Box<dyn std::error::Error + Send + Sync>;

pub struct RunningNode {
    pub http_addr: SocketAddr,
    pub dns_addr: Option<SocketAddr>,
    /// Embedded control plane (standalone mode only).
    pub state: Option<Arc<AppState>>,
    /// Whether an admin UI was found and is being served.
    pub ui: bool,
    store: Option<Arc<FileStore>>,
    shutdown: Option<oneshot::Sender<()>>,
    server: JoinHandle<std::io::Result<()>>,
}

impl RunningNode {
    /// Stop serving and flush the state file.
    pub async fn stop(mut self) -> Result<(), BoxErr> {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
        self.server.await??;
        if let Some(s) = &self.store {
            s.flush()?;
        }
        Ok(())
    }

    /// Resolves when the HTTP server task ends on its own (error).
    pub async fn wait(&mut self) -> Result<(), BoxErr> {
        (&mut self.server).await??;
        Ok(())
    }
}

pub fn read_owner_token(paths: &Paths) -> Result<String, String> {
    std::fs::read_to_string(&paths.owner_token)
        .map(|s| s.trim().to_string())
        .map_err(|e| {
            format!(
                "{}: {e} (has the node been started once?)",
                paths.owner_token.display()
            )
        })
}

/// Public half of the signing key as hex: what the browser extension pins.
pub fn read_public_key(paths: &Paths) -> Result<String, String> {
    if !paths.signing_key.exists() {
        return Err(format!(
            "{} does not exist (has the node been started once?)",
            paths.signing_key.display()
        ));
    }
    let (key, _) = hygeia_runtime::load_or_create_signing_key(&paths.signing_key)?;
    Ok(key
        .verifying_key()
        .to_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect())
}

pub fn load_config(path: &Path) -> Result<Config, String> {
    let cfg: Config = if path.exists() {
        let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
        toml::from_str(&text).map_err(|e| format!("{}: {e}", path.display()))?
    } else {
        Config::default()
    };
    cfg.validate()?;
    Ok(cfg)
}

fn find_web_dir(configured: &str) -> Option<PathBuf> {
    let mut candidates: Vec<PathBuf> = Vec::new();
    if !configured.is_empty() {
        candidates.push(configured.into());
    }
    if let Ok(d) = std::env::var("HYGEIA_WEB_DIR") {
        candidates.push(d.into());
    }
    if let Ok(exe) = std::env::current_exe()
        && let Some(dir) = exe.parent()
    {
        candidates.push(dir.join("web"));
        candidates.push(dir.join("../share/hygeia/web"));
    }
    candidates.push("/usr/share/hygeia/web".into());
    candidates
        .into_iter()
        .find(|p| p.join("index.html").is_file())
}

fn private_dir(dir: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

/// Bring the node up. Returns once the HTTP listener is bound.
pub async fn start(cfg: Config, paths: Paths) -> Result<RunningNode, BoxErr> {
    cfg.validate()?;
    private_dir(&paths.dir).map_err(|e| format!("{}: {e}", paths.dir.display()))?;

    if cfg.mode == Mode::Connected {
        return start_connected(cfg, paths).await;
    }

    let (signing_key, created) = hygeia_runtime::load_or_create_signing_key(&paths.signing_key)?;
    if created {
        tracing::info!(file = %paths.signing_key.display(), "generated a new signing key (browsers pin its public half)");
    }
    let (owner, created) = hygeia_runtime::load_or_create_secret(&paths.owner_token, || {
        format!("hyg_own_{}", hygeia_runtime::rand_hex(24))
    })
    .map_err(|e| format!("{}: {e}", paths.owner_token.display()))?;
    if created {
        tracing::info!(file = %paths.owner_token.display(), "generated the local owner credential; run `hygeia-proxy open` to sign in");
    }

    let store = Arc::new(FileStore::open(&paths.state)?);
    store.bootstrap_default().await?;
    store.flush()?;

    let auth = AuthConfig {
        local_owner: Some(LocalOwner::new(&owner)?),
        break_glass: None,
        oidc: None,
    };
    let mut state = AppState::new(store.clone() as Arc<dyn Store>, signing_key, auth);
    state.public = PublicConfig {
        mode: "standalone".into(),
        environment: "production".into(),
        break_glass: false,
        oidc: None,
    };
    let state = Arc::new(state);

    if cfg.lists.enabled {
        let sources = cfg.lists.resolve()?;
        let insecure = cfg.lists.allow_insecure_http;
        if insecure {
            tracing::warn!(
                "lists.allow_insecure_http is on: list downloads are not protected in transit"
            );
        }
        let manager = Manager::new(
            sources,
            Arc::new(HttpFetcher::new(64 << 20, insecure)?),
            insecure,
        );
        hygeia_runtime::spawn_list_refresher(
            state.clone(),
            manager,
            Duration::from_secs(cfg.lists.refresh_hours.max(1) * 3600),
        );
    }

    let dns_addr = if cfg.dns.mode == DnsMode::Local {
        let rules =
            hygeia_runtime::spawn_dns_follower(state.clone(), DEFAULT_TENANT, DEFAULT_GROUP);
        let upstream = cfg.dns.upstream.first().ok_or("dns.upstream is empty")?;
        Some(
            hygeia_runtime::spawn_dns_server(&cfg.dns.listen, upstream, &cfg.dns.block_mode, rules)
                .await?,
        )
    } else {
        None
    };

    let listener = tokio::net::TcpListener::bind(&cfg.http.listen)
        .await
        .map_err(|e| format!("http.listen {}: {e}", cfg.http.listen))?;
    let http_addr = listener.local_addr()?;

    let web = find_web_dir(&cfg.http.web_dir);
    let ui = web.is_some();
    let app = match web {
        Some(dir) => {
            tracing::info!(dir = %dir.display(), "admin UI enabled");
            hygeia_api::router_with_ui(state.clone(), hygeia_api::ui::Ui::load(&dir, &[])?)
        }
        None => {
            tracing::warn!(
                "no built admin UI found (set http.web_dir or HYGEIA_WEB_DIR); the API still works"
            );
            hygeia_api::router(state.clone())
        }
    };
    let guard = guard::HostGuard::new(http_addr, &cfg.http.allowed_hosts);
    let app = app.layer(axum::middleware::from_fn_with_state(guard, guard::enforce));

    let (tx, rx) = oneshot::channel::<()>();
    let server = tokio::spawn(hygeia_api::serve(listener, app, async move {
        let _ = rx.await;
    }));
    tracing::info!(http = %http_addr, "node listening");
    Ok(RunningNode {
        http_addr,
        dns_addr,
        state: Some(state),
        ui,
        store: Some(store),
        shutdown: Some(tx),
        server,
    })
}

/// Connected mode: no embedded control plane, no signing key, no lists. The node relays to the
/// central server and serves verified, cached bundles (see `connected.rs`).
async fn start_connected(cfg: Config, paths: Paths) -> Result<RunningNode, BoxErr> {
    let (owner, created) = hygeia_runtime::load_or_create_secret(&paths.owner_token, || {
        format!("hyg_own_{}", hygeia_runtime::rand_hex(24))
    })
    .map_err(|e| format!("{}: {e}", paths.owner_token.display()))?;
    if created {
        tracing::info!(file = %paths.owner_token.display(), "generated the local credential (node status)");
    }
    let conn = connected::Connected::new(&cfg.upstream, &paths, owner)?;
    let listener = tokio::net::TcpListener::bind(&cfg.http.listen)
        .await
        .map_err(|e| format!("http.listen {}: {e}", cfg.http.listen))?;
    let http_addr = listener.local_addr()?;
    let guard = guard::HostGuard::new(http_addr, &cfg.http.allowed_hosts);
    let app = connected::router(conn.clone())
        .layer(axum::middleware::from_fn_with_state(guard, guard::enforce));
    let (tx, rx) = oneshot::channel::<()>();
    let server = tokio::spawn(hygeia_api::serve(listener, app, async move {
        let _ = rx.await;
    }));
    tracing::info!(http = %http_addr, node = %conn.node_id(), upstream = %cfg.upstream.url, "node listening (connected)");
    Ok(RunningNode {
        http_addr,
        dns_addr: None,
        state: None,
        ui: false,
        store: None,
        shutdown: Some(tx),
        server,
    })
}
