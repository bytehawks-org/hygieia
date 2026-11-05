//! Connected mode: the node is the endpoint of a central Hygieia server.
//!
//! The node holds **no credential of its own** towards the central server. Trust is per browser
//! device (revocable centrally, visible under central RBAC):
//!
//! * `POST /v1/enroll` is relayed unchanged, tagged with `X-Hygeia-Node: <node id>`;
//! * `GET /v1/bundle` is relayed with the browser's own bearer secret. A `200` is verified against
//!   the **pinned** central public key, checked against rollback and cached on disk; the bytes are
//!   served unchanged (the central signature is preserved, so the extension pins the central key);
//! * when the central server is unreachable the cached bundle is re-verified and served, but only to
//!   a device the central server accepted before (known by the SHA-256 of its secret). Rules keep
//!   being enforced; a revocation takes effect as soon as the central server can be reached.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::Router;
use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use ed25519_dalek::VerifyingKey;
use hygeia_core::SignedBundle;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::config::UpstreamSection;
use crate::paths::Paths;

type BoxErr = Box<dyn std::error::Error + Send + Sync>;

const MAX_BUNDLE: usize = 128 << 20;
const MAX_ENROLL_BODY: usize = 16 << 10;

#[derive(Serialize, Deserialize, Default)]
struct Persisted {
    node_id: String,
    /// sha256(device secret) -> group served to it
    devices: HashMap<String, Known>,
}

#[derive(Serialize, Deserialize, Clone)]
struct Known {
    tenant: String,
    group: String,
    last_ok: i64,
}

pub struct Connected {
    http: reqwest::Client,
    base: String,
    key: VerifyingKey,
    paths: Paths,
    owner: String,
    inner: Mutex<Persisted>,
    /// Serialises the check-then-write of a bundle so rollback checks cannot race.
    write_lock: tokio::sync::Mutex<()>,
    status: Mutex<Status>,
}

#[derive(Default, Clone, Serialize)]
struct Status {
    last_contact_ok: Option<i64>,
    last_error: Option<String>,
}

fn now() -> i64 {
    hygeia_api::now()
}

fn sha_hex(s: &str) -> String {
    Sha256::digest(s.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn write_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let tmp = path.with_extension(format!("tmp{}", hygeia_runtime::rand_hex(3)));
    {
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts.open(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path).inspect_err(|_| {
        let _ = std::fs::remove_file(&tmp);
    })
}

impl Connected {
    pub fn new(up: &UpstreamSection, paths: &Paths, owner: String) -> Result<Arc<Self>, BoxErr> {
        let key = up.verifying_key()?;
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(up.timeout_secs.max(1)))
            .redirect(reqwest::redirect::Policy::none())
            .user_agent(concat!("hygeia-node/", env!("CARGO_PKG_VERSION")))
            .build()?;
        std::fs::create_dir_all(&paths.bundle_cache)?;
        let mut p: Persisted = match std::fs::read(&paths.node_state) {
            Ok(b) => serde_json::from_slice(&b)
                .map_err(|e| format!("{}: {e}", paths.node_state.display()))?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Persisted::default(),
            Err(e) => return Err(format!("{}: {e}", paths.node_state.display()).into()),
        };
        if p.node_id.is_empty() {
            p.node_id = format!("node-{}", hygeia_runtime::rand_hex(8));
        }
        let me = Arc::new(Self {
            http,
            base: up.url.trim_end_matches('/').to_string(),
            key,
            paths: paths.clone(),
            owner,
            inner: Mutex::new(p),
            write_lock: tokio::sync::Mutex::new(()),
            status: Mutex::new(Status::default()),
        });
        me.persist()?;
        Ok(me)
    }

    pub fn node_id(&self) -> String {
        self.inner.lock().unwrap().node_id.clone()
    }

    fn persist(&self) -> std::io::Result<()> {
        let bytes = serde_json::to_vec_pretty(&*self.inner.lock().unwrap()).unwrap();
        write_atomic(&self.paths.node_state, &bytes)
    }

    fn cache_file(&self, tenant: &str, group: &str) -> PathBuf {
        self.paths
            .bundle_cache
            .join(format!("{}.bin", sha_hex(&format!("{tenant}\0{group}"))))
    }

    fn contact(&self, ok: Result<(), String>) {
        let mut s = self.status.lock().unwrap();
        match ok {
            Ok(()) => {
                s.last_contact_ok = Some(now());
                s.last_error = None;
            }
            Err(e) => s.last_error = Some(e),
        }
    }

    /// Read + re-verify a cached bundle (the disk is not trusted either).
    fn read_cached(&self, tenant: &str, group: &str) -> Option<(Vec<u8>, hygeia_core::Meta)> {
        let bytes = std::fs::read(self.cache_file(tenant, group)).ok()?;
        let b = SignedBundle::open(&bytes, &self.key).ok()?;
        (b.meta.tenant_id == tenant && b.meta.group_id == group).then_some((bytes, b.meta))
    }

    fn forget(&self, hash: &str) {
        if self.inner.lock().unwrap().devices.remove(hash).is_some() {
            let _ = self.persist();
        }
    }
}

type S = State<Arc<Connected>>;

pub fn router(c: Arc<Connected>) -> Router {
    Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .route("/v1/pubkey", get(pubkey))
        .route(
            "/v1/enroll",
            post(enroll).layer(DefaultBodyLimit::max(MAX_ENROLL_BODY)),
        )
        .route("/v1/bundle", get(bundle))
        .route("/v1/node/status", get(status))
        .with_state(c)
}

async fn pubkey(State(c): S) -> String {
    c.key
        .to_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn bearer(h: &HeaderMap) -> Option<&str> {
    h.get(header::AUTHORIZATION)?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")
}

async fn enroll(State(c): S, body: Bytes) -> Response {
    let r = c
        .http
        .post(format!("{}/v1/enroll", c.base))
        .header(header::CONTENT_TYPE, "application/json")
        .header("x-hygeia-node", c.node_id())
        .body(body)
        .send()
        .await;
    match r {
        Ok(resp) => {
            c.contact(Ok(()));
            let code =
                StatusCode::from_u16(resp.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
            let ct = resp.headers().get(header::CONTENT_TYPE).cloned();
            let Ok(Some(body)) = read_limited(resp, 64 << 10).await else {
                return StatusCode::BAD_GATEWAY.into_response();
            };
            let mut out = (code, body).into_response();
            if let Some(ct) = ct {
                out.headers_mut().insert(header::CONTENT_TYPE, ct);
            }
            out
        }
        Err(e) => {
            c.contact(Err(e.to_string()));
            (StatusCode::BAD_GATEWAY, "central server unreachable").into_response()
        }
    }
}

async fn read_limited(mut resp: reqwest::Response, max: usize) -> Result<Option<Vec<u8>>, ()> {
    if resp.content_length().is_some_and(|l| l as usize > max) {
        return Err(());
    }
    let mut buf = Vec::new();
    while let Some(chunk) = resp.chunk().await.map_err(|_| ())? {
        if buf.len() + chunk.len() > max {
            return Err(());
        }
        buf.extend_from_slice(&chunk);
    }
    Ok(Some(buf))
}

fn serve_bundle(bytes: Vec<u8>, req: &HeaderMap, stale: bool) -> Response {
    let sb = SignedBundle(bytes);
    let etag = sb.etag();
    let mut resp = if req
        .get(header::IF_NONE_MATCH)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v == etag)
    {
        (StatusCode::NOT_MODIFIED, [(header::ETAG, etag)]).into_response()
    } else {
        (
            [
                (header::ETAG, etag),
                (
                    header::CONTENT_TYPE,
                    "application/vnd.hygeia.bundle".to_string(),
                ),
                (header::CACHE_CONTROL, "private, no-cache".to_string()),
            ],
            sb.0,
        )
            .into_response()
    };
    if stale {
        resp.headers_mut()
            .insert("x-hygeia-stale", HeaderValue::from_static("1"));
    }
    resp
}

async fn bundle(State(c): S, headers: HeaderMap) -> Response {
    let Some(secret) = bearer(&headers) else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    let hash = sha_hex(secret);
    let known = c.inner.lock().unwrap().devices.get(&hash).cloned();

    // Conditional request upstream: only when we hold what the browser holds do we save bytes.
    let mut req = c
        .http
        .get(format!("{}/v1/bundle", c.base))
        .header(header::AUTHORIZATION, format!("Bearer {secret}"));
    if let Some(inm) = headers.get(header::IF_NONE_MATCH) {
        req = req.header(header::IF_NONE_MATCH, inm);
    }
    let resp = match req.send().await {
        Ok(r) => r,
        Err(e) => {
            c.contact(Err(e.to_string()));
            return offline(&c, known, &headers);
        }
    };
    let status = resp.status().as_u16();
    match status {
        200 => {
            let bytes = match read_limited(resp, MAX_BUNDLE).await {
                Ok(Some(b)) => b,
                _ => {
                    c.contact(Err("bundle download failed or too large".into()));
                    return offline(&c, known, &headers);
                }
            };
            let opened = match SignedBundle::open(&bytes, &c.key) {
                Ok(b) => b,
                Err(e) => {
                    // A bad signature is an attack or a misconfigured pin: never serve it.
                    tracing::error!(error = %e, "central bundle failed verification against the pinned key");
                    c.contact(Err(format!("bundle verification failed: {e}")));
                    return offline(&c, known, &headers);
                }
            };
            let (tenant, group) = (opened.meta.tenant_id.clone(), opened.meta.group_id.clone());
            let _g = c.write_lock.lock().await;
            if let Some((prev, meta)) = c.read_cached(&tenant, &group) {
                let older = opened.meta.version < meta.version;
                let same_version_different = opened.meta.version == meta.version && prev != bytes;
                if older || same_version_different {
                    tracing::error!(
                        have = meta.version,
                        got = opened.meta.version,
                        "refusing rollback/replay of a central bundle"
                    );
                    c.contact(Err("rollback refused".into()));
                    return serve_bundle(prev, &headers, true);
                }
            }
            if let Err(e) = write_atomic(&c.cache_file(&tenant, &group), &bytes) {
                tracing::warn!(error = %e, "could not cache the bundle; serving it anyway");
            }
            c.inner.lock().unwrap().devices.insert(
                hash,
                Known {
                    tenant,
                    group,
                    last_ok: now(),
                },
            );
            if let Err(e) = c.persist() {
                tracing::warn!(error = %e, "could not persist node state");
            }
            c.contact(Ok(()));
            serve_bundle(bytes, &headers, false)
        }
        304 => {
            c.contact(Ok(()));
            if let Some(k) = known
                && let Some((bytes, _)) = c.read_cached(&k.tenant, &k.group)
            {
                return serve_bundle(bytes, &headers, false);
            }
            // The browser holds a bundle we do not: it is current upstream, let it keep it.
            (StatusCode::NOT_MODIFIED, ()).into_response()
        }
        401 | 403 => {
            c.contact(Ok(()));
            c.forget(&hash);
            StatusCode::UNAUTHORIZED.into_response()
        }
        other => {
            c.contact(Err(format!("upstream status {other}")));
            offline(&c, known, &headers)
        }
    }
}

fn offline(c: &Connected, known: Option<Known>, headers: &HeaderMap) -> Response {
    if let Some(k) = known
        && let Some((bytes, _)) = c.read_cached(&k.tenant, &k.group)
    {
        tracing::warn!("central server unavailable: serving the cached, verified bundle");
        return serve_bundle(bytes, headers, true);
    }
    (
        StatusCode::BAD_GATEWAY,
        "central server unavailable and nothing cached",
    )
        .into_response()
}

async fn status(State(c): S, headers: HeaderMap) -> Response {
    let ok = bearer(&headers).is_some_and(|t| {
        t.len() == c.owner.len()
            && t.bytes()
                .zip(c.owner.bytes())
                .fold(0, |a, (x, y)| a | (x ^ y))
                == 0
    });
    if !ok {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let (node_id, devices) = {
        let g = c.inner.lock().unwrap();
        (g.node_id.clone(), g.devices.len())
    };
    axum::Json(serde_json::json!({
        "mode": "connected",
        "node_id": node_id,
        "upstream": c.base,
        "known_devices": devices,
        "status": *c.status.lock().unwrap(),
    }))
    .into_response()
}
