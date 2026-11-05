//! Server-side TLS from PEM files, reloadable without a restart (certbot, cert-manager, ...).
//!
//! `TlsSource` holds the current `rustls::ServerConfig`; [`TlsSource::reload_if_changed`] swaps it
//! when the certificate or key file changes (checked every minute by the watcher). A reload that
//! fails (half-written file, mismatched key) keeps the previous certificate and logs the error.

use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime};

use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};

type BoxErr = Box<dyn std::error::Error + Send + Sync>;

type Loaded = (Arc<rustls::ServerConfig>, Option<(SystemTime, SystemTime)>);

pub struct TlsSource {
    cert: PathBuf,
    key: PathBuf,
    alpn: Vec<Vec<u8>>,
    current: RwLock<Loaded>,
}

fn mtimes(cert: &Path, key: &Path) -> Option<(SystemTime, SystemTime)> {
    Some((
        std::fs::metadata(cert).ok()?.modified().ok()?,
        std::fs::metadata(key).ok()?.modified().ok()?,
    ))
}

fn build(cert: &Path, key: &Path, alpn: &[Vec<u8>]) -> Result<Arc<rustls::ServerConfig>, BoxErr> {
    let chain: Vec<CertificateDer<'static>> = CertificateDer::pem_file_iter(cert)
        .map_err(|e| format!("{}: {e}", cert.display()))?
        .collect::<Result<_, _>>()
        .map_err(|e| format!("{}: {e}", cert.display()))?;
    if chain.is_empty() {
        return Err(format!("{}: no certificate found", cert.display()).into());
    }
    let key = PrivateKeyDer::from_pem_file(key).map_err(|e| format!("{}: {e}", key.display()))?;
    let mut cfg = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()?
    .with_no_client_auth()
    .with_single_cert(chain, key)?;
    cfg.alpn_protocols = alpn.to_vec();
    Ok(Arc::new(cfg))
}

impl TlsSource {
    /// `alpn`: e.g. `["h2", "http/1.1"]` for HTTPS, `["dot"]` for DNS over TLS.
    pub fn load(cert: &Path, key: &Path, alpn: &[&str]) -> Result<Arc<Self>, BoxErr> {
        let alpn: Vec<Vec<u8>> = alpn.iter().map(|a| a.as_bytes().to_vec()).collect();
        let cfg = build(cert, key, &alpn)?;
        Ok(Arc::new(Self {
            cert: cert.to_path_buf(),
            key: key.to_path_buf(),
            alpn,
            current: RwLock::new((cfg, mtimes(cert, key))),
        }))
    }

    pub fn config(&self) -> Arc<rustls::ServerConfig> {
        self.current.read().unwrap().0.clone()
    }

    /// Returns true if a new certificate was loaded.
    pub fn reload_if_changed(&self) -> bool {
        let now = mtimes(&self.cert, &self.key);
        if now.is_none() || now == self.current.read().unwrap().1 {
            return false;
        }
        match build(&self.cert, &self.key, &self.alpn) {
            Ok(cfg) => {
                *self.current.write().unwrap() = (cfg, now);
                tracing::info!(cert = %self.cert.display(), "TLS certificate reloaded");
                true
            }
            Err(e) => {
                tracing::error!(error = %e, "TLS certificate reload failed; keeping the previous one");
                false
            }
        }
    }

    pub fn spawn_watcher(self: &Arc<Self>) {
        let me = self.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(60)).await;
                me.reload_if_changed();
            }
        });
    }
}

/// Serve `app` over HTTPS (HTTP/1.1 and h2) until `shutdown` resolves. Each connection gets its
/// peer address as `ConnectInfo`, like the plain-HTTP server.
pub async fn serve_tls(
    listener: tokio::net::TcpListener,
    app: axum::Router,
    tls: Arc<TlsSource>,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
) -> std::io::Result<()> {
    use hyper_util::rt::{TokioExecutor, TokioIo};
    use hyper_util::service::TowerToHyperService;
    use tower::ServiceExt;

    tokio::pin!(shutdown);
    let tasks = tokio_util_free::Tracker::default();
    loop {
        let (tcp, peer) = tokio::select! {
            r = listener.accept() => match r {
                Ok(c) => c,
                Err(e) => { tracing::warn!(error = %e, "accept failed"); continue; }
            },
            _ = &mut shutdown => break,
        };
        let acceptor = tokio_rustls::TlsAcceptor::from(tls.config());
        let app = app.clone();
        let guard = tasks.enter();
        tokio::spawn(async move {
            let _guard = guard;
            let stream =
                match tokio::time::timeout(Duration::from_secs(10), acceptor.accept(tcp)).await {
                    Ok(Ok(s)) => s,
                    Ok(Err(e)) => {
                        tracing::debug!(%peer, error = %e, "TLS handshake failed");
                        return;
                    }
                    Err(_) => return, // slow handshake
                };
            let svc = app
                .layer(axum::Extension(axum::extract::ConnectInfo(peer)))
                .map_request(|r: hyper::Request<hyper::body::Incoming>| {
                    r.map(axum::body::Body::new)
                });
            let _ = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new())
                .serve_connection_with_upgrades(TokioIo::new(stream), TowerToHyperService::new(svc))
                .await;
        });
    }
    // graceful: wait (bounded) for in-flight connections
    tasks.wait(Duration::from_secs(10)).await;
    Ok(())
}

/// Tiny in-flight counter (avoids a dependency for graceful shutdown).
mod tokio_util_free {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::{Duration, Instant};

    #[derive(Default, Clone)]
    pub struct Tracker(Arc<AtomicUsize>);
    pub struct Guard(Arc<AtomicUsize>);
    impl Drop for Guard {
        fn drop(&mut self) {
            self.0.fetch_sub(1, Ordering::SeqCst);
        }
    }
    impl Tracker {
        pub fn enter(&self) -> Guard {
            self.0.fetch_add(1, Ordering::SeqCst);
            Guard(self.0.clone())
        }
        pub async fn wait(&self, max: Duration) {
            let t0 = Instant::now();
            while self.0.load(Ordering::SeqCst) > 0 && t0.elapsed() < max {
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pem(dir: &Path, name: &str) -> (PathBuf, PathBuf) {
        let ck = rcgen::generate_simple_self_signed(vec![name.to_string()]).unwrap();
        let (c, k) = (
            dir.join(format!("{name}.crt")),
            dir.join(format!("{name}.key")),
        );
        std::fs::write(&c, ck.cert.pem()).unwrap();
        std::fs::write(&k, ck.signing_key.serialize_pem()).unwrap();
        (c, k)
    }

    #[test]
    fn loads_reloads_and_keeps_the_old_certificate_on_a_bad_file() {
        let d = std::env::temp_dir().join(format!("hyg-tls-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        let (c, k) = pem(&d, "a.test");
        let src = TlsSource::load(&c, &k, &["h2", "http/1.1"]).unwrap();
        let first = src.config();
        assert_eq!(
            first.alpn_protocols,
            vec![b"h2".to_vec(), b"http/1.1".to_vec()]
        );
        assert!(!src.reload_if_changed(), "unchanged files are not reloaded");

        std::thread::sleep(Duration::from_millis(1100)); // mtime granularity
        let (c2, k2) = pem(&d, "b.test");
        std::fs::copy(&c2, &c).unwrap();
        std::fs::copy(&k2, &k).unwrap();
        assert!(src.reload_if_changed());
        assert!(
            !Arc::ptr_eq(&first, &src.config()),
            "new certificate in use"
        );

        let good = src.config();
        std::thread::sleep(Duration::from_millis(1100));
        std::fs::write(&c, "garbage").unwrap();
        assert!(!src.reload_if_changed());
        assert!(
            Arc::ptr_eq(&good, &src.config()),
            "a broken file keeps the previous certificate"
        );

        assert!(TlsSource::load(&d.join("missing.crt"), &k, &[]).is_err());
        let _ = std::fs::remove_dir_all(d);
    }

    #[tokio::test]
    async fn serves_https_with_the_peer_address_and_drains_on_shutdown() {
        use axum::extract::ConnectInfo;
        let d = std::env::temp_dir().join(format!("hyg-tls-serve-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        let (c, k) = pem(&d, "a.test");
        let tls = TlsSource::load(&c, &k, &["h2", "http/1.1"]).unwrap();
        let app =
            axum::Router::new().route(
                "/ip",
                axum::routing::get(
                    |ConnectInfo(a): ConnectInfo<std::net::SocketAddr>| async move {
                        a.ip().to_string()
                    },
                ),
            );
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        let server = tokio::spawn(serve_tls(l, app, tls, async move {
            let _ = rx.await;
        }));
        let cert = reqwest::Certificate::from_pem(&std::fs::read(&c).unwrap()).unwrap();
        let client = reqwest::Client::builder()
            .no_proxy()
            .add_root_certificate(cert)
            .resolve("a.test", addr)
            .build()
            .unwrap();
        let body = client
            .get(format!("https://a.test:{}/ip", addr.port()))
            .send()
            .await
            .unwrap()
            .text()
            .await
            .unwrap();
        assert_eq!(body, "127.0.0.1");
        // plain HTTP against the TLS port gets nothing useful (and does not hang the server)
        assert!(
            reqwest::get(format!("http://127.0.0.1:{}/ip", addr.port()))
                .await
                .is_err()
        );
        // an untrusted client is refused
        assert!(
            reqwest::Client::builder()
                .resolve("a.test", addr)
                .build()
                .unwrap()
                .get(format!("https://a.test:{}/ip", addr.port()))
                .send()
                .await
                .is_err()
        );
        drop(client);
        tx.send(()).unwrap();
        server.await.unwrap().unwrap();
        let _ = std::fs::remove_dir_all(d);
    }
}
