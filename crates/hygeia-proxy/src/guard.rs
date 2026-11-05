//! Protection of a local admin port against browsers acting on behalf of a web page.
//!
//! * **Host allow-list** (DNS rebinding): a malicious site can point `evil.example` at 127.0.0.1;
//!   the browser then sends `Host: evil.example` and treats the node as same-origin with that site.
//!   Rejecting unknown `Host` values closes that attack.
//! * **Origin check** on state-changing requests: a cross-site `Origin` is refused, except the
//!   browser-extension contract endpoints (`/v1/enroll`, `/v1/bundle`, `/v1/pubkey`), which are
//!   called by `chrome-extension://` / `moz-extension://` origins and authenticate with bearer
//!   credentials, never cookies.

use std::sync::Arc;

use axum::extract::{Request, State};
use axum::http::{Method, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

#[derive(Clone)]
pub struct HostGuard {
    allowed: Arc<Vec<String>>,
}

const EXTENSION_PATHS: [&str; 3] = ["/v1/enroll", "/v1/bundle", "/v1/pubkey"];

impl HostGuard {
    /// `listen` is the bound socket address; loopback listeners accept the usual local names.
    pub fn new(listen: std::net::SocketAddr, extra: &[String]) -> Self {
        let port = listen.port();
        let mut allowed: Vec<String> = Vec::new();
        if listen.ip().is_loopback() {
            allowed.extend([
                format!("127.0.0.1:{port}"),
                format!("localhost:{port}"),
                format!("[::1]:{port}"),
            ]);
        }
        allowed.extend(extra.iter().map(|h| h.to_ascii_lowercase()));
        Self {
            allowed: Arc::new(allowed),
        }
    }

    fn host_ok(&self, host: &str) -> bool {
        let h = host.to_ascii_lowercase();
        self.allowed.contains(&h)
    }
}

pub async fn enforce(State(g): State<HostGuard>, req: Request, next: Next) -> Response {
    let host = req
        .headers()
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if !g.host_ok(host) {
        return (StatusCode::MISDIRECTED_REQUEST, "unexpected Host header").into_response();
    }
    let safe_method = matches!(*req.method(), Method::GET | Method::HEAD | Method::OPTIONS);
    if !safe_method
        && let Some(origin) = req
            .headers()
            .get(header::ORIGIN)
            .and_then(|v| v.to_str().ok())
    {
        let same_origin = origin.eq_ignore_ascii_case(&format!("http://{host}"))
            || origin.eq_ignore_ascii_case(&format!("https://{host}"));
        let extension = (origin.starts_with("chrome-extension://")
            || origin.starts_with("moz-extension://"))
            && EXTENSION_PATHS.contains(&req.uri().path());
        if !same_origin && !extension {
            return (StatusCode::FORBIDDEN, "cross-origin request refused").into_response();
        }
    }
    next.run(req).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::Router;
    use axum::body::Body;
    use axum::routing::{get, post};
    use tower::ServiceExt;

    fn app() -> Router {
        let g = HostGuard::new(
            "127.0.0.1:8470".parse().unwrap(),
            &["pc.lan:8470".to_string()],
        );
        Router::new()
            .route("/ok", get(|| async { "ok" }).post(|| async { "ok" }))
            .route("/v1/enroll", post(|| async { "ok" }))
            .layer(axum::middleware::from_fn_with_state(g, enforce))
    }

    async fn status(
        method: &str,
        uri: &str,
        host: Option<&str>,
        origin: Option<&str>,
    ) -> StatusCode {
        let mut r = Request::builder().method(method).uri(uri);
        if let Some(h) = host {
            r = r.header("host", h);
        }
        if let Some(o) = origin {
            r = r.header("origin", o);
        }
        app()
            .oneshot(r.body(Body::empty()).unwrap())
            .await
            .unwrap()
            .status()
    }

    #[tokio::test]
    async fn host_header_allow_list_blocks_dns_rebinding() {
        assert_eq!(
            status("GET", "/ok", Some("127.0.0.1:8470"), None).await,
            StatusCode::OK
        );
        assert_eq!(
            status("GET", "/ok", Some("localhost:8470"), None).await,
            StatusCode::OK
        );
        assert_eq!(
            status("GET", "/ok", Some("[::1]:8470"), None).await,
            StatusCode::OK
        );
        assert_eq!(
            status("GET", "/ok", Some("PC.LAN:8470"), None).await,
            StatusCode::OK,
            "configured host, case-insensitive"
        );
        assert_eq!(
            status("GET", "/ok", Some("evil.example:8470"), None).await,
            StatusCode::MISDIRECTED_REQUEST
        );
        assert_eq!(
            status("GET", "/ok", Some("127.0.0.1:9999"), None).await,
            StatusCode::MISDIRECTED_REQUEST,
            "wrong port"
        );
        assert_eq!(
            status("GET", "/ok", None, None).await,
            StatusCode::MISDIRECTED_REQUEST,
            "no Host"
        );
    }

    #[tokio::test]
    async fn origin_check_on_state_changing_requests() {
        let h = Some("127.0.0.1:8470");
        assert_eq!(
            status("POST", "/ok", h, None).await,
            StatusCode::OK,
            "no Origin (curl, CLI)"
        );
        assert_eq!(
            status("POST", "/ok", h, Some("http://127.0.0.1:8470")).await,
            StatusCode::OK,
            "same origin (the UI)"
        );
        assert_eq!(
            status("POST", "/ok", h, Some("https://evil.example")).await,
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            status("POST", "/ok", h, Some("chrome-extension://abc")).await,
            StatusCode::FORBIDDEN,
            "extension origin only on its contract paths"
        );
        assert_eq!(
            status("POST", "/v1/enroll", h, Some("chrome-extension://abc")).await,
            StatusCode::OK
        );
        assert_eq!(
            status("POST", "/v1/enroll", h, Some("moz-extension://abc")).await,
            StatusCode::OK
        );
        assert_eq!(
            status("POST", "/v1/enroll", h, Some("https://evil.example")).await,
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            status("GET", "/ok", h, Some("https://evil.example")).await,
            StatusCode::OK,
            "reads are not state-changing"
        );
    }
}
