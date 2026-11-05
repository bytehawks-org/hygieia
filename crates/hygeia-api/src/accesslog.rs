//! Optional access log that never records credentials: the DNS token in `/dns-query/<token>` and
//! `/v1/dns/link/<token>` is replaced before anything is written, and query strings are dropped
//! (`?dns=` carries the DNS message, and tokens must never travel in a query string anyway).

use axum::extract::Request;
use axum::middleware::Next;
use axum::response::Response;

/// Path with secret segments replaced by `<redacted>`.
pub fn redact_path(path: &str) -> String {
    let mut parts: Vec<&str> = path.split('/').collect();
    // ["", "dns-query", TOKEN, ...]  and  ["", "v1", "dns", "link", TOKEN, ...]
    let secret_at = match parts.as_slice() {
        ["", "dns-query", _, ..] => Some(2),
        ["", "v1", "dns", "link", _, ..] => Some(4),
        _ => None,
    };
    if let Some(i) = secret_at {
        parts[i] = "<redacted>";
    }
    parts.join("/")
}

pub async fn log_requests(req: Request, next: Next) -> Response {
    let method = req.method().clone();
    let path = redact_path(req.uri().path());
    let t0 = std::time::Instant::now();
    let resp = next.run(req).await;
    tracing::info!(
        target: "access",
        %method,
        %path,
        status = resp.status().as_u16(),
        ms = t0.elapsed().as_millis() as u64,
        "request"
    );
    resp
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credentials_never_reach_the_log() {
        assert_eq!(
            redact_path("/dns-query/hyg_dns_SECRET"),
            "/dns-query/<redacted>"
        );
        assert_eq!(
            redact_path("/dns-query/hyg_dns_SECRET/"),
            "/dns-query/<redacted>/"
        );
        assert_eq!(
            redact_path("/v1/dns/link/hyg_dns_SECRET"),
            "/v1/dns/link/<redacted>"
        );
        assert_eq!(redact_path("/v1/admin/rules"), "/v1/admin/rules");
        assert_eq!(redact_path("/"), "/");
        assert_eq!(redact_path("/dns-query"), "/dns-query");
    }
}
