//! Static admin UI (Next.js `output: 'export'`) served by the API process, so a
//! single-org install needs no Node at runtime.
//!
//! The UI gets a strict Content-Security-Policy WITHOUT `'unsafe-inline'` for
//! scripts: Next's static export emits inline bootstrap scripts, so their
//! SHA-256 hashes are computed from the built HTML at startup and allow-listed.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use axum::extract::Request;
use axum::http::{HeaderValue, header};
use axum::middleware::Next;
use axum::response::Response;
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use sha2::{Digest, Sha256};
use tower_http::services::{ServeDir, ServeFile};

#[derive(Clone)]
pub struct Ui {
    pub dir: PathBuf,
    csp: HeaderValue,
}

/// SHA-256 CSP source expressions for every executable inline `<script>` in `html`.
pub fn inline_script_hashes(html: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = html;
    while let Some(i) = rest.find("<script") {
        let after = &rest[i..];
        let Some(tag_end) = after.find('>') else {
            break;
        };
        let tag = &after[..tag_end];
        let body_start = tag_end + 1;
        let Some(close) = after[body_start..].find("</script>") else {
            break;
        };
        let body = &after[body_start..body_start + close];
        let external = tag.contains(" src=") || tag.contains("\tsrc=");
        let data_block = tag.contains("application/json") || tag.contains("application/ld+json");
        if !external && !data_block && !body.is_empty() {
            out.push(format!(
                "'sha256-{}'",
                STANDARD.encode(Sha256::digest(body.as_bytes()))
            ));
        }
        rest = &after[body_start + close + "</script>".len()..];
    }
    out
}

fn collect_html(dir: &Path, out: &mut Vec<PathBuf>) -> std::io::Result<()> {
    for e in std::fs::read_dir(dir)? {
        let p = e?.path();
        if p.is_dir() {
            collect_html(&p, out)?;
        } else if p.extension().is_some_and(|x| x == "html") {
            out.push(p);
        }
    }
    Ok(())
}

impl Ui {
    /// `connect_src`: extra origins the UI may call (the OIDC provider for the PKCE flow).
    pub fn load(dir: impl Into<PathBuf>, connect_src: &[String]) -> std::io::Result<Self> {
        let dir = dir.into();
        if !dir.join("index.html").is_file() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("{}: no index.html (is the UI built?)", dir.display()),
            ));
        }
        let mut files = Vec::new();
        collect_html(&dir, &mut files)?;
        let mut hashes = BTreeSet::new();
        for f in files {
            hashes.extend(inline_script_hashes(&std::fs::read_to_string(f)?));
        }
        let scripts = hashes.into_iter().collect::<Vec<_>>().join(" ");
        let connect = std::iter::once("'self'".to_string())
            .chain(connect_src.iter().cloned())
            .collect::<Vec<_>>()
            .join(" ");
        let csp = format!(
            "default-src 'none'; script-src 'self' {scripts}; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; \
             connect-src {connect}; base-uri 'none'; form-action 'self'; frame-ancestors 'none'; object-src 'none'"
        );
        let csp = HeaderValue::from_str(&csp)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        Ok(Self { dir, csp })
    }

    pub fn csp(&self) -> &str {
        self.csp.to_str().unwrap_or_default()
    }

    pub fn service(&self) -> ServeDir<tower_http::set_status::SetStatus<ServeFile>> {
        ServeDir::new(&self.dir)
            .append_index_html_on_directories(true)
            .not_found_service(ServeFile::new(self.dir.join("404.html")))
    }
}

/// Security + cache headers for UI responses.
pub async fn headers(
    axum::extract::State(ui): axum::extract::State<Ui>,
    req: Request,
    next: Next,
) -> Response {
    let immutable = req.uri().path().starts_with("/_next/static/");
    let mut resp = next.run(req).await;
    let h = resp.headers_mut();
    h.insert(header::CONTENT_SECURITY_POLICY, ui.csp.clone());
    h.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    h.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    h.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    h.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static(if immutable {
            "public, max-age=31536000, immutable"
        } else {
            "no-cache"
        }),
    );
    resp
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hashes_inline_scripts_only() {
        let html = r#"<html><script src="/a.js"></script><script>self.x=1</script>
<script type="application/json">{"a":1}</script><script async src="/b.js"></script><script nonce="x">y()</script></html>"#;
        let h = inline_script_hashes(html);
        assert_eq!(h.len(), 2);
        // sha256("self.x=1") base64
        let expect = format!("'sha256-{}'", STANDARD.encode(Sha256::digest(b"self.x=1")));
        assert_eq!(h[0], expect);
    }

    #[test]
    fn load_requires_built_ui_and_builds_csp() {
        let dir = std::env::temp_dir().join(format!("hygeia-ui-{}", std::process::id()));
        std::fs::create_dir_all(dir.join("rules")).unwrap();
        assert!(Ui::load(&dir, &[]).is_err());
        std::fs::write(dir.join("index.html"), "<script>a()</script>").unwrap();
        std::fs::write(
            dir.join("rules/index.html"),
            "<script>b()</script><script>a()</script>",
        )
        .unwrap();
        let ui = Ui::load(&dir, &["https://idp.example.com".into()]).unwrap();
        let csp = ui.csp();
        assert!(csp.contains("script-src 'self' 'sha256-"));
        assert!(!csp.contains("script-src 'self' 'unsafe-inline'") && !csp.contains("unsafe-eval"));
        assert_eq!(
            csp.matches("'sha256-").count(),
            2,
            "deduplicated across pages"
        );
        assert!(csp.contains("connect-src 'self' https://idp.example.com"));
        assert!(csp.contains("frame-ancestors 'none'"));
        std::fs::remove_dir_all(dir).ok();
    }
}
