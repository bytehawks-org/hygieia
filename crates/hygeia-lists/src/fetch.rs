use std::time::Duration;

use async_trait::async_trait;

#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum FetchError {
    #[error("http status {0}")]
    Status(u16),
    #[error("response larger than {0} bytes")]
    TooLarge(usize),
    #[error("insecure url (https required)")]
    Insecure,
    #[error("transport error: {0}")]
    Transport(String),
}

/// Cache validators from a previous successful fetch.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Validators {
    pub etag: Option<String>,
    pub last_modified: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fetched {
    /// `None` = 304 Not Modified.
    pub body: Option<String>,
    pub validators: Validators,
}

#[async_trait]
pub trait Fetch: Send + Sync {
    async fn get(&self, url: &str, v: &Validators) -> Result<Fetched, FetchError>;
}

pub struct HttpFetcher {
    client: reqwest::Client,
    max_bytes: usize,
    allow_http: bool,
}

impl HttpFetcher {
    /// `max_bytes` bounds memory per list. `allow_http` is for tests only.
    pub fn new(max_bytes: usize, allow_http: bool) -> Result<Self, FetchError> {
        let policy = reqwest::redirect::Policy::custom(move |a| {
            if a.previous().len() >= 5 {
                a.error("too many redirects")
            } else if !allow_http && a.url().scheme() != "https" {
                a.error("redirect to non-https url")
            } else {
                a.follow()
            }
        });
        let client = reqwest::Client::builder()
            .user_agent(concat!("hygeia-lists/", env!("CARGO_PKG_VERSION")))
            .timeout(Duration::from_secs(120))
            .connect_timeout(Duration::from_secs(15))
            .redirect(policy)
            .build()
            .map_err(|e| FetchError::Transport(e.to_string()))?;
        Ok(Self {
            client,
            max_bytes,
            allow_http,
        })
    }
}

#[async_trait]
impl Fetch for HttpFetcher {
    async fn get(&self, url: &str, v: &Validators) -> Result<Fetched, FetchError> {
        if !url.starts_with("https://") && !(self.allow_http && url.starts_with("http://")) {
            return Err(FetchError::Insecure);
        }
        let mut req = self.client.get(url);
        if let Some(e) = &v.etag {
            req = req.header(reqwest::header::IF_NONE_MATCH, e);
        }
        if let Some(m) = &v.last_modified {
            req = req.header(reqwest::header::IF_MODIFIED_SINCE, m);
        }
        let mut resp = req
            .send()
            .await
            .map_err(|e| FetchError::Transport(e.to_string()))?;
        let status = resp.status();
        let hdr = |n| {
            resp.headers()
                .get(n)
                .and_then(|h| h.to_str().ok())
                .map(str::to_string)
        };
        let validators = Validators {
            etag: hdr(reqwest::header::ETAG),
            last_modified: hdr(reqwest::header::LAST_MODIFIED),
        };
        if status == reqwest::StatusCode::NOT_MODIFIED {
            return Ok(Fetched {
                body: None,
                validators: v.clone(),
            });
        }
        if !status.is_success() {
            return Err(FetchError::Status(status.as_u16()));
        }
        if resp
            .content_length()
            .is_some_and(|l| l as usize > self.max_bytes)
        {
            return Err(FetchError::TooLarge(self.max_bytes));
        }
        let mut buf: Vec<u8> = Vec::new();
        while let Some(chunk) = resp
            .chunk()
            .await
            .map_err(|e| FetchError::Transport(e.to_string()))?
        {
            if buf.len() + chunk.len() > self.max_bytes {
                return Err(FetchError::TooLarge(self.max_bytes));
            }
            buf.extend_from_slice(&chunk);
        }
        Ok(Fetched {
            body: Some(String::from_utf8_lossy(&buf).into_owned()),
            validators,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::Router;
    use axum::http::{HeaderMap, StatusCode, header};
    use axum::routing::get;

    async fn serve() -> String {
        async fn list(
            h: HeaderMap,
        ) -> (
            StatusCode,
            [(header::HeaderName, &'static str); 1],
            &'static str,
        ) {
            if h.get(header::IF_NONE_MATCH).is_some_and(|v| v == "\"v1\"") {
                return (StatusCode::NOT_MODIFIED, [(header::ETAG, "\"v1\"")], "");
            }
            (
                StatusCode::OK,
                [(header::ETAG, "\"v1\"")],
                "0.0.0.0 ads.test\n",
            )
        }
        let app = Router::new()
            .route("/list", get(list))
            .route("/big", get(|| async { "x".repeat(10_000) }))
            .route("/missing", get(|| async { StatusCode::NOT_FOUND }));
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
        format!("http://{addr}")
    }

    #[tokio::test]
    async fn etag_cap_status_and_https_only() {
        let base = serve().await;
        let f = HttpFetcher::new(1024, true).unwrap();
        let first = f
            .get(&format!("{base}/list"), &Validators::default())
            .await
            .unwrap();
        assert_eq!(first.body.as_deref(), Some("0.0.0.0 ads.test\n"));
        assert_eq!(first.validators.etag.as_deref(), Some("\"v1\""));
        let second = f
            .get(&format!("{base}/list"), &first.validators)
            .await
            .unwrap();
        assert!(second.body.is_none());
        assert_eq!(
            f.get(&format!("{base}/big"), &Validators::default()).await,
            Err(FetchError::TooLarge(1024))
        );
        assert_eq!(
            f.get(&format!("{base}/missing"), &Validators::default())
                .await,
            Err(FetchError::Status(404))
        );

        let strict = HttpFetcher::new(1024, false).unwrap();
        assert_eq!(
            strict
                .get(&format!("{base}/list"), &Validators::default())
                .await,
            Err(FetchError::Insecure)
        );
    }
}
