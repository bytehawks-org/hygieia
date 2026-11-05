//! Cloud DNS over HTTPS (RFC 8484) at `/dns-query/<token>`.
//!
//! * **Never an open resolver:** the token in the path is the only way a query is attributed to a
//!   tenant and group. Unknown, revoked or expired token = 404, nothing is resolved.
//! * The path *is* a credential: it is never logged here; reverse proxies must redact it.
//! * Per-token token-bucket rate limit; positive and negative caching of token lookups so that a
//!   flood of garbage tokens does not turn into a flood of database queries.
//! * TLS is terminated in front of the server (the API speaks plain HTTP).

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use hygeia_core::{Ruleset, SignedBundle};
use hygeia_dns::{BlockMode, Decision, decide, forward_udp, servfail};
use hygeia_store::{DnsToken, hash_secret};

use crate::state::{AppState, now};

const TOKEN_TTL: Duration = Duration::from_secs(30);
const NEGATIVE_TTL: Duration = Duration::from_secs(10);
const RULES_TTL: Duration = Duration::from_secs(5);
const MAX_CACHE: usize = 10_000;
pub const MAX_QUERY: usize = 4096;

#[derive(Debug, Clone)]
pub struct DnsServiceConfig {
    pub upstream: SocketAddr,
    pub block_mode: BlockMode,
    pub rate_per_sec: f64,
    pub burst: f64,
    /// No usable bundle for the tenant: answer anyway (open) instead of SERVFAIL (closed, default).
    pub fail_open: bool,
    pub upstream_timeout: Duration,
}

impl DnsServiceConfig {
    pub fn new(upstream: SocketAddr) -> Self {
        Self {
            upstream,
            block_mode: BlockMode::NxDomain,
            rate_per_sec: 50.0,
            burst: 100.0,
            fail_open: false,
            upstream_timeout: Duration::from_secs(3),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum DohError {
    /// Unknown, revoked or expired token (also: service disabled).
    NotFound,
    RateLimited,
    BadRequest,
}

#[derive(Default)]
pub struct Counters {
    pub queries: AtomicU64,
    pub blocked: AtomicU64,
    pub forwarded: AtomicU64,
    pub auth_failures: AtomicU64,
    pub rate_limited: AtomicU64,
    pub servfail: AtomicU64,
}

struct Bucket {
    tokens: f64,
    at: Instant,
}

type AuthCache = HashMap<[u8; 32], (Option<DnsToken>, Instant)>;
type RulesCache = HashMap<(String, String), (String, Arc<Ruleset>, Instant)>;

pub struct DnsService {
    cfg: DnsServiceConfig,
    auth: Mutex<AuthCache>,
    rules: Mutex<RulesCache>,
    buckets: Mutex<HashMap<String, Bucket>>,
    pub counters: Counters,
}

impl DnsService {
    pub fn new(cfg: DnsServiceConfig) -> Self {
        Self {
            cfg,
            auth: Mutex::new(HashMap::new()),
            rules: Mutex::new(HashMap::new()),
            buckets: Mutex::new(HashMap::new()),
            counters: Counters::default(),
        }
    }

    /// Forget cached token lookups (called on local revocation; other replicas lag by `TOKEN_TTL`).
    pub fn clear_auth_cache(&self) {
        self.auth.lock().unwrap().clear();
    }

    async fn token(&self, st: &AppState, secret: &str) -> Option<DnsToken> {
        let h = hash_secret(secret);
        if let Some((t, at)) = self.auth.lock().unwrap().get(&h) {
            let ttl = if t.is_some() { TOKEN_TTL } else { NEGATIVE_TTL };
            if at.elapsed() < ttl {
                return t.clone();
            }
        }
        let t = match st.store.authenticate_dns_token(secret, now()).await {
            Ok(t) => t,
            Err(e) => {
                tracing::error!(error = %e, "dns token lookup failed");
                return None;
            }
        };
        let mut c = self.auth.lock().unwrap();
        if c.len() >= MAX_CACHE {
            c.clear();
        }
        c.insert(h, (t.clone(), Instant::now()));
        t
    }

    fn allow(&self, id: &str) -> bool {
        let mut b = self.buckets.lock().unwrap();
        if b.len() >= MAX_CACHE {
            b.clear();
        }
        let e = b.entry(id.to_string()).or_insert(Bucket {
            tokens: self.cfg.burst,
            at: Instant::now(),
        });
        let dt = e.at.elapsed().as_secs_f64();
        e.at = Instant::now();
        e.tokens = (e.tokens + dt * self.cfg.rate_per_sec).min(self.cfg.burst);
        if e.tokens >= 1.0 {
            e.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    async fn ruleset(&self, st: &AppState, tenant: &str, group: &str) -> Option<Arc<Ruleset>> {
        let key = (tenant.to_string(), group.to_string());
        if let Some((_, rs, at)) = self.rules.lock().unwrap().get(&key)
            && at.elapsed() < RULES_TTL
        {
            return Some(rs.clone());
        }
        let b = match st.bundle_for(tenant, group).await {
            Ok(b) => b,
            Err(e) => {
                tracing::error!(error = %e, "no bundle for the dns service");
                return self
                    .rules
                    .lock()
                    .unwrap()
                    .get(&key)
                    .map(|(_, r, _)| r.clone());
            }
        };
        let etag = b.etag();
        if let Some((e, rs, at)) = self.rules.lock().unwrap().get_mut(&key)
            && *e == etag
        {
            *at = Instant::now();
            return Some(rs.clone());
        }
        let vk = st.signing_key.verifying_key();
        let bytes = b.0.clone();
        let rs = tokio::task::spawn_blocking(move || {
            SignedBundle::open(&bytes, &vk)
                .ok()
                .map(|b| Arc::new(Ruleset::from_data(&b.network)))
        })
        .await
        .ok()
        .flatten()?;
        self.rules
            .lock()
            .unwrap()
            .insert(key, (etag, rs.clone(), Instant::now()));
        Some(rs)
    }

    /// Resolve one wire-format query on behalf of the token's tenant/group.
    pub async fn answer(
        &self,
        st: &AppState,
        secret: &str,
        packet: &[u8],
    ) -> Result<Vec<u8>, DohError> {
        let Some(tok) = self.token(st, secret).await else {
            self.counters.auth_failures.fetch_add(1, Ordering::Relaxed);
            return Err(DohError::NotFound);
        };
        if packet.is_empty() || packet.len() > MAX_QUERY {
            return Err(DohError::BadRequest);
        }
        if !self.allow(&tok.id) {
            self.counters.rate_limited.fetch_add(1, Ordering::Relaxed);
            return Err(DohError::RateLimited);
        }
        self.counters.queries.fetch_add(1, Ordering::Relaxed);
        let forward = async {
            match forward_udp(packet, self.cfg.upstream, self.cfg.upstream_timeout).await {
                Ok(b) => {
                    self.counters.forwarded.fetch_add(1, Ordering::Relaxed);
                    b
                }
                Err(e) => {
                    tracing::warn!(error = %e, "dns upstream failure");
                    self.counters.servfail.fetch_add(1, Ordering::Relaxed);
                    servfail(packet)
                }
            }
        };
        let Some(rs) = self.ruleset(st, &tok.tenant_id, &tok.group_id).await else {
            return Ok(if self.cfg.fail_open {
                forward.await
            } else {
                self.counters.servfail.fetch_add(1, Ordering::Relaxed);
                servfail(packet)
            });
        };
        match decide(&rs, packet, self.cfg.block_mode).0 {
            Decision::Answer(b) if b.is_empty() => Err(DohError::BadRequest),
            Decision::Answer(b) => {
                self.counters.blocked.fetch_add(1, Ordering::Relaxed);
                Ok(b)
            }
            Decision::Forward => Ok(forward.await),
        }
    }
}
