//! Cloud DNS over HTTPS (RFC 8484) at `/dns-query/<token>`.
//!
//! * **Never an open resolver:** the token in the path is the only way a query is attributed to a
//!   tenant and group. Unknown, revoked or expired token = 404, nothing is resolved.
//! * The path *is* a credential: it is never logged here; reverse proxies must redact it.
//! * Per-token token-bucket rate limit; positive and negative caching of token lookups so that a
//!   flood of garbage tokens does not turn into a flood of database queries.
//! * TLS is terminated in front of the server (the API speaks plain HTTP).

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use hygeia_core::{Ruleset, SignedBundle};
use hygeia_dns::{BlockMode, Decision, decide, forward_udp, question, servfail};
use hygeia_store::{DnsSettings, DnsToken, QueryLogEntry, hash_secret};
use sha2::{Digest, Sha256};
use tokio::sync::mpsc;

use crate::state::{AppState, now};

const TOKEN_TTL: Duration = Duration::from_secs(30);
const NEGATIVE_TTL: Duration = Duration::from_secs(10);
const RULES_TTL: Duration = Duration::from_secs(5);
const SETTINGS_TTL: Duration = Duration::from_secs(10);
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
    /// Master secret for client pseudonyms (`HYGEIA_LOG_KEY`). Random per process if not set, which
    /// makes pseudonyms unlinkable across restarts (set it for stable daily pseudonyms).
    pub log_key: [u8; 32],
    /// Per source address (all transports): sustained queries/s and burst.
    pub ip_rate_per_sec: f64,
    pub ip_burst: f64,
    /// Failed authentications per source address: refill per second and burst.
    pub ip_fail_rate: f64,
    pub ip_fail_burst: f64,
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
            ip_rate_per_sec: 100.0,
            ip_burst: 200.0,
            ip_fail_rate: 0.5,
            ip_fail_burst: 20.0,
            log_key: {
                let mut k = [0u8; 32];
                getrandom::fill(&mut k).expect("OS randomness unavailable");
                k
            },
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
    pub log_dropped: AtomicU64,
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
    ip_buckets: Mutex<HashMap<IpAddr, Bucket>>,
    ip_fail: Mutex<HashMap<IpAddr, Bucket>>,
    settings: Mutex<HashMap<String, (DnsSettings, Instant)>>,
    log_tx: mpsc::Sender<(String, QueryLogEntry)>,
    log_rx: Mutex<Option<mpsc::Receiver<(String, QueryLogEntry)>>>,
    pub counters: Counters,
    pub metrics: DnsMetrics,
}

impl DnsService {
    /// Process-wide counters (also exported by the metrics endpoint).
    pub fn render_counters(&self, out: &mut String) {
        use std::fmt::Write;
        let c = &self.counters;
        for (name, help, v) in [
            (
                "hygeia_dns_auth_failures_total",
                "Queries with an unknown, expired or revoked token.",
                &c.auth_failures,
            ),
            (
                "hygeia_dns_rate_limited_total",
                "Queries refused by the rate limiter.",
                &c.rate_limited,
            ),
            (
                "hygeia_dns_upstream_servfail_total",
                "SERVFAIL answers (upstream failure or no bundle).",
                &c.servfail,
            ),
            (
                "hygeia_dns_query_log_dropped_total",
                "Query-log entries dropped because the writer queue was full.",
                &c.log_dropped,
            ),
        ] {
            let _ = writeln!(
                out,
                "# HELP {name} {help}\n# TYPE {name} counter\n{name} {}",
                v.load(Ordering::Relaxed)
            );
        }
        self.metrics.render(out);
    }

    pub fn new(cfg: DnsServiceConfig) -> Self {
        let (log_tx, log_rx) = mpsc::channel(8192);
        Self {
            cfg,
            auth: Mutex::new(HashMap::new()),
            rules: Mutex::new(HashMap::new()),
            buckets: Mutex::new(HashMap::new()),
            ip_buckets: Mutex::new(HashMap::new()),
            ip_fail: Mutex::new(HashMap::new()),
            settings: Mutex::new(HashMap::new()),
            log_tx,
            log_rx: Mutex::new(Some(log_rx)),
            counters: Counters::default(),
            metrics: DnsMetrics::default(),
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
        take(
            &self.buckets,
            id.to_string(),
            self.cfg.rate_per_sec,
            self.cfg.burst,
            1.0,
        )
    }

    /// Source-address key: IPv6 clients share a /64 (a host can rotate its interface identifier).
    fn ip_key(ip: IpAddr) -> IpAddr {
        match ip {
            IpAddr::V6(v) if v.to_ipv4_mapped().is_none() => {
                let mut o = v.octets();
                o[8..].fill(0);
                IpAddr::V6(o.into())
            }
            IpAddr::V6(v) => IpAddr::V4(v.to_ipv4_mapped().unwrap()),
            v4 => v4,
        }
    }

    /// Per-source limits shared by every transport: a general query budget, and a much smaller one
    /// that failed authentications draw from (slows token guessing from one address).
    pub fn allow_source(&self, ip: IpAddr) -> bool {
        let k = Self::ip_key(ip);
        // a spent failure budget blocks the source until it refills, whatever token it presents
        if self.ip_fail.lock().unwrap().get(&k).is_some_and(|b| {
            b.tokens < 1.0 && b.at.elapsed().as_secs_f64() * self.cfg.ip_fail_rate + b.tokens < 1.0
        }) {
            return false;
        }
        take(
            &self.ip_buckets,
            k,
            self.cfg.ip_rate_per_sec,
            self.cfg.ip_burst,
            1.0,
        )
    }

    fn note_auth_failure(&self, ip: IpAddr) {
        take(
            &self.ip_fail,
            Self::ip_key(ip),
            self.cfg.ip_fail_rate,
            self.cfg.ip_fail_burst,
            1.0,
        );
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

    /// Spawn the background task that batches log entries into the store. Call once.
    pub fn start_log_writer(&self, store: Arc<dyn hygeia_store::Store>) {
        let Some(mut rx) = self.log_rx.lock().unwrap().take() else {
            return;
        };
        tokio::spawn(async move {
            let mut buf: HashMap<String, Vec<QueryLogEntry>> = HashMap::new();
            let mut tick = tokio::time::interval(Duration::from_secs(1));
            loop {
                tokio::select! {
                    m = rx.recv() => match m {
                        Some((t, e)) => {
                            let v = buf.entry(t).or_default();
                            v.push(e);
                            if v.len() < 200 { continue; }
                        }
                        None => break,
                    },
                    _ = tick.tick() => {}
                }
                for (t, entries) in buf.drain() {
                    if let Err(e) = store.append_query_log(&t, &entries).await {
                        tracing::error!(error = %e, "query log write failed");
                    }
                }
            }
        });
    }

    /// Pseudonym of a client address: HMAC-SHA256 with a key derived from the master secret, the
    /// tenant and the UTC day, so the same client is stable within a day (statistics) but cannot be
    /// linked across days or tenants, nor reversed without the master secret. IPv6 is reduced to
    /// its /64 (interface identifiers rotate and identify a host).
    pub fn pseudonym(&self, tenant: &str, ip: IpAddr, now: i64) -> String {
        let day = (now / 86_400).to_string();
        let key = hmac(
            &self.cfg.log_key,
            format!("hygeia-ip-pseudonym-v1|{tenant}|{day}").as_bytes(),
        );
        let bytes: Vec<u8> = match ip {
            IpAddr::V4(v) => v.octets().to_vec(),
            IpAddr::V6(v) => v
                .to_ipv4_mapped()
                .map_or_else(|| v.octets()[..8].to_vec(), |m| m.octets().to_vec()),
        };
        hmac(&key, &bytes)[..8]
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }

    async fn settings(&self, st: &AppState, tenant: &str) -> DnsSettings {
        if let Some((s, at)) = self.settings.lock().unwrap().get(tenant)
            && at.elapsed() < SETTINGS_TTL
        {
            return s.clone();
        }
        let s = st.store.dns_settings(tenant).await.unwrap_or_default();
        let mut c = self.settings.lock().unwrap();
        if c.len() >= MAX_CACHE {
            c.clear();
        }
        c.insert(tenant.to_string(), (s.clone(), Instant::now()));
        s
    }

    /// Forget cached per-tenant settings (called after a local settings change).
    pub fn clear_settings_cache(&self) {
        self.settings.lock().unwrap().clear();
    }

    /// DoH entry: authenticate the token, rate-limit, then [`resolve`](Self::resolve).
    pub async fn answer(
        &self,
        st: &AppState,
        secret: &str,
        packet: &[u8],
        client: Option<IpAddr>,
    ) -> Result<Vec<u8>, DohError> {
        if let Some(ip) = client
            && !self.allow_source(ip)
        {
            self.counters.rate_limited.fetch_add(1, Ordering::Relaxed);
            return Err(DohError::RateLimited);
        }
        let Some(tok) = self.token(st, secret).await else {
            self.counters.auth_failures.fetch_add(1, Ordering::Relaxed);
            if let Some(ip) = client {
                self.note_auth_failure(ip);
            }
            return Err(DohError::NotFound);
        };
        if packet.is_empty() || packet.len() > MAX_QUERY {
            return Err(DohError::BadRequest);
        }
        if !self.allow(&tok.id) {
            self.counters.rate_limited.fetch_add(1, Ordering::Relaxed);
            return Err(DohError::RateLimited);
        }
        let ctx = QueryCtx {
            tenant: &tok.tenant_id,
            group: &tok.group_id,
            token_id: Some(&tok.id),
            transport: "doh",
            client,
        };
        self.resolve(st, &ctx, packet).await
    }

    /// Transport-independent resolution for an already attributed query (tenant + group known).
    pub async fn resolve(
        &self,
        st: &AppState,
        ctx: &QueryCtx<'_>,
        packet: &[u8],
    ) -> Result<Vec<u8>, DohError> {
        let t0 = Instant::now();
        let r = self.resolve_inner(st, ctx, packet).await;
        self.metrics.observe(t0.elapsed());
        match r {
            Ok((reply, outcome)) => {
                self.metrics.count(ctx.tenant, ctx.transport, outcome);
                Ok(reply)
            }
            Err(e) => Err(e),
        }
    }

    async fn resolve_inner(
        &self,
        st: &AppState,
        ctx: &QueryCtx<'_>,
        packet: &[u8],
    ) -> Result<(Vec<u8>, &'static str), DohError> {
        self.counters.queries.fetch_add(1, Ordering::Relaxed);
        let settings = self.settings(st, ctx.tenant).await;
        let fail_open = settings.fail_open.unwrap_or(self.cfg.fail_open);
        let mode = match settings.block_mode.as_deref() {
            Some("null_ip") => BlockMode::NullIp,
            Some(_) => BlockMode::NxDomain,
            None => self.cfg.block_mode,
        };
        let forward = async {
            match forward_udp(packet, self.cfg.upstream, self.cfg.upstream_timeout).await {
                Ok(b) => {
                    self.counters.forwarded.fetch_add(1, Ordering::Relaxed);
                    (b, "allowed")
                }
                Err(e) => {
                    tracing::warn!(error = %e, "dns upstream failure");
                    self.counters.servfail.fetch_add(1, Ordering::Relaxed);
                    (servfail(packet), "servfail")
                }
            }
        };
        let Some(rs) = self.ruleset(st, ctx.tenant, ctx.group).await else {
            return Ok(if fail_open {
                forward.await
            } else {
                self.counters.servfail.fetch_add(1, Ordering::Relaxed);
                (servfail(packet), "servfail")
            });
        };
        let (decision, logged) = decide(&rs, packet, mode);
        let (reply, outcome) = match decision {
            Decision::Answer(b) if b.is_empty() => return Err(DohError::BadRequest),
            Decision::Answer(b) => {
                self.counters.blocked.fetch_add(1, Ordering::Relaxed);
                (b, "blocked")
            }
            Decision::Forward => forward.await,
        };
        if settings.log_enabled
            && let Some((_, verdict)) = logged
            && let Some((qname, qtype)) = question(packet)
        {
            let ts = now();
            let entry = QueryLogEntry {
                ts,
                group_id: ctx.group.to_string(),
                token_id: ctx.token_id.map(str::to_string),
                transport: ctx.transport.to_string(),
                client: ctx
                    .client
                    .map_or_else(|| "-".to_string(), |ip| self.pseudonym(ctx.tenant, ip, ts)),
                qname,
                qtype,
                action: if outcome == "blocked" {
                    "block"
                } else {
                    "allow"
                }
                .to_string(),
                reason: format!("{:?}", verdict.reason),
            };
            if self
                .log_tx
                .try_send((ctx.tenant.to_string(), entry))
                .is_err()
            {
                self.counters.log_dropped.fetch_add(1, Ordering::Relaxed);
            }
        }
        Ok((reply, outcome))
    }
}

/// Take `cost` tokens from the bucket of `key` (refilled at `rate`/s up to `burst`).
fn take<K: std::hash::Hash + Eq>(
    map: &Mutex<HashMap<K, Bucket>>,
    key: K,
    rate: f64,
    burst: f64,
    cost: f64,
) -> bool {
    let mut b = map.lock().unwrap();
    if b.len() >= MAX_CACHE {
        b.clear();
    }
    let e = b.entry(key).or_insert(Bucket {
        tokens: burst,
        at: Instant::now(),
    });
    let dt = e.at.elapsed().as_secs_f64();
    e.at = Instant::now();
    e.tokens = (e.tokens + dt * rate).min(burst);
    if e.tokens >= cost {
        e.tokens -= cost;
        true
    } else {
        false
    }
}

/// Latency histogram bucket bounds in seconds.
const BUCKETS: [f64; 7] = [0.001, 0.005, 0.025, 0.1, 0.5, 2.0, 10.0];

/// Labelled counters and a latency histogram for the Prometheus endpoint. Labels are bounded:
/// tenant ids (as many as tenants), three transports, three outcomes.
#[derive(Default)]
pub struct DnsMetrics {
    by_label: Mutex<HashMap<(String, &'static str, &'static str), u64>>,
    hist: Mutex<([u64; 8], f64)>, // cumulative-ready bucket counts (last = +Inf), sum
}

impl DnsMetrics {
    fn count(&self, tenant: &str, transport: &'static str, outcome: &'static str) {
        *self
            .by_label
            .lock()
            .unwrap()
            .entry((tenant.to_string(), transport, outcome))
            .or_insert(0) += 1;
    }

    fn observe(&self, d: Duration) {
        let secs = d.as_secs_f64();
        let mut h = self.hist.lock().unwrap();
        let i = BUCKETS
            .iter()
            .position(|b| secs <= *b)
            .unwrap_or(BUCKETS.len());
        h.0[i] += 1;
        h.1 += secs;
    }

    /// Prometheus text exposition fragment.
    pub fn render(&self, out: &mut String) {
        use std::fmt::Write;
        let _ = writeln!(
            out,
            "# HELP hygeia_dns_queries_total DNS queries answered, by tenant, transport and outcome."
        );
        let _ = writeln!(out, "# TYPE hygeia_dns_queries_total counter");
        let mut rows: Vec<_> = self
            .by_label
            .lock()
            .unwrap()
            .iter()
            .map(|(k, v)| (k.clone(), *v))
            .collect();
        rows.sort();
        for ((t, tr, o), n) in rows {
            let _ = writeln!(
                out,
                "hygeia_dns_queries_total{{tenant=\"{t}\",transport=\"{tr}\",outcome=\"{o}\"}} {n}"
            );
        }
        let (counts, sum) = *self.hist.lock().unwrap();
        let _ = writeln!(
            out,
            "# HELP hygeia_dns_resolve_seconds Time to resolve a query (excludes TLS/HTTP handling)."
        );
        let _ = writeln!(out, "# TYPE hygeia_dns_resolve_seconds histogram");
        let mut cum = 0;
        for (i, b) in BUCKETS.iter().enumerate() {
            cum += counts[i];
            let _ = writeln!(out, "hygeia_dns_resolve_seconds_bucket{{le=\"{b}\"}} {cum}");
        }
        cum += counts[BUCKETS.len()];
        let _ = writeln!(
            out,
            "hygeia_dns_resolve_seconds_bucket{{le=\"+Inf\"}} {cum}"
        );
        let _ = writeln!(out, "hygeia_dns_resolve_seconds_sum {sum}");
        let _ = writeln!(out, "hygeia_dns_resolve_seconds_count {cum}");
    }
}

/// Who is asking, as established by the transport.
pub struct QueryCtx<'a> {
    pub tenant: &'a str,
    pub group: &'a str,
    pub token_id: Option<&'a str>,
    pub transport: &'static str,
    pub client: Option<IpAddr>,
}

fn hmac(key: &[u8], msg: &[u8]) -> [u8; 32] {
    let mut k = [0u8; 64];
    if key.len() > 64 {
        k[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let mut inner = Sha256::new();
    inner.update(k.map(|b| b ^ 0x36));
    inner.update(msg);
    let mut outer = Sha256::new();
    outer.update(k.map(|b| b ^ 0x5c));
    outer.update(inner.finalize());
    outer.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hmac_sha256_matches_rfc4231_case_2() {
        // key "Jefe", data "what do ya want for nothing?"
        let mac = hmac(b"Jefe", b"what do ya want for nothing?");
        let hex: String = mac.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(
            hex,
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
    }

    #[test]
    fn pseudonyms_are_stable_per_day_and_unlinkable_across_days_tenants_and_hosts() {
        let svc = DnsService::new(DnsServiceConfig::new("127.0.0.1:9".parse().unwrap()));
        let ip: IpAddr = "192.168.1.10".parse().unwrap();
        let d0 = 1_700_000_000;
        let p = svc.pseudonym("t1", ip, d0);
        assert_eq!(p.len(), 16);
        assert!(!p.contains("192"), "not the address");
        assert_eq!(
            p,
            svc.pseudonym("t1", ip, d0 + 3600),
            "same day, same client"
        );
        assert_ne!(p, svc.pseudonym("t1", ip, d0 + 86_400), "rotates daily");
        assert_ne!(p, svc.pseudonym("t2", ip, d0), "per tenant");
        assert_ne!(
            p,
            svc.pseudonym("t1", "192.168.1.11".parse().unwrap(), d0),
            "per client"
        );
        let a: IpAddr = "2001:db8:1:2::1".parse().unwrap();
        let b: IpAddr = "2001:db8:1:2::ffff".parse().unwrap();
        assert_eq!(
            svc.pseudonym("t1", a, d0),
            svc.pseudonym("t1", b, d0),
            "IPv6 reduced to /64"
        );
        let other = DnsService::new(DnsServiceConfig::new("127.0.0.1:9".parse().unwrap()));
        assert_ne!(
            p,
            other.pseudonym("t1", ip, d0),
            "depends on the master secret"
        );
    }
}
