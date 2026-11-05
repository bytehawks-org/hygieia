mod config;

use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use ed25519_dalek::SigningKey;
use hygeia_api::{
    AppState, AuthConfig, BreakGlass, DEFAULT_GROUP, DEFAULT_TENANT, OidcConfig, OidcVerifier,
};
use hygeia_core::{Ruleset, SignedBundle};
use hygeia_dns::{BlockMode, DnsConfig};
use hygeia_lists::{HttpFetcher, Manager};
use hygeia_store::{MemoryStore, PgStore, Store};

fn rand_hex(n: usize) -> String {
    let mut b = vec![0u8; n];
    getrandom::fill(&mut b).expect("OS randomness unavailable");
    b.iter().map(|x| format!("{x:02x}")).collect()
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let cfg: config::Config = match std::env::args().nth(1) {
        Some(path) => toml::from_str(&std::fs::read_to_string(path)?)?,
        None => config::Config::default(),
    };

    let signing_key = match std::env::var("HYGEIA_SIGNING_KEY") {
        Ok(h) if h.len() == 64 => {
            let mut seed = [0u8; 32];
            for (i, c) in h.as_bytes().chunks(2).enumerate() {
                seed[i] = u8::from_str_radix(std::str::from_utf8(c)?, 16)?;
            }
            SigningKey::from_bytes(&seed)
        }
        _ => {
            tracing::warn!(
                "HYGEIA_SIGNING_KEY (64 hex chars) not set; using an ephemeral signing key"
            );
            let mut seed = [0u8; 32];
            getrandom::fill(&mut seed).expect("OS randomness unavailable");
            SigningKey::from_bytes(&seed)
        }
    };

    // HYGEIA_DATABASE_URL: runtime role (non-owner, subject to RLS).
    // HYGEIA_MIGRATE_URL: schema owner; when set, migrations run at startup.
    let store: Arc<dyn Store> = match std::env::var("HYGEIA_DATABASE_URL") {
        Ok(url) => {
            if let Ok(owner) = std::env::var("HYGEIA_MIGRATE_URL") {
                PgStore::migrate(&owner).await?;
                tracing::info!("migrations applied");
            }
            Arc::new(PgStore::connect(&url).await?)
        }
        Err(_) => {
            tracing::warn!("HYGEIA_DATABASE_URL not set: using NON-PERSISTENT in-memory store");
            Arc::new(MemoryStore::new())
        }
    };
    store.bootstrap_default().await?;
    let auth = build_auth(&cfg, &store).await?;
    let state = Arc::new(AppState::new(store, signing_key, auth));

    // Data plane: DNS follows the control plane by pulling the signed bundle.
    if cfg.dns.enabled {
        let verifying = state.signing_key.verifying_key();
        let rules = Arc::new(ArcSwap::from_pointee(Ruleset::from_data(
            &Default::default(),
        )));
        let st = state.clone();
        let r2 = rules.clone();
        tokio::spawn(async move {
            let mut current = 0u64;
            loop {
                match st.bundle_for(DEFAULT_TENANT, DEFAULT_GROUP).await {
                    Ok(b) => {
                        if let Ok(bundle) = SignedBundle::open(&b.0, &verifying)
                            && bundle.meta.version != current
                        {
                            current = bundle.meta.version;
                            r2.store(Arc::new(Ruleset::from_data(&bundle.network)));
                            tracing::info!(version = current, "dns ruleset updated");
                        }
                    }
                    Err(e) => tracing::error!(error = %e, "bundle refresh failed"),
                }
                tokio::time::sleep(Duration::from_secs(5)).await;
            }
        });

        let upstream = cfg
            .dns
            .upstream
            .first()
            .ok_or("dns.upstream is empty")?
            .parse()?;
        let mode = match cfg.dns.block_mode.as_str() {
            "null_ip" => BlockMode::NullIp,
            _ => BlockMode::NxDomain,
        };
        let sock = tokio::net::UdpSocket::bind(&cfg.dns.listen).await?;
        tracing::info!(listen = %cfg.dns.listen, "dns listening (udp)");
        let dns_cfg = Arc::new(DnsConfig {
            upstream,
            block_mode: mode,
            upstream_timeout: Duration::from_secs(3),
        });
        tokio::spawn(async move {
            if let Err(e) = hygeia_dns::serve_udp(sock, rules, dns_cfg).await {
                tracing::error!(error = %e, "dns server stopped");
            }
        });
    }

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
        let interval = Duration::from_secs(cfg.lists.refresh_hours.max(1) * 3600);
        let st = state.clone();
        tokio::spawn(async move {
            let mut first = true;
            loop {
                let r = manager.refresh().await;
                let status = serde_json::to_value(&r.status).unwrap_or_default();
                if r.changed || first {
                    st.set_lists(r.sources, status);
                    tracing::info!(sources = r.status.len(), "lists updated");
                } else {
                    st.set_list_status(status);
                }
                first = false;
                tokio::select! {
                    _ = tokio::time::sleep(interval) => {}
                    _ = st.refresh_requested.notified() => tracing::info!("list refresh requested"),
                }
            }
        });
    }

    let listener = tokio::net::TcpListener::bind(&cfg.api.listen).await?;
    tracing::info!(listen = %cfg.api.listen, "api listening");
    axum_serve(listener, hygeia_api::router(state)).await
}

async fn axum_serve(
    l: tokio::net::TcpListener,
    app: hygeia_api::Router,
) -> Result<(), Box<dyn std::error::Error>> {
    hygeia_api::serve(l, app, async {
        let _ = tokio::signal::ctrl_c().await;
    })
    .await?;
    Ok(())
}

/// Assemble authentication from config + environment. Secrets never come from the file.
async fn build_auth(
    cfg: &config::Config,
    store: &Arc<dyn Store>,
) -> Result<AuthConfig, Box<dyn std::error::Error>> {
    use config::Environment;
    let mut env = cfg.auth.environment;
    if let Ok(v) = std::env::var("HYGEIA_ENVIRONMENT") {
        env = match v.as_str() {
            "production" => Environment::Production,
            "staging" => Environment::Staging,
            "dev" => Environment::Dev,
            other => return Err(format!("HYGEIA_ENVIRONMENT: unknown value {other:?}").into()),
        };
    }
    let bg_wanted = cfg.auth.break_glass.enabled
        || (env == Environment::Dev && std::env::var("HYGEIA_BREAK_GLASS_TOKEN").is_ok());

    let break_glass = if bg_wanted || env == Environment::Dev {
        if env == Environment::Production {
            return Err("break-glass is not allowed when environment = \"production\"".into());
        }
        let secret =
            match std::env::var("HYGEIA_BREAK_GLASS_TOKEN") {
                Ok(t) => t,
                Err(_) if env == Environment::Dev => {
                    let t = format!("hyg_bg_{}", rand_hex(24));
                    tracing::warn!("DEV: generated a throwaway break-glass token: {t}");
                    t
                }
                Err(_) => return Err(
                    "break-glass enabled in staging: set HYGEIA_BREAK_GLASS_TOKEN (>= 32 chars)"
                        .into(),
                ),
            };
        let ttl = (cfg.auth.break_glass.ttl_hours > 0)
            .then(|| Duration::from_secs(cfg.auth.break_glass.ttl_hours * 3600));
        let bg = BreakGlass::new(&secret, ttl)?;
        tracing::warn!(
            ?env,
            ttl_hours = cfg.auth.break_glass.ttl_hours,
            "BREAK-GLASS access is ENABLED; every use is audited"
        );
        if !cfg.api.listen.starts_with("127.") && !cfg.api.listen.starts_with("localhost") {
            tracing::warn!(listen = %cfg.api.listen, "break-glass on a non-loopback listener: restrict it at the network layer");
        }
        Some(bg)
    } else {
        None
    };

    let o = &cfg.auth.oidc;
    let oidc = if o.issuer.is_empty() {
        None
    } else {
        if o.audience.is_empty() {
            return Err("auth.oidc.audience must not be empty".into());
        }
        let v = OidcVerifier::new(OidcConfig {
            issuer: o.issuer.clone(),
            audience: o.audience.clone(),
            leeway_secs: o.leeway_secs,
            allow_insecure_http: o.allow_insecure_http,
        })?;
        for sub in &o.bootstrap_owners {
            let u = store.upsert_user(&o.issuer, sub, None).await?;
            store
                .bind_role(&u.id, None, hygeia_store::rbac::Role::Owner)
                .await?;
            tracing::warn!(subject = %sub, "bootstrap owner ensured");
        }
        Some(v)
    };

    if break_glass.is_none() && oidc.is_none() {
        tracing::warn!(
            "no admin authentication configured (set [auth.oidc], or environment = \"dev\"/\"staging\" with break-glass): the admin API is unusable"
        );
    }
    Ok(AuthConfig { break_glass, oidc })
}
