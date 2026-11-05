mod config;

use std::sync::Arc;
use std::time::Duration;

use ed25519_dalek::SigningKey;
use hygeia_api::{
    AppState, AuthConfig, BreakGlass, DEFAULT_GROUP, DEFAULT_TENANT, OidcConfig, OidcPublic,
    OidcVerifier, PublicConfig,
};
use hygeia_lists::{HttpFetcher, Manager};
use hygeia_store::{MemoryStore, PgStore, Store};

use hygeia_runtime::rand_hex;

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
    let (auth, public) = build_auth(&cfg, &store).await?;
    let mut state = AppState::new(store, signing_key, auth);
    state.public = public;
    let state = Arc::new(state);

    // Data plane: DNS follows the control plane by pulling the signed bundle.
    if cfg.dns.enabled {
        let rules =
            hygeia_runtime::spawn_dns_follower(state.clone(), DEFAULT_TENANT, DEFAULT_GROUP);
        let upstream = cfg.dns.upstream.first().ok_or("dns.upstream is empty")?;
        hygeia_runtime::spawn_dns_server(&cfg.dns.listen, upstream, &cfg.dns.block_mode, rules)
            .await
            .map_err(|e| e.to_string())?;
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
        hygeia_runtime::spawn_list_refresher(state.clone(), manager, interval);
    }

    let listener = tokio::net::TcpListener::bind(&cfg.api.listen).await?;
    tracing::info!(listen = %cfg.api.listen, "api listening");
    let web_dir = if !cfg.api.web_dir.is_empty() {
        Some(cfg.api.web_dir.clone())
    } else if let Ok(d) = std::env::var("HYGEIA_WEB_DIR") {
        Some(d)
    } else {
        std::path::Path::new("/usr/share/hygeia/web")
            .is_dir()
            .then(|| "/usr/share/hygeia/web".to_string())
    };
    let app = match web_dir {
        Some(dir) => {
            let mut connect: Vec<String> = cfg.auth.oidc.ui_connect_src.clone();
            if let Some(origin) = hygeia_runtime::origin_of(&cfg.auth.oidc.issuer) {
                connect.push(origin);
            }
            let ui = hygeia_api::ui::Ui::load(&dir, &connect)?;
            tracing::info!(%dir, "admin UI enabled");
            hygeia_api::router_with_ui(state, ui)
        }
        None => hygeia_api::router(state),
    };
    axum_serve(listener, app).await
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
) -> Result<(AuthConfig, PublicConfig), Box<dyn std::error::Error>> {
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
    let public = PublicConfig {
        mode: "server".into(),
        environment: format!("{env:?}").to_lowercase(),
        break_glass: break_glass.is_some(),
        oidc: (oidc.is_some() && !o.client_id.is_empty()).then(|| OidcPublic {
            issuer: o.issuer.clone(),
            client_id: o.client_id.clone(),
            scope: "openid email profile".into(),
        }),
    };
    Ok((
        AuthConfig {
            local_owner: None,
            break_glass,
            oidc,
        },
        public,
    ))
}
