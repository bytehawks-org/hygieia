mod config;

use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use ed25519_dalek::SigningKey;
use hygeia_api::{AppState, DEFAULT_GROUP, DEFAULT_TENANT};
use hygeia_core::{Ruleset, SignedBundle};
use hygeia_dns::{BlockMode, DnsConfig};

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

    let admin_token = std::env::var("HYGEIA_ADMIN_TOKEN").unwrap_or_else(|_| {
        let t = format!("hyg_adm_{}", rand_hex(24));
        tracing::warn!("HYGEIA_ADMIN_TOKEN not set; generated one-shot admin token: {t}");
        t
    });
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

    let state = Arc::new(AppState::new(signing_key, &admin_token));

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
                let b = st.bundle_for(DEFAULT_TENANT, DEFAULT_GROUP);
                if let Ok(bundle) = SignedBundle::open(&b.0, &verifying)
                    && bundle.meta.version > current
                {
                    current = bundle.meta.version;
                    r2.store(Arc::new(Ruleset::from_data(&bundle.network)));
                    tracing::info!(version = current, "dns ruleset updated");
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
