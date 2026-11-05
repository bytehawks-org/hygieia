use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use clap::{Parser, Subcommand};
use hygeia_proxy::paths::{Paths, real_env_data_dir};
use hygeia_proxy::{load_config, read_owner_token, read_public_key};

/// Hygieia node: local filtering server and browser-extension endpoint.
#[derive(Parser)]
#[command(name = "hygeia-proxy", version)]
struct Cli {
    /// State directory (default: HYGEIA_PROXY_DATA_DIR, else a per-user/per-OS location; see `info`).
    #[arg(long, global = true)]
    data_dir: Option<PathBuf>,
    /// Configuration file (default: <data-dir>/hygeia-proxy.toml, optional).
    #[arg(long, global = true)]
    config: Option<PathBuf>,
    #[command(subcommand)]
    command: Option<Cmd>,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run in the foreground (default).
    Run,
    /// Print the local owner credential (for the UI login or the API).
    Token,
    /// Print the signing public key to pin in the browser extension.
    Pubkey,
    /// Open the admin UI in the browser, already signed in.
    Open,
    /// Show paths, listen address and state.
    Info,
    /// Validate the configuration and exit.
    CheckConfig,
    /// Windows service management (install, uninstall).
    #[command(subcommand)]
    Service(hygeia_proxy::service::ServiceCmd),
}

fn paths(cli: &Cli) -> Result<(Paths, PathBuf), String> {
    let dir = real_env_data_dir(cli.data_dir.as_deref())?;
    let p = Paths::new(dir);
    // Packaged service: root (and the unit) read /etc/hygeia-proxy/hygeia-proxy.toml when present.
    let system_cfg = std::path::PathBuf::from("/etc/hygeia-proxy/hygeia-proxy.toml");
    let cfg = cli.config.clone().unwrap_or_else(|| {
        if cfg!(unix)
            && std::env::var_os("HYGEIA_PROXY_DATA_DIR").is_none()
            && system_cfg.exists()
            && p.dir == std::path::Path::new("/var/lib/hygeia-proxy")
        {
            system_cfg.clone()
        } else {
            p.config.clone()
        }
    });
    Ok((p, cfg))
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    match real_main(cli).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

async fn real_main(cli: Cli) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let (p, cfg_path) = paths(&cli)?;
    match cli.command.unwrap_or(Cmd::Run) {
        Cmd::Service(sub) => {
            // `install` without --data-dir uses the machine-wide location, not the user profile.
            #[cfg(windows)]
            let dir = match (&cli.data_dir, sub) {
                (None, hygeia_proxy::service::ServiceCmd::Install) => {
                    hygeia_proxy::service::program_data_dir()
                }
                _ => p.dir.clone(),
            };
            #[cfg(not(windows))]
            let dir = p.dir.clone();
            let cfg = if cli.config.is_none() {
                dir.join("hygeia-proxy.toml")
            } else {
                cfg_path.clone()
            };
            hygeia_proxy::service::handle(sub, &dir, &cfg).await?;
        }
        Cmd::Run => {
            tracing_subscriber::fmt()
                .with_env_filter(
                    tracing_subscriber::EnvFilter::try_from_default_env()
                        .unwrap_or_else(|_| "info".into()),
                )
                .init();
            let cfg = load_config(&cfg_path)?;
            let mut node = hygeia_proxy::start(cfg, p).await?;
            tokio::select! {
                r = node.wait() => { r?; }
                _ = shutdown_signal() => tracing::info!("shutting down"),
            }
            node.stop().await?;
        }
        Cmd::Token => println!("{}", read_owner_token(&p)?),
        Cmd::Pubkey => {
            let cfg = load_config(&cfg_path)?;
            if cfg.mode == hygeia_proxy::config::Mode::Connected {
                println!("{}", cfg.upstream.public_key.trim());
            } else {
                println!("{}", read_public_key(&p)?);
            }
        }
        Cmd::CheckConfig => {
            load_config(&cfg_path)?;
            println!(
                "configuration OK ({})",
                if cfg_path.exists() {
                    cfg_path.display().to_string()
                } else {
                    "defaults".into()
                }
            );
        }
        Cmd::Info => {
            let cfg = load_config(&cfg_path)?;
            println!("data dir:     {}", p.dir.display());
            println!(
                "config:       {} ({})",
                cfg_path.display(),
                if cfg_path.exists() {
                    "present"
                } else {
                    "absent, defaults"
                }
            );
            println!(
                "state file:   {} ({})",
                p.state.display(),
                if p.state.exists() {
                    "present"
                } else {
                    "not created yet"
                }
            );
            if cfg.mode == hygeia_proxy::config::Mode::Connected {
                println!("mode:         connected to {}", cfg.upstream.url);
                println!(
                    "listen:       http://{}/ (extension feed; no local UI)",
                    cfg.http.listen
                );
                println!(
                    "public key:   {} (central, pinned)",
                    cfg.upstream.public_key.trim()
                );
                return Ok(());
            }
            println!("UI / API:     http://{}/", cfg.http.listen);
            println!(
                "DNS:          {:?}{}",
                cfg.dns.mode,
                if cfg.dns.mode == hygeia_proxy::config::DnsMode::Local {
                    format!(" on {}", cfg.dns.listen)
                } else {
                    String::new()
                }
            );
            match read_public_key(&p) {
                Ok(k) => println!("public key:   {k}"),
                Err(_) => println!("public key:   (generated on first run)"),
            }
        }
        Cmd::Open => {
            let cfg = load_config(&cfg_path)?;
            if cfg.mode == hygeia_proxy::config::Mode::Connected {
                return Err("connected mode has no local UI: administer the central server".into());
            }
            let token = read_owner_token(&p)?;
            open_browser(&p, &cfg.http.listen, &token).await?;
        }
    }
    Ok(())
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let mut term = signal(SignalKind::terminate()).expect("SIGTERM handler");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = term.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

/// The credential must not appear in a process argument list (visible to other local users), so the
/// browser is pointed at a short-lived private file that redirects to the login URL with the token in
/// the URL *fragment* (never sent to any server, never logged).
async fn open_browser(
    p: &Paths,
    listen: &str,
    token: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let plain = format!("http://{listen}/login/");
    println!("UI: {plain}   (sign in with the credential from `hygeia-proxy token`)");
    let page = p
        .dir
        .join(format!("open-{}.html", hygeia_runtime::rand_hex(6)));
    let html = format!(
        "<!doctype html><meta charset=utf-8><meta http-equiv=refresh content=\"0;url={plain}#token={token}\"><title>Hygieia</title>"
    );
    hygeia_runtime::create_private_file(&page, &html)?;
    let launched = {
        #[cfg(windows)]
        {
            std::process::Command::new("cmd")
                .args(["/C", "start", ""])
                .arg(&page)
                .spawn()
        }
        #[cfg(target_os = "macos")]
        {
            std::process::Command::new("open").arg(&page).spawn()
        }
        #[cfg(all(unix, not(target_os = "macos")))]
        {
            std::process::Command::new("xdg-open").arg(&page).spawn()
        }
    };
    if let Err(e) = &launched {
        eprintln!("could not launch a browser ({e}); open the URL above manually");
    }
    let linger = std::env::var("HYGEIA_PROXY_OPEN_LINGER_SECS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(15);
    tokio::time::sleep(Duration::from_secs(linger)).await;
    let _ = std::fs::remove_file(&page);
    Ok(())
}
