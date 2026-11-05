//! `hygeia-proxy service …`: Windows service management. On other platforms the packaged systemd
//! unit is used instead. The Windows part is cross-compiled only; see `hygeia-winsvc`.

use std::path::Path;

use clap::Subcommand;

type BoxErr = Box<dyn std::error::Error + Send + Sync>;

#[derive(Subcommand, Clone, Copy)]
pub enum ServiceCmd {
    /// Register the Windows service (elevated prompt). Data lives in %ProgramData%\Hygeia.
    Install,
    /// Stop and remove the Windows service (state is kept).
    Uninstall,
    /// Entry point used by the Service Control Manager (not for manual use).
    Run,
}

#[cfg(not(windows))]
pub async fn handle(_cmd: ServiceCmd, _data_dir: &Path, _cfg: &Path) -> Result<(), BoxErr> {
    Err("`service` manages the Windows service; on Linux use the systemd unit (systemctl enable --now hygeia-proxy)".into())
}

#[cfg(windows)]
pub fn program_data_dir() -> std::path::PathBuf {
    std::path::PathBuf::from(
        std::env::var("ProgramData").unwrap_or_else(|_| r"C:\ProgramData".into()),
    )
    .join("Hygeia")
}

#[cfg(windows)]
pub async fn handle(cmd: ServiceCmd, data_dir: &Path, cfg: &Path) -> Result<(), BoxErr> {
    match cmd {
        ServiceCmd::Install => install(data_dir, cfg),
        ServiceCmd::Uninstall => hygeia_winsvc::uninstall().map_err(Into::into),
        ServiceCmd::Run => run(data_dir.to_path_buf(), cfg.to_path_buf()).await,
    }
}

#[cfg(windows)]
fn install(data_dir: &Path, cfg: &Path) -> Result<(), BoxErr> {
    use std::ffi::OsString;
    std::fs::create_dir_all(data_dir)?;
    // The directory holds the signing key and the owner credential: only SYSTEM, Administrators
    // and the service account (LocalService) may touch it. SIDs, so this works on any UI language.
    let acl = std::process::Command::new("icacls")
        .arg(data_dir)
        .args(["/inheritance:r", "/grant:r"])
        .args([
            "*S-1-5-19:(OI)(CI)F",
            "*S-1-5-18:(OI)(CI)F",
            "*S-1-5-32-544:(OI)(CI)F",
        ])
        .status()?;
    if !acl.success() {
        return Err(
            "could not restrict the permissions of the data directory (icacls failed)".into(),
        );
    }
    let default_cfg = data_dir.join("hygeia-proxy.toml");
    if !default_cfg.exists() {
        std::fs::write(
            &default_cfg,
            include_str!("../../../packaging/linux/hygeia-proxy.toml"),
        )?;
    }
    let exe = std::env::current_exe()?;
    let args: Vec<OsString> = vec![
        "--data-dir".into(),
        data_dir.into(),
        "--config".into(),
        cfg.into(),
        "service".into(),
        "run".into(),
    ];
    hygeia_winsvc::install(exe, args)?;
    println!("service installed (runs as LocalService, starts automatically).");
    println!("  start now:   sc start {}", hygeia_winsvc::SERVICE_NAME);
    println!(
        "  credential:  hygeia-proxy --data-dir \"{}\" token   (elevated prompt)",
        data_dir.display()
    );
    println!("  config:      {}", cfg.display());
    Ok(())
}

#[cfg(windows)]
async fn run(data_dir: std::path::PathBuf, cfg: std::path::PathBuf) -> Result<(), BoxErr> {
    use std::sync::Mutex;
    // No console under the SCM: log to a file next to the state.
    let log = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(data_dir.join("hygeia-proxy.log"))?;
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .with_ansi(false)
        .with_writer(Mutex::new(log))
        .init();
    let handle = tokio::runtime::Handle::current();
    tokio::task::spawn_blocking(move || {
        hygeia_winsvc::run(Box::new(move |stop| {
            handle.block_on(async move {
                let cfg = crate::load_config(&cfg)?;
                let node = crate::start(cfg, crate::paths::Paths::new(data_dir))
                    .await
                    .map_err(|e| e.to_string())?;
                let _ = tokio::task::spawn_blocking(move || stop.recv()).await;
                tracing::info!("stop requested by the service manager");
                node.stop().await.map_err(|e| e.to_string())
            })
        }))
    })
    .await?
    .map_err(Into::into)
}
