//! Windows service glue. Compiles to nothing on other platforms.
//!
//! NOT TESTED ON A REAL WINDOWS MACHINE: it is only cross-compiled in CI/dev. The first run on
//! Windows decides whether it works (see docs/architecture/node.md, *Verification limits*).

#![cfg(windows)]

use std::ffi::OsString;
use std::path::PathBuf;
use std::sync::OnceLock;
use std::sync::mpsc::{self, Receiver};
use std::time::Duration;

use windows_service::service::{
    ServiceAccess, ServiceControl, ServiceControlAccept, ServiceErrorControl, ServiceExitCode,
    ServiceInfo, ServiceStartType, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
use windows_service::{define_windows_service, service_dispatcher};

pub const SERVICE_NAME: &str = "HygeiaProxy";
const DISPLAY_NAME: &str = "Hygieia node";
const DESCRIPTION: &str =
    "Hygieia node: browser-extension endpoint, local admin UI and optional DNS filtering.";

/// Body of the service: runs until `stop` yields (the SCM asked to stop or the machine shuts down).
pub type Main = Box<dyn FnOnce(Receiver<()>) -> Result<(), String> + Send>;

static MAIN: OnceLock<std::sync::Mutex<Option<Main>>> = OnceLock::new();

define_windows_service!(ffi_service_main, service_main);

/// Hand control to the SCM. Returns when the service has stopped. Fails (quickly) if the process
/// was not started by the SCM, e.g. when run from a console.
pub fn run(main: Main) -> Result<(), String> {
    MAIN.set(std::sync::Mutex::new(Some(main)))
        .map_err(|_| "service entry point already set".to_string())?;
    service_dispatcher::start(SERVICE_NAME, ffi_service_main).map_err(|e| {
        format!("could not start as a Windows service ({e}); use `hygeia-proxy run` from a console")
    })
}

fn service_main(_args: Vec<OsString>) {
    let _ = run_service();
}

fn status(state: ServiceState, accept: ServiceControlAccept, code: u32) -> ServiceStatus {
    ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: state,
        controls_accepted: accept,
        exit_code: ServiceExitCode::Win32(code),
        checkpoint: 0,
        wait_hint: Duration::from_secs(10),
        process_id: None,
    }
}

fn run_service() -> Result<(), windows_service::Error> {
    let (tx, rx) = mpsc::channel::<()>();
    let handler = move |ev| match ev {
        ServiceControl::Stop | ServiceControl::Shutdown => {
            let _ = tx.send(());
            ServiceControlHandlerResult::NoError
        }
        ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
        _ => ServiceControlHandlerResult::NotImplemented,
    };
    let handle = service_control_handler::register(SERVICE_NAME, handler)?;
    handle.set_service_status(status(
        ServiceState::StartPending,
        ServiceControlAccept::empty(),
        0,
    ))?;
    let main = MAIN
        .get()
        .and_then(|m| m.lock().ok()?.take())
        .expect("entry point set by run()");
    handle.set_service_status(status(
        ServiceState::Running,
        ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
        0,
    ))?;
    let result = main(rx);
    handle.set_service_status(status(
        ServiceState::Stopped,
        ServiceControlAccept::empty(),
        u32::from(result.is_err()),
    ))
}

/// Register the service (needs an elevated prompt). `args` are the arguments after the
/// executable, e.g. `--data-dir C:\ProgramData\Hygeia service run`. Runs as LocalService.
pub fn install(exe: PathBuf, args: Vec<OsString>) -> Result<(), String> {
    let manager = ServiceManager::local_computer(
        None::<&str>,
        ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE,
    )
    .map_err(|e| format!("cannot open the service manager (run as Administrator): {e}"))?;
    let info = ServiceInfo {
        name: SERVICE_NAME.into(),
        display_name: DISPLAY_NAME.into(),
        service_type: ServiceType::OWN_PROCESS,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: exe,
        launch_arguments: args,
        dependencies: vec![],
        account_name: Some("NT AUTHORITY\\LocalService".into()),
        account_password: None,
    };
    let svc = manager
        .create_service(&info, ServiceAccess::CHANGE_CONFIG)
        .map_err(|e| format!("cannot create the service: {e}"))?;
    svc.set_description(DESCRIPTION)
        .map_err(|e| format!("service created, description not set: {e}"))
}

/// Stop (if running) and delete the service.
pub fn uninstall() -> Result<(), String> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .map_err(|e| format!("cannot open the service manager (run as Administrator): {e}"))?;
    let svc = manager
        .open_service(
            SERVICE_NAME,
            ServiceAccess::QUERY_STATUS | ServiceAccess::STOP | ServiceAccess::DELETE,
        )
        .map_err(|e| format!("service not found: {e}"))?;
    if let Ok(s) = svc.query_status()
        && s.current_state != ServiceState::Stopped
    {
        let _ = svc.stop();
        for _ in 0..50 {
            std::thread::sleep(Duration::from_millis(200));
            if svc
                .query_status()
                .is_ok_and(|s| s.current_state == ServiceState::Stopped)
            {
                break;
            }
        }
    }
    svc.delete()
        .map_err(|e| format!("cannot delete the service: {e}"))
}
