//! Tray icon for the Hygieia node. It only observes the node (GET /healthz on the loopback port)
//! and opens the dashboard; it holds no credential and changes nothing. Pause/resume of blocking
//! is not offered because the node has no such API yet.
//!
//! NOT TESTED ON A REAL DESKTOP: cross-type-checked for Windows only.
#![cfg_attr(windows, windows_subsystem = "windows")]

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::{Duration, Instant};

use tao::event_loop::{ControlFlow, EventLoopBuilder};
use tray_icon::menu::{Menu, MenuEvent, MenuItem, PredefinedMenuItem};
use tray_icon::{Icon, TrayIconBuilder};

const POLL: Duration = Duration::from_secs(5);

fn listen_addr() -> String {
    std::env::args()
        .skip_while(|a| a != "--listen")
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:8470".into())
}

/// Minimal liveness probe: no HTTP client dependency, loopback only, short timeouts.
fn node_up(addr: &str) -> bool {
    let Ok(sock) = addr.parse::<SocketAddr>() else {
        return false;
    };
    let Ok(mut s) = TcpStream::connect_timeout(&sock, Duration::from_millis(800)) else {
        return false;
    };
    let _ = s.set_read_timeout(Some(Duration::from_millis(800)));
    let _ = s.set_write_timeout(Some(Duration::from_millis(800)));
    let req = format!("GET /healthz HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n");
    if s.write_all(req.as_bytes()).is_err() {
        return false;
    }
    let mut buf = [0u8; 32];
    s.read(&mut buf)
        .is_ok_and(|n| buf[..n].starts_with(b"HTTP/1.1 200"))
}

fn icon(up: bool) -> Icon {
    let (w, h) = (32u32, 32u32);
    let (r, g, b) = if up { (46, 160, 90) } else { (150, 150, 150) };
    let mut px = Vec::with_capacity((w * h * 4) as usize);
    for y in 0..h {
        for x in 0..w {
            let (dx, dy) = (x as f32 - 15.5, y as f32 - 15.5);
            let inside = dx * dx + dy * dy <= 14.0 * 14.0;
            px.extend_from_slice(&[r, g, b, if inside { 255 } else { 0 }]);
        }
    }
    Icon::from_rgba(px, w, h).expect("valid icon buffer")
}

fn open_dashboard(addr: &str) {
    // The login page asks for the owner credential; the tray never handles it.
    let url = format!("http://{addr}/login/");
    #[cfg(windows)]
    let _ = std::process::Command::new("cmd")
        .args(["/C", "start", "", &url])
        .spawn();
    #[cfg(all(unix, not(target_os = "macos")))]
    let _ = std::process::Command::new("xdg-open").arg(&url).spawn();
    #[cfg(target_os = "macos")]
    let _ = std::process::Command::new("open").arg(&url).spawn();
}

fn main() {
    let addr = listen_addr();
    let event_loop = EventLoopBuilder::new().build();

    let menu = Menu::new();
    let status = MenuItem::new("Hygieia node: checking…", false, None);
    let open = MenuItem::new("Open dashboard", true, None);
    let quit = MenuItem::new("Quit tray (node keeps running)", true, None);
    menu.append_items(&[&status, &PredefinedMenuItem::separator(), &open, &quit])
        .expect("menu");
    let (open_id, quit_id) = (open.id().clone(), quit.id().clone());

    let tray = TrayIconBuilder::new()
        .with_menu(Box::new(menu))
        .with_tooltip("Hygieia node")
        .with_icon(icon(false))
        .build()
        .expect("tray icon");

    let mut last: Option<bool> = None;
    event_loop.run(move |_event, _target, flow| {
        *flow = ControlFlow::WaitUntil(Instant::now() + POLL);
        while let Ok(ev) = MenuEvent::receiver().try_recv() {
            if ev.id == open_id {
                open_dashboard(&addr);
            } else if ev.id == quit_id {
                *flow = ControlFlow::Exit;
            }
        }
        let up = node_up(&addr);
        if last != Some(up) {
            last = Some(up);
            status.set_text(if up {
                "Hygieia node: running"
            } else {
                "Hygieia node: not running"
            });
            let _ = tray.set_icon(Some(icon(up)));
            let _ = tray.set_tooltip(Some(if up {
                "Hygieia node: running"
            } else {
                "Hygieia node: not running"
            }));
        }
    });
}
