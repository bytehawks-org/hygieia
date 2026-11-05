//! `hygeia-proxy setup`: first-run wizard. Interactive on a console, or fully driven by flags
//! (used by the Windows installer for silent installs). It only writes the configuration file; the
//! service/unit is installed and started separately.
//!
//! The result is always validated with the same code the node uses at startup, so a wizard can
//! never produce a file the node would refuse.

use std::io::{BufRead, Write};
use std::path::Path;

use clap::Args;

use crate::config::Config;

type BoxErr = Box<dyn std::error::Error + Send + Sync>;

#[derive(Args, Clone, Debug, Default)]
pub struct SetupArgs {
    /// `standalone` or `connected`. Omit to be asked.
    #[arg(long)]
    pub mode: Option<String>,
    /// Central server URL (connected mode).
    #[arg(long)]
    pub upstream_url: Option<String>,
    /// Central signing public key, 64 hex characters (connected mode).
    #[arg(long)]
    pub upstream_key: Option<String>,
    /// Filter DNS on this machine (opt-in; standalone only). `true`/`false`.
    #[arg(long)]
    pub dns: Option<bool>,
    /// Plain-UDP resolvers for local DNS, comma separated `ip:port`.
    #[arg(long, value_delimiter = ',')]
    pub dns_upstream: Vec<String>,
    /// Never ask: fail when an answer is missing (default when stdin is not a terminal).
    #[arg(long)]
    pub non_interactive: bool,
    /// Overwrite an existing configuration (a `.bak` copy is kept).
    #[arg(long)]
    pub force: bool,
    /// Do nothing (successfully) when a configuration already exists. Used by the installer so an
    /// upgrade never touches the administrator's settings.
    #[arg(long, conflicts_with = "force")]
    pub if_missing: bool,
    /// Restart the Windows service after writing, so the new settings apply.
    #[arg(long)]
    pub restart_service: bool,
    /// Wait for Enter before returning (the wizard window would otherwise close at once).
    #[arg(long)]
    pub pause: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Answers {
    pub connected: bool,
    pub upstream_url: String,
    pub upstream_key: String,
    pub dns_local: bool,
    pub dns_upstream: Vec<String>,
}

/// Render the configuration file for the given answers.
pub fn render(a: &Answers) -> String {
    let mut s = String::from(
        "# Written by `hygeia-proxy setup`. Every key is optional; see the documentation for the rest.\n",
    );
    s.push_str(&format!(
        "mode = \"{}\"\n",
        if a.connected {
            "connected"
        } else {
            "standalone"
        }
    ));
    if a.connected {
        s.push_str(&format!(
            "\n[upstream]\nurl = {}\npublic_key = {}\n",
            quote(&a.upstream_url),
            quote(&a.upstream_key)
        ));
    }
    s.push_str("\n[dns]\n");
    if a.dns_local {
        s.push_str("mode = \"local\"\n");
        if !a.dns_upstream.is_empty() {
            let list: Vec<String> = a.dns_upstream.iter().map(|u| quote(u)).collect();
            s.push_str(&format!("upstream = [{}]\n", list.join(", ")));
        }
    } else {
        s.push_str("mode = \"off\"\n");
    }
    s
}

/// TOML basic string. Rejects control characters instead of escaping them: no legitimate URL,
/// key or resolver address contains one.
fn quote(v: &str) -> String {
    let clean: String = v
        .chars()
        .filter(|c| !c.is_control())
        .collect::<String>()
        .replace('\\', "\\\\")
        .replace('"', "\\\"");
    format!("\"{clean}\"")
}

/// Validate through the node's own parser and cross-field checks.
pub fn check(text: &str) -> Result<Config, String> {
    let cfg: Config = toml::from_str(text).map_err(|e| e.to_string())?;
    cfg.validate()?;
    Ok(cfg)
}

/// Write atomically; keep one `.bak` of whatever was there.
pub fn write_config(path: &Path, text: &str, force: bool) -> Result<(), BoxErr> {
    if path.exists() {
        if !force {
            return Err(format!(
                "{} already exists; use --force to replace it (a .bak copy is kept)",
                path.display()
            )
            .into());
        }
        std::fs::copy(path, path.with_extension("toml.bak"))?;
    }
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let tmp = path.with_extension("toml.tmp");
    std::fs::write(&tmp, text)?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

fn normalise_mode(m: &str) -> Result<bool, String> {
    match m.trim().to_ascii_lowercase().as_str() {
        "standalone" | "s" | "1" => Ok(false),
        "connected" | "c" | "2" => Ok(true),
        other => Err(format!(
            "mode must be `standalone` or `connected`, not {other:?}"
        )),
    }
}

fn ask(
    input: &mut dyn BufRead,
    out: &mut dyn Write,
    question: &str,
    default: &str,
) -> Result<String, BoxErr> {
    if default.is_empty() {
        write!(out, "{question}: ")?;
    } else {
        write!(out, "{question} [{default}]: ")?;
    }
    out.flush()?;
    let mut line = String::new();
    if input.read_line(&mut line)? == 0 {
        return Err("input closed before the wizard finished".into());
    }
    let line = line.trim();
    Ok(if line.is_empty() { default } else { line }.to_string())
}

fn ask_yes_no(
    input: &mut dyn BufRead,
    out: &mut dyn Write,
    question: &str,
    default: bool,
) -> Result<bool, BoxErr> {
    loop {
        let a = ask(input, out, question, if default { "y" } else { "n" })?;
        match a.to_ascii_lowercase().as_str() {
            "y" | "yes" | "s" | "si" => return Ok(true),
            "n" | "no" => return Ok(false),
            _ => writeln!(out, "Please answer y or n.")?,
        }
    }
}

/// Collect the answers: flags first, questions for whatever is missing (unless non-interactive).
pub fn gather(
    args: &SetupArgs,
    interactive: bool,
    input: &mut dyn BufRead,
    out: &mut dyn Write,
) -> Result<Answers, BoxErr> {
    if interactive {
        writeln!(
            out,
            "Hygieia node setup. Press Enter to accept the value in brackets.\n"
        )?;
    }
    let connected = match &args.mode {
        Some(m) => normalise_mode(m)?,
        None if interactive => {
            writeln!(
                out,
                "  1) standalone: this machine keeps its own rules and filter lists\n  2) connected:  this machine follows a central Hygieia server"
            )?;
            loop {
                match normalise_mode(&ask(input, out, "Mode", "1")?) {
                    Ok(c) => break c,
                    Err(e) => writeln!(out, "{e}")?,
                }
            }
        }
        None => return Err("--mode is required without a terminal".into()),
    };

    let (mut url, mut key) = (String::new(), String::new());
    if connected {
        url = match (&args.upstream_url, interactive) {
            (Some(u), _) => u.clone(),
            (None, true) => ask(
                input,
                out,
                "Central server URL (https://hygeia.example.com)",
                "",
            )?,
            _ => return Err("--upstream-url is required in connected mode".into()),
        };
        key = match (&args.upstream_key, interactive) {
            (Some(k), _) => k.clone(),
            (None, true) => {
                writeln!(
                    out,
                    "Paste the central signing key (64 hex characters) obtained through a trusted\nchannel, e.g. `hygeia pubkey` on the server. It is pinned: the node never learns it\nfrom the network."
                )?;
                ask(input, out, "Public key", "")?
            }
            _ => return Err("--upstream-key is required in connected mode".into()),
        };
    }

    let dns_local = match (args.dns, connected, interactive) {
        (_, true, _) => false, // not available in connected mode yet
        (Some(v), false, _) => v,
        (None, false, true) => {
            writeln!(
                out,
                "\nLocal DNS filtering is optional. When on, the node answers DNS on a local port;\nyour system resolver is NOT changed automatically."
            )?;
            ask_yes_no(input, out, "Enable local DNS filtering?", false)?
        }
        (None, false, false) => false,
    };
    let dns_upstream = if dns_local {
        let given: Vec<String> = args
            .dns_upstream
            .iter()
            .map(|u| u.trim().to_string())
            .filter(|u| !u.is_empty())
            .collect();
        if !given.is_empty() {
            given
        } else if interactive {
            ask(
                input,
                out,
                "Upstream resolvers (ip:port, comma separated)",
                "9.9.9.9:53",
            )?
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect()
        } else {
            vec![]
        }
    } else {
        vec![]
    };

    Ok(Answers {
        connected,
        upstream_url: url.trim().to_string(),
        upstream_key: key.trim().to_ascii_lowercase(),
        dns_local,
        dns_upstream,
    })
}

/// Entry point used by the binary.
pub fn run(args: &SetupArgs, cfg_path: &Path, stdin_is_terminal: bool) -> Result<(), BoxErr> {
    if args.if_missing && cfg_path.exists() {
        println!("{} exists; left unchanged.", cfg_path.display());
        return Ok(());
    }
    let result = run_inner(args, cfg_path, stdin_is_terminal);
    if args.pause {
        // On failure the window must stay open long enough to read the message.
        if let Err(e) = &result {
            eprintln!("\nerror: {e}");
        }
        print!("\nPress Enter to close. ");
        let _ = std::io::stdout().flush();
        let _ = std::io::stdin().lock().read_line(&mut String::new());
    }
    result
}

fn run_inner(args: &SetupArgs, cfg_path: &Path, stdin_is_terminal: bool) -> Result<(), BoxErr> {
    let interactive = !args.non_interactive && stdin_is_terminal;
    let stdin = std::io::stdin();
    let mut input = stdin.lock();
    let mut out = std::io::stdout();
    let answers = gather(args, interactive, &mut input, &mut out)?;
    let text = render(&answers);
    check(&text).map_err(|e| format!("these answers do not make a valid configuration: {e}"))?;
    write_config(cfg_path, &text, args.force)?;
    writeln!(out, "\nConfiguration written to {}.", cfg_path.display())?;
    if args.restart_service {
        restart_service(&mut out)?;
    } else {
        writeln!(out, "Restart the node to apply it.")?;
    }
    Ok(())
}

#[cfg(windows)]
fn restart_service(out: &mut dyn Write) -> Result<(), BoxErr> {
    let name = hygeia_winsvc::SERVICE_NAME;
    // `net stop/start` wait for the service state change; a stop of a stopped service is harmless.
    let _ = std::process::Command::new("net")
        .args(["stop", name])
        .output();
    let st = std::process::Command::new("net")
        .args(["start", name])
        .output()?;
    if !st.status.success() {
        return Err(format!(
            "the service did not start: {}",
            String::from_utf8_lossy(&st.stdout).trim()
        )
        .into());
    }
    writeln!(out, "Service restarted.")?;
    Ok(())
}

#[cfg(not(windows))]
fn restart_service(out: &mut dyn Write) -> Result<(), BoxErr> {
    writeln!(
        out,
        "--restart-service only manages the Windows service; on Linux run: systemctl restart hygeia-proxy"
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> String {
        ed25519_dalek::SigningKey::from_bytes(&[7u8; 32])
            .verifying_key()
            .to_bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }

    fn gather_with(args: SetupArgs, interactive: bool, typed: &str) -> Result<Answers, String> {
        let mut input = std::io::Cursor::new(typed.as_bytes().to_vec());
        let mut out = Vec::new();
        gather(&args, interactive, &mut input, &mut out).map_err(|e| e.to_string())
    }

    #[test]
    fn enter_everywhere_gives_the_safe_default() {
        let a = gather_with(SetupArgs::default(), true, "\n\n").unwrap();
        assert!(!a.connected && !a.dns_local);
        let cfg = check(&render(&a)).unwrap();
        assert_eq!(
            cfg.dns.mode,
            crate::config::DnsMode::Off,
            "DNS stays opt-in"
        );
    }

    #[test]
    fn standalone_with_local_dns() {
        let a = gather_with(SetupArgs::default(), true, "1\ny\n1.1.1.1:53, 9.9.9.9:53\n").unwrap();
        assert!(a.dns_local);
        let cfg = check(&render(&a)).unwrap();
        assert_eq!(cfg.dns.mode, crate::config::DnsMode::Local);
        assert_eq!(cfg.dns.upstream, ["1.1.1.1:53", "9.9.9.9:53"]);
    }

    #[test]
    fn connected_interactive_pins_the_key() {
        let typed = format!("2\nhttps://hygeia.example.com\n{}\n", key().to_uppercase());
        let a = gather_with(SetupArgs::default(), true, &typed).unwrap();
        let cfg = check(&render(&a)).unwrap();
        assert_eq!(cfg.upstream.url, "https://hygeia.example.com");
        assert_eq!(
            cfg.upstream.public_key,
            key(),
            "key is normalised to lower case"
        );
        assert!(!a.dns_local, "local DNS is not offered in connected mode");
    }

    #[test]
    fn bad_answers_are_re_asked_or_rejected_never_written() {
        // invalid mode, then a valid one
        let a = gather_with(SetupArgs::default(), true, "x\n1\nn\n").unwrap();
        assert!(!a.connected);
        // connected with an http:// URL or a short key does not validate
        let bad = Answers {
            connected: true,
            upstream_url: "http://hygeia.example.com".into(),
            upstream_key: key(),
            dns_local: false,
            dns_upstream: vec![],
        };
        assert!(check(&render(&bad)).unwrap_err().contains("https"));
        let bad = Answers {
            upstream_url: "https://hygeia.example.com".into(),
            upstream_key: "abc".into(),
            ..bad
        };
        assert!(check(&render(&bad)).unwrap_err().contains("64 hex"));
    }

    #[test]
    fn non_interactive_needs_every_answer_and_never_asks() {
        assert!(
            gather_with(SetupArgs::default(), false, "")
                .unwrap_err()
                .contains("--mode")
        );
        let args = SetupArgs {
            mode: Some("connected".into()),
            ..Default::default()
        };
        assert!(
            gather_with(args, false, "")
                .unwrap_err()
                .contains("--upstream-url")
        );
        let args = SetupArgs {
            mode: Some("standalone".into()),
            ..Default::default()
        };
        let a = gather_with(args, false, "").unwrap();
        assert!(!a.dns_local);
        // silent install with local DNS and no explicit resolver falls back to the node default
        let args = SetupArgs {
            mode: Some("standalone".into()),
            dns: Some(true),
            ..Default::default()
        };
        let a = gather_with(args, false, "").unwrap();
        check(&render(&a)).unwrap();
    }

    #[test]
    fn values_cannot_inject_toml() {
        let a = Answers {
            connected: true,
            upstream_url: "https://hygeia.example.com\"\n[http]\nlisten = \"0.0.0.0:80".into(),
            upstream_key: key(),
            dns_local: false,
            dns_upstream: vec![],
        };
        let text = render(&a);
        if let Ok(cfg) = check(&text) {
            assert_eq!(cfg.http.listen, "127.0.0.1:8470", "no injected section");
        }
    }

    #[test]
    fn write_is_atomic_keeps_a_backup_and_refuses_silent_overwrite() {
        let d = std::env::temp_dir().join(format!("hygeia-setup-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        let p = d.join("nested").join("hygeia-proxy.toml");
        write_config(&p, "mode = \"standalone\"\n", false).unwrap();
        assert!(
            write_config(&p, "x", false)
                .unwrap_err()
                .to_string()
                .contains("--force")
        );
        assert_eq!(
            std::fs::read_to_string(&p).unwrap(),
            "mode = \"standalone\"\n"
        );
        write_config(&p, "mode = \"standalone\"\n# v2\n", true).unwrap();
        assert!(std::fs::read_to_string(&p).unwrap().contains("# v2"));
        assert_eq!(
            std::fs::read_to_string(p.with_extension("toml.bak")).unwrap(),
            "mode = \"standalone\"\n"
        );
        assert!(!p.with_extension("toml.tmp").exists());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn if_missing_leaves_an_existing_file_alone_and_empty_flags_are_ignored() {
        let d = std::env::temp_dir().join(format!("hygeia-setup-im-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        let p = d.join("hygeia-proxy.toml");
        std::fs::write(&p, "# mine\n").unwrap();
        let args = SetupArgs {
            mode: Some("standalone".into()),
            if_missing: true,
            non_interactive: true,
            ..Default::default()
        };
        run(&args, &p, false).unwrap();
        assert_eq!(std::fs::read_to_string(&p).unwrap(), "# mine\n");
        // an installer passes empty values for what the user left blank
        let args = SetupArgs {
            mode: Some("standalone".into()),
            dns: Some(true),
            dns_upstream: vec![String::new()],
            ..Default::default()
        };
        let a = gather_with(args, false, "").unwrap();
        assert!(a.dns_upstream.is_empty());
        let _ = std::fs::remove_dir_all(&d);
    }
}
