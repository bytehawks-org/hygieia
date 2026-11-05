# CLI reference

## `hygeia` (server)

```
hygeia [config.toml]
```

No subcommands. Configuration: [reference](configuration.md). Logs go to stderr (`RUST_LOG`). `SIGTERM` and Ctrl-C drain in-flight requests.

## `hygeia-proxy` (node)

```
hygeia-proxy [--data-dir DIR] [--config FILE] [COMMAND]
```

| Command | Purpose |
|---|---|
| `run` (default) | run in the foreground |
| `token` | print the local owner credential (`hyg_own_…`) |
| `pubkey` | print the public key to pin in the extension (standalone: the node's; connected: the configured central key) |
| `open` | open the UI in the browser, already signed in (standalone only). The credential is never in process arguments |
| `info` | data dir, config, listen address, DNS mode, public key |
| `check-config` | validate the configuration and exit non-zero on error |
| `service install` / `uninstall` | Windows service management (elevated). On Linux use systemd |
| `service run` | entry point used by the Windows Service Control Manager (not for manual use) |

`--data-dir` / `HYGEIA_PROXY_DATA_DIR` select the state directory; `--config` defaults to `<data-dir>/hygeia-proxy.toml` (optional; `/etc/hygeia-proxy/hygeia-proxy.toml` for root when present).

## Scripts

| Script | Purpose |
|---|---|
| `scripts/check-all.sh [--e2e] [--smoke] [--all]` | every check with a PASS/FAIL table, logs in `target/check-all/` |
| `scripts/smoke-node.sh` | behaviour scenario against the real node binary |
| `scripts/smoke-server.sh` | behaviour scenario against the real server and a connected node |
| `extension/build.sh` | build the WASM engine into `extension/pkg` |
| `node extension/package.mjs chrome\|firefox` | assemble `extension/dist/<browser>` |
| `packaging/linux/build-deb.sh BIN WEBDIR OUTDIR` | build the `.deb` |
