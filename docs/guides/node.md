# Node guide (`hygeia-proxy`)

The node is one installable binary for a PC or a site. It always serves the **extension feed** (`/v1/enroll`, `/v1/bundle`, `/v1/pubkey`). Beyond that it is either a complete standalone product or the endpoint of a central server. Design and rationale: [Node design](../architecture/node.md).

| | Standalone (default) | Connected |
|---|---|---|
| Control plane | embedded, one implicit tenant | the central server |
| Signing key | the node's own | central's (never re-signed) |
| Lists | downloaded by the node | downloaded by the server |
| Local UI / admin API | yes (loopback, local owner) | no |
| DNS | off; opt-in `local` | not yet |
| Extension pins | `hygeia-proxy pubkey` | the central public key |

## Run it

```bash
cargo run -p hygeia-proxy -- run        # or the installed binary / service
hygeia-proxy info                        # data dir, config path, listen address, public key
hygeia-proxy open                        # open the UI signed in (standalone)
hygeia-proxy token                       # print the local owner credential
hygeia-proxy pubkey                      # public key to pin in the extension
hygeia-proxy check-config                # validate the configuration and exit
```

All commands accept `--data-dir` (or `HYGEIA_PROXY_DATA_DIR`) and `--config`. Default data directory: Linux user `~/.local/share/hygeia-proxy`, Linux root/service `/var/lib/hygeia-proxy`, Windows user `%LOCALAPPDATA%\Hygeia`, Windows service `%ProgramData%\Hygeia`. Reference: [CLI](../reference/cli.md).

## Files in the data directory

| File | Purpose | Notes |
|---|---|---|
| `state.json` | rules, devices, tokens, policy, audit chain | atomic writes, mode 0600, previous copy `state.json.bak`; a damaged or tampered file (including a broken audit chain) **stops the node** instead of being reset |
| `signing.key` | bundle signing seed (standalone) | stable: browsers pin its public half. Losing it means re-pinning every browser |
| `owner.token` | local owner credential `hyg_own_…` | readable by the owning user/service account only |
| `hygeia-proxy.toml` | optional configuration | see below |
| `connected.json`, `bundles/` | connected mode: node id, known devices (hashes), cached verified bundles | |

## Standalone configuration

```toml
mode = "standalone"
[http]
listen = "127.0.0.1:8470"
# allow_lan = true                    # exposing the node needs this AND allowed_hosts
# allowed_hosts = ["pc.lan:8470"]
[dns]
mode = "off"                          # "local": filter DNS on this machine
# listen = "127.0.0.1:5353"           # 53 needs privileges
# upstream = ["9.9.9.9:53"]
# block_mode = "nxdomain"             # or "null_ip"
[lists]
refresh_hours = 12                    # same [lists] section as the server, see Filter lists
```

Local-port security (always on): loopback by default; the `Host` header must be expected (blocks DNS rebinding); state-changing requests need a same-origin `Origin` (browser extensions are accepted only on the three extension endpoints); the credential never appears in process arguments (`open` uses a short-lived private redirect page and the URL fragment, which the UI scrubs).

## Connected mode

```toml
mode = "connected"
[upstream]
url = "https://hygeia.example.com"
public_key = "<central signing key, 64 hex>"     # pinned: never learned from the network
# allow_insecure_http = false                     # labs only
# timeout_secs = 10
```

Behaviour, in short (full details in [Node design](../architecture/node.md#connected-mode-implemented)):

- Enrolment is relayed to the server with `X-Hygeia-Node`; each browser exists centrally and is revoked there.
- Bundles are fetched with the browser's own credential, **verified against the pinned key**, checked against rollback, cached on disk, and served unchanged.
- Server down: known devices get the cached, re-verified bundle with `X-Hygeia-Stale: 1`; unknown credentials and enrolment get 502; a tampered cache is never served.
- `GET /v1/node/status` (bearer = local credential) shows node id, upstream and last contact.

The node holds **no credential of its own** towards the server; a compromised node can see the secrets of devices passing through it and withhold updates, but cannot forge bundles.

## Install as a service

### Linux (`.deb`, systemd)

```bash
(cd web && npm ci && npm run build) && cargo build --release -p hygeia-proxy
packaging/linux/build-deb.sh target/release/hygeia-proxy web/out dist
sudo dpkg -i dist/hygeia-proxy_*.deb
sudo systemctl enable --now hygeia-proxy
sudo hygeia-proxy token                 # sign in at http://127.0.0.1:8470/login/
```

Installing does not start the service and does not touch the system resolver. Config: `/etc/hygeia-proxy/hygeia-proxy.toml` (conffile; restart after editing). State: `/var/lib/hygeia-proxy`. The unit uses `DynamicUser`, `StateDirectory`, `ProtectSystem=strict`, a syscall filter and only `CAP_NET_BIND_SERVICE` (for DNS on port 53). An RPM spec exists in `packaging/linux/` (not built or tested).

Using DNS on port 53 with systemd-resolved: either serve on `127.0.0.1:5353` and point resolved at it, or set `DNSStubListener=no` in a drop-in. The node never changes resolver settings itself.

### Windows (service, **untested**)

From the release zip, in an elevated PowerShell: `./install.ps1` (copies to `Program Files\Hygeia`, runs `hygeia-proxy service install`, starts service `HygeiaProxy` as LocalService, registers the tray icon for logon). Data in `%ProgramData%\Hygeia`, restricted to SYSTEM, Administrators and LocalService. Read the credential from an elevated prompt: `hygeia-proxy --data-dir "%ProgramData%\Hygeia" token`. Remove with `uninstall.ps1` (state is kept). The service code is only cross-type-checked; report what you see when you try it.

### Tray icon

`hygeia-tray` shows whether the node answers on its loopback port and opens the login page. It holds no credential and changes nothing.
