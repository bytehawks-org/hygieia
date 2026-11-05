# Hygieia node (`hygeia-proxy`)

One installable binary for Linux and Windows. It is a **light local server** for a single machine or small site, and, when pointed at a central Hygieia server, an **endpoint/connector** for that server. The central server owns RBAC, configuration and audit; nodes enforce.

**DNS is not required on the node and is off by default.** The default install is the extension connector plus local UI: no port 53, no change to the operating system's resolver. DNS filtering is an opt-in with three choices (see *DNS options*): local filtering on the node, a local stub that forwards to the cloud DNS service, or no node involvement at all (the OS/router points at the cloud service directly).

```mermaid
flowchart LR
  subgraph PC["Endpoint (Linux / Windows)"]
    EXT[Browser extension] -->|enroll + bundle pull| NODE
    OS[OS resolver 127.0.0.1] -->|DNS| NODE
    NODE["hygeia-proxy (node)<br/>bundle feed + local UI + tray<br/>(DNS: opt-in)"]
  end
  NODE -. standalone: own lists, own rules, own signing key .-> NODE
  NODE == connected: enrol, signed bundles, telemetry ==> LB
  subgraph CENTRAL["Central (LAN / cloud), N instances"]
    LB[load balancer] --> S1[hygeia server 1]
    LB --> S2[hygeia server 2]
    S1 & S2 --> PG[(PostgreSQL)]
  end
  EXT2[Extension on another PC] -->|may talk to the central server directly| LB
  OS -. opt-in: DoH/DoT .-> DNSSAAS[Cloud DNS service<br/>DoH token path / DoT SNI]
  DNSSAAS --- LB
```

## Modes

| | `standalone` | `connected` |
|---|---|---|
| Control plane | embedded: local rules, lists, one implicit tenant | none locally: central server |
| Bundle signing key | node's own (generated at first run) | central's (the node never re-signs) |
| Lists | downloaded by the node | downloaded by the central server |
| Rules / RBAC / audit | local, single admin (the machine's owner) | central RBAC; node audit events are forwarded |
| Extension pins | node public key | central public key |
| If the other side is down | n/a | keeps enforcing the last verified bundle (cached on disk); fail-open policy for *configuration*, never for rules |

## Roles of the node

1. **Extension connector** (the default, always on). The extension's server URL is the node. The node serves the same `/v1/enroll`, `/v1/bundle`, `/v1/pubkey` contract as the central server:
   - standalone: enrolment is local; bundles are signed by the node;
   - connected: enrolment is **relayed** to the central server (so every browser shows up as a device under central RBAC), bundles are fetched with the node's credential, **verified, cached and served unchanged** (central signature preserved, extension pins the central key).
2. **Local admin UI + tray icon** (graphical configuration): the existing Next.js admin UI served on `127.0.0.1`, plus a native tray icon (status, open dashboard, pause blocking 5/30/60 min). First-run wizard in the UI: pick mode, set upstream resolver, optionally enrol against a server.
3. **Local DNS** (opt-in, see below).
4. *(later, optional)* HTTP(S) proxy / PAC and selective MITM (tier 3). Not needed for the extension flow.

## DNS options (all opt-in)

| Option | Node does | Resolver of the machine | Filtering happens | Works offline |
|---|---|---|---|---|
| **off** (default) | nothing | unchanged | extension only (URLs, cosmetic); other apps unfiltered | yes |
| **local** | DNS server enforcing the verified bundle (standalone: own rules/lists; connected: central policy) | `127.0.0.1` | on the machine | yes (last bundle) |
| **cloud forward** | local stub (127.0.0.1) that forwards over DoH/DoT to the SaaS DNS endpoint of the tenant, token embedded; no bundle needed for DNS | `127.0.0.1` | in the cloud | no (falls back per policy) |
| **cloud direct** | nothing | set to the tenant's DoH/DoT endpoint (Windows 11 DoH template URL, Android Private DNS, router) | in the cloud | no |

Cloud forward exists for operating systems or networks that cannot use DoH/DoT natively and as the place where "pause blocking" and local caching live. Whatever the option, the extension keeps working independently.

The SaaS DNS service is a first-class feature of the central server, not an afterthought: its constraints (no open resolver, tenant identification, privacy, data residency) are in `docs/architecture/dns-service.md`.

## Connected mode (implemented)

```toml
mode = "connected"
[upstream]
url = "https://hygeia.example.com"
public_key = "<central signing key, 64 hex>"   # pinned, never learned from the network
```

**Decision: the node holds no credential of its own towards the central server** (this replaces the earlier `hyg_node_` idea). Trust is per browser device: each device is enrolled centrally (so it appears under central RBAC and can be revoked there) and the node relays on its behalf.

- `POST /v1/enroll` is relayed unchanged with `X-Hygeia-Node: <node id>`; the server records it in the audit event (`via_node`, informational, unauthenticated).
- `GET /v1/bundle` is relayed with the browser's own bearer secret. A `200` is verified against the pinned key, checked against rollback/replay (same tenant+group, lower version or same version with other bytes is refused and the cached bundle is served), cached on disk and served **unchanged**; the extension pins the central key. `304` and `If-None-Match` pass through.
- Revocation: a `401` from the central server is passed on and the device is forgotten by the node immediately.
- Central unreachable: a device the central server accepted before (known by SHA-256 of its secret, in `connected.json`) gets the cached bundle, re-verified on every read, flagged `X-Hygeia-Stale: 1`. Unknown credentials and enrolment get `502`. A tampered or unverifiable cache is never served.
- `GET /v1/node/status` (local credential) shows node id, upstream and last contact. No admin API, no UI, no lists, no signing key on the node.

Not yet: local DNS in connected mode (rejected by config validation), audit/telemetry forwarding, pause-blocking, central-side per-node revocation. A compromised node can see the secrets of the devices that pass through it, and can withhold updates, but cannot forge bundles.

## Central redundancy (several instances)

The server data plane is already stateless **except** the per-process bundle cache. Required before running replicas:

- compile bundles once, **persist them in PostgreSQL** keyed by (tenant, group, inputs-hash) with a stable ETag, under a Postgres advisory lock; every replica serves the stored bytes (same ETag/version everywhere);
- list refresh coordinated by an advisory lock (one downloader, others read the result);
- health/readiness endpoints for the load balancer; graceful shutdown;
- DNS (DoT/DoH/DoQ) with tenant resolution and query-log ingestion on the replicas.

## Local security constraints (decided up front)

- Local UI/API bind to loopback only, require a credential generated at install (file readable only by the owning user/service account) **and** validate the `Host`/`Origin` headers (DNS-rebinding and cross-site requests against a localhost admin port are a real attack).
- The node never exposes unauthenticated admin endpoints on LAN interfaces; serving other LAN clients as DNS is an explicit opt-in.
- Bundle signature is verified on every fetch; downgrade (lower version) refused, as in the extension.
- Changing the OS resolver never happens implicitly: it is an explicit opt-in step (wizard or CLI), reversible and recorded; uninstall restores the previous settings.

## OS integration (only needed when DNS is *local* or *cloud forward*)

| | Linux | Windows |
|---|---|---|
| Service | systemd unit (`DynamicUser` or dedicated user, `CAP_NET_BIND_SERVICE` for :53) | Windows service (`windows-service` crate), LocalService account |
| Port 53 | conflict with `systemd-resolved` stub: drop-in `DNSStubListener=no`, or serve on 127.0.0.1:5353 and point `resolved` at it | usually free; Windows DNS Client uses the adapter DNS setting |
| Point the OS at the node | `resolvectl dns <iface> 127.0.0.1` / NetworkManager | per-adapter DNS via the IP Helper / `netsh` equivalent |
| Package | `.deb`, `.rpm` (cargo-deb, cargo-generate-rpm), static musl tarball | MSI (WiX), Authenticode-signed |
| Tray | `tray-icon` (AppIndicator on GNOME needs the extension) | `tray-icon` |

With DNS off (default) none of this applies and the install touches no network settings.

**Resolver safety net** (only when the OS resolver points at the node): if the node dies, a machine whose only resolver is 127.0.0.1 loses DNS. Mitigations: service supervision/restart, health-gated configuration (the node removes itself from the OS resolver list on clean shutdown), and an optional secondary resolver (documented trade-off: bypass).

## Assumptions made (change if wrong)

- The binary keeps the name `hygeia-proxy`; "proxy" in the user-facing sense. The crate `hygeia-proxy` becomes the node library; the HTTP proxy/PAC part is demoted to optional.
- "Graphical mode" = tray icon + local web UI (reuses the existing admin UI, same codebase on every OS), not a native widget toolkit.
- Standalone persistence = a file-backed store (atomic snapshot of the in-memory store, including the audit chain), not SQLite: the PostgreSQL schema relies on RLS and functions that do not port, and one machine does not need a database.
- macOS is out of scope for now.
- Node DNS (`local` / `cloud forward`) is off by default; enabling it is a deliberate user action, never part of install.

## Verification limits

Development and CI here run on Linux. Windows code (service, tray, MSI, resolver changes) can be cross-compiled but **only a Windows runner can test it**: the plan adds a `windows-latest` CI job and a manual install checklist; nothing Windows-specific should be called "tested" before that exists.
