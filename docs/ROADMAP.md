# Roadmap (work queue)

Order matters: items 1–4 were requested ahead of the previously suggested steps. Status: `todo` unless noted.

## Queue

| # | Item | Why / outcome | Depends on |
|---|---|---|---|
| 1 | **Node core** (standalone mode implemented; Windows unverified) (`hygeia-proxy` as installable node, standalone mode) | One binary: bundle feed for the extension + embedded control plane with a file-backed store + local UI; **DNS off by default, opt-in** (local filtering or forward to the cloud service); runs in the foreground on Linux and Windows (cross-compiled) | design: `docs/architecture/node.md` |
| 2 | **Connected mode** (relay, pinned key, disk cache, offline: done; local DNS, audit/telemetry forwarding: todo) | Node relays browser enrolments, fetches/verifies/caches central bundles on disk, keeps enforcing during outages | 1, central node endpoints (`/v1/node/*`) |
| 3 | **Central redundancy** (shared compiled bundles, `/readyz`, SIGTERM drain: done; coordinated list refresh: done) | Several server instances behind a load balancer: bundles compiled once and persisted in PostgreSQL (stable ETag/version), coordinated list refresh, health/readiness, graceful shutdown | PostgreSQL store |
| 4 | **Packaging, service and graphical mode** (Linux .deb + systemd: done; Windows service + zip/ps1: written, unverified; tray: written, unverified; MSI, wizard, pause-blocking API: todo) | systemd unit + `.deb`/`.rpm`, Windows service + MSI, tray icon, local UI first-run wizard; OS-resolver integration only as an explicit opt-in step, with safe revert; `windows-latest` CI job | 1 (2 for connected wizard) |
| 5 | **Cloud DNS service** (SaaS, multi-tenant; DoH + tokens + rate limit done; DoT, CIDRs, query log, metrics, DoT/DoH upstream: todo) | Filtering DNS facing the Internet: DoH token path, DoT SNI, registered CIDRs; never an open resolver; rate limiting; DoT/DoH upstream; query log with IP pseudonymisation and retention; metrics. Also the target of the node's *cloud forward* option. Constraints: `docs/architecture/dns-service.md` | 3 (replicas) |
| 6 | **OpenAPI + generated client** | utoipa schema, generated TypeScript client replaces the hand-written types | — |

## Done

Cloud DNS, first slice (item 5): `hyg_dns_` tokens (store, RLS, API), DoH endpoint with per-token rate limit and tenant bundles.

Central redundancy, core (item 3): `compiled_bundles` table, content-addressed bundles shared across replicas, readiness probe, graceful SIGTERM, lease-based coordinated list refresh with lists shared through the store.

Connected mode, relay part (item 2): `mode = "connected"`, pinned central key, device-credential relay, rollback guard, on-disk cache, offline serving, revocation passthrough.

Node core, standalone mode (item 1): file store, stable keys, local owner credential, host/origin guard, opt-in DNS, CLI, e2e with the extension and the UI on Linux.

Core engine and signed bundles · audit hash chain · PostgreSQL store with RLS · list catalogue, downloader and cosmetic/scriptlet parsing · blocker engine, Chrome and Firefox extensions · OIDC/API-token/break-glass authentication with RBAC · admin UI · per-tenant list selection.

## Known gaps carried forward

- Built-in DNS serves only the default tenant, UDP only, plain-UDP upstream (items 1, 5).
- Firefox build not yet run in a real Firefox; Windows nothing yet run on Windows (item 4).
- Scriptlet timing in Chrome MV3 is best-effort for the first HTML chunk.
