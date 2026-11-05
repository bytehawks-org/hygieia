# Roadmap (work queue)

Order matters: items 1–4 were requested ahead of the previously suggested steps. Status: `todo` unless noted.

## Queue

| # | Item | Why / outcome | Depends on |
|---|---|---|---|
| 1 | **Node core** (`hygeia-proxy` as installable node, standalone mode) | One binary: local DNS + bundle feed for the extension + embedded control plane with a file-backed store; runs in the foreground on Linux and Windows (cross-compiled) | design: `docs/architecture/node.md` |
| 2 | **Connected mode** | Node enrols with a central server (`hyg_node_` credential), relays browser enrolments, fetches/verifies/caches central bundles on disk, keeps enforcing during outages, forwards audit/telemetry | 1, central node endpoints (`/v1/node/*`) |
| 3 | **Central redundancy** | Several server instances behind a load balancer: bundles compiled once and persisted in PostgreSQL (stable ETag/version), coordinated list refresh, health/readiness, graceful shutdown | PostgreSQL store |
| 4 | **Packaging, service and graphical mode** | systemd unit + `.deb`/`.rpm`, Windows service + MSI, tray icon, local UI first-run wizard, OS-resolver integration with safe revert; `windows-latest` CI job | 1 (2 for connected wizard) |
| 5 | **DNS multi-tenant on the server** | DoH token path, DoT SNI, source CIDR → tenant; DoT/DoH upstream; query log with IP pseudonymisation and retention; metrics | 3 (replicas), shared by the node's upstream support |
| 6 | **OpenAPI + generated client** | utoipa schema, generated TypeScript client replaces the hand-written types | — |

## Done

Core engine and signed bundles · audit hash chain · PostgreSQL store with RLS · list catalogue, downloader and cosmetic/scriptlet parsing · blocker engine, Chrome and Firefox extensions · OIDC/API-token/break-glass authentication with RBAC · admin UI · per-tenant list selection.

## Known gaps carried forward

- Built-in DNS serves only the default tenant, UDP only, plain-UDP upstream (items 1, 5).
- Bundle cache is per process (item 3).
- Firefox build not yet run in a real Firefox; Windows nothing yet run on Windows (item 4).
- Scriptlet timing in Chrome MV3 is best-effort for the first HTML chunk.
