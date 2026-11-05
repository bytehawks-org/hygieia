# Testing

Short version: `scripts/check-all.sh --all` runs everything and prints a PASS/FAIL table. This page explains what each layer proves, how to run it, and what is **not** verified.

## Layers

| Layer | Command | What it proves | Needs |
|---|---|---|---|
| Format, lint | `cargo fmt --all -- --check` · `cargo clippy --workspace --all-targets -- -D warnings` | style, common bugs (CI is strict) | Rust |
| Rust unit + integration (~110 tests) | `cargo test --workspace` | engine, parsers, bundle signing, audit chain, stores, API behaviour, node, connected relay, DNS decisions, upstream failover (UDP/DoT/DoH), DoT/DoQ/UDP/TCP front-ends over real sockets, TLS reload and HTTPS serving, query-log privacy, rate limits, metrics | Rust |
| Store conformance | included above (`hygeia-store`) | the **same** behavioural suite passes on the in-memory, file and PostgreSQL stores (tenancy, tokens, rules, bundles, leases, DNS tokens, audit) | PostgreSQL for the PG run |
| PostgreSQL isolation | `cargo test -p hygeia-store --test pg` | RLS hides other tenants, runtime role cannot alter schema or audit, migrations apply from scratch | `HYGEIA_TEST_PG_ADMIN`, `HYGEIA_TEST_PG_APP` |
| WASM build | `cargo check -p hygeia-core -p hygeia-blocker --target wasm32-unknown-unknown` | the engine stays I/O-free and portable | `rustup target add wasm32-unknown-unknown` |
| JavaScript unit | `node --test extension/test/*.test.mjs web/test/oidc.test.mjs` · `cd web && npx tsc --noEmit` | scriptlets under hostile input; `background.js` on a fake browser API (Chromium and Firefox code paths, real WASM, real signed bundle); OIDC helpers; UI types | Node 22 |
| Behaviour smoke | `scripts/smoke-node.sh` · `scripts/smoke-server.sh` | the **built binaries** behave as documented, end to end over HTTP/UDP, with human-readable PASS/FAIL lines | `curl`, `python3` |
| Real-browser e2e | `./extension/build.sh && (cd web && npm run build) && cargo build -p hygeia -p hygeia-proxy` then `node extension/test/e2e.mjs` · `E2E_TARGET=node node extension/test/e2e.mjs` · `node web/test/e2e.mjs` · `node web/test/e2e-node.mjs` | real Chromium with the real extension: enrolment, signed bundle install, blocking of a subresource and a navigation, element hiding, a scriptlet in the page world, `trusted-*` dropped; the admin UI (login, rules, lists, devices, audit, OIDC against a mock IdP, CSP violations = 0) against the server and the node | Playwright + Chromium (`CHROMIUM=/path` overrides) |
| Scale report | `cargo test -p hygeia-core --release --test scale -- --ignored --nocapture` | footprint and speed at 240k domains: build time, ns/lookup, bundle size, sign/verify | Rust (release) |
| Live lists | `cargo test -p hygeia-lists --test live -- --ignored --nocapture` | the real upstream lists still download and parse | network |
| Extension lint | `npx web-ext lint -s extension/dist/firefox` | Firefox manifest/API lint | Node |

## The smoke scenarios

They are the quickest way to *see* the system work and the best bug report attachment.

`scripts/smoke-node.sh` (27 checks): starts the standalone node in a temp directory with opt-in DNS and checks mode, 401 without credential, owner identity, hostile `Host` → 421, cross-site POST → 403, rule creation, enrolment (and a bogus token → 401), `HYGB` bundle magic, 304 on `If-None-Match`, `simulate`, DNS NXDOMAIN from the rule, audit chain verification, and — after a **restart** — stable signing key, the device still authenticating, and a still-valid chain; plus the `setup` wizard (valid config written, overwrite refused, `--if-missing`, invalid connected answers rejected without writing).

`scripts/smoke-server.sh` (46 checks): starts the server (in-memory store, dev break-glass, cloud DNS, metrics, log key) and checks readiness and config, wrong break-glass → 401, tenant creation and **tenant isolation** of rules, a viewer API token (can read, cannot write, cannot mint tokens), enrolment and bundle, **DoH gating** (valid token → NXDOMAIN for a blocked name, unknown token and an API token → 404), audit chain and break-glass audit, then **cloud DNS** (opt-in query log without raw IP or token, open-resolver guard for networks, plain DNS `REFUSED` vs registered, metrics token), the audit chain, a **connected node** in front: pinned central key, relayed enrolment visible centrally, identical ETag through the node, and with the server **stopped** the cached bundle served with `X-Hygeia-Stale`, while an unknown credential gets nothing; finally, if `openssl` exists, the server with **native HTTPS** (certificate, HSTS, plain HTTP and unknown CA refused).

Example output:

```
Identity and local-port security
  PASS  reports mode=standalone
  PASS  unexpected Host header (DNS rebinding) -> 421
  …
Result: 19 passed, 0 failed
```

Environment knobs: `HYGEIA_PROXY_BIN`, `HYGEIA_BIN` point at other builds (e.g. `target/release/…`).

## Running PostgreSQL tests locally

```bash
# throwaway PostgreSQL (container) with the two roles
podman run -d --name hygeia-pg -e POSTGRES_PASSWORD=postgres -p 5432:5432 postgres:17
PGPASSWORD=postgres psql -h localhost -U postgres \
  -c "create role hygeia_owner login createdb password 'owner'" \
  -c "create role hygeia_app login password 'app' nosuperuser nobypassrls"
export HYGEIA_TEST_PG_ADMIN=postgres://hygeia_owner:owner@localhost:5432
export HYGEIA_TEST_PG_APP=postgres://hygeia_app:app@localhost:5432
cargo test -p hygeia-store
```

Each test creates and drops its own database. Without these variables the PostgreSQL tests are skipped (and say so).

## CI

| Workflow | When | Content |
|---|---|---|
| `ci` | push, PR | `test` (PostgreSQL 17 service: fmt, clippy `-D warnings`, `cargo test --workspace`, wasm check) · `extension` (WASM build, extension unit tests, web-ext lint) · `extension-e2e` (real Chromium + extension against server and node; **advisory** until its first green run on GitHub) · `web` (typecheck, unit, UI e2e, node e2e) · `package-linux` (.deb) · `windows` (build, tests, zip, MSI via WiX; **advisory**: `continue-on-error`) |
| `codeql` | push to main, PR, weekly | CodeQL for Rust, JavaScript/TypeScript, GitHub Actions |
| `audit` | push to main, PR on dependency files, daily | `cargo audit`, `cargo deny check licenses bans sources`, `npm audit` |
| `coverage` | push to main, manual | `cargo llvm-cov` summary and `lcov.info` as artefacts |
| `release` | tag `v*` or manual | `.deb`, tarballs, Windows zip, extension zips, `SHA256SUMS` → draft GitHub Release |

## What is verified, and what is not

**Verified in automation:** everything in the table above on Linux, Chromium included.

**Not verified:**
- **Cloud DNS under load or against real resolvers/clients**: transports are exercised in-process and by smoke scenarios with fake upstreams; no throughput/latency-under-load numbers, no interoperability run with real DoT/DoQ/DoH clients or public resolvers, no DNSSEC.
- **Windows**: the node, service, installer and tray have never run on Windows (only cross-type-checked; the `windows` CI job is the first real signal and is advisory).
- **Firefox**: lint and fake-API tests only; never run in a real Firefox.
- **systemd unit and `.deb` on a live systemd host**: package contents and `dpkg -i/-r` were exercised in a container without systemd.
- **RPM** (`packaging/linux/hygeia-proxy.spec`): never built.
- **Several real replicas** against one PostgreSQL: convergence is tested with two in-process replicas on a shared store and the store primitives (locks, leases) on PostgreSQL, not with separate processes under load.
- **Load and soak**: no throughput, latency-under-load or long-run tests beyond the scale report.
- **Scriptlet timing in Chrome** is best-effort by design (documented in the extension README).

## Writing tests

- Store behaviour goes into `crates/hygeia-store/src/conformance.rs` so every backend is held to it.
- API behaviour: `crates/hygeia-api/src/routes.rs` tests drive the router with `tower::oneshot`; use the `app()` / `call()` helpers.
- Node and relay behaviour: `crates/hygeia-proxy/tests/` start real listeners on port 0.
- A new user-visible behaviour deserves a line in a smoke script.
