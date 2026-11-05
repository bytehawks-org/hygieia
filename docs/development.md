# Development

## Setup

```bash
git clone https://github.com/bytehawks-org/hygieia && cd hygieia
rustup target add wasm32-unknown-unknown
cargo install wasm-bindgen-cli --version 0.2.130 --locked     # extension only
(cd web && npm ci)                                            # UI + its tests
scripts/check-all.sh                                          # fast confidence check
scripts/gen-api.sh                                            # after changing the API: OpenAPI + TypeScript types
```

Rust edition 2024, resolver 3, MSRV 1.85 (CI uses stable). `hygeia-tray` is a separate workspace (`cargo build --manifest-path crates/hygeia-tray/Cargo.toml`; on Linux it needs GTK/AppIndicator development packages).

## Repository layout

```
crates/hygeia-core      engine (sync, I/O-free, WASM-ready)        crates/hygeia-api      REST control plane, OIDC, DoH
crates/hygeia-audit     hash-chained audit log                      crates/hygeia-dns      DNS decisions + UDP server
crates/hygeia-store     Store trait: memory | file | PostgreSQL     crates/hygeia-runtime  list coordinator, DNS follower, key files
crates/hygeia-lists     catalogue, downloader, guards               crates/hygeia          server binary
crates/hygeia-blocker   engine for JS (WASM) + DNR plan             crates/hygeia-proxy    node binary + library
crates/hygeia-winsvc    Windows service glue                        crates/hygeia-tray     tray icon
extension/              Chrome/Firefox MV3                          web/                   Next.js admin UI
packaging/              linux (.deb, systemd, RPM spec), windows    deploy/Containerfile   server image
docs/                   this documentation                          scripts/               check-all + smoke scenarios
```

## Conventions

- `hygeia-core` takes no runtime and no I/O dependencies; keep it compiling to `wasm32-unknown-unknown`.
- Clippy is `-D warnings` in CI; `cargo fmt` is enforced.
- Secrets: never in logs, audit diffs, process arguments or config files; hash credentials with `hash_secret`; show once.
- Tenant and group come from the credential on the data plane, never from request parameters.
- New configuration keys: add to the serde struct (`deny_unknown_fields` stays on), the [configuration reference](reference/configuration.md) and the sample config if one exists.
- Comments in English. Examples use `example.com` and `192.168.x.x`.

## Adding things

**A store operation.** Add the method to the `Store` trait; implement it for `MemoryStore` (lib.rs), `FileStore` (file.rs; persist if durable), `PgStore` (pg.rs; a migration if the schema changes, with RLS and a grant for `hygeia_app`); extend `conformance.rs` so all backends are tested. Tenant-scoped tables get `tenant_id`, a composite FK to `groups` if they reference one, and a `tenant_isolation` policy.

**An endpoint.** Handler in `crates/hygeia-api/src/routes.rs`; gate with `guard(&st, &h, Permission::…, tenant, "action")`; record an audit event for mutations (no secrets in the diff); add a test using `app()`/`call()`; update the [API reference](reference/api.md) and, if user-visible, a smoke script line and the UI.

**A list source or format.** `crates/hygeia-lists/src/catalog.rs` (license and attribution mandatory) and the parsers in `hygeia-core` (`list.rs`, `cosmetic_list.rs`); parsing must treat input as hostile and count what it skips.

**A migration.** New numbered file in `crates/hygeia-store/migrations`; additive where possible; `hygeia_app` grants inside the `IF EXISTS (… rolname = 'hygeia_app')` block.

**UI.** `web/app`, `web/components`, `web/lib`; `npm run dev` proxies `/v1` to `127.0.0.1:8080`; `npm run build` produces the static export the binaries serve. The CSP forbids inline scripts: no `dangerouslySetInnerHTML`, no inline handlers.

## Releasing

Tag `vX.Y.Z` and push: the `release` workflow builds the `.deb`, tarballs, Windows zip and extension zips and creates a **draft** GitHub Release with `SHA256SUMS`. Review, then publish. Artefacts are unsigned; set your own Firefox add-on id in `extension/package.mjs` before submitting to AMO.

## Debugging tips

- `RUST_LOG=debug` on either binary; the DNS follower and list coordinator log version changes.
- `hygeia-proxy info` shows where the node keeps its state.
- Use `scripts/smoke-*.sh` against a modified build to localise a regression quickly; they print which behaviour broke.
- PostgreSQL: connect as the *runtime* role to reproduce RLS behaviour; the owner bypasses it.
