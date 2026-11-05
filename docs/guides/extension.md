# Browser extension guide

The extension (Chrome MV3 and Firefox MV3) enforces the signed bundle in the browser: network blocking, element hiding and scriptlets. The engine is `hygeia-blocker` compiled to WASM; it is the only code that parses bundle data. Full details, limits and security properties: [extension/README](../../extension/README.md).

## Build and load

```bash
rustup target add wasm32-unknown-unknown
cargo install wasm-bindgen-cli --version 0.2.130 --locked     # must match the wasm-bindgen crate in Cargo.lock
./extension/build.sh                                          # -> extension/pkg
node extension/package.mjs chrome    # or firefox            # -> extension/dist/<browser>
```

Release builds (unsigned zips) are attached to GitHub Releases by the `release` workflow.

- **Chrome / Chromium / Edge:** `chrome://extensions` → Developer mode → *Load unpacked* → `extension/dist/chrome` (or `extension/` directly).
- **Firefox (≥ 140):** `about:debugging` → *This Firefox* → *Load Temporary Add-on* → `extension/dist/firefox/manifest.json`. For permanent installation sign it with your own add-on id through AMO (`web-ext sign`).

## Connect it

Open the extension's options page and enter:

1. **Server URL**: a central server, or a node (`http://127.0.0.1:8470`).
2. **Enrolment token**: from the UI (**Devices → New enrolment token**) or `POST /v1/admin/enrollment-tokens`. Short-lived, limited uses.
3. **Public key**: from `GET /v1/pubkey` or `hygeia-proxy pubkey`. Pin it through a trusted channel; the *Fetch* button is trust-on-first-use.

The device credential (`hyg_dev_…`) is stored in `chrome.storage.local`; the enrolment token is cleared from the form after use. The extension pulls the bundle every 30 minutes (conditional, ETag/304), verifies the signature against the pinned key, refuses anything older than what it holds, then decodes.

## What it enforces

| Layer | Chrome | Firefox |
|---|---|---|
| Network blocking | `declarativeNetRequest` dynamic rules built from the engine's plan | `webRequest` blocking calling the engine per request (no rule limit) |
| Element hiding | constructed stylesheet | `scripting.insertCSS` |
| Scriptlets | `scripting.executeScript(world: MAIN)` with packaged scriptlets | same |

Five scriptlets are supported (`set-constant`, `abort-on-property-read/write`, `no-setTimeout-if`, `no-setInterval-if`, plus uBO aliases). Lists can only select a scriptlet by name and pass string arguments; no `eval`.

## Known limits (short list)

Scriptlet injection timing is best-effort in Chrome; procedural selectors and HTML filtering are not supported; on revocation or outage the last good bundle stays in force (no per-tenant fail-closed); **Firefox has not been run in a real Firefox** (lint and fake-API tests only). See the extension README for the complete table.

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| "signature verification failed" after a server restart | the server generated an ephemeral signing key (`HYGEIA_SIGNING_KEY` not set) |
| New bundles ignored | server restarted with the in-memory store (versions reset); use PostgreSQL |
| Enrolment fails | token expired/used up; or the node's `Host`/`Origin` guard (use the node's own URL, not a LAN alias unless `allowed_hosts` has it) |
| Nothing blocked on Firefox | host access not granted: the options page asks on first use |
