# Getting started

Three ways in, from smallest to largest. All of them run on Linux; the Windows service is untested (see [Node guide](node.md)).

Prerequisites for building from source: Rust (stable, 1.85+), Node.js 22 (for the admin UI and extension tests), `curl` and `python3` (for the smoke scripts). PostgreSQL is optional.

```bash
git clone https://github.com/bytehawks-org/hygieia && cd hygieia
(cd web && npm ci && npm run build)        # admin UI -> web/out (static, served by the binaries)
```

## 1. One PC: the standalone node

No database, no identity provider, nothing to configure. DNS is off, so the system resolver is untouched; the browser extension and the local UI are the product.

```bash
cargo run -p hygeia-proxy -- run           # foreground; UI + API + extension feed on http://127.0.0.1:8470/
cargo run -p hygeia-proxy -- open          # in another terminal: opens the UI already signed in
```

The UI shows the lists being downloaded (**Filter lists**), lets you add allow/block rules and test them (**Rules → what-if**), and issues one-time enrolment tokens (**Devices**).

Connect a browser: build the extension (`./extension/build.sh`), load `extension/` as an unpacked Chrome extension (or `extension/dist/firefox` in Firefox, see [Extension guide](extension.md)), then in its options enter `http://127.0.0.1:8470`, an enrolment token from **Devices**, and the public key printed by `hygeia-proxy pubkey`.

Optional local DNS filtering (opt-in): put this in `<data-dir>/hygeia-proxy.toml` (`hygeia-proxy info` prints the directory) and restart:

```toml
[dns]
mode = "local"
listen = "127.0.0.1:5353"     # port 53 needs privileges
upstream = ["9.9.9.9:53"]
```

```bash
dig @127.0.0.1 -p 5353 ads.example.com     # NXDOMAIN once a rule or list blocks it
```

## 2. A team or organisation: the central server

```bash
HYGEIA_ENVIRONMENT=dev cargo run -p hygeia   # dev: prints a throwaway break-glass token
```

Defaults: API and UI on `127.0.0.1:8080`, in-memory store (not persistent!). For anything real: PostgreSQL, OIDC and a stable signing key, see the [Server guide](server.md).

```bash
TOKEN=hyg_bg_...                              # printed at startup
curl -XPOST localhost:8080/v1/admin/rules -H "authorization: Bearer $TOKEN" \
  -H 'content-type: application/json' -d '{"action":"block","pattern":"ads.example.com"}'
```

Multi-tenancy is built in: single-organisation is the same code path with one default tenant. Create more with `POST /v1/admin/tenants` or in the UI (**Tenants**).

## 3. A node in front of a central server

On each site or PC, run the node in **connected** mode: browsers enrol centrally (so they appear under central RBAC), the node caches the signed bundle and keeps serving it if the server is unreachable.

```toml
# hygeia-proxy.toml
mode = "connected"
[upstream]
url = "https://hygeia.example.com"
public_key = "<hex from GET /v1/pubkey on the server>"   # pinned
```

## Learn what works: the smoke scenarios

```bash
scripts/smoke-node.sh        # real node binary: identity, local-port security, enrolment, bundle, DNS, persistence
scripts/smoke-server.sh      # real server + connected node: RBAC, tenants, DoH gating, audit, offline behaviour
scripts/check-all.sh --all   # everything, with a PASS/FAIL table
```

See [Testing](../testing.md) for what each layer proves and what is not verified.
