# Data formats

## Signed bundle

```
offset  size  field
0       4     magic "HYGB"
4       1     format version (1)
5       4     payload length N (big-endian)
9       N     payload: postcard-encoded Bundle
9+N     64    ed25519 signature over bytes [0, 9+N)
```

Verification order: length and magic → format → **signature** → only then decode. Clients also refuse a bundle whose `meta.version` is lower than the one installed (rollback guard); the in-memory server resets versions on restart, PostgreSQL does not.

`Bundle { meta, network, cosmetic }`:

| Field | Content |
|---|---|
| `meta.version` | monotonic per tenant + group |
| `meta.tenant_id`, `meta.group_id`, `meta.created_at` | scope and time |
| `meta.sources[]` | `id, name, url, license, attribution` of every list used |
| `network` | `custom_allow[]`, `custom_block[]`, `lists[]{id, allow[], block[]}` |
| `cosmetic` | `generic[]` selectors; `by_host{host → {selectors, exceptions, scriptlets[{name,args}]}}` |

ETag = `"` + first 16 bytes of SHA-256 of the whole encoded bundle (hex) + `"`. Equal inputs and key give equal bytes, hence equal ETags (this is what lets replicas converge). Matching: domain rules match the name and all its subdomains (trie on reversed labels).

## Audit chain

One chain per tenant. Each event:

```json
{"seq": 12, "ts": 1760000000, "tenant_id": "…", "actor": "…", "action": "rule.create",
 "target": "ads.example.com", "diff": {"after": {…}}, "prev_hash": "…", "hash": "…"}
```

`hash = SHA-256( JSON{ seq, prev: prev_hash, d: {ts, tenant_id, actor, action, target, diff} } )`, `prev_hash` of the first event is 64 zeros. `GET /v1/admin/audit/verify` recomputes the chain (sequence gaps, broken links, altered content are detected); the standalone node refuses to start on a broken chain; PostgreSQL additionally blocks UPDATE/DELETE on `audit_events` with a trigger (also for the owner role).

Actors: user id, API token id, device id, `system`, `break-glass`, `local-owner`. Secrets never appear in `diff`.

Actions written today: `rule.create`, `rule.delete`, `token.create` (enrolment), `device.enroll`, `device.revoke`, `api-token.create/revoke`, `dns-token.create/revoke`, `bundle.compile`, `auth.break_glass`, `tenant.create`, `group.create`, `binding.create/delete`, `list-policy.set`, `list-subscription.create/delete`. Events enrolled through a relay node carry `via_node` in the diff (informational, unauthenticated).

**CEF export** (`hygeia_audit::to_cef`): `CEF:0|Hygeia|Hygeia|0.1|<action>|<action>|3|rt=<ms> suser=<actor> cs1Label=tenant cs1=<tenant> dst=<target> cs2Label=hash cs2=<hash>` with CEF escaping. There is no HTTP endpoint for the export yet.

## Node state file (`state.json`)

JSON snapshot, `format: 1`: tokens and devices (secret hashes as hex), rules, bundle versions, per-tenant audit events, tenants, groups, users, bindings, API tokens, DNS tokens (optional field), list policy, subscriptions. Written atomically (temp file, fsync, rename) with mode 0600; the previous copy is kept as `.bak`. On load every audit chain is verified.

## Node connected state (`connected.json`)

`{ "node_id": "node-…", "devices": { "<sha256 of device secret>": {tenant, group, last_ok} } }` plus `bundles/<sha256(tenant\0group)>.bin` (verified bundles as received).
