#!/usr/bin/env bash
# Behaviour scenario for the central server and a connected node in front of it: break-glass access,
# RBAC and tenant isolation, signed bundles, cloud DNS (DoH) gating, audit chain, and the node's
# offline behaviour.   usage: scripts/smoke-server.sh   (needs curl, python3; in-memory store)
set -u
cd "$(dirname "$0")/.."
. scripts/lib-smoke.sh
SRV=${HYGEIA_BIN:-target/debug/hygeia}; NODE=${HYGEIA_PROXY_BIN:-target/debug/hygeia-proxy}
[ -x "$SRV" ] && [ -x "$NODE" ] || cargo build -q -p hygeia -p hygeia-proxy || exit 1
D=$(mktemp -d); SP=$(free_port); NP=$(free_port); S=http://127.0.0.1:$SP; N=http://127.0.0.1:$NP
BG=hyg_bg_$(python3 -c 'import secrets;print(secrets.token_hex(24))')
cat > "$D/server.toml" <<CFG
[api]
listen = "127.0.0.1:$SP"
[auth]
environment = "dev"
[dns]
enabled = false
[lists]
enabled = false
[cloud_dns]
enabled = true
upstream = "127.0.0.1:9"
CFG
SPID=; NPID=
stop_srv()  { [ -n "$SPID" ] && kill "$SPID" 2>/dev/null && wait "$SPID" 2>/dev/null; SPID=; }
stop_node() { [ -n "$NPID" ] && kill "$NPID" 2>/dev/null && wait "$NPID" 2>/dev/null; NPID=; }
trap 'stop_srv; stop_node; rm -rf "$D"' EXIT
HYGEIA_BREAK_GLASS_TOKEN=$BG "$SRV" "$D/server.toml" >"$D/server.log" 2>&1 & SPID=$!
A=(-H "authorization: Bearer $BG"); J=(-H 'content-type: application/json')

say "Central server smoke test ($SRV)"
check "server starts, /healthz ok" wait_http "$S/healthz" 10
ceq "/readyz ok (store reachable)" "$(code $S/readyz)" 200
C=$(curl -s $S/v1/config)
ceq "mode=server, environment=dev, break-glass advertised" "$(echo "$C" | jget mode)/$(echo "$C" | jget environment)/$(echo "$C" | jget break_glass)" server/dev/True

say; say "Authentication, RBAC, tenant isolation"
ceq "admin API without credential -> 401" "$(code $S/v1/admin/tenants)" 401
ceq "wrong break-glass token -> 401" "$(code -H 'authorization: Bearer hyg_bg_wrong' $S/v1/admin/tenants)" 401
T=$(curl -s -XPOST "${A[@]}" "${J[@]}" -d '{"slug":"acme","name":"Acme"}' $S/v1/admin/tenants | jget id)
check "create tenant acme" test -n "$T"
ceq "rule in tenant acme" "$(code -XPOST "${A[@]}" "${J[@]}" -d "{\"tenant_id\":\"$T\",\"action\":\"block\",\"pattern\":\"acme-only.example.com\"}" $S/v1/admin/rules)" 201
ceq "default tenant does not see acme's rule" "$(curl -s "${A[@]}" $S/v1/admin/rules | grep -c acme-only)" 0
ceq "acme sees its rule" "$(curl -s "${A[@]}" "$S/v1/admin/rules?tenant_id=$T" | grep -c acme-only)" 1
VT=$(curl -s -XPOST "${A[@]}" "${J[@]}" -d "{\"tenant_id\":\"$T\",\"name\":\"ro\",\"role\":\"viewer\"}" $S/v1/admin/api-tokens | jget token)
check "viewer API token issued (hyg_api_)" has "$VT" hyg_api_
ceq "viewer can read rules" "$(code -H "authorization: Bearer $VT" $S/v1/admin/rules)" 200
ceq "viewer cannot write rules -> 403" "$(code -XPOST -H "authorization: Bearer $VT" "${J[@]}" -d '{"action":"block","pattern":"x.test"}' $S/v1/admin/rules)" 403
ceq "viewer cannot mint API tokens -> 403" "$(code -XPOST -H "authorization: Bearer $VT" "${J[@]}" -d '{"name":"x","role":"admin"}' $S/v1/admin/api-tokens)" 403

say; say "Enrolment and signed bundle"
ceq "default-tenant block rule" "$(code -XPOST "${A[@]}" "${J[@]}" -d '{"action":"block","pattern":"ads.example.com"}' $S/v1/admin/rules)" 201
PUB=$(curl -s $S/v1/pubkey); ceq "public key is 64 hex chars" "${#PUB}" 64
TOK=$(curl -s -XPOST "${A[@]}" "${J[@]}" -d '{}' $S/v1/admin/enrollment-tokens | jget token)
SEC=$(curl -s -XPOST "${J[@]}" -d "{\"token\":\"$TOK\",\"device_info\":\"smoke\"}" $S/v1/enroll | jget device_secret)
check "device credential issued (hyg_dev_)" has "$SEC" hyg_dev_
ceq "device credential cannot open the admin API -> 401" "$(code -H "authorization: Bearer $SEC" $S/v1/admin/rules)" 401
curl -s -D "$D/h" -o "$D/bundle" -H "authorization: Bearer $SEC" $S/v1/bundle
check "bundle starts with HYGB" has "$(head -c4 "$D/bundle")" HYGB
CETAG=$(grep -i '^etag:' "$D/h" | cut -d' ' -f2 | tr -d '\r')

say; say "Cloud DNS (DoH): never an open resolver"
DT=$(curl -s -XPOST "${A[@]}" "${J[@]}" -d '{"name":"smoke"}' $S/v1/admin/dns-tokens | jget token)
check "DNS token issued (hyg_dns_)" has "$DT" hyg_dns_
ceq "valid token, blocked name -> 200 NXDOMAIN" "$(doh $S "$DT" x.ads.example.com)" "200 3"
ceq "unknown token -> 404 (nothing resolved)" "$(doh $S hyg_dns_unknown example.org | cut -d' ' -f1)" 404
ceq "an API token is not a DNS token -> 404" "$(doh $S "$VT" example.org | cut -d' ' -f1)" 404

say; say "Audit"
ceq "audit hash chain verifies" "$(curl -s "${A[@]}" $S/v1/admin/audit/verify | jget ok)" True
check "break-glass use is audited" has "$(curl -s "${A[@]}" $S/v1/admin/audit)" auth.break_glass

say; say "Connected node in front of the server"
cat > "$D/node.toml" <<CFG
mode = "connected"
[http]
listen = "127.0.0.1:$NP"
[upstream]
url = "$S"
public_key = "$PUB"
allow_insecure_http = true
timeout_secs = 2
CFG
"$NODE" --data-dir "$D/node" --config "$D/node.toml" run >"$D/nodelog" 2>&1 & NPID=$!
check "connected node starts" wait_http "$N/healthz" 10
ceq "node serves the CENTRAL public key" "$(curl -s $N/v1/pubkey)" "$PUB"
TOK2=$(curl -s -XPOST "${A[@]}" "${J[@]}" -d '{}' $S/v1/admin/enrollment-tokens | jget token)
NSEC=$(curl -s -XPOST "${J[@]}" -d "{\"token\":\"$TOK2\",\"device_info\":\"via-node\"}" $N/v1/enroll | jget device_secret)
check "enrolment relayed through the node" has "$NSEC" hyg_dev_
check "relayed device is visible centrally" has "$(curl -s "${A[@]}" $S/v1/admin/devices)" via-node
curl -s -D "$D/h2" -o /dev/null -H "authorization: Bearer $NSEC" $N/v1/bundle
ceq "bundle via node has the central ETag" "$(grep -i '^etag:' "$D/h2" | cut -d' ' -f2 | tr -d '\r')" "$CETAG"
stop_srv
curl -s -D "$D/h3" -o /dev/null -H "authorization: Bearer $NSEC" $N/v1/bundle
ceq "server down: node serves the cached verified bundle" "$(head -1 "$D/h3" | cut -d' ' -f2)" 200
check "... flagged as stale" grep -qi '^x-hygeia-stale: 1' "$D/h3"
ceq "server down: unknown credential gets nothing" "$(code -H 'authorization: Bearer hyg_dev_unknown' $N/v1/bundle)" 502
report
