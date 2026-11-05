// End-to-end: real Chromium + built UI (web/out) served by the real hygeia binary + mock OIDC provider.
//   (cd web && npm run build) && cargo build -p hygeia && node web/test/e2e.mjs
import { createRequire } from 'node:module';
import http from 'node:http';
import crypto from 'node:crypto';
import { spawn } from 'node:child_process';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';

const require = createRequire(import.meta.url);
const { chromium } = require('playwright');
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const BG = 'e2e-break-glass-secret-0123456789abcdef';
const API = 'http://127.0.0.1:18180';
const IDP = 'http://127.0.0.1:18190';

const listen = (h, port) => new Promise((res) => { const s = http.createServer(h).listen(port, '127.0.0.1', () => res(s)); });

// ---- list mirror
const mirror = await listen((req, res) => { res.setHeader('content-type', 'text/plain'); res.end(req.url === '/d.txt' ? 'ads.test\ntracker.test\n' : '##.ad\n'); }, 18182);

// ---- mock OIDC provider (authorization code + PKCE S256, ES256 id_token)
const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
const jwk = { ...publicKey.export({ format: 'jwk' }), kid: 'k1', use: 'sig', alg: 'ES256' };
const b64u = (b) => Buffer.from(b).toString('base64url');
const codes = new Map();
const idp = await listen((req, res) => {
  const u = new URL(req.url, IDP);
  const json = (o) => { res.setHeader('content-type', 'application/json'); res.setHeader('access-control-allow-origin', '*'); res.end(JSON.stringify(o)); };
  if (u.pathname === '/.well-known/openid-configuration') return json({ issuer: IDP, authorization_endpoint: `${IDP}/authorize`, token_endpoint: `${IDP}/token`, jwks_uri: `${IDP}/jwks` });
  if (u.pathname === '/jwks') return json({ keys: [jwk] });
  if (u.pathname === '/authorize') {
    const p = u.searchParams;
    assert.equal(p.get('code_challenge_method'), 'S256');
    const code = crypto.randomUUID();
    codes.set(code, { challenge: p.get('code_challenge'), nonce: p.get('nonce'), client: p.get('client_id') });
    res.statusCode = 302;
    res.setHeader('location', `${p.get('redirect_uri')}?code=${code}&state=${p.get('state')}`);
    return res.end();
  }
  if (u.pathname === '/token' && req.method === 'OPTIONS') { res.setHeader('access-control-allow-origin', '*'); res.setHeader('access-control-allow-headers', 'content-type'); return res.end(); }
  if (u.pathname === '/token') {
    let body = '';
    req.on('data', (c) => (body += c));
    req.on('end', () => {
      const p = new URLSearchParams(body);
      const c = codes.get(p.get('code'));
      codes.delete(p.get('code'));
      const ok = c && crypto.createHash('sha256').update(p.get('code_verifier')).digest('base64url') === c.challenge;
      if (!ok) { res.statusCode = 400; res.setHeader('access-control-allow-origin', '*'); return res.end('{"error":"invalid_grant"}'); }
      const head = b64u(JSON.stringify({ alg: 'ES256', typ: 'JWT', kid: 'k1' }));
      const pay = b64u(JSON.stringify({ iss: IDP, aud: c.client, sub: 'alice', email: 'alice@example.com', nonce: c.nonce, exp: Math.floor(Date.now() / 1000) + 600 }));
      const sig = crypto.sign('sha256', Buffer.from(`${head}.${pay}`), { key: privateKey, dsaEncoding: 'ieee-p1363' });
      json({ id_token: `${head}.${pay}.${b64u(sig)}`, token_type: 'Bearer' });
    });
    return;
  }
  res.statusCode = 404; res.end();
}, 18190);

// ---- hygeia
const dir = mkdtempSync(path.join(tmpdir(), 'hygeia-web-e2e-'));
const cfg = path.join(dir, 'hygeia.toml');
writeFileSync(cfg, `
[api]
listen = "127.0.0.1:18180"
web_dir = "${path.join(root, 'web/out')}"
[auth]
environment = "staging"
[auth.break_glass]
enabled = true
[auth.oidc]
issuer = "${IDP}"
audience = "hygeia-ui"
client_id = "hygeia-ui"
allow_insecure_http = true
bootstrap_owners = ["alice"]
[dns]
enabled = false
[lists]
sources = []
allow_insecure_http = true
[[lists.custom]]
id = "d"
name = "Test DNS list"
url = "http://127.0.0.1:18182/d.txt"
format = "domains"
license = "CC0-1.0"
attribution = "e2e"
network = true
`);
const hy = spawn(path.join(root, 'target/debug/hygeia'), [cfg], { env: { ...process.env, HYGEIA_BREAK_GLASS_TOKEN: BG }, stdio: 'inherit' });
process.on('exit', () => hy.kill());
const cleanup = () => { hy.kill(); mirror.close(); idp.close(); };

const csp = [];
let pageRef = null;
try {
  for (let i = 0; i < 50; i++) { try { if ((await fetch(`${API}/healthz`)).ok) break; } catch {} await new Promise((r) => setTimeout(r, 200)); }

  // security headers on the UI
  const index = await fetch(`${API}/`);
  assert.equal(index.status, 200);
  const policy = index.headers.get('content-security-policy');
  assert.match(policy, /script-src 'self' 'sha256-/);
  assert.doesNotMatch(policy, /script-src[^;]*unsafe-inline/);
  assert.equal(index.headers.get('x-frame-options'), 'DENY');
  assert.equal((await fetch(`${API}/v1/config`)).status, 200);
  assert.equal((await fetch(`${API}/does-not-exist/`)).status, 404);
  assert.equal((await fetch(`${API}/v1/admin/rules`)).status, 401, 'API still takes precedence over the UI fallback');

  const browser = await chromium.launch({ args: ['--no-sandbox'] });
  const ctx = await browser.newContext();
  const page = await ctx.newPage();
  pageRef = page;
  page.on('console', (m) => { if (/Content Security Policy|Refused to/i.test(m.text())) csp.push(m.text()); });
  page.on('pageerror', (e) => csp.push(`pageerror: ${e.message}`));
  page.on('dialog', (d) => d.accept());

  // ---- break-glass login
  await page.goto(`${API}/`);
  await page.waitForURL('**/login/');
  await page.getByText('STAGING environment').first().waitFor();
  await page.fill('#token', 'wrong-token-wrong-token-wrong-token-xx');
  await page.getByRole('button', { name: 'Sign in with token' }).click();
  await page.locator('p[role="alert"]').waitFor();
  await page.fill('#token', BG);
  await page.getByRole('button', { name: 'Sign in with token' }).click();
  await page.waitForURL(`${API}/`);
  await page.getByTestId('who').filter({ hasText: 'break-glass' }).waitFor();
  await page.getByRole('note').filter({ hasText: 'break-glass access is enabled' }).waitFor();

  // ---- groups, rules, simulation
  await page.getByRole('link', { name: 'Access' }).click();
  await page.getByLabel('Group name').fill('staff');
  await page.getByRole('button', { name: 'Create', exact: true }).click();
  await page.locator('span', { hasText: /^staff$/ }).first().waitFor();

  await page.getByRole('link', { name: 'Rules' }).click();
  await page.getByLabel('Domain', { exact: true }).fill('ads.example.com');
  await page.getByRole('button', { name: 'Add', exact: true }).click();
  await page.getByRole('cell', { name: 'ads.example.com', exact: true }).waitFor();
  await page.getByLabel('Simulate host').fill('x.ads.example.com');
  await page.getByLabel('Pretend domain').fill('x.ads.example.com');
  await page.getByRole('button', { name: 'Evaluate' }).click();
  const sim = page.getByTestId('sim-result');
  await sim.waitFor();
  assert.match(await sim.innerText(), /Now:\s*Block/);
  assert.match(await sim.innerText(), /With the rule:\s*Allow/);
  await page.getByLabel('Domain', { exact: true }).fill('not a domain');
  await page.getByRole('button', { name: 'Add', exact: true }).click();
  await page.locator('p[role="alert"]').waitFor();

  // ---- enrollment token shown once, then a device enrolls and can be revoked
  await page.getByRole('link', { name: 'Devices' }).click();
  await page.getByRole('button', { name: 'Create enrollment token' }).click();
  const secret = await page.getByTestId('one-time-secret').innerText();
  assert.match(secret, /^hyg_enr_/);
  const enrolled = await fetch(`${API}/v1/enroll`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ token: secret, device_info: 'e2e-browser' }) });
  assert.equal(enrolled.status, 200);
  await page.getByRole('button', { name: 'Done' }).click();
  await page.getByTestId('one-time-secret').waitFor({ state: 'detached' });
  await page.reload();
  await page.getByRole('cell', { name: 'e2e-browser' }).waitFor();
  assert.match(await page.getByTestId('pubkey').innerText(), /^[0-9a-f]{64}$/);
  await page.getByRole('button', { name: 'Revoke' }).click();
  await page.locator('span', { hasText: /^revoked$/ }).first().waitFor();

  // ---- lists
  await page.getByRole('link', { name: 'Filter lists' }).click();
  await page.getByRole('cell', { name: /Test DNS list/ }).waitFor();
  await page.getByText('CC0-1.0').waitFor();
  await page.locator('span', { hasText: /^ok$/ }).first().waitFor();
  // per-tenant selection: all -> selected (nothing) -> subscribe -> unsubscribe -> all
  await page.getByLabel(/All platform-enabled lists/).waitFor();
  await page.getByLabel('Only the lists selected below').check();
  await page.getByText('No lists selected').waitFor();
  await page.getByLabel('List source').selectOption({ label: 'Test DNS list (CC0-1.0)' });
  await page.getByRole('button', { name: 'Subscribe' }).click();
  await page.getByRole('button', { name: 'Unsubscribe Test DNS list' }).waitFor();
  await page.getByRole('button', { name: 'Unsubscribe Test DNS list' }).click();
  await page.getByText('No lists selected').waitFor();
  await page.getByLabel(/All platform-enabled lists/).check();
  await page.getByRole('button', { name: 'Subscribe' }).waitFor({ state: 'detached' });

  // ---- audit: chain intact, break-glass usage visible, secrets absent
  await page.getByRole('link', { name: 'Audit' }).click();
  await page.getByRole('button', { name: 'Verify chain' }).click();
  await page.getByTestId('verify').filter({ hasText: 'intact' }).waitFor();
  await page.locator('span', { hasText: 'auth.break_glass' }).first().waitFor();
  const html = await page.content();
  assert.ok(!html.includes(secret) && !html.includes(BG), 'secrets must not appear in the audit view');

  // ---- tenants (platform) + API token for a restricted role
  await page.getByRole('link', { name: 'Tenants' }).click();
  await page.getByLabel('Slug').fill('acme');
  await page.getByLabel('Name', { exact: true }).fill('Acme');
  await page.getByRole('button', { name: 'Create', exact: true }).click();
  await page.getByRole('cell', { name: 'acme', exact: true }).waitFor();

  await page.getByRole('link', { name: 'Access' }).click();
  await page.getByLabel('Token name').fill('viewer-token');
  await page.getByLabel('Token role').selectOption('viewer');
  await page.getByRole('button', { name: 'Create token' }).click();
  const apiToken = await page.getByTestId('one-time-secret').innerText();
  assert.match(apiToken, /^hyg_api_/);

  // ---- sign out, then sign in with the viewer token: read-only experience
  await page.getByRole('button', { name: 'Sign out' }).click();
  await page.waitForURL('**/login/');
  await page.fill('#token', apiToken);
  await page.getByRole('button', { name: 'Sign in with token' }).click();
  await page.waitForURL(`${API}/`);
  await page.getByTestId('who').filter({ hasText: 'API token' }).waitFor();
  assert.equal(await page.getByRole('link', { name: 'Tenants' }).count(), 0, 'platform pages are hidden for tenant roles');
  await page.getByRole('link', { name: 'Audit' }).click();
  await page.locator('p[role="alert"]').filter({ hasText: 'role does not allow' }).first().waitFor();

  // ---- OIDC (PKCE) login as alice, platform owner via bootstrap_owners
  await page.getByRole('button', { name: 'Sign out' }).click();
  await page.waitForURL('**/login/');
  await page.getByRole('button', { name: 'Sign in with single sign-on' }).click();
  await page.waitForURL(`${API}/`, { timeout: 15000 });
  await page.getByTestId('who').filter({ hasText: 'alice@example.com' }).waitFor();
  await page.getByText('platform', { exact: true }).waitFor();
  assert.equal(await page.getByRole('link', { name: 'Tenants' }).count(), 1);

  // ---- an invalid session is dropped and sends the user to login
  await page.evaluate(() => sessionStorage.setItem('hygeia.session', JSON.stringify({ token: 'hyg_api_revoked', kind: 'token' })));
  await page.reload();
  await page.waitForURL('**/login/');

  assert.deepEqual(csp, [], `CSP violations / page errors:\n${csp.join('\n')}`);
  console.log('WEB E2E OK');
  await browser.close();
  cleanup();
  process.exit(0);
} catch (e) {
  console.error('WEB E2E FAILED:', e);
  if (pageRef) console.error('PAGE TEXT:', (await pageRef.locator('main').innerText().catch(() => '?')).slice(0, 1500), '\nURL:', pageRef.url());
  if (csp.length) console.error('console/CSP:', csp);
  cleanup();
  process.exit(1);
}
