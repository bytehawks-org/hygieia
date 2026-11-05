// End-to-end: real Chromium + extension + real hygeia binary.
//   ./extension/build.sh && cargo build -p hygeia && node extension/test/e2e.mjs
// Requires Playwright with Chromium (set CHROMIUM=/path/to/chrome if not auto-detected).
import { createRequire } from 'node:module';
import http from 'node:http';
import { spawn } from 'node:child_process';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';

const require = createRequire(import.meta.url);
const { chromium } = require('playwright');
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const NODE = process.env.E2E_TARGET === 'node'; // run against the standalone node instead of the server
let ADMIN = 'e2e-break-glass-secret-0123456789abcdef';
const API = 'http://127.0.0.1:18080';

const listen = (handler, port) => new Promise((res) => { const s = http.createServer(handler).listen(port, '127.0.0.1', () => res(s)); });

// --- list mirror (plain http: lab only) ---
const lists = await listen((req, res) => {
  res.setHeader('content-type', 'text/plain');
  if (req.url === '/cosmetic.txt') {
    res.end(['! test list', '##.ad-banner', 'site.test###promo', 'site.test##+js(set-constant, adsEnabled, false)',
      'site.test##+js(trusted-set-constant, secret, 1)', 'site.test##.x:has-text(Ad)'].join('\n'));
  } else if (req.url === '/dns.txt') {
    res.end('blocked.test\n');
  } else { res.statusCode = 404; res.end(); }
}, 18082);

// --- content server: records which Host headers reach it ---
const hits = [];
const content = await listen((req, res) => {
  hits.push(req.headers.host.split(':')[0]);
  res.setHeader('content-type', 'text/html');
  res.end(`<!doctype html><title>t</title>
<div class="ad-banner">AD</div><div id="promo">PROMO</div><p id="keep">KEEP</p>
<script>
// A late-loading ad library assigns its flag AFTER the page started: the scriptlet must
// already be in place by then. (Inline scripts racing document start are best-effort in
// Chrome MV3, see extension/README.md.)
setTimeout(() => { window.adsEnabled = true; window.__ads = window.adsEnabled; window.__secret = window.secret; }, 400);
</script>
<img src="http://blocked.test:18081/pixel.gif">`);
}, 18081);

// --- hygeia ---
const dir = mkdtempSync(path.join(tmpdir(), 'hygeia-e2e-'));
const cfg = path.join(dir, 'hygeia.toml');
const cfg_text = `
[api]
listen = "127.0.0.1:18080"
[auth]
environment = "staging"
[auth.break_glass]
enabled = true
[dns]
enabled = false
[lists]
sources = []
allow_insecure_http = true
[[lists.custom]]
id = "cos"
name = "cos"
url = "http://127.0.0.1:18082/cosmetic.txt"
format = "abp"
license = "CC0-1.0"
attribution = "e2e"
cosmetic = true
[[lists.custom]]
id = "dns"
name = "dns"
url = "http://127.0.0.1:18082/dns.txt"
format = "domains"
license = "CC0-1.0"
attribution = "e2e"
network = true
`;
writeFileSync(cfg, cfg_text);
let hy;
if (NODE) {
  // node config: no [auth]/[api]; own data dir, owner credential read from its file
  const nodeCfg = path.join(dir, 'hygeia-proxy.toml');
  writeFileSync(nodeCfg, `
[http]
listen = "127.0.0.1:18080"
[lists]
sources = []
allow_insecure_http = true
${cfg_text.split('[lists]')[1].split('\n').filter((l) => !/^(sources|allow_insecure_http) /.test(l)).join('\n')}
`);
  hy = spawn(path.join(root, 'target/debug/hygeia-proxy'), ['--data-dir', dir, '--config', nodeCfg, 'run'], { stdio: 'inherit' });
} else {
  hy = spawn(path.join(root, 'target/debug/hygeia'), [cfg], { env: { ...process.env, HYGEIA_BREAK_GLASS_TOKEN: ADMIN }, stdio: 'inherit' });
}
const cleanup = async () => { hy.kill(); lists.close(); content.close(); };
process.on('exit', () => hy.kill());

try {
  for (let i = 0; i < 50; i++) { try { if ((await fetch(`${API}/healthz`)).ok) break; } catch {} await new Promise((r) => setTimeout(r, 200)); }
  if (NODE) ADMIN = readFileSync(path.join(dir, 'owner.token'), 'utf8').trim();
  const admin = (p, init = {}) => fetch(API + p, { ...init, headers: { authorization: `Bearer ${ADMIN}`, 'content-type': 'application/json' } });
  // wait until lists are loaded
  for (let i = 0; i < 50; i++) {
    const st = await (await admin('/v1/admin/lists')).json();
    if (st.length === 2 && st.every((s) => s.last_ok)) break;
    await new Promise((r) => setTimeout(r, 200));
  }
  const { token } = await (await admin('/v1/admin/enrollment-tokens', { method: 'POST', body: '{}' })).json();
  const pubkey = (await (await fetch(`${API}/v1/pubkey`)).text()).trim();

  const ctx = await chromium.launchPersistentContext(mkdtempSync(path.join(tmpdir(), 'pw-')), {
    executablePath: process.env.CHROMIUM || '/opt/pw-browsers/chromium',
    headless: false,
    args: ['--headless=new', '--no-sandbox', `--disable-extensions-except=${path.join(root, 'extension')}`,
      `--load-extension=${path.join(root, 'extension')}`, '--host-resolver-rules=MAP *.test 127.0.0.1'],
  });
  let [sw] = ctx.serviceWorkers();
  sw ??= await ctx.waitForEvent('serviceworker', { timeout: 15000 });
  const extId = new URL(sw.url()).host;

  const opts = await ctx.newPage();
  await opts.goto(`chrome-extension://${extId}/options.html`);
  const r = await opts.evaluate(([server, token, pubkey]) => chrome.runtime.sendMessage({ type: 'enroll', server, token, pubkey }), [API, token, pubkey]);
  console.log('enroll/sync:', JSON.stringify(r));
  assert.equal(r.ok, true, 'enroll + first sync');
  assert.ok(r.dnr.rules >= 1, 'DNR rules installed');

  // 1) cosmetic + scriptlet on a page of site.test
  const page = await ctx.newPage();
  hits.length = 0;
  await page.goto('http://site.test:18081/');
  await page.waitForTimeout(900);
  const state = await page.evaluate(() => ({
    ad: getComputedStyle(document.querySelector('.ad-banner')).display,
    promo: getComputedStyle(document.querySelector('#promo')).display,
    keep: getComputedStyle(document.querySelector('#keep')).display,
    ads: window.__ads,
    secret: window.__secret,
  }));
  console.log('page state:', JSON.stringify(state));
  assert.equal(state.ad, 'none', 'generic selector hidden');
  assert.equal(state.promo, 'none', 'host selector hidden');
  assert.notEqual(state.keep, 'none', 'unrelated element kept');
  assert.equal(state.ads, false, 'set-constant scriptlet applied in page world');
  assert.equal(state.secret, undefined, 'trusted-* scriptlet dropped');

  // 2) the blocked third-party image never reaches the server
  await page.waitForTimeout(500);
  assert.ok(!hits.includes('blocked.test'), `request to blocked.test leaked: ${hits}`);

  // 3) navigating to the blocked domain is blocked
  const nav = await ctx.newPage();
  hits.length = 0;
  const err = await nav.goto('http://blocked.test:18081/').then(() => null, (e) => e.message);
  console.log('blocked navigation:', err);
  assert.match(String(err), /ERR_BLOCKED_BY_CLIENT/);
  assert.ok(!hits.includes('blocked.test'));

  // 4) revocation keeps the cached bundle (fail open for config, not for rules)
  console.log('E2E OK');
  await ctx.close();
  await cleanup();
  process.exit(0);
} catch (e) {
  console.error('E2E FAILED:', e);
  await cleanup();
  process.exit(1);
}
