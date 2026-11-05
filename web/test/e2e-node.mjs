// The standalone node end to end: CLI, local-owner sign-in through `open`, UI in a real Chromium.
//   (cd web && npm run build) && cargo build -p hygeia-proxy && node web/test/e2e-node.mjs
import { createRequire } from 'node:module';
import { spawn, execFileSync } from 'node:child_process';
import { chmodSync, mkdtempSync, readFileSync, writeFileSync, existsSync, readdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';

const require = createRequire(import.meta.url);
const { chromium } = require('playwright');
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const BIN = path.join(root, 'target/debug/hygeia-proxy');
const data = mkdtempSync(path.join(tmpdir(), 'hygeia-node-e2e-'));
const PORT = 18470;
const BASE = `http://127.0.0.1:${PORT}`;
writeFileSync(path.join(data, 'hygeia-proxy.toml'), `
[http]
listen = "127.0.0.1:${PORT}"
web_dir = "${path.join(root, 'web/out')}"
[lists]
enabled = false
`);
const cli = (...args) => execFileSync(BIN, ['--data-dir', data, ...args], { encoding: 'utf8', env: { ...process.env, HYGEIA_PROXY_OPEN_LINGER_SECS: '1' } });

assert.match(cli('check-config'), /configuration OK/);
assert.throws(() => cli('token'), /has the node been started once/);

const node = spawn(BIN, ['--data-dir', data, 'run'], { stdio: 'inherit' });
process.on('exit', () => node.kill());
let browser;
try {
  for (let i = 0; i < 50; i++) { try { if ((await fetch(`${BASE}/healthz`)).ok) break; } catch {} await new Promise((r) => setTimeout(r, 200)); }

  // ---- CLI
  const token = cli('token').trim();
  assert.match(token, /^hyg_own_[0-9a-f]{48}$/);
  assert.match(cli('pubkey').trim(), /^[0-9a-f]{64}$/);
  const info = cli('info');
  assert.match(info, /DNS:\s+Off/);
  assert.ok(info.includes(data));

  // `open` must not put the credential in a process argument: fake opener records its argv
  const bin = mkdtempSync(path.join(tmpdir(), 'fake-open-'));
  const log = path.join(bin, 'argv.txt');
  writeFileSync(path.join(bin, 'xdg-open'), `#!/bin/sh\necho "$@" > ${log}\ncp "$1" ${log}.page\n`);
  chmodSync(path.join(bin, 'xdg-open'), 0o755);
  execFileSync(BIN, ['--data-dir', data, 'open'], { env: { ...process.env, PATH: `${bin}:${process.env.PATH}`, HYGEIA_PROXY_OPEN_LINGER_SECS: '1' } });
  const argv = readFileSync(log, 'utf8');
  assert.ok(!argv.includes(token), 'credential must not be visible in the browser launcher argv');
  assert.match(readFileSync(`${log}.page`, 'utf8'), new RegExp(`${BASE}/login/#token=${token}`));
  assert.deepEqual(readdirSync(data).filter((f) => f.startsWith('open-')), [], 'the redirect page is removed again');

  // ---- UI
  browser = await chromium.launch({ args: ['--no-sandbox'] });
  const page = await (await browser.newContext()).newPage();
  const problems = [];
  page.on('console', (m) => { if (/Content Security Policy|Refused to/i.test(m.text())) problems.push(m.text()); });
  page.on('pageerror', (e) => problems.push(e.message));

  await page.goto(`${BASE}/login/#token=${token}`); // what the `open` page redirects to
  await page.waitForURL(`${BASE}/`);
  assert.ok(!page.url().includes('token'), 'credential scrubbed from the address bar');
  await page.getByTestId('who').filter({ hasText: 'local owner' }).waitFor();
  await page.getByText('Standalone node').waitFor();
  assert.equal(await page.getByRole('link', { name: 'Tenants' }).count(), 0, 'one implicit tenant: no tenant management');
  assert.equal(await page.locator('[role=note]').filter({ hasText: /break-glass/ }).count(), 0);

  await page.getByRole('link', { name: 'Rules' }).click();
  await page.getByLabel('Domain', { exact: true }).fill('ads.example.com');
  await page.getByRole('button', { name: 'Add', exact: true }).click();
  await page.getByRole('cell', { name: 'ads.example.com', exact: true }).waitFor();

  // a wrong fragment is rejected without leaving a session behind
  const other = await (await browser.newContext()).newPage();
  await other.goto(`${BASE}/login/#token=hyg_own_wrong`);
  await other.locator('p[role="alert"]').waitFor();
  assert.equal(await other.evaluate(() => sessionStorage.getItem('hygeia.session')), null);

  // the extension contract is served by the node (what the browser extension talks to)
  assert.match(await (await fetch(`${BASE}/v1/pubkey`)).text(), /^[0-9a-f]{64}$/);
  assert.equal((await fetch(`${BASE}/v1/admin/rules`)).status, 401);
  assert.deepEqual(problems, [], problems.join('\n'));
  console.log('NODE E2E OK');
  await browser.close();
  node.kill();
  process.exit(0);
} catch (e) {
  console.error('NODE E2E FAILED:', e);
  await browser?.close().catch(() => {});
  node.kill();
  process.exit(1);
}
