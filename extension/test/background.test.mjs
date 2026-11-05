// Runs background.js against a FAKE browser API with the real WASM engine and a real signed bundle.
// Verifies the Firefox path (webRequest blocking, no DNR) and the Chromium path (DNR) without a browser.
//   ./extension/build.sh && node --test extension/test/background.test.mjs
import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, '../..');
const fixtures = mkdtempSync(path.join(tmpdir(), 'hygeia-fixture-'));
const mk = (dir, version) => execFileSync('cargo', ['run', '-q', '-p', 'hygeia-blocker', '--example', 'make_bundle', '--', dir, String(version)], { cwd: root });
mk(fixtures, 5);
const bundle5 = readFileSync(path.join(fixtures, 'bundle.bin'));
const pubkey = readFileSync(path.join(fixtures, 'pubkey.hex'), 'utf8');
const older = mkdtempSync(path.join(tmpdir(), 'hygeia-fixture-'));
mk(older, 3);
const bundle3 = readFileSync(path.join(older, 'bundle.bin'));

const SERVER = 'http://hygeia.test';
const listeners = {};
const onEvent = (name) => ({ addListener: (fn, ...rest) => { listeners[name] = { fn, rest }; } });

function installFakes({ firefox }) {
  const local = {};
  const spies = { dnr: [], scripts: [], css: [], dnrUsed: false };
  const idb = new Map();
  globalThis.indexedDB = {
    open() {
      const req = {};
      queueMicrotask(() => {
        req.result = {
          createObjectStore() {},
          transaction() {
            const tx = {};
            tx.objectStore = () => ({
              get(k) { const r = {}; queueMicrotask(() => { r.result = idb.get(k); r.onsuccess?.(); }); return r; },
              put(v, k) { idb.set(k, v); queueMicrotask(() => tx.oncomplete?.()); },
            });
            return tx;
          },
        };
        req.onupgradeneeded?.();
        req.onsuccess?.();
      });
      return req;
    },
  };
  const fake = {
    runtime: { onMessage: onEvent('message'), onStartup: onEvent('startup'), onInstalled: onEvent('installed') },
    storage: { local: {
      get: async (keys) => Object.fromEntries((Array.isArray(keys) ? keys : [keys]).map((k) => [k, local[k]])),
      set: async (o) => { Object.assign(local, o); },
    } },
    alarms: { create() {}, onAlarm: onEvent('alarm') },
    webNavigation: { onCommitted: onEvent('committed') },
    scripting: {
      executeScript: async (o) => { spies.scripts.push(o); },
      insertCSS: async (o) => { spies.css.push(o); },
    },
    declarativeNetRequest: {
      getDynamicRules: async () => { spies.dnrUsed = true; return []; },
      updateDynamicRules: async (o) => { spies.dnrUsed = true; spies.dnr.push(o); },
    },
  };
  if (firefox) {
    fake.runtime.getBrowserInfo = async () => ({ name: 'Firefox' });
    fake.webRequest = { onBeforeRequest: onEvent('webrequest') };
    globalThis.browser = fake;
    delete globalThis.chrome;
  } else {
    globalThis.chrome = fake;
    delete globalThis.browser;
  }
  let bundleResponse = { status: 200, body: bundle5 };
  const realFetch = globalThis.fetch;
  globalThis.fetch = async (url, init) => {
    const u = String(url);
    if (u.startsWith('file:')) return new Response(readFileSync(new URL(u)), { headers: { 'content-type': 'application/wasm' } });
    if (u === `${SERVER}/v1/enroll`) return Response.json({ device_id: 'd1', device_secret: 'hyg_dev_x' });
    if (u === `${SERVER}/v1/bundle`) {
      const r = bundleResponse;
      return new Response(r.status === 200 ? r.body : null, { status: r.status, headers: { ETag: `"e${r.body?.length ?? 0}"` } });
    }
    return realFetch(url, init);
  };
  return { local, spies, setBundle: (status, body) => { bundleResponse = { status, body }; } };
}

const send = (msg, sender = {}) => new Promise((res) => { listeners.message.fn(msg, sender, res); });
const enroll = () => send({ type: 'enroll', server: SERVER, token: 'hyg_enr_x', pubkey });

test('Firefox: webRequest blocking with the full engine, no DNR', async () => {
  const env = installFakes({ firefox: true });
  await import('../background.js?ff');
  assert.ok(listeners.webrequest, 'blocking listener registered at top level');
  assert.deepEqual(listeners.webrequest.rest[1], ['blocking']);

  const r = await enroll();
  assert.equal(r.ok, true);
  assert.equal(r.dnr.mode, 'webRequest');
  assert.equal(env.spies.dnrUsed, false, 'DNR must not be touched on Firefox');

  const decide = (url, extra = {}) => listeners.webrequest.fn({ url, originUrl: 'https://page.test/', ...extra });
  assert.deepEqual(await decide('https://sub.blocked.test/x'), { cancel: true }, 'custom block, subdomain');
  assert.deepEqual(await decide('https://x.ads.test/p.js'), { cancel: true }, 'list block');
  assert.deepEqual(await decide('https://ok.ads.test/p.js'), {}, 'custom allow beats list block');
  assert.deepEqual(await decide('https://example.org/'), {});
  assert.deepEqual(await decide('https://blocked.test/', { originUrl: 'moz-extension://abc/bg.js' }), {}, 'own traffic is never filtered');

  // cosmetics + insert-css fallback + scriptlet injection
  const cos = await send({ type: 'cosmetics', host: 'www.site.test' });
  assert.deepEqual(cos.selectors, ['.ad-banner', '#promo']);
  assert.equal((await send({ type: 'insert-css', css: '.x{display:none}' }, { tab: { id: 7 }, frameId: 2 })).ok, true);
  assert.deepEqual(env.spies.css[0].target, { tabId: 7, frameIds: [2] });
  assert.equal(env.spies.css[0].origin, 'USER');
  assert.equal((await send({ type: 'insert-css', css: 'x' }, {})).ok, false, 'no tab: refused');
  await listeners.committed.fn({ url: 'https://www.site.test/', tabId: 7, frameId: 0 });
  assert.equal(env.spies.scripts.length, 1);
  assert.equal(env.spies.scripts[0].world, 'MAIN');
  assert.deepEqual(env.spies.scripts[0].args[0], [{ name: 'set-constant', args: ['adsEnabled', 'false'] }]);
  await listeners.committed.fn({ url: 'https://other.test/', tabId: 7, frameId: 0 });
  assert.equal(env.spies.scripts.length, 1, 'no scriptlets for other hosts');
  await listeners.committed.fn({ url: 'about:blank', tabId: 7, frameId: 0 });
  assert.equal(env.spies.scripts.length, 1);

  // rollback is refused, the installed bundle stays in force
  env.setBundle(200, bundle3);
  const rb = await send({ type: 'sync' });
  assert.equal(rb.ok, false);
  assert.match(rb.status, /rollback/);
  assert.deepEqual(await decide('https://sub.blocked.test/x'), { cancel: true });

  // revoked device (401) and server outage: cached bundle keeps blocking (fail open for config)
  env.setBundle(401, null);
  assert.match((await send({ type: 'sync' })).status, /revoked/);
  assert.deepEqual(await decide('https://sub.blocked.test/x'), { cancel: true });
});

test('Chromium: declarativeNetRequest rules from the plan', async () => {
  const env = installFakes({ firefox: false });
  listeners.webrequest = undefined;
  await import('../background.js?chrome');
  assert.equal(listeners.webrequest, undefined, 'no webRequest blocking on Chromium');

  const r = await enroll();
  assert.equal(r.ok, true);
  assert.equal(r.dnr.mode, 'dnr');
  const add = env.spies.dnr.at(-1).addRules;
  const byPrio = (p) => add.filter((x) => x.priority === p);
  assert.deepEqual(byPrio(4)[0].action, { type: 'allow' });
  assert.deepEqual(byPrio(4)[0].condition.requestDomains, ['ok.ads.test']);
  assert.deepEqual(byPrio(3)[0].condition.requestDomains, ['blocked.test']);
  assert.deepEqual(byPrio(1)[0].condition.requestDomains, ['ads.test']);
  assert.ok(add.every((x) => x.condition.resourceTypes.includes('main_frame')));
  assert.deepEqual(add.map((x) => x.id), add.map((_, i) => i + 1));
});
