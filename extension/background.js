import init, { Engine } from './pkg/hygeia_blocker.js';
import { injectScriptlets } from './scriptlets.js';

// Domains per DNR budget. Chrome accepted 1M domains in 1000 grouped rules in testing (the 30k
// dynamic-rule cap counts rules, and one rule holds many requestDomains); browsing-latency impact
// at that size is NOT measured, hence the conservative default. Higher-precedence groups are kept first.
const DNR_DOMAIN_BUDGET = 500000;
const RESOURCE_TYPES = ['main_frame', 'sub_frame', 'script', 'image', 'stylesheet', 'object',
  'xmlhttprequest', 'ping', 'media', 'font', 'websocket', 'other'];

// ---------- storage ----------
const get = (keys) => chrome.storage.local.get(keys);
const set = (obj) => chrome.storage.local.set(obj);

function idb() {
  return new Promise((resolve, reject) => {
    const r = indexedDB.open('hygeia', 1);
    r.onupgradeneeded = () => r.result.createObjectStore('kv');
    r.onsuccess = () => resolve(r.result);
    r.onerror = () => reject(r.error);
  });
}
async function idbGet(k) {
  const db = await idb();
  return new Promise((res, rej) => {
    const q = db.transaction('kv').objectStore('kv').get(k);
    q.onsuccess = () => res(q.result);
    q.onerror = () => rej(q.error);
  });
}
async function idbPut(k, v) {
  const db = await idb();
  return new Promise((res, rej) => {
    const t = db.transaction('kv', 'readwrite');
    t.objectStore('kv').put(v, k);
    t.oncomplete = () => res();
    t.onerror = () => rej(t.error);
  });
}

// ---------- engine ----------
let wasmReady = null;
let engine = null;
let enginePromise = null;

function ensureWasm() {
  wasmReady ??= init();
  return wasmReady;
}

/** Load the cached bundle once per service-worker lifetime. */
function getEngine() {
  enginePromise ??= (async () => {
    await ensureWasm();
    const { pubkey } = await get(['pubkey']);
    const bytes = await idbGet('bundle');
    if (!bytes || !pubkey) return null;
    try {
      engine = Engine.load(new Uint8Array(bytes), pubkey, 0);
    } catch (e) {
      await set({ status: `cached bundle rejected: ${e.message}` });
      engine = null;
    }
    return engine;
  })();
  return enginePromise;
}

async function applyDnr(eng) {
  const plan = JSON.parse(eng.dnr_plan(DNR_DOMAIN_BUDGET));
  const old = await chrome.declarativeNetRequest.getDynamicRules();
  const addRules = plan.rules.map((r, i) => ({
    id: i + 1,
    priority: r.priority,
    action: { type: r.action },
    condition: { requestDomains: r.domains, resourceTypes: RESOURCE_TYPES },
  }));
  await chrome.declarativeNetRequest.updateDynamicRules({ removeRuleIds: old.map((r) => r.id), addRules });
  return { rules: addRules.length, truncated: plan.truncated };
}

// ---------- sync ----------
async function sync() {
  const c = await get(['server', 'deviceSecret', 'pubkey', 'etag', 'version']);
  if (!c.server || !c.deviceSecret || !c.pubkey) return { ok: false, status: 'not enrolled' };
  await ensureWasm();
  const headers = { Authorization: `Bearer ${c.deviceSecret}` };
  if (c.etag) headers['If-None-Match'] = c.etag;
  let resp;
  try {
    resp = await fetch(`${c.server}/v1/bundle`, { headers, cache: 'no-store' });
  } catch (e) {
    // Fail open: keep enforcing the last good bundle.
    const status = `server unreachable (${e.message}); using cached bundle`;
    await set({ status });
    return { ok: false, status };
  }
  if (resp.status === 304) {
    await set({ status: `up to date (v${c.version}) at ${new Date().toISOString()}` });
    return { ok: true, status: 'up to date' };
  }
  if (resp.status === 401) {
    const status = 'device credential revoked or invalid; keeping cached bundle';
    await set({ status });
    return { ok: false, status };
  }
  if (!resp.ok) {
    const status = `server error ${resp.status}`;
    await set({ status });
    return { ok: false, status };
  }
  const bytes = new Uint8Array(await resp.arrayBuffer());
  let next;
  try {
    next = Engine.load(bytes, c.pubkey, c.version || 0); // verifies signature + refuses rollback
  } catch (e) {
    const status = `bundle rejected: ${e.message}`;
    await set({ status });
    return { ok: false, status };
  }
  const dnr = await applyDnr(next);
  await idbPut('bundle', bytes.buffer);
  engine = next;
  enginePromise = Promise.resolve(next);
  const version = next.version();
  await set({
    etag: resp.headers.get('ETag'),
    version,
    dnr,
    sources: JSON.parse(next.sources()),
    status: `bundle v${version} installed at ${new Date().toISOString()}`,
  });
  return { ok: true, status: `installed v${version}`, dnr };
}

async function enroll({ server, token, pubkey }) {
  server = server.replace(/\/+$/, '');
  if (!/^https?:\/\//.test(server)) throw new Error('server must be an http(s) URL');
  if (!/^[0-9a-fA-F]{64}$/.test(pubkey)) throw new Error('public key must be 64 hex characters');
  const r = await fetch(`${server}/v1/enroll`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ token, device_info: `${navigator.userAgent}`.slice(0, 200) }),
  });
  if (!r.ok) throw new Error(`enrollment refused (${r.status})`);
  const j = await r.json();
  await set({ server, pubkey: pubkey.toLowerCase(), deviceId: j.device_id, deviceSecret: j.device_secret, etag: null, version: 0 });
  return sync();
}

// ---------- events ----------
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  (async () => {
    if (msg.type === 'cosmetics') {
      const eng = await getEngine();
      if (!eng || typeof msg.host !== 'string') return { selectors: [], scriptlets: [] };
      const c = JSON.parse(eng.cosmetics_for(msg.host));
      return { selectors: c.selectors };
    }
    if (msg.type === 'enroll') return enroll(msg);
    if (msg.type === 'sync') return sync();
    if (msg.type === 'status') return get(['server', 'deviceId', 'version', 'status', 'dnr', 'sources', 'pubkey']);
    return null;
  })().then(sendResponse, (e) => sendResponse({ ok: false, error: e.message }));
  return true; // async response
});

chrome.webNavigation.onCommitted.addListener(async (d) => {
  if (!/^https?:/.test(d.url)) return;
  try {
    const eng = await getEngine();
    if (!eng) return;
    const calls = JSON.parse(eng.cosmetics_for(new URL(d.url).hostname)).scriptlets;
    if (!calls.length) return;
    await chrome.scripting.executeScript({
      target: { tabId: d.tabId, frameIds: [d.frameId] },
      world: 'MAIN',
      injectImmediately: true,
      func: injectScriptlets,
      args: [calls],
    });
  } catch { /* tab gone or restricted page */ }
});

chrome.alarms.create('hygeia-sync', { periodInMinutes: 30 });
chrome.alarms.onAlarm.addListener((a) => { if (a.name === 'hygeia-sync') sync().catch(() => {}); });
chrome.runtime.onStartup.addListener(() => sync().catch(() => {}));
chrome.runtime.onInstalled.addListener(() => sync().catch(() => {}));
