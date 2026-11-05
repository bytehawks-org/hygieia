const $ = (id) => document.getElementById(id);
const api = globalThis.browser ?? globalThis.chrome;
const send = (m) => api.runtime.sendMessage(m);

async function refresh() {
  const s = await send({ type: 'status' });
  if (s?.server && !$('server').value) $('server').value = s.server;
  if (s?.pubkey && !$('pubkey').value) $('pubkey').value = s.pubkey;
  $('out').textContent = JSON.stringify(s, null, 2);
}

$('fetchkey').onclick = async () => {
  try {
    const base = $('server').value.replace(/\/+$/, '');
    const r = await fetch(`${base}/v1/pubkey`);
    $('pubkey').value = (await r.text()).trim();
  } catch (e) { $('out').textContent = `fetch failed: ${e.message}`; }
};
$('enroll').onclick = async () => {
  // Firefox may not have granted host access yet; must be requested from a user gesture.
  try {
    const origins = ['<all_urls>'];
    if (api.permissions && !(await api.permissions.contains({ origins }))) {
      if (!(await api.permissions.request({ origins }))) {
        $('out').textContent = 'Host permission denied: the blocker cannot work without it.';
        return;
      }
    }
  } catch { /* permissions API unavailable: proceed */ }
  const r = await send({ type: 'enroll', server: $('server').value, token: $('token').value.trim(), pubkey: $('pubkey').value.trim() });
  $('token').value = '';
  $('out').textContent = JSON.stringify(r, null, 2);
  setTimeout(refresh, 500);
};
$('sync').onclick = async () => { $('out').textContent = JSON.stringify(await send({ type: 'sync' }), null, 2); setTimeout(refresh, 500); };
refresh();
