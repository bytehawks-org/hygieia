const $ = (id) => document.getElementById(id);
const send = (m) => chrome.runtime.sendMessage(m);

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
  const r = await send({ type: 'enroll', server: $('server').value, token: $('token').value.trim(), pubkey: $('pubkey').value.trim() });
  $('token').value = '';
  $('out').textContent = JSON.stringify(r, null, 2);
  setTimeout(refresh, 500);
};
$('sync').onclick = async () => { $('out').textContent = JSON.stringify(await send({ type: 'sync' }), null, 2); setTimeout(refresh, 500); };
refresh();
