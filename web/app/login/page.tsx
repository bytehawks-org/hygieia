'use client';
import { useEffect, useState, type FormEvent } from 'react';
import { Badge, Button, ErrorBox } from '@/components/ui';
import { api } from '@/lib/api';
import { startLogin } from '@/lib/oidc';
import { saveSession } from '@/lib/session';
import type { PublicConfig } from '@/lib/types';

export default function Login() {
  const [cfg, setCfg] = useState<PublicConfig | null>(null);
  const [token, setToken] = useState('');
  const [err, setErr] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => { api.config().then(setCfg, setErr); }, []);

  // `hygeia-proxy open` lands here with the credential in the URL fragment: it is never sent to a
  // server and never logged. Use it once, then scrub it from the address bar and history.
  useEffect(() => {
    const m = /^#token=([A-Za-z0-9_\-.]+)$/.exec(window.location.hash);
    if (!m?.[1]) return;
    const t = m[1];
    window.history.replaceState(null, '', window.location.pathname);
    api.me(t).then(() => { saveSession({ token: t, kind: 'token' }); window.location.assign('/'); }, setErr);
  }, []);

  const withToken = async (e: FormEvent) => {
    e.preventDefault(); setErr(null); setBusy(true);
    try {
      await api.me(token.trim()); // validates the credential before it is stored
      saveSession({ token: token.trim(), kind: 'token' });
      window.location.assign('/');
    } catch (x) { setErr(x); } finally { setBusy(false); }
  };

  return (
    <main className="mx-auto mt-16 max-w-md space-y-4 p-4">
      <h1 className="text-2xl font-bold text-brand">Hygieia</h1>
      {cfg && cfg.environment !== 'production' && (
        <p role="note" className="rounded-md bg-amber-100 px-3 py-2 text-sm text-amber-900">{cfg.environment.toUpperCase()} environment{cfg.break_glass ? ' — break-glass access is enabled and audited' : ''}.</p>
      )}
      <ErrorBox error={err} />
      {cfg?.oidc && (
        <Button className="w-full" disabled={busy} onClick={async () => { setErr(null); try { await startLogin(cfg.oidc!); } catch (x) { setErr(x); } }}>Sign in with single sign-on</Button>
      )}
      <form onSubmit={withToken} className="space-y-2 rounded-xl border border-zinc-200 bg-white p-4 dark:border-zinc-800 dark:bg-zinc-900">
        <label className="block text-sm font-medium" htmlFor="token">
          {cfg?.mode === 'standalone' ? 'Owner credential' : 'API token'} {cfg?.break_glass && <Badge tone="amber">or break-glass</Badge>}
        </label>
        <input id="token" type="password" autoComplete="off" required className="w-full font-mono" placeholder="hyg_api_…" value={token} onChange={(e) => setToken(e.target.value)} />
        <Button type="submit" variant="ghost" className="w-full" disabled={busy}>Sign in with token</Button>
        <p className="text-xs text-zinc-500">The credential is kept in this tab only (sessionStorage) and sent as a bearer token to this server.</p>
      </form>
    </main>
  );
}
