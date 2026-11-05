'use client';
import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { createContext, useContext, useEffect, useMemo, useState, type ReactNode } from 'react';
import { api } from '@/lib/api';
import { clearSession, loadSession, loadTenant, saveTenant } from '@/lib/session';
import type { Principal, PublicConfig, Tenant } from '@/lib/types';
import { Badge, Button, ErrorBox } from './ui';

interface Ctx {
  config: PublicConfig;
  me: Principal;
  tenants: Tenant[];
  tenant: string;
  setTenant: (id: string) => void;
  tenantLabel: (id: string) => string;
  /** platform-level (tenant lifecycle, user directory): break-glass or a platform-wide owner binding */
  platform: boolean;
}
const AppCtx = createContext<Ctx | null>(null);
export const useApp = () => {
  const c = useContext(AppCtx);
  if (!c) throw new Error('useApp outside Shell');
  return c;
};

const DEFAULT_TENANT = '00000000-0000-0000-0000-000000000001';

function accessibleTenantIds(me: Principal): string[] {
  if (me.kind === 'api_token') return [me.tenant_id];
  if (me.kind === 'user') return [...new Set(me.bindings.flatMap((b) => (b.tenant_id ? [b.tenant_id] : [])))];
  return [];
}

const NAV: { href: string; label: string; platformOnly?: boolean; serverOnly?: boolean }[] = [
  { href: '/', label: 'Overview' },
  { href: '/rules/', label: 'Rules' },
  { href: '/devices/', label: 'Devices' },
  { href: '/lists/', label: 'Filter lists' },
  { href: '/audit/', label: 'Audit' },
  { href: '/access/', label: 'Access' },
  { href: '/tenants/', label: 'Tenants', platformOnly: true, serverOnly: true },
];

export function Shell({ children }: { children: ReactNode }) {
  const path = usePathname();
  const [state, setState] = useState<{ config: PublicConfig; me: Principal; tenants: Tenant[]; tenant: string } | null>(null);
  const [error, setError] = useState<unknown>(null);

  useEffect(() => {
    if (!loadSession()) { window.location.replace('/login/'); return; }
    (async () => {
      try {
        const [config, me] = await Promise.all([api.config(), api.me()]);
        const platform = me.kind === 'break_glass' || me.kind === 'local_owner' || (me.kind === 'user' && me.bindings.some((b) => b.tenant_id === null && b.role === 'owner'));
        let tenants: Tenant[] = [];
        if (platform) tenants = await api.tenants().catch(() => []);
        const ids = platform && tenants.length ? tenants.map((t) => t.id) : accessibleTenantIds(me);
        if (!platform) tenants = ids.map((id) => ({ id, slug: id === DEFAULT_TENANT ? 'default' : id.slice(0, 8), name: id === DEFAULT_TENANT ? 'Default' : id }));
        const saved = loadTenant();
        const tenant = saved && ids.includes(saved) ? saved : (ids[0] ?? DEFAULT_TENANT);
        setState({ config, me, tenants, tenant });
      } catch (e) { setError(e); }
    })();
  }, []);

  const ctx = useMemo<Ctx | null>(() => {
    if (!state) return null;
    const platform = state.me.kind === 'break_glass' || state.me.kind === 'local_owner' || (state.me.kind === 'user' && state.me.bindings.some((b) => b.tenant_id === null && b.role === 'owner'));
    return {
      config: state.config, me: state.me, tenants: state.tenants, tenant: state.tenant, platform,
      setTenant: (id) => { saveTenant(id); setState((s) => (s ? { ...s, tenant: id } : s)); },
      tenantLabel: (id) => state.tenants.find((t) => t.id === id)?.name ?? id.slice(0, 8),
    };
  }, [state]);

  if (error) return <main className="mx-auto max-w-lg p-8"><ErrorBox error={error} /><Link className="mt-4 inline-block underline" href="/login/">Back to login</Link></main>;
  if (!ctx) return <main className="p-8 text-sm text-zinc-500">Loading…</main>;

  const who = ctx.me.kind === 'break_glass' ? 'break-glass' : ctx.me.kind === 'local_owner' ? 'local owner' : ctx.me.kind === 'api_token' ? 'API token' : (ctx.me.email ?? ctx.me.subject);
  return (
    <AppCtx.Provider value={ctx}>
      {ctx.config.environment !== 'production' && (
        <div role="note" className="bg-amber-400 px-4 py-1 text-center text-xs font-semibold text-amber-950">
          {ctx.config.environment.toUpperCase()} environment{ctx.config.break_glass ? ' — break-glass access is enabled; every use is audited' : ''}
        </div>
      )}
      <div className="flex min-h-screen flex-col md:flex-row">
        <aside className="border-b border-zinc-200 bg-white p-4 md:w-56 md:border-b-0 md:border-r dark:border-zinc-800 dark:bg-zinc-900">
          <p className="text-lg font-bold text-brand">Hygieia</p>
          <p className="mb-4 text-xs text-zinc-500">{ctx.config.mode === 'standalone' ? 'Standalone node' : 'Server'}</p>
          <nav aria-label="Main" className="flex flex-wrap gap-1 md:flex-col">
            {NAV.filter((n) => (!n.platformOnly || ctx.platform) && (!n.serverOnly || ctx.config.mode !== 'standalone')).map((n) => {
              const active = n.href === '/' ? path === '/' : path.startsWith(n.href);
              return <Link key={n.href} href={n.href} aria-current={active ? 'page' : undefined}
                className={`rounded-md px-3 py-1.5 text-sm ${active ? 'bg-brand/10 font-semibold text-brand' : 'hover:bg-zinc-100 dark:hover:bg-zinc-800'}`}>{n.label}</Link>;
            })}
          </nav>
        </aside>
        <div className="flex-1">
          <header className="flex flex-wrap items-center justify-between gap-3 border-b border-zinc-200 bg-white px-6 py-3 dark:border-zinc-800 dark:bg-zinc-900">
            <label className="flex items-center gap-2 text-sm">Tenant
              <select aria-label="Tenant" value={ctx.tenant} onChange={(e) => ctx.setTenant(e.target.value)}>
                {ctx.tenants.map((t) => <option key={t.id} value={t.id}>{t.name}</option>)}
              </select>
            </label>
            <div className="flex items-center gap-3 text-sm">
              <span data-testid="who">{who}</span>
              {ctx.platform && ctx.config.mode !== 'standalone' && <Badge tone="amber">platform</Badge>}
              <Button variant="ghost" onClick={() => { clearSession(); window.location.assign('/login/'); }}>Sign out</Button>
            </div>
          </header>
          <main className="mx-auto max-w-6xl space-y-6 p-6">{children}</main>
        </div>
      </div>
    </AppCtx.Provider>
  );
}
