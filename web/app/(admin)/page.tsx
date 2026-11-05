'use client';
import Link from 'next/link';
import { useApp } from '@/components/Shell';
import { Badge, Card, ErrorBox, fmtTime, useAsync } from '@/components/ui';
import { api } from '@/lib/api';

export default function Overview() {
  const { me, tenant, tenantLabel } = useApp();
  const rules = useAsync(() => api.rules(tenant), [tenant]);
  const devices = useAsync(() => api.devices(tenant), [tenant]);
  const lists = useAsync(() => api.lists(), []);
  const audit = useAsync(() => api.verifyAudit(tenant), [tenant]);

  const roles = me.kind === 'break_glass' ? ['owner (break-glass)']
    : me.kind === 'api_token' ? [me.role]
    : me.bindings.map((b) => `${b.role}${b.tenant_id ? '' : ' (platform)'}`);
  const failing = (lists.data ?? []).filter((l) => l.last_error);

  return (
    <>
      <h1 className="text-2xl font-semibold">Overview — {tenantLabel(tenant)}</h1>
      <div className="grid gap-4 md:grid-cols-4">
        <Card title="Custom rules"><p className="text-3xl font-semibold" data-testid="rule-count">{rules.data?.length ?? '–'}</p>{rules.error ? <ErrorBox error={rules.error} /> : <Link className="text-sm text-brand underline" href="/rules/">Manage</Link>}</Card>
        <Card title="Devices"><p className="text-3xl font-semibold">{devices.data ? devices.data.filter((d) => !d.revoked).length : '–'}</p>{devices.error ? <ErrorBox error={devices.error} /> : <Link className="text-sm text-brand underline" href="/devices/">Manage</Link>}</Card>
        <Card title="Filter lists"><p className="text-3xl font-semibold">{lists.data?.length ?? '–'}</p>{failing.length > 0 ? <Badge tone="red">{failing.length} failing</Badge> : <Link className="text-sm text-brand underline" href="/lists/">Status</Link>}</Card>
        <Card title="Audit chain">
          {audit.data ? <><Badge tone={audit.data.ok ? 'green' : 'red'}>{audit.data.ok ? 'intact' : 'BROKEN'}</Badge><p className="mt-1 text-sm">{audit.data.events} events</p></>
            : audit.error ? <ErrorBox error={audit.error} /> : <p>–</p>}
        </Card>
      </div>
      <Card title="Your access">
        <p className="text-sm">Signed in as <strong>{me.kind === 'user' ? (me.email ?? me.subject) : me.kind.replace('_', ' ')}</strong>; roles: {roles.length ? roles.map((r) => <Badge key={r}>{r}</Badge>) : <Badge tone="amber">none yet — ask an administrator to bind a role</Badge>}</p>
        {lists.data && <p className="mt-2 text-xs text-zinc-500">Lists last refreshed: {fmtTime(Math.max(0, ...lists.data.map((l) => l.last_ok ?? 0)))}</p>}
      </Card>
    </>
  );
}
