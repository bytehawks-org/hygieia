'use client';
import { useState, type FormEvent } from 'react';
import { useApp } from '@/components/Shell';
import { Badge, Button, Card, ErrorBox, Field, OneTimeSecret, Table, Td, fmtTime, short, useAsync } from '@/components/ui';
import { api } from '@/lib/api';

export default function Devices() {
  const { tenant } = useApp();
  const devices = useAsync(() => api.devices(tenant), [tenant]);
  const groups = useAsync(() => api.groups(tenant), [tenant]);
  const pubkey = useAsync(() => api.pubkey(), []);
  const [form, setForm] = useState({ group: '', ttlHours: 24, maxUses: 1 });
  const [secret, setSecret] = useState<string | null>(null);
  const [err, setErr] = useState<unknown>(null);

  const create = async (e: FormEvent) => {
    e.preventDefault(); setErr(null); setSecret(null);
    try {
      const group = form.group || groups.data?.[0]?.id;
      if (!group) throw new Error('Create a group first (Access page).');
      const t = await api.createEnrollmentToken(tenant, group, Math.round(form.ttlHours * 3600), form.maxUses > 0 ? form.maxUses : null);
      setSecret(t.token);
    } catch (x) { setErr(x); }
  };

  return (
    <>
      <h1 className="text-2xl font-semibold">Devices</h1>
      <ErrorBox error={err} />
      <Card title="Enroll a browser extension">
        <form onSubmit={create} className="flex flex-wrap items-end gap-3">
          <Field label="Policy group"><select value={form.group} onChange={(e) => setForm({ ...form, group: e.target.value })} aria-label="Policy group">{groups.data?.map((g) => <option key={g.id} value={g.id}>{g.name}</option>)}</select></Field>
          <Field label="Valid for (hours)"><input type="number" min={1} max={720} value={form.ttlHours} onChange={(e) => setForm({ ...form, ttlHours: Number(e.target.value) })} /></Field>
          <Field label="Max uses (0 = unlimited)"><input type="number" min={0} value={form.maxUses} onChange={(e) => setForm({ ...form, maxUses: Number(e.target.value) })} /></Field>
          <Button type="submit">Create enrollment token</Button>
        </form>
        {secret && <div className="mt-3"><OneTimeSecret label="Enrollment token" value={secret} onClose={() => setSecret(null)} /></div>}
        <dl className="mt-4 space-y-1 text-xs text-zinc-600 dark:text-zinc-400">
          <div><dt className="inline font-medium">Server URL: </dt><dd className="inline font-mono">{typeof window !== 'undefined' ? window.location.origin : ''}</dd></div>
          <div><dt className="inline font-medium">Signing public key (pin this in the extension): </dt><dd className="inline break-all font-mono" data-testid="pubkey">{pubkey.data ?? '…'}</dd></div>
        </dl>
      </Card>
      <Card title={`Enrolled devices (${devices.data?.length ?? 0})`}>
        <ErrorBox error={devices.error} />
        <Table head={['Device', 'Info', 'Last seen', 'State', '']} empty={devices.data?.length === 0 ? 'No devices enrolled.' : undefined}>
          {devices.data?.map((d) => (
            <tr key={d.id}>
              <Td mono>{short(d.id)}</Td><Td className="max-w-xs truncate">{d.info}</Td><Td>{fmtTime(d.last_seen)}</Td>
              <Td>{d.revoked ? <Badge tone="red">revoked</Badge> : <Badge tone="green">active</Badge>}</Td>
              <Td>{!d.revoked && <Button variant="danger" onClick={async () => { if (confirm('Revoke this device? It will lose access to new bundles.')) { try { await api.revokeDevice(tenant, d.id); devices.reload(); } catch (x) { setErr(x); } } }}>Revoke</Button>}</Td>
            </tr>
          ))}
        </Table>
      </Card>
    </>
  );
}
