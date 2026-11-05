'use client';
import { useState } from 'react';
import { useApp } from '@/components/Shell';
import { Badge, Button, Card, ErrorBox, Table, Td, short, useAsync } from '@/components/ui';
import { api } from '@/lib/api';

export default function Audit() {
  const { tenant } = useApp();
  const events = useAsync(() => api.audit(tenant, 300), [tenant]);
  const [verify, setVerify] = useState<{ ok: boolean; head: string; events: number } | null>(null);
  const [err, setErr] = useState<unknown>(null);
  const [filter, setFilter] = useState('');
  const rows = [...(events.data ?? [])].reverse().filter((e) => !filter || `${e.actor} ${e.action} ${e.target}`.toLowerCase().includes(filter.toLowerCase()));

  return (
    <>
      <h1 className="text-2xl font-semibold">Audit log</h1>
      <p className="text-sm text-zinc-500">Append-only, hash-chained per tenant. Anchor the head hash externally to detect tail truncation.</p>
      <ErrorBox error={err ?? events.error} />
      <Card title="Integrity" actions={<Button onClick={async () => { setErr(null); try { setVerify(await api.verifyAudit(tenant)); } catch (x) { setErr(x); } }}>Verify chain</Button>}>
        {verify ? <p className="text-sm" data-testid="verify"><Badge tone={verify.ok ? 'green' : 'red'}>{verify.ok ? 'intact' : 'BROKEN'}</Badge> {verify.events} events · head <code className="break-all text-xs">{verify.head}</code></p> : <p className="text-sm text-zinc-500">Not verified in this session.</p>}
      </Card>
      <Card title="Events" actions={<input placeholder="Filter actor / action / target" value={filter} onChange={(e) => setFilter(e.target.value)} aria-label="Filter events" className="w-64" />}>
        <Table head={['#', 'Time', 'Actor', 'Action', 'Target', 'Change']}>
          {rows.map((e) => (
            <tr key={e.seq}>
              <Td>{e.seq}</Td><Td>{new Date(e.ts * 1000).toLocaleString()}</Td>
              <Td mono>{e.actor.startsWith('break-glass') ? <Badge tone="amber">break-glass</Badge> : e.actor.length > 24 ? `${e.actor.slice(0, 24)}…` : e.actor}</Td>
              <Td><Badge tone={e.action === 'auth.break_glass' ? 'amber' : 'zinc'}>{e.action}</Badge></Td>
              <Td mono>{short(e.target)}</Td>
              <Td>{e.diff ? <details><summary className="cursor-pointer text-xs text-brand">diff</summary><pre className="max-w-md overflow-auto text-xs">{JSON.stringify(e.diff, null, 2)}</pre></details> : null}</Td>
            </tr>
          ))}
        </Table>
      </Card>
    </>
  );
}
