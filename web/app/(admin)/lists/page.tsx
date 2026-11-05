'use client';
import { useState } from 'react';
import { Badge, Button, Card, ErrorBox, Table, Td, fmtTime, useAsync } from '@/components/ui';
import { api } from '@/lib/api';

export default function Lists() {
  const lists = useAsync(() => api.lists(), []);
  const [err, setErr] = useState<unknown>(null);
  const [asked, setAsked] = useState(false);
  const n = (x: number) => x.toLocaleString();

  return (
    <>
      <h1 className="text-2xl font-semibold">Filter lists</h1>
      <p className="text-sm text-zinc-500">Third-party lists are downloaded at runtime. Check each license before redistributing derived data.</p>
      <ErrorBox error={err ?? lists.error} />
      <Card title="Sources" actions={
        <div className="flex gap-2">
          <Button variant="ghost" onClick={() => lists.reload()}>Reload</Button>
          <Button onClick={async () => { setErr(null); try { await api.refreshLists(); setAsked(true); setTimeout(lists.reload, 4000); } catch (x) { setErr(x); } }}>Refresh now (platform)</Button>
        </div>}>
        {asked && <p className="mb-2 text-xs text-zinc-500">Refresh requested; status reloads in a few seconds.</p>}
        <Table head={['List', 'License', 'Domains', 'DOM / JS rules', 'Skipped', 'Last OK', 'State']}>
          {lists.data?.map((l) => (
            <tr key={l.id}>
              <Td><div className="font-medium">{l.name}</div><div className="max-w-xs truncate font-mono text-xs text-zinc-500" title={l.url}>{l.url}</div><div className="text-xs text-zinc-500">{l.attribution}</div></Td>
              <Td><Badge>{l.license}</Badge></Td>
              <Td>{n(l.block_domains)}{l.allow_domains > 0 && <span className="text-xs text-zinc-500"> (+{n(l.allow_domains)} allow)</span>}</Td>
              <Td>{n(l.generic_selectors)} generic · {n(l.host_rule_sets)} hosts · {n(l.scriptlet_calls)} scriptlets{l.dropped_trusted_scriptlets > 0 && <span className="block text-xs text-zinc-500">{n(l.dropped_trusted_scriptlets)} trusted-* dropped</span>}</Td>
              <Td>{n(l.skipped_lines)}</Td><Td>{fmtTime(l.last_ok)}</Td>
              <Td>{l.last_error ? <span><Badge tone="red">error</Badge><span className="block max-w-xs text-xs text-red-700 dark:text-red-400">{l.last_error}</span></span> : l.last_ok ? <Badge tone="green">ok</Badge> : <Badge tone="amber">pending</Badge>}</Td>
            </tr>
          ))}
        </Table>
      </Card>
    </>
  );
}
