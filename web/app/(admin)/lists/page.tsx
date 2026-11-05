'use client';
import { useEffect, useState, type FormEvent } from 'react';
import { useApp } from '@/components/Shell';
import { Badge, Button, Card, ErrorBox, Field, Table, Td, fmtTime, short, useAsync } from '@/components/ui';
import { api } from '@/lib/api';

function Selection() {
  const { tenant, tenantLabel } = useApp();
  const sel = useAsync(() => api.listSelection(tenant), [tenant]);
  const groups = useAsync(() => api.groups(tenant), [tenant]);
  const [err, setErr] = useState<unknown>(null);
  const [add, setAdd] = useState({ source: '', group: '' });
  const [pending, setPending] = useState<'all' | 'selected' | null>(null); // optimistic radio state
  const run = async (fn: () => Promise<unknown>): Promise<boolean> => {
    setErr(null);
    let ok = true;
    try { await fn(); } catch (x) { setErr(x); ok = false; }
    sel.reload();
    return ok;
  };
  const d = sel.data;
  // optimistic radio state is dropped once the server value has caught up
  useEffect(() => { if (pending && d?.policy === pending) setPending(null); }, [pending, d?.policy]);
  const groupName = (id: string | null) => (id ? (groups.data?.find((g) => g.id === id)?.name ?? short(id)) : 'whole tenant');
  const nameOf = (id: string) => d?.available.find((a) => a.id === id)?.name ?? id;

  return (
    <Card title={`Lists for ${tenantLabel(tenant)}`}>
      <ErrorBox error={err ?? sel.error} />
      {d && (
        <div className="space-y-3">
          <fieldset className="space-y-1 text-sm">
            <legend className="sr-only">Which lists this tenant receives</legend>
            {(['all', 'selected'] as const).map((p) => (
              <label key={p} className="flex items-center gap-2">
                <input type="radio" name="policy" checked={(pending ?? d.policy) === p}
                  onChange={() => { setPending(p); run(() => api.setListPolicy(tenant, p)).then((ok) => { if (!ok) setPending(null); }); }} />
                {p === 'all' ? `All platform-enabled lists (${d.available.length})` : 'Only the lists selected below'}
              </label>
            ))}
          </fieldset>
          {(pending ?? d.policy) === 'selected' && (
            <>
              <form className="flex flex-wrap items-end gap-3" onSubmit={(e: FormEvent) => { e.preventDefault(); run(() => api.subscribe(tenant, add.source, add.group || null)); }}>
                <Field label="List"><select required value={add.source} onChange={(e) => setAdd({ ...add, source: e.target.value })} aria-label="List source"><option value="">Choose…</option>{d.available.map((a) => <option key={a.id} value={a.id}>{a.name} ({a.license})</option>)}</select></Field>
                <Field label="Applies to"><select value={add.group} onChange={(e) => setAdd({ ...add, group: e.target.value })} aria-label="Applies to"><option value="">Whole tenant</option>{groups.data?.map((g) => <option key={g.id} value={g.id}>Group: {g.name}</option>)}</select></Field>
                <Button type="submit">Subscribe</Button>
              </form>
              <Table head={['List', 'Applies to', '']} empty={d.subscriptions.length === 0 ? 'No lists selected: this tenant receives only its own custom rules.' : undefined}>
                {d.subscriptions.map((s) => (
                  <tr key={`${s.group_id}-${s.source_id}`}>
                    <Td>{nameOf(s.source_id)}</Td><Td>{groupName(s.group_id)}</Td>
                    <Td><Button variant="danger" aria-label={`Unsubscribe ${nameOf(s.source_id)}`} onClick={() => run(() => api.unsubscribe(tenant, s.source_id, s.group_id))}>Remove</Button></Td>
                  </tr>
                ))}
              </Table>
            </>
          )}
        </div>
      )}
    </Card>
  );
}

export default function Lists() {
  const lists = useAsync(() => api.lists(), []);
  const [err, setErr] = useState<unknown>(null);
  const [asked, setAsked] = useState(false);
  const n = (x: number) => x.toLocaleString();

  return (
    <>
      <h1 className="text-2xl font-semibold">Filter lists</h1>
      <p className="text-sm text-zinc-500">Third-party lists are downloaded at runtime. Check each license before redistributing derived data.</p>
      <Selection />
      <ErrorBox error={err ?? lists.error} />
      <Card title="Sources (platform)" actions={
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
