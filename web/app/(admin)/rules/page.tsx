'use client';
import { useState, type FormEvent } from 'react';
import { useApp } from '@/components/Shell';
import { Badge, Button, Card, ErrorBox, Field, Table, Td, short, useAsync } from '@/components/ui';
import { api } from '@/lib/api';
import type { Reason, Simulation, Verdict } from '@/lib/types';

function reasonText(r: Reason): string {
  if (r === 'Default') return 'no rule matched (default allow)';
  const [kind, v] = Object.entries(r)[0] as [string, { rule: string; list?: string }];
  const label = { CustomAllow: 'custom allow', CustomBlock: 'custom block', ListAllow: 'list allow', ListBlock: 'list block' }[kind] ?? kind;
  return `${label}: ${v.rule}${v.list ? ` (list ${v.list})` : ''}`;
}
const VerdictView = ({ v }: { v: Verdict }) => <span><Badge tone={v.action === 'Block' ? 'red' : 'green'}>{v.action}</Badge> <span className="text-xs text-zinc-500">{reasonText(v.reason)}</span></span>;

export default function Rules() {
  const { tenant } = useApp();
  const rules = useAsync(() => api.rules(tenant), [tenant]);
  const groups = useAsync(() => api.groups(tenant), [tenant]);
  const [form, setForm] = useState({ action: 'block' as 'allow' | 'block', pattern: '', comment: '', group: '' });
  const [err, setErr] = useState<unknown>(null);
  const [sim, setSim] = useState({ host: '', action: 'allow' as 'allow' | 'block', pattern: '' });
  const [simRes, setSimRes] = useState<Simulation | null>(null);

  const add = async (e: FormEvent) => {
    e.preventDefault(); setErr(null);
    try {
      await api.addRule(tenant, { action: form.action, pattern: form.pattern.trim(), comment: form.comment, group_id: form.group || null });
      setForm({ ...form, pattern: '', comment: '' });
      rules.reload();
    } catch (x) { setErr(x); }
  };
  const runSim = async (e: FormEvent) => {
    e.preventDefault(); setErr(null); setSimRes(null);
    try {
      setSimRes(await api.simulate(tenant, sim.host.trim(), sim.pattern.trim() ? [{ action: sim.action, pattern: sim.pattern.trim() }] : []));
    } catch (x) { setErr(x); }
  };
  const groupName = (id: string | null) => (id ? (groups.data?.find((g) => g.id === id)?.name ?? short(id)) : 'whole tenant');

  return (
    <>
      <h1 className="text-2xl font-semibold">Rules</h1>
      <p className="text-sm text-zinc-500">Precedence: custom allow, custom block, list allow, list block, default allow. A domain also covers its subdomains.</p>
      <ErrorBox error={err} />
      <Card title="Add rule">
        <form onSubmit={add} className="flex flex-wrap items-end gap-3">
          <Field label="Action"><select value={form.action} onChange={(e) => setForm({ ...form, action: e.target.value as 'allow' | 'block' })}><option value="block">Block</option><option value="allow">Allow</option></select></Field>
          <Field label="Domain"><input required placeholder="ads.example.com" value={form.pattern} onChange={(e) => setForm({ ...form, pattern: e.target.value })} aria-label="Domain" /></Field>
          <Field label="Scope"><select value={form.group} onChange={(e) => setForm({ ...form, group: e.target.value })} aria-label="Scope"><option value="">Whole tenant</option>{groups.data?.map((g) => <option key={g.id} value={g.id}>{g.name}</option>)}</select></Field>
          <Field label="Comment"><input value={form.comment} onChange={(e) => setForm({ ...form, comment: e.target.value })} /></Field>
          <Button type="submit">Add</Button>
        </form>
      </Card>
      <Card title="Simulate (what if)">
        <form onSubmit={runSim} className="flex flex-wrap items-end gap-3">
          <Field label="Host"><input required placeholder="x.ads.example.com" value={sim.host} onChange={(e) => setSim({ ...sim, host: e.target.value })} aria-label="Simulate host" /></Field>
          <Field label="Pretend rule (optional)"><span className="flex gap-1"><select value={sim.action} onChange={(e) => setSim({ ...sim, action: e.target.value as 'allow' | 'block' })}><option value="allow">Allow</option><option value="block">Block</option></select><input placeholder="domain" value={sim.pattern} onChange={(e) => setSim({ ...sim, pattern: e.target.value })} aria-label="Pretend domain" /></span></Field>
          <Button type="submit" variant="ghost">Evaluate</Button>
        </form>
        {simRes && <dl className="mt-3 space-y-1 text-sm" data-testid="sim-result"><div><dt className="inline font-medium">Now: </dt><dd className="inline"><VerdictView v={simRes.current} /></dd></div><div><dt className="inline font-medium">With the rule: </dt><dd className="inline"><VerdictView v={simRes.with_changes} /></dd></div></dl>}
      </Card>
      <Card title={`Custom rules (${rules.data?.length ?? 0})`}>
        <ErrorBox error={rules.error} />
        <Table head={['Action', 'Domain', 'Scope', 'Comment', '']} empty={rules.data?.length === 0 ? 'No custom rules yet.' : undefined}>
          {rules.data?.map((r) => (
            <tr key={r.id}>
              <Td><Badge tone={r.action === 'block' ? 'red' : 'green'}>{r.action}</Badge></Td>
              <Td mono>{r.pattern}</Td><Td>{groupName(r.group_id)}</Td><Td>{r.comment}</Td>
              <Td><Button variant="danger" aria-label={`Delete ${r.pattern}`} onClick={async () => { if (confirm(`Delete rule for ${r.pattern}?`)) { try { await api.deleteRule(tenant, r.id); rules.reload(); } catch (x) { setErr(x); } } }}>Delete</Button></Td>
            </tr>
          ))}
        </Table>
      </Card>
    </>
  );
}
