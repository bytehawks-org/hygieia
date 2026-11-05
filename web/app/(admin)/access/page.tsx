'use client';
import { useState, type FormEvent } from 'react';
import { useApp } from '@/components/Shell';
import { Badge, Button, Card, ErrorBox, Field, OneTimeSecret, Table, Td, fmtTime, short, useAsync } from '@/components/ui';
import { api } from '@/lib/api';
import type { Role } from '@/lib/types';

const TENANT_ROLES: Role[] = ['admin', 'editor', 'viewer', 'auditor'];

export default function Access() {
  const { tenant, platform } = useApp();
  const groups = useAsync(() => api.groups(tenant), [tenant]);
  const bindings = useAsync(() => api.bindings(tenant), [tenant]);
  const tokens = useAsync(() => api.apiTokens(tenant), [tenant]);
  const users = useAsync(() => (platform ? api.users() : Promise.resolve([])), [platform]);
  const [err, setErr] = useState<unknown>(null);
  const [secret, setSecret] = useState<string | null>(null);
  const [group, setGroup] = useState('');
  const [bind, setBind] = useState({ user: '', role: 'viewer' as Role });
  const [tok, setTok] = useState({ name: '', role: 'editor' as Role, days: 90 });

  const guard = async (fn: () => Promise<unknown>, after: () => void) => { setErr(null); try { await fn(); after(); } catch (x) { setErr(x); } };

  return (
    <>
      <h1 className="text-2xl font-semibold">Access</h1>
      <ErrorBox error={err} />

      <Card title="Policy groups">
        <form className="mb-3 flex items-end gap-3" onSubmit={(e: FormEvent) => { e.preventDefault(); guard(() => api.createGroup(tenant, group.trim()), () => { setGroup(''); groups.reload(); }); }}>
          <Field label="New group"><input required value={group} onChange={(e) => setGroup(e.target.value)} placeholder="staff" aria-label="Group name" /></Field>
          <Button type="submit">Create</Button>
        </form>
        <ErrorBox error={groups.error} />
        <p className="text-sm">{groups.data?.map((g) => <Badge key={g.id}>{g.name}</Badge>)} {groups.data?.length === 0 && <span className="text-zinc-500">No groups yet.</span>}</p>
      </Card>

      <Card title="Role bindings">
        <p className="mb-2 text-xs text-zinc-500">Users appear after their first OIDC login and have no roles until bound here. Roles apply to this tenant.</p>
        <form className="mb-3 flex flex-wrap items-end gap-3" onSubmit={(e: FormEvent) => { e.preventDefault(); guard(() => api.addBinding(bind.user.trim(), tenant, bind.role), () => { setBind({ ...bind, user: '' }); bindings.reload(); }); }}>
          <Field label="User id">
            <input required list="users" value={bind.user} onChange={(e) => setBind({ ...bind, user: e.target.value })} placeholder="user id (uuid)" aria-label="User id" className="w-72" />
          </Field>
          <datalist id="users">{users.data?.map((u) => <option key={u.id} value={u.id}>{u.email ?? u.subject}</option>)}</datalist>
          <Field label="Role"><select value={bind.role} onChange={(e) => setBind({ ...bind, role: e.target.value as Role })} aria-label="Role">{TENANT_ROLES.map((r) => <option key={r}>{r}</option>)}</select></Field>
          <Button type="submit">Bind</Button>
        </form>
        <ErrorBox error={bindings.error} />
        <Table head={['User', 'Role', '']} empty={bindings.data?.length === 0 ? 'No bindings for this tenant.' : undefined}>
          {bindings.data?.map((b) => {
            const u = users.data?.find((x) => x.id === b.user_id);
            return <tr key={b.id}><Td>{u ? (u.email ?? u.subject) : <span className="font-mono text-xs">{short(b.user_id)}</span>}</Td><Td><Badge>{b.role}</Badge></Td>
              <Td><Button variant="danger" onClick={() => confirm('Remove this role binding?') && guard(() => api.removeBinding(tenant, b.id), bindings.reload)}>Remove</Button></Td></tr>;
          })}
        </Table>
      </Card>

      <Card title="API tokens">
        <form className="mb-3 flex flex-wrap items-end gap-3" onSubmit={(e: FormEvent) => { e.preventDefault(); setSecret(null); guard(async () => { setSecret((await api.createApiToken(tenant, tok.name.trim(), tok.role, tok.days > 0 ? tok.days * 86400 : null)).token); }, () => { setTok({ ...tok, name: '' }); tokens.reload(); }); }}>
          <Field label="Name"><input required value={tok.name} onChange={(e) => setTok({ ...tok, name: e.target.value })} placeholder="ci-pipeline" aria-label="Token name" /></Field>
          <Field label="Role"><select value={tok.role} onChange={(e) => setTok({ ...tok, role: e.target.value as Role })} aria-label="Token role">{TENANT_ROLES.map((r) => <option key={r}>{r}</option>)}</select></Field>
          <Field label="Valid for (days, 0 = no expiry)"><input type="number" min={0} value={tok.days} onChange={(e) => setTok({ ...tok, days: Number(e.target.value) })} /></Field>
          <Button type="submit">Create token</Button>
        </form>
        {secret && <div className="mb-3"><OneTimeSecret label="API token" value={secret} onClose={() => setSecret(null)} /></div>}
        <ErrorBox error={tokens.error} />
        <Table head={['Name', 'Role', 'Expires', 'State', '']} empty={tokens.data?.length === 0 ? 'No API tokens.' : undefined}>
          {tokens.data?.map((t) => (
            <tr key={t.id}><Td>{t.name}</Td><Td><Badge>{t.role}</Badge></Td><Td>{t.expires_at ? fmtTime(t.expires_at) : 'never'}</Td>
              <Td>{t.revoked ? <Badge tone="red">revoked</Badge> : <Badge tone="green">active</Badge>}</Td>
              <Td>{!t.revoked && <Button variant="danger" onClick={() => confirm(`Revoke token "${t.name}"?`) && guard(() => api.revokeApiToken(tenant, t.id), tokens.reload)}>Revoke</Button>}</Td></tr>
          ))}
        </Table>
      </Card>
    </>
  );
}
