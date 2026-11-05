'use client';
import { useState, type FormEvent } from 'react';
import { useApp } from '@/components/Shell';
import { Button, Card, ErrorBox, Field, Table, Td, useAsync } from '@/components/ui';
import { api } from '@/lib/api';

export default function Tenants() {
  const { platform } = useApp();
  const tenants = useAsync(() => (platform ? api.tenants() : Promise.resolve([])), [platform]);
  const [form, setForm] = useState({ slug: '', name: '' });
  const [err, setErr] = useState<unknown>(null);
  if (!platform) return <ErrorBox error={new Error('Tenant management requires platform-level access.')} />;

  return (
    <>
      <h1 className="text-2xl font-semibold">Tenants</h1>
      <ErrorBox error={err} />
      <Card title="Create tenant">
        <form className="flex flex-wrap items-end gap-3" onSubmit={async (e: FormEvent) => {
          e.preventDefault(); setErr(null);
          try { await api.createTenant(form.slug.trim(), form.name.trim()); setForm({ slug: '', name: '' }); tenants.reload(); } catch (x) { setErr(x); }
        }}>
          <Field label="Slug (a-z, 0-9, -)"><input required pattern="[a-z0-9][a-z0-9-]{0,62}" value={form.slug} onChange={(e) => setForm({ ...form, slug: e.target.value })} aria-label="Slug" /></Field>
          <Field label="Name"><input required value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} aria-label="Name" /></Field>
          <Button type="submit">Create</Button>
        </form>
        <p className="mt-2 text-xs text-zinc-500">Reload the page after creating a tenant to see it in the tenant selector.</p>
      </Card>
      <Card title="All tenants">
        <ErrorBox error={tenants.error} />
        <Table head={['Name', 'Slug', 'Id']}>{tenants.data?.map((t) => <tr key={t.id}><Td>{t.name}</Td><Td mono>{t.slug}</Td><Td mono>{t.id}</Td></tr>)}</Table>
      </Card>
    </>
  );
}
