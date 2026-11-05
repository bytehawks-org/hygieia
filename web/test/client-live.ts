// Live check of the generated client against a running node/server:
//   node --experimental-strip-types test/client-live.ts <base-url> <owner-credential>
import { apiClient } from '../lib/client.ts';

const [base, token] = process.argv.slice(2);
if (!base || !token) throw new Error('usage: client-live.ts <base-url> <credential>');
const c = apiClient(base, token);
const fail = (m: string): never => { console.error('FAIL', m); process.exit(1); };

const me = await c.GET('/v1/me');
if (me.response.status !== 200 || !me.data) fail('/v1/me');
const added = await c.POST('/v1/admin/rules', { body: { action: 'block', pattern: 'client-live.example.com', comment: 'generated client' } });
const ruleId = added.data?.id;
if (added.response.status !== 201 || !ruleId) throw new Error('add rule failed');
const list = await c.GET('/v1/admin/rules', {});
if (!list.data?.some((r) => r.pattern === 'client-live.example.com')) fail('list rules');
const sim = await c.POST('/v1/admin/simulate', { body: { host: 'client-live.example.com' } });
if (sim.data?.current.action !== 'Block') fail('simulate');
const del = await c.DELETE('/v1/admin/rules/{id}', { params: { path: { id: ruleId } } });
if (del.response.status !== 204) fail('delete rule');
const anon = await apiClient(base).GET('/v1/admin/rules', {});
if (anon.response.status !== 401) fail('anonymous must be 401');
console.log('generated client OK');
