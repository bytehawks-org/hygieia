// Compile-time contract check (never executed): `tsc` fails when a path, a parameter, a request body
// or a response shape stops matching docs/reference/openapi.json.
import { apiClient } from './client';

export async function contract() {
  const c = apiClient('http://127.0.0.1:8470', 'hyg_api_example');
  const rules = await c.GET('/v1/admin/rules', { params: { query: { tenant_id: 't1' } } });
  const first: { id: string; action: 'allow' | 'block' } | undefined = rules.data?.[0];
  await c.POST('/v1/admin/rules', { body: { action: 'block', pattern: 'ads.example.com' } });
  await c.DELETE('/v1/admin/rules/{id}', { params: { path: { id: 'r1' } } });
  const sim = await c.POST('/v1/admin/simulate', { body: { host: 'ads.example.com' } });
  const verdict: 'Allow' | 'Block' | undefined = sim.data?.current.action;
  const log = await c.GET('/v1/admin/dns/query-log', { params: { query: { limit: 10, action: 'block' } } });
  const client: string | undefined = log.data?.[0]?.client;
  // @ts-expect-error unknown path
  await c.GET('/v1/admin/does-not-exist');
  // @ts-expect-error role must be one of the documented values
  await c.POST('/v1/admin/api-tokens', { body: { name: 'ci', role: 'superuser' } });
  return { first, verdict, client };
}
