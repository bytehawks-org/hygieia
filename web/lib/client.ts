// Typed client generated from the OpenAPI document: every path, parameter, body and response is
// checked by the compiler against docs/reference/openapi.json (via lib/api-schema.d.ts).
//
//   const c = apiClient('https://hygeia.example.com', 'hyg_api_…');
//   const { data, error, response } = await c.GET('/v1/admin/rules', { params: { query: { tenant_id } } });
//
// The admin UI keeps its own thin wrapper (lib/api.ts: session handling, redirect on 401);
// this client is for scripts, tests and integrations.
import createClient from 'openapi-fetch';
import type { paths } from './api-schema';

export type { paths };

export function apiClient(baseUrl: string, token?: string) {
  return createClient<paths>({
    baseUrl,
    headers: token ? { Authorization: `Bearer ${token}` } : undefined,
    cache: 'no-store',
  });
}
