import { clearSession, loadSession } from './session';
import type {
  ApiToken, AuditEvent, Binding, Device, Group, ListPolicy, ListSelection, ListStatus, Principal, PublicConfig, Role, Rule, Simulation,
  Tenant, User,
} from './types';

export class ApiError extends Error {
  constructor(public status: number, message: string) { super(message); }
}

const MESSAGES: Record<number, string> = {
  401: 'Not authenticated (credential missing, expired or revoked).',
  403: 'Your role does not allow this.',
  404: 'Not found.',
  409: 'Already exists.',
  422: 'Invalid input.',
};

async function request<T>(path: string, init: RequestInit & { token?: string; auth?: boolean } = {}): Promise<T> {
  const headers = new Headers(init.headers);
  const token = init.token ?? loadSession()?.token;
  if (init.auth !== false && token) headers.set('Authorization', `Bearer ${token}`);
  if (init.body && !headers.has('Content-Type')) headers.set('Content-Type', 'application/json');
  const resp = await fetch(path, { ...init, headers, cache: 'no-store' });
  if (resp.status === 401 && init.token === undefined && init.auth !== false) {
    // session no longer valid: drop it and go to the login screen
    clearSession();
    if (typeof window !== 'undefined' && !window.location.pathname.startsWith('/login')) window.location.assign('/login/');
  }
  if (!resp.ok) throw new ApiError(resp.status, MESSAGES[resp.status] ?? `Request failed (${resp.status}).`);
  if (resp.status === 204) return undefined as T;
  const text = await resp.text();
  return (resp.headers.get('content-type')?.includes('json') ? JSON.parse(text) : text) as T;
}

const q = (tenant: string | null | undefined, extra: Record<string, string> = {}) => {
  const p = new URLSearchParams(extra);
  if (tenant) p.set('tenant_id', tenant);
  const s = p.toString();
  return s ? `?${s}` : '';
};
const json = (body: unknown) => ({ body: JSON.stringify(body) });

export const api = {
  config: () => request<PublicConfig>('/v1/config', { auth: false }),
  pubkey: () => request<string>('/v1/pubkey', { auth: false }),
  me: (token?: string) => request<Principal>('/v1/me', { token }),

  tenants: () => request<Tenant[]>('/v1/admin/tenants'),
  createTenant: (slug: string, name: string) => request<Tenant>('/v1/admin/tenants', { method: 'POST', ...json({ slug, name }) }),
  groups: (t: string) => request<Group[]>(`/v1/admin/groups${q(t)}`),
  createGroup: (t: string, name: string) => request<Group>('/v1/admin/groups', { method: 'POST', ...json({ tenant_id: t, name }) }),
  users: () => request<User[]>('/v1/admin/users'),

  rules: (t: string) => request<Rule[]>(`/v1/admin/rules${q(t)}`),
  addRule: (t: string, r: { action: 'allow' | 'block'; pattern: string; comment: string; group_id: string | null }) =>
    request<Rule>('/v1/admin/rules', { method: 'POST', ...json({ tenant_id: t, ...r }) }),
  deleteRule: (t: string, id: string) => request<void>(`/v1/admin/rules/${encodeURIComponent(id)}${q(t)}`, { method: 'DELETE' }),
  simulate: (t: string, host: string, extra: { action: 'allow' | 'block'; pattern: string }[]) =>
    request<Simulation>('/v1/admin/simulate', { method: 'POST', ...json({ tenant_id: t, host, extra_rules: extra }) }),

  devices: (t: string) => request<Device[]>(`/v1/admin/devices${q(t)}`),
  revokeDevice: (t: string, id: string) => request<void>(`/v1/admin/devices/${encodeURIComponent(id)}${q(t)}`, { method: 'DELETE' }),
  createEnrollmentToken: (t: string, group_id: string, ttl_secs: number, max_uses: number | null) =>
    request<{ id: string; token: string; expires_at: number }>('/v1/admin/enrollment-tokens', { method: 'POST', ...json({ tenant_id: t, group_id, ttl_secs, max_uses }) }),

  lists: () => request<ListStatus[]>('/v1/admin/lists'),
  refreshLists: () => request<void>('/v1/admin/lists/refresh', { method: 'POST' }),

  listSelection: (t: string) => request<ListSelection>(`/v1/admin/list-subscriptions${q(t)}`),
  setListPolicy: (t: string, policy: ListPolicy) => request<void>('/v1/admin/list-policy', { method: 'PUT', ...json({ tenant_id: t, policy }) }),
  subscribe: (t: string, source_id: string, group_id: string | null) =>
    request<void>('/v1/admin/list-subscriptions', { method: 'POST', ...json({ tenant_id: t, source_id, group_id }) }),
  unsubscribe: (t: string, source_id: string, group_id: string | null) =>
    request<void>(`/v1/admin/list-subscriptions${q(t, { source_id, ...(group_id ? { group_id } : {}) })}`, { method: 'DELETE' }),

  audit: (t: string, limit = 200) => request<AuditEvent[]>(`/v1/admin/audit${q(t, { limit: String(limit) })}`),
  verifyAudit: (t: string) => request<{ ok: boolean; head: string; events: number }>(`/v1/admin/audit/verify${q(t)}`),

  bindings: (t: string) => request<Binding[]>(`/v1/admin/bindings${q(t)}`),
  addBinding: (user_id: string, tenant_id: string | null, role: Role) =>
    request<Binding>('/v1/admin/bindings', { method: 'POST', ...json({ user_id, tenant_id, role }) }),
  removeBinding: (t: string, id: string) => request<void>(`/v1/admin/bindings/${encodeURIComponent(id)}${q(t)}`, { method: 'DELETE' }),

  apiTokens: (t: string) => request<ApiToken[]>(`/v1/admin/api-tokens${q(t)}`),
  createApiToken: (t: string, name: string, role: Role, ttl_secs: number | null) =>
    request<{ id: string; token: string; role: Role; expires_at: number | null }>('/v1/admin/api-tokens', { method: 'POST', ...json({ tenant_id: t, name, role, ttl_secs }) }),
  revokeApiToken: (t: string, id: string) => request<void>(`/v1/admin/api-tokens/${encodeURIComponent(id)}${q(t)}`, { method: 'DELETE' }),
};
