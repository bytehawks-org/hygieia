// Hand-maintained mirror of the API's JSON (an OpenAPI-generated client replaces this once utoipa lands).
export type Role = 'owner' | 'admin' | 'editor' | 'viewer' | 'auditor';

export interface Binding { id: string; user_id: string; tenant_id: string | null; role: Role }

export type Principal =
  | { kind: 'break_glass' }
  | { kind: 'api_token'; id: string; tenant_id: string; role: Role }
  | { kind: 'user'; id: string; issuer: string; subject: string; email: string | null; bindings: Binding[] };

export interface PublicConfig {
  environment: 'production' | 'staging' | 'dev' | string;
  break_glass: boolean;
  oidc: { issuer: string; client_id: string; scope: string } | null;
}

export interface Tenant { id: string; slug: string; name: string }
export interface Group { id: string; tenant_id: string; name: string }
export interface User { id: string; issuer: string; subject: string; email: string | null; disabled: boolean }
export interface Rule { id: string; tenant_id: string; group_id: string | null; action: 'allow' | 'block'; pattern: string; comment: string }
export interface Device { id: string; tenant_id: string; group_id: string; info: string; last_seen: number; revoked: boolean }
export interface ApiToken { id: string; tenant_id: string; name: string; role: Role; expires_at: number | null; revoked: boolean }

export interface AuditEvent {
  seq: number; ts: number; tenant_id: string; actor: string; action: string; target: string;
  diff: unknown; prev_hash: string; hash: string;
}

export interface ListStatus {
  id: string; name: string; url: string; license: string; attribution: string;
  last_ok: number | null; last_error: string | null;
  block_domains: number; allow_domains: number; generic_selectors: number;
  host_rule_sets: number; scriptlet_calls: number; skipped_lines: number;
  dropped_trusted_scriptlets: number; sha256: string | null;
}

export type Reason =
  | { CustomAllow: { rule: string } } | { CustomBlock: { rule: string } }
  | { ListAllow: { list: string; rule: string } } | { ListBlock: { list: string; rule: string } }
  | 'Default';
export interface Verdict { action: 'Allow' | 'Block'; reason: Reason }
export interface Simulation { current: Verdict; with_changes: Verdict }

export type ListPolicy = 'all' | 'selected';
export interface Subscription { group_id: string | null; source_id: string }
export interface ListSelection {
  policy: ListPolicy;
  subscriptions: Subscription[];
  available: { id: string; name: string; license: string }[];
}
