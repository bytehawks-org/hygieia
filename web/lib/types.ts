// Types of the API's JSON, derived from the generated OpenAPI schema (lib/api-schema.d.ts, produced
// by scripts/gen-api.sh from docs/reference/openapi.json). Do not hand-edit shapes here: change the
// API description in crates/hygeia-api/src/openapi.rs and regenerate; `tsc` then shows what breaks.
import type { components } from './api-schema';

type S = components['schemas'];

export type Role = S['Role'];
export type Binding = S['Binding'];
export type Principal = S['Principal'];
export type PublicConfig = S['PublicConfig'];
export type Tenant = S['Tenant'];
export type Group = S['Group'];
export type User = S['User'];
export type Rule = S['Rule'];
export type Device = S['Device'];
export type ApiToken = S['ApiToken'];
export type AuditEvent = S['AuditEvent'];
export type ListStatus = S['ListStatus'];
export type Reason = S['Reason'];
export type Verdict = S['Verdict'];
export type Simulation = S['Simulation'];
export type ListPolicy = S['ListPolicy'];
export type ListSelection = S['ListSelection'];
export type Subscription = ListSelection['subscriptions'][number];
export type DnsToken = S['DnsToken'];
export type DnsNetwork = S['DnsNetwork'];
export type DnsSettings = S['DnsSettings'];
export type QueryLogEntry = S['QueryLogEntry'];
export type DnsStats = S['DnsStats'];
