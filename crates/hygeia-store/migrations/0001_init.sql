-- PostgreSQL schema. Single-org deployments are multi-tenant with exactly one tenant.
-- Tenant isolation is enforced by RLS: set per transaction with
--   SET LOCAL app.tenant = '<uuid>';

CREATE TABLE tenants (
  id         uuid PRIMARY KEY,
  name       text NOT NULL,
  fail_mode  text NOT NULL DEFAULT 'open' CHECK (fail_mode IN ('open','closed')),
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE groups (
  id        uuid PRIMARY KEY,
  tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  name      text NOT NULL,
  UNIQUE (tenant_id, name)
);

CREATE TABLE rules (
  id        uuid PRIMARY KEY,
  tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  group_id  uuid REFERENCES groups(id) ON DELETE CASCADE, -- NULL = whole tenant
  action    text NOT NULL CHECK (action IN ('allow','block')),
  pattern   text NOT NULL,
  comment   text,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE enrollment_tokens (
  id          uuid PRIMARY KEY,
  tenant_id   uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  group_id    uuid NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
  secret_hash bytea NOT NULL UNIQUE,          -- SHA-256, secret never stored
  expires_at  timestamptz NOT NULL,
  max_uses    integer,
  used        integer NOT NULL DEFAULT 0,
  revoked_at  timestamptz
);

CREATE TABLE device_credentials (
  id          uuid PRIMARY KEY,
  tenant_id   uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  group_id    uuid NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
  secret_hash bytea NOT NULL UNIQUE,
  info        jsonb,
  last_seen   timestamptz,
  rotated_at  timestamptz NOT NULL DEFAULT now(),
  revoked_at  timestamptz
);

CREATE TABLE audit_events (
  seq       bigint NOT NULL,
  tenant_id uuid NOT NULL,
  event     jsonb NOT NULL,    -- hygeia_audit::Event
  hash      text NOT NULL,
  PRIMARY KEY (tenant_id, seq)
);
REVOKE UPDATE, DELETE ON audit_events FROM PUBLIC; -- append-only at DB level too

DO $$ DECLARE t text; BEGIN
  FOREACH t IN ARRAY ARRAY['groups','rules','enrollment_tokens','device_credentials','audit_events'] LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format($p$CREATE POLICY tenant_isolation ON %I
      USING (tenant_id = current_setting('app.tenant')::uuid)$p$, t);
  END LOOP;
END $$;
