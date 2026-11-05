-- Hygeia schema (PostgreSQL 14+). Single-org = multi-tenant with one tenant.
--
-- Isolation model
--   * Tenant-scoped tables have ROW LEVEL SECURITY keyed on the per-transaction
--     setting `app.tenant` (set with set_config(..., true) = SET LOCAL).
--     If unset, current_setting(..., true) is NULL and NO rows are visible.
--   * The migration role owns the tables and bypasses RLS (no FORCE). The
--     runtime role (`hygeia_app`, NOT owner, NOT bypassrls) is subject to it.
--   * Lookups that must happen BEFORE the tenant is known (device auth,
--     enrollment) go through SECURITY DEFINER functions below.

CREATE TABLE tenants (
  id         uuid PRIMARY KEY,
  slug       text NOT NULL UNIQUE CHECK (slug ~ '^[a-z0-9][a-z0-9-]{0,62}$'),
  name       text NOT NULL,
  fail_mode  text NOT NULL DEFAULT 'open' CHECK (fail_mode IN ('open','closed')),
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE groups (
  id        uuid PRIMARY KEY,
  tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  name      text NOT NULL,
  UNIQUE (tenant_id, name),
  UNIQUE (tenant_id, id)            -- target of composite FKs: forces same-tenant references
);

-- ---------- identity / RBAC ----------
-- Users are global (an MSP operator may serve several tenants); access is granted
-- by role_bindings. tenant_id NULL = platform-wide binding.
CREATE TABLE users (
  id           uuid PRIMARY KEY,
  oidc_issuer  text NOT NULL,
  oidc_subject text NOT NULL,
  email        text,
  created_at   timestamptz NOT NULL DEFAULT now(),
  disabled_at  timestamptz,
  UNIQUE (oidc_issuer, oidc_subject)
);

CREATE TABLE role_bindings (
  id        uuid PRIMARY KEY,
  user_id   uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  tenant_id uuid REFERENCES tenants(id) ON DELETE CASCADE,
  role      text NOT NULL CHECK (role IN ('owner','admin','editor','viewer','auditor')),
  UNIQUE NULLS NOT DISTINCT (user_id, tenant_id, role)
);

CREATE TABLE api_tokens (
  id          uuid PRIMARY KEY,
  tenant_id   uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  name        text NOT NULL,
  role        text NOT NULL CHECK (role IN ('admin','editor','viewer','auditor')),
  secret_hash bytea NOT NULL UNIQUE,
  expires_at  timestamptz,
  revoked_at  timestamptz,
  created_at  timestamptz NOT NULL DEFAULT now()
);

-- ---------- policy ----------
CREATE TABLE rules (
  id         uuid PRIMARY KEY,
  tenant_id  uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  group_id   uuid,                       -- NULL = whole tenant
  action     text NOT NULL CHECK (action IN ('allow','block')),
  pattern    text NOT NULL,
  comment    text NOT NULL DEFAULT '',
  created_at timestamptz NOT NULL DEFAULT now(),
  FOREIGN KEY (tenant_id, group_id) REFERENCES groups (tenant_id, id) ON DELETE CASCADE
);
CREATE INDEX rules_tenant_idx ON rules (tenant_id, group_id);

-- Global catalogue of third-party lists (license + attribution are mandatory).
CREATE TABLE list_sources (
  id          text PRIMARY KEY,
  name        text NOT NULL,
  url         text NOT NULL,
  format      text NOT NULL CHECK (format IN ('hosts','domains','abp')),
  license     text NOT NULL,
  attribution text NOT NULL,
  enabled     boolean NOT NULL DEFAULT true
);

CREATE TABLE list_subscriptions (
  tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  group_id  uuid,                        -- NULL = whole tenant
  source_id text NOT NULL REFERENCES list_sources(id),
  UNIQUE NULLS NOT DISTINCT (tenant_id, group_id, source_id),
  FOREIGN KEY (tenant_id, group_id) REFERENCES groups (tenant_id, id) ON DELETE CASCADE
);

CREATE TABLE bundle_versions (
  tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  group_id  uuid NOT NULL,
  version   bigint NOT NULL DEFAULT 0,
  PRIMARY KEY (tenant_id, group_id),
  FOREIGN KEY (tenant_id, group_id) REFERENCES groups (tenant_id, id) ON DELETE CASCADE
);

-- ---------- device enrolment ----------
CREATE TABLE enrollment_tokens (
  id          uuid PRIMARY KEY,
  tenant_id   uuid NOT NULL,
  group_id    uuid NOT NULL,
  secret_hash bytea NOT NULL UNIQUE,     -- SHA-256; the secret is never stored
  expires_at  timestamptz NOT NULL,
  max_uses    integer CHECK (max_uses > 0),
  used        integer NOT NULL DEFAULT 0,
  revoked_at  timestamptz,
  FOREIGN KEY (tenant_id, group_id) REFERENCES groups (tenant_id, id) ON DELETE CASCADE
);

CREATE TABLE device_credentials (
  id          uuid PRIMARY KEY,
  tenant_id   uuid NOT NULL,
  group_id    uuid NOT NULL,
  secret_hash bytea NOT NULL UNIQUE,
  info        text NOT NULL DEFAULT '',
  last_seen   timestamptz NOT NULL DEFAULT now(),
  rotated_at  timestamptz NOT NULL DEFAULT now(),
  revoked_at  timestamptz,
  FOREIGN KEY (tenant_id, group_id) REFERENCES groups (tenant_id, id) ON DELETE CASCADE
);

-- ---------- audit (per-tenant hash chain) ----------
CREATE TABLE audit_events (
  tenant_id uuid NOT NULL REFERENCES tenants(id),   -- no cascade: audit outlives config
  seq       bigint NOT NULL,
  event     jsonb NOT NULL,                         -- hygeia_audit::Event
  hash      text NOT NULL,
  PRIMARY KEY (tenant_id, seq)
);

-- Append-only: block UPDATE/DELETE/TRUNCATE for everyone, including the owner.
CREATE FUNCTION audit_immutable() RETURNS trigger LANGUAGE plpgsql AS
$$ BEGIN RAISE EXCEPTION 'audit_events is append-only'; END $$;
CREATE TRIGGER audit_no_mutation BEFORE UPDATE OR DELETE ON audit_events
  FOR EACH ROW EXECUTE FUNCTION audit_immutable();
CREATE TRIGGER audit_no_truncate BEFORE TRUNCATE ON audit_events
  FOR EACH STATEMENT EXECUTE FUNCTION audit_immutable();

-- ---------- row level security ----------
DO $$ DECLARE t text; BEGIN
  FOREACH t IN ARRAY ARRAY['groups','api_tokens','rules','list_subscriptions','bundle_versions',
                           'enrollment_tokens','device_credentials','audit_events'] LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format($p$CREATE POLICY tenant_isolation ON %I
      USING (tenant_id = nullif(current_setting('app.tenant', true), '')::uuid)
      WITH CHECK (tenant_id = nullif(current_setting('app.tenant', true), '')::uuid)$p$, t);
  END LOOP;
END $$;

-- ---------- pre-tenant lookups (SECURITY DEFINER) ----------
CREATE FUNCTION hyg_enroll(p_token_hash bytea, p_dev_id uuid, p_dev_hash bytea, p_info text, p_now timestamptz)
RETURNS TABLE (tenant_id uuid, group_id uuid)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp AS $$
DECLARE v_tenant uuid; v_group uuid;
BEGIN
  -- single atomic statement: check + consume one use
  UPDATE enrollment_tokens t SET used = used + 1
   WHERE t.secret_hash = p_token_hash AND t.revoked_at IS NULL AND t.expires_at > p_now
     AND (t.max_uses IS NULL OR t.used < t.max_uses)
  RETURNING t.tenant_id, t.group_id INTO v_tenant, v_group;
  IF NOT FOUND THEN RETURN; END IF;
  INSERT INTO device_credentials (id, tenant_id, group_id, secret_hash, info, last_seen, rotated_at)
  VALUES (p_dev_id, v_tenant, v_group, p_dev_hash, left(p_info, 256), p_now, p_now);
  RETURN QUERY SELECT v_tenant, v_group;
END $$;

CREATE FUNCTION hyg_auth_device(p_hash bytea, p_now timestamptz)
RETURNS TABLE (id uuid, tenant_id uuid, group_id uuid, info text)
LANGUAGE sql SECURITY DEFINER SET search_path = public, pg_temp AS $$
  UPDATE device_credentials d SET last_seen = p_now
   WHERE d.secret_hash = p_hash AND d.revoked_at IS NULL
  RETURNING d.id, d.tenant_id, d.group_id, d.info
$$;

REVOKE ALL ON FUNCTION hyg_enroll(bytea, uuid, bytea, text, timestamptz) FROM PUBLIC;
REVOKE ALL ON FUNCTION hyg_auth_device(bytea, timestamptz) FROM PUBLIC;

-- ---------- runtime role grants ----------
DO $$ BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'hygeia_app') THEN
    GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO hygeia_app;
    REVOKE UPDATE, DELETE, TRUNCATE ON audit_events FROM hygeia_app;
    GRANT EXECUTE ON FUNCTION hyg_enroll(bytea, uuid, bytea, text, timestamptz) TO hygeia_app;
    GRANT EXECUTE ON FUNCTION hyg_auth_device(bytea, timestamptz) TO hygeia_app;
  END IF;
END $$;
