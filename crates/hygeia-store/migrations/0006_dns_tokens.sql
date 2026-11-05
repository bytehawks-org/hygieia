-- DNS access tokens for the cloud DNS service (DoH path /dns-query/<token>). A token identifies a
-- tenant + group and is the ONLY way a query is attributed: no token, no answer (never an open resolver).
CREATE TABLE dns_tokens (
  id          uuid PRIMARY KEY,
  tenant_id   uuid NOT NULL,
  group_id    uuid NOT NULL,
  name        text NOT NULL,
  secret_hash bytea NOT NULL UNIQUE,
  expires_at  timestamptz,
  revoked_at  timestamptz,
  created_at  timestamptz NOT NULL DEFAULT now(),
  FOREIGN KEY (tenant_id, group_id) REFERENCES groups (tenant_id, id) ON DELETE CASCADE
);
ALTER TABLE dns_tokens ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON dns_tokens
  USING (tenant_id = nullif(current_setting('app.tenant', true), '')::uuid)
  WITH CHECK (tenant_id = nullif(current_setting('app.tenant', true), '')::uuid);

-- Authentication happens before the tenant is known: SECURITY DEFINER lookup (same pattern as
-- hyg_auth_device / hyg_auth_api_token).
CREATE FUNCTION hyg_auth_dns_token(p_hash bytea, p_now timestamptz)
RETURNS TABLE (id uuid, tenant_id uuid, group_id uuid, name text, expires_at bigint)
LANGUAGE sql SECURITY DEFINER SET search_path = public, pg_temp AS $$
  SELECT t.id, t.tenant_id, t.group_id, t.name, extract(epoch from t.expires_at)::bigint
    FROM dns_tokens t
   WHERE t.secret_hash = p_hash AND t.revoked_at IS NULL
     AND (t.expires_at IS NULL OR t.expires_at > p_now)
$$;
REVOKE ALL ON FUNCTION hyg_auth_dns_token(bytea, timestamptz) FROM PUBLIC;
DO $$ BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'hygeia_app') THEN
    GRANT SELECT, INSERT, UPDATE, DELETE ON dns_tokens TO hygeia_app;
    GRANT EXECUTE ON FUNCTION hyg_auth_dns_token(bytea, timestamptz) TO hygeia_app;
  END IF;
END $$;
