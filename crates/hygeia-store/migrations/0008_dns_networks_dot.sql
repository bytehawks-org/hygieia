-- Attribution of plain DNS and DoT/DoQ clients:
--   dns_networks : source networks a tenant registered ("these addresses are my clients");
--                  a CIDR belongs to exactly one tenant, and broad ranges are refused by the API
--                  (the service must never become an open resolver)
--   dns_tokens.dot_label : optional endpoint label for DoT/DoQ (SNI <label>.<dot domain>). The SNI
--                  is visible on the wire, so the label is an identifier, not a secret.
ALTER TABLE dns_tokens ADD COLUMN dot_label text UNIQUE;

CREATE TABLE dns_networks (
  id         uuid PRIMARY KEY,
  tenant_id  uuid NOT NULL,
  group_id   uuid NOT NULL,
  name       text NOT NULL,
  cidr       text NOT NULL UNIQUE,
  created_at timestamptz NOT NULL DEFAULT now(),
  FOREIGN KEY (tenant_id, group_id) REFERENCES groups (tenant_id, id) ON DELETE CASCADE
);
ALTER TABLE dns_networks ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON dns_networks
  USING (tenant_id = nullif(current_setting('app.tenant', true), '')::uuid)
  WITH CHECK (tenant_id = nullif(current_setting('app.tenant', true), '')::uuid);

-- Pre-tenant lookups (the data plane does not know the tenant yet).
CREATE FUNCTION hyg_dns_networks()
RETURNS TABLE (id uuid, tenant_id uuid, group_id uuid, name text, cidr text)
LANGUAGE sql SECURITY DEFINER SET search_path = public, pg_temp AS $$
  SELECT id, tenant_id, group_id, name, cidr FROM dns_networks
$$;
CREATE FUNCTION hyg_auth_dot_label(p_label text, p_now timestamptz)
RETURNS TABLE (id uuid, tenant_id uuid, group_id uuid, name text, expires_at bigint, dot_label text)
LANGUAGE sql SECURITY DEFINER SET search_path = public, pg_temp AS $$
  SELECT t.id, t.tenant_id, t.group_id, t.name, extract(epoch from t.expires_at)::bigint, t.dot_label
    FROM dns_tokens t
   WHERE t.dot_label = p_label AND t.revoked_at IS NULL
     AND (t.expires_at IS NULL OR t.expires_at > p_now)
$$;
REVOKE ALL ON FUNCTION hyg_dns_networks() FROM PUBLIC;
REVOKE ALL ON FUNCTION hyg_auth_dot_label(text, timestamptz) FROM PUBLIC;
DO $$ BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'hygeia_app') THEN
    GRANT SELECT, INSERT, UPDATE, DELETE ON dns_networks TO hygeia_app;
    GRANT EXECUTE ON FUNCTION hyg_dns_networks() TO hygeia_app;
    GRANT EXECUTE ON FUNCTION hyg_auth_dot_label(text, timestamptz) TO hygeia_app;
  END IF;
END $$;
