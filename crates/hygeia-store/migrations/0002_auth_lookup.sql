-- API token authentication happens before the tenant is known (same reason as
-- device auth in 0001): SECURITY DEFINER lookup, execute granted to the runtime role only.
CREATE FUNCTION hyg_auth_api_token(p_hash bytea, p_now timestamptz)
RETURNS TABLE (id uuid, tenant_id uuid, name text, role text, expires_at bigint)
LANGUAGE sql SECURITY DEFINER SET search_path = public, pg_temp AS $$
  SELECT t.id, t.tenant_id, t.name, t.role, extract(epoch from t.expires_at)::bigint
    FROM api_tokens t
   WHERE t.secret_hash = p_hash AND t.revoked_at IS NULL
     AND (t.expires_at IS NULL OR t.expires_at > p_now)
$$;
REVOKE ALL ON FUNCTION hyg_auth_api_token(bytea, timestamptz) FROM PUBLIC;

DO $$ BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'hygeia_app') THEN
    GRANT EXECUTE ON FUNCTION hyg_auth_api_token(bytea, timestamptz) TO hygeia_app;
  END IF;
END $$;
