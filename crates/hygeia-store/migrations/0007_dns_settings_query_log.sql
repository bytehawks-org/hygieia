-- Per-tenant cloud-DNS settings and the (optional, pseudonymised) query log.
--   * the log is OFF by default (log_enabled = false);
--   * client is a keyed, daily-rotating pseudonym of the source IP, never the address itself;
--   * retention is enforced by a purge job (retention_days, 1..365).
CREATE TABLE dns_settings (
  tenant_id      uuid PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
  log_enabled    boolean NOT NULL DEFAULT false,
  retention_days integer NOT NULL DEFAULT 30 CHECK (retention_days BETWEEN 1 AND 365),
  fail_open      boolean,
  block_mode     text CHECK (block_mode IN ('nxdomain', 'null_ip'))
);
CREATE TABLE query_log (
  id        bigserial PRIMARY KEY,
  tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  ts        bigint NOT NULL,
  group_id  text NOT NULL,
  token_id  text,
  transport text NOT NULL,
  client    text NOT NULL,
  qname     text NOT NULL,
  qtype     text NOT NULL,
  action    text NOT NULL,
  reason    text NOT NULL
);
CREATE INDEX query_log_tenant_ts ON query_log (tenant_id, ts DESC);
DO $$ DECLARE t text; BEGIN
  FOREACH t IN ARRAY ARRAY['dns_settings', 'query_log'] LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format($p$CREATE POLICY tenant_isolation ON %I
      USING (tenant_id = nullif(current_setting('app.tenant', true), '')::uuid)
      WITH CHECK (tenant_id = nullif(current_setting('app.tenant', true), '')::uuid)$p$, t);
  END LOOP;
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'hygeia_app') THEN
    GRANT SELECT, INSERT, UPDATE, DELETE ON dns_settings, query_log TO hygeia_app;
    GRANT USAGE ON SEQUENCE query_log_id_seq TO hygeia_app;
  END IF;
END $$;
