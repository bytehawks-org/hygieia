-- Compiled, signed bundles shared by all server replicas: the first replica that compiles a given
-- input set stores the bytes; every replica then serves the same bytes (same version, same ETag).
CREATE TABLE compiled_bundles (
  tenant_id   uuid NOT NULL,
  group_id    uuid NOT NULL,
  inputs_hash text NOT NULL,
  version     bigint NOT NULL,
  bytes       bytea NOT NULL,
  created_at  timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, group_id),
  FOREIGN KEY (tenant_id, group_id) REFERENCES groups (tenant_id, id) ON DELETE CASCADE
);
ALTER TABLE compiled_bundles ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON compiled_bundles
  USING (tenant_id = nullif(current_setting('app.tenant', true), '')::uuid)
  WITH CHECK (tenant_id = nullif(current_setting('app.tenant', true), '')::uuid);
DO $$ BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'hygeia_app') THEN
    GRANT SELECT, INSERT, UPDATE, DELETE ON compiled_bundles TO hygeia_app;
  END IF;
END $$;
