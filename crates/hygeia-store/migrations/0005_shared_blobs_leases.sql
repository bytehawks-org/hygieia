-- Platform-level (not tenant-scoped) coordination between server replicas:
--   shared_blobs : content-addressed artefacts one replica publishes and the others load
--                  (parsed filter lists, list status)
--   leases       : a named lease so that only one replica talks to the Internet at a time
CREATE TABLE shared_blobs (
  key        text PRIMARY KEY,
  hash       text NOT NULL,
  bytes      bytea NOT NULL,
  updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE leases (
  name   text PRIMARY KEY,
  holder text NOT NULL,
  until  timestamptz NOT NULL
);
DO $$ BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'hygeia_app') THEN
    GRANT SELECT, INSERT, UPDATE, DELETE ON shared_blobs, leases TO hygeia_app;
  END IF;
END $$;
