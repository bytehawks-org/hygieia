-- Per-tenant filter-list selection.
--   list_policy 'all'      : the tenant gets every platform-enabled source (default; zero-config friendly)
--   list_policy 'selected' : only sources in list_subscriptions (tenant-wide: group_id NULL, or per group)
ALTER TABLE tenants
  ADD COLUMN list_policy text NOT NULL DEFAULT 'all' CHECK (list_policy IN ('all', 'selected'));

-- The catalogue is mirrored from the platform configuration (id, provenance); the parser format is not
-- needed in the database.
ALTER TABLE list_sources DROP CONSTRAINT list_sources_format_check;
ALTER TABLE list_sources ALTER COLUMN format DROP NOT NULL;
