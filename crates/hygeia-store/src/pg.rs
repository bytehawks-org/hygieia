//! PostgreSQL implementation. Every tenant-scoped statement runs in a
//! transaction that first sets `app.tenant` (SET LOCAL semantics), so row
//! level security enforces isolation even if a query forgets `tenant_id`.

use async_trait::async_trait;
use hygeia_audit::{Draft, Event, GENESIS};
use sqlx::postgres::{PgPool, PgPoolOptions};
use sqlx::{Postgres, Row, Transaction};

use crate::rbac::Role;
use crate::{
    ApiToken, AuditStatus, Binding, CatalogSource, DEFAULT_GROUP_ID, DEFAULT_TENANT_ID, Device,
    EnrollmentToken, Group, ListPolicy, PREFIX_API, PREFIX_DEVICE, PREFIX_ENROLL, Result, Rule,
    RuleAction, Selection, Store, StoreError, Subscription, Tenant, User, hash_secret, new_id,
    new_secret,
};
use crate::{DnsSettings, DnsToken, PREFIX_DNS, QueryLogEntry, StoredBundle};

#[derive(Clone)]
pub struct PgStore {
    pool: PgPool,
}

fn map_err(e: sqlx::Error) -> StoreError {
    if let sqlx::Error::Database(d) = &e {
        // invalid uuid text, FK violation, check violation: caller-supplied ids that don't resolve
        match d.code().as_deref() {
            Some("22P02" | "23503" | "23514") => return StoreError::NotFound,
            Some("23505") => return StoreError::Conflict,
            _ => {}
        }
    }
    StoreError::Backend(e.to_string())
}

impl PgStore {
    pub async fn connect(url: &str) -> Result<Self> {
        let pool = PgPoolOptions::new()
            .max_connections(10)
            .connect(url)
            .await
            .map_err(map_err)?;
        Ok(Self { pool })
    }

    pub fn from_pool(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Apply migrations. Run with the schema OWNER role, not the runtime role.
    pub async fn migrate(owner_url: &str) -> Result<()> {
        let pool = PgPoolOptions::new()
            .max_connections(1)
            .connect(owner_url)
            .await
            .map_err(map_err)?;
        sqlx::migrate!("./migrations")
            .run(&pool)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))?;
        Ok(())
    }

    /// Begin a transaction bound to one tenant.
    async fn tenant_tx(&self, tenant_id: &str) -> Result<Transaction<'static, Postgres>> {
        let mut tx = self.pool.begin().await.map_err(map_err)?;
        sqlx::query("select set_config('app.tenant', $1, true)")
            .bind(tenant_id)
            .execute(&mut *tx)
            .await
            .map_err(map_err)?;
        Ok(tx)
    }
}

fn device_from(r: &sqlx::postgres::PgRow, secret_hash: [u8; 32]) -> Device {
    Device {
        id: r.get("id"),
        tenant_id: r.get("tenant_id"),
        group_id: r.get("group_id"),
        secret_hash,
        info: r.get("info"),
        last_seen: r.get("last_seen"),
        revoked: r.get("revoked"),
    }
}

fn binding_from(r: &sqlx::postgres::PgRow) -> Option<Binding> {
    Some(Binding {
        id: r.get(0),
        user_id: r.get(1),
        tenant_id: r.get(2),
        role: r.get::<String, _>(3).parse().ok()?,
    })
}

fn rule_from(r: &sqlx::postgres::PgRow) -> Rule {
    Rule {
        id: r.get("id"),
        tenant_id: r.get("tenant_id"),
        group_id: r.get("group_id"),
        action: if r.get::<String, _>("action") == "allow" {
            RuleAction::Allow
        } else {
            RuleAction::Block
        },
        pattern: r.get("pattern"),
        comment: r.get("comment"),
    }
}

// Macro (not const) so `concat!` yields a literal: sqlx rejects dynamic SQL strings.
macro_rules! rule_cols {
    () => {
        "id::text, tenant_id::text, group_id::text, action, pattern, comment"
    };
}

#[async_trait]
impl Store for PgStore {
    async fn bootstrap_default(&self) -> Result<()> {
        sqlx::query(
            "insert into tenants (id, slug, name) values ($1::uuid, 'default', 'Default') on conflict do nothing",
        )
        .bind(DEFAULT_TENANT_ID)
        .execute(&self.pool)
        .await
        .map_err(map_err)?;
        let mut tx = self.tenant_tx(DEFAULT_TENANT_ID).await?;
        sqlx::query("insert into groups (id, tenant_id, name) values ($1::uuid, $2::uuid, 'default') on conflict do nothing")
            .bind(DEFAULT_GROUP_ID)
            .bind(DEFAULT_TENANT_ID)
            .execute(&mut *tx)
            .await
            .map_err(map_err)?;
        tx.commit().await.map_err(map_err)
    }

    async fn create_enrollment_token(
        &self,
        tenant_id: &str,
        group_id: &str,
        ttl_secs: i64,
        max_uses: Option<u32>,
        now: i64,
    ) -> Result<(EnrollmentToken, String)> {
        let (secret, hash) = new_secret(PREFIX_ENROLL);
        let id = new_id();
        let expires_at = now.saturating_add(ttl_secs);
        let mut tx = self.tenant_tx(tenant_id).await?;
        sqlx::query(
            "insert into enrollment_tokens (id, tenant_id, group_id, secret_hash, expires_at, max_uses)
             values ($1::uuid, $2::uuid, $3::uuid, $4, to_timestamp($5::float8), $6)",
        )
        .bind(&id)
        .bind(tenant_id)
        .bind(group_id)
        .bind(&hash[..])
        .bind(expires_at as f64)
        .bind(max_uses.map(|m| m as i32))
        .execute(&mut *tx)
        .await
        .map_err(map_err)?;
        tx.commit().await.map_err(map_err)?;
        let t = EnrollmentToken {
            id,
            tenant_id: tenant_id.into(),
            group_id: group_id.into(),
            secret_hash: hash,
            expires_at,
            max_uses,
            used: 0,
            revoked: false,
        };
        Ok((t, secret))
    }

    async fn revoke_enrollment_token(&self, tenant_id: &str, id: &str) -> Result<()> {
        let mut tx = self.tenant_tx(tenant_id).await?;
        let n = sqlx::query("update enrollment_tokens set revoked_at = now() where id = $1::uuid")
            .bind(id)
            .execute(&mut *tx)
            .await
            .map_err(map_err)?
            .rows_affected();
        tx.commit().await.map_err(map_err)?;
        if n == 0 {
            Err(StoreError::NotFound)
        } else {
            Ok(())
        }
    }

    async fn enroll(&self, secret: &str, info: &str, now: i64) -> Result<(Device, String)> {
        if !secret.starts_with(PREFIX_ENROLL) {
            return Err(StoreError::InvalidToken);
        }
        let (dev_secret, dev_hash) = new_secret(PREFIX_DEVICE);
        let dev_id = new_id();
        let row = sqlx::query(
            "select tenant_id::text, group_id::text from hyg_enroll($1, $2::uuid, $3, $4, to_timestamp($5::float8))",
        )
        .bind(&hash_secret(secret)[..])
        .bind(&dev_id)
        .bind(&dev_hash[..])
        .bind(info)
        .bind(now as f64)
        .fetch_optional(&self.pool)
        .await
        .map_err(map_err)?
        .ok_or(StoreError::InvalidToken)?;
        let d = Device {
            id: dev_id,
            tenant_id: row.get(0),
            group_id: row.get(1),
            secret_hash: dev_hash,
            info: info.chars().take(256).collect(),
            last_seen: now,
            revoked: false,
        };
        Ok((d, dev_secret))
    }

    async fn authenticate_device(&self, secret: &str, now: i64) -> Result<Option<Device>> {
        if !secret.starts_with(PREFIX_DEVICE) {
            return Ok(None);
        }
        let h = hash_secret(secret);
        let row = sqlx::query("select id::text, tenant_id::text, group_id::text, info from hyg_auth_device($1, to_timestamp($2::float8))")
            .bind(&h[..])
            .bind(now as f64)
            .fetch_optional(&self.pool)
            .await
            .map_err(map_err)?;
        Ok(row.map(|r| Device {
            id: r.get(0),
            tenant_id: r.get(1),
            group_id: r.get(2),
            secret_hash: h,
            info: r.get(3),
            last_seen: now,
            revoked: false,
        }))
    }

    async fn revoke_device(&self, tenant_id: &str, id: &str) -> Result<()> {
        let mut tx = self.tenant_tx(tenant_id).await?;
        let n = sqlx::query("update device_credentials set revoked_at = now() where id = $1::uuid")
            .bind(id)
            .execute(&mut *tx)
            .await
            .map_err(map_err)?
            .rows_affected();
        tx.commit().await.map_err(map_err)?;
        if n == 0 {
            Err(StoreError::NotFound)
        } else {
            Ok(())
        }
    }

    async fn list_devices(&self, tenant_id: &str) -> Result<Vec<Device>> {
        let mut tx = self.tenant_tx(tenant_id).await?;
        let rows = sqlx::query(
            "select id::text, tenant_id::text, group_id::text, info,
                    extract(epoch from last_seen)::bigint as last_seen,
                    revoked_at is not null as revoked
             from device_credentials order by last_seen desc",
        )
        .fetch_all(&mut *tx)
        .await
        .map_err(map_err)?;
        tx.commit().await.map_err(map_err)?;
        Ok(rows.iter().map(|r| device_from(r, [0; 32])).collect())
    }

    async fn add_rule(&self, mut r: Rule) -> Result<Rule> {
        r.id = new_id();
        let mut tx = self.tenant_tx(&r.tenant_id).await?;
        sqlx::query(
            "insert into rules (id, tenant_id, group_id, action, pattern, comment)
             values ($1::uuid, $2::uuid, $3::uuid, $4, $5, $6)",
        )
        .bind(&r.id)
        .bind(&r.tenant_id)
        .bind(r.group_id.as_deref())
        .bind(match r.action {
            RuleAction::Allow => "allow",
            RuleAction::Block => "block",
        })
        .bind(&r.pattern)
        .bind(&r.comment)
        .execute(&mut *tx)
        .await
        .map_err(map_err)?;
        tx.commit().await.map_err(map_err)?;
        Ok(r)
    }

    async fn delete_rule(&self, tenant_id: &str, id: &str) -> Result<Rule> {
        let mut tx = self.tenant_tx(tenant_id).await?;
        let row = sqlx::query(concat!(
            "delete from rules where id = $1::uuid returning ",
            rule_cols!()
        ))
        .bind(id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(map_err)?
        .ok_or(StoreError::NotFound)?;
        tx.commit().await.map_err(map_err)?;
        Ok(rule_from(&row))
    }

    async fn rules_for(&self, tenant_id: &str, group_id: &str) -> Result<Vec<Rule>> {
        let mut tx = self.tenant_tx(tenant_id).await?;
        let rows = sqlx::query(concat!(
            "select ",
            rule_cols!(),
            " from rules where group_id is null or group_id = $1::uuid order by created_at, id"
        ))
        .bind(group_id)
        .fetch_all(&mut *tx)
        .await
        .map_err(map_err)?;
        tx.commit().await.map_err(map_err)?;
        Ok(rows.iter().map(rule_from).collect())
    }

    async fn list_rules(&self, tenant_id: &str) -> Result<Vec<Rule>> {
        let mut tx = self.tenant_tx(tenant_id).await?;
        let rows = sqlx::query(concat!(
            "select ",
            rule_cols!(),
            " from rules order by created_at, id"
        ))
        .fetch_all(&mut *tx)
        .await
        .map_err(map_err)?;
        tx.commit().await.map_err(map_err)?;
        Ok(rows.iter().map(rule_from).collect())
    }

    async fn next_bundle_version(&self, tenant_id: &str, group_id: &str) -> Result<u64> {
        let mut tx = self.tenant_tx(tenant_id).await?;
        let v: i64 = sqlx::query_scalar(
            "insert into bundle_versions (tenant_id, group_id, version) values ($1::uuid, $2::uuid, 1)
             on conflict (tenant_id, group_id) do update set version = bundle_versions.version + 1
             returning version",
        )
        .bind(tenant_id)
        .bind(group_id)
        .fetch_one(&mut *tx)
        .await
        .map_err(map_err)?;
        tx.commit().await.map_err(map_err)?;
        Ok(v as u64)
    }

    async fn load_compiled(&self, tenant_id: &str, group_id: &str) -> Result<Option<StoredBundle>> {
        let mut tx = self.tenant_tx(tenant_id).await?;
        let row = sqlx::query(
            "select inputs_hash, version, bytes from compiled_bundles
             where tenant_id = $1::uuid and group_id = $2::uuid",
        )
        .bind(tenant_id)
        .bind(group_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(map_err)?;
        tx.commit().await.map_err(map_err)?;
        Ok(row.map(|r| StoredBundle {
            inputs_hash: r.get("inputs_hash"),
            version: r.get::<i64, _>("version") as u64,
            bytes: r.get("bytes"),
        }))
    }

    async fn store_compiled(
        &self,
        tenant_id: &str,
        group_id: &str,
        c: StoredBundle,
    ) -> Result<StoredBundle> {
        let mut tx = self.tenant_tx(tenant_id).await?;
        // Serialise concurrent publishers of the same (tenant, group) across replicas.
        sqlx::query("select pg_advisory_xact_lock(hashtextextended($1, 0))")
            .bind(format!("compiled:{tenant_id}:{group_id}"))
            .execute(&mut *tx)
            .await
            .map_err(map_err)?;
        let cur = sqlx::query(
            "select inputs_hash, version, bytes from compiled_bundles
             where tenant_id = $1::uuid and group_id = $2::uuid",
        )
        .bind(tenant_id)
        .bind(group_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(map_err)?
        .map(|r| StoredBundle {
            inputs_hash: r.get("inputs_hash"),
            version: r.get::<i64, _>("version") as u64,
            bytes: r.get("bytes"),
        });
        let winner = match cur {
            Some(cur) if cur.inputs_hash == c.inputs_hash || cur.version >= c.version => cur,
            _ => {
                sqlx::query(
                    "insert into compiled_bundles (tenant_id, group_id, inputs_hash, version, bytes)
                     values ($1::uuid, $2::uuid, $3, $4, $5)
                     on conflict (tenant_id, group_id) do update
                       set inputs_hash = excluded.inputs_hash, version = excluded.version,
                           bytes = excluded.bytes, created_at = now()",
                )
                .bind(tenant_id)
                .bind(group_id)
                .bind(&c.inputs_hash)
                .bind(c.version as i64)
                .bind(&c.bytes)
                .execute(&mut *tx)
                .await
                .map_err(map_err)?;
                c
            }
        };
        tx.commit().await.map_err(map_err)?;
        Ok(winner)
    }

    async fn try_lease(&self, name: &str, holder: &str, ttl_secs: i64, now: i64) -> Result<bool> {
        // One atomic statement: insert, or take over only if ours or expired.
        let r = sqlx::query(
            "insert into leases (name, holder, until) values ($1, $2, to_timestamp($3::bigint + $4::bigint))
             on conflict (name) do update set holder = excluded.holder, until = excluded.until
               where leases.holder = excluded.holder or leases.until < to_timestamp($3::bigint)",
        )
        .bind(name)
        .bind(holder)
        .bind(now)
        .bind(ttl_secs)
        .execute(&self.pool)
        .await
        .map_err(map_err)?;
        Ok(r.rows_affected() == 1)
    }

    async fn put_shared(&self, key: &str, hash: &str, bytes: &[u8]) -> Result<()> {
        sqlx::query(
            "insert into shared_blobs (key, hash, bytes) values ($1, $2, $3)
             on conflict (key) do update set hash = excluded.hash, bytes = excluded.bytes, updated_at = now()",
        )
        .bind(key)
        .bind(hash)
        .bind(bytes)
        .execute(&self.pool)
        .await
        .map_err(map_err)?;
        Ok(())
    }

    async fn shared_index(&self, prefix: &str) -> Result<Vec<(String, String)>> {
        let rows = sqlx::query(
            "select key, hash from shared_blobs where starts_with(key, $1) order by key",
        )
        .bind(prefix)
        .fetch_all(&self.pool)
        .await
        .map_err(map_err)?;
        Ok(rows.iter().map(|r| (r.get("key"), r.get("hash"))).collect())
    }

    async fn get_shared(&self, key: &str) -> Result<Option<(String, Vec<u8>)>> {
        let r = sqlx::query("select hash, bytes from shared_blobs where key = $1")
            .bind(key)
            .fetch_optional(&self.pool)
            .await
            .map_err(map_err)?;
        Ok(r.map(|r| (r.get("hash"), r.get("bytes"))))
    }

    async fn dns_settings(&self, tenant_id: &str) -> Result<DnsSettings> {
        let mut tx = self.tenant_tx(tenant_id).await?;
        let row = sqlx::query("select log_enabled, retention_days, fail_open, block_mode from dns_settings where tenant_id = $1::uuid")
            .bind(tenant_id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(map_err)?;
        tx.commit().await.map_err(map_err)?;
        Ok(row.map_or_else(DnsSettings::default, |r| DnsSettings {
            log_enabled: r.get(0),
            retention_days: r.get::<i32, _>(1) as u32,
            fail_open: r.get(2),
            block_mode: r.get(3),
        }))
    }

    async fn set_dns_settings(&self, tenant_id: &str, s: DnsSettings) -> Result<()> {
        let mut tx = self.tenant_tx(tenant_id).await?;
        // CHECK constraints reject out-of-range retention and unknown block modes
        sqlx::query(
            "insert into dns_settings (tenant_id, log_enabled, retention_days, fail_open, block_mode)
             values ($1::uuid, $2, $3, $4, $5)
             on conflict (tenant_id) do update set log_enabled = excluded.log_enabled,
               retention_days = excluded.retention_days, fail_open = excluded.fail_open,
               block_mode = excluded.block_mode",
        )
        .bind(tenant_id)
        .bind(s.log_enabled)
        .bind(s.retention_days as i32)
        .bind(s.fail_open)
        .bind(s.block_mode)
        .execute(&mut *tx)
        .await
        .map_err(map_err)?;
        tx.commit().await.map_err(map_err)?;
        Ok(())
    }

    async fn append_query_log(&self, tenant_id: &str, entries: &[QueryLogEntry]) -> Result<()> {
        if entries.is_empty() {
            return Ok(());
        }
        let mut tx = self.tenant_tx(tenant_id).await?;
        for e in entries {
            sqlx::query(
                "insert into query_log (tenant_id, ts, group_id, token_id, transport, client, qname, qtype, action, reason)
                 values ($1::uuid, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
            )
            .bind(tenant_id)
            .bind(e.ts)
            .bind(&e.group_id)
            .bind(&e.token_id)
            .bind(&e.transport)
            .bind(&e.client)
            .bind(&e.qname)
            .bind(&e.qtype)
            .bind(&e.action)
            .bind(&e.reason)
            .execute(&mut *tx)
            .await
            .map_err(map_err)?;
        }
        tx.commit().await.map_err(map_err)?;
        Ok(())
    }

    async fn query_log(
        &self,
        tenant_id: &str,
        since: i64,
        limit: u32,
        qname_contains: Option<&str>,
        action: Option<&str>,
    ) -> Result<Vec<QueryLogEntry>> {
        let mut tx = self.tenant_tx(tenant_id).await?;
        let rows = sqlx::query(
            "select ts, group_id, token_id, transport, client, qname, qtype, action, reason from query_log
             where ts >= $1 and ($2::text is null or position(lower($2) in lower(qname)) > 0)
               and ($3::text is null or action = $3)
             order by ts desc, id desc limit $4",
        )
        .bind(since)
        .bind(qname_contains)
        .bind(action)
        .bind(limit as i64)
        .fetch_all(&mut *tx)
        .await
        .map_err(map_err)?;
        tx.commit().await.map_err(map_err)?;
        Ok(rows
            .iter()
            .map(|r| QueryLogEntry {
                ts: r.get(0),
                group_id: r.get(1),
                token_id: r.get(2),
                transport: r.get(3),
                client: r.get(4),
                qname: r.get(5),
                qtype: r.get(6),
                action: r.get(7),
                reason: r.get(8),
            })
            .collect())
    }

    async fn purge_query_log(&self, tenant_id: &str, before: i64) -> Result<u64> {
        let mut tx = self.tenant_tx(tenant_id).await?;
        let n = sqlx::query("delete from query_log where ts < $1")
            .bind(before)
            .execute(&mut *tx)
            .await
            .map_err(map_err)?
            .rows_affected();
        tx.commit().await.map_err(map_err)?;
        Ok(n)
    }

    async fn ping(&self) -> Result<()> {
        sqlx::query("select 1")
            .execute(&self.pool)
            .await
            .map_err(map_err)?;
        Ok(())
    }

    async fn sync_catalog(&self, sources: &[CatalogSource]) -> Result<()> {
        let mut tx = self.pool.begin().await.map_err(map_err)?;
        for c in sources {
            sqlx::query(
                "insert into list_sources (id, name, url, license, attribution, enabled) values ($1, $2, $3, $4, $5, true)
                 on conflict (id) do update set name = excluded.name, url = excluded.url,
                   license = excluded.license, attribution = excluded.attribution, enabled = true",
            )
            .bind(&c.id)
            .bind(&c.name)
            .bind(&c.url)
            .bind(&c.license)
            .bind(&c.attribution)
            .execute(&mut *tx)
            .await
            .map_err(map_err)?;
        }
        // sources no longer in the configuration stay (subscriptions reference them) but are disabled
        let ids: Vec<&str> = sources.iter().map(|c| c.id.as_str()).collect();
        sqlx::query("update list_sources set enabled = false where not (id = any($1))")
            .bind(&ids)
            .execute(&mut *tx)
            .await
            .map_err(map_err)?;
        tx.commit().await.map_err(map_err)
    }

    async fn list_policy(&self, tenant_id: &str) -> Result<ListPolicy> {
        let p: Option<String> =
            sqlx::query_scalar("select list_policy from tenants where id = $1::uuid")
                .bind(tenant_id)
                .fetch_optional(&self.pool)
                .await
                .map_err(map_err)?;
        match p.as_deref() {
            Some("selected") => Ok(ListPolicy::Selected),
            Some(_) => Ok(ListPolicy::All),
            None => Err(StoreError::NotFound),
        }
    }

    async fn set_list_policy(&self, tenant_id: &str, policy: ListPolicy) -> Result<()> {
        let n = sqlx::query("update tenants set list_policy = $2 where id = $1::uuid")
            .bind(tenant_id)
            .bind(match policy {
                ListPolicy::All => "all",
                ListPolicy::Selected => "selected",
            })
            .execute(&self.pool)
            .await
            .map_err(map_err)?
            .rows_affected();
        if n == 0 {
            Err(StoreError::NotFound)
        } else {
            Ok(())
        }
    }

    async fn subscriptions(&self, tenant_id: &str) -> Result<Vec<Subscription>> {
        let mut tx = self.tenant_tx(tenant_id).await?;
        let rows = sqlx::query(
            "select group_id::text, source_id from list_subscriptions order by source_id, group_id",
        )
        .fetch_all(&mut *tx)
        .await
        .map_err(map_err)?;
        tx.commit().await.map_err(map_err)?;
        Ok(rows
            .iter()
            .map(|r| Subscription {
                group_id: r.get(0),
                source_id: r.get(1),
            })
            .collect())
    }

    async fn subscribe(
        &self,
        tenant_id: &str,
        group_id: Option<&str>,
        source_id: &str,
    ) -> Result<()> {
        let mut tx = self.tenant_tx(tenant_id).await?;
        sqlx::query(
            "insert into list_subscriptions (tenant_id, group_id, source_id) values ($1::uuid, $2::uuid, $3)
             on conflict (tenant_id, group_id, source_id) do nothing",
        )
        .bind(tenant_id)
        .bind(group_id)
        .bind(source_id)
        .execute(&mut *tx)
        .await
        .map_err(map_err)?;
        tx.commit().await.map_err(map_err)
    }

    async fn unsubscribe(
        &self,
        tenant_id: &str,
        group_id: Option<&str>,
        source_id: &str,
    ) -> Result<()> {
        let mut tx = self.tenant_tx(tenant_id).await?;
        let n = sqlx::query(
            "delete from list_subscriptions where group_id is not distinct from $1::uuid and source_id = $2",
        )
        .bind(group_id)
        .bind(source_id)
        .execute(&mut *tx)
        .await
        .map_err(map_err)?
        .rows_affected();
        tx.commit().await.map_err(map_err)?;
        if n == 0 {
            Err(StoreError::NotFound)
        } else {
            Ok(())
        }
    }

    async fn selection(&self, tenant_id: &str, group_id: &str) -> Result<Selection> {
        if self.list_policy(tenant_id).await? == ListPolicy::All {
            return Ok(Selection::All);
        }
        let mut tx = self.tenant_tx(tenant_id).await?;
        let ids: Vec<String> = sqlx::query_scalar(
            "select distinct source_id from list_subscriptions where group_id is null or group_id = $1::uuid order by 1",
        )
        .bind(group_id)
        .fetch_all(&mut *tx)
        .await
        .map_err(map_err)?;
        tx.commit().await.map_err(map_err)?;
        Ok(Selection::Only(ids))
    }

    async fn create_tenant(&self, slug: &str, name: &str) -> Result<Tenant> {
        let id = new_id();
        sqlx::query("insert into tenants (id, slug, name) values ($1::uuid, $2, $3)")
            .bind(&id)
            .bind(slug)
            .bind(name)
            .execute(&self.pool)
            .await
            .map_err(map_err)?;
        Ok(Tenant {
            id,
            slug: slug.into(),
            name: name.into(),
        })
    }

    async fn list_tenants(&self) -> Result<Vec<Tenant>> {
        let rows =
            sqlx::query("select id::text, slug, name from tenants order by created_at, slug")
                .fetch_all(&self.pool)
                .await
                .map_err(map_err)?;
        Ok(rows
            .iter()
            .map(|r| Tenant {
                id: r.get(0),
                slug: r.get(1),
                name: r.get(2),
            })
            .collect())
    }

    async fn create_group(&self, tenant_id: &str, name: &str) -> Result<Group> {
        let id = new_id();
        let mut tx = self.tenant_tx(tenant_id).await?;
        sqlx::query("insert into groups (id, tenant_id, name) values ($1::uuid, $2::uuid, $3)")
            .bind(&id)
            .bind(tenant_id)
            .bind(name)
            .execute(&mut *tx)
            .await
            .map_err(map_err)?;
        tx.commit().await.map_err(map_err)?;
        Ok(Group {
            id,
            tenant_id: tenant_id.into(),
            name: name.into(),
        })
    }

    async fn list_groups(&self, tenant_id: &str) -> Result<Vec<Group>> {
        let mut tx = self.tenant_tx(tenant_id).await?;
        let rows = sqlx::query("select id::text, tenant_id::text, name from groups order by name")
            .fetch_all(&mut *tx)
            .await
            .map_err(map_err)?;
        tx.commit().await.map_err(map_err)?;
        Ok(rows
            .iter()
            .map(|r| Group {
                id: r.get(0),
                tenant_id: r.get(1),
                name: r.get(2),
            })
            .collect())
    }

    async fn upsert_user(&self, issuer: &str, subject: &str, email: Option<&str>) -> Result<User> {
        let row = sqlx::query(
            "insert into users (id, oidc_issuer, oidc_subject, email) values ($1::uuid, $2, $3, $4)
             on conflict (oidc_issuer, oidc_subject) do update set email = coalesce(excluded.email, users.email)
             returning id::text, email, disabled_at is not null",
        )
        .bind(new_id())
        .bind(issuer)
        .bind(subject)
        .bind(email)
        .fetch_one(&self.pool)
        .await
        .map_err(map_err)?;
        Ok(User {
            id: row.get(0),
            issuer: issuer.into(),
            subject: subject.into(),
            email: row.get(1),
            disabled: row.get(2),
        })
    }

    async fn list_users(&self) -> Result<Vec<User>> {
        let rows = sqlx::query("select id::text, oidc_issuer, oidc_subject, email, disabled_at is not null from users order by created_at")
            .fetch_all(&self.pool)
            .await
            .map_err(map_err)?;
        Ok(rows
            .iter()
            .map(|r| User {
                id: r.get(0),
                issuer: r.get(1),
                subject: r.get(2),
                email: r.get(3),
                disabled: r.get(4),
            })
            .collect())
    }

    async fn bindings_for_user(&self, user_id: &str) -> Result<Vec<Binding>> {
        let rows = sqlx::query("select id::text, user_id::text, tenant_id::text, role from role_bindings where user_id = $1::uuid")
            .bind(user_id)
            .fetch_all(&self.pool)
            .await
            .map_err(map_err)?;
        Ok(rows.iter().filter_map(binding_from).collect())
    }

    async fn list_bindings(&self, tenant_id: Option<&str>) -> Result<Vec<Binding>> {
        let rows = sqlx::query(
            "select id::text, user_id::text, tenant_id::text, role from role_bindings
             where tenant_id is not distinct from $1::uuid order by id",
        )
        .bind(tenant_id)
        .fetch_all(&self.pool)
        .await
        .map_err(map_err)?;
        Ok(rows.iter().filter_map(binding_from).collect())
    }

    async fn bind_role(
        &self,
        user_id: &str,
        tenant_id: Option<&str>,
        role: Role,
    ) -> Result<Binding> {
        let row = sqlx::query(
            "insert into role_bindings (id, user_id, tenant_id, role) values ($1::uuid, $2::uuid, $3::uuid, $4)
             on conflict (user_id, tenant_id, role) do update set role = excluded.role
             returning id::text",
        )
        .bind(new_id())
        .bind(user_id)
        .bind(tenant_id)
        .bind(role.as_str())
        .fetch_one(&self.pool)
        .await
        .map_err(map_err)?;
        Ok(Binding {
            id: row.get(0),
            user_id: user_id.into(),
            tenant_id: tenant_id.map(Into::into),
            role,
        })
    }

    async fn unbind_role(&self, binding_id: &str) -> Result<()> {
        let n = sqlx::query("delete from role_bindings where id = $1::uuid")
            .bind(binding_id)
            .execute(&self.pool)
            .await
            .map_err(map_err)?
            .rows_affected();
        if n == 0 {
            Err(StoreError::NotFound)
        } else {
            Ok(())
        }
    }

    async fn create_api_token(
        &self,
        tenant_id: &str,
        name: &str,
        role: Role,
        expires_at: Option<i64>,
    ) -> Result<(ApiToken, String)> {
        let (secret, hash) = new_secret(PREFIX_API);
        let id = new_id();
        let mut tx = self.tenant_tx(tenant_id).await?;
        // role CHECK constraint rejects 'owner' (platform-only) => NotFound via map_err
        sqlx::query(
            "insert into api_tokens (id, tenant_id, name, role, secret_hash, expires_at)
             values ($1::uuid, $2::uuid, $3, $4, $5, to_timestamp($6::float8))",
        )
        .bind(&id)
        .bind(tenant_id)
        .bind(name)
        .bind(role.as_str())
        .bind(&hash[..])
        .bind(expires_at.map(|e| e as f64))
        .execute(&mut *tx)
        .await
        .map_err(map_err)?;
        tx.commit().await.map_err(map_err)?;
        Ok((
            ApiToken {
                id,
                tenant_id: tenant_id.into(),
                name: name.into(),
                role,
                expires_at,
                revoked: false,
            },
            secret,
        ))
    }

    async fn authenticate_api_token(&self, secret: &str, now: i64) -> Result<Option<ApiToken>> {
        if !secret.starts_with(PREFIX_API) {
            return Ok(None);
        }
        let row = sqlx::query("select id::text, tenant_id::text, name, role, expires_at from hyg_auth_api_token($1, to_timestamp($2::float8))")
            .bind(&hash_secret(secret)[..])
            .bind(now as f64)
            .fetch_optional(&self.pool)
            .await
            .map_err(map_err)?;
        Ok(row.and_then(|r| {
            Some(ApiToken {
                id: r.get(0),
                tenant_id: r.get(1),
                name: r.get(2),
                role: r.get::<String, _>(3).parse().ok()?,
                expires_at: r.get(4),
                revoked: false,
            })
        }))
    }

    async fn revoke_api_token(&self, tenant_id: &str, id: &str) -> Result<()> {
        let mut tx = self.tenant_tx(tenant_id).await?;
        let n = sqlx::query("update api_tokens set revoked_at = now() where id = $1::uuid")
            .bind(id)
            .execute(&mut *tx)
            .await
            .map_err(map_err)?
            .rows_affected();
        tx.commit().await.map_err(map_err)?;
        if n == 0 {
            Err(StoreError::NotFound)
        } else {
            Ok(())
        }
    }

    async fn list_api_tokens(&self, tenant_id: &str) -> Result<Vec<ApiToken>> {
        let mut tx = self.tenant_tx(tenant_id).await?;
        let rows = sqlx::query(
            "select id::text, tenant_id::text, name, role, extract(epoch from expires_at)::bigint, revoked_at is not null
             from api_tokens order by created_at",
        )
        .fetch_all(&mut *tx)
        .await
        .map_err(map_err)?;
        tx.commit().await.map_err(map_err)?;
        Ok(rows
            .iter()
            .filter_map(|r| {
                Some(ApiToken {
                    id: r.get(0),
                    tenant_id: r.get(1),
                    name: r.get(2),
                    role: r.get::<String, _>(3).parse().ok()?,
                    expires_at: r.get(4),
                    revoked: r.get(5),
                })
            })
            .collect())
    }

    async fn create_dns_token(
        &self,
        tenant_id: &str,
        group_id: &str,
        name: &str,
        expires_at: Option<i64>,
    ) -> Result<(DnsToken, String)> {
        let (secret, hash) = new_secret(PREFIX_DNS);
        let id = new_id();
        let mut tx = self.tenant_tx(tenant_id).await?;
        // composite FK (tenant, group) rejects a group of another tenant
        sqlx::query(
            "insert into dns_tokens (id, tenant_id, group_id, name, secret_hash, expires_at)
             values ($1::uuid, $2::uuid, $3::uuid, $4, $5, to_timestamp($6::float8))",
        )
        .bind(&id)
        .bind(tenant_id)
        .bind(group_id)
        .bind(name)
        .bind(&hash[..])
        .bind(expires_at.map(|e| e as f64))
        .execute(&mut *tx)
        .await
        .map_err(map_err)?;
        tx.commit().await.map_err(map_err)?;
        Ok((
            DnsToken {
                id,
                tenant_id: tenant_id.into(),
                group_id: group_id.into(),
                name: name.into(),
                expires_at,
                revoked: false,
            },
            secret,
        ))
    }

    async fn authenticate_dns_token(&self, secret: &str, now: i64) -> Result<Option<DnsToken>> {
        if !secret.starts_with(PREFIX_DNS) {
            return Ok(None);
        }
        let row = sqlx::query("select id::text, tenant_id::text, group_id::text, name, expires_at from hyg_auth_dns_token($1, to_timestamp($2::float8))")
            .bind(&hash_secret(secret)[..])
            .bind(now as f64)
            .fetch_optional(&self.pool)
            .await
            .map_err(map_err)?;
        Ok(row.map(|r| DnsToken {
            id: r.get(0),
            tenant_id: r.get(1),
            group_id: r.get(2),
            name: r.get(3),
            expires_at: r.get(4),
            revoked: false,
        }))
    }

    async fn revoke_dns_token(&self, tenant_id: &str, id: &str) -> Result<()> {
        let mut tx = self.tenant_tx(tenant_id).await?;
        let n = sqlx::query("update dns_tokens set revoked_at = now() where id = $1::uuid")
            .bind(id)
            .execute(&mut *tx)
            .await
            .map_err(map_err)?
            .rows_affected();
        tx.commit().await.map_err(map_err)?;
        if n == 0 {
            Err(StoreError::NotFound)
        } else {
            Ok(())
        }
    }

    async fn list_dns_tokens(&self, tenant_id: &str) -> Result<Vec<DnsToken>> {
        let mut tx = self.tenant_tx(tenant_id).await?;
        let rows = sqlx::query(
            "select id::text, tenant_id::text, group_id::text, name, extract(epoch from expires_at)::bigint, revoked_at is not null
             from dns_tokens order by created_at",
        )
        .fetch_all(&mut *tx)
        .await
        .map_err(map_err)?;
        tx.commit().await.map_err(map_err)?;
        Ok(rows
            .iter()
            .map(|r| DnsToken {
                id: r.get(0),
                tenant_id: r.get(1),
                group_id: r.get(2),
                name: r.get(3),
                expires_at: r.get(4),
                revoked: r.get(5),
            })
            .collect())
    }

    async fn append_audit(&self, draft: Draft) -> Result<()> {
        let tenant = draft.tenant_id.clone();
        let mut tx = self.tenant_tx(&tenant).await?;
        // Serialise appends per tenant so the chain head cannot fork.
        sqlx::query("select pg_advisory_xact_lock(hashtextextended($1, 0))")
            .bind(&tenant)
            .execute(&mut *tx)
            .await
            .map_err(map_err)?;
        let head = sqlx::query("select seq, hash from audit_events order by seq desc limit 1")
            .fetch_optional(&mut *tx)
            .await
            .map_err(map_err)?;
        let (seq, prev) = match head {
            Some(r) => ((r.get::<i64, _>(0) + 1) as u64, r.get::<String, _>(1)),
            None => (0, GENESIS.to_string()),
        };
        let ev = hygeia_audit::seal(seq, &prev, draft);
        let json = serde_json::to_string(&ev).map_err(|e| StoreError::Backend(e.to_string()))?;
        sqlx::query("insert into audit_events (tenant_id, seq, event, hash) values ($1::uuid, $2, $3::jsonb, $4)")
            .bind(&tenant)
            .bind(seq as i64)
            .bind(json)
            .bind(&ev.hash)
            .execute(&mut *tx)
            .await
            .map_err(map_err)?;
        tx.commit().await.map_err(map_err)
    }

    async fn list_audit(&self, tenant_id: &str, limit: u32) -> Result<Vec<Event>> {
        let mut tx = self.tenant_tx(tenant_id).await?;
        let rows = sqlx::query(
            "select event::text from (select seq, event from audit_events order by seq desc limit $1) s order by seq",
        )
        .bind(limit as i64)
        .fetch_all(&mut *tx)
        .await
        .map_err(map_err)?;
        tx.commit().await.map_err(map_err)?;
        rows.iter()
            .map(|r| {
                serde_json::from_str(&r.get::<String, _>(0))
                    .map_err(|e| StoreError::Backend(e.to_string()))
            })
            .collect()
    }

    async fn verify_audit(&self, tenant_id: &str) -> Result<AuditStatus> {
        let mut tx = self.tenant_tx(tenant_id).await?;
        let rows = sqlx::query("select event::text from audit_events order by seq")
            .fetch_all(&mut *tx)
            .await
            .map_err(map_err)?;
        tx.commit().await.map_err(map_err)?;
        let events: Vec<Event> = rows
            .iter()
            .map(|r| {
                serde_json::from_str(&r.get::<String, _>(0))
                    .map_err(|e| StoreError::Backend(e.to_string()))
            })
            .collect::<Result<_>>()?;
        hygeia_audit::verify(&events)?;
        Ok(AuditStatus {
            events: events.len() as u64,
            head: events
                .last()
                .map_or_else(|| GENESIS.to_string(), |e| e.hash.clone()),
        })
    }
}
