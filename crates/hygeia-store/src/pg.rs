//! PostgreSQL implementation. Every tenant-scoped statement runs in a
//! transaction that first sets `app.tenant` (SET LOCAL semantics), so row
//! level security enforces isolation even if a query forgets `tenant_id`.

use async_trait::async_trait;
use hygeia_audit::{Draft, Event, GENESIS};
use sqlx::postgres::{PgPool, PgPoolOptions};
use sqlx::{Postgres, Row, Transaction};

use crate::{
    AuditStatus, DEFAULT_GROUP_ID, DEFAULT_TENANT_ID, Device, EnrollmentToken, PREFIX_DEVICE,
    PREFIX_ENROLL, Result, Rule, RuleAction, Store, StoreError, hash_secret, new_id, new_secret,
};

#[derive(Clone)]
pub struct PgStore {
    pool: PgPool,
}

fn map_err(e: sqlx::Error) -> StoreError {
    if let sqlx::Error::Database(d) = &e {
        // invalid uuid text, FK violation, check violation: caller-supplied ids that don't resolve
        if matches!(d.code().as_deref(), Some("22P02" | "23503" | "23514")) {
            return StoreError::NotFound;
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

    pub async fn create_tenant(&self, slug: &str, name: &str) -> Result<String> {
        let id = new_id();
        sqlx::query("insert into tenants (id, slug, name) values ($1::uuid, $2, $3)")
            .bind(&id)
            .bind(slug)
            .bind(name)
            .execute(&self.pool)
            .await
            .map_err(map_err)?;
        Ok(id)
    }

    pub async fn create_group(&self, tenant_id: &str, name: &str) -> Result<String> {
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
        Ok(id)
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
