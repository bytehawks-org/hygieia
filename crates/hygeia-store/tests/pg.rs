//! PostgreSQL integration tests. Skipped unless both are set:
//!   HYGEIA_TEST_PG_ADMIN = postgres://<schema-owner>@host:5432        (no db name; needs CREATEDB)
//!   HYGEIA_TEST_PG_APP   = postgres://hygeia_app:<pw>@host:5432       (runtime role, non-owner)
//! The role `hygeia_app` must exist before migrations run (grants are conditional on it).

use hygeia_store::{PgStore, Store, conformance};
use sqlx::{Connection, PgConnection, Row};

struct Env {
    admin_db: String,
    app_db: String,
}

async fn setup() -> Option<Env> {
    let admin = std::env::var("HYGEIA_TEST_PG_ADMIN").ok()?;
    let app = std::env::var("HYGEIA_TEST_PG_APP").ok()?;
    let name = format!("hygeia_t_{}", &hygeia_store::new_id()[..8]);
    let mut c = PgConnection::connect(&format!("{admin}/postgres"))
        .await
        .unwrap();
    // `name` is hex we generated: safe to interpolate.
    sqlx::query(sqlx::AssertSqlSafe(format!("create database {name}")))
        .execute(&mut c)
        .await
        .unwrap();
    let admin_db = format!("{admin}/{name}");
    PgStore::migrate(&admin_db).await.unwrap();
    Some(Env {
        admin_db,
        app_db: format!("{app}/{name}"),
    })
}

#[tokio::test]
async fn pg_store_conformance() {
    let Some(env) = setup().await else {
        eprintln!("skipped: HYGEIA_TEST_PG_* not set");
        return;
    };
    let st = PgStore::connect(&env.app_db).await.unwrap();
    let ta = st.create_tenant("a", "A").await.unwrap();
    let tb = st.create_tenant("b", "B").await.unwrap();
    let ga = st.create_group(&ta, "g1").await.unwrap();
    let ga2 = st.create_group(&ta, "g2").await.unwrap();
    let gb = st.create_group(&tb, "g1").await.unwrap();
    conformance::run(&st, (&ta, &ga, &ga2), (&tb, &gb)).await;

    // cross-tenant group reference is rejected by the composite FK
    let (_, secret) = st
        .create_enrollment_token(&ta, &ga, 60, None, 0)
        .await
        .unwrap();
    assert!(st.enroll(&secret, "x", 1).await.is_ok());
    assert!(
        st.create_enrollment_token(&ta, &gb, 60, None, 0)
            .await
            .is_err()
    );

    st.bootstrap_default().await.unwrap();
    st.bootstrap_default().await.unwrap(); // idempotent
}

#[tokio::test]
async fn pg_rls_and_audit_immutability() {
    let Some(env) = setup().await else { return };
    let st = PgStore::connect(&env.app_db).await.unwrap();
    let ta = st.create_tenant("a", "A").await.unwrap();
    let tb = st.create_tenant("b", "B").await.unwrap();
    let ga = st.create_group(&ta, "g").await.unwrap();
    let gb = st.create_group(&tb, "g").await.unwrap();
    for (t, g) in [(&ta, &ga), (&tb, &gb)] {
        st.add_rule(hygeia_store::Rule {
            id: String::new(),
            tenant_id: t.clone(),
            group_id: Some(g.clone()),
            action: hygeia_store::RuleAction::Block,
            pattern: "x.test".into(),
            comment: String::new(),
        })
        .await
        .unwrap();
        st.append_audit(hygeia_audit::Draft {
            ts: 1,
            tenant_id: t.clone(),
            actor: "t".into(),
            action: "a.b".into(),
            target: "x".into(),
            diff: None,
        })
        .await
        .unwrap();
    }

    // Raw connection as the runtime role, bypassing all store code.
    let mut c = PgConnection::connect(&env.app_db).await.unwrap();
    let n: i64 = sqlx::query("select count(*) from rules")
        .fetch_one(&mut c)
        .await
        .unwrap()
        .get(0);
    assert_eq!(n, 0, "no tenant set => no rows");

    let mut tx = c.begin().await.unwrap();
    sqlx::query("select set_config('app.tenant', $1, true)")
        .bind(&ta)
        .execute(&mut *tx)
        .await
        .unwrap();
    let n: i64 = sqlx::query("select count(*) from rules")
        .fetch_one(&mut *tx)
        .await
        .unwrap()
        .get(0);
    assert_eq!(n, 1, "only own tenant rows, even without WHERE");
    // writing a row for another tenant violates the policy
    let r = sqlx::query("insert into rules (id, tenant_id, action, pattern) values (gen_random_uuid(), $1::uuid, 'block', 'z.test')")
        .bind(&tb).execute(&mut *tx).await;
    assert!(r.is_err());
    tx.rollback().await.unwrap();

    // audit is append-only for the runtime role AND for the owner (trigger)
    let r = sqlx::query("update audit_events set hash = 'x'")
        .execute(&mut c)
        .await;
    assert!(r.is_err());
    let mut o = PgConnection::connect(&env.admin_db).await.unwrap();
    assert!(
        sqlx::query("delete from audit_events")
            .execute(&mut o)
            .await
            .is_err()
    );
    assert!(
        sqlx::query("truncate audit_events")
            .execute(&mut o)
            .await
            .is_err()
    );

    // credential tables are not readable directly without a tenant
    let n: i64 = sqlx::query("select count(*) from device_credentials")
        .fetch_one(&mut c)
        .await
        .unwrap()
        .get(0);
    assert_eq!(n, 0);
}
