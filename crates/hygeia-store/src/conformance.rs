//! Behavioural contract every [`Store`] implementation must satisfy.
//! Callers must have created tenant `a.0` with groups `a.1`, `a.2` and tenant
//! `b.0` with group `b.1` (when the backend enforces referential integrity).

use hygeia_audit::Draft;

use crate::rbac::Role;
use crate::{
    CatalogSource, ListPolicy, Rule, RuleAction, Selection, Store, StoreError, StoredBundle,
    Subscription,
};

fn draft(tenant: &str, n: i64) -> Draft {
    Draft {
        ts: n,
        tenant_id: tenant.into(),
        actor: "test".into(),
        action: "x.y".into(),
        target: format!("n{n}"),
        diff: Some(serde_json::json!({"n": n})),
    }
}

pub async fn run(st: &dyn Store, a: (&str, &str, &str), b: (&str, &str)) {
    let (ta, ga, ga2) = a;
    let (tb, gb) = b;

    // --- enrollment flow ---
    let (tok, secret) = st
        .create_enrollment_token(ta, ga, 60, Some(1), 100)
        .await
        .unwrap();
    let (dev, dsecret) = st.enroll(&secret, "chrome", 110).await.unwrap();
    assert_eq!((dev.tenant_id.as_str(), dev.group_id.as_str()), (ta, ga));
    assert_eq!(
        st.enroll(&secret, "x", 111).await,
        Err(StoreError::InvalidToken),
        "max_uses"
    );
    let authed = st
        .authenticate_device(&dsecret, 120)
        .await
        .unwrap()
        .expect("device auth");
    assert_eq!(authed.id, dev.id);
    assert!(
        st.authenticate_device(&secret, 0).await.unwrap().is_none(),
        "enrollment secret is not a device secret"
    );
    assert!(
        st.authenticate_device("hyg_dev_nope", 0)
            .await
            .unwrap()
            .is_none()
    );

    // wrong tenant cannot revoke
    assert_eq!(
        st.revoke_device(tb, &dev.id).await,
        Err(StoreError::NotFound)
    );
    assert_eq!(st.list_devices(tb).await.unwrap().len(), 0);
    assert_eq!(st.list_devices(ta).await.unwrap().len(), 1);
    st.revoke_device(ta, &dev.id).await.unwrap();
    assert!(
        st.authenticate_device(&dsecret, 121)
            .await
            .unwrap()
            .is_none()
    );

    // expiry and revocation of enrollment tokens
    let (_, s1) = st
        .create_enrollment_token(ta, ga, 10, None, 0)
        .await
        .unwrap();
    assert!(st.enroll(&s1, "", 10).await.is_err(), "expired");
    let (t2, s2) = st
        .create_enrollment_token(ta, ga, 10, None, 0)
        .await
        .unwrap();
    assert_eq!(
        st.revoke_enrollment_token(tb, &t2.id).await,
        Err(StoreError::NotFound)
    );
    st.revoke_enrollment_token(ta, &t2.id).await.unwrap();
    assert!(st.enroll(&s2, "", 1).await.is_err(), "revoked");
    let _ = tok;

    // --- rules: scoping ---
    let mk = |t: &str, g: Option<&str>| Rule {
        id: String::new(),
        tenant_id: t.into(),
        group_id: g.map(Into::into),
        action: RuleAction::Block,
        pattern: "a.test".into(),
        comment: String::new(),
    };
    let r_all = st.add_rule(mk(ta, None)).await.unwrap();
    st.add_rule(mk(ta, Some(ga))).await.unwrap();
    st.add_rule(mk(ta, Some(ga2))).await.unwrap();
    st.add_rule(mk(tb, None)).await.unwrap();
    assert_eq!(st.rules_for(ta, ga).await.unwrap().len(), 2);
    assert_eq!(st.list_rules(ta).await.unwrap().len(), 3);
    assert_eq!(st.list_rules(tb).await.unwrap().len(), 1);
    assert_eq!(
        st.delete_rule(tb, &r_all.id).await.map(|_| ()),
        Err(StoreError::NotFound)
    );
    st.delete_rule(ta, &r_all.id).await.unwrap();
    assert_eq!(st.list_rules(ta).await.unwrap().len(), 2);
    let _ = &gb;

    // --- bundle versions are monotonic per (tenant, group) ---
    assert_eq!(st.next_bundle_version(ta, ga).await.unwrap(), 1);
    assert_eq!(st.next_bundle_version(ta, ga).await.unwrap(), 2);
    assert_eq!(st.next_bundle_version(ta, ga2).await.unwrap(), 1);

    // --- compiled bundles: shared, first writer of an input set wins, versions only go up ---
    assert!(st.load_compiled(ta, ga).await.unwrap().is_none());
    let sb = |h: &str, v: u64, b: &[u8]| StoredBundle {
        inputs_hash: h.into(),
        version: v,
        bytes: b.to_vec(),
    };
    assert_eq!(
        st.store_compiled(ta, ga, sb("h1", 3, b"one"))
            .await
            .unwrap(),
        sb("h1", 3, b"one")
    );
    assert_eq!(
        st.store_compiled(ta, ga, sb("h1", 4, b"dup"))
            .await
            .unwrap(),
        sb("h1", 3, b"one"),
        "same inputs: the stored bundle wins"
    );
    assert_eq!(
        st.store_compiled(ta, ga, sb("h2", 2, b"old"))
            .await
            .unwrap(),
        sb("h1", 3, b"one"),
        "a lower version never replaces a higher one"
    );
    assert_eq!(
        st.store_compiled(ta, ga, sb("h2", 5, b"two"))
            .await
            .unwrap(),
        sb("h2", 5, b"two")
    );
    assert_eq!(
        st.load_compiled(ta, ga).await.unwrap(),
        Some(sb("h2", 5, b"two"))
    );
    assert!(st.load_compiled(ta, ga2).await.unwrap().is_none());
    assert!(
        st.load_compiled(tb, gb).await.unwrap().is_none(),
        "tenant isolation"
    );
    st.ping().await.unwrap();

    // --- audit: one chain per tenant ---
    for n in 0..5 {
        st.append_audit(draft(ta, n)).await.unwrap();
    }
    st.append_audit(draft(tb, 0)).await.unwrap();
    let sa = st.verify_audit(ta).await.unwrap();
    let sb = st.verify_audit(tb).await.unwrap();
    assert_eq!((sa.events, sb.events), (5, 1));
    assert_ne!(sa.head, sb.head);
    let last3 = st.list_audit(ta, 3).await.unwrap();
    assert_eq!(last3.len(), 3);
    assert_eq!(last3[0].seq, 2);
    assert!(last3.iter().all(|e| e.draft.tenant_id == ta));
}

/// Tenants, groups, users, role bindings and API tokens. Creates its own tenants.
pub async fn run_identity(st: &dyn Store) {
    let a = st.create_tenant("acme", "Acme").await.unwrap();
    let b = st.create_tenant("beta", "Beta").await.unwrap();
    assert_eq!(
        st.create_tenant("acme", "dup").await.map(|_| ()),
        Err(StoreError::Conflict)
    );
    assert!(st.list_tenants().await.unwrap().len() >= 2);

    let g = st.create_group(&a.id, "staff").await.unwrap();
    assert_eq!(
        st.create_group(&a.id, "staff").await.map(|_| ()),
        Err(StoreError::Conflict)
    );
    st.create_group(&b.id, "staff").await.unwrap(); // same name in another tenant is fine
    assert_eq!(st.list_groups(&a.id).await.unwrap(), vec![g]);

    // users: idempotent upsert keyed by (issuer, subject); no implicit roles
    let u1 = st
        .upsert_user("https://idp.example.com", "sub-1", Some("a@example.com"))
        .await
        .unwrap();
    let u1b = st
        .upsert_user("https://idp.example.com", "sub-1", None)
        .await
        .unwrap();
    assert_eq!(u1.id, u1b.id);
    assert_eq!(
        u1b.email.as_deref(),
        Some("a@example.com"),
        "missing claim must not erase the email"
    );
    let u2 = st
        .upsert_user("https://other-idp.example.com", "sub-1", None)
        .await
        .unwrap();
    assert_ne!(
        u1.id, u2.id,
        "same subject at another issuer is another user"
    );
    assert!(st.bindings_for_user(&u1.id).await.unwrap().is_empty());

    // bindings: tenant-scoped and platform-wide, idempotent
    let b1 = st
        .bind_role(&u1.id, Some(&a.id), Role::Editor)
        .await
        .unwrap();
    assert_eq!(
        st.bind_role(&u1.id, Some(&a.id), Role::Editor)
            .await
            .unwrap()
            .id,
        b1.id
    );
    st.bind_role(&u1.id, None, Role::Auditor).await.unwrap();
    assert_eq!(st.bindings_for_user(&u1.id).await.unwrap().len(), 2);
    assert_eq!(st.list_bindings(Some(&a.id)).await.unwrap().len(), 1);
    assert_eq!(st.list_bindings(Some(&b.id)).await.unwrap().len(), 0);
    assert!(
        st.list_bindings(None)
            .await
            .unwrap()
            .iter()
            .all(|x| x.tenant_id.is_none())
    );
    assert_eq!(
        st.bind_role("00000000-0000-0000-0000-0000000000ff", None, Role::Viewer)
            .await
            .map(|_| ()),
        Err(StoreError::NotFound)
    );
    st.unbind_role(&b1.id).await.unwrap();
    assert_eq!(st.unbind_role(&b1.id).await, Err(StoreError::NotFound));

    // API tokens
    let (t, secret) = st
        .create_api_token(&a.id, "ci", Role::Editor, Some(1000))
        .await
        .unwrap();
    assert!(secret.starts_with("hyg_api_"));
    let got = st
        .authenticate_api_token(&secret, 500)
        .await
        .unwrap()
        .expect("valid token");
    assert_eq!(
        (got.tenant_id.as_str(), got.role),
        (a.id.as_str(), Role::Editor)
    );
    assert!(
        st.authenticate_api_token(&secret, 1000)
            .await
            .unwrap()
            .is_none(),
        "expired"
    );
    assert!(
        st.authenticate_api_token("hyg_api_nope", 0)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        st.authenticate_api_token("hyg_dev_whatever", 0)
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(
        st.revoke_api_token(&b.id, &t.id).await,
        Err(StoreError::NotFound),
        "other tenant cannot revoke"
    );
    assert_eq!(st.list_api_tokens(&b.id).await.unwrap().len(), 0);
    st.revoke_api_token(&a.id, &t.id).await.unwrap();
    assert!(
        st.authenticate_api_token(&secret, 500)
            .await
            .unwrap()
            .is_none()
    );
    assert!(st.list_api_tokens(&a.id).await.unwrap()[0].revoked);
    assert!(
        st.create_api_token(&a.id, "x", Role::Owner, None)
            .await
            .is_err(),
        "owner is platform-only"
    );
}

fn src(id: &str) -> CatalogSource {
    CatalogSource {
        id: id.into(),
        name: format!("List {id}"),
        url: format!("https://example.com/{id}.txt"),
        license: "CC0-1.0".into(),
        attribution: "test".into(),
    }
}

/// Per-tenant filter-list selection. Creates its own tenants and groups.
pub async fn run_lists(st: &dyn Store) {
    st.sync_catalog(&[src("a"), src("b"), src("c")])
        .await
        .unwrap();
    st.sync_catalog(&[src("a"), src("b"), src("c")])
        .await
        .unwrap(); // idempotent
    let t1 = st.create_tenant("lists-one", "One").await.unwrap();
    let t2 = st.create_tenant("lists-two", "Two").await.unwrap();
    let g1 = st.create_group(&t1.id, "kids").await.unwrap();
    let g2 = st.create_group(&t1.id, "staff").await.unwrap();
    let other_group = st.create_group(&t2.id, "x").await.unwrap();

    // default: every platform-enabled source
    assert_eq!(st.list_policy(&t1.id).await.unwrap(), ListPolicy::All);
    assert_eq!(st.selection(&t1.id, &g1.id).await.unwrap(), Selection::All);

    st.set_list_policy(&t1.id, ListPolicy::Selected)
        .await
        .unwrap();
    assert_eq!(
        st.selection(&t1.id, &g1.id).await.unwrap(),
        Selection::Only(vec![]),
        "selected + nothing = nothing"
    );
    assert_eq!(
        st.list_policy(&t2.id).await.unwrap(),
        ListPolicy::All,
        "other tenant unaffected"
    );

    st.subscribe(&t1.id, None, "a").await.unwrap();
    st.subscribe(&t1.id, None, "a").await.unwrap(); // idempotent
    st.subscribe(&t1.id, Some(&g1.id), "b").await.unwrap();
    assert_eq!(
        st.selection(&t1.id, &g1.id).await.unwrap(),
        Selection::Only(vec!["a".into(), "b".into()])
    );
    assert_eq!(
        st.selection(&t1.id, &g2.id).await.unwrap(),
        Selection::Only(vec!["a".into()]),
        "group list does not leak to other groups"
    );
    assert_eq!(st.subscriptions(&t1.id).await.unwrap().len(), 2);
    assert!(st.subscriptions(&t2.id).await.unwrap().is_empty());
    assert!(
        st.subscriptions(&t1.id)
            .await
            .unwrap()
            .contains(&Subscription {
                group_id: Some(g1.id.clone()),
                source_id: "b".into()
            })
    );

    // integrity: unknown source / foreign group / unknown tenant
    assert_eq!(
        st.subscribe(&t1.id, None, "nope").await,
        Err(StoreError::NotFound)
    );
    assert_eq!(
        st.subscribe(&t1.id, Some(&other_group.id), "a").await,
        Err(StoreError::NotFound),
        "group of another tenant"
    );
    assert_eq!(
        st.set_list_policy("00000000-0000-0000-0000-0000000000fe", ListPolicy::All)
            .await,
        Err(StoreError::NotFound)
    );

    st.unsubscribe(&t1.id, Some(&g1.id), "b").await.unwrap();
    assert_eq!(
        st.unsubscribe(&t1.id, Some(&g1.id), "b").await,
        Err(StoreError::NotFound)
    );
    assert_eq!(
        st.selection(&t1.id, &g1.id).await.unwrap(),
        Selection::Only(vec!["a".into()])
    );
    assert_eq!(
        st.unsubscribe(&t2.id, None, "a").await,
        Err(StoreError::NotFound),
        "cannot remove another tenant's subscription"
    );

    st.set_list_policy(&t1.id, ListPolicy::All).await.unwrap();
    assert_eq!(st.selection(&t1.id, &g1.id).await.unwrap(), Selection::All);
}
