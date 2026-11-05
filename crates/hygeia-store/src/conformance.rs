//! Behavioural contract every [`Store`] implementation must satisfy.
//! Callers must have created tenant `a.0` with groups `a.1`, `a.2` and tenant
//! `b.0` with group `b.1` (when the backend enforces referential integrity).

use hygeia_audit::Draft;

use crate::{Rule, RuleAction, Store, StoreError};

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
    let _ = gb;

    // --- bundle versions are monotonic per (tenant, group) ---
    assert_eq!(st.next_bundle_version(ta, ga).await.unwrap(), 1);
    assert_eq!(st.next_bundle_version(ta, ga).await.unwrap(), 2);
    assert_eq!(st.next_bundle_version(ta, ga2).await.unwrap(), 1);

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
