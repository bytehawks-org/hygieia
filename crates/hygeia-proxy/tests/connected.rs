//! Connected mode end to end: a real central API (in memory) and a real node in front of it.

use std::path::PathBuf;
use std::sync::Arc;

use hygeia_api::{AppState, AuthConfig, LocalOwner};
use hygeia_core::SignedBundle;
use hygeia_proxy::config::Config;
use hygeia_proxy::paths::Paths;
use hygeia_proxy::{read_owner_token, start};
use hygeia_store::{MemoryStore, Store};
use serde_json::{Value, json};

fn tmp() -> PathBuf {
    let d = std::env::temp_dir().join(format!(
        "hygeia-conn-{}-{}",
        std::process::id(),
        hygeia_runtime::rand_hex(4)
    ));
    std::fs::create_dir_all(&d).unwrap();
    d
}

struct Central {
    base: String,
    admin: String,
    key_hex: String,
    state: Arc<AppState>,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    task: tokio::task::JoinHandle<std::io::Result<()>>,
}

impl Central {
    async fn start() -> Self {
        let store: Arc<dyn Store> = Arc::new(MemoryStore::new());
        store.bootstrap_default().await.unwrap();
        let mut seed = [0u8; 32];
        getrandom::fill(&mut seed).unwrap();
        let sk = ed25519_dalek::SigningKey::from_bytes(&seed);
        let key_hex: String = sk
            .verifying_key()
            .to_bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        let admin = format!("hyg_own_{}", hygeia_runtime::rand_hex(24));
        let auth = AuthConfig {
            local_owner: Some(LocalOwner::new(&admin).unwrap()),
            break_glass: None,
            oidc: None,
        };
        let state = Arc::new(AppState::new(store, sk, auth));
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", l.local_addr().unwrap());
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        let app = hygeia_api::router(state.clone());
        let task = tokio::spawn(hygeia_api::serve(l, app, async move {
            let _ = rx.await;
        }));
        Self {
            base,
            admin,
            key_hex,
            state,
            stop: Some(tx),
            task,
        }
    }

    async fn stop(&mut self) {
        let _ = self.stop.take().unwrap().send(());
        let _ = (&mut self.task).await;
    }
}

fn node_cfg(up: &str, key: &str) -> Config {
    toml::from_str(&format!(
        "mode = \"connected\"\n[http]\nlisten = \"127.0.0.1:0\"\n[upstream]\nurl = \"{up}\"\npublic_key = \"{key}\"\nallow_insecure_http = true\ntimeout_secs = 2\n"
    ))
    .unwrap()
}

async fn enroll_via(http: &reqwest::Client, c: &Central, node: &str) -> (String, String) {
    let tok: Value = http
        .post(format!("{}/v1/admin/enrollment-tokens", c.base))
        .bearer_auth(&c.admin)
        .json(&json!({}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let r = http
        .post(format!("{node}/v1/enroll"))
        .header("origin", "chrome-extension://abc")
        .json(&json!({"token": tok["token"], "device_info": "browser"}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    let j: Value = r.json().await.unwrap();
    (
        j["device_id"].as_str().unwrap().into(),
        j["device_secret"].as_str().unwrap().into(),
    )
}

fn vk(hex: &str) -> ed25519_dalek::VerifyingKey {
    let mut raw = [0u8; 32];
    for (i, c) in hex.as_bytes().chunks(2).enumerate() {
        raw[i] = u8::from_str_radix(std::str::from_utf8(c).unwrap(), 16).unwrap();
    }
    ed25519_dalek::VerifyingKey::from_bytes(&raw).unwrap()
}

#[tokio::test]
async fn relay_cache_offline_revocation_and_pinning() {
    let http = reqwest::Client::new();
    let mut central = Central::start().await;
    let r = http
        .post(format!("{}/v1/admin/rules", central.base))
        .bearer_auth(&central.admin)
        .json(&json!({"action": "block", "pattern": "ads.example.com"}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 201);

    let dir = tmp();
    let paths = Paths::new(dir.clone());
    let node = start(node_cfg(&central.base, &central.key_hex), paths.clone())
        .await
        .unwrap();
    let nb = format!("http://{}", node.http_addr);
    assert!(
        node.state.is_none(),
        "no embedded control plane in connected mode"
    );

    // the extension pins the CENTRAL key, served by the node
    assert_eq!(
        http.get(format!("{nb}/v1/pubkey"))
            .send()
            .await
            .unwrap()
            .text()
            .await
            .unwrap(),
        central.key_hex
    );
    // no local admin surface
    assert_eq!(
        http.get(format!("{nb}/v1/admin/rules"))
            .send()
            .await
            .unwrap()
            .status(),
        404
    );

    // enrolment is relayed: the device exists centrally, vouched for by this node
    let (dev_id, secret) = enroll_via(&http, &central, &nb).await;
    let devs: Value = http
        .get(format!("{}/v1/admin/devices", central.base))
        .bearer_auth(&central.admin)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(devs.to_string().contains(&dev_id));
    let audit: Value = http
        .get(format!("{}/v1/admin/audit", central.base))
        .bearer_auth(&central.admin)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(audit.to_string().contains("via_node"), "{audit}");
    assert_eq!(
        http.post(format!("{nb}/v1/enroll"))
            .json(&json!({"token":"hyg_enr_bogus","device_info":""}))
            .send()
            .await
            .unwrap()
            .status(),
        401
    );

    // bundle: central signature preserved, ETag/304 works through the node
    let r = http
        .get(format!("{nb}/v1/bundle"))
        .bearer_auth(&secret)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    assert!(r.headers().get("x-hygeia-stale").is_none());
    let etag = r.headers()["etag"].to_str().unwrap().to_string();
    let bytes = r.bytes().await.unwrap().to_vec();
    let b = SignedBundle::open(&bytes, &vk(&central.key_hex)).expect("signed by central");
    assert_eq!(b.meta.version, 1);
    let r = http
        .get(format!("{nb}/v1/bundle"))
        .bearer_auth(&secret)
        .header("if-none-match", &etag)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 304);
    assert_eq!(
        http.get(format!("{nb}/v1/bundle"))
            .send()
            .await
            .unwrap()
            .status(),
        401
    );
    assert_eq!(
        http.get(format!("{nb}/v1/bundle"))
            .bearer_auth("hyg_dev_nope")
            .send()
            .await
            .unwrap()
            .status(),
        401
    );

    // status needs the local credential
    let owner = read_owner_token(&paths).unwrap();
    assert_eq!(
        http.get(format!("{nb}/v1/node/status"))
            .send()
            .await
            .unwrap()
            .status(),
        401
    );
    let st: Value = http
        .get(format!("{nb}/v1/node/status"))
        .bearer_auth(&owner)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(st["known_devices"], 1);

    // revocation: reaches the browser through the node while central is reachable
    let (rev_id, rev_secret) = enroll_via(&http, &central, &nb).await;
    assert_eq!(
        http.get(format!("{nb}/v1/bundle"))
            .bearer_auth(&rev_secret)
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    let r = http
        .delete(format!("{}/v1/admin/devices/{rev_id}", central.base))
        .bearer_auth(&central.admin)
        .send()
        .await
        .unwrap();
    assert!(r.status().is_success());
    assert_eq!(
        http.get(format!("{nb}/v1/bundle"))
            .bearer_auth(&rev_secret)
            .send()
            .await
            .unwrap()
            .status(),
        401
    );

    // central down: the known device keeps getting the cached, verified bundle (flagged stale)
    central.stop().await;
    let r = http
        .get(format!("{nb}/v1/bundle"))
        .bearer_auth(&secret)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    assert_eq!(r.headers()["x-hygeia-stale"], "1");
    assert_eq!(r.bytes().await.unwrap().to_vec(), bytes);
    // ... but not the revoked one, nor an unknown credential, nor enrolment
    assert_ne!(
        http.get(format!("{nb}/v1/bundle"))
            .bearer_auth(&rev_secret)
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    assert_ne!(
        http.get(format!("{nb}/v1/bundle"))
            .bearer_auth("hyg_dev_unknown")
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    assert_eq!(
        http.post(format!("{nb}/v1/enroll"))
            .json(&json!({"token":"x","device_info":""}))
            .send()
            .await
            .unwrap()
            .status(),
        502
    );

    // restart the node while central is still down: state and cache survive
    node.stop().await.unwrap();
    let node = start(node_cfg(&central.base, &central.key_hex), paths.clone())
        .await
        .unwrap();
    let nb = format!("http://{}", node.http_addr);
    let r = http
        .get(format!("{nb}/v1/bundle"))
        .bearer_auth(&secret)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    assert_eq!(r.bytes().await.unwrap().to_vec(), bytes);

    // a tampered cache is not served
    for f in std::fs::read_dir(&paths.bundle_cache).unwrap() {
        let p = f.unwrap().path();
        let mut b = std::fs::read(&p).unwrap();
        let n = b.len();
        b[n / 2] ^= 0xff;
        std::fs::write(&p, b).unwrap();
    }
    assert_ne!(
        http.get(format!("{nb}/v1/bundle"))
            .bearer_auth(&secret)
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    node.stop().await.unwrap();
    let _ = std::fs::remove_dir_all(dir);
    let _ = &central.state;
}

#[tokio::test]
async fn wrong_pinned_key_never_serves_central_bundles() {
    let http = reqwest::Client::new();
    let mut central = Central::start().await;
    let good = start(node_cfg(&central.base, &central.key_hex), Paths::new(tmp()))
        .await
        .unwrap();
    let gb = format!("http://{}", good.http_addr);
    let (_, secret) = enroll_via(&http, &central, &gb).await;

    let other = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
    let wrong: String = other
        .verifying_key()
        .to_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let bad = start(node_cfg(&central.base, &wrong), Paths::new(tmp()))
        .await
        .unwrap();
    let bb = format!("http://{}", bad.http_addr);
    let r = http
        .get(format!("{bb}/v1/bundle"))
        .bearer_auth(&secret)
        .send()
        .await
        .unwrap();
    assert_eq!(
        r.status(),
        502,
        "unverifiable bundle must not reach the browser"
    );
    good.stop().await.unwrap();
    bad.stop().await.unwrap();
    central.stop().await;
}
