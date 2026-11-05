//! The node, in process: real listener, real file-backed state, real HTTP.

use std::path::PathBuf;
use std::time::Duration;

use hygeia_core::SignedBundle;
use hygeia_proxy::config::{Config, DnsMode};
use hygeia_proxy::paths::Paths;
use hygeia_proxy::{read_owner_token, read_public_key, start};
use serde_json::json;

fn tmp() -> PathBuf {
    let d = std::env::temp_dir().join(format!(
        "hygeia-node-{}-{}",
        std::process::id(),
        hygeia_runtime::rand_hex(4)
    ));
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn cfg(extra: &str) -> Config {
    let mut c: Config = toml::from_str(&format!(
        "[http]\nlisten = \"127.0.0.1:0\"\n[lists]\nenabled = false\n{extra}"
    ))
    .unwrap();
    c.lists.enabled = false;
    c
}

fn pubkey_bytes(hex: &str) -> ed25519_dalek::VerifyingKey {
    let mut raw = [0u8; 32];
    for (i, c) in hex.as_bytes().chunks(2).enumerate() {
        raw[i] = u8::from_str_radix(std::str::from_utf8(c).unwrap(), 16).unwrap();
    }
    ed25519_dalek::VerifyingKey::from_bytes(&raw).unwrap()
}

#[tokio::test]
async fn standalone_flow_security_and_persistence() {
    let dir = tmp();
    let paths = Paths::new(dir.clone());
    let http = reqwest::Client::new();

    let node = start(cfg(""), paths.clone()).await.unwrap();
    let base = format!("http://{}", node.http_addr);
    assert!(
        node.dns_addr.is_none(),
        "DNS is opt-in: nothing listens by default"
    );
    let owner = read_owner_token(&paths).unwrap();
    let pubkey = read_public_key(&paths).unwrap();
    let auth = |t: &str| format!("Bearer {t}");

    // identity: the local owner, nobody else
    let me: serde_json::Value = http
        .get(format!("{base}/v1/me"))
        .header("authorization", auth(&owner))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(me["kind"], "local_owner");
    let cfgj: serde_json::Value = http
        .get(format!("{base}/v1/config"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(cfgj["mode"], "standalone");
    assert_eq!(
        http.get(format!("{base}/v1/me"))
            .header("authorization", auth("hyg_own_wrong"))
            .send()
            .await
            .unwrap()
            .status(),
        401
    );
    assert_eq!(
        http.get(format!("{base}/v1/admin/rules"))
            .send()
            .await
            .unwrap()
            .status(),
        401
    );

    // DNS-rebinding style request: right socket, hostile Host header
    let r = http
        .get(format!("{base}/v1/config"))
        .header("host", "evil.example")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 421);
    // cross-site POST to the admin API
    let r = http
        .post(format!("{base}/v1/admin/rules"))
        .header("authorization", auth(&owner))
        .header("origin", "https://evil.example")
        .json(&json!({"action": "block", "pattern": "x.test"}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 403);

    // admin creates a rule and an enrolment token; "the extension" enrols and pulls the bundle
    let r = http
        .post(format!("{base}/v1/admin/rules"))
        .header("authorization", auth(&owner))
        .json(&json!({"action": "block", "pattern": "ads.example.com"}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 201);
    let tok: serde_json::Value = http
        .post(format!("{base}/v1/admin/enrollment-tokens"))
        .header("authorization", auth(&owner))
        .json(&json!({}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let enrolled: serde_json::Value = http
        .post(format!("{base}/v1/enroll"))
        .header("origin", "chrome-extension://abcdef")
        .json(&json!({"token": tok["token"], "device_info": "test"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let dev = enrolled["device_secret"].as_str().unwrap().to_string();

    let resp = http
        .get(format!("{base}/v1/bundle"))
        .header("authorization", auth(&dev))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let bytes = resp.bytes().await.unwrap();
    let bundle = SignedBundle::open(&bytes, &pubkey_bytes(&pubkey))
        .expect("signed with the key the extension pins");
    assert_eq!(bundle.network.custom_block, vec!["ads.example.com"]);
    let v1 = bundle.meta.version;
    node.stop().await.unwrap();

    // ---- restart: same key, same credentials, same data, monotonic versions
    let node = start(cfg(""), paths.clone()).await.unwrap();
    let base = format!("http://{}", node.http_addr);
    assert_eq!(read_owner_token(&paths).unwrap(), owner);
    assert_eq!(
        read_public_key(&paths).unwrap(),
        pubkey,
        "the pinned key must survive restarts"
    );
    let resp = http
        .get(format!("{base}/v1/bundle"))
        .header("authorization", auth(&dev))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "device credential survives restart");
    let bundle = SignedBundle::open(&resp.bytes().await.unwrap(), &pubkey_bytes(&pubkey)).unwrap();
    assert_eq!(bundle.network.custom_block, vec!["ads.example.com"]);
    assert!(
        bundle.meta.version > v1,
        "bundle versions never go backwards (extension rollback guard)"
    );
    let audit: serde_json::Value = http
        .get(format!("{base}/v1/admin/audit/verify"))
        .header("authorization", auth(&owner))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(audit["ok"], true);
    node.stop().await.unwrap();

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for f in [&paths.signing_key, &paths.owner_token, &paths.state] {
            assert_eq!(
                std::fs::metadata(f).unwrap().permissions().mode() & 0o777,
                0o600,
                "{}",
                f.display()
            );
        }
        assert_eq!(
            std::fs::metadata(&paths.dir).unwrap().permissions().mode() & 0o777,
            0o700
        );
    }
}

#[tokio::test]
async fn refuses_lan_exposure_by_default_and_damaged_state() {
    let dir = tmp();
    let mut c = cfg("");
    c.http.listen = "0.0.0.0:0".into();
    assert!(
        start(c, Paths::new(dir.clone()))
            .await
            .err()
            .unwrap()
            .to_string()
            .contains("allow_lan")
    );

    // a damaged state file stops the node and is left untouched
    let paths = Paths::new(dir);
    std::fs::write(&paths.state, "{ garbage").unwrap();
    let err = start(cfg(""), paths.clone())
        .await
        .err()
        .unwrap()
        .to_string();
    assert!(err.contains("not a valid state file"), "{err}");
    assert_eq!(std::fs::read_to_string(&paths.state).unwrap(), "{ garbage");
}

fn dns_query(name: &str) -> Vec<u8> {
    let mut p = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
    for l in name.split('.') {
        p.push(l.len() as u8);
        p.extend_from_slice(l.as_bytes());
    }
    p.extend_from_slice(&[0, 0, 1, 0, 1]);
    p
}

#[tokio::test]
async fn local_dns_is_opt_in_and_enforces_the_nodes_rules() {
    let dir = tmp();
    let mut c = cfg("");
    c.dns.mode = DnsMode::Local;
    c.dns.listen = "127.0.0.1:0".into();
    c.dns.upstream = vec!["127.0.0.1:9".into()]; // never reached for blocked names
    let paths = Paths::new(dir);
    let node = start(c, paths.clone()).await.unwrap();
    let dns = node.dns_addr.expect("dns.mode = local opens a listener");
    let owner = read_owner_token(&paths).unwrap();
    let http = reqwest::Client::new();
    let r = http
        .post(format!("http://{}/v1/admin/rules", node.http_addr))
        .header("authorization", format!("Bearer {owner}"))
        .json(&json!({"action": "block", "pattern": "ads.example.com"}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 201);

    let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut rcode = None;
    for _ in 0..30 {
        sock.send_to(&dns_query("x.ads.example.com"), dns)
            .await
            .unwrap();
        let mut buf = [0u8; 512];
        if let Ok(Ok((n, _))) =
            tokio::time::timeout(Duration::from_millis(500), sock.recv_from(&mut buf)).await
            && n > 3
            && buf[3] & 0xf == 3
        {
            rcode = Some(3);
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    assert_eq!(
        rcode,
        Some(3),
        "NXDOMAIN once the follower picked up the rule"
    );
    node.stop().await.unwrap();
}
