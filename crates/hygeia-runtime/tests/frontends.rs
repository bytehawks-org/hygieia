//! Plain UDP/TCP and DNS over TLS front-ends of the cloud DNS service, over real sockets.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use hygeia_api::doh::{DnsService, DnsServiceConfig};
use hygeia_api::tls::TlsSource;
use hygeia_api::{AppState, AuthConfig, DEFAULT_GROUP, DEFAULT_TENANT};
use hygeia_runtime::frontends;
use hygeia_store::{MemoryStore, Rule, RuleAction, Store};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

fn query(name: &str) -> Vec<u8> {
    let mut q = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
    for l in name.split('.') {
        q.push(l.len() as u8);
        q.extend_from_slice(l.as_bytes());
    }
    q.extend_from_slice(&[0, 0, 1, 0, 1]);
    q
}

async fn fake_upstream() -> SocketAddr {
    let s = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = s.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = [0u8; 512];
        while let Ok((n, peer)) = s.recv_from(&mut buf).await {
            let mut r = buf[..n].to_vec();
            r[2] |= 0x80;
            let _ = s.send_to(&r, peer).await;
        }
    });
    addr
}

async fn state() -> Arc<AppState> {
    let store: Arc<dyn Store> = Arc::new(MemoryStore::new());
    store.bootstrap_default().await.unwrap();
    store
        .add_rule(Rule {
            id: String::new(),
            tenant_id: DEFAULT_TENANT.into(),
            group_id: None,
            action: RuleAction::Block,
            pattern: "ads.example.com".into(),
            comment: String::new(),
        })
        .await
        .unwrap();
    let mut st = AppState::new(
        store,
        ed25519_dalek::SigningKey::from_bytes(&[5; 32]),
        AuthConfig::default(),
    );
    let svc = Arc::new(DnsService::new(DnsServiceConfig::new(
        fake_upstream().await,
    )));
    st.dns = Some(svc);
    Arc::new(st)
}

fn rcode(reply: &[u8]) -> u8 {
    reply[3] & 0x0f
}

async fn udp_ask(server: SocketAddr, from: &str, q: &[u8]) -> Option<Vec<u8>> {
    let c = UdpSocket::bind(format!("{from}:0")).await.unwrap();
    c.send_to(q, server).await.unwrap();
    let mut buf = [0u8; 2048];
    match tokio::time::timeout(Duration::from_secs(2), c.recv_from(&mut buf)).await {
        Ok(Ok((n, _))) => Some(buf[..n].to_vec()),
        _ => None,
    }
}

async fn framed<S: AsyncReadExt + AsyncWriteExt + Unpin>(s: &mut S, q: &[u8]) -> Option<Vec<u8>> {
    let mut out = (q.len() as u16).to_be_bytes().to_vec();
    out.extend_from_slice(q);
    s.write_all(&out).await.ok()?;
    let mut len = [0u8; 2];
    tokio::time::timeout(Duration::from_secs(2), s.read_exact(&mut len))
        .await
        .ok()?
        .ok()?;
    let mut b = vec![0u8; u16::from_be_bytes(len) as usize];
    s.read_exact(&mut b).await.ok()?;
    Some(b)
}

#[tokio::test]
async fn plain_udp_and_tcp_serve_registered_networks_and_refuse_everyone_else() {
    let st = state().await;
    st.store
        .add_dns_network(DEFAULT_TENANT, DEFAULT_GROUP, "lo", "127.0.0.1/32")
        .await
        .unwrap();
    let svc = st.dns.clone().unwrap();
    svc.refresh_networks(st.store.as_ref()).await;
    let udp = frontends::spawn_udp(st.clone(), "127.0.0.1:0")
        .await
        .unwrap();
    let tcp = frontends::spawn_tcp(st.clone(), "127.0.0.1:0")
        .await
        .unwrap();

    // registered (127.0.0.1): blocked name -> NXDOMAIN, other -> forwarded
    assert_eq!(
        rcode(
            &udp_ask(udp, "127.0.0.1", &query("x.ads.example.com"))
                .await
                .unwrap()
        ),
        3
    );
    assert_eq!(
        rcode(
            &udp_ask(udp, "127.0.0.1", &query("example.org"))
                .await
                .unwrap()
        ),
        0
    );
    // unregistered (127.0.0.2): REFUSED, header only, never larger than the query
    let q = query("example.org");
    let r = udp_ask(udp, "127.0.0.2", &q).await.unwrap();
    assert_eq!((rcode(&r), r.len()), (5, 12));
    assert!(r.len() <= q.len(), "no amplification");

    let mut ok = TcpStream::connect(tcp).await.unwrap();
    assert_eq!(
        rcode(&framed(&mut ok, &query("ads.example.com")).await.unwrap()),
        3
    );
    assert_eq!(
        rcode(&framed(&mut ok, &query("example.org")).await.unwrap()),
        0,
        "several queries on one connection"
    );
    let sock = tokio::net::TcpSocket::new_v4().unwrap();
    sock.bind("127.0.0.2:0".parse().unwrap()).unwrap();
    let mut stranger = sock.connect(tcp).await.unwrap();
    assert_eq!(
        rcode(&framed(&mut stranger, &query("example.org")).await.unwrap()),
        5
    );

    // an oversized frame closes the connection instead of being processed
    let mut bad = TcpStream::connect(tcp).await.unwrap();
    bad.write_all(&[0xff, 0xff]).await.unwrap();
    let mut b = [0u8; 1];
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(2), bad.read(&mut b))
            .await
            .unwrap()
            .unwrap(),
        0
    );

    // after the registration is deleted the same client is refused
    let n = st
        .store
        .list_dns_networks(DEFAULT_TENANT)
        .await
        .unwrap()
        .remove(0);
    st.store
        .delete_dns_network(DEFAULT_TENANT, &n.id)
        .await
        .unwrap();
    svc.refresh_networks(st.store.as_ref()).await;
    assert_eq!(rcode(&udp_ask(udp, "127.0.0.1", &q).await.unwrap()), 5);
}

#[tokio::test]
async fn dot_attributes_by_sni_label_or_registered_network() {
    let st = state().await;
    let svc = st.dns.clone().unwrap();
    let (tok, _) = st
        .store
        .create_dns_token(DEFAULT_TENANT, DEFAULT_GROUP, "dot", None, true)
        .await
        .unwrap();
    let label = tok.dot_label.clone().unwrap();
    st.store
        .add_dns_network(DEFAULT_TENANT, DEFAULT_GROUP, "lo", "127.0.0.1/32")
        .await
        .unwrap();
    svc.refresh_networks(st.store.as_ref()).await;

    let dir = std::env::temp_dir().join(format!("hyg-dot-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let ck = rcgen::generate_simple_self_signed(vec!["*.dns.test".to_string()]).unwrap();
    let (c, k) = (dir.join("c.pem"), dir.join("k.pem"));
    std::fs::write(&c, ck.cert.pem()).unwrap();
    std::fs::write(&k, ck.signing_key.serialize_pem()).unwrap();
    let tls = TlsSource::load(&c, &k, &["dot"]).unwrap();
    let addr = frontends::spawn_dot(st.clone(), "127.0.0.1:0", tls, "dns.test")
        .await
        .unwrap();

    let mut roots = rustls::RootCertStore::empty();
    for cert in
        <rustls::pki_types::CertificateDer as rustls::pki_types::pem::PemObject>::pem_slice_iter(
            ck.cert.pem().as_bytes(),
        )
    {
        roots.add(cert.unwrap()).unwrap();
    }
    let cfg = Arc::new(
        rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth(),
    );
    let connect = |from: &'static str, sni: String| {
        let cfg = cfg.clone();
        async move {
            let sock = tokio::net::TcpSocket::new_v4().unwrap();
            sock.bind(format!("{from}:0").parse().unwrap()).unwrap();
            let tcp = sock.connect(addr).await.unwrap();
            tokio_rustls::TlsConnector::from(cfg)
                .connect(rustls::pki_types::ServerName::try_from(sni).unwrap(), tcp)
                .await
                .unwrap()
        }
    };

    // an unregistered client (127.0.0.2) with the token's label: attributed, filtered
    let mut s = connect("127.0.0.2", format!("{label}.dns.test")).await;
    assert_eq!(
        rcode(&framed(&mut s, &query("ads.example.com")).await.unwrap()),
        3
    );
    assert_eq!(
        rcode(&framed(&mut s, &query("example.org")).await.unwrap()),
        0
    );
    // unknown label from an unregistered client: refused
    let mut s = connect("127.0.0.2", "nope.dns.test".into()).await;
    assert_eq!(
        rcode(&framed(&mut s, &query("example.org")).await.unwrap()),
        5
    );
    // unknown label from a registered client: served by its network
    let mut s = connect("127.0.0.1", "nope.dns.test".into()).await;
    assert_eq!(
        rcode(&framed(&mut s, &query("ads.example.com")).await.unwrap()),
        3
    );
    // a revoked token's label stops working once the lookup cache is cleared
    st.store
        .revoke_dns_token(DEFAULT_TENANT, &tok.id)
        .await
        .unwrap();
    svc.clear_auth_cache();
    let mut s = connect("127.0.0.2", format!("{label}.dns.test")).await;
    assert_eq!(
        rcode(&framed(&mut s, &query("example.org")).await.unwrap()),
        5
    );
    let _ = std::fs::remove_dir_all(dir);
}
