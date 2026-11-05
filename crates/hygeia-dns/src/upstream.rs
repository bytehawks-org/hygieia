//! Upstream recursive resolvers with failover: plain UDP, DNS-over-TLS (RFC 7858) and
//! DNS-over-HTTPS (RFC 8484).
//!
//! Spec strings (config): `udp://9.9.9.9:53` (or bare `9.9.9.9:53`), `tls://9.9.9.9:853#dns.quad9.net`
//! (the part after `#` is the TLS server name; for a hostname it defaults to the host),
//! `https://dns.quad9.net/dns-query`.
//!
//! Failover: upstreams are tried in order; one that fails twice in a row is skipped for 30 s (if all
//! are down they are all tried anyway). A reply is accepted only if it parses and carries the id of
//! the query. DoT keeps one idle connection per upstream for reuse.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use hickory_proto::op::Message;
use rustls::pki_types::{CertificateDer, ServerName, pem::PemObject};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;

const DOWN_FOR: Duration = Duration::from_secs(30);
const MAX_REPLY: usize = 65_535;

#[derive(Debug, thiserror::Error)]
pub enum UpstreamError {
    #[error("invalid upstream {0:?}: {1}")]
    Spec(String, String),
    #[error("all upstreams failed: {0}")]
    AllFailed(String),
    #[error("{0}")]
    Io(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Kind {
    Udp(SocketAddr),
    /// `host:port` is resolved at connect time; `name` is the TLS server name.
    Dot {
        host: String,
        port: u16,
        name: String,
    },
    Doh {
        url: String,
    },
}

type IdleConn = Mutex<Option<TlsStream<TcpStream>>>;

struct Upstream {
    kind: Kind,
    fails: Mutex<(u32, Option<Instant>)>,
    idle: IdleConn,
}

impl std::fmt::Debug for UpstreamPool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UpstreamPool")
            .field("upstreams", &self.kinds())
            .finish()
    }
}

pub struct UpstreamPool {
    ups: Vec<Upstream>,
    timeout: Duration,
    tls: Arc<rustls::ClientConfig>,
    http: reqwest::Client,
    allow_insecure_http: bool,
}

pub fn parse_spec(spec: &str) -> Result<Kind, UpstreamError> {
    let bad = |m: &str| UpstreamError::Spec(spec.to_string(), m.to_string());
    if let Some(rest) = spec.strip_prefix("tls://") {
        let (hostport, name) = match rest.split_once('#') {
            Some((h, n)) => (h, Some(n.to_string())),
            None => (rest, None),
        };
        let (host, port) = match hostport.rsplit_once(':') {
            Some((h, p))
                if !h.ends_with(':') && p.chars().all(|c| c.is_ascii_digit()) && !p.is_empty() =>
            {
                (
                    h.trim_matches(['[', ']']).to_string(),
                    p.parse().map_err(|_| bad("bad port"))?,
                )
            }
            _ => (hostport.trim_matches(['[', ']']).to_string(), 853),
        };
        if host.is_empty() {
            return Err(bad("missing host"));
        }
        let is_ip = host.parse::<std::net::IpAddr>().is_ok();
        let name = name.unwrap_or_else(|| host.clone());
        if is_ip && name == host {
            return Err(bad(
                "an IP address needs the server name: tls://IP:853#dns.example.com",
            ));
        }
        return Ok(Kind::Dot { host, port, name });
    }
    if spec.starts_with("https://") || spec.starts_with("http://") {
        return Ok(Kind::Doh {
            url: spec.to_string(),
        });
    }
    let addr = spec.strip_prefix("udp://").unwrap_or(spec);
    addr.parse::<SocketAddr>()
        .map(Kind::Udp)
        .map_err(|e| bad(&e.to_string()))
}

impl UpstreamPool {
    pub fn new(specs: &[String], timeout: Duration) -> Result<Self, UpstreamError> {
        Self::build(specs, timeout, None, false)
    }

    /// For tests and private PKI: trust these PEM certificates in addition to the public roots,
    /// and optionally allow `http://` DoH upstreams.
    pub fn with_options(
        specs: &[String],
        timeout: Duration,
        extra_root_pem: Option<&[u8]>,
        allow_insecure_http: bool,
    ) -> Result<Self, UpstreamError> {
        Self::build(specs, timeout, extra_root_pem, allow_insecure_http)
    }

    fn build(
        specs: &[String],
        timeout: Duration,
        extra_root_pem: Option<&[u8]>,
        allow_insecure_http: bool,
    ) -> Result<Self, UpstreamError> {
        if specs.is_empty() {
            return Err(UpstreamError::Spec(
                String::new(),
                "at least one upstream is required".into(),
            ));
        }
        let mut ups = Vec::new();
        for s in specs {
            let kind = parse_spec(s)?;
            if let Kind::Doh { url } = &kind
                && url.starts_with("http://")
                && !allow_insecure_http
            {
                return Err(UpstreamError::Spec(
                    s.clone(),
                    "DoH upstreams must use https://".into(),
                ));
            }
            ups.push(Upstream {
                kind,
                fails: Mutex::new((0, None)),
                idle: Mutex::new(None),
            });
        }
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        if let Some(pem) = extra_root_pem {
            for c in CertificateDer::pem_slice_iter(pem) {
                roots
                    .add(c.map_err(|e| UpstreamError::Io(e.to_string()))?)
                    .map_err(|e| UpstreamError::Io(e.to_string()))?;
            }
        }
        let tls = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .map_err(|e| UpstreamError::Io(e.to_string()))?
        .with_root_certificates(roots)
        .with_no_client_auth();
        let mut hb = reqwest::Client::builder()
            .timeout(timeout)
            .redirect(reqwest::redirect::Policy::none());
        if let Some(pem) = extra_root_pem {
            for c in reqwest::Certificate::from_pem_bundle(pem)
                .map_err(|e| UpstreamError::Io(e.to_string()))?
            {
                hb = hb.add_root_certificate(c);
            }
        }
        Ok(Self {
            ups,
            timeout,
            tls: Arc::new(tls),
            http: hb.build().map_err(|e| UpstreamError::Io(e.to_string()))?,
            allow_insecure_http,
        })
    }

    pub fn kinds(&self) -> Vec<Kind> {
        self.ups.iter().map(|u| u.kind.clone()).collect()
    }

    fn is_down(u: &Upstream) -> bool {
        u.fails
            .lock()
            .unwrap()
            .1
            .is_some_and(|t| t > Instant::now())
    }

    /// Send one query; returns the first valid reply, failing over in order.
    pub async fn forward(&self, packet: &[u8]) -> Result<Vec<u8>, UpstreamError> {
        let id = packet
            .get(..2)
            .map(|b| u16::from_be_bytes([b[0], b[1]]))
            .ok_or_else(|| UpstreamError::Io("query too short".into()))?;
        let healthy: Vec<&Upstream> = self.ups.iter().filter(|u| !Self::is_down(u)).collect();
        let order: Vec<&Upstream> = if healthy.is_empty() {
            self.ups.iter().collect()
        } else {
            healthy
        };
        let mut errors = Vec::new();
        for u in order {
            match self.try_one(u, packet, id).await {
                Ok(reply) => {
                    *u.fails.lock().unwrap() = (0, None);
                    return Ok(reply);
                }
                Err(e) => {
                    let mut f = u.fails.lock().unwrap();
                    f.0 += 1;
                    if f.0 >= 2 {
                        f.1 = Some(Instant::now() + DOWN_FOR);
                    }
                    errors.push(format!("{:?}: {e}", u.kind));
                }
            }
        }
        Err(UpstreamError::AllFailed(errors.join("; ")))
    }

    async fn try_one(
        &self,
        u: &Upstream,
        packet: &[u8],
        id: u16,
    ) -> Result<Vec<u8>, UpstreamError> {
        let fut = async {
            match &u.kind {
                Kind::Udp(a) => udp(*a, packet, self.timeout).await,
                Kind::Dot { host, port, name } => self.dot(u, host, *port, name, packet).await,
                Kind::Doh { url } => self.doh(url, packet).await,
            }
        };
        let reply = tokio::time::timeout(self.timeout, fut)
            .await
            .map_err(|_| UpstreamError::Io("timeout".into()))??;
        match Message::from_vec(&reply) {
            Ok(m) if m.metadata.id == id => Ok(reply),
            Ok(_) => Err(UpstreamError::Io(
                "reply id does not match the query".into(),
            )),
            Err(e) => Err(UpstreamError::Io(format!("unparseable reply: {e}"))),
        }
    }

    async fn dial(
        &self,
        host: &str,
        port: u16,
        name: &str,
    ) -> Result<TlsStream<TcpStream>, UpstreamError> {
        let io = |e: std::io::Error| UpstreamError::Io(e.to_string());
        let tcp = TcpStream::connect((host, port)).await.map_err(io)?;
        let _ = tcp.set_nodelay(true);
        let sn =
            ServerName::try_from(name.to_string()).map_err(|e| UpstreamError::Io(e.to_string()))?;
        TlsConnector::from(self.tls.clone())
            .connect(sn, tcp)
            .await
            .map_err(io)
    }

    async fn dot(
        &self,
        u: &Upstream,
        host: &str,
        port: u16,
        name: &str,
        packet: &[u8],
    ) -> Result<Vec<u8>, UpstreamError> {
        // Reuse the idle connection once; a stale one (closed by the peer) falls back to a fresh dial.
        let cached = u.idle.lock().unwrap().take();
        if let Some(mut c) = cached
            && let Ok(r) = dot_exchange(&mut c, packet).await
        {
            *u.idle.lock().unwrap() = Some(c);
            return Ok(r);
        }
        let mut c = self.dial(host, port, name).await?;
        let r = dot_exchange(&mut c, packet).await?;
        *u.idle.lock().unwrap() = Some(c);
        Ok(r)
    }

    async fn doh(&self, url: &str, packet: &[u8]) -> Result<Vec<u8>, UpstreamError> {
        debug_assert!(self.allow_insecure_http || url.starts_with("https://"));
        let resp = self
            .http
            .post(url)
            .header("content-type", "application/dns-message")
            .header("accept", "application/dns-message")
            .body(packet.to_vec())
            .send()
            .await
            .map_err(|e| UpstreamError::Io(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(UpstreamError::Io(format!("HTTP {}", resp.status())));
        }
        let b = resp
            .bytes()
            .await
            .map_err(|e| UpstreamError::Io(e.to_string()))?;
        if b.len() > MAX_REPLY {
            return Err(UpstreamError::Io("reply too large".into()));
        }
        Ok(b.to_vec())
    }
}

async fn udp(addr: SocketAddr, packet: &[u8], timeout: Duration) -> Result<Vec<u8>, UpstreamError> {
    crate::forward_udp(packet, addr, timeout)
        .await
        .map_err(|e| UpstreamError::Io(e.to_string()))
}

async fn dot_exchange(
    c: &mut TlsStream<TcpStream>,
    packet: &[u8],
) -> Result<Vec<u8>, UpstreamError> {
    let io = |e: std::io::Error| UpstreamError::Io(e.to_string());
    let mut out = Vec::with_capacity(packet.len() + 2);
    out.extend_from_slice(&(packet.len() as u16).to_be_bytes());
    out.extend_from_slice(packet);
    c.write_all(&out).await.map_err(io)?;
    c.flush().await.map_err(io)?;
    let mut len = [0u8; 2];
    c.read_exact(&mut len).await.map_err(io)?;
    let mut buf = vec![0u8; u16::from_be_bytes(len) as usize];
    c.read_exact(&mut buf).await.map_err(io)?;
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::op::Query;
    use hickory_proto::rr::{Name, RecordType};
    use std::str::FromStr;
    use tokio::net::{TcpListener, UdpSocket};

    fn query(id: u16) -> Vec<u8> {
        let mut m = Message::query();
        m.metadata.id = id;
        m.add_query(Query::query(
            Name::from_str("example.org.").unwrap(),
            RecordType::A,
        ));
        m.to_vec().unwrap()
    }

    fn as_reply(q: &[u8]) -> Vec<u8> {
        let mut r = q.to_vec();
        r[2] |= 0x80;
        r
    }

    #[test]
    fn spec_parsing() {
        assert_eq!(
            parse_spec("9.9.9.9:53").unwrap(),
            Kind::Udp("9.9.9.9:53".parse().unwrap())
        );
        assert_eq!(
            parse_spec("udp://[2620:fe::fe]:53").unwrap(),
            Kind::Udp("[2620:fe::fe]:53".parse().unwrap())
        );
        assert_eq!(
            parse_spec("tls://9.9.9.9:853#dns.quad9.net").unwrap(),
            Kind::Dot {
                host: "9.9.9.9".into(),
                port: 853,
                name: "dns.quad9.net".into()
            }
        );
        assert_eq!(
            parse_spec("tls://dns.quad9.net").unwrap(),
            Kind::Dot {
                host: "dns.quad9.net".into(),
                port: 853,
                name: "dns.quad9.net".into()
            }
        );
        assert!(
            parse_spec("tls://9.9.9.9").is_err(),
            "an IP without a server name cannot be verified"
        );
        assert_eq!(
            parse_spec("https://dns.quad9.net/dns-query").unwrap(),
            Kind::Doh {
                url: "https://dns.quad9.net/dns-query".into()
            }
        );
        for bad in ["", "nonsense", "udp://x", "tls://#x"] {
            assert!(parse_spec(bad).is_err(), "{bad}");
        }
        assert!(
            UpstreamPool::new(&["http://x/dns".into()], Duration::from_secs(1)).is_err(),
            "plain-http DoH refused"
        );
        assert!(UpstreamPool::new(&[], Duration::from_secs(1)).is_err());
    }

    async fn udp_server(good: bool) -> SocketAddr {
        let s = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let a = s.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            while let Ok((n, peer)) = s.recv_from(&mut buf).await {
                let mut r = as_reply(&buf[..n]);
                if !good {
                    r[0] ^= 0xff; // wrong id: must be rejected
                }
                let _ = s.send_to(&r, peer).await;
            }
        });
        a
    }

    #[tokio::test]
    async fn udp_failover_skips_dead_and_forged_upstreams() {
        let dead: SocketAddr = {
            let s = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            s.local_addr().unwrap() // closed when dropped: ICMP unreachable
        };
        let forged = udp_server(false).await;
        let good = udp_server(true).await;
        let pool = UpstreamPool::new(
            &[dead.to_string(), forged.to_string(), good.to_string()],
            Duration::from_millis(800),
        )
        .unwrap();
        let q = query(0x1234);
        for _ in 0..4 {
            let r = pool.forward(&q).await.unwrap();
            assert_eq!(&r[..2], &[0x12, 0x34]);
        }
        // everything dead -> a clear error
        let none = UpstreamPool::new(&[dead.to_string()], Duration::from_millis(300)).unwrap();
        assert!(matches!(
            none.forward(&q).await,
            Err(UpstreamError::AllFailed(_))
        ));
    }

    fn cert() -> (String, String) {
        let ck = rcgen::generate_simple_self_signed(vec!["dns.test".to_string()]).unwrap();
        (ck.cert.pem(), ck.signing_key.serialize_pem())
    }

    #[tokio::test]
    async fn dot_verifies_the_server_name_and_reuses_the_connection() {
        let (cert_pem, key_pem) = cert();
        let certs: Vec<CertificateDer<'static>> =
            CertificateDer::pem_slice_iter(cert_pem.as_bytes())
                .map(|c| c.unwrap())
                .collect();
        let key = rustls::pki_types::PrivateKeyDer::from_pem_slice(key_pem.as_bytes()).unwrap();
        let cfg = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(cfg));
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        let accepted = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let acc = accepted.clone();
        tokio::spawn(async move {
            while let Ok((tcp, _)) = l.accept().await {
                let a = acceptor.clone();
                acc.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                tokio::spawn(async move {
                    let Ok(mut tls) = a.accept(tcp).await else {
                        return;
                    };
                    loop {
                        let mut len = [0u8; 2];
                        if tls.read_exact(&mut len).await.is_err() {
                            return;
                        }
                        let mut b = vec![0u8; u16::from_be_bytes(len) as usize];
                        if tls.read_exact(&mut b).await.is_err() {
                            return;
                        }
                        let r = as_reply(&b);
                        let mut out = (r.len() as u16).to_be_bytes().to_vec();
                        out.extend_from_slice(&r);
                        if tls.write_all(&out).await.is_err() {
                            return;
                        }
                    }
                });
            }
        });

        let ok = UpstreamPool::with_options(
            &[format!("tls://127.0.0.1:{port}#dns.test")],
            Duration::from_secs(3),
            Some(cert_pem.as_bytes()),
            false,
        )
        .unwrap();
        for i in 0..3u16 {
            let r = ok.forward(&query(100 + i)).await.unwrap();
            assert_eq!(u16::from_be_bytes([r[0], r[1]]), 100 + i);
        }
        assert_eq!(
            accepted.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "one TLS connection serves sequential queries"
        );

        // wrong server name: the certificate must not verify
        let wrong = UpstreamPool::with_options(
            &[format!("tls://127.0.0.1:{port}#evil.test")],
            Duration::from_secs(3),
            Some(cert_pem.as_bytes()),
            false,
        )
        .unwrap();
        assert!(
            wrong.forward(&query(1)).await.is_err(),
            "name mismatch is refused"
        );
        // untrusted certificate (no extra root): refused
        let untrusted = UpstreamPool::new(
            &[format!("tls://127.0.0.1:{port}#dns.test")],
            Duration::from_secs(3),
        )
        .unwrap();
        assert!(
            untrusted.forward(&query(2)).await.is_err(),
            "unknown CA is refused"
        );
    }

    #[tokio::test]
    async fn doh_upstream_and_failover_from_a_dead_dot_server() {
        // a minimal HTTP/1.1 DoH server
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        tokio::spawn(async move {
            while let Ok((mut s, _)) = l.accept().await {
                tokio::spawn(async move {
                    let mut buf = Vec::new();
                    let mut tmp = [0u8; 2048];
                    let (hdr_end, clen) = loop {
                        let n = s.read(&mut tmp).await.unwrap_or(0);
                        if n == 0 {
                            return;
                        }
                        buf.extend_from_slice(&tmp[..n]);
                        if let Some(p) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                            let head = String::from_utf8_lossy(&buf[..p]).to_ascii_lowercase();
                            let cl = head
                                .lines()
                                .find_map(|l| l.strip_prefix("content-length: "))
                                .and_then(|v| v.trim().parse::<usize>().ok())
                                .unwrap_or(0);
                            break (p + 4, cl);
                        }
                    };
                    while buf.len() < hdr_end + clen {
                        let n = s.read(&mut tmp).await.unwrap_or(0);
                        if n == 0 {
                            return;
                        }
                        buf.extend_from_slice(&tmp[..n]);
                    }
                    let body = as_reply(&buf[hdr_end..hdr_end + clen]);
                    let head = format!(
                        "HTTP/1.1 200 OK\r\ncontent-type: application/dns-message\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                        body.len()
                    );
                    let _ = s.write_all(head.as_bytes()).await;
                    let _ = s.write_all(&body).await;
                });
            }
        });
        let dead_dot = {
            let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
            l.local_addr().unwrap().port() // closed when dropped
        };
        let pool = UpstreamPool::with_options(
            &[
                format!("tls://127.0.0.1:{dead_dot}#dns.test"),
                format!("http://127.0.0.1:{port}/dns-query"),
            ],
            Duration::from_secs(2),
            None,
            true,
        )
        .unwrap();
        let r = pool.forward(&query(77)).await.unwrap();
        assert_eq!(u16::from_be_bytes([r[0], r[1]]), 77);
    }
}
