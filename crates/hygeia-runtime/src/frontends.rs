//! Network front-ends of the cloud DNS service besides DoH: plain DNS over UDP and TCP (clients
//! identified by their registered source network) and DNS over TLS (clients identified by the SNI
//! label of a token, or by their registered network). All of them hand the attributed query to
//! `DnsService`; none of them recurses for an unidentified client (REFUSED).

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use hygeia_api::AppState;
use hygeia_api::doh::{DnsService, DohError, MAX_QUERY};
use hygeia_api::tls::TlsSource;
use hygeia_dns::{refused, truncated};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::Semaphore;

type BoxErr = Box<dyn std::error::Error + Send + Sync>;

const MAX_CONNECTIONS: usize = 2048;
const IDLE: Duration = Duration::from_secs(15);
const UDP_MAX_REPLY: usize = 1232;

fn service(state: &AppState) -> Result<Arc<DnsService>, BoxErr> {
    state
        .dns
        .clone()
        .ok_or_else(|| "the cloud DNS service is not enabled ([cloud_dns] enabled = true)".into())
}

/// Answer to send for a failed resolution, if any (`None` = stay silent).
fn failure_reply(e: &DohError, packet: &[u8]) -> Option<Vec<u8>> {
    match e {
        DohError::NotFound => Some(refused(packet)),
        DohError::RateLimited | DohError::BadRequest => None,
    }
}

pub async fn spawn_udp(state: Arc<AppState>, listen: &str) -> Result<SocketAddr, BoxErr> {
    let svc = service(&state)?;
    let sock = Arc::new(
        UdpSocket::bind(listen)
            .await
            .map_err(|e| format!("dns.udp listen {listen}: {e}"))?,
    );
    let addr = sock.local_addr()?;
    tracing::info!(listen = %addr, "cloud dns listening (udp, registered networks only)");
    tokio::spawn(async move {
        let mut buf = vec![0u8; 4096];
        loop {
            let Ok((n, peer)) = sock.recv_from(&mut buf).await else {
                continue;
            };
            let packet = buf[..n].to_vec();
            let (sock, svc, state) = (sock.clone(), svc.clone(), state.clone());
            tokio::spawn(async move {
                let reply = match svc
                    .resolve_from_network(&state, peer.ip(), "udp", &packet)
                    .await
                {
                    Ok(r) if r.len() > UDP_MAX_REPLY => Some(truncated(&packet)),
                    Ok(r) => Some(r),
                    Err(e) => failure_reply(&e, &packet),
                };
                if let Some(r) = reply.filter(|r| !r.is_empty()) {
                    let _ = sock.send_to(&r, peer).await;
                }
            });
        }
    });
    Ok(addr)
}

pub async fn spawn_tcp(state: Arc<AppState>, listen: &str) -> Result<SocketAddr, BoxErr> {
    let svc = service(&state)?;
    let l = TcpListener::bind(listen)
        .await
        .map_err(|e| format!("dns.tcp listen {listen}: {e}"))?;
    let addr = l.local_addr()?;
    tracing::info!(listen = %addr, "cloud dns listening (tcp, registered networks only)");
    let permits = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    tokio::spawn(async move {
        loop {
            let Ok((tcp, peer)) = l.accept().await else {
                continue;
            };
            let Ok(permit) = permits.clone().try_acquire_owned() else {
                continue;
            };
            let (svc, state) = (svc.clone(), state.clone());
            tokio::spawn(async move {
                let _permit = permit;
                serve_stream(&state, &svc, tcp, peer.ip(), None, "tcp").await;
            });
        }
    });
    Ok(addr)
}

/// DNS over TLS. `dot_domain` (e.g. `dns.example.com`): an SNI of `<label>.dns.example.com`
/// attributes the connection to the token with that label; anything else falls back to the
/// client's registered network.
pub async fn spawn_dot(
    state: Arc<AppState>,
    listen: &str,
    tls: Arc<TlsSource>,
    dot_domain: &str,
) -> Result<SocketAddr, BoxErr> {
    let svc = service(&state)?;
    let l = TcpListener::bind(listen)
        .await
        .map_err(|e| format!("dns.dot listen {listen}: {e}"))?;
    let addr = l.local_addr()?;
    tracing::info!(listen = %addr, "cloud dns listening (dot)");
    let suffix = format!(".{}", dot_domain.trim_matches('.').to_ascii_lowercase());
    let permits = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    tokio::spawn(async move {
        loop {
            let Ok((tcp, peer)) = l.accept().await else {
                continue;
            };
            let Ok(permit) = permits.clone().try_acquire_owned() else {
                continue;
            };
            let (svc, state, tls, suffix) =
                (svc.clone(), state.clone(), tls.clone(), suffix.clone());
            tokio::spawn(async move {
                let _permit = permit;
                let hs = async {
                    let start = tokio_rustls::LazyConfigAcceptor::new(
                        rustls::server::Acceptor::default(),
                        tcp,
                    )
                    .await?;
                    let sni = start
                        .client_hello()
                        .server_name()
                        .map(str::to_ascii_lowercase);
                    let stream = start.into_stream(tls.config()).await?;
                    Ok::<_, std::io::Error>((stream, sni))
                };
                let Ok(Ok((stream, sni))) = tokio::time::timeout(Duration::from_secs(10), hs).await
                else {
                    return;
                };
                // exactly one label in front of the DoT domain
                let label = sni
                    .as_deref()
                    .and_then(|s| s.strip_suffix(&suffix))
                    .filter(|l| !l.is_empty() && !l.contains('.'))
                    .map(str::to_string);
                serve_stream(&state, &svc, stream, peer.ip(), label, "dot").await;
            });
        }
    });
    Ok(addr)
}

/// Length-prefixed DNS over a byte stream (RFC 1035 §4.2.2, RFC 7858).
async fn serve_stream<S: AsyncRead + AsyncWrite + Unpin>(
    state: &AppState,
    svc: &DnsService,
    mut s: S,
    ip: IpAddr,
    label: Option<String>,
    transport: &'static str,
) {
    for _ in 0..10_000 {
        let mut len = [0u8; 2];
        match tokio::time::timeout(IDLE, s.read_exact(&mut len)).await {
            Ok(Ok(_)) => {}
            _ => return,
        }
        let n = u16::from_be_bytes(len) as usize;
        if n == 0 || n > MAX_QUERY {
            return;
        }
        let mut packet = vec![0u8; n];
        if !matches!(
            tokio::time::timeout(Duration::from_secs(5), s.read_exact(&mut packet)).await,
            Ok(Ok(_))
        ) {
            return;
        }
        let r = match &label {
            Some(l) => {
                svc.resolve_from_label(state, Some(l), ip, transport, &packet)
                    .await
            }
            None => {
                svc.resolve_from_network(state, ip, transport, &packet)
                    .await
            }
        };
        let reply = match r {
            Ok(r) => r,
            Err(e) => match failure_reply(&e, &packet) {
                Some(r) => r,
                None => return, // rate limited or malformed: close the connection
            },
        };
        if reply.is_empty() || reply.len() > u16::MAX as usize {
            return;
        }
        let mut out = (reply.len() as u16).to_be_bytes().to_vec();
        out.extend_from_slice(&reply);
        if s.write_all(&out).await.is_err() || s.flush().await.is_err() {
            return;
        }
    }
}

/// DNS over QUIC (RFC 9250): one query per bidirectional stream, 2-byte length prefix, ALPN `doq`.
/// Attribution as for DoT: SNI label of a token, else the client's registered network. Address
/// validation (QUIC Retry) is always on, so a spoofed source cannot use the server as a reflector.
pub async fn spawn_doq(
    state: Arc<AppState>,
    listen: &str,
    tls: Arc<TlsSource>,
    dot_domain: &str,
) -> Result<SocketAddr, BoxErr> {
    let svc = service(&state)?;
    let quic_cfg = quinn::crypto::rustls::QuicServerConfig::try_from(tls.config())
        .map_err(|e| format!("DoQ TLS configuration: {e}"))?;
    let mut server_cfg = quinn::ServerConfig::with_crypto(Arc::new(quic_cfg));
    let transport = Arc::get_mut(&mut server_cfg.transport).expect("fresh transport config");
    transport.max_concurrent_bidi_streams(100u8.into());
    transport.max_concurrent_uni_streams(0u8.into());
    transport.max_idle_timeout(Some(
        Duration::from_secs(30).try_into().expect("valid timeout"),
    ));
    let sock: SocketAddr = listen
        .parse()
        .map_err(|e| format!("dns.doq listen {listen}: {e}"))?;
    let endpoint = quinn::Endpoint::server(server_cfg, sock)
        .map_err(|e| format!("dns.doq listen {listen}: {e}"))?;
    let addr = endpoint.local_addr()?;
    tracing::info!(listen = %addr, "cloud dns listening (doq)");
    let suffix = format!(".{}", dot_domain.trim_matches('.').to_ascii_lowercase());
    let permits = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    tokio::spawn(async move {
        while let Some(incoming) = endpoint.accept().await {
            if !incoming.remote_address_validated() && incoming.may_retry() {
                let _ = incoming.retry();
                continue;
            }
            let Ok(permit) = permits.clone().try_acquire_owned() else {
                continue;
            };
            let (svc, state, suffix) = (svc.clone(), state.clone(), suffix.clone());
            tokio::spawn(async move {
                let _permit = permit;
                let Ok(connecting) = incoming.accept() else {
                    return;
                };
                let Ok(Ok(conn)) = tokio::time::timeout(Duration::from_secs(10), connecting).await
                else {
                    return;
                };
                let ip = conn.remote_address().ip();
                let sni = conn
                    .handshake_data()
                    .and_then(|h| h.downcast::<quinn::crypto::rustls::HandshakeData>().ok())
                    .and_then(|h| h.server_name.clone())
                    .map(|s| s.to_ascii_lowercase());
                let label = sni
                    .as_deref()
                    .and_then(|s| s.strip_suffix(&suffix))
                    .filter(|l| !l.is_empty() && !l.contains('.'))
                    .map(str::to_string);
                while let Ok((mut send, mut recv)) = conn.accept_bi().await {
                    let (svc, state, label) = (svc.clone(), state.clone(), label.clone());
                    tokio::spawn(async move {
                        let Ok(Ok(buf)) = tokio::time::timeout(
                            Duration::from_secs(5),
                            recv.read_to_end(MAX_QUERY + 2),
                        )
                        .await
                        else {
                            return;
                        };
                        if buf.len() < 2
                            || u16::from_be_bytes([buf[0], buf[1]]) as usize != buf.len() - 2
                        {
                            return;
                        }
                        let packet = &buf[2..];
                        let r = match &label {
                            Some(l) => {
                                svc.resolve_from_label(&state, Some(l), ip, "doq", packet)
                                    .await
                            }
                            None => svc.resolve_from_network(&state, ip, "doq", packet).await,
                        };
                        let reply = match r {
                            Ok(r) => r,
                            Err(e) => match failure_reply(&e, packet) {
                                Some(r) => r,
                                None => return,
                            },
                        };
                        if reply.is_empty() || reply.len() > u16::MAX as usize {
                            return;
                        }
                        let mut out = (reply.len() as u16).to_be_bytes().to_vec();
                        out.extend_from_slice(&reply);
                        if send.write_all(&out).await.is_ok() {
                            let _ = send.finish();
                            // let the client read the reply before the stream is dropped
                            let _ =
                                tokio::time::timeout(Duration::from_secs(2), send.stopped()).await;
                        }
                    });
                }
            });
        }
    });
    Ok(addr)
}
