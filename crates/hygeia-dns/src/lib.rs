//! DNS data plane. The decision logic ([`decide`]) is a pure function over
//! wire bytes; [`serve_udp`] wraps it with a socket loop and upstream forwarding.
//!
//! Not yet implemented: TCP, DoT/DoH/DoQ listeners, DoT upstream, per-client
//! tenant resolution, query-log sink. See the project roadmap in README.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use hickory_proto::op::{Message, OpCode, ResponseCode};
use hickory_proto::rr::rdata::{A, AAAA};
use hickory_proto::rr::{RData, Record, RecordType};
use hygeia_core::{Ruleset, Verdict};
use tokio::net::UdpSocket;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum BlockMode {
    /// Answer `NXDOMAIN`.
    #[default]
    NxDomain,
    /// Answer `0.0.0.0` / `::` for A/AAAA, empty NOERROR otherwise.
    NullIp,
}

#[derive(Debug)]
pub enum Decision {
    /// Reply directly with these bytes (blocked or malformed).
    Answer(Vec<u8>),
    /// Allowed: forward the original packet upstream.
    Forward,
}

/// Evaluate one DNS query packet. Returns the decision and, when a question
/// was parsed, the `(qname, verdict)` pair for logging.
pub fn decide(
    rs: &Ruleset,
    packet: &[u8],
    mode: BlockMode,
) -> (Decision, Option<(String, Verdict)>) {
    let Ok(req) = Message::from_vec(packet) else {
        // Unparseable: cannot even build a valid reply without an id.
        return (Decision::Answer(Vec::new()), None);
    };
    if req.metadata.op_code != OpCode::Query || req.queries.len() != 1 {
        let r = Message::error_msg(req.metadata.id, req.metadata.op_code, ResponseCode::NotImp);
        return (Decision::Answer(r.to_vec().unwrap_or_default()), None);
    }
    let q = &req.queries[0];
    let host = q.name().to_ascii();
    let verdict = rs.evaluate(&host);
    if !verdict.is_block() {
        return (Decision::Forward, Some((host, verdict)));
    }

    let mut resp = Message::response(req.metadata.id, req.metadata.op_code);
    resp.metadata.recursion_desired = req.metadata.recursion_desired;
    resp.metadata.recursion_available = true;
    resp.add_query(q.clone());
    match mode {
        BlockMode::NxDomain => resp.metadata.response_code = ResponseCode::NXDomain,
        BlockMode::NullIp => {
            let rdata = match q.query_type() {
                RecordType::A => Some(RData::A(A(Ipv4Addr::UNSPECIFIED))),
                RecordType::AAAA => Some(RData::AAAA(AAAA(Ipv6Addr::UNSPECIFIED))),
                _ => None,
            };
            if let Some(rd) = rdata {
                resp.add_answer(Record::from_rdata(q.name().clone(), 60, rd));
            }
        }
    }
    (
        Decision::Answer(resp.to_vec().unwrap_or_default()),
        Some((host, verdict)),
    )
}

pub struct DnsConfig {
    pub upstream: SocketAddr,
    pub block_mode: BlockMode,
    pub upstream_timeout: Duration,
}

/// Run a UDP DNS server until the task is dropped. The ruleset is read
/// lock-free per query; publish new bundles with `rules.store(Arc::new(..))`.
pub async fn serve_udp(
    sock: UdpSocket,
    rules: Arc<ArcSwap<Ruleset>>,
    cfg: Arc<DnsConfig>,
) -> std::io::Result<()> {
    let sock = Arc::new(sock);
    let mut buf = vec![0u8; 4096];
    loop {
        let (n, peer) = sock.recv_from(&mut buf).await?;
        let packet = buf[..n].to_vec();
        let (sock, rules, cfg) = (sock.clone(), rules.clone(), cfg.clone());
        tokio::spawn(async move {
            let (decision, logged) = decide(&rules.load(), &packet, cfg.block_mode);
            if let Some((host, v)) = &logged {
                tracing::debug!(%peer, %host, action = ?v.action, reason = ?v.reason, "query");
            }
            let reply = match decision {
                Decision::Answer(b) if b.is_empty() => return,
                Decision::Answer(b) => b,
                Decision::Forward => match forward(&packet, &cfg).await {
                    Ok(b) => b,
                    Err(e) => {
                        tracing::warn!(error = %e, "upstream failure");
                        servfail(&packet)
                    }
                },
            };
            let _ = sock.send_to(&reply, peer).await;
        });
    }
}

fn servfail(packet: &[u8]) -> Vec<u8> {
    Message::from_vec(packet)
        .ok()
        .and_then(|r| {
            Message::error_msg(r.metadata.id, r.metadata.op_code, ResponseCode::ServFail)
                .to_vec()
                .ok()
        })
        .unwrap_or_default()
}

async fn forward(packet: &[u8], cfg: &DnsConfig) -> std::io::Result<Vec<u8>> {
    let bind: SocketAddr = if cfg.upstream.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    }
    .parse()
    .unwrap();
    let s = UdpSocket::bind(bind).await?;
    s.connect(cfg.upstream).await?;
    s.send(packet).await?;
    let mut buf = vec![0u8; 4096];
    let n = tokio::time::timeout(cfg.upstream_timeout, s.recv(&mut buf))
        .await
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "upstream timeout"))??;
    buf.truncate(n);
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::op::Query;
    use hickory_proto::rr::Name;
    use hygeia_core::{ListData, RulesetData};
    use std::str::FromStr;

    fn rs() -> Ruleset {
        Ruleset::from_data(&RulesetData {
            custom_allow: vec![],
            custom_block: vec![],
            lists: vec![ListData {
                id: "l".into(),
                allow: vec![],
                block: vec!["ads.example.com".into()],
            }],
        })
    }

    fn query(name: &str, t: RecordType) -> Vec<u8> {
        let mut m = Message::query();
        m.metadata.recursion_desired = true;
        m.add_query(Query::query(Name::from_str(name).unwrap(), t));
        m.to_vec().unwrap()
    }

    #[test]
    fn blocks_nxdomain_and_forwards_allowed() {
        let r = rs();
        let (d, log) = decide(
            &r,
            &query("x.ads.example.com.", RecordType::A),
            BlockMode::NxDomain,
        );
        let Decision::Answer(b) = d else {
            panic!("expected answer")
        };
        let m = Message::from_vec(&b).unwrap();
        assert_eq!(m.metadata.response_code, ResponseCode::NXDomain);
        assert!(log.unwrap().1.is_block());

        let (d, _) = decide(
            &r,
            &query("example.org.", RecordType::A),
            BlockMode::NxDomain,
        );
        assert!(matches!(d, Decision::Forward));
    }

    #[test]
    fn null_ip_mode() {
        let (d, _) = decide(
            &rs(),
            &query("ads.example.com.", RecordType::A),
            BlockMode::NullIp,
        );
        let Decision::Answer(b) = d else { panic!() };
        let m = Message::from_vec(&b).unwrap();
        assert_eq!(m.metadata.response_code, ResponseCode::NoError);
        assert_eq!(m.answers.len(), 1);
    }

    #[test]
    fn garbage_is_dropped() {
        let (d, _) = decide(&rs(), &[1, 2, 3], BlockMode::NxDomain);
        assert!(matches!(d, Decision::Answer(b) if b.is_empty()));
    }
}
