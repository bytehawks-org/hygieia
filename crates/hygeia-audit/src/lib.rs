//! Append-only, hash-chained audit log (tamper evidence) with CEF export.
//!
//! Each event commits to the previous one: `hash = SHA-256(prev_hash || body)`.
//! Editing or removing any past event breaks verification from that point on.
//! Note: a chain proves *internal* consistency; to detect truncation of the
//! tail, periodically anchor the head hash externally (syslog, OTLP, WORM).

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// What the caller supplies; sequence, chaining and hash are added on append.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Draft {
    pub ts: i64,
    pub tenant_id: String,
    /// Who: admin user id, API token id, device id or `system`.
    pub actor: String,
    /// What: dotted verb, e.g. `rule.create`, `token.revoke`, `bundle.publish`.
    pub action: String,
    pub target: String,
    /// Before/after of the change (secrets must never be put here).
    pub diff: Option<serde_json::Value>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Event {
    pub seq: u64,
    #[serde(flatten)]
    pub draft: Draft,
    pub prev_hash: String,
    pub hash: String,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ChainError {
    #[error("sequence gap or reorder at seq {0}")]
    Sequence(u64),
    #[error("prev_hash mismatch at seq {0}")]
    Link(u64),
    #[error("hash mismatch at seq {0}")]
    Hash(u64),
}

fn compute_hash(seq: u64, prev: &str, d: &Draft) -> String {
    #[derive(Serialize)]
    struct Body<'a> {
        seq: u64,
        prev: &'a str,
        d: &'a Draft,
    }
    let body = serde_json::to_vec(&Body { seq, prev, d }).expect("serialisable");
    hex(&Sha256::digest(&body))
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

#[derive(Debug, Default)]
pub struct AuditLog {
    events: Vec<Event>,
}

impl AuditLog {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn head(&self) -> &str {
        self.events.last().map_or(GENESIS, |e| e.hash.as_str())
    }

    pub fn append(&mut self, draft: Draft) -> &Event {
        let seq = self.events.len() as u64;
        let prev_hash = self.head().to_string();
        let hash = compute_hash(seq, &prev_hash, &draft);
        self.events.push(Event {
            seq,
            draft,
            prev_hash,
            hash,
        });
        self.events.last().unwrap()
    }

    pub fn events(&self) -> &[Event] {
        &self.events
    }

    pub fn verify(&self) -> Result<(), ChainError> {
        verify(&self.events)
    }
}

/// Verify an exported chain starting at genesis.
pub fn verify(events: &[Event]) -> Result<(), ChainError> {
    let mut prev = GENESIS;
    for (i, e) in events.iter().enumerate() {
        if e.seq != i as u64 {
            return Err(ChainError::Sequence(e.seq));
        }
        if e.prev_hash != prev {
            return Err(ChainError::Link(e.seq));
        }
        if compute_hash(e.seq, &e.prev_hash, &e.draft) != e.hash {
            return Err(ChainError::Hash(e.seq));
        }
        prev = &e.hash;
    }
    Ok(())
}

fn cef_escape(s: &str, header: bool) -> String {
    let mut o = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\\' => o.push_str("\\\\"),
            '|' if header => o.push_str("\\|"),
            '=' if !header => o.push_str("\\="),
            '\n' | '\r' => o.push(' '),
            c => o.push(c),
        }
    }
    o
}

/// ArcSight CEF line for SIEM export.
pub fn to_cef(e: &Event) -> String {
    let d = &e.draft;
    format!(
        "CEF:0|Hygeia|Hygeia|0.1|{}|{}|3|rt={} suser={} cs1Label=tenant cs1={} dst={} cs2Label=hash cs2={}",
        cef_escape(&d.action, true),
        cef_escape(&d.action, true),
        d.ts.saturating_mul(1000),
        cef_escape(&d.actor, false),
        cef_escape(&d.tenant_id, false),
        cef_escape(&d.target, false),
        e.hash,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn d(n: i64) -> Draft {
        Draft {
            ts: n,
            tenant_id: "t1".into(),
            actor: "admin|x".into(),
            action: "rule.create".into(),
            target: "ads.example.com".into(),
            diff: Some(serde_json::json!({"after": {"action": "block"}})),
        }
    }

    #[test]
    fn chain_verifies_and_detects_tamper() {
        let mut log = AuditLog::new();
        for i in 0..5 {
            log.append(d(i));
        }
        assert_eq!(log.verify(), Ok(()));

        let mut ev = log.events().to_vec();
        ev[2].draft.target = "evil.test".into();
        assert_eq!(verify(&ev), Err(ChainError::Hash(2)));

        let mut ev = log.events().to_vec();
        ev.remove(1);
        assert!(verify(&ev).is_err());

        // tail truncation is NOT detectable without an external anchor
        let ev = &log.events()[..3];
        assert_eq!(verify(ev), Ok(()));
    }

    #[test]
    fn cef_escapes() {
        let mut log = AuditLog::new();
        let e = log.append(d(1)).clone();
        let line = to_cef(&e);
        assert!(line.starts_with("CEF:0|Hygeia|Hygeia|0.1|rule.create|"));
        assert!(line.contains("suser=admin|x"));
    }
}
