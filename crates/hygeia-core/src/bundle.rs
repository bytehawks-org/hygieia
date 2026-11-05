//! Versioned, ed25519-signed ruleset bundle. DNS, proxy and blocker all load
//! this same artefact.
//!
//! Wire format: `"HYGB" | u8 format | u32 BE payload_len | payload | 64B signature`
//! where `payload` is postcard-encoded [`Bundle`]. The signature covers
//! everything before it (magic, format, length, payload).

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::cosmetic::CosmeticRules;
use crate::policy::RulesetData;

const MAGIC: &[u8; 4] = b"HYGB";
const FORMAT: u8 = 1;
const SIG_LEN: usize = 64;
const HEADER_LEN: usize = 4 + 1 + 4;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceMeta {
    pub id: String,
    pub name: String,
    pub url: String,
    pub license: String,
    pub attribution: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Meta {
    /// Monotonic per tenant/group; clients refuse downgrades.
    pub version: u64,
    pub tenant_id: String,
    pub group_id: String,
    pub created_at: i64,
    pub sources: Vec<SourceMeta>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Bundle {
    pub meta: Meta,
    pub network: RulesetData,
    pub cosmetic: CosmeticRules,
}

#[derive(Debug, thiserror::Error)]
pub enum BundleError {
    #[error("bad magic or truncated bundle")]
    Malformed,
    #[error("unsupported bundle format {0}")]
    UnsupportedFormat(u8),
    #[error("signature verification failed")]
    BadSignature,
    #[error("decode error: {0}")]
    Decode(String),
}

/// Encoded + signed bundle bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedBundle(pub Vec<u8>);

impl SignedBundle {
    pub fn sign(bundle: &Bundle, key: &SigningKey) -> Self {
        let payload = postcard::to_stdvec(bundle).expect("bundle serialisation is infallible");
        let mut out = Vec::with_capacity(HEADER_LEN + payload.len() + SIG_LEN);
        out.extend_from_slice(MAGIC);
        out.push(FORMAT);
        out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        out.extend_from_slice(&payload);
        let sig = key.sign(&out);
        out.extend_from_slice(&sig.to_bytes());
        Self(out)
    }

    /// Verify the signature, then decode. Never decodes unauthenticated data.
    pub fn open(bytes: &[u8], key: &VerifyingKey) -> Result<Bundle, BundleError> {
        if bytes.len() < HEADER_LEN + SIG_LEN || &bytes[..4] != MAGIC {
            return Err(BundleError::Malformed);
        }
        if bytes[4] != FORMAT {
            return Err(BundleError::UnsupportedFormat(bytes[4]));
        }
        let len = u32::from_be_bytes(bytes[5..9].try_into().unwrap()) as usize;
        if bytes.len() != HEADER_LEN + len + SIG_LEN {
            return Err(BundleError::Malformed);
        }
        let (signed, sig) = bytes.split_at(HEADER_LEN + len);
        let sig = Signature::from_slice(sig).map_err(|_| BundleError::BadSignature)?;
        key.verify(signed, &sig)
            .map_err(|_| BundleError::BadSignature)?;
        postcard::from_bytes(&signed[HEADER_LEN..]).map_err(|e| BundleError::Decode(e.to_string()))
    }

    /// Strong ETag for `If-None-Match` handling.
    pub fn etag(&self) -> String {
        let h = Sha256::digest(&self.0);
        let mut s = String::with_capacity(34);
        s.push('"');
        for b in &h[..16] {
            s.push_str(&format!("{b:02x}"));
        }
        s.push('"');
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::ListData;

    fn sample() -> Bundle {
        Bundle {
            meta: Meta {
                version: 7,
                tenant_id: "t".into(),
                group_id: "g".into(),
                created_at: 0,
                sources: vec![],
            },
            network: RulesetData {
                custom_allow: vec![],
                custom_block: vec!["a.test".into()],
                lists: vec![ListData {
                    id: "l".into(),
                    allow: vec![],
                    block: vec!["b.test".into()],
                }],
            },
            cosmetic: CosmeticRules::default(),
        }
    }

    #[test]
    fn roundtrip_and_tamper() {
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let signed = SignedBundle::sign(&sample(), &sk);
        assert_eq!(
            SignedBundle::open(&signed.0, &sk.verifying_key()).unwrap(),
            sample()
        );

        let mut bad = signed.0.clone();
        bad[HEADER_LEN + 2] ^= 1;
        assert!(matches!(
            SignedBundle::open(&bad, &sk.verifying_key()),
            Err(BundleError::BadSignature)
        ));

        let other = SigningKey::from_bytes(&[8u8; 32]);
        assert!(SignedBundle::open(&signed.0, &other.verifying_key()).is_err());
        assert!(matches!(
            SignedBundle::open(b"nope", &sk.verifying_key()),
            Err(BundleError::Malformed)
        ));
        assert_eq!(signed.etag(), signed.etag());
    }
}
