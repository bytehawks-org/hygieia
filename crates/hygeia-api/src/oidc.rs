//! OIDC resource-server side: validates bearer JWTs issued by an external IdP.
//! The admin UI performs the authorization-code + PKCE flow with the IdP and
//! sends the resulting token; this module never handles user passwords.
//!
//! Identity is `(iss, sub)` ONLY. Roles come from `role_bindings`; the e-mail
//! claim is informational and never used for authorisation (e-mail based
//! matching enables account takeover through IdP misconfiguration).

use std::sync::RwLock;
use std::time::{Duration, Instant};

use jsonwebtoken::jwk::JwkSet;
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use serde::Deserialize;

#[derive(Debug, Clone)]
pub struct OidcConfig {
    pub issuer: String,
    pub audience: String,
    /// Clock skew tolerance in seconds.
    pub leeway_secs: u64,
    /// Lab only: allow http:// discovery/JWKS URLs.
    pub allow_insecure_http: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum OidcError {
    #[error("invalid token: {0}")]
    Invalid(String),
    #[error("identity provider unavailable: {0}")]
    Provider(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    pub issuer: String,
    pub subject: String,
    pub email: Option<String>,
}

#[derive(Deserialize)]
struct Claims {
    sub: String,
    email: Option<String>,
}

#[derive(Deserialize)]
struct Discovery {
    issuer: String,
    jwks_uri: String,
}

struct Cached {
    keys: JwkSet,
    fetched: Instant,
}

pub struct OidcVerifier {
    cfg: OidcConfig,
    http: reqwest::Client,
    cache: RwLock<Option<Cached>>,
}

/// Asymmetric algorithms only. HS* is excluded on purpose: with a JWKS-published
/// key it enables the classic "public key used as HMAC secret" forgery; `none`
/// is not representable.
const ALGS: [Algorithm; 5] = [
    Algorithm::RS256,
    Algorithm::RS384,
    Algorithm::RS512,
    Algorithm::ES256,
    Algorithm::ES384,
];
const MIN_REFRESH: Duration = Duration::from_secs(30);
const MAX_AGE: Duration = Duration::from_secs(3600);

impl OidcVerifier {
    pub fn new(cfg: OidcConfig) -> Result<Self, OidcError> {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| OidcError::Provider(e.to_string()))?;
        Ok(Self {
            cfg,
            http,
            cache: RwLock::new(None),
        })
    }

    fn check_scheme(&self, url: &str) -> Result<(), OidcError> {
        if url.starts_with("https://")
            || (self.cfg.allow_insecure_http && url.starts_with("http://"))
        {
            Ok(())
        } else {
            Err(OidcError::Provider(format!("refusing non-https url {url}")))
        }
    }

    async fn fetch_keys(&self) -> Result<JwkSet, OidcError> {
        let well_known = format!(
            "{}/.well-known/openid-configuration",
            self.cfg.issuer.trim_end_matches('/')
        );
        self.check_scheme(&well_known)?;
        let perr = |e: reqwest::Error| OidcError::Provider(e.to_string());
        let d: Discovery = self
            .http
            .get(&well_known)
            .send()
            .await
            .map_err(perr)?
            .error_for_status()
            .map_err(perr)?
            .json()
            .await
            .map_err(perr)?;
        // Mix-up protection: the document must describe the issuer we configured.
        if d.issuer.trim_end_matches('/') != self.cfg.issuer.trim_end_matches('/') {
            return Err(OidcError::Provider("discovery issuer mismatch".into()));
        }
        self.check_scheme(&d.jwks_uri)?;
        self.http
            .get(&d.jwks_uri)
            .send()
            .await
            .map_err(perr)?
            .error_for_status()
            .map_err(perr)?
            .json()
            .await
            .map_err(perr)
    }

    async fn refresh(&self, force: bool) -> Result<(), OidcError> {
        {
            let c = self.cache.read().unwrap();
            if let Some(c) = &*c {
                let age = c.fetched.elapsed();
                // Unknown kid may mean key rotation: refetch, but not more than every MIN_REFRESH.
                if age < MIN_REFRESH || (!force && age < MAX_AGE) {
                    return Ok(());
                }
            }
        }
        let keys = self.fetch_keys().await?;
        *self.cache.write().unwrap() = Some(Cached {
            keys,
            fetched: Instant::now(),
        });
        Ok(())
    }

    fn find_key(&self, kid: Option<&str>, alg: Algorithm) -> Option<DecodingKey> {
        let c = self.cache.read().unwrap();
        let set = &c.as_ref()?.keys;
        let jwk = match kid {
            Some(k) => set.find(k)?,
            None if set.keys.len() == 1 => &set.keys[0],
            None => return None,
        };
        // Key must be usable for signatures and compatible with the token's algorithm.
        if let Some(u) = &jwk.common.public_key_use
            && !matches!(u, jsonwebtoken::jwk::PublicKeyUse::Signature)
        {
            return None;
        }
        // Variant names coincide (ES256, RS256, ...): a key pinned to another alg is not usable.
        if let Some(a) = jwk.common.key_algorithm
            && format!("{a:?}") != format!("{alg:?}")
        {
            return None;
        }
        DecodingKey::from_jwk(jwk).ok()
    }

    pub async fn verify(&self, token: &str) -> Result<Identity, OidcError> {
        let header = decode_header(token).map_err(|e| OidcError::Invalid(e.to_string()))?;
        if !ALGS.contains(&header.alg) {
            return Err(OidcError::Invalid("unsupported algorithm".into()));
        }
        self.refresh(false).await?;
        let mut key = self.find_key(header.kid.as_deref(), header.alg);
        if key.is_none() {
            self.refresh(true).await?;
            key = self.find_key(header.kid.as_deref(), header.alg);
        }
        let key = key.ok_or_else(|| OidcError::Invalid("no matching signing key".into()))?;

        let mut v = Validation::new(header.alg);
        v.set_issuer(&[self.cfg.issuer.as_str()]);
        v.set_audience(&[self.cfg.audience.as_str()]);
        v.set_required_spec_claims(&["exp", "iss", "aud", "sub"]);
        v.validate_nbf = true;
        v.leeway = self.cfg.leeway_secs;
        let data =
            decode::<Claims>(token, &key, &v).map_err(|e| OidcError::Invalid(e.to_string()))?;
        if data.claims.sub.is_empty() {
            return Err(OidcError::Invalid("empty subject".into()));
        }
        Ok(Identity {
            issuer: self.cfg.issuer.clone(),
            subject: data.claims.sub,
            email: data.claims.email,
        })
    }
}
