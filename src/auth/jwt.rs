//! JWT minting and verification for PoolPay admin access tokens.
//!
//! Design notes (Plan 3 / BE-3):
//!
//! * **RS256 only.** NextAuth (and Cognito later) holds the private key; this
//!   service holds only public keys. HS256 would share a secret between FE and
//!   BE — a footgun we actively avoid.
//! * **`kid`-indexed key map.** `JWT_KEYS` is a JSON array of
//!   `{ kid, private_pem, public_pem, active }`. Signing picks the single
//!   `active:true` entry; verification accepts any kid in the map. Rotation =
//!   add a new active key, flip the previous to `active:false`, remove after a
//!   grace window — zero code change.
//! * **Production fail-closed.** In production (`APP_ENV=production`) boot
//!   panics if `JWT_KEYS` is unset or resolves to zero active keys. Outside
//!   production, we generate an ephemeral RSA-2048 keypair so `cargo run` and
//!   the test suite stay frictionless. The generated key is process-local and
//!   logged as a warning so accidental prod use is visible.

use std::collections::HashMap;
use std::sync::Arc;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jsonwebtoken::{
    Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, decode_header, encode,
};
use rand::RngCore;
use rsa::pkcs8::{EncodePrivateKey, EncodePublicKey, LineEnding};
use rsa::{RsaPrivateKey, RsaPublicKey};
use serde::{Deserialize, Serialize};
use tracing::warn;

/// Access token claims. Shape is stable across providers so the verifier is
/// identical for NextAuth today and Cognito later.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessClaims {
    pub sub: String,
    pub role: String,
    pub token_version: i64,
    pub aud: String,
    pub iss: String,
    pub exp: i64,
    pub iat: i64,
    pub nbf: i64,
}

/// Errors surfaced by the verifier. Callers translate these to
/// `AppError::Unauthorized` — the distinction is kept for logging only, never
/// leaked to HTTP responses.
#[derive(Debug)]
pub enum JwtError {
    Malformed,
    MissingKid,
    UnknownKid,
    Invalid,
    NoActiveKey,
}

impl std::fmt::Display for JwtError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::Malformed => "malformed token",
            Self::MissingKid => "missing kid",
            Self::UnknownKid => "unknown kid",
            Self::Invalid => "signature or claim verification failed",
            Self::NoActiveKey => "no active signing key configured",
        };
        f.write_str(s)
    }
}

impl std::error::Error for JwtError {}

/// The `TokenVerifier` abstraction lets BE-8 swap in a `JwksVerifier` for
/// Cognito without touching handlers or extractors.
pub trait TokenVerifier: Send + Sync {
    fn verify_access(&self, token: &str) -> Result<AccessClaims, JwtError>;
}

/// A single RS256 keypair identified by `kid`. Private key is optional: a
/// pure-verifier deployment (BE-8, Cognito) would have public-only entries.
struct KeyEntry {
    kid: String,
    encoding: Option<EncodingKey>,
    decoding: DecodingKey,
    active: bool,
}

/// Static, in-process key store. Loaded once at boot and shared via `Arc`.
pub struct StaticKeyVerifier {
    keys: HashMap<String, KeyEntry>,
    active_kid: Option<String>,
    audience: String,
    issuer: String,
    access_ttl_secs: i64,
    leeway_secs: u64,
}

#[derive(Debug, Deserialize)]
struct JwtKeysEntryEnv {
    kid: String,
    private_pem: Option<String>,
    public_pem: String,
    #[serde(default)]
    active: bool,
}

/// Runtime configuration for token minting and verification. Values come from
/// env vars with the defaults below; exposed as a struct so tests can build
/// one directly.
#[derive(Debug, Clone)]
pub struct JwtConfig {
    pub audience: String,
    pub issuer: String,
    pub access_ttl_secs: i64,
    pub leeway_secs: u64,
}

impl JwtConfig {
    pub fn from_env() -> Self {
        Self {
            audience: std::env::var("JWT_AUDIENCE")
                .unwrap_or_else(|_| "poolpay-api".to_string()),
            issuer: std::env::var("JWT_ISSUER")
                .unwrap_or_else(|_| "poolpay-nextauth".to_string()),
            access_ttl_secs: std::env::var("JWT_ACCESS_TTL_SECS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(900),
            leeway_secs: std::env::var("JWT_LEEWAY_SECS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(60),
        }
    }
}

impl StaticKeyVerifier {
    /// Build from `JWT_KEYS` (JSON array) + `JwtConfig`. In production the
    /// caller must supply a populated `JWT_KEYS`; outside production we mint
    /// an ephemeral keypair if the env is missing so local dev and tests do
    /// not need an extra setup step.
    pub fn from_env(config: JwtConfig) -> Result<Self, String> {
        let is_prod = std::env::var("APP_ENV").as_deref() == Ok("production");

        match std::env::var("JWT_KEYS") {
            Ok(raw) if !raw.trim().is_empty() => Self::from_json(&raw, config),
            _ => {
                if is_prod {
                    return Err(
                        "JWT_KEYS must be set in production (JSON array with at least one \
                         active RS256 keypair)"
                            .to_string(),
                    );
                }
                warn!(
                    "JWT_KEYS is not set — generating an ephemeral RSA-2048 keypair for this \
                     process. Set JWT_KEYS in any real environment."
                );
                Self::from_ephemeral(config)
            }
        }
    }

    /// Parse a `JWT_KEYS` JSON string. Separate from `from_env()` so tests can
    /// drive the parser directly without mutating process env.
    pub fn from_json(raw: &str, config: JwtConfig) -> Result<Self, String> {
        let entries: Vec<JwtKeysEntryEnv> =
            serde_json::from_str(raw).map_err(|e| format!("JWT_KEYS is not valid JSON: {e}"))?;
        if entries.is_empty() {
            return Err("JWT_KEYS must contain at least one entry".to_string());
        }

        let mut keys: HashMap<String, KeyEntry> = HashMap::with_capacity(entries.len());
        let mut active_kid: Option<String> = None;

        for entry in entries {
            let decoding = DecodingKey::from_rsa_pem(entry.public_pem.as_bytes())
                .map_err(|e| format!("kid={} has invalid public_pem: {e}", entry.kid))?;
            let encoding = match entry.private_pem.as_deref() {
                Some(pem) if !pem.is_empty() => Some(
                    EncodingKey::from_rsa_pem(pem.as_bytes())
                        .map_err(|e| format!("kid={} has invalid private_pem: {e}", entry.kid))?,
                ),
                _ => None,
            };
            if entry.active {
                if encoding.is_none() {
                    return Err(format!(
                        "kid={} is marked active but has no private_pem — cannot sign",
                        entry.kid
                    ));
                }
                if active_kid.is_some() {
                    return Err(
                        "JWT_KEYS contains more than one active key; mark exactly one as active"
                            .to_string(),
                    );
                }
                active_kid = Some(entry.kid.clone());
            }
            keys.insert(
                entry.kid.clone(),
                KeyEntry { kid: entry.kid, encoding, decoding, active: entry.active },
            );
        }

        if active_kid.is_none() {
            return Err("JWT_KEYS has no active key".to_string());
        }

        Ok(Self {
            keys,
            active_kid,
            audience: config.audience,
            issuer: config.issuer,
            access_ttl_secs: config.access_ttl_secs,
            leeway_secs: config.leeway_secs,
        })
    }

    /// Generate a fresh RSA-2048 keypair for the current process. Only called
    /// outside production and only when `JWT_KEYS` is unset.
    fn from_ephemeral(config: JwtConfig) -> Result<Self, String> {
        let mut rng = rand::thread_rng();
        let private = RsaPrivateKey::new(&mut rng, 2048)
            .map_err(|e| format!("failed to generate ephemeral RSA key: {e}"))?;
        let public = RsaPublicKey::from(&private);
        let private_pem = private
            .to_pkcs8_pem(LineEnding::LF)
            .map_err(|e| format!("encode pkcs8 pem: {e}"))?
            .to_string();
        let public_pem = public
            .to_public_key_pem(LineEnding::LF)
            .map_err(|e| format!("encode public pem: {e}"))?;

        let kid = ephemeral_kid();
        let decoding = DecodingKey::from_rsa_pem(public_pem.as_bytes())
            .map_err(|e| format!("decode ephemeral public key: {e}"))?;
        let encoding = EncodingKey::from_rsa_pem(private_pem.as_bytes())
            .map_err(|e| format!("decode ephemeral private key: {e}"))?;

        let mut keys = HashMap::new();
        keys.insert(
            kid.clone(),
            KeyEntry { kid: kid.clone(), encoding: Some(encoding), decoding, active: true },
        );
        Ok(Self {
            keys,
            active_kid: Some(kid),
            audience: config.audience,
            issuer: config.issuer,
            access_ttl_secs: config.access_ttl_secs,
            leeway_secs: config.leeway_secs,
        })
    }

    /// Mint an access token. Kept public so BE-4 can wire it into the compat
    /// shim and integration tests can mint valid tokens. Lives behind
    /// `#[allow(dead_code)]` until a handler actually calls it.
    #[allow(dead_code)]
    pub fn mint_access(&self, subject: &str, role: &str, token_version: i64) -> Result<String, JwtError> {
        let kid = self.active_kid.as_deref().ok_or(JwtError::NoActiveKey)?;
        let entry = self.keys.get(kid).ok_or(JwtError::NoActiveKey)?;
        let encoding = entry.encoding.as_ref().ok_or(JwtError::NoActiveKey)?;

        let now = chrono::Utc::now().timestamp();
        let claims = AccessClaims {
            sub: subject.to_string(),
            role: role.to_string(),
            token_version,
            aud: self.audience.clone(),
            iss: self.issuer.clone(),
            exp: now + self.access_ttl_secs,
            iat: now,
            nbf: now,
        };

        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(kid.to_string());

        encode(&header, &claims, encoding).map_err(|_| JwtError::Invalid)
    }
}

impl TokenVerifier for StaticKeyVerifier {
    fn verify_access(&self, token: &str) -> Result<AccessClaims, JwtError> {
        let header = decode_header(token).map_err(|_| JwtError::Malformed)?;
        let kid = header.kid.ok_or(JwtError::MissingKid)?;
        let entry = self.keys.get(&kid).ok_or(JwtError::UnknownKid)?;

        // Pinning the algorithm to RS256 rejects the classic "alg: none" and
        // "alg: HS256 with public key as secret" attacks against mixed
        // verifiers.
        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_audience(&[&self.audience]);
        validation.set_issuer(&[&self.issuer]);
        validation.leeway = self.leeway_secs;
        validation.validate_exp = true;
        validation.validate_nbf = true;

        let data = decode::<AccessClaims>(token, &entry.decoding, &validation)
            .map_err(|_| JwtError::Invalid)?;
        Ok(data.claims)
    }
}

/// Type-erased handle used by extractors and the router state.
pub type SharedVerifier = Arc<dyn TokenVerifier>;

/// 16-byte random id, base64url-encoded, used for ephemeral dev keys.
fn ephemeral_kid() -> String {
    let mut bytes = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut bytes);
    format!("ephemeral-{}", URL_SAFE_NO_PAD.encode(bytes))
}

// Suppress unused warnings on fields that become load-bearing in later
// commits (active/kid are exercised by tests and the rotation path).
impl KeyEntry {
    #[allow(dead_code)]
    fn is_active(&self) -> bool { self.active }
    #[allow(dead_code)]
    fn kid(&self) -> &str { &self.kid }
}
