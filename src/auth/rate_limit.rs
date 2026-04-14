//! Rate limiting for the HMAC-gated auth endpoints (Plan 3, BE-2).
//!
//! Two layers compose:
//!
//!   * **Per-IP** — a `tower_governor` `GovernorLayer` mounted in front of
//!     `/api/auth/verify-credentials` and `/api/auth/ensure-user`. Runs before
//!     HMAC verification so anonymous floods are dropped cheaply.
//!   * **Composite `(ip, email_normalised)`** — an in-handler limiter on
//!     `verify_credentials` that charges a quota slot only on a failed login
//!     attempt. Successful logins never consume quota.
//!
//! Limits are configured via env; see `.env.example`. The peer-IP source is
//! governed by `TRUST_PROXY_HEADERS` — only set that to `true` when the
//! service sits behind a proxy that strips client-supplied headers.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::num::NonZeroU32;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::{ConnectInfo, FromRequestParts};
use axum::http::{Extensions, HeaderMap, Request, request::Parts};
use governor::clock::{Clock, DefaultClock};
use governor::state::keyed::DashMapStateStore;
use governor::{NotUntil, Quota, RateLimiter};
use tower_governor::GovernorLayer;
use tower_governor::errors::GovernorError;
use tower_governor::governor::{GovernorConfig, GovernorConfigBuilder};
use tower_governor::key_extractor::KeyExtractor;

// ── env keys & defaults ───────────────────────────────────────────────────────

const ENV_PER_IP_PER_MINUTE: &str = "AUTH_RATE_LIMIT_PER_MINUTE";
const ENV_PER_IP_BURST: &str = "AUTH_RATE_LIMIT_BURST";
const ENV_CRED_FAILURE_LIMIT: &str = "AUTH_CREDENTIAL_FAILURE_LIMIT";
const ENV_CRED_FAILURE_WINDOW_SECS: &str = "AUTH_CREDENTIAL_FAILURE_WINDOW_SECS";
const ENV_TRUST_PROXY_HEADERS: &str = "TRUST_PROXY_HEADERS";
const ENV_APP_ENV: &str = "APP_ENV";

const DEFAULT_PER_IP_PER_MINUTE: u32 = 60;
const DEFAULT_PER_IP_BURST: u32 = 10;
const DEFAULT_CRED_FAILURE_LIMIT: u32 = 5;
const DEFAULT_CRED_FAILURE_WINDOW_SECS: u64 = 900;

/// Header tests set to simulate a peer IP when the service is exercised via
/// `tower::ServiceExt::oneshot`, which has no `ConnectInfo`. Never honoured in
/// production — only when `APP_ENV` is `development` or `test`.
pub const TEST_PEER_IP_HEADER: &str = "x-test-peer-ip";

// ── config ────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    pub per_ip_per_minute: u32,
    pub per_ip_burst: u32,
    pub credential_failure_limit: u32,
    pub credential_failure_window_secs: u64,
    pub trust_proxy_headers: bool,
    pub test_mode: bool,
}

impl RateLimitConfig {
    /// Load config from env with documented defaults. Invalid values fall back
    /// to the default and emit a warning rather than panic — misconfiguring
    /// rate limits should not take the whole service down.
    pub fn from_env() -> Self {
        Self {
            per_ip_per_minute: parse_u32(ENV_PER_IP_PER_MINUTE, DEFAULT_PER_IP_PER_MINUTE),
            per_ip_burst: parse_u32(ENV_PER_IP_BURST, DEFAULT_PER_IP_BURST),
            credential_failure_limit: parse_u32(
                ENV_CRED_FAILURE_LIMIT,
                DEFAULT_CRED_FAILURE_LIMIT,
            ),
            credential_failure_window_secs: parse_u64(
                ENV_CRED_FAILURE_WINDOW_SECS,
                DEFAULT_CRED_FAILURE_WINDOW_SECS,
            ),
            trust_proxy_headers: parse_bool(ENV_TRUST_PROXY_HEADERS, false),
            test_mode: matches!(
                std::env::var(ENV_APP_ENV).as_deref(),
                Ok("development" | "test")
            ),
        }
    }
}

fn parse_u32(key: &str, default: u32) -> u32 {
    match std::env::var(key) {
        Ok(v) => v.parse::<u32>().unwrap_or_else(|_| {
            tracing::warn!(env = key, value = %v, "invalid u32 — using default");
            default
        }),
        Err(_) => default,
    }
}

fn parse_u64(key: &str, default: u64) -> u64 {
    match std::env::var(key) {
        Ok(v) => v.parse::<u64>().unwrap_or_else(|_| {
            tracing::warn!(env = key, value = %v, "invalid u64 — using default");
            default
        }),
        Err(_) => default,
    }
}

fn parse_bool(key: &str, default: bool) -> bool {
    match std::env::var(key) {
        Ok(v) => matches!(v.trim().to_ascii_lowercase().as_str(), "true" | "1" | "yes"),
        Err(_) => default,
    }
}

// ── key extractor ─────────────────────────────────────────────────────────────

/// Extracts the client IP from, in order:
///   1. `X-Test-Peer-Ip` header — only when `APP_ENV` is development/test.
///   2. `X-Forwarded-For` (first hop) — only when `trust_proxy_headers=true`.
///   3. `ConnectInfo<SocketAddr>` — the actual peer IP.
#[derive(Debug, Clone)]
pub struct AuthIpKeyExtractor {
    trust_proxy_headers: bool,
    test_mode: bool,
}

impl AuthIpKeyExtractor {
    pub fn new(cfg: &RateLimitConfig) -> Self {
        Self {
            trust_proxy_headers: cfg.trust_proxy_headers,
            test_mode: cfg.test_mode,
        }
    }
}

impl KeyExtractor for AuthIpKeyExtractor {
    type Key = IpAddr;

    fn extract<T>(&self, req: &Request<T>) -> Result<Self::Key, GovernorError> {
        if let Some(ip) = extract_ip(req, self.trust_proxy_headers, self.test_mode) {
            return Ok(ip);
        }
        // If we somehow have no peer IP (shouldn't happen in production with
        // `into_make_service_with_connect_info`), bucket all such requests
        // together under 127.0.0.1 rather than 500-ing the caller. Keeping
        // the service available is more important than perfect per-IP
        // accounting in an edge case.
        Ok(IpAddr::V4(Ipv4Addr::LOCALHOST))
    }
}

fn extract_ip<T>(req: &Request<T>, trust_proxy: bool, test_mode: bool) -> Option<IpAddr> {
    resolve_client_ip(req.headers(), req.extensions(), trust_proxy, test_mode)
}

/// Resolve the client IP from already-borrowed header/extension views. Used
/// both by the tower-governor key extractor and by the `ClientIp` handler
/// extractor so the two limiters key on the same IP.
pub fn resolve_client_ip(
    headers: &HeaderMap,
    extensions: &Extensions,
    trust_proxy: bool,
    test_mode: bool,
) -> Option<IpAddr> {
    if test_mode {
        if let Some(ip) = headers
            .get(TEST_PEER_IP_HEADER)
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse::<IpAddr>().ok())
        {
            return Some(ip);
        }
    }
    if trust_proxy {
        if let Some(ip) = headers
            .get("x-forwarded-for")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.split(',').next())
            .map(str::trim)
            .and_then(|s| s.parse::<IpAddr>().ok())
        {
            return Some(ip);
        }
    }
    extensions
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ci| ci.0.ip())
}

/// Handler extractor that yields the caller's IP using the same rules as the
/// per-IP rate limiter. Requires `RateLimitConfig` to be present as a request
/// extension — mounted by the auth sub-router. Falls back to 127.0.0.1 when
/// nothing is available so a broken extension layer cannot 500 every call.
pub struct ClientIp(pub IpAddr);

impl<S> FromRequestParts<S> for ClientIp
where
    S: Send + Sync,
{
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let cfg = parts
            .extensions
            .get::<RateLimitConfig>()
            .cloned()
            .unwrap_or_else(RateLimitConfig::from_env);
        let ip = resolve_client_ip(
            &parts.headers,
            &parts.extensions,
            cfg.trust_proxy_headers,
            cfg.test_mode,
        )
        .unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST));
        Ok(ClientIp(ip))
    }
}

// ── per-IP layer ──────────────────────────────────────────────────────────────

pub type AuthGovernorConfig =
    GovernorConfig<AuthIpKeyExtractor, governor::middleware::NoOpMiddleware>;

/// Build the `tower_governor` config for the per-IP limiter on auth endpoints.
///
/// Panics only at startup if the configured values are zero — surfacing a
/// misconfig loud and early is better than silently shipping an un-limited
/// auth surface.
pub fn build_per_ip_config(cfg: &RateLimitConfig) -> Arc<AuthGovernorConfig> {
    let burst = NonZeroU32::new(cfg.per_ip_burst).expect("AUTH_RATE_LIMIT_BURST must be > 0");
    let per_min = NonZeroU32::new(cfg.per_ip_per_minute)
        .expect("AUTH_RATE_LIMIT_PER_MINUTE must be > 0");

    // `tower_governor`'s builder takes a replenish-period + burst-size. Convert
    // "N requests per minute, burst B" into "replenish one cell every 60/N
    // seconds, bucket size B". Clamp the period to >=1ms so a misconfig does
    // not produce a zero duration.
    let period = Duration::from_millis((60_000 / u64::from(per_min.get())).max(1));

    let config = GovernorConfigBuilder::default()
        .period(period)
        .burst_size(burst.get())
        .key_extractor(AuthIpKeyExtractor::new(cfg))
        .finish()
        .expect("rate-limit config must be non-zero");

    Arc::new(config)
}

pub fn build_per_ip_layer(
    cfg: &RateLimitConfig,
) -> GovernorLayer<AuthIpKeyExtractor, governor::middleware::NoOpMiddleware, axum::body::Body> {
    GovernorLayer::new(build_per_ip_config(cfg))
}

// ── composite (ip, email) failure limiter ─────────────────────────────────────

/// Key for the composite limiter. Email is normalised (trim + lowercase) by
/// the caller to match the identity-lookup path used in `verify_credentials`.
pub type CredentialFailureKey = (IpAddr, String);

type CredentialFailureRateLimiter = RateLimiter<
    CredentialFailureKey,
    DashMapStateStore<CredentialFailureKey>,
    DefaultClock,
>;

/// Charges one quota slot per failed credential attempt per `(ip, email)` pair.
/// Successful logins never call `charge_failure`, so they never consume quota.
#[derive(Clone)]
pub struct CredentialFailureLimiter {
    inner: Arc<CredentialFailureRateLimiter>,
}

impl CredentialFailureLimiter {
    pub fn new(cfg: &RateLimitConfig) -> Self {
        let limit = NonZeroU32::new(cfg.credential_failure_limit)
            .expect("AUTH_CREDENTIAL_FAILURE_LIMIT must be > 0");
        let window = cfg.credential_failure_window_secs.max(1);

        // Bucket of size `limit` that replenishes one cell every
        // `window / limit` — a continuous-refill analogue of "N failures per
        // window". E.g. 5 per 900s → one slot every 180s. Computed in
        // milliseconds so very high limits (large default in tests) still
        // produce a non-zero period.
        let replenish_ms = (window * 1000 / u64::from(limit.get())).max(1);
        let replenish = Duration::from_millis(replenish_ms);
        let quota = Quota::with_period(replenish)
            .expect("credential-failure replenish period must be non-zero")
            .allow_burst(limit);

        let limiter = RateLimiter::dashmap(quota);
        Self {
            inner: Arc::new(limiter),
        }
    }

    /// Consume one slot to charge a failed credential attempt. Returns
    /// `Err(retry_after_secs)` when the bucket is already empty — the caller
    /// should translate that into a 429 instead of the usual 401.
    pub fn charge_failure(&self, key: &CredentialFailureKey) -> Result<(), u64> {
        match self.inner.check_key(key) {
            Ok(_) => Ok(()),
            Err(neg) => Err(retry_after_secs(&neg)),
        }
    }
}

fn retry_after_secs(neg: &NotUntil<governor::clock::QuantaInstant>) -> u64 {
    neg.wait_time_from(DefaultClock::default().now()).as_secs()
}
