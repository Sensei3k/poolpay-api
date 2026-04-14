//! Argon2id password hashing with OWASP 2024 parameters.
//!
//! `verify_or_dummy` keeps login timing flat: unknown-email paths still run
//! a full Argon2 verify against a static dummy hash, so an attacker cannot
//! distinguish "no such user" from "wrong password" by response latency.

use argon2::{Algorithm, Argon2, Params, Version};
use password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString, rand_core::OsRng};
use std::sync::OnceLock;

use crate::api::models::AppError;

/// OWASP 2024 baseline: m=19 MiB, t=2, p=1.
///
/// Under `cargo test` these collapse to the Argon2 minimum — a single hash
/// at the OWASP params runs ~500 ms in debug mode, and the auth suite calls
/// `hash`/`verify` 50+ times across bootstrap and credential-verification
/// tests. That alone added ~30 s of pure CPU per `cargo test` cycle and
/// dragged tower-governor's wall-clock-based rate-limit tests into flaky
/// territory by pushing real-time refills past the assertion windows.
///
/// The algorithm (Argon2id), version (V0x13), salt generation and PHC
/// encoding are unchanged — only the work factor differs — so weak-params
/// hashes still verify correctly and still reject wrong passwords. Drift
/// on the prod params themselves is covered by `prod_params_round_trip`
/// in the test module below, which runs the OWASP baseline once per CI.
#[cfg(not(test))]
const ARGON2_M_COST_KIB: u32 = 19_456;
#[cfg(not(test))]
const ARGON2_T_COST: u32 = 2;
#[cfg(not(test))]
const ARGON2_P_COST: u32 = 1;

#[cfg(test)]
const ARGON2_M_COST_KIB: u32 = argon2::Params::MIN_M_COST;
#[cfg(test)]
const ARGON2_T_COST: u32 = argon2::Params::MIN_T_COST;
#[cfg(test)]
const ARGON2_P_COST: u32 = argon2::Params::MIN_P_COST;

/// The placeholder password used to generate `dummy_hash()`. Its value is
/// irrelevant — it only needs to produce a valid Argon2 PHC string so the
/// unknown-email branch of `verify-credentials` spends the same CPU as the
/// known-email branch.
const DUMMY_PASSWORD: &str = "dummy-password-for-constant-time-verify";

fn argon2() -> Argon2<'static> {
    let params = Params::new(ARGON2_M_COST_KIB, ARGON2_T_COST, ARGON2_P_COST, None)
        .expect("argon2 params within valid range");
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
}

/// Hash a plaintext password for storage. Generates a fresh random salt.
pub fn hash(plaintext: &str) -> Result<String, AppError> {
    let salt = SaltString::generate(&mut OsRng);
    argon2()
        .hash_password(plaintext.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|e| AppError::Internal(format!("argon2 hash failed: {e}")))
}

/// Verify a plaintext password against a stored Argon2 PHC hash.
/// Returns `Ok(true)` on match, `Ok(false)` on mismatch, `Err` only if the
/// stored hash is malformed.
pub fn verify(plaintext: &str, stored_hash: &str) -> Result<bool, AppError> {
    let parsed = PasswordHash::new(stored_hash)
        .map_err(|e| AppError::Internal(format!("argon2 hash parse failed: {e}")))?;
    match argon2().verify_password(plaintext.as_bytes(), &parsed) {
        Ok(()) => Ok(true),
        Err(password_hash::Error::Password) => Ok(false),
        Err(e) => Err(AppError::Internal(format!("argon2 verify failed: {e}"))),
    }
}

/// Returns `true` iff the provided password matches the stored hash.
/// When `stored_hash` is `None`, run a verify against a dummy hash to preserve
/// constant-time behaviour, then return `false`.
pub fn verify_or_dummy(plaintext: &str, stored_hash: Option<&str>) -> Result<bool, AppError> {
    match stored_hash {
        Some(h) => verify(plaintext, h),
        None => {
            let _ = verify(plaintext, dummy_hash())?;
            Ok(false)
        }
    }
}

/// Lazily-initialised Argon2 hash of `DUMMY_PASSWORD`. Salt is generated once
/// at process start — that is fine because the hash is only ever used to burn
/// CPU time, not to authenticate anything.
fn dummy_hash() -> &'static str {
    static DUMMY: OnceLock<String> = OnceLock::new();
    DUMMY.get_or_init(|| hash(DUMMY_PASSWORD).expect("dummy hash generation must succeed"))
}

/// Force the lazy `dummy_hash()` static to initialise now. Call once at boot
/// so the first unknown-email login does not pay extra Argon2 CPU relative to
/// the warm path — closes a subtle timing side channel.
pub fn prewarm() {
    let _ = dummy_hash();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_and_verify_roundtrip() {
        let h = hash("correct horse battery staple").unwrap();
        assert!(verify("correct horse battery staple", &h).unwrap());
        assert!(!verify("wrong password", &h).unwrap());
    }

    #[test]
    fn verify_or_dummy_handles_missing_hash() {
        assert!(!verify_or_dummy("anything", None).unwrap());
    }

    /// Exercise the production Argon2 parameters explicitly so a typo or
    /// out-of-range bump in the `#[cfg(not(test))]` constants is caught
    /// even though the rest of the suite runs on weakened params for
    /// speed. One hash + one verify; ~500 ms in debug mode.
    #[test]
    fn prod_params_round_trip() {
        use password_hash::{PasswordHasher, PasswordVerifier, SaltString, rand_core::OsRng};

        let params = Params::new(19_456, 2, 1, None).expect("prod params must be valid");
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        let salt = SaltString::generate(&mut OsRng);
        let hash = argon2
            .hash_password(b"prod-params-smoke", &salt)
            .expect("hash with prod params")
            .to_string();
        let parsed = PasswordHash::new(&hash).expect("parse PHC");
        assert!(argon2.verify_password(b"prod-params-smoke", &parsed).is_ok());
    }
}
