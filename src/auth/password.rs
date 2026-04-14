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
const ARGON2_M_COST_KIB: u32 = 19_456;
const ARGON2_T_COST: u32 = 2;
const ARGON2_P_COST: u32 = 1;

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
}
