//! Authentication primitives — password hashing, HMAC signing, bootstrap.
//!
//! This module is the foundation layer of the auth stack (Plan 3, BE-1).
//! JWT, refresh tokens, and request extractors land in subsequent increments.

pub mod audit;
pub mod bootstrap;
pub mod extractors;
pub mod hmac;
pub mod jwt;
pub mod password;
pub mod rate_limit;
pub mod refresh;
