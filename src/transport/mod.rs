//! Transport abstractions.
//!
//! Provides a uniform interface over the four supported transport combinations:
//!
//! | Agent side  | Upstream side |
//! |-------------|---------------|
//! | stdio       | stdio         |
//! | stdio       | HTTPS         |
//! | HTTP        | stdio         |
//! | HTTP        | HTTPS         |
//!
//! The policy engine and audit logger are transport-agnostic; they depend only
//! on the trait interfaces defined here.
//!
//! Stub — full implementation across Stories 1.5–1.7.

pub mod agent_http;
pub mod agent_stdio;
pub mod upstream_https;
pub mod upstream_stdio;
