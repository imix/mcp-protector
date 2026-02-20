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

pub(crate) mod agent_http;
pub(crate) mod agent_stdio;
pub(crate) mod upstream_https;
pub(crate) mod upstream_stdio;
