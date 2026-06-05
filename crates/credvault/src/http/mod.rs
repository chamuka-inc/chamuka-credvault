//! The HTTP surface: the inbound axum router and its middleware (`api`, `auth`,
//! `ratelimit`) plus the outbound token transport (`transport`) used to talk to
//! provider token endpoints. Everything that speaks HTTP — in either direction —
//! lives here; the rest of the crate is transport-agnostic.

pub mod api;
pub mod auth;
pub mod ratelimit;
pub mod transport;
