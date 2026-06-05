//! credvault — multi-tenant, multi-provider credential vault.
//!
//! The load-bearing layer of an integration platform: it stores per-end-user
//! credentials for many providers across many tenants, and keeps them alive across
//! expiry, rotation, and revocation. Built in Rust so the compiler enforces the
//! security invariants (secrets can't be logged; one refresh path; tenant-bound
//! ciphertext) rather than leaving them to discipline.

pub mod config;
pub mod crypto;
pub mod db;
pub mod error;
pub mod http;
pub mod models;
pub mod oauth;
pub mod providers;
pub mod service;
pub mod state;
pub mod worker;

use std::sync::Arc;

pub use error::{Error, Result};

use crate::config::Config;
use crate::crypto::Keyring;
use crate::http::transport::TokenTransport;

/// Shared, cheaply-cloneable application state (Factor VI: state lives in the DB).
#[derive(Clone)]
pub struct AppState {
    pub pool: crate::db::Pool,
    pub keyring: Arc<Keyring>,
    pub transport: Arc<dyn TokenTransport>,
    pub cfg: Arc<Config>,
}
