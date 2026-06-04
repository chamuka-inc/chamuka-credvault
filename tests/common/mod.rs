//! Shared setup for integration tests. Each test file is its own process, so each must
//! point the plugin loader at the shipped default manifests before touching the provider
//! registry — there are no built-in providers any more.
#![allow(dead_code)]

use std::sync::Once;

static INIT: Once = Once::new();

/// Load the shipped default provider plugins (`plugins/default`) into this process's
/// registry. Idempotent and thread-safe: `call_once` blocks every caller until the registry
/// is initialized, so any test may call this as its first line and then rely on
/// `providers::get(...)`. The path is relative to the crate root, which is the working
/// directory Cargo uses for integration tests.
pub fn default_plugins() {
    INIT.call_once(|| {
        std::env::set_var("VAULT_PLUGIN_DIRS", "plugins/default");
        // Force the lazy registry to initialize now, from the dir we just set.
        let _ = credvault::providers::registry();
    });
}
