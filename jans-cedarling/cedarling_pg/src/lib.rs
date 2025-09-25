use pgrx::AnyElement;
use pgrx::prelude::*;

::pgrx::pg_module_magic!();

// Module declarations
mod authorization;
mod config;
mod error;
mod resource;
mod token;

/// Manual authorization function - for complex cases
#[pg_extern]
fn cedarling_authorized(
    resource_data: &str,
    token_bundle: &str,
) -> Result<bool, Box<dyn std::error::Error + Send + Sync + 'static>> {
    match authorization::authorize_manual(resource_data, token_bundle, "Read") {
        Ok(decision) => Ok(decision),
        Err(e) => {
            pgrx::warning!("Authorization error: {}", e);
            Ok(false) // Fail-safe: deny on error
        },
    }
}

// ============================================================================
// Extension Initialization
// ============================================================================

#[pg_guard]
pub extern "C-unwind" fn _PG_init() {
    pgrx::info!("Initializing Cedarling PostgreSQL Extension v0.1.0");

    // Initialize authorization system
    if let Err(e) = authorization::initialize_cedarling() {
        pgrx::error!("Failed to initialize authorization system: {}", e);
    }

    pgrx::info!("Cedarling PostgreSQL Extension initialized successfully");
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(any(test, feature = "pg_test"))]
#[pg_schema]
mod tests {
    use pgrx::prelude::*;
    use serde_json::json;

    #[pg_test]
    fn test_cedarling_authorized() {
        let resource = r#"{"type": "Student", "id": "1", "grad_year": 2022}"#;
        let tokens = r#"{"access_token": "test_token"}"#;

        let result = crate::cedarling_authorized(resource, tokens);
        assert!(result.is_ok());
    }
}

/// This module is required by `cargo pgrx test` invocations.
#[cfg(test)]
pub mod pg_test {
    pub fn setup(_options: Vec<&str>) {
        // perform one-off initialization when the pg_test framework starts
    }

    #[must_use]
    pub fn postgresql_conf_options() -> Vec<&'static str> {
        // return any postgresql.conf settings that are required for your tests
        vec![]
    }
}
