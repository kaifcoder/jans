use crate::config::OperationMode;
use crate::config::get_fail_mode;
use crate::config::get_operation_mode;
use crate::error::CedarlingError;
use crate::resource::CedarResource;
use crate::token::TokenBundle;
use cedarling::{
    AuthorizationConfig, BootstrapConfig, CedarEntityMapping, EntityBuilderConfig, EntityData,
    JsonRule, JwtConfig, LogConfig, LogLevel, LogTypeConfig, PolicyStoreConfig, PolicyStoreSource,
    Request, blocking::Cedarling,
};
use chrono::{DateTime, Utc};
use pgrx::prelude::*;
use serde_json::Value;
use serde_json::json;
use std::collections::HashMap;
use std::collections::VecDeque;
use std::sync::{OnceLock, RwLock};

// Global Cedarling instance
static CEDARLING_INSTANCE: OnceLock<Cedarling> = OnceLock::new();

/// Get the global Cedarling instance
pub fn get_cedarling_instance() -> Result<&'static Cedarling, CedarlingError> {
    CEDARLING_INSTANCE
        .get()
        .ok_or_else(|| CedarlingError::System("Cedarling instance not initialized".to_string()))
}

/// Initialize the Cedarling instance during extension startup
pub fn initialize_cedarling() -> Result<(), CedarlingError> {
    // Create a minimal policy store with the correct AgamaPolicyStore structure
    let minimal_policy_store = r#"{
        "cedar_version": "v4.0.0",
        "policy_stores": {
            "minimal_store": {
                "name": "MinimalStore",
                "description": "Minimal policy store for PostgreSQL extension",
                "policies": {},
                "schema": {
                    "encoding": "none",
                    "content_type": "cedar",
                    "body": "namespace Jans {\nentity Resource;\nentity User;\nentity Workload;\naction \"Read\" appliesTo {\n  principal: [User, Workload],\n  resource: [Resource],\n  context: {}\n};\n}\n"
                }
            }
        }
    }"#;

    // Create bootstrap config with minimal dependencies
    let bootstrap_config = BootstrapConfig {
        application_name: "cedarling_pg".to_string(),
        log_config: LogConfig {
            log_type: LogTypeConfig::Off, // Disable logging to avoid complexity
            log_level: LogLevel::INFO,
        },
        policy_store_config: PolicyStoreConfig {
            source: PolicyStoreSource::Json(minimal_policy_store.to_string()),
        },
        jwt_config: JwtConfig::new_without_validation(), // Disable JWT validation initially
        authorization_config: AuthorizationConfig::default(),
        entity_builder_config: EntityBuilderConfig::default(),
        lock_config: None, // Disable lock service
    };

    let cedarling = Cedarling::new(&bootstrap_config)
        .map_err(|e| CedarlingError::System(format!("Failed to initialize Cedarling: {}", e)))?;

    CEDARLING_INSTANCE.set(cedarling).map_err(|_| {
        CedarlingError::System("Failed to set global Cedarling instance".to_string())
    })?;

    pgrx::info!("Cedarling instance initialized successfully");
    Ok(())
}

/// Core authorization function for rows
pub fn authorize_row(
    resource: &CedarResource,
    token_bundle: &TokenBundle,
    action: &str,
) -> Result<bool, CedarlingError> {
    let start_time = std::time::Instant::now();
    let cedarling = get_cedarling_instance()?;

    // Build the authorization request
    let mut tokens = std::collections::HashMap::new();
    if let Some(access_token) = &token_bundle.access_token {
        tokens.insert("access_token".to_string(), access_token.clone());
    }
    if let Some(id_token) = &token_bundle.id_token {
        tokens.insert("id_token".to_string(), id_token.clone());
    }
    if let Some(userinfo_token) = &token_bundle.userinfo_token {
        tokens.insert("userinfo_token".to_string(), userinfo_token.clone());
    }

    let request = Request {
        tokens,
        action: action.to_string(),
        resource: resource.to_entity_data(),
        context: json!({}),
    };

    // Execute authorization using blocking API
    let result = match cedarling.authorize(request) {
        Ok(result) => {
            let decision = result.decision;
            let execution_time = start_time.elapsed().as_millis() as u64;

            // Handle different operation modes
            match get_operation_mode() {
                OperationMode::Enforcement => Ok(decision),
                OperationMode::Instrumentation => {
                    // Log the decision but always allow
                    pgrx::info!(
                        "Instrumentation mode: decision={}, allowing access",
                        decision
                    );
                    Ok(true)
                },
                OperationMode::Shadow => {
                    // Log the decision but always allow
                    pgrx::debug1!("Shadow mode: decision={}, allowing access", decision);
                    Ok(true)
                },
            }
        },
        Err(e) => {
            let error_msg = format!("Authorization failed: {}", e);
            let execution_time = start_time.elapsed().as_millis() as u64;

            pgrx::warning!("{}", error_msg);

            match get_fail_mode() {
                crate::config::FailMode::Closed => Ok(false),
                crate::config::FailMode::Open => {
                    pgrx::warning!("Fail-open mode: allowing access despite error");
                    Ok(true)
                },
            }
        },
    };

    result
}

/// Manual authorization with JSON input
pub fn authorize_manual(
    resource_json: &str,
    token_json: &str,
    action: &str,
) -> Result<bool, CedarlingError> {
    let resource: CedarResource = serde_json::from_str(resource_json)
        .map_err(|e| CedarlingError::JsonParsing(format!("Invalid resource JSON: {}", e)))?;

    let token_bundle: TokenBundle = serde_json::from_str(token_json)
        .map_err(|e| CedarlingError::JsonParsing(format!("Invalid token JSON: {}", e)))?;

    authorize_row(&resource, &token_bundle, action)
}
