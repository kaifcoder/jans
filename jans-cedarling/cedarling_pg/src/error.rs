use chrono::{DateTime, Utc};
use pgrx::prelude::*;
use serde::{Deserialize, Serialize};
use std::fmt;
use thiserror::Error;

/// Comprehensive error types for the Cedarling PostgreSQL Extension
#[derive(Error, Debug, Clone, Serialize, Deserialize)]
pub enum CedarlingError {
    #[error("Token validation failed: {0}")]
    TokenValidation(String),

    #[error("Resource construction failed: {0}")]
    ResourceConstruction(String),

    #[error("Policy evaluation failed: {0}")]
    PolicyEvaluation(String),

    #[error("Configuration error: {0}")]
    Configuration(String),

    #[error("System error: {0}")]
    System(String),

    #[error("Cache operation failed: {0}")]
    Cache(String),

    #[error("JSON parsing failed: {0}")]
    JsonParsing(String),

    #[error("Database operation failed: {0}")]
    Database(String),

    #[error("Authorization denied: {0}")]
    AuthorizationDenied(String),

    #[error("Policy loading failed: {0}")]
    PolicyLoading(String),

    #[error("Schema validation failed: {0}")]
    SchemaValidation(String),

    #[error("Network operation failed: {0}")]
    Network(String),

    #[error("Timeout occurred: {0}")]
    Timeout(String),
}

impl CedarlingError {
    /// Determine if this error should result in access denial
    pub fn should_deny(&self) -> bool {
        match self {
            // Security-critical errors always deny
            CedarlingError::TokenValidation(_) => true,
            CedarlingError::AuthorizationDenied(_) => true,
            CedarlingError::PolicyEvaluation(_) => true,

            // System errors depend on fail mode
            CedarlingError::System(_) => true,
            CedarlingError::Database(_) => true,
            CedarlingError::Network(_) => true,
            CedarlingError::Timeout(_) => true,
            CedarlingError::PolicyLoading(_) => true,

            // Configuration errors are serious
            CedarlingError::Configuration(_) => true,
            CedarlingError::SchemaValidation(_) => true,

            // Data processing errors might be recoverable
            CedarlingError::ResourceConstruction(_) => false,
            CedarlingError::JsonParsing(_) => false,
            CedarlingError::Cache(_) => false,
        }
    }

    /// Get the appropriate log level for this error
    pub fn log_level(&self) -> LogLevel {
        match self {
            // Security issues are critical
            CedarlingError::TokenValidation(_) => LogLevel::Error,
            CedarlingError::AuthorizationDenied(_) => LogLevel::Info, // Normal operation

            // Policy issues are serious
            CedarlingError::PolicyEvaluation(_) => LogLevel::Error,
            CedarlingError::PolicyLoading(_) => LogLevel::Error,
            CedarlingError::SchemaValidation(_) => LogLevel::Error,

            // System issues are warnings or errors
            CedarlingError::System(_) => LogLevel::Warning,
            CedarlingError::Database(_) => LogLevel::Error,
            CedarlingError::Network(_) => LogLevel::Warning,
            CedarlingError::Timeout(_) => LogLevel::Warning,
            CedarlingError::Configuration(_) => LogLevel::Error,

            // Data processing issues are usually warnings
            CedarlingError::ResourceConstruction(_) => LogLevel::Warning,
            CedarlingError::JsonParsing(_) => LogLevel::Warning,
            CedarlingError::Cache(_) => LogLevel::Debug,
        }
    }

    /// Get error category for metrics and audit
    pub fn category(&self) -> &'static str {
        match self {
            CedarlingError::TokenValidation(_) => "token_validation",
            CedarlingError::ResourceConstruction(_) => "resource_construction",
            CedarlingError::PolicyEvaluation(_) => "policy_evaluation",
            CedarlingError::Configuration(_) => "configuration",
            CedarlingError::System(_) => "system",
            CedarlingError::Cache(_) => "cache",
            CedarlingError::JsonParsing(_) => "json_parsing",
            CedarlingError::Database(_) => "database",
            CedarlingError::AuthorizationDenied(_) => "authorization_denied",
            CedarlingError::PolicyLoading(_) => "policy_loading",
            CedarlingError::SchemaValidation(_) => "schema_validation",
            CedarlingError::Network(_) => "network",
            CedarlingError::Timeout(_) => "timeout",
        }
    }

    /// Create audit log entry for this error
    pub fn to_audit_log(&self, context: Option<&str>) -> AuditLogEntry {
        AuditLogEntry {
            timestamp: Utc::now(),
            error_id: uuid::Uuid::new_v4().to_string(),
            category: self.category().to_string(),
            message: self.to_string(),
            context: context.map(|s| s.to_string()),
            should_deny: self.should_deny(),
            log_level: format!("{:?}", self.log_level()),
        }
    }

    /// Log this error with appropriate level and audit trail
    pub fn log_with_audit(&self, context: Option<&str>) {
        let audit_entry = self.to_audit_log(context);

        // Log to PostgreSQL log with appropriate level
        match self.log_level() {
            LogLevel::Debug => pgrx::debug1!("[{}] {}", audit_entry.error_id, self),
            LogLevel::Info => pgrx::info!("[{}] {}", audit_entry.error_id, self),
            LogLevel::Warning => pgrx::warning!("[{}] {}", audit_entry.error_id, self),
            LogLevel::Error => pgrx::error!("[{}] {}", audit_entry.error_id, self),
        }

        // Store in audit log (TODO: implement persistent audit storage)
        store_audit_entry(audit_entry);
    }
}

/// Log levels for error reporting
#[derive(Debug, Clone)]
pub enum LogLevel {
    Debug,
    Info,
    Warning,
    Error,
}

/// Audit log entry for comprehensive error tracking
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditLogEntry {
    pub timestamp: DateTime<Utc>,
    pub error_id: String,
    pub category: String,
    pub message: String,
    pub context: Option<String>,
    pub should_deny: bool,
    pub log_level: String,
}

impl AuditLogEntry {
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "timestamp": self.timestamp.to_rfc3339(),
            "error_id": self.error_id,
            "category": self.category,
            "message": self.message,
            "context": self.context,
            "should_deny": self.should_deny,
            "log_level": self.log_level
        })
    }
}

/// Store audit entry (placeholder for now)
fn store_audit_entry(_entry: AuditLogEntry) {
    // TODO: Implement persistent audit storage
    // This could be:
    // - PostgreSQL table for audit logs
    // - External logging system
    // - File-based audit trail
}

impl From<serde_json::Error> for CedarlingError {
    fn from(error: serde_json::Error) -> Self {
        CedarlingError::JsonParsing(error.to_string())
    }
}

impl From<pgrx::spi::Error> for CedarlingError {
    fn from(error: pgrx::spi::Error) -> Self {
        CedarlingError::System(format!("SPI error: {}", error))
    }
}
