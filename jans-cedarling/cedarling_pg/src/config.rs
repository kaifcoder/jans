use crate::error::CedarlingError;
use pgrx::prelude::*;
use std::sync::{OnceLock, RwLock};

#[derive(Debug, Clone)]
pub enum OperationMode {
    Enforcement,
    Instrumentation,
    Shadow,
}

impl std::str::FromStr for OperationMode {
    type Err = CedarlingError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "enforcement" => Ok(OperationMode::Enforcement),
            "instrumentation" => Ok(OperationMode::Instrumentation),
            "shadow" => Ok(OperationMode::Shadow),
            _ => Err(CedarlingError::Configuration(format!(
                "Invalid operation mode: {}. Must be 'enforcement', 'instrumentation', or 'shadow'",
                s
            ))),
        }
    }
}

#[derive(Debug, Clone)]
pub enum FailMode {
    Closed,
    Open,
}

impl std::str::FromStr for FailMode {
    type Err = CedarlingError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "closed" => Ok(FailMode::Closed),
            "open" => Ok(FailMode::Open),
            _ => Err(CedarlingError::Configuration(format!(
                "Invalid fail mode: {}. Must be 'closed' or 'open'",
                s
            ))),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ExtensionConfig {
    pub mode: OperationMode,
    pub fail_mode: FailMode,
}

impl Default for ExtensionConfig {
    fn default() -> Self {
        Self {
            mode: OperationMode::Enforcement,
            fail_mode: FailMode::Closed,
        }
    }
}

static CONFIG: OnceLock<ExtensionConfig> = OnceLock::new();

pub fn initialize() -> Result<(), CedarlingError> {
    let config = ExtensionConfig::default();

    CONFIG.set(config).map_err(|_| {
        CedarlingError::Configuration("Failed to initialize configuration".to_string())
    })?;

    pgrx::info!("Configuration system initialized");
    Ok(())
}

pub fn get_config() -> Option<&'static ExtensionConfig> {
    CONFIG.get()
}

pub fn get_fail_mode() -> FailMode {
    match get_config_value("cedarling.fail_mode") {
        Some(fail_mode_str) => fail_mode_str.parse().unwrap_or(FailMode::Closed),
        None => FailMode::Closed,
    }
}

pub fn get_operation_mode() -> OperationMode {
    match get_config_value("cedarling.mode") {
        Some(mode_str) => mode_str.parse().unwrap_or(OperationMode::Enforcement),
        None => OperationMode::Enforcement,
    }
}

pub fn get_config_value(setting_name: &str) -> Option<String> {
    match Spi::get_one::<String>(&format!("SELECT current_setting('{}', true)", setting_name)) {
        Ok(Some(value)) if !value.is_empty() => Some(value),
        _ => None,
    }
}
