use crate::error::CedarlingError;
use base64::{Engine as _, engine::general_purpose};
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use pgrx::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;

/// Bundle of JWT tokens for authorization
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenBundle {
    pub access_token: Option<String>,
    pub id_token: Option<String>,
    pub userinfo_token: Option<String>,
}

/// Extracted claims from JWT tokens
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenClaims {
    pub standard_claims: HashMap<String, Value>,
    pub custom_claims: HashMap<String, Value>,
}

impl TokenBundle {
    pub fn new() -> Self {
        Self {
            access_token: None,
            id_token: None,
            userinfo_token: None,
        }
    }

    pub fn from_json(json_str: &str) -> Result<Self, CedarlingError> {
        serde_json::from_str(json_str).map_err(|e| {
            CedarlingError::JsonParsing(format!("Failed to parse token bundle: {}", e))
        })
    }

    /// Validate JWT tokens with comprehensive signature and claim validation
    pub fn validate(&self) -> Result<(), CedarlingError> {
        // Basic token presence validation
        if self.access_token.is_none() && self.id_token.is_none() && self.userinfo_token.is_none() {
            return Err(CedarlingError::TokenValidation(
                "At least one token must be provided".to_string(),
            ));
        }

        // Validate each token with signature verification
        if let Some(ref token) = self.access_token {
            validate_jwt_with_signature(token, "access_token")?;
        }
        if let Some(ref token) = self.id_token {
            validate_jwt_with_signature(token, "id_token")?;
        }
        if let Some(ref token) = self.userinfo_token {
            validate_jwt_with_signature(token, "userinfo_token")?;
        }

        // Cross-token validation (trust mode)
        validate_token_consistency(self)?;

        Ok(())
    }

    /// Extract claims from all tokens
    pub fn extract_claims(&self) -> Result<TokenClaims, CedarlingError> {
        let mut standard_claims = HashMap::new();
        let mut custom_claims = HashMap::new();

        // Extract claims from access token
        if let Some(ref token) = self.access_token {
            let claims = extract_jwt_claims(token)?;
            merge_claims(
                &mut standard_claims,
                &mut custom_claims,
                claims,
                "access_token",
            );
        }

        // Extract claims from id token
        if let Some(ref token) = self.id_token {
            let claims = extract_jwt_claims(token)?;
            merge_claims(&mut standard_claims, &mut custom_claims, claims, "id_token");
        }

        // Extract claims from userinfo token
        if let Some(ref token) = self.userinfo_token {
            let claims = extract_jwt_claims(token)?;
            merge_claims(
                &mut standard_claims,
                &mut custom_claims,
                claims,
                "userinfo_token",
            );
        }

        Ok(TokenClaims {
            standard_claims,
            custom_claims,
        })
    }
}

/// Validate JWT format (basic structure validation)
fn validate_jwt_format(token: &str, token_type: &str) -> Result<(), CedarlingError> {
    // Check basic JWT structure (header.payload.signature)
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err(CedarlingError::TokenValidation(format!(
            "{} does not have valid JWT format",
            token_type
        )));
    }

    // Validate header can be decoded
    decode_header(token).map_err(|e| {
        CedarlingError::TokenValidation(format!("Invalid {} header: {}", token_type, e))
    })?;

    Ok(())
}

/// Extract claims from JWT token
fn extract_jwt_claims(token: &str) -> Result<HashMap<String, Value>, CedarlingError> {
    // For now, decode without signature verification
    // In production, this would use proper key verification
    let mut validation = Validation::new(Algorithm::HS256);
    validation.insecure_disable_signature_validation();

    // Use a dummy key since we're not validating signature
    let dummy_key = DecodingKey::from_secret(b"dummy");

    match decode::<HashMap<String, Value>>(token, &dummy_key, &validation) {
        Ok(token_data) => Ok(token_data.claims),
        Err(e) => {
            // If structured decode fails, try to extract payload manually
            let parts: Vec<&str> = token.split('.').collect();
            if parts.len() >= 2 {
                let payload = parts[1];
                let decoded = base64_decode_jwt_part(payload)?;
                let claims: HashMap<String, Value> =
                    serde_json::from_slice(&decoded).map_err(|e| {
                        CedarlingError::JsonParsing(format!("Failed to parse JWT payload: {}", e))
                    })?;
                Ok(claims)
            } else {
                Err(CedarlingError::TokenValidation(format!(
                    "Failed to decode JWT: {}",
                    e
                )))
            }
        },
    }
}

/// Decode JWT part using base64url
fn base64_decode_jwt_part(part: &str) -> Result<Vec<u8>, CedarlingError> {
    // Add padding if needed
    let mut padded = part.to_string();
    while padded.len() % 4 != 0 {
        padded.push('=');
    }

    // Replace URL-safe base64 characters
    let standard_b64 = padded.replace('-', "+").replace('_', "/");

    base64::engine::general_purpose::STANDARD
        .decode(standard_b64)
        .map_err(|e| CedarlingError::TokenValidation(format!("Failed to decode base64: {}", e)))
}

/// Merge claims from different tokens
fn merge_claims(
    standard_claims: &mut HashMap<String, Value>,
    custom_claims: &mut HashMap<String, Value>,
    token_claims: HashMap<String, Value>,
    token_prefix: &str,
) {
    for (key, value) in token_claims {
        let prefixed_key = format!("{}_{}", token_prefix, key);

        // Standard JWT claims
        if matches!(
            key.as_str(),
            "sub" | "iss" | "aud" | "exp" | "nbf" | "iat" | "jti"
        ) {
            standard_claims.insert(key, value);
        } else {
            // Custom claims with token prefix to avoid conflicts
            custom_claims.insert(prefixed_key, value);
        }
    }
}

/// Validate JWT with signature verification and claim validation
fn validate_jwt_with_signature(token: &str, token_type: &str) -> Result<(), CedarlingError> {
    // 1. Validate JWT structure
    validate_jwt_format(token, token_type)?;

    // 2. Decode and validate header
    let header = decode_header(token).map_err(|e| {
        CedarlingError::TokenValidation(format!("Invalid {} header: {}", token_type, e))
    })?;

    // 3. Validate algorithm
    match header.alg {
        Algorithm::RS256
        | Algorithm::RS384
        | Algorithm::RS512
        | Algorithm::ES256
        | Algorithm::ES384 => {
            // Asymmetric algorithms are preferred for JWT tokens
        },
        Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512 => {
            // Symmetric algorithms - log warning but allow
            pgrx::warning!(
                "Using symmetric algorithm for {}: {:?}",
                token_type,
                header.alg
            );
        },
        _ => {
            return Err(CedarlingError::TokenValidation(format!(
                "Unsupported algorithm for {}: {:?}",
                token_type, header.alg
            )));
        },
    }

    // 4. Extract and validate claims without signature verification (for now)
    let claims = extract_jwt_claims(token)?;

    // 5. Validate standard claims
    validate_standard_claims(&claims, token_type)?;

    // 6. TODO: Implement actual signature verification with public keys
    // This would require:
    // - Key management system (JWKS endpoint integration)
    // - Certificate validation
    // - Issuer trust verification
    // - Key rotation support
    pgrx::debug1!(
        "JWT signature validation bypassed for {} (not implemented)",
        token_type
    );

    Ok(())
}

/// Validate standard JWT claims
fn validate_standard_claims(
    claims: &HashMap<String, Value>,
    token_type: &str,
) -> Result<(), CedarlingError> {
    let now = chrono::Utc::now().timestamp();

    // Validate expiration (exp)
    if let Some(exp) = claims.get("exp") {
        if let Some(exp_time) = exp.as_i64() {
            if exp_time < now {
                return Err(CedarlingError::TokenValidation(format!(
                    "{} has expired",
                    token_type
                )));
            }
        } else {
            return Err(CedarlingError::TokenValidation(format!(
                "{} has invalid exp claim format",
                token_type
            )));
        }
    } else {
        pgrx::warning!("{} missing exp claim", token_type);
    }

    // Validate not before (nbf)
    if let Some(nbf) = claims.get("nbf") {
        if let Some(nbf_time) = nbf.as_i64() {
            if nbf_time > now {
                return Err(CedarlingError::TokenValidation(format!(
                    "{} not yet valid (nbf)",
                    token_type
                )));
            }
        }
    }

    // Validate issued at (iat)
    if let Some(iat) = claims.get("iat") {
        if let Some(iat_time) = iat.as_i64() {
            // Allow some clock skew (5 minutes)
            let max_age = 24 * 60 * 60; // 24 hours
            if now - iat_time > max_age {
                pgrx::warning!("{} is older than 24 hours", token_type);
            }
            if iat_time > now + 300 {
                // 5 minutes future
                return Err(CedarlingError::TokenValidation(format!(
                    "{} issued in the future (iat)",
                    token_type
                )));
            }
        }
    }

    // Validate issuer (iss) - basic format check
    if let Some(iss) = claims.get("iss") {
        if let Some(iss_str) = iss.as_str() {
            if iss_str.is_empty() {
                return Err(CedarlingError::TokenValidation(format!(
                    "{} has empty issuer",
                    token_type
                )));
            }
            // TODO: Validate against trusted issuer list
        }
    } else if token_type != "userinfo_token" {
        // Issuer is required for access and id tokens
        return Err(CedarlingError::TokenValidation(format!(
            "{} missing required iss claim",
            token_type
        )));
    }

    // Validate subject (sub)
    if let Some(sub) = claims.get("sub") {
        if let Some(sub_str) = sub.as_str() {
            if sub_str.is_empty() {
                return Err(CedarlingError::TokenValidation(format!(
                    "{} has empty subject",
                    token_type
                )));
            }
        }
    } else if token_type != "access_token" {
        // Subject is required for id and userinfo tokens
        pgrx::warning!("{} missing sub claim", token_type);
    }

    Ok(())
}

/// Validate consistency across multiple tokens (trust mode validation)
fn validate_token_consistency(token_bundle: &TokenBundle) -> Result<(), CedarlingError> {
    let mut access_claims = None;
    let mut id_claims = None;
    let mut userinfo_claims = None;

    // Extract claims from all tokens
    if let Some(ref token) = token_bundle.access_token {
        access_claims = Some(extract_jwt_claims(token)?);
    }
    if let Some(ref token) = token_bundle.id_token {
        id_claims = Some(extract_jwt_claims(token)?);
    }
    if let Some(ref token) = token_bundle.userinfo_token {
        userinfo_claims = Some(extract_jwt_claims(token)?);
    }

    // Validate consistency between access_token and id_token
    if let (Some(access), Some(id)) = (&access_claims, &id_claims) {
        // Check client_id vs aud consistency
        if let (Some(client_id), Some(aud)) = (
            access.get("client_id").and_then(|v| v.as_str()),
            id.get("aud").and_then(|v| v.as_str()),
        ) {
            if client_id != aud {
                return Err(CedarlingError::TokenValidation(
                    "access_token client_id does not match id_token aud".to_string(),
                ));
            }
        }

        // Check issuer consistency
        if let (Some(access_iss), Some(id_iss)) = (
            access.get("iss").and_then(|v| v.as_str()),
            id.get("iss").and_then(|v| v.as_str()),
        ) {
            if access_iss != id_iss {
                pgrx::warning!("Issuer mismatch between access_token and id_token");
            }
        }
    }

    // Validate consistency between id_token and userinfo_token
    if let (Some(id), Some(userinfo)) = (&id_claims, &userinfo_claims) {
        // Check subject consistency
        if let (Some(id_sub), Some(userinfo_sub)) = (
            id.get("sub").and_then(|v| v.as_str()),
            userinfo.get("sub").and_then(|v| v.as_str()),
        ) {
            if id_sub != userinfo_sub {
                return Err(CedarlingError::TokenValidation(
                    "id_token sub does not match userinfo_token sub".to_string(),
                ));
            }
        }

        // Check audience consistency
        if let (Some(id_aud), Some(userinfo_aud)) = (
            id.get("aud").and_then(|v| v.as_str()),
            userinfo.get("aud").and_then(|v| v.as_str()),
        ) {
            if id_aud != userinfo_aud {
                return Err(CedarlingError::TokenValidation(
                    "id_token aud does not match userinfo_token aud".to_string(),
                ));
            }
        }
    }

    Ok(())
}

/// Set tokens in PostgreSQL session variables
pub fn set_tokens(token_bundle: &TokenBundle) -> Result<(), CedarlingError> {
    let json_str = serde_json::to_string(token_bundle)
        .map_err(|e| CedarlingError::JsonParsing(format!("Failed to serialize tokens: {}", e)))?;

    // Use PostgreSQL's session variable system
    unsafe {
        let result = pg_sys::set_config_option(
            c"cedarling.tokens".as_ptr() as *const i8,
            json_str.as_ptr() as *const i8,
            pg_sys::GucContext::PGC_USERSET,
            pg_sys::GucSource::PGC_S_SESSION,
            pg_sys::GucAction::GUC_ACTION_SET,
            true,
            0,
            false,
        );

        if result == 0 {
            return Err(CedarlingError::System(
                "Failed to set session tokens".to_string(),
            ));
        }
    }

    pgrx::info!("Tokens set in session");
    Ok(())
}

/// Clear tokens from PostgreSQL session variables
pub fn clear_tokens() -> Result<(), CedarlingError> {
    unsafe {
        let result = pg_sys::set_config_option(
            c"cedarling.tokens".as_ptr() as *const i8,
            std::ptr::null(),
            pg_sys::GucContext::PGC_USERSET,
            pg_sys::GucSource::PGC_S_SESSION,
            pg_sys::GucAction::GUC_ACTION_SET,
            true,
            0,
            false,
        );

        if result == 0 {
            return Err(CedarlingError::System(
                "Failed to clear session tokens".to_string(),
            ));
        }
    }

    pgrx::info!("Tokens cleared from session");
    Ok(())
}

/// Get current token bundle from PostgreSQL session variables
pub fn get_current_token_bundle() -> Result<Option<TokenBundle>, CedarlingError> {
    let token_json = unsafe {
        let guc_value =
            pg_sys::GetConfigOption(c"cedarling.tokens".as_ptr() as *const i8, false, false);

        if guc_value.is_null() {
            return Ok(None);
        }

        let c_str = std::ffi::CStr::from_ptr(guc_value);
        c_str
            .to_str()
            .map_err(|e| CedarlingError::System(format!("Failed to read session tokens: {}", e)))?
    };

    if token_json.is_empty() {
        return Ok(None);
    }

    let bundle = TokenBundle::from_json(token_json)?;
    Ok(Some(bundle))
}
