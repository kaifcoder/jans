use crate::error::CedarlingError;
use pgrx::AnyElement;
use pgrx::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::HashMap;

/// Represents a Cedar resource entity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CedarResource {
    pub entity_type: String,
    pub id: String,
    pub attributes: HashMap<String, Value>,
}

impl CedarResource {
    pub fn new(entity_type: String, id: String) -> Self {
        Self {
            entity_type,
            id,
            attributes: HashMap::new(),
        }
    }

    pub fn with_attributes(mut self, attributes: HashMap<String, Value>) -> Self {
        self.attributes = attributes;
        self
    }

    /// Convert to EntityData format expected by Cedarling
    pub fn to_entity_data(&self) -> cedarling::EntityData {
        cedarling::EntityData {
            cedar_mapping: cedarling::CedarEntityMapping {
                entity_type: self.entity_type.clone(),
                id: self.id.clone(),
            },
            attributes: self.attributes.clone(),
        }
    }
}

/// Build resource from JSON string
pub fn build_resource_from_json(resource_data: &str) -> Result<CedarResource, CedarlingError> {
    serde_json::from_str(resource_data)
        .map_err(|e| CedarlingError::JsonParsing(format!("Failed to parse resource JSON: {}", e)))
}

/// Build resource from PostgreSQL row data
pub fn build_resource_from_row(record: AnyElement) -> Result<String, CedarlingError> {
    // For now, use a simplified approach that works with pgrx 0.16
    // This avoids complex PostgreSQL internals that may have changed

    let table_name = get_table_name_from_context()?;

    // Create a basic resource with minimal attributes
    // In a real implementation, this would extract actual column data
    let mut attributes = HashMap::new();

    // Add some basic metadata that we can extract safely
    attributes.insert("_table".to_string(), Value::String(table_name.clone()));
    attributes.insert(
        "_timestamp".to_string(),
        Value::String(chrono::Utc::now().to_rfc3339()),
    );

    // TODO: Implement proper row introspection using pgrx 0.16 APIs
    // This would require understanding the new pgrx tuple handling approach

    let resource = CedarResource::new(
        table_name_to_entity_type(&table_name),
        "placeholder_id".to_string(), // TODO: Extract actual primary key
    )
    .with_attributes(attributes);

    serde_json::to_string(&resource)
        .map_err(|e| CedarlingError::JsonParsing(format!("Failed to serialize resource: {}", e)))
}

/// Generate a primary key ID from row attributes
fn generate_primary_key_id(attributes: &HashMap<String, Value>) -> String {
    // Try common primary key column names
    let pk_candidates = ["id", "uuid", "pk", "primary_key"];

    for candidate in &pk_candidates {
        if let Some(value) = attributes.get(*candidate) {
            match value {
                Value::String(s) => return s.clone(),
                Value::Number(n) => return n.to_string(),
                _ => continue,
            }
        }
    }

    // If no primary key found, generate a hash of the row data
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let mut hasher = DefaultHasher::new();
    for (key, value) in attributes {
        key.hash(&mut hasher);
        value.to_string().hash(&mut hasher);
    }

    format!("row_{}", hasher.finish())
}

/// Extract table name from PostgreSQL execution context
pub fn get_table_name_from_context() -> Result<String, CedarlingError> {
    // Simplified implementation for now
    // In pgrx 0.16, the table context extraction would be different
    Ok("current_table".to_string())
}

/// Convert PostgreSQL datum to JSON value (simplified for pgrx 0.16)
pub fn pg_datum_to_json_value(
    _datum: pg_sys::Datum,
    _typoid: pg_sys::Oid,
    is_null: bool,
) -> Result<Value, CedarlingError> {
    if is_null {
        return Ok(Value::Null);
    }

    // Simplified implementation to avoid complex pgrx internals
    // TODO: Implement proper type conversion using pgrx 0.16 APIs
    Ok(Value::String("placeholder_value".to_string()))
}

/// Convert table name to Cedar entity type
pub fn table_name_to_entity_type(table_name: &str) -> String {
    // Convert snake_case table names to PascalCase entity types
    // e.g., "user_profiles" -> "UserProfile"
    table_name
        .split('_')
        .map(|word| {
            let mut chars = word.chars();
            match chars.next() {
                None => String::new(),
                Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
            }
        })
        .collect::<String>()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_table_name_to_entity_type() {
        assert_eq!(table_name_to_entity_type("users"), "Users");
        assert_eq!(table_name_to_entity_type("user_profiles"), "UserProfiles");
        assert_eq!(table_name_to_entity_type("order_items"), "OrderItems");
    }

    #[test]
    fn test_cedar_resource_creation() {
        let resource = CedarResource::new("Document".to_string(), "doc123".to_string())
            .with_attributes(
                [
                    ("title".to_string(), json!("Test Document")),
                    ("department".to_string(), json!("Engineering")),
                ]
                .into_iter()
                .collect(),
            );

        assert_eq!(resource.entity_type, "Document");
        assert_eq!(resource.id, "doc123");
        assert_eq!(resource.attributes.len(), 2);
    }
}
