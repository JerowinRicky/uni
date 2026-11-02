use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use universalrun_common::error::{Result, UniversalRunError};
use universalrun_profile_manager::{DllOverrideMode, PermissionPolicy};

/// Match criteria for binding an executable to a recipe.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct MatchRules {
    /// Exact SHA-256 binary digests (highest precedence).
    #[serde(default)]
    pub sha256: Vec<String>,
    /// Product name substring or glob.
    pub product_name: Option<String>,
    /// Minimum application version.
    pub min_version: Option<String>,
    /// Maximum application version.
    pub max_version: Option<String>,
}

/// Preferred runtime and Windows environment settings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeRecipeConfig {
    pub preferred: String,
    pub min_version: String,
    pub architecture: String,
    pub windows_version: String,
}

/// Registry value data type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistryValueType {
    String,
    Dword,
}

/// Declarative registry operation (data only, no execution script).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegistryEntry {
    pub key: String,
    pub value_name: String,
    pub value_type: RegistryValueType,
    pub value_data: String,
}

/// Compatibility test farm observation record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TestedResult {
    pub date: String,
    pub test_runner: String,
    pub distro: String,
    pub wine_version: String,
    pub outcome: String,
    pub notes: Option<String>,
}

/// Cryptographic Ed25519 signature over the canonical recipe bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecipeSignature {
    /// Public key identifier used for signing (allows key rotation).
    pub key_id: String,
    /// Hex-encoded Ed25519 signature (128 hex characters = 64 bytes).
    pub signature_hex: String,
}

/// Declarative Recipe (data only, zero shell scripts).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Recipe {
    pub schema_version: String,
    pub id: String,
    /// Monotonic revision counter for downgrade protection.
    pub revision: u32,
    pub name: String,
    pub match_rules: MatchRules,
    pub runtime: RuntimeRecipeConfig,
    /// Catalog dependency IDs (e.g. "vcredist2022", "corefonts").
    #[serde(default)]
    pub dependencies: Vec<String>,
    /// DLL overrides map.
    #[serde(default)]
    pub dll_overrides: HashMap<String, DllOverrideMode>,
    /// Declarative registry entries.
    #[serde(default)]
    pub registry_entries: Vec<RegistryEntry>,
    /// Permission scoping.
    pub permissions: PermissionPolicy,
    /// Known issues or manual workaround notes.
    #[serde(default)]
    pub known_issues: Vec<String>,
    /// Verified test farm results backing compatibility claims.
    #[serde(default)]
    pub tested_results: Vec<TestedResult>,
    /// Optional signature block.
    pub signature: Option<RecipeSignature>,
}

impl Recipe {
    pub const SCHEMA_VERSION: &'static str = "1.0.0";

    /// Produce the exact canonical UTF-8 bytes that are signed.
    ///
    /// Definition:
    /// 1. The `signature` block is stripped.
    /// 2. All JSON keys are recursively sorted lexicographically (BTreeMap).
    /// 3. Serialized as compact JSON without trailing newlines or whitespace.
    pub fn compute_canonical_bytes(&self) -> Result<Vec<u8>> {
        let mut unsigned = self.clone();
        unsigned.signature = None;

        let value = serde_json::to_value(&unsigned)
            .map_err(|e| UniversalRunError::Recipe(format!("Serialization error: {}", e)))?;

        let canonical_val = sort_json_value(&value);
        let bytes = serde_json::to_vec(&canonical_val)
            .map_err(|e| UniversalRunError::Recipe(format!("Canonical JSON error: {}", e)))?;

        Ok(bytes)
    }
}

/// Recursively sorts all JSON object keys to produce a deterministic canonical representation.
fn sort_json_value(value: &serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::Object(map) => {
            let mut sorted_map = BTreeMap::new();
            for (k, v) in map {
                sorted_map.insert(k.clone(), sort_json_value(v));
            }
            serde_json::to_value(sorted_map).unwrap_or(serde_json::Value::Null)
        }
        serde_json::Value::Array(arr) => {
            let sorted_elements: Vec<serde_json::Value> =
                arr.iter().map(sort_json_value).collect();
            serde_json::Value::Array(sorted_elements)
        }
        other => other.clone(),
    }
}

