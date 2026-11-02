use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use universalrun_common::error::{Result, UniversalRunError};

/// Declarative dependency definition from catalog.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DependencyEntry {
    pub id: String,
    pub name: String,
    pub version: String,
    /// Must be an HTTPS URL.
    pub source_url: String,
    /// Expected SHA-256 digest in hex, or literal "TODO" if unverified.
    pub sha256: String,
    /// Per-dependency download size cap in bytes declared in catalog.
    pub max_size_bytes: u64,
    pub license: String,
    pub provenance: String,
}

impl DependencyEntry {
    /// Return true if the entry possesses a real SHA-256 hash (not a "TODO" placeholder).
    pub fn is_verified(&self) -> bool {
        let trimmed = self.sha256.trim();
        !trimmed.is_empty() && !trimmed.eq_ignore_ascii_case("TODO")
    }
}

/// Catalog of known, verified third-party dependencies.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DependencyCatalog {
    pub dependencies: HashMap<String, DependencyEntry>,
}

impl DependencyCatalog {
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let content = fs::read_to_string(path).map_err(UniversalRunError::Io)?;
        Self::from_toml_str(&content)
    }

    pub fn from_toml_str(content: &str) -> Result<Self> {
        let raw: HashMap<String, DependencyEntry> = toml::from_str(content)
            .map_err(|e| UniversalRunError::Recipe(format!("Failed to parse catalog TOML: {}", e)))?;
        Ok(Self {
            dependencies: raw,
        })
    }

    pub fn get(&self, id: &str) -> Option<&DependencyEntry> {
        self.dependencies.get(id)
    }
}

