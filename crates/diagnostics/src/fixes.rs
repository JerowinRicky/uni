use crate::types::{DeclaredFix, DiagnosticCategory};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use universalrun_common::error::{Result, UniversalRunError};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FixCatalog {
    pub fixes: HashMap<String, DeclaredFix>,
}

impl FixCatalog {
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let content = fs::read_to_string(path).map_err(UniversalRunError::Io)?;
        Self::from_toml_str(&content)
    }

    pub fn from_toml_str(content: &str) -> Result<Self> {
        let fixes: HashMap<String, DeclaredFix> = toml::from_str(content).map_err(|e| {
            UniversalRunError::Analyzer(format!("Failed to parse fixes catalog TOML: {}", e))
        })?;
        Ok(Self { fixes })
    }

    pub fn get(&self, id: &str) -> Option<&DeclaredFix> {
        self.fixes.get(id)
    }

    /// Retrieve recommended fixes for a given category and evidence context.
    pub fn lookup_fixes(
        &self,
        category: DiagnosticCategory,
        evidence: &[String],
    ) -> Vec<DeclaredFix> {
        let mut results = Vec::new();

        let evidence_blob = evidence.join(" ").to_ascii_lowercase();

        match category {
            DiagnosticCategory::MissingDependency => {
                if evidence_blob.contains("msvcp") || evidence_blob.contains("vcruntime") {
                    if let Some(f) = self.get("missing_vcredist") {
                        results.push(f.clone());
                    }
                }
                if evidence_blob.contains("mscorlib")
                    || evidence_blob.contains("clr")
                    || evidence_blob.contains(".net")
                {
                    if let Some(f) = self.get("missing_dotnet") {
                        results.push(f.clone());
                    }
                }
            }
            DiagnosticCategory::MissingDllOrApi => {
                if let Some(f) = self.get("dll_native_override") {
                    results.push(f.clone());
                }
            }
            DiagnosticCategory::GraphicsError => {
                if let Some(f) = self.get("enable_dxvk") {
                    results.push(f.clone());
                }
                if let Some(f) = self.get("enable_virtual_desktop") {
                    results.push(f.clone());
                }
            }
            DiagnosticCategory::PermissionDenial
                if evidence_blob.contains("network")
                    || evidence_blob.contains("socket")
                    || evidence_blob.contains("connect") =>
            {
                if let Some(f) = self.get("grant_network_permission") {
                    results.push(f.clone());
                }
            }
            _ => {}
        }

        results
    }
}

