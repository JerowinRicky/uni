use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// DLL override modes matching Wine DLL overrides.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DllOverrideMode {
    Native,
    Builtin,
    NativeThenBuiltin,
    BuiltinThenNative,
    Disabled,
}

impl DllOverrideMode {
    pub fn to_wine_string(&self) -> &'static str {
        match self {
            DllOverrideMode::Native => "native",
            DllOverrideMode::Builtin => "builtin",
            DllOverrideMode::NativeThenBuiltin => "native,builtin",
            DllOverrideMode::BuiltinThenNative => "builtin,native",
            DllOverrideMode::Disabled => "",
        }
    }
}

/// Explicit container filesystem mapping.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FsMapping {
    /// Host source directory or file. Must be sanitized and validated at use time.
    pub host_path: String,
    /// Destination path inside the sandbox container (e.g. C:\users\steamuser\Documents).
    pub guest_path: String,
    /// Whether mapping is read-only.
    pub read_only: bool,
}

/// Explicit hardware and system resource permissions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct PermissionPolicy {
    /// Allow outbound network socket access.
    pub network: bool,
    /// Allow audio server passthrough (e.g. PulseAudio/PipeWire socket).
    pub audio: bool,
    /// Allow display server passthrough (X11 / Wayland).
    pub display: bool,
    /// Allow Direct Rendering Infrastructure (DRI / GPU) access.
    pub dri: bool,
}

/// Pinned runtime configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeConfig {
    pub name: String,
    pub version: String,
    pub architecture: String,
    pub windows_version: String,
}

/// Pinned dependency entry in a profile.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolvedDependency {
    pub id: String,
    pub version: String,
    pub sha256: String,
}

/// Declarative, reproducible profile manifest.
/// A profile can be completely reconstructed from this manifest alone.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProfileManifest {
    pub schema_version: String,
    pub profile_id: String,
    pub display_name: String,
    pub target_app: String,
    pub target_app_sha256: Option<String>,
    pub recipe_id: Option<String>,
    pub recipe_revision: Option<u32>,
    pub runtime: RuntimeConfig,
    pub dependencies: Vec<ResolvedDependency>,
    pub env_vars: HashMap<String, String>,
    pub dll_overrides: HashMap<String, DllOverrideMode>,
    pub filesystem_mappings: Vec<FsMapping>,
    pub permissions: PermissionPolicy,
    /// Wine debug channel settings (defaults to "fixme-all").
    #[serde(default)]
    pub wine_debug: Option<String>,
    /// Hash of canonical manifest fields guaranteeing deterministic reproducibility.
    pub rebuild_hash: Option<String>,
}

impl ProfileManifest {
    pub const SCHEMA_VERSION: &'static str = "1.0.0";

    /// Compute deterministic rebuild hash over canonical serialized content.
    pub fn compute_rebuild_hash(&self) -> String {
        use sha2::{Digest, Sha256};
        let mut clone = self.clone();
        clone.rebuild_hash = None; // Exclude self
        let json = serde_json::to_string(&clone).unwrap_or_default();
        let hash = Sha256::digest(json.as_bytes());
        hex::encode(hash)
    }
}

