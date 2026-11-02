use serde::{Deserialize, Serialize};

pub const SCHEMA_VERSION: &str = "1.0.0";

/// Confidence tag indicating the certainty of an analyzer finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    /// Explicitly declared in PE headers, manifest, or verified tables.
    Certain,
    /// Detected via heuristics, pattern matching, strings, or unconfirmed structures.
    Likely,
    /// Could not be definitively determined through static analysis alone.
    Unknown,
}

/// A wrapper around a discovered value tagged with its analytical confidence level.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Finding<T> {
    pub value: T,
    pub confidence: Confidence,
    pub note: Option<String>,
}

impl<T> Finding<T> {
    pub fn certain(value: T) -> Self {
        Self {
            value,
            confidence: Confidence::Certain,
            note: None,
        }
    }

    pub fn likely(value: T, note: impl Into<String>) -> Self {
        Self {
            value,
            confidence: Confidence::Likely,
            note: Some(note.into()),
        }
    }

    pub fn unknown(value: T, note: impl Into<String>) -> Self {
        Self {
            value,
            confidence: Confidence::Unknown,
            note: Some(note.into()),
        }
    }
}

/// Target CPU architecture.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Architecture {
    X86,
    X64,
    Arm64,
    Unknown,
}

impl std::fmt::Display for Architecture {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::X86 => write!(f, "x86 (32-bit)"),
            Self::X64 => write!(f, "x86_64 (64-bit)"),
            Self::Arm64 => write!(f, "ARM64"),
            Self::Unknown => write!(f, "Unknown"),
        }
    }
}

/// Windows Subsystem.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Subsystem {
    WindowsGui,
    WindowsCui,
    Native,
    PosixCui,
    WindowsCeGui,
    EfiApplication,
    Unknown,
}

/// Execution level requested in application manifest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ExecutionLevel {
    AsInvoker,
    HighestAvailable,
    RequireAdministrator,
    Unknown,
}

/// Authenticode signature verification status.
/// Note: Never label an app "signed" on presence alone.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthenticodeReport {
    /// Whether an Authenticode signature directory / PKCS#7 block is present.
    pub signature_present: bool,
    /// Whether the file digest matches the signed digest. None if signature was unparsed.
    pub file_hash_verified: Option<bool>,
    /// Trust chain validation status against local or system trust store.
    pub chain_trust: ChainTrust,
    /// Extracted publisher / signer subject common name, if available.
    pub publisher: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ChainTrust {
    Trusted,
    Untrusted,
    Unknown,
}

/// Installer type classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InstallerKind {
    Portable,
    Msi,
    Nsis,
    InnoSetup,
    InstallShield,
    Unknown,
}

/// .NET CLR metadata analysis.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DotNetReport {
    pub is_dotnet: bool,
    pub flavor: DotNetFlavor,
    pub target_framework: Option<String>,
    pub confidence: Confidence,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DotNetFlavor {
    Framework,
    ModernDotNet,
    Unknown,
}

/// Detected Graphics APIs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum GraphicsApi {
    Direct3D9,
    Direct3D10,
    Direct3D11,
    Direct3D12,
    OpenGL,
    Vulkan,
}

/// Overall categorical compatibility rating.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RatingCategory {
    Excellent,
    Good,
    Partial,
    Experimental,
    Unsupported,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompatibilityRating {
    pub category: RatingCategory,
    pub summary: String,
    pub evidence: Vec<String>,
}

/// Comprehensive static analysis report for dropped executable or installer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnalysisReport {
    pub schema_version: String,
    pub file_name: String,
    pub file_size_bytes: u64,
    pub sha256: String,
    pub architecture: Architecture,
    pub subsystem: Subsystem,
    pub entry_point: Option<u64>,
    pub num_sections: usize,
    pub imports: Vec<ImportSummary>,
    pub delay_load_imports: Vec<String>,
    pub execution_level: Finding<ExecutionLevel>,
    pub authenticode: AuthenticodeReport,
    pub installer_type: Finding<InstallerKind>,
    pub installer_version: Option<String>,
    pub dotnet: Option<DotNetReport>,
    pub graphics_apis: Vec<Finding<GraphicsApi>>,
    pub required_runtimes: Vec<Finding<String>>,
    pub security_flags: SecurityFlags,
    pub compatibility_rating: CompatibilityRating,
    pub unverifiable_aspects: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImportSummary {
    pub dll_name: String,
    pub function_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecurityFlags {
    pub requests_admin: bool,
    pub has_drivers_or_services: bool,
    pub known_anticheat_or_drm: Option<String>,
}
