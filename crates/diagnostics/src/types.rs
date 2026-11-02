use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiagnosticCategory {
    MissingDependency,
    MissingDllOrApi,
    GraphicsError,
    PermissionDenial,
    StartupCrash,
    HangOrTimeout,
    InstallerFailure,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiagnosticConfidence {
    Certain,
    Likely,
    Possible,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskLevel {
    Low,
    Medium,
    High,
}

/// Declarative fix definition loaded from catalog.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeclaredFix {
    pub id: String,
    pub title: String,
    pub description: String,
    pub target_change: String,
    pub reversible: bool,
    pub risk_level: RiskLevel,
    /// Explanatory note (e.g. "[UNTESTED candidate]").
    pub status_note: Option<String>,
}

/// Complete diagnostic report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiagnosticReport {
    pub category: DiagnosticCategory,
    pub confidence: DiagnosticConfidence,
    pub summary: String,
    pub exit_code: Option<i32>,
    pub evidence_lines: Vec<String>,
    pub recommended_fixes: Vec<DeclaredFix>,
}

