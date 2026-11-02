pub mod bundle;
pub mod classifier;
pub mod fixes;
pub mod scrubbing;
pub mod types;

pub use bundle::BundleBuilder;
pub use classifier::{LogClassifier, MAX_LOG_SIZE_BYTES};
pub use fixes::FixCatalog;
pub use scrubbing::{PiiScrubber, SAFE_ENV_ALLOWLIST};
pub use types::{
    DeclaredFix, DiagnosticCategory, DiagnosticConfidence, DiagnosticReport, RiskLevel,
};

#[cfg(test)]
mod tests;
