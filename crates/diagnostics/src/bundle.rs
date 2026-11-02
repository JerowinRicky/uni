use crate::classifier::MAX_LOG_SIZE_BYTES;
use crate::scrubbing::PiiScrubber;
use crate::types::DiagnosticReport;
use std::fs;
use std::path::{Path, PathBuf};
use universalrun_common::error::{Result, UniversalRunError};
use universalrun_profile_manager::ProfileManifest;

pub struct BundleBuilder {
    scrubber: PiiScrubber,
}

impl BundleBuilder {
    pub fn new() -> Self {
        Self {
            scrubber: PiiScrubber::new(),
        }
    }

    /// Build a sanitized diagnostic bundle directory.
    ///
    /// Safety rules:
    /// - Refuses to overwrite existing files or non-empty directories.
    /// - Enforces 10MB maximum input log size cap.
    /// - Scrubs tokens, emails, IPs, UNC paths, and usernames.
    /// - Scrubs environment variables via strict allowlist.
    pub fn build_bundle(
        &self,
        raw_log_path: &Path,
        manifest: &ProfileManifest,
        report: &DiagnosticReport,
        out_dir: &Path,
    ) -> Result<PathBuf> {
        // Refuse to overwrite existing directory
        if out_dir.exists() {
            let is_empty = fs::read_dir(out_dir)
                .map(|mut i| i.next().is_none())
                .unwrap_or(false);
            if !is_empty {
                return Err(UniversalRunError::Analyzer(format!(
                    "Output bundle path '{}' already exists: refusing to overwrite existing files",
                    out_dir.display()
                )));
            }
        } else {
            fs::create_dir_all(out_dir).map_err(UniversalRunError::Io)?;
        }

        // Read log with size cap
        let log_metadata = fs::metadata(raw_log_path).map_err(UniversalRunError::Io)?;
        let log_bytes = if log_metadata.len() > MAX_LOG_SIZE_BYTES as u64 {
            let bytes = fs::read(raw_log_path).map_err(UniversalRunError::Io)?;
            bytes[bytes.len() - MAX_LOG_SIZE_BYTES..].to_vec()
        } else {
            fs::read(raw_log_path).map_err(UniversalRunError::Io)?
        };

        let raw_log_str = String::from_utf8_lossy(&log_bytes);
        let scrubbed_log = self.scrubber.scrub_text(&raw_log_str);

        // Scrub manifest
        let scrubbed_manifest = self.scrubber.scrub_manifest(manifest);

        // Generic host system summary (no usernames or host paths)
        let system_info = serde_json::json!({
            "os": std::env::consts::OS,
            "arch": std::env::consts::ARCH,
            "universalrun_version": env!("CARGO_PKG_VERSION")
        });

        // Write bundle files
        fs::write(out_dir.join("scrubbed_log.txt"), scrubbed_log)
            .map_err(UniversalRunError::Io)?;

        let manifest_json = serde_json::to_string_pretty(&scrubbed_manifest)
            .map_err(|e| UniversalRunError::Analyzer(format!("Failed to serialize manifest: {}", e)))?;
        fs::write(out_dir.join("profile_manifest.json"), manifest_json)
            .map_err(UniversalRunError::Io)?;

        let report_json = serde_json::to_string_pretty(report)
            .map_err(|e| UniversalRunError::Analyzer(format!("Failed to serialize report: {}", e)))?;
        fs::write(out_dir.join("diagnostic_report.json"), report_json)
            .map_err(UniversalRunError::Io)?;

        let sys_info_json = serde_json::to_string_pretty(&system_info)
            .map_err(|e| UniversalRunError::Analyzer(format!("Failed to serialize system info: {}", e)))?;
        fs::write(out_dir.join("system_info.json"), sys_info_json)
            .map_err(UniversalRunError::Io)?;

        Ok(out_dir.to_path_buf())
    }
}

impl Default for BundleBuilder {
    fn default() -> Self {
        Self::new()
    }
}

