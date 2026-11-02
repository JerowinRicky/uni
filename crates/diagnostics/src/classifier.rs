use crate::fixes::FixCatalog;
use crate::types::{DiagnosticCategory, DiagnosticConfidence, DiagnosticReport};
use universalrun_common::error::Result;

pub const MAX_LOG_SIZE_BYTES: usize = 10 * 1024 * 1024; // 10 MB limit
pub const TAIL_WINDOW_LINES: usize = 100;

/// Classifier for Wine and Windows application process execution logs.
pub struct LogClassifier<'a> {
    catalog: &'a FixCatalog,
}

impl<'a> LogClassifier<'a> {
    pub fn new(catalog: &'a FixCatalog) -> Self {
        Self { catalog }
    }

    /// Classify raw log bytes into structured diagnostic findings.
    ///
    /// Robustness guarantees:
    /// - Strictly bounds input size to 10MB max to prevent memory exhaustion.
    /// - Decodes non-UTF-8 lossily without panicking.
    /// - Linear-time pattern scanning without catastrophic regex backtracking.
    /// - Distinguishes benign fixme/err lines on successful (exit code 0) executions.
    pub fn classify(&self, log_bytes: &[u8], exit_code: Option<i32>) -> Result<DiagnosticReport> {
        // Enforce size cap
        let bounded_bytes = if log_bytes.len() > MAX_LOG_SIZE_BYTES {
            &log_bytes[log_bytes.len() - MAX_LOG_SIZE_BYTES..]
        } else {
            log_bytes
        };

        let decoded = String::from_utf8_lossy(bounded_bytes);
        let lines: Vec<&str> = decoded.lines().collect();

        // Rule: If process exited with code 0, do not flag benign err/fixme warnings
        if exit_code == Some(0) {
            return Ok(DiagnosticReport {
                category: DiagnosticCategory::Unknown,
                confidence: DiagnosticConfidence::Certain,
                summary: "Process exited successfully with code 0. Diagnostic analyzer ignored benign Wine fixme and runtime warning lines.".to_string(),
                exit_code,
                evidence_lines: Vec::new(),
                recommended_fixes: Vec::new(),
            });
        }

        // Focus especially on log tail (where crashes/failures manifest)
        let tail_start = lines.len().saturating_sub(TAIL_WINDOW_LINES);
        let tail_lines = &lines[tail_start..];

        // 1. Missing Visual C++ or .NET Dependencies
        let mut dep_evidence = Vec::new();
        for &line in tail_lines {
            let lower = line.to_ascii_lowercase();
            let is_match = (lower.contains("msvcp") && (lower.contains("not found") || lower.contains("failed to load") || lower.contains("error")))
                || (lower.contains("vcruntime") && (lower.contains("not found") || lower.contains("failed to load")))
                || lower.contains("clr error")
                || lower.contains("could not load file or assembly 'mscorlib");
            if is_match {
                dep_evidence.push(line.trim().to_string());
            }
        }
        if !dep_evidence.is_empty() {
            let fixes = self.catalog.lookup_fixes(DiagnosticCategory::MissingDependency, &dep_evidence);
            return Ok(DiagnosticReport {
                category: DiagnosticCategory::MissingDependency,
                confidence: DiagnosticConfidence::Certain,
                summary: "Application failed due to missing runtime redistributable library (VC++ or .NET Framework CLR).".to_string(),
                exit_code,
                evidence_lines: dep_evidence,
                recommended_fixes: fixes,
            });
        }

        // 2. Missing DLL or Entry Point API
        let mut dll_evidence = Vec::new();
        for &line in tail_lines {
            let lower = line.to_ascii_lowercase();
            let is_match = lower.contains("err:module:import_dll")
                || lower.contains("status_dll_not_found")
                || lower.contains("0xc0000135")
                || (lower.contains("err:module:load_builtin_dll") && lower.contains("failed"))
                || lower.contains("entry point not found")
                || lower.contains("procedure not found");
            if is_match {
                dll_evidence.push(line.trim().to_string());
            }
        }
        if !dll_evidence.is_empty() {
            let fixes = self.catalog.lookup_fixes(DiagnosticCategory::MissingDllOrApi, &dll_evidence);
            return Ok(DiagnosticReport {
                category: DiagnosticCategory::MissingDllOrApi,
                confidence: DiagnosticConfidence::Certain,
                summary: "Application failed to start because a required Win32 DLL or API procedure entry point was missing.".to_string(),
                exit_code,
                evidence_lines: dll_evidence,
                recommended_fixes: fixes,
            });
        }

        // 3. Graphics, Vulkan, or Display Failures
        let mut gfx_evidence = Vec::new();
        for &line in tail_lines {
            let lower = line.to_ascii_lowercase();
            let is_match = lower.contains("vk_error")
                || lower.contains("vulkan:")
                || lower.contains("failed to create vulkan")
                || (lower.contains("d3d11") && (lower.contains("failed") || lower.contains("createfailed")))
                || lower.contains("could not open display")
                || lower.contains("x11 connection rejected")
                || lower.contains("wayland connection failed")
                || (lower.contains("wglcreatecontext") && lower.contains("failed"));
            if is_match {
                gfx_evidence.push(line.trim().to_string());
            }
        }
        if !gfx_evidence.is_empty() {
            let fixes = self.catalog.lookup_fixes(DiagnosticCategory::GraphicsError, &gfx_evidence);
            return Ok(DiagnosticReport {
                category: DiagnosticCategory::GraphicsError,
                confidence: DiagnosticConfidence::Likely,
                summary: "Graphics rendering or display server initialization failed.".to_string(),
                exit_code,
                evidence_lines: gfx_evidence,
                recommended_fixes: fixes,
            });
        }

        // 4. Permission / Sandbox Access Denial
        let mut perm_evidence = Vec::new();
        for &line in tail_lines {
            let lower = line.to_ascii_lowercase();
            let is_match = lower.contains("permission denied")
                || lower.contains("operation not permitted")
                || lower.contains("eacces")
                || lower.contains("network is unreachable")
                || (lower.contains("socket:") && lower.contains("denied"));
            if is_match {
                perm_evidence.push(line.trim().to_string());
            }
        }
        if !perm_evidence.is_empty() {
            let fixes = self.catalog.lookup_fixes(DiagnosticCategory::PermissionDenial, &perm_evidence);
            return Ok(DiagnosticReport {
                category: DiagnosticCategory::PermissionDenial,
                confidence: DiagnosticConfidence::Likely,
                summary: "Application attempted an operation forbidden by sandbox permission policy.".to_string(),
                exit_code,
                evidence_lines: perm_evidence,
                recommended_fixes: fixes,
            });
        }

        // 5. Startup Crash / Page Fault
        let mut crash_evidence = Vec::new();
        for &line in tail_lines {
            let lower = line.to_ascii_lowercase();
            let is_match = lower.contains("page fault")
                || lower.contains("status_access_violation")
                || lower.contains("0xc0000005")
                || lower.contains("unhandled exception")
                || lower.contains("backtrace:");
            if is_match {
                crash_evidence.push(line.trim().to_string());
            }
        }
        if !crash_evidence.is_empty() {
            return Ok(DiagnosticReport {
                category: DiagnosticCategory::StartupCrash,
                confidence: DiagnosticConfidence::Certain,
                summary: "Application crashed due to unhandled Win32 exception (Access Violation / Page Fault).".to_string(),
                exit_code,
                evidence_lines: crash_evidence,
                recommended_fixes: Vec::new(),
            });
        }

        // 6. Hang or Watchdog Timeout
        if exit_code == Some(124) || exit_code == Some(137) {
            return Ok(DiagnosticReport {
                category: DiagnosticCategory::HangOrTimeout,
                confidence: DiagnosticConfidence::Likely,
                summary: "Application hung or exceeded execution timeout limit and was terminated by supervisor watchdog.".to_string(),
                exit_code,
                evidence_lines: vec![format!("Process terminated with timeout/hang exit code {:?}", exit_code)],
                recommended_fixes: Vec::new(),
            });
        }

        // 7. Installer Failure
        let mut installer_evidence = Vec::new();
        for &line in tail_lines {
            let lower = line.to_ascii_lowercase();
            let is_match = (lower.contains("msiexec") && lower.contains("failed"))
                || (lower.contains("inno setup") && lower.contains("failed"))
                || lower.contains("nsis error");
            if is_match {
                installer_evidence.push(line.trim().to_string());
            }
        }
        if !installer_evidence.is_empty() {
            return Ok(DiagnosticReport {
                category: DiagnosticCategory::InstallerFailure,
                confidence: DiagnosticConfidence::Likely,
                summary: "Application installer package encountered an internal installation failure.".to_string(),
                exit_code,
                evidence_lines: installer_evidence,
                recommended_fixes: Vec::new(),
            });
        }

        // 8. Weak / Inconclusive Evidence -> Category Unknown
        Ok(DiagnosticReport {
            category: DiagnosticCategory::Unknown,
            confidence: DiagnosticConfidence::Unknown,
            summary: format!(
                "Non-zero exit code ({:?}) detected, but log output contains insufficient conclusive diagnostic failure signatures.",
                exit_code
            ),
            exit_code,
            evidence_lines: Vec::new(),
            recommended_fixes: Vec::new(),
        })
    }
}

