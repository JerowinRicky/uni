pub mod detector;
pub mod dotnet;
pub mod installer;
pub mod limits;
pub mod pe;
pub mod rating;
pub mod signatures;
pub mod types;

use goblin::pe::PE;
use limits::AnalyzerLimits;
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::Read;
use std::path::Path;
pub use types::*;
use universalrun_common::error::{Result, UniversalRunError};

pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

/// Analyzes an executable or installer from disk.
pub fn analyze_file(path: &Path) -> Result<AnalysisReport> {
    let limits = AnalyzerLimits::default();
    let metadata = std::fs::metadata(path).map_err(UniversalRunError::Io)?;
    
    if metadata.len() > limits.max_file_size_bytes {
        return Err(UniversalRunError::Analyzer(format!(
            "File size {} bytes exceeds maximum allowed {} bytes",
            metadata.len(),
            limits.max_file_size_bytes
        )));
    }

    let mut file = File::open(path)?;
    let mut buffer = Vec::with_capacity(metadata.len() as usize);
    file.read_to_end(&mut buffer)?;

    let file_name = path
        .file_name()
        .map(|f| f.to_string_lossy().to_string())
        .unwrap_or_else(|| "unknown.exe".to_string());

    analyze_bytes(&file_name, &buffer, &limits)
}

/// Analyzes an executable or installer from an in-memory byte buffer.
pub fn analyze_bytes(
    file_name: &str,
    bytes: &[u8],
    limits: &AnalyzerLimits,
) -> Result<AnalysisReport> {
    let file_size_bytes = bytes.len() as u64;

    // 1. Calculate SHA-256
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let sha256 = hex::encode(hasher.finalize());

    // 2. Unverifiable aspects baseline
    let unverifiable_aspects = vec![
        "Dynamic DLL loading (LoadLibrary / GetProcAddress) cannot be statically enumerated".to_string(),
        "Runtime hardware-accelerated rendering behavior and driver quirks".to_string(),
        "Dynamic network socket calls and remote server availability".to_string(),
        "Windows Print Spooler and peripheral device communication".to_string(),
    ];

    // 3. Check for PE format vs non-PE (e.g. MSI/MSP)
    let is_pe = bytes.len() >= 2 && &bytes[..2] == b"MZ";
    let installer_analysis = installer::detect_installer(bytes, file_name, is_pe);

    // If it's an MSI or MSP compound file (not a standard PE)
    if (matches!(installer_analysis.kind.value, InstallerKind::Msi) || matches!(installer_analysis.kind.value, InstallerKind::Msp)) && !is_pe {
        let is_msp = matches!(installer_analysis.kind.value, InstallerKind::Msp);
        let summary = if is_msp {
            "Rated Partial: Windows Installer Patch (MSP). Installation requires target application prefix."
        } else {
            "Rated Partial: Windows Installer Package (MSI). Embedded tables, custom actions, and services require staging."
        };

        let rating = CompatibilityRating {
            category: RatingCategory::Partial,
            summary: summary.to_string(),
            evidence: vec![
                "Static-only analysis cap: maximum assignable rating is Good".to_string(),
                if is_msp {
                    "MSP patch package: static rating capped at Partial (requires target application prefix)".to_string()
                } else {
                    "MSI package: static rating capped at Partial (internal tables, custom actions, services, and embedded drivers require prefix execution)".to_string()
                },
            ],
        };

        return Ok(AnalysisReport {
            schema_version: SCHEMA_VERSION.to_string(),
            file_name: file_name.to_string(),
            file_size_bytes,
            sha256,
            architecture: None,
            subsystem: None,
            entry_point: None,
            num_sections: 0,
            imports: Vec::new(),
            delay_load_imports: Vec::new(),
            execution_level: Finding::unknown(ExecutionLevel::AsInvoker, "MSI packages manage elevation via UAC properties"),
            authenticode: AuthenticodeReport {
                signature_present: false,
                file_hash_verified: None,
                chain_trust: ChainTrust::Unknown,
                publisher: None,
                note: None,
            },
            installer_type: installer_analysis.kind,
            installer_version: installer_analysis.version,
            dotnet: None,
            graphics_apis: Vec::new(),
            required_runtimes: Vec::new(),
            security_flags: SecurityFlags {
                requests_admin: false,
                has_drivers_or_services: false,
                known_anticheat_or_drm: None,
            },
            compatibility_rating: rating,
            unverifiable_aspects,
        });
    }

    // 4. Parse PE
    let pe = PE::parse(bytes).map_err(|e| {
        UniversalRunError::Analyzer(format!("Failed to parse PE binary headers: {}", e))
    })?;

    let pe_info = pe::parse_pe_info(bytes, &pe, limits);
    let authenticode = signatures::analyze_authenticode(bytes, &pe);
    let dotnet_analysis = dotnet::analyze_dotnet(bytes, &pe);

    let requests_admin = matches!(pe_info.execution_level.value, ExecutionLevel::RequireAdministrator);
    let mut detected = detector::detect_attributes(bytes, &pe, requests_admin);

    // If .NET analysis found a required runtime, append it to required_runtimes
    let mut dotnet_rt_name = None;
    let dotnet_report = if let Some(dna) = &dotnet_analysis {
        if let Some(rt) = &dna.required_runtime {
            detected.required_runtimes.push(Finding::certain(rt.clone()));
            dotnet_rt_name = Some(rt.as_str());
        }
        Some(dna.report.clone())
    } else {
        None
    };

    let compatibility_rating = rating::compute_static_rating(
        Some(pe_info.architecture),
        Some(pe_info.subsystem),
        &installer_analysis.kind,
        &detected.graphics_apis,
        &detected.security_flags,
        &pe_info.execution_level,
        dotnet_rt_name,
    );

    Ok(AnalysisReport {
        schema_version: SCHEMA_VERSION.to_string(),
        file_name: file_name.to_string(),
        file_size_bytes,
        sha256,
        architecture: Some(pe_info.architecture),
        subsystem: Some(pe_info.subsystem),
        entry_point: pe_info.entry_point,
        num_sections: pe_info.num_sections,
        imports: pe_info.imports,
        delay_load_imports: pe_info.delay_load_imports,
        execution_level: pe_info.execution_level,
        authenticode,
        installer_type: installer_analysis.kind,
        installer_version: installer_analysis.version,
        dotnet: dotnet_report,
        graphics_apis: detected.graphics_apis,
        required_runtimes: detected.required_runtimes,
        security_flags: detected.security_flags,
        compatibility_rating,
        unverifiable_aspects,
    })
}
