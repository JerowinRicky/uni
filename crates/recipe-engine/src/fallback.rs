use crate::types::{MatchRules, Recipe, RuntimeRecipeConfig};
use std::collections::HashMap;
use universalrun_analyzer::AnalysisReport;
use universalrun_profile_manager::{DllOverrideMode, PermissionPolicy};

/// Synthesize a safe, generic fallback recipe from static binary analysis.
pub fn generate_fallback_recipe(report: &AnalysisReport) -> Recipe {
    let sanitized_id = report
        .file_name
        .to_ascii_lowercase()
        .replace(".exe", "")
        .replace(".msi", "")
        .replace(|c: char| !c.is_ascii_alphanumeric() && c != '-', "-");

    let id = format!("{}-fallback", sanitized_id.trim_matches('-'));

    let arch = match &report.architecture {
        Some(universalrun_analyzer::Architecture::X86) => "win32",
        _ => "win64",
    };

    let mut dependencies = Vec::new();
    let mut dll_overrides = HashMap::new();

    // Infer dependencies from static analysis
    for runtime in &report.required_runtimes {
        if runtime.value.contains(".NET") {
            dependencies.push("dotnet48".to_string());
        }
        if runtime.value.contains("Visual C++") {
            dependencies.push("vcredist2022".to_string());
        }
    }

    // Default DXVK for D3D11/D3D10 if direct3d is used
    if report.graphics_apis.iter().any(|api| {
        matches!(
            api.value,
            universalrun_analyzer::GraphicsApi::Direct3D10
                | universalrun_analyzer::GraphicsApi::Direct3D11
        )
    }) {
        dll_overrides.insert("dxgi".to_string(), DllOverrideMode::Native);
        dll_overrides.insert("d3d11".to_string(), DllOverrideMode::Native);
    }

    Recipe {
        schema_version: Recipe::SCHEMA_VERSION.to_string(),
        id,
        revision: 1,
        name: format!("Generic Fallback for {}", report.file_name),
        match_rules: MatchRules {
            sha256: vec![report.sha256.clone()],
            product_name: Some(report.file_name.clone()),
            min_version: None,
            max_version: None,
        },
        runtime: RuntimeRecipeConfig {
            preferred: "wine".to_string(),
            min_version: "9.0".to_string(),
            architecture: arch.to_string(),
            windows_version: "win10".to_string(),
        },
        dependencies,
        dll_overrides,
        registry_entries: Vec::new(),
        permissions: PermissionPolicy {
            network: false, // Security default: deny ambient networking
            audio: true,
            display: true,
            dri: true,
        },
        known_issues: vec![
            "Synthesized fallback recipe generated from static PE/MSI analysis; not backed by verified test farm results."
                .to_string(),
        ],
        tested_results: Vec::new(),
        signature: None,
    }
}

