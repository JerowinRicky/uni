use crate::types::{
    Architecture, CompatibilityRating, ExecutionLevel, Finding, GraphicsApi, InstallerKind,
    RatingCategory, SecurityFlags, Subsystem,
};

/// Computes the compatibility rating based purely on static evidence.
///
/// RULE (Section 5 & M1 Requirements):
/// Without a verified recipe backed by test evidence, the MAXIMUM rating
/// for static-only analysis is `Good`. `Excellent` is strictly reserved
/// for apps with verified test-farm execution results.
pub fn compute_static_rating(
    arch: Option<Architecture>,
    subsystem: Option<Subsystem>,
    installer: &Finding<InstallerKind>,
    graphics_apis: &[Finding<GraphicsApi>],
    security_flags: &SecurityFlags,
    execution_level: &Finding<ExecutionLevel>,
    dotnet_runtime: Option<&str>,
) -> CompatibilityRating {
    let mut evidence = Vec::new();
    let mut category = RatingCategory::Good;

    // Rule: Static analysis cap
    evidence.push("Static-only analysis cap: maximum assignable rating is Good (Excellent requires verified test farm results)".to_string());

    // 1. Installer check (MSI/MSP rating cap)
    match installer.value {
        InstallerKind::Msi => {
            category = RatingCategory::Partial;
            evidence.push("MSI package: static rating capped at Partial (internal tables, custom actions, services, and embedded drivers require prefix execution)".to_string());
        }
        InstallerKind::Msp => {
            category = RatingCategory::Partial;
            evidence.push("MSP patch package: static rating capped at Partial (patch installation requires target application prefix)".to_string());
        }
        InstallerKind::Nsis => evidence.push("NSIS installer format (supported in Wine)".to_string()),
        InstallerKind::InnoSetup => evidence.push("Inno Setup installer format (supported in Wine)".to_string()),
        InstallerKind::Portable => evidence.push("Portable standalone executable (no installation required)".to_string()),
        InstallerKind::InstallShield => {
            category = RatingCategory::Partial;
            evidence.push("InstallShield installer format (may use proprietary setup scripts)".to_string());
        }
        InstallerKind::Unknown => {}
    }

    // 2. Architecture check
    if let Some(a) = arch {
        match a {
            Architecture::X64 => evidence.push("Target architecture is x86_64 (first-class Wine support)".to_string()),
            Architecture::X86 => evidence.push("Target architecture is x86 32-bit (supported via WoW64)".to_string()),
            Architecture::AnyCPU => evidence.push("Target architecture is AnyCPU (.NET IL, runs natively on 64-bit or 32-bit Wine)".to_string()),
            Architecture::Arm64 => {
                category = RatingCategory::Experimental;
                evidence.push("ARM64 PE binary requires emulation bridge".to_string());
            }
            Architecture::Unknown => {
                return CompatibilityRating {
                    category: RatingCategory::Unknown,
                    summary: "Unknown or unparsed binary architecture".to_string(),
                    evidence,
                };
            }
        }
    }

    // 3. Kernel drivers / Anti-cheat
    if security_flags.has_drivers_or_services {
        category = RatingCategory::Unsupported;
        evidence.push("Contains kernel-mode drivers or Native subsystem components (unsupported in unprivileged Wine sandbox)".to_string());
    }

    if let Some(anticheat) = &security_flags.known_anticheat_or_drm {
        category = RatingCategory::Unsupported;
        evidence.push(format!("Known anti-cheat/DRM detected ({}); unsupported without kernel drivers", anticheat));
    }

    // 4. Subsystem
    if let Some(sub) = subsystem {
        match sub {
            Subsystem::WindowsGui => evidence.push("Standard Win32 GUI subsystem".to_string()),
            Subsystem::WindowsCui => evidence.push("Win32 Console subsystem".to_string()),
            Subsystem::Native => {
                category = RatingCategory::Unsupported;
                evidence.push("Native NT subsystem is not supported".to_string());
            }
            _ => {}
        }
    }

    // 5. .NET Runtime requirement
    if let Some(rt) = dotnet_runtime {
        evidence.push(format!("Requires {rt} runtime in Wine prefix"));
    }

    // 6. Graphics APIs
    for api in graphics_apis {
        match api.value {
            GraphicsApi::Direct3D12 => {
                if category == RatingCategory::Good {
                    category = RatingCategory::Partial;
                }
                evidence.push("Direct3D 12 detected (requires VKD3D-Proton and Vulkan driver)".to_string());
            }
            GraphicsApi::Direct3D11 => {
                evidence.push("Direct3D 11 detected (supported via DXVK)".to_string());
            }
            GraphicsApi::Direct3D9 => {
                evidence.push("Direct3D 9 detected (supported via DXVK/wined3d)".to_string());
            }
            GraphicsApi::OpenGL => {
                evidence.push("OpenGL detected (supported via host DRI)".to_string());
            }
            GraphicsApi::Vulkan => {
                evidence.push("Vulkan detected (supported via host driver)".to_string());
            }
            _ => {}
        }
    }

    // 7. Admin execution level
    if matches!(execution_level.value, ExecutionLevel::RequireAdministrator) {
        if category == RatingCategory::Good {
            category = RatingCategory::Partial;
        }
        evidence.push("Manifest explicitly requests Administrator privileges".to_string());
    }

    let summary = match category {
        RatingCategory::Good => "Rated Good: standard desktop software with no kernel drivers or conflicting DRM.".to_string(),
        RatingCategory::Partial => "Rated Partial: installer or application requires elevated privileges, special runtimes, or MSI staging.".to_string(),
        RatingCategory::Experimental => "Rated Experimental: unusual architecture or complex subsystem requirements.".to_string(),
        RatingCategory::Unsupported => "Rated Unsupported: relies on kernel-mode components or unsupported anti-cheat.".to_string(),
        _ => "Rated Unknown.".to_string(),
    };

    CompatibilityRating {
        category,
        summary,
        evidence,
    }
}
