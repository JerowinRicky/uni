use crate::types::{Confidence, DotNetFlavor, DotNetReport};
use goblin::pe::PE;

pub struct DotNetAnalysis {
    pub report: DotNetReport,
    pub required_runtime: Option<String>,
}

/// Analyzes whether the binary is a .NET application, distinguishing .NET Framework vs modern .NET (.NET 5+ / Core).
pub fn analyze_dotnet(bytes: &[u8], pe: &PE) -> Option<DotNetAnalysis> {
    let opt = pe.header.optional_header.as_ref()?;
    
    // Index 14 in Data Directories is the CLR Runtime Header (COM Descriptor Table)
    let clr_dir = opt.data_directories.get_clr_runtime_header();
    let has_clr_header = match clr_dir {
        Some(dir) => dir.virtual_address > 0 && dir.size > 0,
        None => false,
    };

    let imports_mscoree = pe.imports.iter().any(|imp| {
        imp.dll.eq_ignore_ascii_case("mscoree.dll")
    });

    if !has_clr_header && !imports_mscoree {
        return None;
    }

    // 1. Check for explicit TargetFrameworkAttribute in metadata / strings
    if let Some((fw_str, is_modern)) = find_target_framework(bytes) {
        let (flavor, runtime) = if is_modern {
            (DotNetFlavor::ModernDotNet, Some(".NET Runtime (Modern .NET)".to_string()))
        } else {
            (DotNetFlavor::Framework, Some("Microsoft .NET Framework".to_string()))
        };
        return Some(DotNetAnalysis {
            report: DotNetReport {
                is_dotnet: true,
                flavor,
                target_framework: Some(fw_str),
                confidence: Confidence::Certain,
            },
            required_runtime: runtime,
        });
    }

    // 2. Check assembly reference signatures
    let has_corelib = find_subsequence(bytes, b"System.Private.CoreLib").is_some();
    let has_mscorlib = find_subsequence(bytes, b"mscorlib").is_some();
    let has_v4_header = find_subsequence(bytes, b"v4.0.30319").is_some();
    let has_v2_header = find_subsequence(bytes, b"v2.0.50727").is_some();

    if has_corelib {
        Some(DotNetAnalysis {
            report: DotNetReport {
                is_dotnet: true,
                flavor: DotNetFlavor::ModernDotNet,
                target_framework: None,
                confidence: Confidence::Likely,
            },
            required_runtime: Some(".NET Runtime (Modern .NET)".to_string()),
        })
    } else if has_mscorlib || has_v4_header || has_v2_header {
        let fw_version = if has_v4_header {
            "Microsoft .NET Framework 4.x"
        } else if has_v2_header {
            "Microsoft .NET Framework 2.0/3.5"
        } else {
            "Microsoft .NET Framework"
        };
        Some(DotNetAnalysis {
            report: DotNetReport {
                is_dotnet: true,
                flavor: DotNetFlavor::Framework,
                target_framework: if has_v4_header {
                    Some("v4.0.30319".to_string())
                } else if has_v2_header {
                    Some("v2.0.50727".to_string())
                } else {
                    None
                },
                confidence: Confidence::Certain,
            },
            required_runtime: Some(fw_version.to_string()),
        })
    } else {
        // Could not determine flavor
        Some(DotNetAnalysis {
            report: DotNetReport {
                is_dotnet: true,
                flavor: DotNetFlavor::Unknown,
                target_framework: None,
                confidence: Confidence::Unknown,
            },
            required_runtime: None,
        })
    }
}

fn find_target_framework(bytes: &[u8]) -> Option<(String, bool)> {
    if let Some(pos) = find_subsequence(bytes, b".NETFramework,Version=v") {
        let after = &bytes[pos..];
        let end = after.iter().position(|&b| b == 0 || b == b'"' || b == b'\'' || b > 126)?;
        let s = std::str::from_utf8(&after[..end]).ok()?.to_string();
        return Some((s, false));
    }
    if let Some(pos) = find_subsequence(bytes, b".NETCoreApp,Version=v") {
        let after = &bytes[pos..];
        let end = after.iter().position(|&b| b == 0 || b == b'"' || b == b'\'' || b > 126)?;
        let s = std::str::from_utf8(&after[..end]).ok()?.to_string();
        return Some((s, true));
    }
    None
}

fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}
