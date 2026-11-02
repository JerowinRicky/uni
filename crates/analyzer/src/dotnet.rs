use crate::types::{Confidence, DotNetFlavor, DotNetReport};
use goblin::pe::PE;

/// Analyzes whether the binary is a .NET application, distinguishing .NET Framework vs modern .NET (.NET 5+ / Core).
pub fn analyze_dotnet(bytes: &[u8], pe: &PE) -> Option<DotNetReport> {
    let opt = pe.header.optional_header.as_ref()?;
    
    // Index 14 in Data Directories is the CLR Runtime Header (COM Descriptor Table)
    let clr_dir = opt.data_directories.get_clr_runtime_header();
    let has_clr_header = match clr_dir {
        Some(dir) => dir.virtual_address > 0 && dir.size > 0,
        None => false,
    };

    // Also check if mscoree.dll is in imports with _CorExeMain or _CorDllMain
    let imports_mscoree = pe.imports.iter().any(|imp| {
        imp.dll.eq_ignore_ascii_case("mscoree.dll")
    });

    if !has_clr_header && !imports_mscoree {
        return None;
    }

    // Inspect strings to differentiate .NET Framework from modern .NET (.NET Core / .NET 5+)
    let (flavor, target_framework, confidence) = if let Some((fw_str, is_modern)) = find_target_framework(bytes) {
        let flavor = if is_modern {
            DotNetFlavor::ModernDotNet
        } else {
            DotNetFlavor::Framework
        };
        (flavor, Some(fw_str), Confidence::Certain)
    } else {
        // Fallback: check if mscorlib vs System.Runtime is referenced in string table
        let has_mscorlib = find_subsequence(bytes, b"mscorlib").is_some();
        let has_sys_runtime = find_subsequence(bytes, b"System.Runtime").is_some();
        let has_netcore = find_subsequence(bytes, b".NETCoreApp").is_some();

        if has_netcore || has_sys_runtime {
            (DotNetFlavor::ModernDotNet, None, Confidence::Likely)
        } else if has_mscorlib {
            (DotNetFlavor::Framework, None, Confidence::Likely)
        } else {
            (DotNetFlavor::Unknown, None, Confidence::Likely)
        }
    };

    Some(DotNetReport {
        is_dotnet: true,
        flavor,
        target_framework,
        confidence,
    })
}

fn find_target_framework(bytes: &[u8]) -> Option<(String, bool)> {
    // Look for TargetFramework string pattern like ".NETFramework,Version=v4.8" or ".NETCoreApp,Version=v8.0"
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
