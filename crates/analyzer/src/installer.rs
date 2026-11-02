use crate::types::{Finding, InstallerKind};
use std::io::Cursor;

pub struct InstallerAnalysis {
    pub kind: Finding<InstallerKind>,
    pub version: Option<String>,
}

/// Detects whether the file is an MSI, MSP, NSIS, Inno Setup, InstallShield, or standard portable PE.
pub fn detect_installer(bytes: &[u8], file_name: &str, is_pe: bool) -> InstallerAnalysis {
    let lower_name = file_name.to_ascii_lowercase();

    // 1. MSI / MSP Detection via Compound File Binary Format (CFB) verification
    if bytes.starts_with(b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1") {
        if let Ok(comp) = cfb::CompoundFile::open(Cursor::new(bytes)) {
            // Check for MSP (Patch) specific streams
            let has_patch_summary = comp.exists("/\u{0005}PatchSummaryInformation");
            let has_patch_stream = comp.walk().any(|e| e.name().eq_ignore_ascii_case("Patch"));

            if has_patch_summary || has_patch_stream || lower_name.ends_with(".msp") {
                return InstallerAnalysis {
                    kind: Finding::certain(InstallerKind::Msp),
                    version: None,
                };
            }

            // Check for MSI streams / storage entries
            let has_summary = comp.exists("/\u{0005}SummaryInformation");
            let has_msi_tables = comp.walk().any(|entry| {
                let name = entry.name();
                name == "Property" || name == "_Tables" || name == "File" || name == "Component"
            });

            if has_summary || has_msi_tables || lower_name.ends_with(".msi") {
                return InstallerAnalysis {
                    kind: Finding::certain(InstallerKind::Msi),
                    version: None,
                };
            }
        }
        // CFBF magic present but internal MSI tables unconfirmed
        let kind = if lower_name.ends_with(".msp") {
            InstallerKind::Msp
        } else {
            InstallerKind::Msi
        };
        return InstallerAnalysis {
            kind: Finding::likely(kind, "CFBF header present but tables unconfirmed"),
            version: None,
        };
    }

    // 2. Inno Setup Detection
    if let Some(pos) = find_subsequence(bytes, b"Inno Setup Setup Data (") {
        let after = &bytes[pos + 23..];
        let end_pos = after.iter().position(|&b| b == b')' || b == 0);
        let version_str = end_pos.and_then(|e| std::str::from_utf8(&after[..e]).ok()).map(|s| s.to_string());
        
        return InstallerAnalysis {
            kind: Finding::certain(InstallerKind::InnoSetup),
            version: version_str,
        };
    } else if find_subsequence(bytes, b"Inno Setup").is_some() {
        return InstallerAnalysis {
            kind: Finding::likely(InstallerKind::InnoSetup, "Inno Setup markers detected without full data block"),
            version: None,
        };
    }

    // 3. NSIS Detection
    if let Some(pos) = find_subsequence(bytes, b"NullsoftInst") {
        let header_valid = bytes.len() >= pos + 28;
        if header_valid {
            return InstallerAnalysis {
                kind: Finding::certain(InstallerKind::Nsis),
                version: None,
            };
        } else {
            return InstallerAnalysis {
                kind: Finding::likely(InstallerKind::Nsis, "NullsoftInst marker found near EOF"),
                version: None,
            };
        }
    }

    // 4. InstallShield Detection
    if find_subsequence(bytes, b"InstallShield").is_some() || find_subsequence(bytes, b"ISSetup.dll").is_some() {
        return InstallerAnalysis {
            kind: Finding::likely(InstallerKind::InstallShield, "InstallShield markers identified"),
            version: None,
        };
    }

    // 5. If it's a standard PE with no installer marks
    if is_pe {
        InstallerAnalysis {
            kind: Finding::certain(InstallerKind::Portable),
            version: None,
        }
    } else {
        InstallerAnalysis {
            kind: Finding::unknown(InstallerKind::Unknown, "Not a recognized installer or PE file"),
            version: None,
        }
    }
}

fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|window| window == needle)
}
