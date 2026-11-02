use crate::limits::AnalyzerLimits;
use crate::types::{Architecture, ExecutionLevel, Finding, ImportSummary, Subsystem};
use goblin::pe::PE;
use std::collections::HashMap;

pub struct PeInfo {
    pub architecture: Architecture,
    pub subsystem: Subsystem,
    pub entry_point: Option<u64>,
    pub num_sections: usize,
    pub imports: Vec<ImportSummary>,
    pub delay_load_imports: Vec<String>,
    pub execution_level: Finding<ExecutionLevel>,
}

pub fn parse_pe_info(bytes: &[u8], pe: &PE, limits: &AnalyzerLimits) -> PeInfo {
    // 1. Architecture
    let architecture = match pe.header.coff_header.machine {
        0x014c => Architecture::X86,
        0x8664 => Architecture::X64,
        0xaa64 => Architecture::Arm64,
        _ => Architecture::Unknown,
    };

    // 2. Subsystem & Entry Point
    let (subsystem, entry_point) = if let Some(opt) = &pe.header.optional_header {
        let sub = match opt.windows_fields.subsystem {
            1 => Subsystem::Native,
            2 => Subsystem::WindowsGui,
            3 => Subsystem::WindowsCui,
            7 => Subsystem::PosixCui,
            9 => Subsystem::WindowsCeGui,
            10 => Subsystem::EfiApplication,
            _ => Subsystem::Unknown,
        };
        let ep = if opt.standard_fields.address_of_entry_point > 0 {
            Some(opt.standard_fields.address_of_entry_point)
        } else {
            None
        };
        (sub, ep)
    } else {
        (Subsystem::Unknown, None)
    };

    // 3. Sections count (capped by limit)
    let num_sections = pe.sections.len().min(limits.max_sections);

    // 4. Imports (summarized by DLL)
    let mut import_map: HashMap<String, usize> = HashMap::new();
    for (i, imp) in pe.imports.iter().enumerate() {
        if i >= limits.max_imports {
            break;
        }
        *import_map.entry(imp.dll.to_string()).or_insert(0) += 1;
    }
    let mut imports: Vec<ImportSummary> = import_map
        .into_iter()
        .map(|(dll_name, function_count)| ImportSummary {
            dll_name,
            function_count,
        })
        .collect();
    imports.sort_by(|a, b| a.dll_name.cmp(&b.dll_name));

    // 5. Delay-load imports
    let mut delay_load_imports = Vec::new();
    if let Some(opt) = &pe.header.optional_header {
        // Data directory index 13 is Delay Import Descriptor
        if let Some(delay_dir) = opt.data_directories.get_delay_import_descriptor() {
            if delay_dir.virtual_address > 0 && delay_dir.size > 0 {
                // If present, mark as detected
                delay_load_imports.push("Delay-load directory present".to_string());
            }
        }
    }

    // 6. Manifest inspection for requested execution level
    let execution_level = parse_manifest_execution_level(bytes);

    PeInfo {
        architecture,
        subsystem,
        entry_point,
        num_sections,
        imports,
        delay_load_imports,
        execution_level,
    }
}

fn parse_manifest_execution_level(bytes: &[u8]) -> Finding<ExecutionLevel> {
    // Look for <requestedExecutionLevel level="..."/> in resources or UTF-8 strings
    if let Some(pos) = find_subsequence(bytes, b"requestedExecutionLevel") {
        let window_len = 256.min(bytes.len() - pos);
        let snippet = &bytes[pos..pos + window_len];
        if let Ok(text) = std::str::from_utf8(snippet) {
            if text.contains("requireAdministrator") {
                return Finding::certain(ExecutionLevel::RequireAdministrator);
            } else if text.contains("highestAvailable") {
                return Finding::certain(ExecutionLevel::HighestAvailable);
            } else if text.contains("asInvoker") {
                return Finding::certain(ExecutionLevel::AsInvoker);
            }
        }
        Finding::likely(ExecutionLevel::Unknown, "Manifest present but level unparsed")
    } else {
        // Default execution level on Windows when manifest is absent is asInvoker (with legacy heuristic elevation)
        Finding::unknown(ExecutionLevel::AsInvoker, "No manifest found; defaults to asInvoker")
    }
}

fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}
