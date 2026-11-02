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
    // 1. Architecture (with .NET AnyCPU inspection)
    let mut architecture = match pe.header.coff_header.machine {
        0x014c => Architecture::X86,
        0x8664 => Architecture::X64,
        0xaa64 => Architecture::Arm64,
        _ => Architecture::Unknown,
    };

    // Inspect CLR Header Flags for AnyCPU if x86
    if let Some(opt) = &pe.header.optional_header {
        if let Some(clr_dir) = opt.data_directories.get_clr_runtime_header() {
            if clr_dir.virtual_address > 0 && clr_dir.size >= 20 {
                if let Some(clr_offset) = rva_to_offset(clr_dir.virtual_address, pe) {
                    // Flags is a uint32 at offset 16 within IMAGE_COR20_HEADER
                    if clr_offset + 20 <= bytes.len() {
                        let flags = u32::from_le_bytes([
                            bytes[clr_offset + 16],
                            bytes[clr_offset + 17],
                            bytes[clr_offset + 18],
                            bytes[clr_offset + 19],
                        ]);
                        let il_only = (flags & 0x00000001) != 0;
                        let bit32_required = (flags & 0x00000002) != 0;
                        let bit32_preferred = (flags & 0x00020000) != 0;

                        if il_only && (!bit32_required || bit32_preferred) {
                            architecture = Architecture::AnyCPU;
                        }
                    }
                }
            }
        }
    }

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

    // 5. Delay-load imports: parse real DLL names
    let mut delay_load_imports = Vec::new();
    if let Some(opt) = &pe.header.optional_header {
        // Data directory index 13 is Delay Import Descriptor
        if let Some(delay_dir) = opt.data_directories.get_delay_import_descriptor() {
            if delay_dir.virtual_address > 0 && delay_dir.size > 0 {
                if let Some(mut offset) = rva_to_offset(delay_dir.virtual_address, pe) {
                    while offset + 32 <= bytes.len() {
                        let desc = &bytes[offset..offset + 32];
                        // Null terminator descriptor is all zeroes
                        if desc.iter().all(|&b| b == 0) {
                            break;
                        }
                        // DllNameRVA is at offset 4 (bytes 4..8) in IMAGE_DELAYLOAD_DESCRIPTOR
                        let dll_name_rva = u32::from_le_bytes([desc[4], desc[5], desc[6], desc[7]]);
                        if dll_name_rva > 0 {
                            if let Some(str_offset) = rva_to_offset(dll_name_rva, pe) {
                                if str_offset < bytes.len() {
                                    let str_slice = &bytes[str_offset..];
                                    let len = str_slice.iter().position(|&b| b == 0).unwrap_or(0);
                                    if len > 0 {
                                        if let Ok(dll_name) = std::str::from_utf8(&str_slice[..len]) {
                                            let name_str = dll_name.to_string();
                                            if !delay_load_imports.contains(&name_str) {
                                                delay_load_imports.push(name_str);
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        offset += 32;
                    }
                }
            }
        }
    }
    delay_load_imports.sort();

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

pub fn rva_to_offset(rva: u32, pe: &PE) -> Option<usize> {
    for section in &pe.sections {
        let start = section.virtual_address;
        let size = section.virtual_size.max(section.size_of_raw_data);
        if rva >= start && rva < start + size {
            let offset_in_sect = (rva - start) as usize;
            return Some((section.pointer_to_raw_data as usize) + offset_in_sect);
        }
    }
    None
}

fn parse_manifest_execution_level(bytes: &[u8]) -> Finding<ExecutionLevel> {
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
        Finding::unknown(ExecutionLevel::AsInvoker, "No manifest found; defaults to asInvoker")
    }
}

fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}
