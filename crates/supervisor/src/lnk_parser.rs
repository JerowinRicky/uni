use std::fs;
use std::path::Path;
use universalrun_common::error::{Result, UniversalRunError};

const LINK_CLSID: [u8; 16] = [
    0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x46,
];
const MAX_LNK_SIZE: usize = 1024 * 1024; // 1 MB cap

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ShellLinkInfo {
    pub target_path: Option<String>,
    pub working_dir: Option<String>,
    pub icon_location: Option<String>,
}

/// Robust, bounds-checked parser for Microsoft Shell Link (.lnk) files.
/// Strict safety guarantees against malformed or malicious inputs.
pub struct ShellLinkParser;

impl ShellLinkParser {
    pub fn parse_file(path: &Path) -> Result<ShellLinkInfo> {
        let bytes = fs::read(path).map_err(UniversalRunError::Io)?;
        Self::parse_bytes(&bytes)
    }

    pub fn parse_bytes(data: &[u8]) -> Result<ShellLinkInfo> {
        if data.len() < 0x4C {
            return Err(UniversalRunError::Sandbox(
                "Malformed .lnk file: smaller than 76-byte ShellLinkHeader".into(),
            ));
        }

        if data.len() > MAX_LNK_SIZE {
            return Err(UniversalRunError::Sandbox(
                "Malformed .lnk file: exceeds 1MB safety size cap".into(),
            ));
        }

        // Verify header size (0x0000004C)
        let header_size = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        if header_size != 0x4C {
            return Err(UniversalRunError::Sandbox(
                "Malformed .lnk file: invalid ShellLinkHeader size".into(),
            ));
        }

        // Verify LinkCLSID
        if data[4..20] != LINK_CLSID {
            return Err(UniversalRunError::Sandbox(
                "Malformed .lnk file: invalid LinkCLSID".into(),
            ));
        }

        let flags = u32::from_le_bytes([data[20], data[21], data[22], data[23]]);
        let has_id_list = (flags & 0x01) != 0;
        let has_link_info = (flags & 0x02) != 0;
        let has_name = (flags & 0x04) != 0;
        let has_relative_path = (flags & 0x08) != 0;
        let has_working_dir = (flags & 0x10) != 0;
        let has_arguments = (flags & 0x20) != 0;
        let has_icon_location = (flags & 0x40) != 0;
        let is_unicode = (flags & 0x80) != 0;

        let mut offset = 0x4C;

        // Skip LinkTargetIDList if present
        if has_id_list {
            if offset + 2 > data.len() {
                return Ok(ShellLinkInfo::default());
            }
            let id_list_size = u16::from_le_bytes([data[offset], data[offset + 1]]) as usize;
            offset += 2 + id_list_size;
            if offset > data.len() {
                return Ok(ShellLinkInfo::default());
            }
        }

        let mut target_path = None;

        // Parse LinkInfo if present
        if has_link_info && offset + 4 <= data.len() {
            let link_info_size =
                u32::from_le_bytes([data[offset], data[offset + 1], data[offset + 2], data[offset + 3]])
                    as usize;

            if link_info_size >= 0x1C && offset + link_info_size <= data.len() {
                let link_info = &data[offset..offset + link_info_size];
                let local_base_path_offset = u32::from_le_bytes([
                    link_info[0x10],
                    link_info[0x11],
                    link_info[0x12],
                    link_info[0x13],
                ]) as usize;

                if local_base_path_offset < link_info.len() {
                    let path_slice = &link_info[local_base_path_offset..];
                    target_path = extract_null_terminated_ascii(path_slice);
                }
            }
            offset += link_info_size;
        }

        // Parse StringData structures
        let mut working_dir = None;
        let mut icon_location = None;

        // NAME_STRING
        if has_name {
            offset = skip_string_data(data, offset, is_unicode);
        }

        // RELATIVE_PATH
        if has_relative_path {
            let (next_off, rel_path) = read_string_data(data, offset, is_unicode);
            if target_path.is_none() {
                target_path = rel_path;
            }
            offset = next_off;
        }

        // WORKING_DIR
        if has_working_dir {
            let (next_off, w_dir) = read_string_data(data, offset, is_unicode);
            working_dir = w_dir;
            offset = next_off;
        }

        // COMMAND_LINE_ARGUMENTS
        if has_arguments {
            offset = skip_string_data(data, offset, is_unicode);
        }

        // ICON_LOCATION
        if has_icon_location {
            let (_, icon) = read_string_data(data, offset, is_unicode);
            icon_location = icon;
        }

        Ok(ShellLinkInfo {
            target_path,
            working_dir,
            icon_location,
        })
    }
}

fn extract_null_terminated_ascii(bytes: &[u8]) -> Option<String> {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    let s = String::from_utf8_lossy(&bytes[..end]).trim().to_string();
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}

fn read_string_data(data: &[u8], offset: usize, is_unicode: bool) -> (usize, Option<String>) {
    if offset + 2 > data.len() {
        return (data.len(), None);
    }

    let char_count = u16::from_le_bytes([data[offset], data[offset + 1]]) as usize;
    let start = offset + 2;

    if is_unicode {
        let byte_count = char_count * 2;
        if start + byte_count > data.len() {
            return (data.len(), None);
        }
        let u16s: Vec<u16> = data[start..start + byte_count]
            .chunks_exact(2)
            .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
            .collect();
        let s = String::from_utf16_lossy(&u16s).trim().to_string();
        (start + byte_count, if s.is_empty() { None } else { Some(s) })
    } else {
        if start + char_count > data.len() {
            return (data.len(), None);
        }
        let s = String::from_utf8_lossy(&data[start..start + char_count])
            .trim()
            .to_string();
        (start + char_count, if s.is_empty() { None } else { Some(s) })
    }
}

fn skip_string_data(data: &[u8], offset: usize, is_unicode: bool) -> usize {
    if offset + 2 > data.len() {
        return data.len();
    }
    let char_count = u16::from_le_bytes([data[offset], data[offset + 1]]) as usize;
    let byte_count = if is_unicode {
        char_count * 2
    } else {
        char_count
    };
    std::cmp::min(offset + 2 + byte_count, data.len())
}
