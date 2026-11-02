use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;
use universalrun_common::error::{Result, UniversalRunError};

const MAX_REGISTRY_FILE_BYTES: u64 = 15 * 1024 * 1024; // 15 MB limit
const MAX_LINE_BYTES: usize = 64 * 1024; // 64 KB line limit

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct UninstallRegistryEntry {
    pub key_name: String,
    pub display_name: Option<String>,
    pub install_location: Option<String>,
    pub display_icon: Option<String>,
    pub uninstall_string: Option<String>,
}

/// Pure static text parser for Wine's `system.reg` and `user.reg`.
/// Strictly avoids running `wine reg query` or any wine binaries.
pub struct WineRegistryParser;

impl WineRegistryParser {
    /// Parse all uninstall entries from prefix registry files (`system.reg` and `user.reg`).
    pub fn parse_prefix_uninstall_keys(prefix_path: &Path) -> Result<Vec<UninstallRegistryEntry>> {
        let mut entries = Vec::new();

        let system_reg = prefix_path.join("system.reg");
        if system_reg.exists() {
            if let Ok(mut sys_entries) = Self::parse_file(&system_reg) {
                entries.append(&mut sys_entries);
            }
        }

        let user_reg = prefix_path.join("user.reg");
        if user_reg.exists() {
            if let Ok(mut usr_entries) = Self::parse_file(&user_reg) {
                entries.append(&mut usr_entries);
            }
        }

        Ok(entries)
    }

    /// Parse a single Wine registry file safely as untrusted input.
    pub fn parse_file(path: &Path) -> Result<Vec<UninstallRegistryEntry>> {
        let meta = std::fs::metadata(path).map_err(UniversalRunError::Io)?;
        if meta.len() > MAX_REGISTRY_FILE_BYTES {
            return Err(UniversalRunError::Sandbox(format!(
                "Registry file '{}' exceeds safety size limit ({} bytes)",
                path.display(),
                meta.len()
            )));
        }

        let file = File::open(path).map_err(UniversalRunError::Io)?;
        let reader = BufReader::new(file);

        let mut results = Vec::new();
        let mut current_key: Option<String> = None;
        let mut is_uninstall_section = false;
        let mut current_values: HashMap<String, String> = HashMap::new();

        for line_res in reader.lines() {
            let line = match line_res {
                Ok(l) => l,
                Err(_) => continue, // Lossy skip on decoding error
            };

            if line.len() > MAX_LINE_BYTES {
                continue; // Skip abnormally long lines
            }

            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with(';') {
                continue;
            }

            // Section header: [Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\App]
            if trimmed.starts_with('[') && trimmed.ends_with(']') {
                // If previous section was an uninstall entry, save it
                if is_uninstall_section {
                    if let Some(key) = current_key.take() {
                        results.push(Self::build_entry(key, &current_values));
                    }
                }

                current_values.clear();
                let section = &trimmed[1..trimmed.len() - 1];

                if is_uninstall_key(section) {
                    is_uninstall_section = true;
                    current_key = Some(section.to_string());
                } else {
                    is_uninstall_section = false;
                    current_key = None;
                }
                continue;
            }

            // Key-value pair in active section
            if is_uninstall_section {
                if let Some((name, val)) = parse_reg_key_value(trimmed) {
                    current_values.insert(name.to_lowercase(), val);
                }
            }
        }

        // Flush last section if active
        if is_uninstall_section {
            if let Some(key) = current_key {
                results.push(Self::build_entry(key, &current_values));
            }
        }

        Ok(results)
    }

    fn build_entry(key_name: String, values: &HashMap<String, String>) -> UninstallRegistryEntry {
        UninstallRegistryEntry {
            key_name,
            display_name: values.get("displayname").cloned(),
            install_location: values.get("installlocation").cloned(),
            display_icon: values.get("displayicon").cloned(),
            uninstall_string: values.get("uninstallstring").cloned(),
        }
    }
}

fn is_uninstall_key(section: &str) -> bool {
    let normalized = section.replace("\\\\", "\\").replace('/', "\\").to_lowercase();
    normalized.contains("currentversion\\uninstall\\")
}

fn parse_reg_key_value(line: &str) -> Option<(String, String)> {
    if !line.starts_with('"') {
        return None;
    }

    let mut in_quote = false;
    let mut escape = false;
    let mut split_idx = None;

    for (i, ch) in line.char_indices() {
        if escape {
            escape = false;
            continue;
        }
        if ch == '\\' {
            escape = true;
            continue;
        }
        if ch == '"' {
            in_quote = !in_quote;
            continue;
        }
        if ch == '=' && !in_quote {
            split_idx = Some(i);
            break;
        }
    }

    let idx = split_idx?;
    let key_raw = &line[..idx].trim();
    let val_raw = &line[idx + 1..].trim();

    let key = unquote_str(key_raw);
    let val = if val_raw.starts_with('"') {
        unquote_str(val_raw)
    } else if let Some(hex_str) = val_raw.strip_prefix("hex(2):") {
        // REG_EXPAND_SZ hex encoded UTF-16LE
        decode_hex_utf16(hex_str)
    } else if let Some(hex_str) = val_raw.strip_prefix("hex:") {
        // REG_BINARY or ASCII
        decode_hex_ascii(hex_str)
    } else {
        val_raw.to_string()
    };

    Some((key, val))
}

fn unquote_str(s: &str) -> String {
    let trimmed = s.trim();
    let inner = if trimmed.starts_with('"') && trimmed.ends_with('"') && trimmed.len() >= 2 {
        &trimmed[1..trimmed.len() - 1]
    } else {
        trimmed
    };

    let mut out = String::with_capacity(inner.len());
    let mut chars = inner.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\\' {
            if let Some(&next) = chars.peek() {
                if next == '\\' || next == '"' {
                    out.push(next);
                    chars.next();
                    continue;
                }
            }
        }
        out.push(c);
    }
    out
}

fn decode_hex_utf16(hex_csv: &str) -> String {
    let bytes: Vec<u8> = hex_csv
        .split(',')
        .filter_map(|s| u8::from_str_radix(s.trim().trim_end_matches('\\'), 16).ok())
        .collect();

    let u16s: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
        .take_while(|&u| u != 0)
        .collect();

    String::from_utf16_lossy(&u16s)
}

fn decode_hex_ascii(hex_csv: &str) -> String {
    let bytes: Vec<u8> = hex_csv
        .split(',')
        .filter_map(|s| u8::from_str_radix(s.trim().trim_end_matches('\\'), 16).ok())
        .take_while(|&b| b != 0)
        .collect();

    String::from_utf8_lossy(&bytes).to_string()
}
