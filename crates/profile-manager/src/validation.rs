use std::collections::HashSet;
use std::fs;
use std::path::{Component, Path, PathBuf};
use universalrun_common::error::{Result, UniversalRunError};

const WINDOWS_RESERVED_NAMES: &[&str] = &[
    "CON", "PRN", "AUX", "NUL",
    "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
    "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
];

/// Validate profile ID: 1-64 chars, ASCII alphanumeric plus '-' and '_', not reserved.
pub fn validate_profile_id(id: &str) -> Result<()> {
    if id.is_empty() || id.len() > 64 {
        return Err(UniversalRunError::Profile(format!(
            "Profile ID '{}' is invalid: must be between 1 and 64 characters",
            id
        )));
    }

    if !id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') {
        return Err(UniversalRunError::Profile(format!(
            "Profile ID '{}' contains invalid characters: only [a-zA-Z0-9_-] are allowed",
            id
        )));
    }

    let upper = id.to_ascii_uppercase();
    if WINDOWS_RESERVED_NAMES.contains(&upper.as_str()) {
        return Err(UniversalRunError::Profile(format!(
            "Profile ID '{}' is a forbidden Windows reserved name",
            id
        )));
    }

    Ok(())
}

/// Check if a single path component contains Windows reserved names (e.g. "CON.txt" or "NUL").
pub fn is_windows_reserved_name(segment: &str) -> bool {
    let stem = match segment.split('.').next() {
        Some(s) => s.trim_end(),
        None => segment.trim_end(),
    };
    WINDOWS_RESERVED_NAMES.iter().any(|&res| res.eq_ignore_ascii_case(stem))
}

/// Check for Unicode confusable characters, bidirectional overrides, and invisible chars.
pub fn check_unicode_safety(text: &str) -> Result<()> {
    for c in text.chars() {
        // Control characters
        if c.is_control() {
            return Err(UniversalRunError::Profile(format!(
                "String contains forbidden control character (U+{:04X})",
                c as u32
            )));
        }

        // Zero-width & invisible characters
        match c as u32 {
            0x200B..=0x200F | 0xFEFF | 0x2028 | 0x2029 => {
                return Err(UniversalRunError::Profile(format!(
                    "String contains forbidden zero-width or separator character (U+{:04X})",
                    c as u32
                )));
            }
            // Bidirectional override characters
            0x202A..=0x202E | 0x2066..=0x2069 => {
                return Err(UniversalRunError::Profile(format!(
                    "String contains forbidden bidirectional control character (U+{:04X})",
                    c as u32
                )));
            }
            _ => {}
        }
    }
    Ok(())
}

/// Re-validate and canonicalize a host filesystem mapping path at use time.
/// Strictly rejects symlinks, Windows reserved names, traversal, and ambient $HOME / root.
pub fn validate_and_canonicalize_host_path(path_str: &str) -> Result<PathBuf> {
    check_unicode_safety(path_str)?;

    let trimmed = path_str.trim();
    if trimmed.is_empty() {
        return Err(UniversalRunError::Profile("Host path cannot be empty".into()));
    }

    // Reject direct references to $HOME or environment expansions
    if trimmed.contains("$HOME") || trimmed.contains("${HOME}") || trimmed.starts_with('~') {
        return Err(UniversalRunError::Profile(
            "Host path cannot reference $HOME or '~'; explicit sandboxed paths required".into(),
        ));
    }

    let path = Path::new(trimmed);

    // Inspect components for traversal and reserved names
    for comp in path.components() {
        match comp {
            Component::ParentDir => {
                return Err(UniversalRunError::Profile(
                    "Path traversal ('..') is strictly forbidden".into(),
                ));
            }
            Component::Normal(os_str) => {
                if let Some(s) = os_str.to_str() {
                    check_unicode_safety(s)?;
                    if is_windows_reserved_name(s) {
                        return Err(UniversalRunError::Profile(format!(
                            "Path component '{}' is a forbidden Windows reserved name",
                            s
                        )));
                    }
                }
            }
            _ => {}
        }
    }

    // If path exists on disk, check for symlinks and canonicalize
    if path.exists() {
        let meta = fs::symlink_metadata(path).map_err(|e| {
            UniversalRunError::Profile(format!("Failed to read metadata for '{}': {}", path_str, e))
        })?;

        if meta.file_type().is_symlink() {
            return Err(UniversalRunError::Profile(format!(
                "Host path '{}' is a symlink: symlinks are strictly rejected for security",
                path_str
            )));
        }

        let canonical = fs::canonicalize(path).map_err(|e| {
            UniversalRunError::Profile(format!("Failed to canonicalize '{}': {}", path_str, e))
        })?;

        // Re-verify that canonical path is not root
        if canonical.parent().is_none() {
            return Err(UniversalRunError::Profile(
                "Host path cannot map system root directory".into(),
            ));
        }

        Ok(canonical)
    } else {
        // Path does not exist yet (e.g. planned profile directory)
        Ok(path.to_path_buf())
    }
}

/// Validate guest target path (must be virtual Windows path like C:\...).
pub fn validate_guest_path(guest_path: &str) -> Result<()> {
    check_unicode_safety(guest_path)?;

    let trimmed = guest_path.trim();
    if trimmed.is_empty() {
        return Err(UniversalRunError::Profile("Guest path cannot be empty".into()));
    }

    // Must be a virtual Windows path starting with a drive letter C:\ or similar
    if !(trimmed.len() >= 3 && trimmed.as_bytes()[1] == b':' && (trimmed.as_bytes()[2] == b'\\' || trimmed.as_bytes()[2] == b'/')) {
        return Err(UniversalRunError::Profile(format!(
            "Guest path '{}' must be a virtual Windows drive path (e.g. 'C:\\users\\app\\Documents')",
            guest_path
        )));
    }

    if trimmed.contains("..") {
        return Err(UniversalRunError::Profile(
            "Guest path cannot contain traversal '..'".into(),
        ));
    }

    for part in trimmed.split(&['\\', '/'][..]) {
        if is_windows_reserved_name(part) {
            return Err(UniversalRunError::Profile(format!(
                "Guest path component '{}' is a forbidden Windows reserved name",
                part
            )));
        }
    }

    Ok(())
}

/// Detect case collisions within a collection of paths.
pub fn detect_case_collisions<P: AsRef<Path>>(paths: &[P]) -> Result<()> {
    let mut seen = HashSet::new();
    for p in paths {
        let normalized = p.as_ref().to_string_lossy().to_ascii_lowercase();
        if !seen.insert(normalized) {
            return Err(UniversalRunError::Profile(format!(
                "Case collision detected for path: {}",
                p.as_ref().display()
            )));
        }
    }
    Ok(())
}

