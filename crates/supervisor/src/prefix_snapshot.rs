use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use universalrun_common::error::{Result, UniversalRunError};

const MAX_SNAPSHOT_FILES: usize = 100_000;
const MAX_SNAPSHOT_DURATION: Duration = Duration::from_secs(15);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileMetadataEntry {
    pub size_bytes: u64,
    pub mtime_secs: u64,
    pub is_executable: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrefixSnapshot {
    pub root: PathBuf,
    pub files: HashMap<PathBuf, FileMetadataEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PrefixDiff {
    pub added: Vec<PathBuf>,
    pub modified: Vec<PathBuf>,
    pub removed: Vec<PathBuf>,
}

pub struct PrefixSnapshotter;

impl PrefixSnapshotter {
    /// Capture prefix filesystem snapshot.
    /// Invariant: NEVER follows symlinks; enforces file count and duration caps.
    pub fn snapshot(prefix_dir: &Path) -> Result<PrefixSnapshot> {
        let start = Instant::now();
        let mut files = HashMap::new();

        if prefix_dir.exists() {
            Self::scan_dir(prefix_dir, prefix_dir, &mut files, start)?;
        }

        Ok(PrefixSnapshot {
            root: prefix_dir.to_path_buf(),
            files,
        })
    }

    fn scan_dir(
        root: &Path,
        current_dir: &Path,
        files: &mut HashMap<PathBuf, FileMetadataEntry>,
        start: Instant,
    ) -> Result<()> {
        if start.elapsed() > MAX_SNAPSHOT_DURATION {
            return Err(UniversalRunError::Sandbox(
                "Prefix snapshot exceeded time safety budget of 15 seconds".into(),
            ));
        }

        let entries = match fs::read_dir(current_dir) {
            Ok(e) => e,
            Err(_) => return Ok(()), // Ignore inaccessible directories gracefully
        };

        for entry_res in entries {
            let entry = match entry_res {
                Ok(e) => e,
                Err(_) => continue,
            };

            let path = entry.path();
            // NEVER FOLLOW SYMLINKS: use symlink_metadata
            let meta = match fs::symlink_metadata(&path) {
                Ok(m) => m,
                Err(_) => continue,
            };

            if meta.file_type().is_symlink() {
                // Strictly skip following symlinks to prevent loops and host traversal
                continue;
            }

            if meta.is_dir() {
                Self::scan_dir(root, &path, files, start)?;
            } else if meta.is_file() {
                if files.len() >= MAX_SNAPSHOT_FILES {
                    return Err(UniversalRunError::Sandbox(
                        "Prefix snapshot exceeded safety cap of 100,000 files".into(),
                    ));
                }

                let rel_path = path.strip_prefix(root).unwrap_or(&path).to_path_buf();
                let mtime_secs = meta
                    .modified()
                    .unwrap_or(SystemTime::now())
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();

                let is_executable = path
                    .extension()
                    .and_then(|s| s.to_str())
                    .map(|ext| ext.eq_ignore_ascii_case("exe"))
                    .unwrap_or(false);

                files.insert(
                    rel_path,
                    FileMetadataEntry {
                        size_bytes: meta.len(),
                        mtime_secs,
                        is_executable,
                    },
                );
            }
        }

        Ok(())
    }

    /// Compare two prefix snapshots and return added/modified/removed files.
    pub fn diff(before: &PrefixSnapshot, after: &PrefixSnapshot) -> PrefixDiff {
        let mut added = Vec::new();
        let mut modified = Vec::new();
        let mut removed = Vec::new();

        for (path, after_meta) in &after.files {
            match before.files.get(path) {
                None => added.push(path.clone()),
                Some(before_meta) => {
                    if before_meta.size_bytes != after_meta.size_bytes
                        || before_meta.mtime_secs != after_meta.mtime_secs
                    {
                        modified.push(path.clone());
                    }
                }
            }
        }

        for path in before.files.keys() {
            if !after.files.contains_key(path) {
                removed.push(path.clone());
            }
        }

        PrefixDiff {
            added,
            modified,
            removed,
        }
    }
}
