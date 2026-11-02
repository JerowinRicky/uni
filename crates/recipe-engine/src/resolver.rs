use crate::catalog::{DependencyCatalog, DependencyEntry};
use directories::ProjectDirs;
use sha2::{Digest, Sha256};
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use tracing::{info, warn};
use universalrun_common::error::{Result, UniversalRunError};

use serde::{Deserialize, Serialize};

/// Pinned dependency resolution plan entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolvedDependencyPlan {
    pub id: String,
    pub name: String,
    pub version: String,
    pub source_url: String,
    pub sha256: String,
    pub max_size_bytes: u64,
    pub is_verified: bool,
    pub cached: bool,
}

/// Hardened dependency resolver and downloader.
pub struct DependencyResolver {
    catalog: DependencyCatalog,
    cache_dir: PathBuf,
}

impl DependencyResolver {
    pub fn new(catalog: DependencyCatalog, custom_cache: Option<PathBuf>) -> Self {
        let cache_dir = custom_cache.unwrap_or_else(Self::default_cache_dir);
        Self { catalog, cache_dir }
    }

    pub fn default_cache_dir() -> PathBuf {
        ProjectDirs::from("org", "universalrun", "universalrun")
            .map(|dirs| dirs.cache_dir().join("dependencies"))
            .unwrap_or_else(|| PathBuf::from(".universalrun/cache/dependencies"))
    }

    pub fn catalog(&self) -> &DependencyCatalog {
        &self.catalog
    }

    pub fn cache_dir(&self) -> &Path {
        &self.cache_dir
    }

    /// Compute dependency plan for a list of dependency IDs without downloading anything.
    pub fn create_plan(&self, dependency_ids: &[String]) -> Result<Vec<ResolvedDependencyPlan>> {
        let mut plan = Vec::new();

        for id in dependency_ids {
            let entry = self.catalog.get(id).ok_or_else(|| {
                UniversalRunError::Recipe(format!(
                    "Dependency '{}' not found in dependency catalog",
                    id
                ))
            })?;

            let cached = if entry.is_verified() {
                self.cache_dir.join(format!("{}.bin", entry.sha256.to_ascii_lowercase())).exists()
            } else {
                false
            };

            plan.push(ResolvedDependencyPlan {
                id: entry.id.clone(),
                name: entry.name.clone(),
                version: entry.version.clone(),
                source_url: entry.source_url.clone(),
                sha256: entry.sha256.clone(),
                max_size_bytes: entry.max_size_bytes,
                is_verified: entry.is_verified(),
                cached,
            });
        }

        Ok(plan)
    }

    /// Fetch and verify a single dependency.
    ///
    /// Security guarantees:
    /// - Strictly refuses dependencies marked with "TODO" or empty hashes.
    /// - HTTPS only on origin URL and on every redirect hop.
    /// - Maximum 3 redirects.
    /// - Size cap checked while streaming; aborts immediately if exceeded.
    /// - Downloaded to temp file -> verified via SHA-256 -> atomic rename to cache.
    /// - No corrupted or unverified files are ever left in the cache.
    pub fn fetch_dependency(&self, entry: &DependencyEntry) -> Result<PathBuf> {
        if !entry.is_verified() {
            return Err(UniversalRunError::Recipe(format!(
                "Dependency '{}' has unverified hash (marked TODO). The resolver strictly refuses to download unverified dependencies.",
                entry.id
            )));
        }

        fs::create_dir_all(&self.cache_dir).map_err(UniversalRunError::Io)?;
        let final_path = self
            .cache_dir
            .join(format!("{}.bin", entry.sha256.to_ascii_lowercase()));

        // Return immediately if already verified in cache
        if final_path.exists() {
            if let Ok(mut f) = File::open(&final_path) {
                let mut hasher = Sha256::new();
                let mut buffer = [0u8; 8192];
                while let Ok(n) = f.read(&mut buffer) {
                    if n == 0 {
                        break;
                    }
                    hasher.update(&buffer[..n]);
                }
                let hex_digest = hex::encode(hasher.finalize());
                if hex_digest.eq_ignore_ascii_case(&entry.sha256) {
                    info!(id = %entry.id, "Dependency already verified in cache");
                    return Ok(final_path);
                } else {
                    warn!(id = %entry.id, "Cached dependency checksum mismatch, re-fetching");
                    let _ = fs::remove_file(&final_path);
                }
            }
        }

        // Test-only mock path
        #[cfg(test)]
        if entry.source_url.starts_with("test://") {
            return self.fetch_test_mock(entry, &final_path);
        }

        // Enforce HTTPS
        if !entry.source_url.starts_with("https://") {
            return Err(UniversalRunError::Recipe(format!(
                "Insecure URL '{}' for dependency '{}': only HTTPS is permitted",
                entry.source_url, entry.id
            )));
        }

        // Configure hardened HTTP client
        let client = reqwest::blocking::Client::builder()
            .redirect(reqwest::redirect::Policy::custom(|attempt| {
                if attempt.url().scheme() != "https" {
                    return attempt.error("Insecure redirect: every redirect hop must be HTTPS");
                }
                if attempt.previous().len() >= 3 {
                    return attempt.error("Too many redirects: exceeded maximum of 3 hops");
                }
                attempt.follow()
            }))
            .timeout(std::time::Duration::from_secs(60))
            .build()
            .map_err(|e| {
                UniversalRunError::Recipe(format!("Failed to build HTTP client: {}", e))
            })?;

        let mut response = client.get(&entry.source_url).send().map_err(|e| {
            UniversalRunError::Recipe(format!("Download failed for '{}': {}", entry.id, e))
        })?;

        if !response.status().is_success() {
            return Err(UniversalRunError::Recipe(format!(
                "HTTP error {} downloading dependency '{}'",
                response.status(),
                entry.id
            )));
        }

        // Write to temp file with size cap and live hash verification
        let temp_path = self
            .cache_dir
            .join(format!("{}.tmp.{}", entry.id, std::process::id()));
        let mut temp_file = File::create(&temp_path).map_err(UniversalRunError::Io)?;

        let mut hasher = Sha256::new();
        let mut buffer = [0u8; 8192];
        let mut total_bytes: u64 = 0;

        loop {
            let n = response.read(&mut buffer).map_err(UniversalRunError::Io)?;
            if n == 0 {
                break;
            }

            total_bytes += n as u64;
            if total_bytes > entry.max_size_bytes {
                let _ = fs::remove_file(&temp_path);
                return Err(UniversalRunError::Recipe(format!(
                    "Download size for '{}' exceeded declared catalog limit of {} bytes (received {} bytes)",
                    entry.id, entry.max_size_bytes, total_bytes
                )));
            }

            hasher.update(&buffer[..n]);
            temp_file
                .write_all(&buffer[..n])
                .map_err(UniversalRunError::Io)?;
        }

        temp_file.flush().map_err(UniversalRunError::Io)?;
        drop(temp_file);

        let computed_digest = hex::encode(hasher.finalize());
        if !computed_digest.eq_ignore_ascii_case(&entry.sha256) {
            let _ = fs::remove_file(&temp_path);
            return Err(UniversalRunError::Recipe(format!(
                "Checksum mismatch for dependency '{}': expected {}, computed {}",
                entry.id, entry.sha256, computed_digest
            )));
        }

        // Atomic move to final cache location
        fs::rename(&temp_path, &final_path).map_err(UniversalRunError::Io)?;
        info!(
            id = %entry.id,
            path = %final_path.display(),
            "Dependency downloaded and verified"
        );

        Ok(final_path)
    }

    #[cfg(test)]
    fn fetch_test_mock(&self, entry: &DependencyEntry, final_path: &Path) -> Result<PathBuf> {
        let payload = entry.source_url.trim_start_matches("test://").as_bytes();
        if payload.len() as u64 > entry.max_size_bytes {
            return Err(UniversalRunError::Recipe(format!(
                "Download size exceeded limit of {} bytes",
                entry.max_size_bytes
            )));
        }

        let mut hasher = Sha256::new();
        hasher.update(payload);
        let digest = hex::encode(hasher.finalize());

        if !digest.eq_ignore_ascii_case(&entry.sha256) {
            return Err(UniversalRunError::Recipe(format!(
                "Checksum mismatch: expected {}, computed {}",
                entry.sha256, digest
            )));
        }

        fs::write(final_path, payload).map_err(UniversalRunError::Io)?;
        Ok(final_path.to_path_buf())
    }
}

