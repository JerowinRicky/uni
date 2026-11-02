use crate::types::ProfileManifest;
use crate::validation::{
    detect_case_collisions, validate_and_canonicalize_host_path, validate_guest_path,
    validate_profile_id,
};
use directories::ProjectDirs;
use std::fs;
use std::path::{Path, PathBuf};
use tracing::{info, warn};
use universalrun_common::error::{Result, UniversalRunError};

pub struct ProfileStorage {
    root_dir: PathBuf,
}

impl ProfileStorage {
    /// Create new ProfileStorage with custom or standard XDG/OS storage path.
    pub fn new(custom_root: Option<PathBuf>) -> Self {
        let root_dir = custom_root.unwrap_or_else(Self::default_base_dir);
        Self { root_dir }
    }

    /// Resolve default storage path using `directories` crate (XDG on Linux).
    pub fn default_base_dir() -> PathBuf {
        ProjectDirs::from("org", "universalrun", "universalrun")
            .map(|dirs| dirs.data_dir().join("profiles"))
            .unwrap_or_else(|| PathBuf::from(".universalrun/profiles"))
    }

    pub fn root_dir(&self) -> &Path {
        &self.root_dir
    }

    pub fn profile_dir(&self, id: &str) -> PathBuf {
        self.root_dir.join(id)
    }

    /// Create or initialize a profile from its manifest.
    pub fn create_profile(&self, manifest: &ProfileManifest) -> Result<PathBuf> {
        validate_profile_id(&manifest.profile_id)?;

        // Validate filesystem mappings
        let mut host_paths = Vec::new();
        for mapping in &manifest.filesystem_mappings {
            let canonical = validate_and_canonicalize_host_path(&mapping.host_path)?;
            validate_guest_path(&mapping.guest_path)?;
            host_paths.push(canonical);
        }
        detect_case_collisions(&host_paths)?;

        let p_dir = self.profile_dir(&manifest.profile_id);
        if p_dir.exists() {
            return Err(UniversalRunError::Profile(format!(
                "Profile '{}' already exists at '{}'",
                manifest.profile_id,
                p_dir.display()
            )));
        }

        fs::create_dir_all(&p_dir).map_err(UniversalRunError::Io)?;

        // Prepare finalized manifest with computed rebuild hash
        let mut finalized = manifest.clone();
        finalized.rebuild_hash = Some(manifest.compute_rebuild_hash());

        // Save manifest in TOML and JSON formats for auditability
        let toml_str = toml::to_string_pretty(&finalized)
            .map_err(|e| UniversalRunError::Profile(format!("Failed to serialize TOML: {}", e)))?;
        let json_str = serde_json::to_string_pretty(&finalized)
            .map_err(|e| UniversalRunError::Profile(format!("Failed to serialize JSON: {}", e)))?;

        fs::write(p_dir.join("profile.toml"), toml_str).map_err(UniversalRunError::Io)?;
        fs::write(p_dir.join("profile.json"), json_str).map_err(UniversalRunError::Io)?;

        info!(
            profile_id = %manifest.profile_id,
            path = %p_dir.display(),
            "Profile created successfully"
        );

        Ok(p_dir)
    }

    /// Load an existing profile manifest.
    pub fn get_profile(&self, id: &str) -> Result<ProfileManifest> {
        validate_profile_id(id)?;
        let p_dir = self.profile_dir(id);
        if !p_dir.exists() {
            return Err(UniversalRunError::Profile(format!(
                "Profile '{}' does not exist",
                id
            )));
        }

        let toml_path = p_dir.join("profile.toml");
        if toml_path.exists() {
            let content = fs::read_to_string(&toml_path).map_err(UniversalRunError::Io)?;
            let manifest: ProfileManifest = toml::from_str(&content).map_err(|e| {
                UniversalRunError::Profile(format!("Failed to parse profile manifest: {}", e))
            })?;
            return Ok(manifest);
        }

        let json_path = p_dir.join("profile.json");
        if json_path.exists() {
            let content = fs::read_to_string(&json_path).map_err(UniversalRunError::Io)?;
            let manifest: ProfileManifest = serde_json::from_str(&content).map_err(|e| {
                UniversalRunError::Profile(format!("Failed to parse profile manifest: {}", e))
            })?;
            return Ok(manifest);
        }

        Err(UniversalRunError::Profile(format!(
            "No profile manifest found in '{}'",
            p_dir.display()
        )))
    }

    /// List all installed profiles.
    pub fn list_profiles(&self) -> Result<Vec<ProfileManifest>> {
        if !self.root_dir.exists() {
            return Ok(Vec::new());
        }

        let mut results = Vec::new();
        let entries = fs::read_dir(&self.root_dir).map_err(UniversalRunError::Io)?;

        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                    if let Ok(manifest) = self.get_profile(name) {
                        results.push(manifest);
                    }
                }
            }
        }

        Ok(results)
    }

    /// Delete a profile.
    pub fn delete_profile(&self, id: &str) -> Result<()> {
        validate_profile_id(id)?;
        let p_dir = self.profile_dir(id);
        if !p_dir.exists() {
            return Err(UniversalRunError::Profile(format!(
                "Profile '{}' does not exist",
                id
            )));
        }

        fs::remove_dir_all(&p_dir).map_err(UniversalRunError::Io)?;
        info!(profile_id = %id, "Profile deleted successfully");
        Ok(())
    }

    /// Rebuild profile from manifest, applying downgrade protection checks.
    pub fn rebuild_profile(
        &self,
        id: &str,
        allow_older: bool,
        new_manifest: Option<&ProfileManifest>,
    ) -> Result<ProfileManifest> {
        let existing = self.get_profile(id)?;

        let target_manifest = if let Some(new_m) = new_manifest {
            // Check downgrade protection
            let existing_rev = existing.recipe_revision.unwrap_or(0);
            let candidate_rev = new_m.recipe_revision.unwrap_or(0);

            if candidate_rev < existing_rev {
                if !allow_older {
                    return Err(UniversalRunError::Profile(format!(
                        "Downgrade rejected: existing profile has revision {}, candidate recipe has older revision {}. Use --allow-older to force deliberate rebuild.",
                        existing_rev, candidate_rev
                    )));
                } else {
                    warn!(
                        "Deliberate profile downgrade permitted: revision {} -> {} (--allow-older specified)",
                        existing_rev, candidate_rev
                    );
                }
            }
            new_m.clone()
        } else {
            existing
        };

        // Re-verify hash and re-write manifests
        let p_dir = self.profile_dir(id);
        let mut finalized = target_manifest;
        finalized.rebuild_hash = Some(finalized.compute_rebuild_hash());

        let toml_str = toml::to_string_pretty(&finalized)
            .map_err(|e| UniversalRunError::Profile(format!("Failed to serialize TOML: {}", e)))?;
        let json_str = serde_json::to_string_pretty(&finalized)
            .map_err(|e| UniversalRunError::Profile(format!("Failed to serialize JSON: {}", e)))?;

        fs::write(p_dir.join("profile.toml"), toml_str).map_err(UniversalRunError::Io)?;
        fs::write(p_dir.join("profile.json"), json_str).map_err(UniversalRunError::Io)?;

        info!(profile_id = %id, "Profile rebuilt successfully from manifest alone");
        Ok(finalized)
    }
}

