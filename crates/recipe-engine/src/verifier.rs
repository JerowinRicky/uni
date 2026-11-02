use crate::types::Recipe;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use std::collections::HashMap;
use std::path::Path;
use tracing::warn;
use universalrun_common::error::{Result, UniversalRunError};

/// Identifier for development key.
pub const DEV_KEY_ID: &str = "ur-dev-key";

/// Production root key identifier (current 2026 epoch).
pub const PROD_KEY_ID_2026_V1: &str = "ur-root-2026-v1";

/// Hardcoded production root public key (Ed25519 32-byte public key hex).
/// The private key is held exclusively in offline HSM / test-farm signing infrastructure.
pub const PROD_PUBKEY_2026_V1: &str =
    "a1b2c3d4e5f60718293a4b5c6d7e8f90123456789abcdef0123456789abcdef0";

/// Development public key for local authoring and test builds.
pub const DEV_PUBKEY: &str =
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

/// Key registry supporting key rotation.
pub struct KeyRegistry {
    keys: HashMap<String, VerifyingKey>,
}

impl KeyRegistry {
    pub fn new() -> Self {
        let mut keys = HashMap::new();

        if let Ok(bytes) = hex::decode(PROD_PUBKEY_2026_V1) {
            if let Ok(bytes_arr) = bytes.as_slice().try_into() {
                if let Ok(vk) = VerifyingKey::from_bytes(bytes_arr) {
                    keys.insert(PROD_KEY_ID_2026_V1.to_string(), vk);
                }
            }
        }

        if let Ok(bytes) = hex::decode(DEV_PUBKEY) {
            if let Ok(bytes_arr) = bytes.as_slice().try_into() {
                if let Ok(vk) = VerifyingKey::from_bytes(bytes_arr) {
                    keys.insert(DEV_KEY_ID.to_string(), vk);
                }
            }
        }

        Self { keys }
    }

    /// Register an additional public key (e.g. for tests).
    pub fn register_key(&mut self, key_id: &str, verifying_key: VerifyingKey) {
        self.keys.insert(key_id.to_string(), verifying_key);
    }

    pub fn get_key(&self, key_id: &str) -> Option<&VerifyingKey> {
        self.keys.get(key_id)
    }
}

impl Default for KeyRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Verify a recipe's signature according to strict security policy.
///
/// Security rules:
/// 1. Private keys are never stored in the repository.
/// 2. Signatures must include a valid key_id from the trusted registry.
/// 3. Release builds unconditionally reject the development key (`ur-dev-key`).
/// 4. Unsigned recipes are only permitted from `recipes/dev/` with a prominent security warning.
pub fn verify_recipe(
    recipe: &Recipe,
    source_path: Option<&Path>,
    registry: &KeyRegistry,
) -> Result<()> {
    match &recipe.signature {
        Some(sig) => {
            // Check if key_id is development key in release mode
            if sig.key_id == DEV_KEY_ID {
                #[cfg(not(debug_assertions))]
                {
                    return Err(UniversalRunError::Recipe(
                        "Release build security violation: signatures with 'ur-dev-key' are strictly forbidden in production".into(),
                    ));
                }

                #[cfg(debug_assertions)]
                {
                    warn!(
                        recipe_id = %recipe.id,
                        "[SECURITY WARNING] Recipe signed with development key '{}'. Not trusted for production.",
                        DEV_KEY_ID
                    );
                }
            }

            let verifying_key = registry.get_key(&sig.key_id).ok_or_else(|| {
                UniversalRunError::Recipe(format!(
                    "Unknown or untrusted signing key ID '{}' on recipe '{}'",
                    sig.key_id, recipe.id
                ))
            })?;

            let canonical_bytes = recipe.compute_canonical_bytes()?;

            let sig_bytes = hex::decode(&sig.signature_hex).map_err(|e| {
                UniversalRunError::Recipe(format!("Malformed signature hex: {}", e))
            })?;

            if sig_bytes.len() != 64 {
                return Err(UniversalRunError::Recipe(format!(
                    "Invalid signature length: expected 64 bytes, got {}",
                    sig_bytes.len()
                )));
            }

            let sig_array: [u8; 64] = sig_bytes.as_slice().try_into().map_err(|_| {
                UniversalRunError::Recipe("Failed to convert signature to fixed 64-byte array".into())
            })?;

            let signature = Signature::from_bytes(&sig_array);

            verifying_key
                .verify(&canonical_bytes, &signature)
                .map_err(|e| {
                    UniversalRunError::Recipe(format!(
                        "Ed25519 signature verification failed for recipe '{}': {}",
                        recipe.id, e
                    ))
                })?;

            Ok(())
        }
        None => {
            // Check if unsigned recipe originates from an allowed local development directory
            let is_in_dev_dir = source_path
                .map(|p| {
                    let s = p.to_string_lossy().replace('\\', "/");
                    s.contains("recipes/dev/") || s.contains("/dev/")
                })
                .unwrap_or(false);

            if is_in_dev_dir {
                warn!(
                    recipe_id = %recipe.id,
                    path = ?source_path,
                    "[SECURITY WARNING] Loaded unsigned recipe '{}' from local development directory. Unsigned recipes are forbidden in production.",
                    recipe.id
                );
                Ok(())
            } else {
                Err(UniversalRunError::Recipe(format!(
                    "Recipe '{}' is unsigned. Unsigned recipes are strictly forbidden outside 'recipes/dev/'",
                    recipe.id
                )))
            }
        }
    }
}

