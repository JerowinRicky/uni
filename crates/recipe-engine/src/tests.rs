use crate::catalog::{DependencyCatalog, DependencyEntry};
use crate::matching::match_recipe;
use crate::resolver::DependencyResolver;
use crate::types::{MatchRules, Recipe, RecipeSignature, RuntimeRecipeConfig};
use crate::verifier::{verify_recipe, KeyRegistry};
use ed25519_dalek::{Signer, SigningKey};
use rand::RngCore;
use std::collections::HashMap;
use std::path::PathBuf;
use tempfile::tempdir;
use universalrun_analyzer::{
    AnalysisReport, Architecture, CompatibilityRating, RatingCategory, Subsystem,
};
use universalrun_profile_manager::{DllOverrideMode, PermissionPolicy};

fn sample_recipe(id: &str, revision: u32) -> Recipe {
    let mut overrides = HashMap::new();
    overrides.insert("d3d11".to_string(), DllOverrideMode::Native);

    Recipe {
        schema_version: Recipe::SCHEMA_VERSION.to_string(),
        id: id.to_string(),
        revision,
        name: "Test Recipe".to_string(),
        match_rules: MatchRules {
            sha256: vec!["abc123456789".to_string()],
            product_name: Some("test-app".to_string()),
            min_version: None,
            max_version: None,
        },
        runtime: RuntimeRecipeConfig {
            preferred: "wine".to_string(),
            min_version: "9.0".to_string(),
            architecture: "win64".to_string(),
            windows_version: "win10".to_string(),
        },
        dotnet_runtime: crate::types::DotNetRuntimeStrategy::None,
        dependencies: vec!["vcredist2022".to_string()],
        dll_overrides: overrides,
        registry_entries: Vec::new(),
        permissions: PermissionPolicy::default(),
        known_issues: Vec::new(),
        tested_results: Vec::new(),
        signature: None,
    }
}

#[test]
fn test_canonical_bytes_determinism() {
    let r1 = sample_recipe("notepad-test", 1);
    let mut r2 = sample_recipe("notepad-test", 1);
    r2.signature = Some(RecipeSignature {
        key_id: "test-key".to_string(),
        signature_hex: "00".repeat(64),
    });

    let bytes1 = r1.compute_canonical_bytes().expect("canonical bytes r1");
    let bytes2 = r2.compute_canonical_bytes().expect("canonical bytes r2");
    assert_eq!(bytes1, bytes2, "Canonical bytes must ignore signature field");
}

#[test]
fn test_security_rule_unsigned_recipe() {
    let registry = KeyRegistry::new();
    let recipe = sample_recipe("unsigned-app", 1);

    // Rule: Unsigned recipe outside recipes/dev/ MUST be rejected
    let outside_path = PathBuf::from("recipes/community/app.toml");
    let res_outside = verify_recipe(&recipe, Some(&outside_path), &registry);
    assert!(res_outside.is_err(), "Unsigned recipe from community/ must be rejected");

    let no_path_res = verify_recipe(&recipe, None, &registry);
    assert!(no_path_res.is_err(), "Unsigned recipe with no path must be rejected");

    // Rule: Unsigned recipe inside recipes/dev/ is permitted with security warning
    let dev_path = PathBuf::from("recipes/dev/my-app.toml");
    let res_dev = verify_recipe(&recipe, Some(&dev_path), &registry);
    assert!(res_dev.is_ok(), "Unsigned recipe in recipes/dev/ must be permitted");
}

#[test]
fn test_security_rule_signature_verification_and_tampering() {
    let mut csprng = rand::thread_rng();
    let mut secret_bytes = [0u8; 32];
    csprng.fill_bytes(&mut secret_bytes);
    let signing_key = SigningKey::from_bytes(&secret_bytes);
    let verifying_key = signing_key.verifying_key();

    let mut registry = KeyRegistry::new();
    registry.register_key("test-ephemeral-key", verifying_key);

    let mut recipe = sample_recipe("signed-app", 1);
    let canonical_bytes = recipe.compute_canonical_bytes().expect("canonical bytes");
    let sig = signing_key.sign(&canonical_bytes);

    recipe.signature = Some(RecipeSignature {
        key_id: "test-ephemeral-key".to_string(),
        signature_hex: hex::encode(sig.to_bytes()),
    });

    // Verification succeeds
    assert!(verify_recipe(&recipe, None, &registry).is_ok());

    // Tampering detection: changing revision invalidates signature
    let mut tampered = recipe.clone();
    tampered.revision = 2;
    assert!(verify_recipe(&tampered, None, &registry).is_err(), "Tampered recipe must fail verification");

    // Unknown Key ID rejection
    let mut rogue_key = recipe.clone();
    if let Some(sig) = &mut rogue_key.signature {
        sig.key_id = "unknown-rogue-key".to_string();
    }
    assert!(verify_recipe(&rogue_key, None, &registry).is_err(), "Unknown key ID must be rejected");
}

#[test]
fn test_security_rule_dev_key_policy() {
    let registry = KeyRegistry::new();
    let mut recipe = sample_recipe("dev-key-app", 1);
    recipe.signature = Some(RecipeSignature {
        key_id: crate::verifier::DEV_KEY_ID.to_string(),
        signature_hex: "00".repeat(64),
    });

    #[cfg(not(debug_assertions))]
    {
        let res = verify_recipe(&recipe, None, &registry);
        assert!(res.is_err(), "Release builds must strictly reject ur-dev-key signatures");
        assert!(res.unwrap_err().to_string().contains("forbidden in production"));
    }

    #[cfg(debug_assertions)]
    {
        // In debug builds, verify_recipe continues to cryptographic check (which fails on dummy signature)
        let res = verify_recipe(&recipe, None, &registry);
        assert!(res.is_err(), "Dummy signature must fail Dalek verification");
    }
}

#[test]
fn test_security_rule_todo_hash_rejection() {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let catalog_path = manifest_dir.join("../../recipes/catalog/dependencies.toml");
    let catalog = DependencyCatalog::from_file(&catalog_path)
        .expect("load dependencies.toml from repository");

    let vcredist = catalog.get("vcredist2022").cloned().expect("vcredist2022 exists");
    assert_eq!(vcredist.sha256, "TODO", "Catalog entry must maintain literal TODO");
    assert!(!vcredist.is_verified());

    let temp = tempdir().expect("tempdir");
    let resolver = DependencyResolver::new(catalog.clone(), Some(temp.path().to_path_buf()));

    // Rule: Resolver MUST strictly reject dependencies with TODO hash
    let res = resolver.fetch_dependency(&vcredist);
    assert!(res.is_err(), "Resolver must strictly refuse to download unverified TODO hashes");
    let err_msg = res.unwrap_err().to_string();
    assert!(err_msg.contains("unverified hash (marked TODO)"));
}

#[test]
fn test_security_rule_checksum_mismatch_and_size_cap() {
    use sha2::{Digest, Sha256};
    let payload = b"UniversalRun Test Binary Payload - Safe Content";
    let hash = hex::encode(Sha256::digest(payload));

    let entry = DependencyEntry {
        id: "mock-dep".to_string(),
        name: "Mock Dependency".to_string(),
        version: "1.0".to_string(),
        source_url: format!("test://{}", String::from_utf8_lossy(payload)),
        sha256: hash,
        max_size_bytes: 1024,
        license: "MIT".to_string(),
        provenance: "Test Suite".to_string(),
    };

    let temp = tempdir().expect("tempdir");
    let mut catalog = DependencyCatalog::default();
    catalog.dependencies.insert("mock-dep".to_string(), entry.clone());

    let resolver = DependencyResolver::new(catalog.clone(), Some(temp.path().to_path_buf()));

    // 1. Valid download succeeds
    let path = resolver.fetch_dependency(&entry).expect("fetch valid");
    assert!(path.exists());

    // 2. Rule: Checksum mismatch MUST fail and delete temporary file
    let mut bad_entry = entry.clone();
    bad_entry.sha256 = "00".repeat(32);
    let mismatch_res = resolver.fetch_dependency(&bad_entry);
    assert!(mismatch_res.is_err(), "Checksum mismatch must be rejected");

    // 3. Rule: Exceeding declared catalog size cap MUST abort immediately
    let temp_size = tempdir().expect("tempdir");
    let resolver_size = DependencyResolver::new(catalog, Some(temp_size.path().to_path_buf()));
    let mut size_exceeded = entry;
    size_exceeded.max_size_bytes = 10; // Less than payload size
    let size_res = resolver_size.fetch_dependency(&size_exceeded);
    assert!(size_res.is_err(), "Exceeding size cap must fail");
}

#[test]
fn test_recipe_matching_precedence() {
    let recipe_sha = Recipe {
        match_rules: MatchRules {
            sha256: vec!["sha_exact_match_999".to_string()],
            product_name: None,
            min_version: None,
            max_version: None,
        },
        ..sample_recipe("exact-sha-recipe", 1)
    };

    let recipe_name = Recipe {
        match_rules: MatchRules {
            sha256: Vec::new(),
            product_name: Some("AppTarget".to_string()),
            min_version: None,
            max_version: None,
        },
        ..sample_recipe("name-recipe", 1)
    };

    let candidates = vec![recipe_name, recipe_sha];

    let report = AnalysisReport {
        schema_version: "1.0.0".to_string(),
        file_name: "AppTarget_v1.exe".to_string(),
        file_size_bytes: 1000,
        sha256: "sha_exact_match_999".to_string(),
        architecture: Some(Architecture::X64),
        subsystem: Some(Subsystem::WindowsGui),
        entry_point: Some(100),
        num_sections: 4,
        imports: Vec::new(),
        delay_load_imports: Vec::new(),
        execution_level: universalrun_analyzer::Finding {
            value: universalrun_analyzer::ExecutionLevel::AsInvoker,
            confidence: universalrun_analyzer::Confidence::Certain,
            note: None,
        },
        authenticode: universalrun_analyzer::AuthenticodeReport {
            signature_present: false,
            file_hash_verified: None,
            chain_trust: universalrun_analyzer::ChainTrust::Unknown,
            publisher: None,
            note: None,
        },
        installer_type: universalrun_analyzer::Finding {
            value: universalrun_analyzer::InstallerKind::Portable,
            confidence: universalrun_analyzer::Confidence::Certain,
            note: None,
        },
        installer_version: None,
        dotnet: None,
        graphics_apis: Vec::new(),
        required_runtimes: Vec::new(),
        security_flags: universalrun_analyzer::SecurityFlags {
            requests_admin: false,
            has_drivers_or_services: false,
            known_anticheat_or_drm: None,
        },
        compatibility_rating: CompatibilityRating {
            category: RatingCategory::Good,
            summary: "Good".to_string(),
            evidence: Vec::new(),
        },
        unverifiable_aspects: Vec::new(),
    };

    // 1. Exact SHA match takes precedence
    let match1 = match_recipe(&report, &candidates).expect("match1");
    assert_eq!(match1.match_type(), "exact_sha256");
    assert_eq!(match1.recipe().id, "exact-sha-recipe");

    // 2. Name match when SHA differs
    let mut report2 = report.clone();
    report2.sha256 = "different_sha".to_string();
    let match2 = match_recipe(&report2, &candidates).expect("match2");
    assert_eq!(match2.match_type(), "product_name");
    assert_eq!(match2.recipe().id, "name-recipe");

    // 3. Fallback synthesis when nothing matches
    let mut report3 = report;
    report3.file_name = "UnknownProgram.exe".to_string();
    report3.sha256 = "different_sha".to_string();
    let match3 = match_recipe(&report3, &candidates).expect("match3");
    assert_eq!(match3.match_type(), "synthesized_fallback");
    assert!(match3.recipe().id.contains("fallback"));
}
