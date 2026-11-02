use std::collections::HashMap;
use tempfile::tempdir;
use universalrun_profile_manager::{
    detect_case_collisions, is_windows_reserved_name, validate_and_canonicalize_host_path,
    validate_guest_path, validate_profile_id, DllOverrideMode, PermissionPolicy,
    ProfileManifest, ProfileStorage, RuntimeConfig,
};

fn sample_manifest(id: &str, revision: u32) -> ProfileManifest {
    let mut overrides = HashMap::new();
    overrides.insert("d3d11".to_string(), DllOverrideMode::Native);

    ProfileManifest {
        schema_version: ProfileManifest::SCHEMA_VERSION.to_string(),
        profile_id: id.to_string(),
        display_name: "Test Application".to_string(),
        target_app: "app.exe".to_string(),
        target_app_sha256: Some(
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string(),
        ),
        recipe_id: Some("test-recipe".to_string()),
        recipe_revision: Some(revision),
        runtime: RuntimeConfig {
            name: "wine".to_string(),
            version: "9.0".to_string(),
            architecture: "win64".to_string(),
            windows_version: "win10".to_string(),
        },
        dependencies: Vec::new(),
        env_vars: HashMap::new(),
        dll_overrides: overrides,
        filesystem_mappings: Vec::new(),
        permissions: PermissionPolicy::default(),
        wine_debug: None,
        rebuild_hash: None,
    }
}

#[test]
fn test_profile_id_validation() {
    assert!(validate_profile_id("valid-profile-123_test").is_ok());

    // Too long
    let long_id = "a".repeat(65);
    assert!(validate_profile_id(&long_id).is_err());

    // Empty
    assert!(validate_profile_id("").is_err());

    // Forbidden characters
    assert!(validate_profile_id("invalid/id").is_err());
    assert!(validate_profile_id("invalid id").is_err());
    assert!(validate_profile_id("invalid..id").is_err());

    // Windows reserved names
    assert!(validate_profile_id("con").is_err());
    assert!(validate_profile_id("PRN").is_err());
    assert!(validate_profile_id("aux").is_err());
    assert!(validate_profile_id("NUL").is_err());
    assert!(validate_profile_id("COM1").is_err());
    assert!(validate_profile_id("lpt9").is_err());
}

#[test]
fn test_windows_reserved_names_detection() {
    assert!(is_windows_reserved_name("CON"));
    assert!(is_windows_reserved_name("con.txt"));
    assert!(is_windows_reserved_name("aux.tar.gz"));
    assert!(is_windows_reserved_name("NUL"));
    assert!(is_windows_reserved_name("com3.dll"));
    assert!(!is_windows_reserved_name("console.txt"));
    assert!(!is_windows_reserved_name("auxiliary.dll"));
}

#[test]
fn test_path_sanitization_and_traversal_rejection() {
    assert!(validate_and_canonicalize_host_path("../secret").is_err());
    assert!(validate_and_canonicalize_host_path("sub/../../traversal").is_err());
    assert!(validate_and_canonicalize_host_path("$HOME/documents").is_err());
    assert!(validate_and_canonicalize_host_path("~/documents").is_err());

    // Unicode bidirectional trickery
    assert!(validate_and_canonicalize_host_path("folder\u{202E}txt").is_err());
    // Zero-width space
    assert!(validate_and_canonicalize_host_path("folder\u{200B}test").is_err());
    // Control chars
    assert!(validate_and_canonicalize_host_path("folder\nmalicious").is_err());
}

#[test]
fn test_guest_path_validation() {
    assert!(validate_guest_path("C:\\Program Files\\App").is_ok());
    assert!(validate_guest_path("c:/users/app/Documents").is_ok());

    // Non-virtual Windows drive
    assert!(validate_guest_path("/usr/bin/app").is_err());
    assert!(validate_guest_path("relative/path").is_err());

    // Traversal inside guest path
    assert!(validate_guest_path("C:\\Program Files\\..\\Windows").is_err());

    // Windows reserved component in guest path
    assert!(validate_guest_path("C:\\Program Files\\CON\\file.exe").is_err());
}

#[test]
fn test_case_collision_detection() {
    let paths = vec!["path/to/File.txt", "path/to/file.txt"];
    assert!(detect_case_collisions(&paths).is_err());

    let safe_paths = vec!["path/to/file1.txt", "path/to/file2.txt"];
    assert!(detect_case_collisions(&safe_paths).is_ok());
}

#[test]
#[cfg(unix)]
fn test_security_rule_linux_symlink_rejection() {
    let temp = tempdir().expect("tempdir");
    let real_file = temp.path().join("real.txt");
    std::fs::write(&real_file, b"content").expect("write real file");
    let symlink_file = temp.path().join("symlink.txt");
    std::os::unix::fs::symlink(&real_file, &symlink_file).expect("create symlink");

    let res = validate_and_canonicalize_host_path(symlink_file.to_str().unwrap());
    assert!(res.is_err(), "Symlinks must be rejected");
    assert!(res.unwrap_err().to_string().contains("symlink"));
}

#[test]
fn test_profile_lifecycle_and_rebuild_from_manifest() {
    let temp = tempdir().expect("tempdir");
    let storage = ProfileStorage::new(Some(temp.path().to_path_buf()));

    let manifest = sample_manifest("test-app", 2);
    let p_dir = storage.create_profile(&manifest).expect("create profile");
    assert!(p_dir.exists());
    assert!(p_dir.join("profile.toml").exists());
    assert!(p_dir.join("profile.json").exists());

    // Retrieve and verify rebuild hash
    let loaded = storage.get_profile("test-app").expect("get profile");
    assert_eq!(loaded.profile_id, "test-app");
    assert!(loaded.rebuild_hash.is_some());
    assert_eq!(loaded.rebuild_hash.unwrap(), manifest.compute_rebuild_hash());

    // List profiles
    let list = storage.list_profiles().expect("list profiles");
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].profile_id, "test-app");

    // Downgrade protection test: try rebuilding with older revision without --allow-older
    let older_manifest = sample_manifest("test-app", 1);
    let downgrade_err = storage.rebuild_profile("test-app", false, Some(&older_manifest));
    assert!(downgrade_err.is_err(), "Older revision must be rejected without --allow-older");

    // Now permit older revision with allow_older = true
    let downgraded = storage
        .rebuild_profile("test-app", true, Some(&older_manifest))
        .expect("downgrade permitted with allow_older");
    assert_eq!(downgraded.recipe_revision, Some(1));

    // Delete profile
    storage.delete_profile("test-app").expect("delete profile");
    assert!(!p_dir.exists());
    assert!(storage.get_profile("test-app").is_err());
}

