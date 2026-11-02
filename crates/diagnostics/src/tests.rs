use crate::bundle::BundleBuilder;
use crate::classifier::LogClassifier;
use crate::fixes::FixCatalog;
use crate::scrubbing::PiiScrubber;
use crate::types::{DiagnosticCategory, DiagnosticConfidence};
use std::collections::HashMap;
use std::path::PathBuf;
use tempfile::tempdir;
use universalrun_profile_manager::{
    FsMapping, PermissionPolicy, ProfileManifest, RuntimeConfig,
};

fn test_catalog() -> FixCatalog {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let catalog_path = manifest_dir.join("../../diagnostics/catalog/fixes.toml");
    FixCatalog::from_file(catalog_path).expect("load fixes.toml")
}

// =========================================================================
// SYNTHETIC LOG FIXTURES
// =========================================================================

const SYNTHETIC_SUCCESSFUL_RUN_LOG: &str = "\
002c:fixme:font:get_outline_text_metrics failed to read full name\n\
002c:fixme:nls:RtlGetThreadLangIdStub ()\n\
0034:err:ole:CoGetClassObject class {0000031a-0000-0000-c000-000000000046} not registered\n\
0034:fixme:imm:ImeSetActiveContext (0x20092, 1): stub\n\
0024:fixme:process:SetProcessShutdownParameters (00000280, 00000000): partial stub\n";

const SYNTHETIC_MISSING_VCREDIST_LOG: &str = "\
002c:fixme:font:get_outline_text_metrics failed to read full name\n\
0078:err:module:import_dll Library msvcp140.dll (which is needed by L\"C:\\\\app.exe\") not found\n\
0078:err:module:LdrInitializeThunk Importing dlls for L\"C:\\\\app.exe\" failed, status c0000135\n";

const SYNTHETIC_MISSING_DLL_LOG: &str = "\
002c:fixme:nls:RtlGetThreadLangIdStub ()\n\
0084:err:module:import_dll Library KERNEL32.dll (which is needed by L\"C:\\\\test.exe\") not found\n\
0084:err:module:LdrInitializeThunk Importing dlls for L\"C:\\\\test.exe\" failed, status c0000135\n";

const SYNTHETIC_GRAPHICS_ERROR_LOG: &str = "\
002c:fixme:d3d11:d3d11_device_create failed\n\
0048:err:vulkan:wine_vk_init_device VK_ERROR_DEVICE_LOST: driver lost connection\n";

const SYNTHETIC_PERMISSION_DENIAL_LOG: &str = "\
0024:fixme:winsock:WSAStartup stub\n\
0058:err:winsock:wsa_socket socket: Permission denied (EACCES)\n\
0058:err:network:connect Network is unreachable\n";

const SYNTHETIC_PAGE_FAULT_CRASH_LOG: &str = "\
0024:fixme:seh:RtlAddFunctionTable stub\n\
Unhandled exception: page fault on read access to 0x0000000000000008 in 64-bit code (0x0000000140001000).\n\
Backtrace:\n\
=>0 0x0000000140001000 in app (+0x1000)\n";

const SYNTHETIC_INSTALLER_FAILURE_LOG: &str = "\
0030:fixme:msi:MsiSetInternalUI stub\n\
0030:err:msi:ACTION_PerformAction msiexec failed with error 1603\n";

// =========================================================================
// CLASSIFIER & FIX LOOKUP TESTS
// =========================================================================

#[test]
fn test_benign_successful_run_false_positive_fixture() {
    let catalog = test_catalog();
    let classifier = LogClassifier::new(&catalog);

    // Rule: Success (exit code 0) MUST NOT flag benign fixme/err lines
    let report = classifier
        .classify(SYNTHETIC_SUCCESSFUL_RUN_LOG.as_bytes(), Some(0))
        .expect("classify success");

    assert_eq!(report.category, DiagnosticCategory::Unknown);
    assert_eq!(report.confidence, DiagnosticConfidence::Certain);
    assert!(report.evidence_lines.is_empty(), "Successful exit must not extract false-positive evidence");
    assert!(report.recommended_fixes.is_empty());
}

#[test]
fn test_classify_missing_dependency() {
    let catalog = test_catalog();
    let classifier = LogClassifier::new(&catalog);

    let report = classifier
        .classify(SYNTHETIC_MISSING_VCREDIST_LOG.as_bytes(), Some(1))
        .expect("classify");

    assert_eq!(report.category, DiagnosticCategory::MissingDependency);
    assert_eq!(report.confidence, DiagnosticConfidence::Likely);
    assert!(!report.evidence_lines.is_empty());
    assert!(report.evidence_lines.iter().any(|l| l.contains("msvcp140.dll")));
    assert!(report.recommended_fixes.iter().any(|f| f.id == "missing_vcredist"));
}

#[test]
fn test_classify_missing_dll_or_api() {
    let catalog = test_catalog();
    let classifier = LogClassifier::new(&catalog);

    let report = classifier
        .classify(SYNTHETIC_MISSING_DLL_LOG.as_bytes(), Some(1))
        .expect("classify");

    assert_eq!(report.category, DiagnosticCategory::MissingDllOrApi);
    assert_eq!(report.confidence, DiagnosticConfidence::Likely);
    assert!(report.evidence_lines.iter().any(|l| l.contains("KERNEL32.dll")));
    assert!(report.recommended_fixes.iter().any(|f| f.id == "dll_native_override"));
}

#[test]
fn test_classify_graphics_error() {
    let catalog = test_catalog();
    let classifier = LogClassifier::new(&catalog);

    let report = classifier
        .classify(SYNTHETIC_GRAPHICS_ERROR_LOG.as_bytes(), Some(1))
        .expect("classify");

    assert_eq!(report.category, DiagnosticCategory::GraphicsError);
    assert_eq!(report.confidence, DiagnosticConfidence::Likely);
    assert!(report.evidence_lines.iter().any(|l| l.contains("VK_ERROR_DEVICE_LOST")));
    assert!(report.recommended_fixes.iter().any(|f| f.id == "enable_dxvk"));
}

#[test]
fn test_classify_permission_denial() {
    let catalog = test_catalog();
    let classifier = LogClassifier::new(&catalog);

    let report = classifier
        .classify(SYNTHETIC_PERMISSION_DENIAL_LOG.as_bytes(), Some(1))
        .expect("classify");

    assert_eq!(report.category, DiagnosticCategory::PermissionDenial);
    assert_eq!(report.confidence, DiagnosticConfidence::Likely);
    assert!(report.evidence_lines.iter().any(|l| l.contains("Permission denied")));
    assert!(report.recommended_fixes.iter().any(|f| f.id == "grant_network_permission"));
}

#[test]
fn test_classify_startup_crash() {
    let catalog = test_catalog();
    let classifier = LogClassifier::new(&catalog);

    let report = classifier
        .classify(SYNTHETIC_PAGE_FAULT_CRASH_LOG.as_bytes(), Some(139))
        .expect("classify");

    assert_eq!(report.category, DiagnosticCategory::StartupCrash);
    assert_eq!(report.confidence, DiagnosticConfidence::Certain);
    assert!(report.evidence_lines.iter().any(|l| l.contains("page fault")));
}

#[test]
fn test_classify_hang_timeout() {
    let catalog = test_catalog();
    let classifier = LogClassifier::new(&catalog);

    let report = classifier
        .classify(b"Application hanging with no output", Some(124))
        .expect("classify");

    assert_eq!(report.category, DiagnosticCategory::HangOrTimeout);
    assert_eq!(report.confidence, DiagnosticConfidence::Likely);
}

#[test]
fn test_classify_installer_failure() {
    let catalog = test_catalog();
    let classifier = LogClassifier::new(&catalog);

    let report = classifier
        .classify(SYNTHETIC_INSTALLER_FAILURE_LOG.as_bytes(), Some(1603))
        .expect("classify");

    assert_eq!(report.category, DiagnosticCategory::InstallerFailure);
    assert_eq!(report.confidence, DiagnosticConfidence::Likely);
    assert!(report.evidence_lines.iter().any(|l| l.contains("msiexec failed")));
}

// =========================================================================
// PII SCRUBBING TESTS (ONE TEST PER REQUIRED CATEGORY)
// =========================================================================

#[test]
fn test_scrubbing_category_token_shaped_strings() {
    let scrubber = PiiScrubber::new();

    let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
    let gh_token = "ghp_1234567890abcdefghijklmnopqrstuvwxyzABCD";
    let gh_pat = "github_pat_11TESTEXAMPLE000000000000_fakeSyntheticTokenForScrubberVerificationOnly1234567890";
    let aws_key = "AKIAIOSFODNN7EXAMPLE";
    let bearer = "Bearer my_secret_bearer_token_12345678";

    let input = format!(
        "Log: token={} pat={} gh={} aws={} auth={}",
        jwt, gh_pat, gh_token, aws_key, bearer
    );
    let scrubbed = scrubber.scrub_text(&input);

    assert!(!scrubbed.contains(jwt));
    assert!(!scrubbed.contains(gh_token));
    assert!(!scrubbed.contains(gh_pat));
    assert!(!scrubbed.contains(aws_key));
    assert!(!scrubbed.contains("my_secret_bearer_token"));
    assert!(scrubbed.contains("<REDACTED_JWT>"));
    assert!(scrubbed.contains("<REDACTED_TOKEN>"));
    assert!(scrubbed.contains("<REDACTED_AWS_KEY>"));
    assert!(scrubbed.contains("Bearer <REDACTED_BEARER>"));
}

#[test]
fn test_scrubbing_category_emails() {
    let scrubber = PiiScrubber::new();
    let input = "Contact developer at john.doe@internal-corp.example.com for support";
    let scrubbed = scrubber.scrub_text(input);

    assert!(!scrubbed.contains("john.doe@internal-corp.example.com"));
    assert_eq!(scrubbed, "Contact developer at <REDACTED_EMAIL> for support");
}

#[test]
fn test_scrubbing_category_ips_and_hostnames() {
    let scrubber = PiiScrubber::new();
    let input = "Failed to bind listening socket on 192.168.1.100 port 8080 or connect to database.corp.internal";
    let scrubbed = scrubber.scrub_text(input);

    assert!(!scrubbed.contains("192.168.1.100"));
    assert!(!scrubbed.contains("database.corp.internal"));
    assert_eq!(scrubbed, "Failed to bind listening socket on <REDACTED_IP> port 8080 or connect to <REDACTED_HOSTNAME>");
}

#[test]
fn test_scrubbing_category_hostnames() {
    let scrubber = PiiScrubber::new();
    let input = "Resolving backend server at auth-service.internal and storage.nas.lan for user sync";
    let scrubbed = scrubber.scrub_text(input);

    assert!(!scrubbed.contains("auth-service.internal"));
    assert!(!scrubbed.contains("storage.nas.lan"));
    assert!(scrubbed.contains("<REDACTED_HOSTNAME>"));
}

#[test]
fn test_scrubbing_category_prefix_usernames() {
    let scrubber = PiiScrubber::new();
    let input = "Reading config from C:\\drive_c\\users\\alice_smith\\AppData\\Roaming\\settings.ini";
    let scrubbed = scrubber.scrub_text(input);

    assert!(!scrubbed.contains("alice_smith"));
    assert!(scrubbed.contains("drive_c\\users\\<REDACTED_USER>\\AppData"));
}

#[test]
fn test_scrubbing_category_unc_paths() {
    let scrubber = PiiScrubber::new();
    let input = "Attempted network drive access at \\\\internal-nas.corp\\secret_share\\file.dat";
    let scrubbed = scrubber.scrub_text(input);

    assert!(!scrubbed.contains("internal-nas.corp"));
    assert!(!scrubbed.contains("secret_share"));
    assert!(scrubbed.contains("<REDACTED_UNC>\\file.dat"));
}

#[test]
fn test_scrubbing_category_env_allowlist() {
    let scrubber = PiiScrubber::new();
    let mut env = HashMap::new();
    env.insert("PATH".to_string(), "/usr/bin:/bin".to_string());
    env.insert("DISPLAY".to_string(), ":0".to_string());
    env.insert("SECRET_AUTH_TOKEN".to_string(), "super_secret_token_123".to_string());
    env.insert("AWS_SECRET_KEY".to_string(), "unallowlisted_secret".to_string());

    let scrubbed = scrubber.scrub_env_vars(&env);

    // Rule: Only allowlisted variables are retained; all others are deleted
    assert!(scrubbed.contains_key("PATH"));
    assert!(scrubbed.contains_key("DISPLAY"));
    assert!(!scrubbed.contains_key("SECRET_AUTH_TOKEN"));
    assert!(!scrubbed.contains_key("AWS_SECRET_KEY"));
}

#[test]
fn test_scrubbing_category_manifest_host_paths() {
    let scrubber = PiiScrubber::new();
    let manifest = ProfileManifest {
        schema_version: "1.0.0".to_string(),
        profile_id: "test-app".to_string(),
        display_name: "Test App".to_string(),
        target_app: "app.exe".to_string(),
        target_app_sha256: None,
        recipe_id: None,
        recipe_revision: None,
        runtime: RuntimeConfig {
            name: "wine".to_string(),
            version: "9.0".to_string(),
            architecture: "win64".to_string(),
            windows_version: "win10".to_string(),
        },
        dependencies: Vec::new(),
        env_vars: HashMap::new(),
        dll_overrides: HashMap::new(),
        filesystem_mappings: vec![FsMapping {
            host_path: "/home/johndoe/private_documents".to_string(),
            guest_path: "C:\\users\\app\\Documents".to_string(),
            read_only: false,
        }],
        permissions: PermissionPolicy::default(),
        rebuild_hash: None,
    };

    let scrubbed = scrubber.scrub_manifest(&manifest);
    assert_eq!(
        scrubbed.filesystem_mappings[0].host_path,
        "<REDACTED_HOST_PATH>"
    );
}

// =========================================================================
// BUNDLE BUILDER SAFETY TESTS
// =========================================================================

#[test]
fn test_bundle_builder_refuses_overwrite_and_enforces_caps() {
    let temp = tempdir().expect("tempdir");
    let log_file = temp.path().join("crash.log");
    std::fs::write(&log_file, SYNTHETIC_MISSING_VCREDIST_LOG).expect("write log");

    let manifest = ProfileManifest {
        schema_version: "1.0.0".to_string(),
        profile_id: "test-app".to_string(),
        display_name: "Test App".to_string(),
        target_app: "app.exe".to_string(),
        target_app_sha256: None,
        recipe_id: None,
        recipe_revision: None,
        runtime: RuntimeConfig {
            name: "wine".to_string(),
            version: "9.0".to_string(),
            architecture: "win64".to_string(),
            windows_version: "win10".to_string(),
        },
        dependencies: Vec::new(),
        env_vars: HashMap::new(),
        dll_overrides: HashMap::new(),
        filesystem_mappings: Vec::new(),
        permissions: PermissionPolicy::default(),
        rebuild_hash: None,
    };

    let catalog = test_catalog();
    let classifier = LogClassifier::new(&catalog);
    let report = classifier
        .classify(SYNTHETIC_MISSING_VCREDIST_LOG.as_bytes(), Some(1))
        .expect("classify");

    let bundle_dir = temp.path().join("out_bundle");
    let builder = BundleBuilder::new();

    // 1. Initial build succeeds
    builder
        .build_bundle(&log_file, &manifest, &report, &bundle_dir)
        .expect("initial bundle creation");
    assert!(bundle_dir.join("scrubbed_log.txt").exists());
    assert!(bundle_dir.join("profile_manifest.json").exists());
    assert!(bundle_dir.join("diagnostic_report.json").exists());
    assert!(bundle_dir.join("system_info.json").exists());

    // 2. Overwrite refusal: must return error on non-empty existing directory
    let overwrite_res = builder.build_bundle(&log_file, &manifest, &report, &bundle_dir);
    assert!(overwrite_res.is_err(), "Refusing to overwrite existing bundle directory");
    assert!(overwrite_res.unwrap_err().to_string().contains("refusing to overwrite"));
}

// =========================================================================
// LOG CLASSIFIER FUZZ SMOKE TEST
// =========================================================================

#[test]
fn test_fuzz_smoke_log_classifier() {
    let catalog = test_catalog();
    let classifier = LogClassifier::new(&catalog);

    let mut state: u32 = 0xDEADBEEF;
    let mut rng = move || {
        state = state.wrapping_mul(1664525).wrapping_add(1013904223);
        state
    };

    for _ in 0..2000 {
        let len = (rng() % 1024) as usize;
        let mut bytes = Vec::with_capacity(len);
        for _ in 0..len {
            bytes.push((rng() & 0xFF) as u8);
        }

        let exit_code = if (rng() % 2) == 0 {
            Some((rng() % 256) as i32)
        } else {
            None
        };

        // Must never panic on arbitrary input
        let res = classifier.classify(&bytes, exit_code);
        assert!(res.is_ok(), "Classifier must not panic on arbitrary input");
    }
}

