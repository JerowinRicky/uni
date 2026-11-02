mod fixtures_builder;

use fixtures_builder::{create_synthetic_msi, PeBuilder};
use universalrun_analyzer::analyze_bytes;
use universalrun_analyzer::limits::AnalyzerLimits;
use universalrun_analyzer::types::*;

#[test]
fn test_synthetic_x64_gui_pe() {
    let limits = AnalyzerLimits::default();
    let bytes = PeBuilder::x64_gui().build();

    let report = analyze_bytes("test_x64_gui.exe", &bytes, &limits)
        .expect("Should parse minimal x64 GUI PE");

    assert_eq!(report.schema_version, "1.0.0");
    assert_eq!(report.architecture, Some(Architecture::X64));
    assert_eq!(report.subsystem, Some(Subsystem::WindowsGui));
    assert_eq!(report.entry_point, Some(0x1000));
    assert_eq!(report.installer_type.value, InstallerKind::Portable);
    assert_eq!(report.installer_type.confidence, Confidence::Certain);

    // Rule: Static-only rating cannot be Excellent
    assert_eq!(report.compatibility_rating.category, RatingCategory::Good);
    assert!(report.compatibility_rating.evidence.iter().any(|e| e.contains("Static-only analysis cap")));
    assert!(!report.unverifiable_aspects.is_empty());
}

#[test]
fn test_synthetic_x86_console_pe() {
    let limits = AnalyzerLimits::default();
    let bytes = PeBuilder::x86_console().build();

    let report = analyze_bytes("test_x86_console.exe", &bytes, &limits)
        .expect("Should parse minimal x86 console PE");

    assert_eq!(report.architecture, Some(Architecture::X86));
    assert_eq!(report.subsystem, Some(Subsystem::WindowsCui));
    assert_eq!(report.installer_type.value, InstallerKind::Portable);
    assert_eq!(report.compatibility_rating.category, RatingCategory::Good);
}

#[test]
fn test_synthetic_msi_detection_via_cfb() {
    let limits = AnalyzerLimits::default();
    let msi_bytes = create_synthetic_msi();

    let report = analyze_bytes("installer.msi", &msi_bytes, &limits)
        .expect("Should parse synthetic MSI container");

    assert_eq!(report.installer_type.value, InstallerKind::Msi);
    assert_eq!(report.installer_type.confidence, Confidence::Certain);
    // MSI architecture and subsystem must be null (None)
    assert_eq!(report.architecture, None);
    assert_eq!(report.subsystem, None);
    // MSI rating must be capped at Partial until full staging
    assert_eq!(report.compatibility_rating.category, RatingCategory::Partial);
    assert!(report.compatibility_rating.evidence.iter().any(|e| e.contains("MSI package")));
}

#[test]
fn test_inno_setup_signature_and_version() {
    let limits = AnalyzerLimits::default();
    let inno_payload = b"Inno Setup Setup Data (6.2.1) header test";
    let bytes = PeBuilder::x64_gui().with_payload(inno_payload).build();

    let report = analyze_bytes("setup.exe", &bytes, &limits)
        .expect("Should parse Inno Setup executable");

    assert_eq!(report.installer_type.value, InstallerKind::InnoSetup);
    assert_eq!(report.installer_type.confidence, Confidence::Certain);
    assert_eq!(report.installer_version, Some("6.2.1".to_string()));
}

#[test]
fn test_nsis_installer_detection() {
    let limits = AnalyzerLimits::default();
    let mut payload = vec![0u8; 64];
    payload[..12].copy_from_slice(b"NullsoftInst");
    let bytes = PeBuilder::x64_gui().with_payload(&payload).build();

    let report = analyze_bytes("nsis_setup.exe", &bytes, &limits)
        .expect("Should parse NSIS executable");

    assert_eq!(report.installer_type.value, InstallerKind::Nsis);
    assert_eq!(report.installer_type.confidence, Confidence::Certain);
}

#[test]
fn test_dotnet_detection() {
    let limits = AnalyzerLimits::default();
    let payload = b".NETCoreApp,Version=v8.0\0";
    let bytes = PeBuilder::x64_gui().with_clr().with_payload(payload).build();

    let report = analyze_bytes("dotnet_app.exe", &bytes, &limits)
        .expect("Should parse .NET modern app");

    assert!(report.dotnet.is_some());
    let dotnet = report.dotnet.unwrap();
    assert!(dotnet.is_dotnet);
    assert_eq!(dotnet.flavor, DotNetFlavor::ModernDotNet);
    assert_eq!(dotnet.target_framework, Some(".NETCoreApp,Version=v8.0".to_string()));
    assert_eq!(dotnet.confidence, Confidence::Certain);
    // Required runtimes must include .NET Runtime
    assert!(report.required_runtimes.iter().any(|r| r.value.contains(".NET Runtime")));
}

#[test]
fn test_admin_manifest_lowers_rating_to_partial() {
    let limits = AnalyzerLimits::default();
    let manifest_payload = b"<requestedExecutionLevel level=\"requireAdministrator\" uiAccess=\"false\"/>";
    let bytes = PeBuilder::x64_gui().with_payload(manifest_payload).build();

    let report = analyze_bytes("admin_app.exe", &bytes, &limits)
        .expect("Should parse app requesting admin");

    assert!(report.security_flags.requests_admin);
    assert_eq!(report.execution_level.value, ExecutionLevel::RequireAdministrator);
    assert_eq!(report.compatibility_rating.category, RatingCategory::Partial);
    assert!(report.compatibility_rating.evidence.iter().any(|e| e.contains("Administrator")));
}

#[test]
fn test_authenticode_three_state_reporting() {
    let limits = AnalyzerLimits::default();
    // Case 1: No certificate table
    let unsigned_bytes = PeBuilder::x64_gui().build();
    let report1 = analyze_bytes("unsigned.exe", &unsigned_bytes, &limits).unwrap();
    assert!(!report1.authenticode.signature_present);
    assert_eq!(report1.authenticode.file_hash_verified, None);
    assert_eq!(report1.authenticode.chain_trust, ChainTrust::Unknown);

    // Case 2: Present certificate block
    let mut cert_data = vec![0u8; 64];
    cert_data[..4].copy_from_slice(&64u32.to_le_bytes());
    cert_data[4..6].copy_from_slice(&0x0200u16.to_le_bytes());
    cert_data[6..8].copy_from_slice(&0x0002u16.to_le_bytes());

    let mut signed_pe = PeBuilder::x64_gui().with_security_cert(0x400, 64).build();
    signed_pe.extend_from_slice(&cert_data);

    let report2 = analyze_bytes("signed_test.exe", &signed_pe, &limits).unwrap();
    assert!(report2.authenticode.signature_present);
    assert_eq!(report2.authenticode.chain_trust, ChainTrust::Unknown);
}

#[test]
fn test_malformed_truncated_corpus_safety() {
    let limits = AnalyzerLimits::default();

    // 1. Empty buffer
    assert!(analyze_bytes("empty.exe", &[], &limits).is_err());

    // 2. 1-byte buffer
    assert!(analyze_bytes("one_byte.exe", &[0x4D], &limits).is_err());

    // 3. Truncated DOS header (10 bytes)
    let ten_bytes = [b'M', b'Z', 0, 0, 0, 0, 0, 0, 0, 0];
    assert!(analyze_bytes("truncated.exe", &ten_bytes, &limits).is_err());

    // 4. Invalid PE offset in DOS header pointing way out of bounds
    let mut corrupt_dos = vec![0u8; 128];
    corrupt_dos[0] = b'M';
    corrupt_dos[1] = b'Z';
    corrupt_dos[0x3c] = 0xFF;
    corrupt_dos[0x3d] = 0xFF;
    assert!(analyze_bytes("corrupt_dos.exe", &corrupt_dos, &limits).is_err());

    // 5. Corrupted PE signature
    let mut corrupt_pe = PeBuilder::x64_gui().build();
    corrupt_pe[0x80] = b'X';
    corrupt_pe[0x81] = b'X';
    assert!(analyze_bytes("corrupt_sig.exe", &corrupt_pe, &limits).is_err());
}

#[test]
fn test_golden_json_output_conforms_to_schema() {
    let limits = AnalyzerLimits::default();
    let bytes = PeBuilder::x64_gui().build();
    let report = analyze_bytes("golden_sample.exe", &bytes, &limits).unwrap();

    let json_str = serde_json::to_string_pretty(&report).unwrap();
    let json_val: serde_json::Value = serde_json::from_str(&json_str).unwrap();

    assert_eq!(json_val["schema_version"], "1.0.0");
    assert_eq!(json_val["file_name"], "golden_sample.exe");
    assert_eq!(json_val["architecture"], "x64");
    assert_eq!(json_val["subsystem"], "windows_gui");
    assert_eq!(json_val["installer_type"]["value"], "portable");
    assert_eq!(json_val["compatibility_rating"]["category"], "Good");
    assert!(json_val["sha256"].as_str().unwrap().len() == 64);
}
