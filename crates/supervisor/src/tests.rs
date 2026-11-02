use crate::installer::InstallerCandidateEngine;
use crate::ipc::{validate_handshake, HandshakeRequest, IpcEventDispatcher};
use crate::lnk_parser::ShellLinkParser;
use crate::mock::{create_mock_lnk_bytes, MockRuntime};
use crate::prefix_snapshot::{PrefixSnapshot, PrefixSnapshotter};
use crate::process::ProcessSupervisor;
use crate::registry_parser::WineRegistryParser;
use crate::types::*;
use rand::Rng;
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tempfile::tempdir;

#[tokio::test]
async fn test_ui_disconnect_does_not_affect_app() {
    let supervisor = Arc::new(ProcessSupervisor::new("test-app", None));
    let mock = MockRuntime::new(supervisor.clone());

    // Subscriber connects and subscribes
    let rx = supervisor.subscribe();
    assert_eq!(supervisor.state(), ProcessState::Stopped);

    // Subscriber disconnects / is dropped immediately
    drop(rx);

    // Process runs and completes simulation normally
    let result = mock
        .run_simulation(
            Duration::from_millis(50),
            &["Line 1: init", "Line 2: processing", "Line 3: done"],
            0,
        )
        .await;

    assert!(result.is_ok());
    assert_eq!(supervisor.state(), ProcessState::Terminated);
    assert_eq!(supervisor.ring_buffer().get_lines().len(), 3);
}

#[tokio::test]
async fn test_app_crash_does_not_affect_supervisor() {
    let supervisor = Arc::new(ProcessSupervisor::new("crash-app", None));
    let mock = MockRuntime::new(supervisor.clone());
    let mut rx = supervisor.subscribe();

    // Run simulation ending in NTSTATUS Access Violation (0xC0000005)
    let exit_code = 0xC0000005u32 as i32;
    let sim_result = mock
        .run_simulation(
            Duration::from_millis(20),
            &["err:ntdll:RtlDispatchException access violation reading 0x00000000"],
            exit_code,
        )
        .await;

    assert!(sim_result.is_ok());
    assert_eq!(supervisor.state(), ProcessState::Crashed);

    // Check mapped exit info
    let exit_info = ProcessExitInfo::from_raw_code(exit_code);
    assert!(!exit_info.is_success);
    assert!(exit_info.description.contains("STATUS_ACCESS_VIOLATION"));
    assert!(exit_info.diagnostic_hint.unwrap().contains("Memory access violation"));

    // Verify supervisor caught events and remains fully operational
    let mut saw_crashed = false;
    let mut saw_diag = false;
    while let Ok(event) = rx.try_recv() {
        match event.event {
            EventKind::LifecycleStateChanged { to, .. } => {
                if to == ProcessState::Crashed {
                    saw_crashed = true;
                }
            }
            EventKind::DiagnosticsReady { .. } => {
                saw_diag = true;
            }
            _ => {}
        }
    }

    assert!(saw_crashed, "Expected lifecycle transition to Crashed");
    assert!(saw_diag, "Expected diagnostic classifier handoff event");

    // Supervisor is still alive and can supervise another run
    supervisor.transition_state(ProcessState::Stopped, None);
    assert_eq!(supervisor.state(), ProcessState::Stopped);
}

#[tokio::test]
async fn test_slow_ui_does_not_block_supervisor() {
    // Create supervisor and push 2000 events through broadcast channel of capacity 1024
    let supervisor = Arc::new(ProcessSupervisor::new("fast-app", None));
    let mut rx = supervisor.subscribe();
    let dispatcher = IpcEventDispatcher::new(supervisor.clone());

    // Emit 1500 log lines rapidly without reading
    for i in 0..1500 {
        supervisor.record_log_line(&format!("Burst message {}", i), LogChannel::Stdout);
    }

    // Supervisor execution was completely non-blocking
    assert_eq!(supervisor.ring_buffer().get_lines().len(), 1500);

    // Now slow reader attempts to read
    let next_event = dispatcher.next_client_event(&mut rx).await.expect("event");
    match next_event.event {
        EventKind::EventsDropped { dropped_count, notice } => {
            assert!(dropped_count > 0);
            assert!(notice.contains("UI consumer is lagging"));
        }
        _ => panic!("Expected EventsDropped notice on lagged receiver"),
    }
}

#[test]
fn test_malformed_and_oversized_ipc_messages_rejected() {
    // 1. Oversized payload (> 1 MB)
    let huge = vec![b'A'; MAX_IPC_MESSAGE_SIZE + 10];
    let res_huge = validate_handshake(&huge);
    assert!(res_huge.is_err());
    assert!(res_huge.unwrap_err().to_string().contains("1MB"));

    // 2. Malformed JSON
    let malformed = b"{ schema_version: not valid json }";
    let res_malformed = validate_handshake(malformed);
    assert!(res_malformed.is_err());

    // 3. Version mismatch
    let old_version = serde_json::to_vec(&HandshakeRequest {
        schema_version: "0.9.0".into(),
        client_name: "legacy-ui".into(),
    })
    .unwrap();
    let res_version = validate_handshake(&old_version).expect("parsed");
    assert!(!res_version.accepted);
    assert!(res_version.error.unwrap().contains("mismatch"));

    // 4. Valid handshake
    let valid = serde_json::to_vec(&HandshakeRequest {
        schema_version: SUPERVISOR_SCHEMA_VERSION.into(),
        client_name: "desktop-ui".into(),
    })
    .unwrap();
    let res_valid = validate_handshake(&valid).expect("parsed");
    assert!(res_valid.accepted);
    assert!(res_valid.error.is_none());
}

#[test]
fn test_wine_registry_parser_uninstall_keys() {
    let tmp = tempdir().unwrap();
    let system_reg_path = tmp.path().join("system.reg");

    let reg_content = r#"WINE REGISTRY Version 2
;; All keys relative to \\Machine

[Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\7-Zip]
"DisplayName"="7-Zip 23.01 (x64)"
"InstallLocation"="C:\\Program Files\\7-Zip"
"DisplayIcon"="C:\\Program Files\\7-Zip\\7zFM.exe"
"UninstallString"="\"C:\\Program Files\\7-Zip\\Uninstall.exe\""

[Software\\Microsoft\\Windows\\CurrentVersion\\Run]
"IgnoredStartup"="C:\\some\\run.exe"
"#;
    fs::write(&system_reg_path, reg_content).unwrap();

    let entries = WineRegistryParser::parse_file(&system_reg_path).expect("parse_file");
    assert_eq!(entries.len(), 1);
    let entry = &entries[0];
    assert_eq!(entry.display_name.as_deref(), Some("7-Zip 23.01 (x64)"));
    assert_eq!(entry.install_location.as_deref(), Some("C:\\Program Files\\7-Zip"));
    assert_eq!(entry.display_icon.as_deref(), Some("C:\\Program Files\\7-Zip\\7zFM.exe"));
    assert_eq!(entry.uninstall_string.as_deref(), Some("\"C:\\Program Files\\7-Zip\\Uninstall.exe\""));
}

#[test]
fn test_lnk_parser_valid_and_fuzz_smoke() {
    // 1. Valid synthetic .lnk
    let target = "C:\\Program Files\\7-Zip\\7zFM.exe";
    let lnk_bytes = create_mock_lnk_bytes(target);
    let info = ShellLinkParser::parse_bytes(&lnk_bytes).expect("parse valid lnk");
    assert_eq!(info.target_path.as_deref(), Some(target));

    // 2. 2,000-iteration Fuzz Smoke Test: zero panics on arbitrary/corrupted bytes
    let mut rng = rand::thread_rng();
    for _ in 0..2000 {
        let len = rng.gen_range(0..1024);
        let mut corrupted = vec![0u8; len];
        rng.fill(&mut corrupted[..]);

        // Occasionally inject valid header size or CLSID to exercise deeper code branches
        if len >= 4 && rng.gen_bool(0.3) {
            corrupted[0..4].copy_from_slice(&0x4Cu32.to_le_bytes());
        }
        if len >= 20 && rng.gen_bool(0.3) {
            corrupted[4..20].copy_from_slice(&[
                0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x46,
            ]);
        }

        // Must never panic
        let _ = ShellLinkParser::parse_bytes(&corrupted);
    }
}

#[test]
fn test_prefix_snapshot_never_follows_symlinks() {
    let tmp = tempdir().unwrap();
    let prefix = tmp.path().join("prefix");
    let drive_c = prefix.join("drive_c");
    fs::create_dir_all(&drive_c).unwrap();

    let real_file = drive_c.join("app.exe");
    fs::write(&real_file, b"MZ_REAL").unwrap();

    #[cfg(unix)]
    {
        // Create symlink pointing outside prefix to /etc
        let evil_link = drive_c.join("outside_link");
        let _ = std::os::unix::fs::symlink("/etc", &evil_link);
    }

    let snap = PrefixSnapshotter::snapshot(&prefix).expect("snapshot");
    // Verify only the real file was recorded and symlinks outside were not recursed into
    assert!(snap.files.len() <= 2);
    let rel_app = PathBuf::from("drive_c/app.exe");
    assert!(snap.files.contains_key(&rel_app));
}

#[test]
fn test_installer_candidate_ranking_on_fixtures() {
    let tmp = tempdir().unwrap();
    let prefix = tmp.path().join("prefix");
    MockRuntime::populate_mock_installed_prefix(&prefix).expect("populate mock prefix");

    let snap_before = PrefixSnapshot {
        root: prefix.clone(),
        files: std::collections::HashMap::new(),
    };
    let snap_after = PrefixSnapshotter::snapshot(&prefix).expect("snapshot after");
    let diff = PrefixSnapshotter::diff(&snap_before, &snap_after);

    let (candidates, needs_choice) = InstallerCandidateEngine::rank_candidates(
        &prefix,
        &diff,
        Some("Notepad++"),
    );

    assert!(!candidates.is_empty(), "Expected candidates from mock prefix");

    // The top candidate MUST be notepad++.exe with high confidence
    let top = &candidates[0];
    assert!(top.path.to_lowercase().contains("notepad++.exe"));
    assert!(top.confidence_score >= 80, "Expected high confidence for main executable (got {})", top.confidence_score);
    assert!(!needs_choice, "Expected clear winner, no user choice required");

    // Uninstaller MUST be penalized heavily
    let uninst = candidates.iter().find(|c| c.path.to_lowercase().contains("uninstall.exe")).unwrap();
    assert!(uninst.confidence_score <= 20, "Expected heavy penalty on uninstaller (got {})", uninst.confidence_score);

    // Updater MUST be penalized
    let updater = candidates.iter().find(|c| c.path.to_lowercase().contains("updater.exe")).unwrap();
    assert!(updater.confidence_score <= 50, "Expected penalty on updater (got {})", updater.confidence_score);
}

#[test]
fn test_exit_code_mappings() {
    // 0xC0000005: STATUS_ACCESS_VIOLATION
    let info_av = ProcessExitInfo::from_raw_code(0xC0000005u32 as i32);
    assert!(!info_av.is_success);
    assert!(info_av.description.contains("STATUS_ACCESS_VIOLATION"));
    assert!(info_av.diagnostic_hint.unwrap().contains("Memory access violation"));

    // 0xC00000FD: STATUS_STACK_OVERFLOW
    let info_so = ProcessExitInfo::from_raw_code(0xC00000FDu32 as i32);
    assert!(info_so.description.contains("STATUS_STACK_OVERFLOW"));

    // 139: POSIX SIGSEGV (128 + 11)
    let info_sigsegv = ProcessExitInfo::from_raw_code(139);
    assert!(info_sigsegv.description.contains("Segmentation fault (Signal 11)"));

    // 1603: ERROR_INSTALL_FAILURE
    let info_msi_fail = ProcessExitInfo::from_raw_code(1603);
    assert!(info_msi_fail.description.contains("ERROR_INSTALL_FAILURE"));

    // 0: Clean exit
    let info_clean = ProcessExitInfo::from_raw_code(0);
    assert!(info_clean.is_success);
    assert!(info_clean.diagnostic_hint.is_none());
}
