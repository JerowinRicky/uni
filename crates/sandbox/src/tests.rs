use crate::bwrap::{BwrapBackend, SandboxContext};
use crate::checker::*;
use crate::mock::MockSandbox;
use crate::traits::SandboxBackend;
use crate::types::*;
use rand::Rng;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use universalrun_profile_manager::{
    PermissionPolicy as ProfilePermissionPolicy, ProfileManifest, RuntimeConfig,
};

fn sample_manifest() -> ProfileManifest {
    ProfileManifest {
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
        dependencies: vec![],
        env_vars: HashMap::new(),
        dll_overrides: HashMap::new(),
        filesystem_mappings: vec![],
        permissions: ProfilePermissionPolicy::default(),
        rebuild_hash: Some("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string()),
    }
}

fn sample_context(policy: SandboxPolicy) -> SandboxContext {
    SandboxContext {
        policy,
        manifest: sample_manifest(),
        host_wine_runtime: PathBuf::from("/opt/universalrun/runtimes/wine-9.0"),
        host_prefix_dir: PathBuf::from("/var/data/universalrun/prefixes/test-app"),
        host_scoped_xauth: Some(PathBuf::from("/tmp/xauth_test")),
        host_wayland_socket: Some(PathBuf::from("/run/user/1000/wayland-0")),
        host_pulse_socket: Some(PathBuf::from("/run/user/1000/pulse/native")),
    }
}

// ============================================================================
// 1. DEDICATED REJECTION TESTS (NAMED PER SECURITY CHECKER RULE)
// ============================================================================

#[test]
fn test_rejection_rule_root_mount() {
    assert!(check_no_root_mount(Path::new("/")).is_err());
    assert!(check_no_root_mount(Path::new("\\")).is_err());
    assert!(check_no_root_mount(Path::new("/home/user/docs")).is_ok());
}

#[test]
fn test_rejection_rule_home_mount() {
    assert!(check_no_home_mount(Path::new("/home")).is_err());
    assert!(check_no_home_mount(Path::new("/root")).is_err());
    assert!(check_no_home_mount(Path::new("~")).is_err());
    assert!(check_no_home_mount(Path::new("$HOME")).is_err());
    assert!(check_no_home_mount(Path::new("${HOME}/data")).is_err());
    assert!(check_no_home_mount(Path::new("/data/shared")).is_ok());
}

#[test]
fn test_rejection_rule_writable_system_paths() {
    // Read-only is allowed
    assert!(check_no_writable_system_paths(Path::new("/usr"), true).is_ok());
    assert!(check_no_writable_system_paths(Path::new("/etc"), true).is_ok());

    // Writable is rejected
    assert!(check_no_writable_system_paths(Path::new("/usr"), false).is_err());
    assert!(check_no_writable_system_paths(Path::new("/usr/bin"), false).is_err());
    assert!(check_no_writable_system_paths(Path::new("/lib"), false).is_err());
    assert!(check_no_writable_system_paths(Path::new("/lib64"), false).is_err());
    assert!(check_no_writable_system_paths(Path::new("/bin"), false).is_err());
    assert!(check_no_writable_system_paths(Path::new("/sbin"), false).is_err());
    assert!(check_no_writable_system_paths(Path::new("/etc"), false).is_err());
    assert!(check_no_writable_system_paths(Path::new("/etc/hosts"), false).is_err());

    // Safe path is allowed
    assert!(check_no_writable_system_paths(Path::new("/srv/storage"), false).is_ok());
}

#[test]
fn test_rejection_rule_sensitive_dev_or_proc() {
    assert!(check_no_sensitive_dev_or_proc(Path::new("/dev")).is_err());
    assert!(check_no_sensitive_dev_or_proc(Path::new("/dev/")).is_err());
    assert!(check_no_sensitive_dev_or_proc(Path::new("/proc/sys")).is_err());
    assert!(check_no_sensitive_dev_or_proc(Path::new("/proc/sys/kernel")).is_err());
    assert!(check_no_sensitive_dev_or_proc(Path::new("/proc/cpuinfo")).is_ok());
}

#[test]
fn test_rejection_rule_container_sockets() {
    assert!(check_no_container_sockets(Path::new("/var/run/docker.sock")).is_err());
    assert!(check_no_container_sockets(Path::new("/run/podman/podman.sock")).is_err());
    assert!(check_no_container_sockets(Path::new("/run/containerd/containerd.sock")).is_err());
    assert!(check_no_container_sockets(Path::new("/run/user/1000/app.sock")).is_ok());
}

#[test]
fn test_rejection_rule_dbus_session_bus() {
    assert!(check_no_dbus_session_bus(Path::new("/run/user/1000/bus")).is_err());
    assert!(check_no_dbus_session_bus(Path::new("/run/user/1000/wayland-0")).is_ok());
    assert!(check_no_dbus_session_bus(Path::new("/var/bus")).is_ok());
}

#[test]
fn test_rejection_rule_ssh_agent_socket() {
    assert!(check_no_ssh_agent_socket(Path::new("/tmp/ssh-ABC123/agent.1234")).is_err());
    assert!(check_no_ssh_agent_socket(Path::new("/run/user/1000/ssh-auth.sock")).is_err());
    assert!(check_no_ssh_agent_socket(Path::new("/run/user/1000/pulse/native")).is_ok());
}

#[test]
fn test_rejection_rule_whole_xdg_runtime_dir() {
    assert!(check_no_whole_xdg_runtime_dir(Path::new("/run/user/1000")).is_err());
    assert!(check_no_whole_xdg_runtime_dir(Path::new("/run/user/1000/")).is_err());
    // Sub-sockets like pulse or wayland are allowed
    assert!(check_no_whole_xdg_runtime_dir(Path::new("/run/user/1000/pulse/native")).is_ok());
    assert!(check_no_whole_xdg_runtime_dir(Path::new("/run/user/1000/wayland-0")).is_ok());
}

#[test]
fn test_rejection_rule_parent_traversal() {
    assert!(check_no_parent_traversal(Path::new("../secret")).is_err());
    assert!(check_no_parent_traversal(Path::new("/home/user/../../etc/shadow")).is_err());
    assert!(check_no_parent_traversal(Path::new("/var/data/shared")).is_ok());
}

#[test]
fn test_rejection_rule_sensitive_user_credentials() {
    assert!(check_granted_folder_safety(Path::new("/home/user/.ssh")).is_err());
    assert!(check_granted_folder_safety(Path::new("/home/user/.gnupg")).is_err());
    assert!(check_granted_folder_safety(Path::new("/home/user/.aws")).is_err());
    assert!(check_granted_folder_safety(Path::new("/home/user/.config")).is_err());
    assert!(check_granted_folder_safety(Path::new("/home/user/.mozilla")).is_err());
    assert!(check_granted_folder_safety(Path::new("/home/user/.config/google-chrome")).is_err());
    assert!(check_granted_folder_safety(Path::new("/home/user/.config/chromium")).is_err());
    assert!(check_granted_folder_safety(Path::new("/home/user/.config/brave")).is_err());
    assert!(check_granted_folder_safety(Path::new("/srv/appdata")).is_ok());
}

// ============================================================================
// 2. GOLDEN SNAPSHOT TESTS FOR BWRAP ARGUMENT VECTORS
// ============================================================================

#[test]
fn test_golden_default_policy_arguments() {
    let policy = SandboxPolicy::default();
    let ctx = sample_context(policy);
    let backend = BwrapBackend::new();
    let args = backend.build_args(&ctx).expect("build_args failed");

    let args_str: Vec<String> = args.iter().map(|s| s.to_string_lossy().into_owned()).collect();

    // Verify vital sandbox flags
    assert_eq!(args_str[0], "--unshare-all");
    assert_eq!(args_str[1], "--unshare-uts");
    assert_eq!(args_str[2], "--hostname");
    assert_eq!(args_str[3], "universalrun-sandbox");

    // Network is disabled by default: --share-net MUST NOT be present
    assert!(!args_str.contains(&"--share-net".to_string()));

    // Process lifecycle and dropped capabilities
    assert!(args_str.contains(&"--die-with-parent".to_string()));
    assert!(args_str.contains(&"--new-session".to_string()));
    assert!(args_str.contains(&"--cap-drop".to_string()));

    // Clearenv + Wine HOME pinned inside prefix
    assert!(args_str.contains(&"--clearenv".to_string()));
    let home_idx = args_str.iter().position(|r| r == "HOME").unwrap();
    assert_eq!(args_str[home_idx + 1], "/wineprefix");

    // Tmpfs ordering: --tmpfs /tmp MUST appear before X11 socket bind
    let tmpfs_idx = args_str.iter().position(|r| r == "--tmpfs").unwrap();
    assert_eq!(args_str[tmpfs_idx + 1], "/tmp");
    let x11_idx = args_str.iter().position(|r| r == "/tmp/.X11-unix/X0").unwrap();
    assert!(tmpfs_idx < x11_idx, "tmpfs must be mounted before binds under /tmp");

    // Pinned Wine runtime and prefix
    assert!(args_str.contains(&"/opt/universalrun/runtimes/wine-9.0".to_string()));
    assert!(args_str.contains(&"/var/data/universalrun/prefixes/test-app".to_string()));

    // Terminating wine execution
    assert_eq!(args_str[args_str.len() - 3], "--");
    assert_eq!(args_str[args_str.len() - 2], "/usr/lib/wine/bin/wine");
    assert_eq!(args_str[args_str.len() - 1], "C:\\app.exe");
}

#[test]
fn test_golden_network_allowed_policy() {
    let policy = SandboxPolicy {
        network: true,
        ..Default::default()
    };
    let ctx = sample_context(policy);
    let backend = BwrapBackend::new();
    let args = backend.build_args(&ctx).expect("build_args failed");

    let args_str: Vec<String> = args.iter().map(|s| s.to_string_lossy().into_owned()).collect();

    // Verify that --share-net appears AFTER --unshare-all
    let unshare_idx = args_str.iter().position(|r| r == "--unshare-all").unwrap();
    let share_net_idx = args_str.iter().position(|r| r == "--share-net").unwrap();
    assert!(share_net_idx > unshare_idx, "--share-net must come after --unshare-all");

    // SSL certificates must be mounted when network is enabled
    assert!(args_str.contains(&"/etc/ssl".to_string()));
    assert!(args_str.contains(&"/etc/ca-certificates".to_string()));
}

#[test]
fn test_golden_gpu_allowed_policy() {
    let policy = SandboxPolicy {
        gpu: true,
        ..Default::default()
    };
    let ctx = sample_context(policy);
    let backend = BwrapBackend::new();
    let args = backend.build_args(&ctx).expect("build_args failed");

    let args_str: Vec<String> = args.iter().map(|s| s.to_string_lossy().into_owned()).collect();

    // GPU device nodes and narrow sysfs
    assert!(args_str.contains(&"/dev/dri".to_string()));
    assert!(args_str.contains(&"/sys/dev/char".to_string()));
    assert!(args_str.contains(&"/sys/devices".to_string()));
}

#[test]
fn test_golden_granted_folder_policy() {
    let mut policy = SandboxPolicy::default();
    policy.granted_folders.push(GrantedFolder {
        host_path: PathBuf::from("/srv/game_data"),
        container_path: "/data/game".to_string(),
        read_only: true,
    });
    policy.granted_folders.push(GrantedFolder {
        host_path: PathBuf::from("/srv/game_saves"),
        container_path: "/data/saves".to_string(),
        read_only: false,
    });

    let ctx = sample_context(policy);
    let backend = BwrapBackend::new();
    let args = backend.build_args(&ctx).expect("build_args failed");

    let args_str: Vec<String> = args.iter().map(|s| s.to_string_lossy().into_owned()).collect();

    let ro_idx = args_str.iter().position(|r| r == "/srv/game_data").unwrap();
    assert_eq!(args_str[ro_idx - 1], "--ro-bind");
    assert_eq!(args_str[ro_idx + 1], "/data/game");

    let rw_idx = args_str.iter().position(|r| r == "/srv/game_saves").unwrap();
    assert_eq!(args_str[rw_idx - 1], "--bind");
    assert_eq!(args_str[rw_idx + 1], "/data/saves");
}

#[test]
fn test_golden_wayland_display_policy() {
    let policy = SandboxPolicy {
        display: DisplayBackend::Wayland,
        ..Default::default()
    };

    let ctx = sample_context(policy);
    let backend = BwrapBackend::new();
    let args = backend.build_args(&ctx).expect("build_args failed");

    let args_str: Vec<String> = args.iter().map(|s| s.to_string_lossy().into_owned()).collect();

    assert!(args_str.contains(&"WAYLAND_DISPLAY".to_string()));
    assert!(args_str.contains(&"wayland-0".to_string()));
    assert!(args_str.contains(&"/run/user/container/wayland-0".to_string()));
    assert!(!args_str.contains(&"DISPLAY".to_string()));
}

// ============================================================================
// 3. PROPERTY-STYLE RANDOMIZED TEST (500 ITERATIONS)
// ============================================================================

#[test]
fn test_property_randomized_policies_never_leak_forbidden_paths() {
    let mut rng = rand::thread_rng();

    for _ in 0..500 {
        let policy = SandboxPolicy {
            schema_version: "1.0.0".to_string(),
            files: match rng.gen_range(0..3) {
                0 => FilePermissionMode::Deny,
                1 => FilePermissionMode::Ask,
                _ => FilePermissionMode::Allow,
            },
            granted_folders: vec![GrantedFolder {
                host_path: PathBuf::from(format!("/srv/random_data_{}", rng.gen_range(1..1000))),
                container_path: "/data/folder".to_string(),
                read_only: rng.gen_bool(0.5),
            }],
            network: rng.gen_bool(0.5),
            audio: rng.gen_bool(0.5),
            microphone: rng.gen_bool(0.5),
            display: match rng.gen_range(0..3) {
                0 => DisplayBackend::X11,
                1 => DisplayBackend::Wayland,
                _ => DisplayBackend::Headless,
            },
            gpu: rng.gen_bool(0.5),
            camera: rng.gen_bool(0.5),
            usb: rng.gen_bool(0.5),
            system_access: false,
        };

        let ctx = sample_context(policy);
        let backend = BwrapBackend::new();
        let args = backend.build_args(&ctx).expect("build_args failed on valid random policy");

        for arg in &args {
            let s = arg.to_string_lossy();
            assert!(!s.contains("/root"), "Argument leaked /root: {}", s);
            assert!(!s.contains("/etc/shadow"), "Argument leaked /etc/shadow: {}", s);
            assert!(!s.contains("docker.sock"), "Argument leaked docker.sock: {}", s);
            assert!(!s.contains("$HOME"), "Argument leaked $HOME: {}", s);
            assert!(!s.contains("${HOME}"), "Argument leaked ${{HOME}}: {}", s);
        }
    }
}

// ============================================================================
// 4. ENFORCEMENT STATUS TESTS
// ============================================================================

#[test]
fn test_enforcement_status_microphone_boundary() {
    // When audio is enabled but mic is disabled, bubblewrap CANNOT enforce mic block
    let policy = SandboxPolicy {
        audio: true,
        microphone: false,
        ..Default::default()
    };

    let status = policy.enforcement_status();
    let (mic_level, mic_msg) = status.get("microphone").unwrap();
    assert_eq!(*mic_level, EnforcementLevel::No);
    assert!(mic_msg.contains("CANNOT BE ENFORCED"));

    // When audio is disabled, mic is safely blocked
    let policy_no_audio = SandboxPolicy {
        audio: false,
        ..Default::default()
    };
    let status_no_audio = policy_no_audio.enforcement_status();
    let (mic_level_off, _) = status_no_audio.get("microphone").unwrap();
    assert_eq!(*mic_level_off, EnforcementLevel::Yes);
}

#[test]
fn test_enforcement_status_gpu_boundary() {
    let policy = SandboxPolicy {
        gpu: true,
        ..Default::default()
    };
    let status = policy.enforcement_status();
    let (gpu_level, gpu_msg) = status.get("gpu").unwrap();
    assert_eq!(*gpu_level, EnforcementLevel::Partial);
    assert!(gpu_msg.contains("driver attack surface"));
}

#[test]
fn test_enforcement_status_display_isolation() {
    let policy_x11 = SandboxPolicy {
        display: DisplayBackend::X11,
        ..Default::default()
    };
    let status_x11 = policy_x11.enforcement_status();
    assert_eq!(status_x11.get("display").unwrap().0, EnforcementLevel::Partial);

    let policy_wayland = SandboxPolicy {
        display: DisplayBackend::Wayland,
        ..Default::default()
    };
    let status_wayland = policy_wayland.enforcement_status();
    assert_eq!(status_wayland.get("display").unwrap().0, EnforcementLevel::Yes);
}

// ============================================================================
// 5. MOCK SANDBOX TESTS
// ============================================================================

#[test]
fn test_mock_sandbox_behavior() {
    let mock = MockSandbox::new();
    let policy = SandboxPolicy::default();
    let ctx = sample_context(policy);

    let args = mock.build_args(&ctx).expect("mock build_args");
    assert!(!args.is_empty());

    let pid = mock.spawn(&args).expect("mock spawn");
    assert_eq!(pid, 42000);
    assert_eq!(mock.last_args().unwrap(), args);

    mock.fail_with("Simulated spawn error");
    let err = mock.spawn(&args).unwrap_err();
    assert!(err.to_string().contains("Simulated spawn error"));
}

// ============================================================================
// 6. BWRAP SPAWN ON NON-LINUX HOST
// ============================================================================

#[test]
fn test_bwrap_spawn_non_linux_host_error() {
    let backend = BwrapBackend::new();
    let args = vec![std::ffi::OsString::from("--help")];
    let res = backend.spawn(&args);
    #[cfg(not(target_os = "linux"))]
    {
        assert!(res.is_err());
        assert!(res.unwrap_err().to_string().contains("UNTESTED ON LINUX"));
    }
}
