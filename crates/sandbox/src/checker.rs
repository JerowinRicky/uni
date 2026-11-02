use crate::types::SandboxPolicy;
use std::path::{Component, Path};
use universalrun_common::error::{Result, UniversalRunError};

const SENSITIVE_USER_DIRECTORIES: &[&str] = &[
    ".ssh",
    ".gnupg",
    ".aws",
    ".config",
    ".mozilla",
    "google-chrome",
    "chromium",
    "brave",
];

/// Rejects mounting root `/` or empty path.
pub fn check_no_root_mount(path: &Path) -> Result<()> {
    let s = path.to_string_lossy();
    if s == "/" || s == "\\" || path.parent().is_none() {
        return Err(UniversalRunError::Sandbox(
            "Security rule violation: mounting system root '/' is strictly forbidden".into(),
        ));
    }
    Ok(())
}

/// Rejects mounting host `/home`, `/root`, or `$HOME`.
pub fn check_no_home_mount(path: &Path) -> Result<()> {
    let s = path.to_string_lossy().replace('\\', "/");
    if s == "/home" || s == "/root" || s == "~" || s.contains("$HOME") || s.contains("${HOME}") {
        return Err(UniversalRunError::Sandbox(
            "Security rule violation: mounting host home directory is strictly forbidden".into(),
        ));
    }
    Ok(())
}

/// Rejects mounting `/usr`, `/lib`, `/bin`, `/sbin`, or `/etc` as writable.
pub fn check_no_writable_system_paths(path: &Path, read_only: bool) -> Result<()> {
    if read_only {
        return Ok(());
    }

    let s = path.to_string_lossy().replace('\\', "/");
    let forbidden_writable = ["/usr", "/lib", "/lib64", "/bin", "/sbin", "/etc"];
    for sys in &forbidden_writable {
        if s == *sys || s.starts_with(&format!("{}/", sys)) {
            return Err(UniversalRunError::Sandbox(format!(
                "Security rule violation: system directory '{}' cannot be mounted writable",
                sys
            )));
        }
    }
    Ok(())
}

/// Rejects mounting whole `/dev` or `/proc/sys`.
pub fn check_no_sensitive_dev_or_proc(path: &Path) -> Result<()> {
    let s = path.to_string_lossy().replace('\\', "/");
    if s == "/dev" || s == "/dev/" {
        return Err(UniversalRunError::Sandbox(
            "Security rule violation: binding entire host '/dev' is forbidden (use scoped --dev)".into(),
        ));
    }
    if s == "/proc/sys" || s.starts_with("/proc/sys/") {
        return Err(UniversalRunError::Sandbox(
            "Security rule violation: binding '/proc/sys' is strictly forbidden".into(),
        ));
    }
    Ok(())
}

/// Rejects container and hypervisor control sockets (Docker, Podman).
pub fn check_no_container_sockets(path: &Path) -> Result<()> {
    let s = path.to_string_lossy().replace('\\', "/");
    if s.contains("docker.sock") || s.contains("podman.sock") || s.contains("containerd.sock") {
        return Err(UniversalRunError::Sandbox(
            "Security rule violation: mounting container daemon sockets is strictly forbidden".into(),
        ));
    }
    Ok(())
}

/// Rejects host D-Bus session bus.
pub fn check_no_dbus_session_bus(path: &Path) -> Result<()> {
    let s = path.to_string_lossy().replace('\\', "/");
    if s.ends_with("/bus") && s.contains("/run/user/") {
        return Err(UniversalRunError::Sandbox(
            "Security rule violation: exposing host D-Bus session bus is strictly forbidden".into(),
        ));
    }
    Ok(())
}

/// Rejects SSH authentication agent sockets.
pub fn check_no_ssh_agent_socket(path: &Path) -> Result<()> {
    let s = path.to_string_lossy().replace('\\', "/");
    if s.contains("ssh-") || s.contains("agent.") || s.contains("auth_sock") {
        return Err(UniversalRunError::Sandbox(
            "Security rule violation: exposing SSH authentication agent socket is strictly forbidden".into(),
        ));
    }
    Ok(())
}

/// Rejects mounting whole `$XDG_RUNTIME_DIR` (`/run/user/<uid>`).
pub fn check_no_whole_xdg_runtime_dir(path: &Path) -> Result<()> {
    let s = path.to_string_lossy().replace('\\', "/");
    if s.starts_with("/run/user/") && !s.contains("/pulse") && !s.contains("/pipewire") && !s.contains("/wayland") {
        let parts: Vec<&str> = s.split('/').filter(|p| !p.is_empty()).collect();
        // /run/user/<uid> with no sub-path
        if parts.len() <= 3 {
            return Err(UniversalRunError::Sandbox(
                "Security rule violation: mounting whole XDG_RUNTIME_DIR is forbidden (only scoped sockets allowed)".into(),
            ));
        }
    }
    Ok(())
}

/// Rejects path traversal `..`.
pub fn check_no_parent_traversal(path: &Path) -> Result<()> {
    for comp in path.components() {
        if comp == Component::ParentDir {
            return Err(UniversalRunError::Sandbox(
                "Security rule violation: path traversal ('..') is strictly forbidden".into(),
            ));
        }
    }
    Ok(())
}

/// Rejects dangerous granted folders (system roots, private user credentials).
pub fn check_granted_folder_safety(path: &Path) -> Result<()> {
    check_no_root_mount(path)?;
    check_no_home_mount(path)?;
    check_no_parent_traversal(path)?;

    let s = path.to_string_lossy().replace('\\', "/");
    let forbidden_roots = ["/run", "/var", "/root", "/proc", "/sys", "/boot", "/dev"];
    for root in &forbidden_roots {
        if s == *root || s == format!("{}/", root) {
            return Err(UniversalRunError::Sandbox(format!(
                "Security rule violation: granting host directory '{}' is forbidden",
                root
            )));
        }
    }

    // Refuse sensitive user credentials & browser profiles
    for sensitive in SENSITIVE_USER_DIRECTORIES {
        if s.contains(&format!("/{}", sensitive)) || s.ends_with(sensitive) {
            return Err(UniversalRunError::Sandbox(format!(
                "Security rule violation: granted folder '{}' contains sensitive credentials or browser data",
                sensitive
            )));
        }
    }

    Ok(())
}

/// Validate entire SandboxPolicy before any Bubblewrap argument vector is generated.
pub fn validate_sandbox_policy(policy: &SandboxPolicy) -> Result<()> {
    for folder in &policy.granted_folders {
        check_granted_folder_safety(&folder.host_path)?;
        check_no_writable_system_paths(&folder.host_path, folder.read_only)?;
        check_no_container_sockets(&folder.host_path)?;
        check_no_dbus_session_bus(&folder.host_path)?;
        check_no_ssh_agent_socket(&folder.host_path)?;
        check_no_whole_xdg_runtime_dir(&folder.host_path)?;
    }
    Ok(())
}
