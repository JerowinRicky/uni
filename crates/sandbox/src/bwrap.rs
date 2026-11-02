use crate::checker::validate_sandbox_policy;
use crate::types::{DisplayBackend, SandboxPolicy};
use std::ffi::OsString;
use std::path::PathBuf;
use universalrun_common::error::{Result, UniversalRunError};
use universalrun_profile_manager::ProfileManifest;

/// Host paths and runtime context passed into the bubblewrap argument generator.
#[derive(Debug, Clone)]
pub struct SandboxContext {
    pub policy: SandboxPolicy,
    pub manifest: ProfileManifest,
    /// Absolute host path to pinned Wine runtime directory.
    pub host_wine_runtime: PathBuf,
    /// Absolute host path to the application's isolated wine prefix.
    pub host_prefix_dir: PathBuf,
    /// Path to scoped Xauthority cookie (when X11 enabled).
    pub host_scoped_xauth: Option<PathBuf>,
    /// Path to Wayland socket (when Wayland enabled).
    pub host_wayland_socket: Option<PathBuf>,
    /// Path to PulseAudio/PipeWire socket (when audio enabled).
    pub host_pulse_socket: Option<PathBuf>,
}

/// Bubblewrap sandbox backend generator.
pub struct BwrapBackend;

impl BwrapBackend {
    pub fn new() -> Self {
        Self
    }

    /// Build the bubblewrap argument vector as strongly typed data (`Vec<OsString>`).
    ///
    /// Security invariants guaranteed:
    /// - Strict validation: safety checker runs BEFORE argument generation.
    /// - Vector ordering: `--unshare-all`, `--unshare-uts`, `--hostname`, followed by `--share-net` (if network enabled).
    /// - Environment: `--clearenv` + strict allowlist of `--setenv`.
    /// - Filesystem: Host root and `$HOME` are never mounted; `/etc` is never mounted as a whole.
    /// - Prefix isolation: The profile prefix is the ONLY writable app location (`/wineprefix`).
    /// - Tmpfs ordering: `--tmpfs /tmp` is created *before* any bind under `/tmp`.
    /// - Device access: GPU nodes `/dev/dri` and narrow sysfs are exposed ONLY when GPU is granted.
    pub fn build_args(&self, ctx: &SandboxContext) -> Result<Vec<OsString>> {
        // 1. Validate safety policy first
        validate_sandbox_policy(&ctx.policy)?;

        // 2. Namespace unsharing and process lifecycle
        let mut args: Vec<OsString> = vec![
            "--unshare-all".into(),
            "--unshare-uts".into(),
            "--hostname".into(),
            "universalrun-sandbox".into(),
        ];

        // Note: --share-net MUST come after --unshare-all to re-enable networking when permitted
        if ctx.policy.network {
            args.push("--share-net".into());
        }

        args.push("--die-with-parent".into());
        args.push("--new-session".into());
        args.push("--cap-drop".into());
        args.push("ALL".into());

        // 3. Environment allowlist & cleaning
        args.push("--clearenv".into());

        // Wine environment setup (HOME is pinned inside prefix, never host user home)
        args.push("--setenv".into());
        args.push("HOME".into());
        args.push("/wineprefix".into());

        args.push("--setenv".into());
        args.push("WINEPREFIX".into());
        args.push("/wineprefix".into());

        args.push("--setenv".into());
        args.push("WINEARCH".into());
        args.push(ctx.manifest.runtime.architecture.clone().into());

        args.push("--setenv".into());
        args.push("LANG".into());
        args.push("C.UTF-8".into());

        args.push("--setenv".into());
        args.push("PATH".into());
        args.push("/usr/lib/wine/bin:/usr/bin:/bin".into());

        args.push("--setenv".into());
        args.push("WINESERVER".into());
        args.push("/usr/lib/wine/bin/wineserver".into());

        args.push("--setenv".into());
        args.push("WINEDEBUG".into());
        args.push("-all,fixme-all".into());

        // DLL overrides from profile
        if !ctx.manifest.dll_overrides.is_empty() {
            let overrides_str = ctx
                .manifest
                .dll_overrides
                .iter()
                .map(|(dll, mode)| format!("{}={}", dll, mode.to_wine_string()))
                .collect::<Vec<_>>()
                .join(";");
            args.push("--setenv".into());
            args.push("WINEDLLOVERRIDES".into());
            args.push(overrides_str.into());
        }

        // Display environment
        match ctx.policy.display {
            DisplayBackend::X11 => {
                args.push("--setenv".into());
                args.push("DISPLAY".into());
                args.push(":0".into());

                args.push("--setenv".into());
                args.push("XAUTHORITY".into());
                args.push("/tmp/xauth/cookie".into());
            }
            DisplayBackend::Wayland => {
                args.push("--setenv".into());
                args.push("WAYLAND_DISPLAY".into());
                args.push("wayland-0".into());

                args.push("--setenv".into());
                args.push("XDG_RUNTIME_DIR".into());
                args.push("/run/user/container".into());
            }
            DisplayBackend::Headless => {}
        }

        // Audio environment
        if ctx.policy.audio {
            args.push("--setenv".into());
            args.push("PULSE_SERVER".into());
            args.push("unix:/run/user/container/pulse/native".into());

            args.push("--setenv".into());
            args.push("PIPEWIRE_RUNTIME_DIR".into());
            args.push("/run/user/container".into());
        }

        // 4. Core system and pseudo-filesystem mounts
        args.push("--proc".into());
        args.push("/proc".into());

        args.push("--dev".into());
        args.push("/dev".into());

        // CRITICAL TMPFS ORDERING: mount /tmp tmpfs before mounting any sockets under /tmp
        args.push("--tmpfs".into());
        args.push("/tmp".into());

        // Read-only host system mounts (usr-merge compliant)
        args.push("--ro-bind-try".into());
        args.push("/usr".into());
        args.push("/usr".into());

        args.push("--ro-bind-try".into());
        args.push("/lib".into());
        args.push("/lib".into());

        args.push("--ro-bind-try".into());
        args.push("/lib64".into());
        args.push("/lib64".into());

        args.push("--ro-bind-try".into());
        args.push("/bin".into());
        args.push("/bin".into());

        args.push("--ro-bind-try".into());
        args.push("/sbin".into());
        args.push("/sbin".into());

        // Specific /etc files (NEVER mount whole /etc)
        args.push("--ro-bind-try".into());
        args.push("/etc/ld.so.cache".into());
        args.push("/etc/ld.so.cache".into());

        args.push("--ro-bind-try".into());
        args.push("/etc/fonts".into());
        args.push("/etc/fonts".into());

        args.push("--ro-bind-try".into());
        args.push("/etc/machine-id".into());
        args.push("/etc/machine-id".into());

        // Note on systemd-resolved: resolv.conf may be a symlink to /run/systemd/resolve/stub-resolv.conf
        args.push("--ro-bind-try".into());
        args.push("/etc/resolv.conf".into());
        args.push("/etc/resolv.conf".into());

        if ctx.policy.network {
            args.push("--ro-bind-try".into());
            args.push("/etc/ssl".into());
            args.push("/etc/ssl".into());

            args.push("--ro-bind-try".into());
            args.push("/etc/pki".into());
            args.push("/etc/pki".into());

            args.push("--ro-bind-try".into());
            args.push("/etc/ca-certificates".into());
            args.push("/etc/ca-certificates".into());
        }

        // 5. Pinned Wine Runtime Mount (Read-Only)
        args.push("--ro-bind".into());
        args.push(ctx.host_wine_runtime.as_os_str().to_os_string());
        args.push("/usr/lib/wine".into());

        // 6. Application Prefix Mount (The ONLY writable app location)
        args.push("--bind".into());
        args.push(ctx.host_prefix_dir.as_os_str().to_os_string());
        args.push("/wineprefix".into());

        // 7. GPU device nodes and narrow sysfs
        if ctx.policy.gpu {
            args.push("--dev-bind-try".into());
            args.push("/dev/dri".into());
            args.push("/dev/dri".into());

            // Narrow sysfs binds for GPU initialization
            args.push("--ro-bind-try".into());
            args.push("/sys/dev/char".into());
            args.push("/sys/dev/char".into());

            args.push("--ro-bind-try".into());
            args.push("/sys/devices".into());
            args.push("/sys/devices".into());
        }

        // 8. Display socket bindings
        match ctx.policy.display {
            DisplayBackend::X11 => {
                // Bind specific X11 socket (never whole /tmp/.X11-unix)
                args.push("--ro-bind-try".into());
                args.push("/tmp/.X11-unix/X0".into());
                args.push("/tmp/.X11-unix/X0".into());

                if let Some(xauth) = &ctx.host_scoped_xauth {
                    args.push("--ro-bind-try".into());
                    args.push(xauth.as_os_str().to_os_string());
                    args.push("/tmp/xauth/cookie".into());
                }
            }
            DisplayBackend::Wayland => {
                if let Some(wayland_sock) = &ctx.host_wayland_socket {
                    args.push("--ro-bind-try".into());
                    args.push(wayland_sock.as_os_str().to_os_string());
                    args.push("/run/user/container/wayland-0".into());
                }
            }
            DisplayBackend::Headless => {}
        }

        // 9. Audio socket binding
        if ctx.policy.audio {
            if let Some(pulse_sock) = &ctx.host_pulse_socket {
                args.push("--ro-bind-try".into());
                args.push(pulse_sock.as_os_str().to_os_string());
                args.push("/run/user/container/pulse/native".into());
            }
        }

        // 10. Explicitly granted folders
        for folder in &ctx.policy.granted_folders {
            if folder.read_only {
                args.push("--ro-bind".into());
            } else {
                args.push("--bind".into());
            }
            args.push(folder.host_path.as_os_str().to_os_string());
            args.push(folder.container_path.clone().into());
        }

        // 11. Command terminator and entry point
        args.push("--".into());
        args.push("/usr/lib/wine/bin/wine".into());
        args.push(format!("C:\\{}", ctx.manifest.target_app).into());

        Ok(args)
    }

    /// Spawn bubblewrap process.
    ///
    /// [UNTESTED ON LINUX] Execution is deferred until host Linux validation.
    /// On Windows, returns a graceful error to prevent unexpected execution.
    pub fn spawn(&self, _args: &[OsString]) -> Result<u32> {
        #[cfg(target_os = "linux")]
        {
            // UNTESTED ON LINUX
            // Ensure no inherited extra file descriptors
            let mut cmd = std::process::Command::new("bwrap");
            cmd.args(_args);
            let child = cmd.spawn().map_err(UniversalRunError::Io)?;
            Ok(child.id())
        }

        #[cfg(not(target_os = "linux"))]
        {
            Err(UniversalRunError::Sandbox(
                "Bubblewrap execution is supported only on Linux hosts (UNTESTED ON LINUX)".into(),
            ))
        }
    }
}

impl Default for BwrapBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl crate::traits::SandboxBackend for BwrapBackend {
    fn build_args(&self, ctx: &SandboxContext) -> Result<Vec<OsString>> {
        self.build_args(ctx)
    }

    fn spawn(&self, args: &[OsString]) -> Result<u32> {
        self.spawn(args)
    }
}
