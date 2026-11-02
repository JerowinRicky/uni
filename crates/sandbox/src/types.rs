use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

/// Realistic enforcement capability of the sandbox isolation backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnforcementLevel {
    /// Fully enforced by kernel namespaces and mount isolation.
    Yes,
    /// Partially enforced (e.g. device nodes exposed or shared socket protocol).
    Partial,
    /// Cannot be enforced by bubblewrap alone without protocol-level portal or daemon support.
    No,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum FilePermissionMode {
    #[default]
    Deny,
    Ask,
    Allow,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum DisplayBackend {
    #[default]
    X11,
    Wayland,
    Headless,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GrantedFolder {
    pub host_path: PathBuf,
    pub container_path: String,
    pub read_only: bool,
}

impl Default for GrantedFolder {
    fn default() -> Self {
        Self {
            host_path: PathBuf::new(),
            container_path: String::new(),
            read_only: true, // Least-privilege default
        }
    }
}

/// Comprehensive hardware and resource sandbox policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SandboxPolicy {
    pub schema_version: String,
    pub files: FilePermissionMode,
    pub granted_folders: Vec<GrantedFolder>,
    pub network: bool,
    pub audio: bool,
    pub microphone: bool,
    pub display: DisplayBackend,
    pub gpu: bool,
    pub camera: bool,
    pub usb: bool,
    pub system_access: bool,
}

impl Default for SandboxPolicy {
    fn default() -> Self {
        Self {
            schema_version: "1.0.0".to_string(),
            files: FilePermissionMode::Deny,
            granted_folders: Vec::new(),
            network: false,
            audio: false,
            microphone: false,
            display: DisplayBackend::X11,
            gpu: false,
            camera: false,
            usb: false,
            system_access: false,
        }
    }
}

impl SandboxPolicy {
    /// Return the exact, verified enforcement capabilities of Bubblewrap for each permission.
    ///
    /// Security truth:
    /// - Files: Yes (tmpfs + dedicated read-only/writable mounts; host root/home never bound).
    /// - Network: Yes (net namespace unshared unless `--share-net` is explicitly set).
    /// - Display:
    ///   - X11: Partial (X11 protocol has no client boundary; clients can capture screen/input).
    ///   - Wayland: Yes (wayland socket isolates clients by default).
    /// - GPU: Partial (exposes `/dev/dri` directly to kernel GPU driver; driver attack surface).
    /// - Audio & Microphone:
    ///   - When audio=false: Yes (no audio sockets passed).
    ///   - When audio=true and microphone=false: NO (PulseAudio/PipeWire sockets do not allow
    ///     bwrap to block microphone recording while permitting audio output without portals).
    /// - Camera / USB: Yes (device nodes omitted from container `/dev`).
    pub fn enforcement_status(&self) -> HashMap<&'static str, (EnforcementLevel, &'static str)> {
        let mut status = HashMap::new();

        status.insert("files", (EnforcementLevel::Yes, "Enforced via mount namespace"));
        status.insert(
            "network",
            (EnforcementLevel::Yes, "Enforced via unshared network namespace"),
        );

        match self.display {
            DisplayBackend::X11 => status.insert(
                "display",
                (EnforcementLevel::Partial, "X11 lacks native client isolation (snooping possible)"),
            ),
            DisplayBackend::Wayland => status.insert(
                "display",
                (EnforcementLevel::Yes, "Wayland enforces per-client display isolation"),
            ),
            DisplayBackend::Headless => status.insert(
                "display",
                (EnforcementLevel::Yes, "No display server sockets exposed"),
            ),
        };

        if self.gpu {
            status.insert(
                "gpu",
                (EnforcementLevel::Partial, "Kernel /dev/dri nodes exposed directly; driver attack surface"),
            );
        } else {
            status.insert(
                "gpu",
                (EnforcementLevel::Yes, "GPU device nodes completely omitted from container /dev"),
            );
        }

        if !self.audio {
            status.insert(
                "audio",
                (EnforcementLevel::Yes, "Audio sockets completely omitted"),
            );
            status.insert(
                "microphone",
                (EnforcementLevel::Yes, "Microphone blocked (audio sockets omitted)"),
            );
        } else {
            status.insert(
                "audio",
                (EnforcementLevel::Yes, "Audio socket exposed for playback"),
            );
            // Crucial: Bubblewrap cannot filter microphone input over an exposed Pulse/PipeWire socket
            if !self.microphone {
                status.insert(
                    "microphone",
                    (EnforcementLevel::No, "CANNOT BE ENFORCED: Exposing audio socket permits microphone recording without daemon portal filtering"),
                );
            } else {
                status.insert(
                    "microphone",
                    (EnforcementLevel::Yes, "Microphone recording explicitly granted"),
                );
            }
        }

        status.insert(
            "camera",
            (EnforcementLevel::Yes, "Camera /dev/video* nodes omitted"),
        );
        status.insert(
            "usb",
            (EnforcementLevel::Yes, "USB /dev/bus/usb nodes omitted"),
        );

        status
    }
}

