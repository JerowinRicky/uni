use std::path::Path;
use crate::error::Result;

/// Core host platform operations and detection.
pub trait PlatformAdapter: Send + Sync {
    fn platform_name(&self) -> &'static str;
    fn supports_unprivileged_userns(&self) -> bool;
}

/// Runtime abstraction (e.g., Wine, Proton).
pub trait RuntimeBackend: Send + Sync {
    fn name(&self) -> &'static str;
    fn version(&self) -> String;
    fn initialize_prefix(&self, prefix_path: &Path) -> Result<()>;
}

/// Sandbox isolation provider (e.g., Bubblewrap on Linux).
pub trait SandboxBackend: Send + Sync {
    fn name(&self) -> &'static str;
    fn is_available(&self) -> bool;
}

/// Filesystem mapping and permission scoping.
pub trait FilesystemAdapter: Send + Sync {
    fn sanitize_prefix(&self, prefix_path: &Path) -> Result<()>;
}

/// Display and graphics isolation.
pub trait GraphicsAdapter: Send + Sync {
    fn display_type(&self) -> &'static str;
}

/// Audio backend passthrough.
pub trait AudioAdapter: Send + Sync {
    fn audio_server(&self) -> &'static str;
}

/// Installer detection and execution handler.
pub trait InstallerAdapter: Send + Sync {
    fn can_handle(&self, target_path: &Path) -> bool;
}
