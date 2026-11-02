//! UniversalRun Process Supervisor and IPC Subsystem

pub mod installer;
pub mod ipc;
pub mod lnk_parser;
pub mod mock;
pub mod prefix_snapshot;
pub mod process;
pub mod registry_parser;
pub mod types;

#[cfg(test)]
mod tests;

pub use installer::InstallerCandidateEngine;
pub use ipc::*;
pub use lnk_parser::{ShellLinkInfo, ShellLinkParser};
pub use mock::MockRuntime;
pub use prefix_snapshot::{PrefixDiff, PrefixSnapshot, PrefixSnapshotter};
pub use process::{ProcessSupervisor, ScrubbedRingBuffer};
pub use registry_parser::{UninstallRegistryEntry, WineRegistryParser};
pub use types::*;

pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}
