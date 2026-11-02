use crate::bwrap::SandboxContext;
use std::ffi::OsString;
use universalrun_common::error::Result;

/// Abstraction for sandbox backend implementations.
pub trait SandboxBackend: Send + Sync {
    /// Build argument vector as pure data.
    fn build_args(&self, ctx: &SandboxContext) -> Result<Vec<OsString>>;

    /// Spawn sandboxed process.
    fn spawn(&self, args: &[OsString]) -> Result<u32>;
}

