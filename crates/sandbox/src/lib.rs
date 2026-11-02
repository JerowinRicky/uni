//! UniversalRun Sandbox Abstraction and Bubblewrap Backend

pub mod bwrap;
pub mod checker;
pub mod mock;
pub mod traits;
pub mod types;

#[cfg(test)]
mod tests;

pub use bwrap::{BwrapBackend, SandboxContext};
pub use checker::*;
pub use mock::MockSandbox;
pub use traits::SandboxBackend;
pub use types::*;

pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}
