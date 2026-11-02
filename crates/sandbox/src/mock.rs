use crate::bwrap::SandboxContext;
use crate::traits::SandboxBackend;
use std::ffi::OsString;
use std::sync::{Arc, Mutex};
use universalrun_common::error::{Result, UniversalRunError};

/// Mock sandbox implementation for host-agnostic and Windows testing.
#[derive(Debug, Clone)]
pub struct MockSandbox {
    pub spawned_args: Arc<Mutex<Vec<Vec<OsString>>>>,
    pub next_pid: u32,
    pub fail_next_spawn: Arc<Mutex<Option<String>>>,
}

impl MockSandbox {
    pub fn new() -> Self {
        Self {
            spawned_args: Arc::new(Mutex::new(Vec::new())),
            next_pid: 42000,
            fail_next_spawn: Arc::new(Mutex::new(None)),
        }
    }

    pub fn fail_with(&self, err_msg: &str) {
        let mut guard = self.fail_next_spawn.lock().unwrap();
        *guard = Some(err_msg.to_string());
    }

    pub fn last_args(&self) -> Option<Vec<OsString>> {
        let guard = self.spawned_args.lock().unwrap();
        guard.last().cloned()
    }
}

impl Default for MockSandbox {
    fn default() -> Self {
        Self::new()
    }
}

impl SandboxBackend for MockSandbox {
    fn build_args(&self, ctx: &SandboxContext) -> Result<Vec<OsString>> {
        // Delegate argument generation to BwrapBackend logic to verify argument correctness
        crate::bwrap::BwrapBackend::new().build_args(ctx)
    }

    fn spawn(&self, args: &[OsString]) -> Result<u32> {
        let mut fail_guard = self.fail_next_spawn.lock().unwrap();
        if let Some(msg) = fail_guard.take() {
            return Err(UniversalRunError::Sandbox(msg));
        }

        let mut guard = self.spawned_args.lock().unwrap();
        guard.push(args.to_vec());
        Ok(self.next_pid)
    }
}
