use serde::{Deserialize, Serialize};
use std::fmt;

pub const SUPERVISOR_SCHEMA_VERSION: &str = "1.0.0";
pub const MAX_IPC_MESSAGE_SIZE: usize = 1024 * 1024; // 1 MB cap
pub const MAX_RING_BUFFER_LINES: usize = 50_000;

/// Process lifecycle state machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ProcessState {
    #[default]
    Stopped,
    Starting,
    Running,
    Stopping,
    Crashed,
    Terminated,
}

impl fmt::Display for ProcessState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProcessState::Stopped => write!(f, "stopped"),
            ProcessState::Starting => write!(f, "starting"),
            ProcessState::Running => write!(f, "running"),
            ProcessState::Stopping => write!(f, "stopping"),
            ProcessState::Crashed => write!(f, "crashed"),
            ProcessState::Terminated => write!(f, "terminated"),
        }
    }
}

/// Standardized process exit information mapping NTSTATUS and signals.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessExitInfo {
    pub raw_code: i32,
    pub is_success: bool,
    pub description: String,
    pub diagnostic_hint: Option<String>,
}

impl ProcessExitInfo {
    pub fn from_raw_code(code: i32) -> Self {
        let is_success = code == 0;
        let (description, hint) = match code as u32 {
            0 => ("Success (Clean Exit)".to_string(), None),
            // Windows NTSTATUS code mappings
            0xC0000005 => (
                "STATUS_ACCESS_VIOLATION (0xC0000005)".to_string(),
                Some("Memory access violation: process tried to read/write unmapped or protected memory".to_string()),
            ),
            0xC00000FD => (
                "STATUS_STACK_OVERFLOW (0xC00000FD)".to_string(),
                Some("Stack overflow: deep recursion or stack buffer exhaustion".to_string()),
            ),
            0xC000001D => (
                "STATUS_ILLEGAL_INSTRUCTION (0xC000001D)".to_string(),
                Some("Illegal CPU instruction: application tried to execute instructions unsupported by CPU or translated environment".to_string()),
            ),
            0xC000013A => (
                "STATUS_CONTROL_C_EXIT (0xC000013A)".to_string(),
                Some("Process terminated by Ctrl+C / interrupt signal".to_string()),
            ),
            0x80000003 => (
                "STATUS_BREAKPOINT (0x80000003)".to_string(),
                Some("Hardcoded debug breakpoint or assertion failure encountered".to_string()),
            ),
            // Common POSIX signals (exit code 128 + signal)
            137 => (
                "Killed by SIGKILL (Signal 9)".to_string(),
                Some("Process was killed immediately by host OOM killer or external SIGKILL".to_string()),
            ),
            143 => (
                "Terminated by SIGTERM (Signal 15)".to_string(),
                Some("Process was requested to terminate gracefully".to_string()),
            ),
            139 => (
                "Segmentation fault (Signal 11)".to_string(),
                Some("Segmentation fault in user-space or translated NT DLL".to_string()),
            ),
            134 => (
                "Aborted by SIGABRT (Signal 6)".to_string(),
                Some("Runtime assertion or abort() invoked".to_string()),
            ),
            // Windows installer exit codes
            1602 => (
                "ERROR_INSTALL_USEREXIT (1602)".to_string(),
                Some("User cancelled installation".to_string()),
            ),
            1603 => (
                "ERROR_INSTALL_FAILURE (1603)".to_string(),
                Some("Fatal error during installation".to_string()),
            ),
            _ => (
                format!("Process exited with status code {}", code),
                if code != 0 {
                    Some(format!("Non-zero abnormal exit code {}", code))
                } else {
                    None
                },
            ),
        };

        Self {
            raw_code: code,
            is_success,
            description,
            diagnostic_hint: hint,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LogChannel {
    Stdout,
    Stderr,
    System,
}

/// Ranked installer executable candidate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CandidateExecutable {
    /// Relative path inside prefix drive_c (e.g. "Program Files/App/app.exe")
    pub path: String,
    /// Absolute host path
    pub host_path: String,
    /// Calculated confidence score (0 to 100)
    pub confidence_score: u32,
    /// Reason / evidence for candidate ranking
    pub rationale: Vec<String>,
}

/// Real-time event dispatched over IPC.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SupervisorEvent {
    pub schema_version: String,
    pub sequence: u64,
    pub timestamp: String,
    pub profile_id: String,
    pub event: EventKind,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", content = "payload", rename_all = "snake_case")]
pub enum EventKind {
    LifecycleStateChanged {
        from: ProcessState,
        to: ProcessState,
        exit_info: Option<ProcessExitInfo>,
    },
    LogLine {
        channel: LogChannel,
        line: String,
    },
    EventsDropped {
        dropped_count: u64,
        notice: String,
    },
    InstallerProgress {
        phase: String,
        percent: Option<u8>,
        candidates: Vec<CandidateExecutable>,
        needs_user_choice: bool,
    },
    DiagnosticsReady {
        category: String,
        confidence: String,
        recommended_fixes_count: usize,
    },
}
