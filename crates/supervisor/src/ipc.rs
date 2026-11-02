use crate::process::ProcessSupervisor;
use crate::types::{EventKind, SupervisorEvent, MAX_IPC_MESSAGE_SIZE, SUPERVISOR_SCHEMA_VERSION};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::broadcast::error::RecvError;
use universalrun_common::error::{Result, UniversalRunError};

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct HandshakeRequest {
    pub schema_version: String,
    pub client_name: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct HandshakeResponse {
    pub accepted: bool,
    pub server_version: String,
    pub error: Option<String>,
}

/// Version handshake validation.
pub fn validate_handshake(json_bytes: &[u8]) -> Result<HandshakeResponse> {
    if json_bytes.len() > MAX_IPC_MESSAGE_SIZE {
        return Err(UniversalRunError::Sandbox(
            "IPC message exceeds 1MB safety size cap".into(),
        ));
    }

    let req: HandshakeRequest = serde_json::from_slice(json_bytes).map_err(|e| {
        UniversalRunError::Sandbox(format!("Invalid IPC handshake payload: {}", e))
    })?;

    if req.schema_version != SUPERVISOR_SCHEMA_VERSION {
        return Ok(HandshakeResponse {
            accepted: false,
            server_version: SUPERVISOR_SCHEMA_VERSION.to_string(),
            error: Some(format!(
                "Schema version mismatch: client '{}' vs server '{}'",
                req.schema_version, SUPERVISOR_SCHEMA_VERSION
            )),
        });
    }

    Ok(HandshakeResponse {
        accepted: true,
        server_version: SUPERVISOR_SCHEMA_VERSION.to_string(),
        error: None,
    })
}

/// Dispatches events to an active IPC stream.
/// Invariants:
/// - Never blocks supervisor on slow consumer.
/// - Emits EventsDropped with count and notice when lagged.
pub struct IpcEventDispatcher {
    pub supervisor: Arc<ProcessSupervisor>,
    dropped_counter: AtomicU64,
}

impl IpcEventDispatcher {
    pub fn new(supervisor: Arc<ProcessSupervisor>) -> Self {
        Self {
            supervisor,
            dropped_counter: AtomicU64::new(0),
        }
    }

    /// Read next event for client, converting lag into an explicit EventsDropped event.
    pub async fn next_client_event(
        &self,
        rx: &mut tokio::sync::broadcast::Receiver<SupervisorEvent>,
    ) -> Option<SupervisorEvent> {
        match rx.recv().await {
            Ok(event) => Some(event),
            Err(RecvError::Lagged(dropped_count)) => {
                let total_dropped = self.dropped_counter.fetch_add(dropped_count, Ordering::SeqCst) + dropped_count;
                // Return synthetic EventsDropped event to inform UI client
                Some(SupervisorEvent {
                    schema_version: SUPERVISOR_SCHEMA_VERSION.to_string(),
                    sequence: 0,
                    timestamp: crate::process::chrono_iso8601(),
                    profile_id: "system".to_string(),
                    event: EventKind::EventsDropped {
                        dropped_count: total_dropped,
                        notice: format!(
                            "UI consumer is lagging; dropped {} events to prevent supervisor stall",
                            dropped_count
                        ),
                    },
                })
            }
            Err(RecvError::Closed) => None,
        }
    }
}

/// Linux SO_PEERCRED peer credential verification.
///
/// [UNTESTED ON LINUX]
/// Verifies that connecting peer process UID matches current user UID.
#[cfg(target_os = "linux")]
pub fn verify_linux_peer_credential(fd: std::os::unix::io::RawFd) -> Result<()> {
    // UNTESTED ON LINUX
    unsafe {
        let mut ucred = libc::ucred {
            pid: 0,
            uid: 0,
            gid: 0,
        };
        let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
        let res = libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut ucred as *mut _ as *mut libc::c_void,
            &mut len,
        );
        if res != 0 {
            return Err(UniversalRunError::Sandbox(
                "Failed to retrieve SO_PEERCRED socket credentials".into(),
            ));
        }

        if ucred.uid != libc::getuid() {
            return Err(UniversalRunError::Sandbox(format!(
                "Security rejection: IPC peer UID {} does not match supervisor UID {}",
                ucred.uid,
                libc::getuid()
            )));
        }
    }
    Ok(())
}
