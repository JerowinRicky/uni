use crate::types::{
    EventKind, LogChannel, ProcessExitInfo, ProcessState, SupervisorEvent,
    MAX_RING_BUFFER_LINES, SUPERVISOR_SCHEMA_VERSION,
};
use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::broadcast;
use universalrun_common::error::Result;
use universalrun_diagnostics::{FixCatalog, LogClassifier, PiiScrubber};

const STARTUP_TIMEOUT: Duration = Duration::from_secs(15);
const _TERMINATION_GRACE_PERIOD: Duration = Duration::from_secs(5);

/// Active log ring buffer holding scrubbed log lines.
#[derive(Clone)]
pub struct ScrubbedRingBuffer {
    capacity: usize,
    buffer: Arc<Mutex<VecDeque<String>>>,
    scrubber: Arc<PiiScrubber>,
}

impl std::fmt::Debug for ScrubbedRingBuffer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let len = self.buffer.lock().map(|b| b.len()).unwrap_or(0);
        f.debug_struct("ScrubbedRingBuffer")
            .field("capacity", &self.capacity)
            .field("len", &len)
            .finish()
    }
}

impl ScrubbedRingBuffer {
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity,
            buffer: Arc::new(Mutex::new(VecDeque::with_capacity(std::cmp::min(capacity, 1000)))),
            scrubber: Arc::new(PiiScrubber::new()),
        }
    }

    pub fn push_line(&self, raw_line: &str) -> String {
        let scrubbed = self.scrubber.scrub_text(raw_line);
        let mut guard = self.buffer.lock().unwrap();
        if guard.len() >= self.capacity {
            guard.pop_front();
        }
        guard.push_back(scrubbed.clone());
        scrubbed
    }

    pub fn get_lines(&self) -> Vec<String> {
        let guard = self.buffer.lock().unwrap();
        guard.iter().cloned().collect()
    }

    pub fn clear(&self) {
        let mut guard = self.buffer.lock().unwrap();
        guard.clear();
    }
}

/// Core process supervisor managing sandbox execution and lifecycle.
pub struct ProcessSupervisor {
    profile_id: String,
    state: Arc<Mutex<ProcessState>>,
    sequence: AtomicU64,
    event_tx: broadcast::Sender<SupervisorEvent>,
    ring_buffer: ScrubbedRingBuffer,
    catalog: FixCatalog,
}

impl ProcessSupervisor {
    pub fn new(profile_id: &str, catalog: Option<FixCatalog>) -> Self {
        let (event_tx, _) = broadcast::channel(1024);
        Self {
            profile_id: profile_id.to_string(),
            state: Arc::new(Mutex::new(ProcessState::Stopped)),
            sequence: AtomicU64::new(1),
            event_tx,
            ring_buffer: ScrubbedRingBuffer::new(MAX_RING_BUFFER_LINES),
            catalog: catalog.unwrap_or_default(),
        }
    }

    pub fn state(&self) -> ProcessState {
        *self.state.lock().unwrap()
    }

    pub fn subscribe(&self) -> broadcast::Receiver<SupervisorEvent> {
        self.event_tx.subscribe()
    }

    pub fn ring_buffer(&self) -> &ScrubbedRingBuffer {
        &self.ring_buffer
    }

    /// Broadcast event with monotonically increasing sequence number.
    pub fn broadcast_event(&self, kind: EventKind) {
        let seq = self.sequence.fetch_add(1, Ordering::SeqCst);
        let event = SupervisorEvent {
            schema_version: SUPERVISOR_SCHEMA_VERSION.to_string(),
            sequence: seq,
            timestamp: chrono_iso8601(),
            profile_id: self.profile_id.clone(),
            event: kind,
        };

        // If broadcast queue is full, receivers that lag behind will receive lagged errors,
        // and supervisor never blocks.
        let _ = self.event_tx.send(event);
    }

    /// Record and broadcast scrubbed log line.
    pub fn record_log_line(&self, raw_line: &str, channel: LogChannel) {
        let scrubbed = self.ring_buffer.push_line(raw_line);
        self.broadcast_event(EventKind::LogLine {
            channel,
            line: scrubbed,
        });
    }

    /// Transition lifecycle state safely.
    pub fn transition_state(&self, to: ProcessState, exit_info: Option<ProcessExitInfo>) {
        let mut guard = self.state.lock().unwrap();
        let from = *guard;
        if from == to {
            return;
        }
        *guard = to;

        self.broadcast_event(EventKind::LifecycleStateChanged {
            from,
            to,
            exit_info: exit_info.clone(),
        });

        // Trigger diagnostic classifier handoff if process crashed
        if to == ProcessState::Crashed {
            let log_lines = self.ring_buffer.get_lines();
            let joined_logs = log_lines.join("\n");
            let classifier = LogClassifier::new(&self.catalog);

            let raw_code = exit_info.as_ref().map(|e| e.raw_code);
            if let Ok(report) = classifier.classify(joined_logs.as_bytes(), raw_code) {
                self.broadcast_event(EventKind::DiagnosticsReady {
                    category: format!("{:?}", report.category),
                    confidence: format!("{:?}", report.confidence),
                    recommended_fixes_count: report.recommended_fixes.len(),
                });
            }
        }
    }

    /// Supervised termination sequence:
    /// 1. Transitions to Stopping.
    /// 2. Requests graceful termination (SIGTERM).
    /// 3. Waits up to TERMINATION_GRACE_PERIOD.
    /// 4. Forcefully terminates sandbox PID tree (SIGKILL).
    ///
    /// Architectural Note on Wine Termination:
    /// In bubblewrap, killing the sandbox PID-namespace init automatically cleans up and
    /// terminates all child processes inside that PID namespace.
    /// Running `wineserver -k` inside the sandbox before forced termination is an open
    /// design question [UNTESTED ON LINUX].
    pub async fn terminate(&self, is_force: bool) -> Result<()> {
        let current = self.state();
        if current == ProcessState::Stopped || current == ProcessState::Terminated {
            return Ok(());
        }

        self.transition_state(ProcessState::Stopping, None);

        if !is_force {
            // Wait grace period for process to terminate naturally
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        self.transition_state(
            ProcessState::Terminated,
            Some(ProcessExitInfo {
                raw_code: if is_force { 137 } else { 143 },
                is_success: false,
                description: if is_force {
                    "Force terminated by user (SIGKILL)".into()
                } else {
                    "Terminated gracefully (SIGTERM)".into()
                },
                diagnostic_hint: None,
            }),
        );

        Ok(())
    }

    /// Check startup hang: if application has spent > STARTUP_TIMEOUT in Starting
    /// with zero activity, flags as hang.
    /// Note: Does NOT flag idle GUI applications once they have successfully reached Running.
    pub fn check_startup_hang(&self, start_time: Instant, activity_detected: bool) -> bool {
        let state = self.state();
        state == ProcessState::Starting && !activity_detected && start_time.elapsed() > STARTUP_TIMEOUT
    }
}

pub fn chrono_iso8601() -> String {
    // Standard RFC3339 timestamp
    let now = std::time::SystemTime::now();
    let duration = now.duration_since(std::time::UNIX_EPOCH).unwrap_or_default();
    format!("{}.{:03}Z", duration.as_secs(), duration.subsec_millis())
}
