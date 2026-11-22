//! Internal IPC messages (newline-delimited JSON).
//!
//! ```text
//! MCP server (macOS) --stdin/stdout of `docker run -i`--> supervisor (container)
//! supervisor --AF_UNIX socketpair (runner's fd 0)--> runner (traced by strace)
//! ```

use crate::policy::Policy;
use crate::request::SyscallRequest;
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// supervisor <-> runner
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunnerRequest {
    pub id: u64,
    #[serde(flatten)]
    pub op: RunnerOp,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum RunnerOp {
    Invoke { request: SyscallRequest },
    ListHandles,
    Ping,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunnerReply {
    pub id: u64,
    #[serde(flatten)]
    pub body: RunnerReplyBody,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "reply", rename_all = "snake_case")]
pub enum RunnerReplyBody {
    Invoked { outcome: InvokeOutcome },
    Handles { handles: Vec<HandleInfo> },
    Pong,
    Error { message: String },
}

/// First line the runner sends after initialisation (seccomp already applied).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunnerHello {
    pub pid: i32,
    pub arch: String,
    pub policy: Policy,
    /// true if the runner installed its own seccomp filter (policy non-empty).
    pub seccomp_filter_installed: bool,
    pub workspace: String,
}

/// errno of a failed syscall, as reported by the kernel.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErrnoInfo {
    pub name: String,
    pub code: i32,
    pub message: String,
}

/// Why the runner issued a particular kernel syscall.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IssuedPurpose {
    /// The syscall the AI asked for, with its arguments passed verbatim.
    Requested,
    /// Internal state check (e.g. `fcntl(F_GETFD)` after a failed close).
    StateCheck,
}

/// A syscall the runner itself reports having issued (self-report; the
/// independent observation comes from strace).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IssuedCall {
    pub syscall: String,
    pub purpose: IssuedPurpose,
    /// strace-like rendering of the arguments with *real* file descriptors.
    pub args: String,
    pub ret: i64,
    pub errno: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HandleInfo {
    /// File descriptor number. Kept for compatibility; always equal to
    /// `real_fd` (SacredArts passes fds to the kernel verbatim).
    pub handle: i32,
    /// Kernel file descriptor inside the runner process.
    pub real_fd: i32,
    /// Path as requested, joined with the dirfd's path for display.
    pub path: String,
    /// Flags as the kernel received them, decoded strace-style.
    pub flags: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "change", rename_all = "snake_case")]
pub enum HandleChange {
    Opened { info: HandleInfo },
    Closed { info: HandleInfo },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum InvokeOutcome {
    /// Syscalls reached the kernel. `requested_executed` tells whether the
    /// requested syscall itself was issued (paths and flags are passed
    /// verbatim, so today this is always true for a completed request).
    Completed {
        requested_executed: bool,
        ret: i64,
        errno: Option<ErrnoInfo>,
        issued: Vec<IssuedCall>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        handle_change: Option<HandleChange>,
        /// Bytes returned by `read`, base64 encoded.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        read_data_b64: Option<String>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        notes: Vec<String>,
    },
    /// Rejected by application-level validation; nothing was issued.
    Rejected { code: String, message: String },
}

// ---------------------------------------------------------------------------
// strace observation
// ---------------------------------------------------------------------------

/// One syscall line observed by strace. Fields that strace did not report
/// (or that could not be parsed) are `None`; nothing is estimated.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ObservedSyscall {
    /// Seconds since the Unix epoch as printed by `strace -ttt`.
    pub timestamp_epoch: Option<f64>,
    pub syscall: String,
    /// Raw argument text as printed by strace (`-y` adds fd paths).
    pub args: String,
    /// Raw return text, e.g. `3</workspace/a.txt>` or `-1`.
    pub return_raw: String,
    pub ret: Option<i64>,
    pub errno: Option<String>,
    pub errno_message: Option<String>,
    /// Time spent in the syscall (`strace -T`).
    pub duration_ns: Option<u64>,
    /// The unmodified strace line.
    pub raw: String,
}

impl ObservedSyscall {
    /// strace-like line without the timestamp, e.g. `read(3</a>, "x", 4) = 1 <0.000004>`.
    pub fn line(&self) -> String {
        let base = format!("{}({}) = {}", self.syscall, self.args, self.return_raw);
        match self.duration_ns {
            Some(d) => format!("{base} <{:.6}>", d as f64 / 1e9),
            None => base,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObservationStatus {
    /// Both boundary markers were seen.
    Complete,
    /// The end marker was not seen in time, or output was truncated.
    Incomplete,
    /// strace is not running for this runner.
    Unavailable,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Observation {
    pub status: ObservationStatus,
    pub syscalls: Vec<ObservedSyscall>,
    #[serde(default)]
    pub truncated: bool,
}

// ---------------------------------------------------------------------------
// host <-> supervisor
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SupervisorLimits {
    /// Per-request timeout inside the sandbox.
    pub request_timeout_ms: u64,
    /// Supervisor exits if the host is silent for this long.
    /// `u64::MAX` means no limit.
    pub idle_timeout_secs: u64,
    /// Supervisor exits after this lifetime regardless of activity.
    pub max_lifetime_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum HostMessage {
    Init { policy: Policy, limits: SupervisorLimits },
    Invoke { id: u64, request: SyscallRequest },
    Inspect { id: u64 },
    SetPolicy { id: u64, policy: Policy },
    Shutdown { id: u64 },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum TracingStatus {
    Active { tool: String, version: String },
    Unavailable { reason: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SeccompStatus {
    /// `Seccomp:` field of /proc/<pid>/status (0 = off, 2 = filter).
    pub mode: Option<u8>,
    /// `Seccomp_filters:` field (Docker's default profile counts as one).
    pub filters: Option<u32>,
    /// Whether the runner installed a SacredArts filter on top.
    pub sacredarts_filter_installed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunnerInfo {
    /// Incremented every time the runner is (re)created.
    pub generation: u64,
    pub pid: i32,
    pub arch: String,
    pub policy: Policy,
    pub seccomp: SeccompStatus,
    pub tracing: TracingStatus,
    /// strace lines from runner start-up that show seccomp being installed
    /// (`prctl(PR_SET_NO_NEW_PRIVS)`, `seccomp(...)`).
    pub seccomp_evidence: Vec<ObservedSyscall>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkspaceEntry {
    pub name: String,
    pub kind: String,
    pub size: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InspectInfo {
    pub runner: RunnerInfo,
    pub handles: Vec<HandleInfo>,
    pub cwd: String,
    pub workspace_entries: Vec<WorkspaceEntry>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SupervisorErrorKind {
    /// The request did not finish in time; the runner was recreated.
    RunnerTimeout,
    /// The runner died unexpectedly; it was recreated.
    RunnerCrashed,
    /// The policy cannot be turned into a seccomp filter (e.g. an errno name
    /// the C library does not know). Nothing was changed.
    InvalidPolicy,
    /// The new runner could not be started; the old one is still active.
    PolicyApplyFailed,
    /// The runner could not be (re)started at all.
    RunnerUnavailable,
    Internal,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SupervisorMessage {
    Ready {
        runner: RunnerInfo,
    },
    InitFailed {
        message: String,
        /// Set when the failure was caused by the requested policy.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        kind: Option<SupervisorErrorKind>,
    },
    Invoked {
        id: u64,
        outcome: InvokeOutcome,
        observation: Observation,
        runner_generation: u64,
    },
    Inspected {
        id: u64,
        info: InspectInfo,
    },
    PolicyApplied {
        id: u64,
        runner: RunnerInfo,
    },
    Error {
        id: u64,
        kind: SupervisorErrorKind,
        message: String,
        /// true if the runner was recreated and its open fds were lost.
        state_reset: bool,
        runner: Option<RunnerInfo>,
    },
    ShuttingDown {
        id: u64,
    },
}

impl SupervisorMessage {
    pub fn id(&self) -> Option<u64> {
        match self {
            SupervisorMessage::Ready { .. } | SupervisorMessage::InitFailed { .. } => None,
            SupervisorMessage::Invoked { id, .. }
            | SupervisorMessage::Inspected { id, .. }
            | SupervisorMessage::PolicyApplied { id, .. }
            | SupervisorMessage::Error { id, .. }
            | SupervisorMessage::ShuttingDown { id } => Some(*id),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runner_request_wire_format() {
        let r = RunnerRequest {
            id: 7,
            op: RunnerOp::Invoke {
                request: SyscallRequest::Getpid,
            },
        };
        let s = serde_json::to_string(&r).unwrap();
        assert_eq!(s, r#"{"id":7,"op":"invoke","request":{"syscall":"getpid"}}"#);
        let back: RunnerRequest = serde_json::from_str(&s).unwrap();
        assert!(matches!(back.op, RunnerOp::Invoke { .. }));
        let p: RunnerRequest = serde_json::from_str(r#"{"id":1,"op":"ping"}"#).unwrap();
        assert!(matches!(p.op, RunnerOp::Ping));
    }

    #[test]
    fn host_message_roundtrip() {
        let m = HostMessage::SetPolicy {
            id: 3,
            policy: Policy::default(),
        };
        let s = serde_json::to_string(&m).unwrap();
        let back: HostMessage = serde_json::from_str(&s).unwrap();
        assert!(matches!(back, HostMessage::SetPolicy { id: 3, .. }));
    }
}
