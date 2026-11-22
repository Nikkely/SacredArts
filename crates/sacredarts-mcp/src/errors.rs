//! Tool-level errors. Three families are kept apart on purpose:
//!
//! * `invalid_argument` / `unsupported_syscall` — application-level
//!   validation; no syscall was issued.
//! * Linux errors (errno) are **not** tool errors: a syscall that returned -1
//!   is a successful tool call with `success: false` and `errno` set.
//! * `infrastructure` / `timeout` — Docker, IPC, or sandbox problems.

use serde::Serialize;
use serde_json::Value;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorKind {
    InvalidArgument,
    UnsupportedSyscall,
    SessionNotFound,
    LimitExceeded,
    Timeout,
    Infrastructure,
}

#[derive(Debug, Clone, Serialize)]
pub struct ToolError {
    pub kind: ErrorKind,
    pub code: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<Value>,
}

impl ToolError {
    pub fn new(kind: ErrorKind, code: &str, message: impl Into<String>) -> Self {
        ToolError {
            kind,
            code: code.to_string(),
            message: message.into(),
            details: None,
        }
    }

    pub fn details(mut self, v: Value) -> Self {
        self.details = Some(v);
        self
    }

    pub fn infra(code: &str, message: impl Into<String>) -> Self {
        Self::new(ErrorKind::Infrastructure, code, message)
    }

    pub fn not_found(id: &str) -> Self {
        Self::new(
            ErrorKind::SessionNotFound,
            "session_not_found",
            format!(
                "no active sandbox with session_id {id:?} (it may have been destroyed or timed out); call sandbox_create"
            ),
        )
    }

    pub fn from_validation(v: sacredarts_core::ValidationError) -> Self {
        let kind = match v.code.as_str() {
            "unsupported_syscall" => ErrorKind::UnsupportedSyscall,
            "limit_exceeded" => ErrorKind::LimitExceeded,
            _ => ErrorKind::InvalidArgument,
        };
        let mut e = Self::new(kind, &v.code, v.message);
        if let Some(f) = v.field {
            e.details = Some(serde_json::json!({ "field": f }));
        }
        e
    }
}

impl std::fmt::Display for ToolError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}
