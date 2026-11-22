//! Observation side of SacredArts.
//!
//! * [`parse`] — platform-independent parser for strace output.
//! * `supervisor` (Linux only) — the in-container process that runs the
//!   runner under strace and relays requests from the MCP server.

pub mod parse;

#[cfg(target_os = "linux")]
pub mod supervisor;
