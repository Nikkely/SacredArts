//! SacredArts syscall runner.
//!
//! The runner is a long-lived process inside the sandbox container. It keeps
//! learning handles (file descriptors) across requests, so that
//! `openat -> write -> close` issued as separate MCP tool calls operate on the
//! same kernel file description.
//!
//! `handles` is pure logic (testable anywhere). Everything that
//! issues syscalls is Linux-only.

pub mod handles;

#[cfg(target_os = "linux")]
pub mod errno;
#[cfg(target_os = "linux")]
pub mod exec;
#[cfg(target_os = "linux")]
pub mod sockio;
