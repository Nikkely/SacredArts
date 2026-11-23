//! Shared, platform-independent types for SacredArts.
//!
//! Everything in this crate is plain data + validation. Nothing here executes
//! a Linux syscall, so it compiles and is unit-tested on macOS as well.

pub mod format;
pub mod ipc;
pub mod limits;
pub mod modes;
pub mod policy;
pub mod process;
pub mod request;
pub mod syscall;

pub use modes::{GuideLevel, TraceMode};
pub use policy::{DenyErrno, Policy};
pub use request::{DecodedFlags, Dirfd, NICE_MAX, NICE_MIN, OpenFlag, PrioWhich, SyscallRequest, ValidationError};
pub use syscall::SyscallName;
