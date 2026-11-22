//! Limits shared by the host and the sandbox.
//!
//! These only bound what has to be marshalled through the IPC channels.
//! Everything else (path length, number of open files, permissions, ...) is
//! left to the kernel, so its real errno (ENAMETOOLONG, EMFILE, ...) is seen.

/// Working directory of the runner inside the sandbox.
pub const WORKSPACE_ROOT: &str = "/workspace";
/// Maximum size of a path argument that is marshalled to the runner. Far
/// above the kernel's PATH_MAX (4096), so ENAMETOOLONG comes from the kernel.
pub const MAX_PATH_BYTES: usize = 64 * 1024;
/// Maximum bytes transferred by a single `read` / `write` request (the data
/// travels through the JSON IPC channel).
pub const MAX_IO_BYTES: usize = 64 * 1024;
/// Maximum size of one JSON line on any internal IPC channel.
pub const MAX_IPC_LINE_BYTES: usize = 4 * 1024 * 1024;
/// Maximum number of strace lines kept for one request.
pub const MAX_OBSERVED_PER_REQUEST: usize = 256;
/// Prefix of the marker paths the runner passes to `faccessat` so that the
/// supervisor can find request boundaries in the strace output.
pub const MARKER_PREFIX: &str = "/.sacredarts-marker/";
