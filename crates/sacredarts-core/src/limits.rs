//! Hard limits shared by the host and the sandbox.

/// Virtual path under which the learning workspace is exposed to the AI.
pub const WORKSPACE_ROOT: &str = "/workspace";
/// Maximum length of a path argument in bytes.
pub const MAX_PATH_BYTES: usize = 1024;
/// Maximum length of a single path component (NAME_MAX on Linux).
pub const MAX_COMPONENT_BYTES: usize = 255;
/// Maximum bytes transferred by a single `read` / `write` request.
pub const MAX_IO_BYTES: usize = 64 * 1024;
/// Maximum number of simultaneously open learning handles per session.
pub const MAX_HANDLES: usize = 64;
/// Lowest learning handle number (0, 1, 2 are reserved like stdio).
pub const FIRST_HANDLE: u32 = 3;
/// Maximum size of one JSON line on any internal IPC channel.
pub const MAX_IPC_LINE_BYTES: usize = 4 * 1024 * 1024;
/// Maximum number of strace lines kept for one request.
pub const MAX_OBSERVED_PER_REQUEST: usize = 256;
/// Prefix of the marker paths the runner passes to `faccessat` so that the
/// supervisor can find request boundaries in the strace output.
pub const MARKER_PREFIX: &str = "/.sacredarts-marker/";
