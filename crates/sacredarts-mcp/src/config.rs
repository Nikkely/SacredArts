//! Server configuration. Set by the human operator through environment
//! variables in the MCP client configuration; the AI cannot change any of it.

use std::path::PathBuf;
use std::time::Duration;

pub const DEFAULT_IMAGE: &str = concat!("sacredarts-sandbox:", env!("CARGO_PKG_VERSION"));

/// When the AI may use SacredArts tools. The server never sees the user's
/// message, so this is communicated to the model as an instruction; it
/// cannot be enforced by the server itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Activation {
    /// Only after the user says "System Call" / "システムコール" (default).
    Incantation,
    /// Whenever the model finds the tools useful.
    Always,
}

impl Activation {
    pub fn instructions(self) -> &'static str {
        match self {
            Activation::Incantation => {
                "ACTIVATION RULE (incantation required): Like a Sacred Art, SacredArts is invoked by an incantation. \
                 Call SacredArts tools ONLY when the user's current message contains \"System Call\", \"SystemCall\", \
                 \"Systemcall\" or \"システムコール\" (case-insensitive, with or without a space), or explicitly names SacredArts. \
                 Otherwise do NOT call any SacredArts tool, even if the conversation is about syscalls, Linux or files; \
                 answer normally instead. Exception: while an experiment the user started this way is still in progress \
                 (a sandbox created at the user's request is active and the user is clearly continuing it), follow-up \
                 messages may use the tools without repeating the incantation."
            }
            Activation::Always => "ACTIVATION RULE: SacredArts tools may be used whenever they help answer the user.",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Config {
    /// SACREDARTS_ACTIVATION=incantation (default) | always
    pub activation: Activation,
    pub docker_bin: PathBuf,
    pub image: String,
    pub max_sessions: usize,
    /// `None` = unlimited (env value 0). The sandbox still disappears when the
    /// MCP server (the client session) ends.
    pub idle_timeout: Option<Duration>,
    pub max_lifetime: Option<Duration>,
    /// Per-syscall timeout enforced inside the sandbox.
    pub request_timeout: Duration,
    /// Extra host-side margin before the IPC channel itself is declared hung.
    pub ipc_margin: Duration,
    pub startup_timeout: Duration,
    pub events_per_session: usize,
}

/// Seconds from the environment; 0 means "no limit".
fn env_secs_opt(key: &str, default: u64, min: u64, max: u64) -> Option<Duration> {
    let v = std::env::var(key)
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .unwrap_or(default);
    if v == 0 {
        None
    } else {
        Some(Duration::from_secs(v.clamp(min, max)))
    }
}

fn env_u64(key: &str, default: u64, min: u64, max: u64) -> u64 {
    std::env::var(key)
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .unwrap_or(default)
        .clamp(min, max)
}

/// Locate the docker CLI. MCP clients often start servers with a minimal
/// PATH, so the usual Docker Desktop locations are checked too.
fn find_docker() -> PathBuf {
    if let Ok(p) = std::env::var("SACREDARTS_DOCKER") {
        return PathBuf::from(p);
    }
    if let Some(path) = std::env::var_os("PATH") {
        for dir in std::env::split_paths(&path) {
            let c = dir.join("docker");
            if c.is_file() {
                return c;
            }
        }
    }
    for c in [
        "/usr/local/bin/docker",
        "/opt/homebrew/bin/docker",
        "/Applications/Docker.app/Contents/Resources/bin/docker",
        "/usr/bin/docker",
    ] {
        if std::path::Path::new(c).is_file() {
            return PathBuf::from(c);
        }
    }
    PathBuf::from("docker")
}

impl Config {
    pub fn from_env() -> Self {
        Config {
            activation: match std::env::var("SACREDARTS_ACTIVATION").as_deref().map(str::trim) {
                Ok("always") => Activation::Always,
                _ => Activation::Incantation,
            },
            docker_bin: find_docker(),
            image: std::env::var("SACREDARTS_IMAGE").unwrap_or_else(|_| DEFAULT_IMAGE.to_string()),
            max_sessions: env_u64("SACREDARTS_MAX_SESSIONS", 4, 1, 16) as usize,
            // Learning sessions are often paused for a while: 4 h idle, 24 h total.
            idle_timeout: env_secs_opt("SACREDARTS_IDLE_TIMEOUT_SECS", 4 * 3600, 60, 30 * 86_400),
            max_lifetime: env_secs_opt("SACREDARTS_MAX_LIFETIME_SECS", 24 * 3600, 60, 30 * 86_400),
            request_timeout: Duration::from_millis(env_u64("SACREDARTS_REQUEST_TIMEOUT_MS", 5000, 200, 60_000)),
            ipc_margin: Duration::from_secs(15),
            startup_timeout: Duration::from_secs(env_u64("SACREDARTS_STARTUP_TIMEOUT_SECS", 30, 5, 300)),
            events_per_session: env_u64("SACREDARTS_EVENTS_PER_SESSION", 2000, 100, 100_000) as usize,
        }
    }
}
