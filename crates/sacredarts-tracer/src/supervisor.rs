//! In-container supervisor.
//!
//! * talks to the MCP server over its own stdin/stdout (JSON lines; stdout is
//!   reserved for protocol messages, diagnostics go to stderr),
//! * starts the runner as a child of `strace` (falls back to an untraced
//!   runner if ptrace is not permitted, and reports that honestly),
//! * splits strace output into per-request observations using the runner's
//!   boundary markers,
//! * recreates the runner on timeout / crash / policy change.

use crate::parse::{TraceLine, parse_line};
use sacredarts_core::Policy;
use sacredarts_core::ipc::*;
use sacredarts_core::limits::{MAX_IPC_LINE_BYTES, MAX_OBSERVED_PER_REQUEST};
use std::collections::VecDeque;
use std::fs::{File, OpenOptions};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::os::fd::OwnedFd;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicI32, AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const STARTUP_TIMEOUT: Duration = Duration::from_secs(10);
const OBSERVE_TIMEOUT: Duration = Duration::from_secs(2);
const MAX_STARTUP_LINES: usize = 4000;

#[derive(Debug, Clone)]
pub struct Config {
    pub runner_bin: PathBuf,
    pub strace_bin: Option<PathBuf>,
    pub workspace: PathBuf,
    pub tmp: PathBuf,
}

enum TraceEvent {
    Line(String),
    Eof,
}

struct Trace {
    rx: Receiver<TraceEvent>,
    fifo: PathBuf,
}

struct RunnerProc {
    child: Child,
    sock: UnixStream,
    reader: BufReader<UnixStream>,
    trace: Option<Trace>,
    info: RunnerInfo,
    next_id: u64,
    stderr_tail: Arc<Mutex<VecDeque<String>>>,
}

enum ReqError {
    Timeout,
    Crashed(String),
}

/// pids that the watchdog must kill on forced exit.
static RUNNER_PID: AtomicI32 = AtomicI32::new(0);
static CHILD_PID: AtomicI32 = AtomicI32::new(0);

fn log(msg: impl AsRef<str>) {
    eprintln!("[sacredarts-supervisor] {}", msg.as_ref());
}

/// The name contains a random part, so there is never a stale file to remove.
fn mkfifo(path: &Path) -> io::Result<()> {
    let c = std::ffi::CString::new(path.as_os_str().as_encoded_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "NUL in path"))?;
    // SAFETY: `c` is a valid NUL-terminated path for the duration of the call.
    if unsafe { libc::mkfifo(c.as_ptr(), 0o600) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn random_u64() -> u64 {
    let mut b = [0u8; 8];
    // SAFETY: `b` is a writable buffer of exactly the length passed.
    let n = unsafe { libc::getrandom(b.as_mut_ptr().cast(), b.len(), 0) };
    if n == 8 {
        u64::from_ne_bytes(b)
    } else {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0)
            ^ u64::from(std::process::id())
    }
}

fn kill_pid(pid: i32) {
    if pid > 0 {
        // SAFETY: sending a signal has no memory-safety implications.
        unsafe { libc::kill(pid, libc::SIGKILL) };
    }
}

pub fn read_seccomp_status(pid: i32, installed: bool) -> SeccompStatus {
    let text = std::fs::read_to_string(format!("/proc/{pid}/status")).unwrap_or_default();
    let field = |k: &str| {
        text.lines()
            .find_map(|l| l.strip_prefix(k))
            .map(|v| v.trim().to_string())
    };
    SeccompStatus {
        mode: field("Seccomp:").and_then(|v| v.parse().ok()),
        filters: field("Seccomp_filters:").and_then(|v| v.parse().ok()),
        sacredarts_filter_installed: installed,
    }
}

fn strace_version(bin: &Path) -> Option<String> {
    let out = Command::new(bin).arg("-V").stdin(Stdio::null()).output().ok()?;
    let s = String::from_utf8_lossy(&out.stdout);
    s.lines().next().map(|l| l.trim().to_string())
}

impl RunnerProc {
    fn spawn(cfg: &Config, generation: u64, policy: &Policy, use_strace: bool) -> Result<RunnerProc, String> {
        let (ours, theirs) = UnixStream::pair().map_err(|e| format!("socketpair: {e}"))?;
        let policy_json = serde_json::to_string(policy).map_err(|e| e.to_string())?;

        let strace = if use_strace { cfg.strace_bin.clone() } else { None };
        let mut trace = None;
        let mut cmd = match &strace {
            Some(strace_bin) => {
                // /tmp is shared with the learner, so use an unpredictable
                // name and unlink it as soon as both ends are open.
                let fifo = cfg
                    .tmp
                    .join(format!(".sacredarts-trace-{generation}-{:016x}.fifo", random_u64()));
                mkfifo(&fifo).map_err(|e| format!("mkfifo {}: {e}", fifo.display()))?;
                let (tx, rx) = mpsc::channel();
                let fifo2 = fifo.clone();
                std::thread::spawn(move || {
                    // Blocks until strace opens the FIFO for writing.
                    match File::open(&fifo2) {
                        Ok(f) => {
                            let _ = std::fs::remove_file(&fifo2);
                            let mut r = BufReader::new(f);
                            let mut line = String::new();
                            loop {
                                line.clear();
                                match (&mut r).take(MAX_IPC_LINE_BYTES as u64).read_line(&mut line) {
                                    Ok(0) | Err(_) => break,
                                    Ok(_) => {
                                        if tx.send(TraceEvent::Line(line.clone())).is_err() {
                                            return;
                                        }
                                    }
                                }
                            }
                        }
                        Err(e) => log(format!("cannot open trace fifo: {e}")),
                    }
                    let _ = tx.send(TraceEvent::Eof);
                });
                trace = Some(Trace { rx, fifo: fifo.clone() });
                let mut c = Command::new(strace_bin);
                // -ttt: epoch timestamps, -T: time in syscall, -y: fd paths,
                // -s 64: string bytes shown, -qq: no attach/exit chatter.
                c.arg("-o")
                    .arg(&fifo)
                    .args(["-ttt", "-T", "-y", "-s", "64", "-qq", "--"]);
                c.arg(&cfg.runner_bin);
                c
            }
            None => Command::new(&cfg.runner_bin),
        };
        cmd.arg("--workspace")
            .arg(&cfg.workspace)
            .arg("--policy")
            .arg(&policy_json)
            .current_dir(&cfg.workspace)
            .stdin(Stdio::from(OwnedFd::from(theirs)))
            .stdout(Stdio::null())
            .stderr(Stdio::piped());
        let mut child = cmd.spawn().map_err(|e| format!("spawn runner: {e}"))?;

        let stderr_tail = Arc::new(Mutex::new(VecDeque::new()));
        if let Some(err) = child.stderr.take() {
            let tail = stderr_tail.clone();
            std::thread::spawn(move || {
                for line in BufReader::new(err).lines().map_while(Result::ok) {
                    log(format!("runner gen{generation}: {line}"));
                    if let Ok(mut t) = tail.lock() {
                        if t.len() >= 20 {
                            t.pop_front();
                        }
                        t.push_back(line);
                    }
                }
            });
        }

        let mut proc = RunnerProc {
            child,
            reader: BufReader::new(ours.try_clone().map_err(|e| e.to_string())?),
            sock: ours,
            trace,
            info: RunnerInfo {
                generation,
                pid: 0,
                arch: std::env::consts::ARCH.to_string(),
                policy: policy.clone(),
                seccomp: SeccompStatus {
                    mode: None,
                    filters: None,
                    sacredarts_filter_installed: false,
                },
                tracing: TracingStatus::Unavailable {
                    reason: "strace not used".into(),
                },
                seccomp_evidence: vec![],
            },
            next_id: 1,
            stderr_tail,
        };

        let hello: RunnerHello = match proc.read_line(STARTUP_TIMEOUT) {
            Ok(l) => match serde_json::from_str(&l) {
                Ok(h) => h,
                Err(e) => {
                    proc.kill();
                    return Err(format!("bad hello from runner: {e}"));
                }
            },
            Err(e) => {
                let why = match e {
                    ReqError::Timeout => "timed out waiting for runner".to_string(),
                    ReqError::Crashed(m) => m,
                };
                std::thread::sleep(Duration::from_millis(50));
                let tail = proc.stderr_text();
                proc.kill();
                return Err(format!("runner failed to start: {why}. stderr: {tail}"));
            }
        };
        proc.info.pid = hello.pid;
        proc.info.arch = hello.arch.clone();
        proc.info.seccomp = read_seccomp_status(hello.pid, hello.seccomp_filter_installed);
        if let Some(s) = &strace {
            proc.info.tracing = TracingStatus::Active {
                tool: "strace".into(),
                version: strace_version(s).unwrap_or_else(|| "unknown".into()),
            };
            proc.info.seccomp_evidence = proc.collect_startup();
        }
        RUNNER_PID.store(hello.pid, Ordering::SeqCst);
        CHILD_PID.store(proc.child.id() as i32, Ordering::SeqCst);
        Ok(proc)
    }

    fn stderr_text(&self) -> String {
        self.stderr_tail
            .lock()
            .map(|t| t.iter().cloned().collect::<Vec<_>>().join(" | "))
            .unwrap_or_default()
    }

    /// strace lines up to the `ready` marker that document seccomp set-up.
    fn collect_startup(&mut self) -> Vec<ObservedSyscall> {
        let Some(trace) = &self.trace else { return vec![] };
        let deadline = Instant::now() + OBSERVE_TIMEOUT;
        let lines = std::iter::from_fn(|| {
            match trace
                .rx
                .recv_timeout(deadline.saturating_duration_since(Instant::now()))
            {
                Ok(TraceEvent::Line(l)) => Some(parse_line(&l)),
                _ => None,
            }
        });
        lines
            .take(MAX_STARTUP_LINES)
            .take_while(|t| !matches!(t, TraceLine::Marker { kind, .. } if kind == "ready"))
            .filter_map(|t| match t {
                TraceLine::Syscall(s)
                    if s.syscall == "seccomp" || (s.syscall == "prctl" && s.args.contains("PR_SET_NO_NEW_PRIVS")) =>
                {
                    Some(s)
                }
                _ => None,
            })
            .collect()
    }

    fn read_line(&mut self, timeout: Duration) -> Result<String, ReqError> {
        self.sock
            .set_read_timeout(Some(timeout))
            .map_err(|e| ReqError::Crashed(format!("cannot set the IPC timeout: {e}")))?;
        let mut line = String::new();
        match (&mut self.reader).take(MAX_IPC_LINE_BYTES as u64).read_line(&mut line) {
            Ok(0) => Err(ReqError::Crashed("runner closed the connection".into())),
            Ok(_) if line.ends_with('\n') => Ok(line),
            Ok(_) => Err(ReqError::Crashed("runner sent an incomplete line".into())),
            Err(e) if matches!(e.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut) => Err(ReqError::Timeout),
            Err(e) => Err(ReqError::Crashed(format!("ipc error: {e}"))),
        }
    }

    fn request(&mut self, op: RunnerOp, timeout: Duration) -> Result<(u64, RunnerReplyBody), ReqError> {
        let id = self.next_id;
        self.next_id += 1;
        let s = serde_json::to_string(&RunnerRequest { id, op }).map_err(|e| ReqError::Crashed(e.to_string()))?;
        let mut w = &self.sock;
        w.write_all(s.as_bytes())
            .and_then(|_| w.write_all(b"\n"))
            .map_err(|e| ReqError::Crashed(format!("send to runner: {e}")))?;
        let line = self.read_line(timeout)?;
        let reply: RunnerReply =
            serde_json::from_str(&line).map_err(|e| ReqError::Crashed(format!("bad reply: {e}")))?;
        if reply.id != id {
            return Err(ReqError::Crashed(format!("reply id {} != request id {id}", reply.id)));
        }
        Ok((id, reply.body))
    }

    /// strace lines strictly between the `begin`/`end` markers of `id`.
    fn observe(&mut self, id: u64) -> Observation {
        let Some(trace) = &self.trace else {
            return Observation {
                status: ObservationStatus::Unavailable,
                syscalls: vec![],
                truncated: false,
            };
        };
        let deadline = Instant::now() + OBSERVE_TIMEOUT;
        let mut collecting = false;
        let mut out = Vec::new();
        let mut truncated = false;
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            match trace.rx.recv_timeout(left) {
                Ok(TraceEvent::Line(l)) => match parse_line(&l) {
                    TraceLine::Marker { kind, id: mid } if mid == id && kind == "begin" => collecting = true,
                    TraceLine::Marker { kind, id: mid } if mid == id && kind == "end" => {
                        return Observation {
                            status: ObservationStatus::Complete,
                            syscalls: out,
                            truncated,
                        };
                    }
                    TraceLine::Syscall(s) if collecting => {
                        if out.len() < MAX_OBSERVED_PER_REQUEST {
                            out.push(s);
                        } else {
                            truncated = true;
                        }
                    }
                    _ => {}
                },
                Ok(TraceEvent::Eof) | Err(RecvTimeoutError::Disconnected) | Err(RecvTimeoutError::Timeout) => {
                    return Observation {
                        status: ObservationStatus::Incomplete,
                        syscalls: out,
                        truncated,
                    };
                }
            }
        }
    }

    fn kill(&mut self) {
        kill_pid(self.info.pid);
        let _ = self.child.kill();
        let _ = self.child.wait();
        if let Some(t) = self.trace.take() {
            // If strace never opened the FIFO the reader thread is still blocked
            // in open(); opening the write side once releases it.
            let _ = OpenOptions::new()
                .write(true)
                .custom_flags(libc::O_NONBLOCK)
                .open(&t.fifo);
            let _ = std::fs::remove_file(&t.fifo);
        }
    }

    fn refresh_seccomp(&mut self) {
        self.info.seccomp = read_seccomp_status(self.info.pid, self.info.seccomp.sacredarts_filter_installed);
    }
}

pub struct Supervisor {
    cfg: Config,
    runner: Option<RunnerProc>,
    generation: u64,
    limits: SupervisorLimits,
    /// Once strace failed to start we stop retrying it for this container.
    strace_failure: Option<String>,
}

fn send(msg: &SupervisorMessage) {
    let s = serde_json::to_string(msg)
        .unwrap_or_else(|e| format!(r#"{{"type":"init_failed","message":"serialize: {e}"}}"#));
    let mut out = io::stdout().lock();
    if let Err(e) = writeln!(out, "{s}").and_then(|()| out.flush()) {
        // The host is gone; it will notice through the closed pipe.
        log(format!("cannot write to the host: {e}"));
    }
}

impl Supervisor {
    pub fn new(cfg: Config) -> Self {
        Supervisor {
            cfg,
            runner: None,
            generation: 0,
            limits: SupervisorLimits {
                request_timeout_ms: 5000,
                idle_timeout_secs: 900,
                max_lifetime_secs: 3600,
            },
            strace_failure: None,
        }
    }

    fn spawn_runner(&mut self, policy: &Policy) -> Result<RunnerProc, String> {
        self.generation += 1;
        let generation = self.generation;
        if self.cfg.strace_bin.is_some() && self.strace_failure.is_none() {
            match RunnerProc::spawn(&self.cfg, generation, policy, true) {
                Ok(p) => return Ok(p),
                Err(e) => {
                    log(format!("traced runner failed, retrying without strace: {e}"));
                    self.strace_failure = Some(e);
                }
            }
        }
        let mut p = RunnerProc::spawn(&self.cfg, generation, policy, false)?;
        p.info.tracing = TracingStatus::Unavailable {
            reason: self
                .strace_failure
                .clone()
                .unwrap_or_else(|| "strace binary not configured".into()),
        };
        Ok(p)
    }

    /// Replace a broken runner with a fresh one using the same policy.
    fn recover(&mut self, id: u64, kind: SupervisorErrorKind, message: String) -> SupervisorMessage {
        let policy = self.runner.as_ref().map(|r| r.info.policy.clone()).unwrap_or_default();
        if let Some(mut old) = self.runner.take() {
            old.kill();
        }
        match self.spawn_runner(&policy) {
            Ok(p) => {
                let info = p.info.clone();
                self.runner = Some(p);
                SupervisorMessage::Error {
                    id,
                    kind,
                    message,
                    state_reset: true,
                    runner: Some(info),
                }
            }
            Err(e) => SupervisorMessage::Error {
                id,
                kind: SupervisorErrorKind::RunnerUnavailable,
                message: format!("{message}; restarting the runner failed: {e}"),
                state_reset: true,
                runner: None,
            },
        }
    }

    fn handle(&mut self, msg: HostMessage) -> Option<SupervisorMessage> {
        let timeout = Duration::from_millis(self.limits.request_timeout_ms);
        Some(match msg {
            HostMessage::Init { policy, limits } => {
                self.limits = limits;
                if self.runner.is_some() {
                    return Some(SupervisorMessage::InitFailed {
                        message: "already initialised".into(),
                        kind: None,
                    });
                }
                if let Err(e) = sacredarts_policy::compile(&policy) {
                    return Some(SupervisorMessage::InitFailed {
                        message: e,
                        kind: Some(SupervisorErrorKind::InvalidPolicy),
                    });
                }
                match self.spawn_runner(&policy) {
                    Ok(p) => {
                        let runner = p.info.clone();
                        self.runner = Some(p);
                        SupervisorMessage::Ready { runner }
                    }
                    Err(e) => SupervisorMessage::InitFailed { message: e, kind: None },
                }
            }
            HostMessage::Invoke { id, request } => {
                let Some(r) = self.runner.as_mut() else {
                    return Some(self.recover(id, SupervisorErrorKind::RunnerCrashed, "no runner".into()));
                };
                match r.request(RunnerOp::Invoke { request }, timeout) {
                    Ok((rid, RunnerReplyBody::Invoked { outcome })) => {
                        let observation = r.observe(rid);
                        SupervisorMessage::Invoked {
                            id,
                            outcome,
                            observation,
                            runner_generation: r.info.generation,
                        }
                    }
                    Ok((_, other)) => SupervisorMessage::Error {
                        id,
                        kind: SupervisorErrorKind::Internal,
                        message: format!("unexpected runner reply: {other:?}"),
                        state_reset: false,
                        runner: None,
                    },
                    Err(ReqError::Timeout) => self.recover(
                        id,
                        SupervisorErrorKind::RunnerTimeout,
                        format!(
                            "the syscall did not complete within {} ms; the runner was killed and recreated",
                            timeout.as_millis()
                        ),
                    ),
                    Err(ReqError::Crashed(m)) => {
                        self.recover(id, SupervisorErrorKind::RunnerCrashed, format!("runner died: {m}"))
                    }
                }
            }
            HostMessage::Inspect { id } => {
                let Some(r) = self.runner.as_mut() else {
                    return Some(self.recover(id, SupervisorErrorKind::RunnerCrashed, "no runner".into()));
                };
                match r.request(RunnerOp::ListHandles, timeout) {
                    Ok((_, RunnerReplyBody::Handles { handles })) => {
                        r.refresh_seccomp();
                        SupervisorMessage::Inspected {
                            id,
                            info: InspectInfo {
                                runner: r.info.clone(),
                                handles,
                                cwd: self.cfg.workspace.display().to_string(),
                                workspace_entries: list_workspace(&self.cfg.workspace),
                            },
                        }
                    }
                    Ok((_, other)) => SupervisorMessage::Error {
                        id,
                        kind: SupervisorErrorKind::Internal,
                        message: format!("unexpected runner reply: {other:?}"),
                        state_reset: false,
                        runner: None,
                    },
                    Err(ReqError::Timeout) => {
                        self.recover(id, SupervisorErrorKind::RunnerTimeout, "runner did not answer".into())
                    }
                    Err(ReqError::Crashed(m)) => self.recover(id, SupervisorErrorKind::RunnerCrashed, m),
                }
            }
            HostMessage::SetPolicy { id, policy } => {
                // Check the policy before touching the current runner or strace.
                if let Err(e) = sacredarts_policy::compile(&policy) {
                    return Some(SupervisorMessage::Error {
                        id,
                        kind: SupervisorErrorKind::InvalidPolicy,
                        message: e,
                        state_reset: false,
                        runner: self.runner.as_ref().map(|r| r.info.clone()),
                    });
                }
                // Start the new runner first; only switch when it is healthy.
                match self.spawn_runner(&policy) {
                    Ok(mut new) => match new.request(RunnerOp::Ping, timeout) {
                        Ok((_, RunnerReplyBody::Pong)) => {
                            if let Some(mut old) = self.runner.replace(new) {
                                old.kill();
                            }
                            let runner = self.runner.as_ref().map(|r| r.info.clone())?;
                            SupervisorMessage::PolicyApplied { id, runner }
                        }
                        _ => {
                            new.kill();
                            SupervisorMessage::Error {
                                id,
                                kind: SupervisorErrorKind::PolicyApplyFailed,
                                message: "new runner failed its health check; previous runner kept".into(),
                                state_reset: false,
                                runner: self.runner.as_ref().map(|r| r.info.clone()),
                            }
                        }
                    },
                    Err(e) => SupervisorMessage::Error {
                        id,
                        kind: SupervisorErrorKind::PolicyApplyFailed,
                        message: format!("{e}; previous runner kept"),
                        state_reset: false,
                        runner: self.runner.as_ref().map(|r| r.info.clone()),
                    },
                }
            }
            HostMessage::Shutdown { id } => {
                self.shutdown();
                send(&SupervisorMessage::ShuttingDown { id });
                std::process::exit(0);
            }
        })
    }

    fn shutdown(&mut self) {
        if let Some(mut r) = self.runner.take() {
            r.kill();
        }
    }

    /// Main loop. Returns when the host closes stdin.
    pub fn run(mut self) -> i32 {
        let start = Instant::now();
        let last_activity = Arc::new(AtomicU64::new(0));
        let idle = Arc::new(AtomicU64::new(self.limits.idle_timeout_secs));
        let lifetime = Arc::new(AtomicU64::new(self.limits.max_lifetime_secs));
        {
            let (last, idle, lifetime) = (last_activity.clone(), idle.clone(), lifetime.clone());
            std::thread::spawn(move || {
                loop {
                    std::thread::sleep(Duration::from_secs(2));
                    let now = start.elapsed().as_secs();
                    let quiet = now.saturating_sub(last.load(Ordering::SeqCst));
                    if quiet > idle.load(Ordering::SeqCst) || now > lifetime.load(Ordering::SeqCst) {
                        log("idle timeout or maximum lifetime reached; exiting");
                        kill_pid(RUNNER_PID.load(Ordering::SeqCst));
                        kill_pid(CHILD_PID.load(Ordering::SeqCst));
                        std::process::exit(0);
                    }
                }
            });
        }
        let stdin = io::stdin();
        let mut input = stdin.lock();
        let mut line = String::new();
        loop {
            line.clear();
            match (&mut input).take(MAX_IPC_LINE_BYTES as u64).read_line(&mut line) {
                Ok(0) => break,
                Ok(_) => {}
                Err(e) => {
                    log(format!("stdin error: {e}"));
                    break;
                }
            }
            last_activity.store(start.elapsed().as_secs(), Ordering::SeqCst);
            let msg: HostMessage = match serde_json::from_str(line.trim()) {
                Ok(m) => m,
                Err(e) => {
                    log(format!("ignoring malformed host message: {e}"));
                    continue;
                }
            };
            if let HostMessage::Init { limits, .. } = &msg {
                idle.store(limits.idle_timeout_secs, Ordering::SeqCst);
                lifetime.store(limits.max_lifetime_secs, Ordering::SeqCst);
            }
            if let Some(reply) = self.handle(msg) {
                send(&reply);
            }
            last_activity.store(start.elapsed().as_secs(), Ordering::SeqCst);
        }
        log("host closed the connection; shutting down");
        self.shutdown();
        0
    }
}

fn list_workspace(dir: &Path) -> Vec<WorkspaceEntry> {
    let Ok(rd) = std::fs::read_dir(dir) else { return vec![] };
    let mut v: Vec<WorkspaceEntry> = rd
        .filter_map(Result::ok)
        .take(200)
        .filter_map(|e| {
            let md = e.path().symlink_metadata().ok()?;
            let ft = md.file_type();
            let kind = if ft.is_symlink() {
                "symlink"
            } else if ft.is_dir() {
                "directory"
            } else if ft.is_file() {
                "file"
            } else {
                "other"
            };
            Some(WorkspaceEntry {
                name: e.file_name().to_string_lossy().into_owned(),
                kind: kind.into(),
                size: md.len(),
            })
        })
        .collect();
    v.sort_by(|a, b| a.name.cmp(&b.name));
    v
}
