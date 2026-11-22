//! Session manager: one session = one Docker container = one supervisor.
//!
//! Concurrency: each session has a tokio mutex around its state, so tool
//! calls on the same session are serialised (the runner handles one request
//! at a time) while different sessions run in parallel. Destroy does not wait
//! for that mutex: it removes the session from the map and force-removes the
//! container, which makes any in-flight call fail cleanly.

use crate::config::Config;
use crate::docker::{Docker, SupervisorConn};
use crate::errors::{ErrorKind, ToolError};
use crate::store::{self, EventKind, EventStore, SyscallEvent};
use sacredarts_core::ipc::*;
use sacredarts_core::{GuideLevel, Policy, SyscallRequest, TraceMode};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use uuid::Uuid;

pub struct SessionState {
    conn: Option<SupervisorConn>,
    pub dead_reason: Option<String>,
    pub guide_level: GuideLevel,
    pub trace_mode: TraceMode,
    pub policy: Policy,
    pub runner: RunnerInfo,
    pub events: EventStore,
    next_msg: u64,
    next_request: u64,
}

pub struct Session {
    pub id: String,
    pub container: String,
    pub created_at: String,
    created: Instant,
    last_used: Mutex<Instant>,
    pub state: tokio::sync::Mutex<SessionState>,
}

impl Session {
    fn touch(&self) {
        if let Ok(mut t) = self.last_used.lock() {
            *t = Instant::now();
        }
    }

    pub fn idle_for(&self) -> Duration {
        self.last_used.lock().map(|t| t.elapsed()).unwrap_or_default()
    }

    pub fn age(&self) -> Duration {
        self.created.elapsed()
    }
}

struct Registry {
    sessions: HashMap<String, Arc<Session>>,
    /// Creations in progress (counted against max_sessions).
    pending: usize,
}

pub struct Manager {
    pub cfg: Config,
    pub docker: Docker,
    reg: Mutex<Registry>,
}

/// Outcome of `invoke` as seen by the tool layer.
pub struct Invoked {
    pub request_id: String,
    pub event_id: u64,
    pub observed_event_ids: Vec<u64>,
    pub outcome: InvokeOutcome,
    pub observation: Observation,
    pub runner: RunnerInfo,
    pub guide_level: GuideLevel,
    pub trace_mode: TraceMode,
    pub policy: Policy,
}

struct Reservation<'a>(&'a Manager);

impl Drop for Reservation<'_> {
    fn drop(&mut self) {
        if let Ok(mut r) = self.0.reg.lock() {
            r.pending = r.pending.saturating_sub(1);
        }
    }
}

fn lifecycle(event: &str, details: Value) -> SyscallEvent {
    SyscallEvent {
        event_id: 0,
        kind: EventKind::Lifecycle,
        source: "sacredarts",
        request_id: None,
        timestamp: store::now(),
        syscall: None,
        arguments: Value::Null,
        return_value: Value::Null,
        errno: None,
        duration_ns: None,
        process: None,
        details: json!({ "event": event, "info": details }),
        formatted: format!("[{event}]"),
    }
}

fn runner_summary(r: &RunnerInfo) -> Value {
    json!({
        "generation": r.generation,
        "pid": r.pid,
        "policy": r.policy,
        "seccomp": r.seccomp,
        "tracing": r.tracing,
    })
}

impl Manager {
    pub fn new(cfg: Config) -> Arc<Self> {
        Arc::new(Manager {
            docker: Docker::new(cfg.clone()),
            cfg,
            reg: Mutex::new(Registry {
                sessions: HashMap::new(),
                pending: 0,
            }),
        })
    }

    fn limits(&self) -> SupervisorLimits {
        SupervisorLimits {
            request_timeout_ms: self.cfg.request_timeout.as_millis() as u64,
            // The supervisor's own watchdog is a backstop slightly behind ours.
            // u64::MAX = no limit
            idle_timeout_secs: self
                .cfg
                .idle_timeout
                .map_or(u64::MAX, |d| d.as_secs().saturating_add(60)),
            max_lifetime_secs: self
                .cfg
                .max_lifetime
                .map_or(u64::MAX, |d| d.as_secs().saturating_add(60)),
        }
    }

    fn ipc_timeout(&self) -> Duration {
        // Covers the in-sandbox timeout plus a runner restart.
        self.cfg.request_timeout + self.cfg.ipc_margin
    }

    pub fn get(&self, id: &str) -> Result<Arc<Session>, ToolError> {
        self.reg
            .lock()
            .ok()
            .and_then(|r| r.sessions.get(id).cloned())
            .ok_or_else(|| ToolError::not_found(id))
    }

    pub fn ids(&self) -> Vec<String> {
        self.reg
            .lock()
            .map(|r| r.sessions.keys().cloned().collect())
            .unwrap_or_default()
    }

    fn reserve(&self) -> Result<Reservation<'_>, ToolError> {
        let mut r = self
            .reg
            .lock()
            .map_err(|_| ToolError::infra("internal", "registry poisoned"))?;
        if r.sessions.len() + r.pending >= self.cfg.max_sessions {
            return Err(ToolError::new(
                ErrorKind::LimitExceeded,
                "too_many_sessions",
                format!(
                    "at most {} sandboxes may exist at once; destroy one with sandbox_destroy first",
                    self.cfg.max_sessions
                ),
            )
            .details(json!({ "active_sessions": r.sessions.keys().collect::<Vec<_>>() })));
        }
        r.pending += 1;
        Ok(Reservation(self))
    }

    pub async fn create(
        &self,
        guide_level: GuideLevel,
        trace_mode: TraceMode,
        policy: Policy,
    ) -> Result<Arc<Session>, ToolError> {
        let _slot = self.reserve()?;
        self.docker.preflight().await?;
        let id = Uuid::new_v4().to_string();
        let container = format!("sacredarts-{}", &id[..8]);
        let mut conn = self.docker.spawn_sandbox(&container, &id).await?;
        let started = async {
            conn.send(&HostMessage::Init {
                policy: policy.clone(),
                limits: self.limits(),
            })
            .await?;
            match conn.recv(self.cfg.startup_timeout).await? {
                SupervisorMessage::Ready { runner } => Ok(runner),
                SupervisorMessage::InitFailed {
                    message,
                    kind: Some(SupervisorErrorKind::InvalidPolicy),
                } => Err(ToolError::new(ErrorKind::InvalidArgument, "invalid_policy", message)),
                SupervisorMessage::InitFailed { message, .. } => Err(ToolError::infra(
                    "runner_start_failed",
                    format!("the sandbox could not start the runner: {message}"),
                )),
                other => Err(ToolError::infra(
                    "ipc_failed",
                    format!("unexpected first message: {other:?}"),
                )),
            }
        }
        .await;
        let runner = match started {
            Ok(r) => r,
            Err(e) => {
                conn.kill().await;
                self.docker.remove(&container).await;
                return Err(e);
            }
        };
        let mut events = EventStore::new(self.cfg.events_per_session);
        events.push(lifecycle(
            "sandbox_created",
            json!({ "container": container, "image": self.cfg.image, "runner": runner_summary(&runner) }),
        ));
        let session = Arc::new(Session {
            id: id.clone(),
            container,
            created_at: store::now(),
            created: Instant::now(),
            last_used: Mutex::new(Instant::now()),
            state: tokio::sync::Mutex::new(SessionState {
                conn: Some(conn),
                dead_reason: None,
                guide_level,
                trace_mode,
                policy,
                runner,
                events,
                next_msg: 1,
                next_request: 1,
            }),
        });
        let mut r = self
            .reg
            .lock()
            .map_err(|_| ToolError::infra("internal", "registry poisoned"))?;
        r.sessions.insert(id, session.clone());
        Ok(session)
    }

    /// Idempotent. Returns whether a live session was found.
    pub async fn destroy(&self, id: &str) -> bool {
        let s = self.reg.lock().ok().and_then(|mut r| r.sessions.remove(id));
        let Some(s) = s else { return false };
        // Ask politely if the session is idle; never wait on a busy one.
        if let Ok(mut st) = s.state.try_lock() {
            let n = st.next_msg;
            if let Some(conn) = st.conn.as_mut() {
                let _ = conn
                    .call(&HostMessage::Shutdown { id: n }, n, Duration::from_secs(3))
                    .await;
            }
            if let Some(mut c) = st.conn.take() {
                c.kill().await;
            }
            st.dead_reason = Some("destroyed".into());
        }
        // Force removal covers busy/hung sandboxes and is a no-op otherwise.
        self.docker.remove(&s.container).await;
        true
    }

    pub async fn destroy_all(&self) {
        for id in self.ids() {
            self.destroy(&id).await;
        }
    }

    /// Mark a session unusable after an infrastructure failure and clean up.
    async fn bury(&self, s: &Session, st: &mut SessionState, why: &ToolError) {
        st.dead_reason = Some(why.message.clone());
        if let Some(mut c) = st.conn.take() {
            c.kill().await;
        }
        if let Ok(mut r) = self.reg.lock() {
            r.sessions.remove(&s.id);
        }
        self.docker.remove(&s.container).await;
    }

    async fn call(
        &self,
        s: &Session,
        st: &mut SessionState,
        make: impl FnOnce(u64) -> HostMessage,
    ) -> Result<SupervisorMessage, ToolError> {
        s.touch();
        if let Some(r) = &st.dead_reason {
            return Err(ToolError::infra(
                "sandbox_terminated",
                format!("this sandbox is no longer usable ({r}); create a new one"),
            ));
        }
        let id = st.next_msg;
        st.next_msg += 1;
        let timeout = self.ipc_timeout();
        let res = match st.conn.as_mut() {
            Some(c) => c.call(&make(id), id, timeout).await,
            None => Err(ToolError::infra("sandbox_terminated", "sandbox connection is closed")),
        };
        s.touch();
        match res {
            Ok(m) => Ok(m),
            Err(e) => {
                tracing::warn!(session = %s.id, "sandbox failure: {e}");
                self.bury(s, st, &e).await;
                let mut e = e;
                e.message
                    .push_str(" (the sandbox was destroyed; create a new one with sandbox_create)");
                Err(e)
            }
        }
    }

    /// Convert a supervisor-side error into a tool error, updating state.
    fn supervisor_error(
        st: &mut SessionState,
        kind: SupervisorErrorKind,
        message: String,
        state_reset: bool,
        runner: Option<RunnerInfo>,
    ) -> ToolError {
        if let Some(r) = runner.clone() {
            st.runner = r;
        }
        st.events.push(lifecycle(
            "runner_error",
            json!({ "kind": kind, "message": message, "state_reset": state_reset, "runner": runner.as_ref().map(runner_summary) }),
        ));
        let (ek, code) = match kind {
            SupervisorErrorKind::RunnerTimeout => (ErrorKind::Timeout, "syscall_timeout"),
            SupervisorErrorKind::RunnerCrashed => (ErrorKind::Infrastructure, "runner_crashed"),
            SupervisorErrorKind::InvalidPolicy => (ErrorKind::InvalidArgument, "invalid_policy"),
            SupervisorErrorKind::PolicyApplyFailed => (ErrorKind::Infrastructure, "policy_apply_failed"),
            SupervisorErrorKind::RunnerUnavailable => (ErrorKind::Infrastructure, "runner_unavailable"),
            SupervisorErrorKind::Internal => (ErrorKind::Infrastructure, "internal"),
        };
        if kind == SupervisorErrorKind::RunnerUnavailable {
            st.dead_reason = Some(message.clone());
        }
        ToolError::new(ek, code, message).details(json!({
            "state_reset": state_reset,
            "runner": runner.as_ref().map(runner_summary),
        }))
    }

    pub async fn invoke(&self, id: &str, request: SyscallRequest, requested_args: Value) -> Result<Invoked, ToolError> {
        let s = self.get(id)?;
        let mut st = s.state.lock().await;
        let request_id = format!("req-{}", st.next_request);
        st.next_request += 1;
        let req2 = request.clone();
        let msg = self
            .call(&s, &mut st, |n| HostMessage::Invoke { id: n, request: req2 })
            .await?;
        let (outcome, observation, generation) = match msg {
            SupervisorMessage::Invoked {
                outcome,
                observation,
                runner_generation,
                ..
            } => (outcome, observation, runner_generation),
            SupervisorMessage::Error {
                kind,
                message,
                state_reset,
                runner,
                ..
            } => {
                let mut e = Self::supervisor_error(&mut st, kind, message, state_reset, runner);
                // record that the AI asked for it
                st.events.push(SyscallEvent {
                    event_id: 0,
                    kind: EventKind::Requested,
                    source: "ai_request",
                    request_id: Some(request_id.clone()),
                    timestamp: store::now(),
                    syscall: Some(request.name().to_string()),
                    arguments: requested_args,
                    return_value: Value::Null,
                    errno: None,
                    duration_ns: None,
                    process: None,
                    details: json!({ "status": "failed", "error": e.code }),
                    formatted: format!("{} -> {}", sacredarts_core::format::format_call(&request, None), e.code),
                });
                if let Some(d) = e.details.as_mut() {
                    d["request_id"] = json!(request_id);
                }
                return Err(e);
            }
            other => return Err(ToolError::infra("ipc_failed", format!("unexpected reply: {other:?}"))),
        };
        debug_assert_eq!(generation, st.runner.generation);

        // Requested event
        let (formatted, ret, errno, details) = match &outcome {
            InvokeOutcome::Completed {
                requested_executed,
                ret,
                errno,
                issued,
                handle_change,
                read_data_b64,
                notes,
            } => {
                let ai_ret = match (handle_change, errno) {
                    (Some(HandleChange::Opened { info }), None) => info.handle as i64,
                    _ => *ret,
                };
                let data = read_data_b64.as_deref().and_then(|b| {
                    use base64::Engine;
                    base64::engine::general_purpose::STANDARD.decode(b).ok()
                });
                let line = sacredarts_core::format::format_call(&request, data.as_deref())
                    + &sacredarts_core::format::format_result(
                        ai_ret,
                        errno.as_ref().map(|e| (e.name.as_str(), e.message.as_str())),
                    );
                (
                    line,
                    json!(ai_ret),
                    errno.as_ref().map(|e| e.name.clone()),
                    json!({
                        "status": "completed",
                        "requested_syscall_executed": requested_executed,
                        "kernel_return_value": ret,
                        "handle_change": handle_change,
                        "runner_issued": issued,
                        "notes": notes,
                    }),
                )
            }
            InvokeOutcome::Rejected { code, message } => (
                format!(
                    "{} -> rejected ({code})",
                    sacredarts_core::format::format_call(&request, None)
                ),
                Value::Null,
                None,
                json!({ "status": "rejected", "code": code, "message": message }),
            ),
        };
        let event_id = st.events.push(SyscallEvent {
            event_id: 0,
            kind: EventKind::Requested,
            source: "ai_request",
            request_id: Some(request_id.clone()),
            timestamp: store::now(),
            syscall: Some(request.name().to_string()),
            arguments: requested_args,
            return_value: ret,
            errno,
            duration_ns: None,
            process: None,
            details,
            formatted,
        });

        // Observed events (strace)
        let pid = st.runner.pid;
        let mut observed_event_ids = Vec::new();
        for o in &observation.syscalls {
            let mut line = format!("{}({}) = {}", o.syscall, o.args, o.return_raw);
            if let Some(d) = o.duration_ns {
                line.push_str(&format!(" <{:.6}>", d as f64 / 1e9));
            }
            let eid = st.events.push(SyscallEvent {
                event_id: 0,
                kind: EventKind::Observed,
                source: "strace",
                request_id: Some(request_id.clone()),
                timestamp: o.timestamp_epoch.and_then(store::from_epoch).unwrap_or_else(store::now),
                syscall: Some(o.syscall.clone()),
                arguments: json!({ "raw": o.args }),
                return_value: json!({ "raw": o.return_raw, "value": o.ret }),
                errno: o.errno.clone(),
                duration_ns: o.duration_ns,
                process: Some(json!({ "pid": pid, "role": "runner", "pid_namespace": "container" })),
                details: json!({ "errno_message": o.errno_message, "strace_line": o.raw }),
                formatted: line,
            });
            observed_event_ids.push(eid);
        }
        Ok(Invoked {
            request_id,
            event_id,
            observed_event_ids,
            outcome,
            observation,
            runner: st.runner.clone(),
            guide_level: st.guide_level,
            trace_mode: st.trace_mode,
            policy: st.policy.clone(),
        })
    }

    pub async fn inspect(&self, id: &str) -> Result<(InspectInfo, Value), ToolError> {
        let s = self.get(id)?;
        let mut st = s.state.lock().await;
        let msg = self.call(&s, &mut st, |n| HostMessage::Inspect { id: n }).await?;
        match msg {
            SupervisorMessage::Inspected { info, .. } => {
                st.runner = info.runner.clone();
                let meta = json!({
                    "session_id": s.id,
                    "container": s.container,
                    "created_at": s.created_at,
                    "idle_seconds": s.idle_for().as_secs(),
                    "idle_timeout_seconds": self.cfg.idle_timeout.map(|d| d.as_secs()),
                    "max_lifetime_seconds": self.cfg.max_lifetime.map(|d| d.as_secs()),
                    "guide_level": st.guide_level,
                    "trace_mode": st.trace_mode,
                    "policy": st.policy,
                    "event_count": st.events.len(),
                    "requested_event_count": st.events.count_kind(EventKind::Requested),
                    "observed_event_count": st.events.count_kind(EventKind::Observed),
                });
                Ok((info, meta))
            }
            SupervisorMessage::Error {
                kind,
                message,
                state_reset,
                runner,
                ..
            } => Err(Self::supervisor_error(&mut st, kind, message, state_reset, runner)),
            other => Err(ToolError::infra("ipc_failed", format!("unexpected reply: {other:?}"))),
        }
    }

    pub async fn set_policy(&self, id: &str, policy: Policy) -> Result<(Policy, RunnerInfo, RunnerInfo), ToolError> {
        let s = self.get(id)?;
        let mut st = s.state.lock().await;
        let old_runner = st.runner.clone();
        let old_policy = st.policy.clone();
        let p2 = policy.clone();
        let msg = self
            .call(&s, &mut st, |n| HostMessage::SetPolicy { id: n, policy: p2 })
            .await?;
        match msg {
            SupervisorMessage::PolicyApplied { runner, .. } => {
                // Commit only after the supervisor confirmed the switch.
                st.policy = policy;
                st.runner = runner.clone();
                let new_policy = st.policy.clone();
                st.events.push(lifecycle(
                    "policy_applied",
                    json!({
                        "old_policy": old_policy,
                        "new_policy": new_policy,
                        "state_reset": true,
                        "old_runner": runner_summary(&old_runner),
                        "new_runner": runner_summary(&runner),
                    }),
                ));
                Ok((old_policy, old_runner, runner))
            }
            SupervisorMessage::Error {
                kind,
                message,
                state_reset,
                runner,
                ..
            } => {
                let mut e = Self::supervisor_error(&mut st, kind, message, state_reset, runner);
                if let Some(d) = e.details.as_mut() {
                    d["policy_unchanged"] = json!(true);
                    d["current_policy"] = json!(st.policy);
                }
                Err(e)
            }
            other => Err(ToolError::infra("ipc_failed", format!("unexpected reply: {other:?}"))),
        }
    }

    pub async fn set_guide(
        &self,
        id: &str,
        level: GuideLevel,
        trace_mode: Option<TraceMode>,
    ) -> Result<(GuideLevel, TraceMode, RunnerInfo), ToolError> {
        let s = self.get(id)?;
        s.touch();
        let mut st = s.state.lock().await;
        if let Some(r) = &st.dead_reason {
            return Err(ToolError::infra(
                "sandbox_terminated",
                format!("this sandbox is no longer usable ({r})"),
            ));
        }
        let old = (st.guide_level, st.trace_mode);
        st.guide_level = level;
        if let Some(t) = trace_mode {
            st.trace_mode = t;
        }
        let new = (st.guide_level, st.trace_mode);
        st.events.push(lifecycle(
            "guide_changed",
            json!({ "old": { "guide_level": old.0, "trace_mode": old.1 }, "new": { "guide_level": new.0, "trace_mode": new.1 }, "runner_recreated": false }),
        ));
        Ok((st.guide_level, st.trace_mode, st.runner.clone()))
    }

    /// Destroy sessions that are idle or too old.
    pub async fn reap(&self) {
        let victims: Vec<(String, &'static str)> = self
            .reg
            .lock()
            .map(|r| {
                r.sessions
                    .values()
                    .filter_map(|s| {
                        if self.cfg.idle_timeout.is_some_and(|t| s.idle_for() > t) {
                            Some((s.id.clone(), "idle timeout"))
                        } else if self.cfg.max_lifetime.is_some_and(|t| s.age() > t) {
                            Some((s.id.clone(), "maximum lifetime"))
                        } else {
                            None
                        }
                    })
                    .collect()
            })
            .unwrap_or_default();
        for (id, why) in victims {
            tracing::info!(session = %id, "destroying sandbox: {why}");
            self.destroy(&id).await;
        }
    }

    /// Remove SacredArts containers whose owning MCP server process is gone.
    pub async fn cleanup_orphans(&self) -> Result<Vec<String>, ToolError> {
        let me = std::process::id() as i32;
        let mine: Vec<String> = self
            .reg
            .lock()
            .map(|r| r.sessions.values().map(|s| s.container.clone()).collect())
            .unwrap_or_default();
        let mut removed = Vec::new();
        for (name, owner) in self.docker.list_managed().await? {
            let orphan = match owner {
                Some(pid) if pid == me => !mine.contains(&name),
                Some(pid) => !process_alive(pid),
                None => true,
            };
            if orphan {
                self.docker.remove(&name).await;
                removed.push(name);
            }
        }
        Ok(removed)
    }
}

fn process_alive(pid: i32) -> bool {
    if pid <= 0 {
        return false;
    }
    // SAFETY: signal 0 only checks for existence/permission; nothing is sent.
    let r = unsafe { libc::kill(pid, 0) };
    r == 0 || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}
