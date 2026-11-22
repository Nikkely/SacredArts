//! MCP tool definitions.

use crate::errors::{ErrorKind, ToolError};
use crate::session::{Invoked, Manager};
use base64::Engine;
use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{CallToolResult, ContentBlock, Implementation, ServerCapabilities, ServerConfig};
use rmcp::{ErrorData as McpError, ServerHandler, schemars, tool, tool_handler, tool_router};
use sacredarts_core::ipc::{HandleChange, InvokeOutcome, ObservationStatus};
use sacredarts_core::{GuideLevel, Policy, SyscallName, SyscallRequest, TraceMode};
use sacredarts_guide::{Guides, InvocationView, render_describe, render_invocation};
use serde::Deserialize;
use serde_json::{Map, Value, json};
use std::sync::Arc;

#[derive(Debug, Clone, Copy, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum TraceModeParam {
    /// Show only the operations the AI requested.
    Requested,
    /// Also show every syscall strace observed for each request.
    All,
}

impl From<TraceModeParam> for TraceMode {
    fn from(t: TraceModeParam) -> Self {
        match t {
            TraceModeParam::Requested => TraceMode::Requested,
            TraceModeParam::All => TraceMode::All,
        }
    }
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct PolicyParam {
    /// Syscalls to deny with seccomp (subset of: getpid, openat, read, write, close, mkdirat).
    #[serde(default)]
    pub deny: Vec<String>,
    /// errno name returned for denied syscalls, e.g. EPERM (default), ENOSYS, EIO; any errno name Linux defines.
    pub errno: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct SandboxCreateParams {
    /// Explanation detail: 1 = syscall lines only (default), 2 = + short explanation, 3 = + signature, arguments, errno, internals.
    pub guide_level: Option<u8>,
    /// "requested" (default) or "all" (also show strace-observed kernel syscalls).
    pub trace_mode: Option<TraceModeParam>,
    /// Initial seccomp deny policy.
    pub policy: Option<PolicyParam>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct SyscallInvokeParams {
    /// Session returned by sandbox_create.
    pub session_id: String,
    /// One of: getpid, openat, read, write, close, mkdirat.
    pub name: String,
    /// Syscall arguments (see the tool description for each syscall).
    pub args: Option<Map<String, Value>>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct SyscallDescribeParams {
    /// Syscall name: getpid, openat, read, write, close, mkdirat, or open (description only).
    pub name: String,
    /// 1-3 (default 1).
    pub guide_level: Option<u8>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct TraceGetParams {
    pub session_id: String,
    /// Maximum events to return (1-500, default 50).
    pub limit: Option<u32>,
    /// Return events with event_id greater than this (paging cursor; default 0).
    pub after_event_id: Option<u64>,
    /// Override the session trace mode for this query: "requested" hides strace-observed events.
    pub trace_mode: Option<TraceModeParam>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct PolicySetParams {
    pub session_id: String,
    /// Syscalls to deny (empty list removes all restrictions).
    pub deny: Vec<String>,
    /// errno name for denied syscalls: EPERM (default) or any other errno name (ENOSYS, EIO, ...).
    pub errno: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct SessionParams {
    pub session_id: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct SessionSetGuideParams {
    pub session_id: String,
    /// 1, 2 or 3.
    pub guide_level: u8,
    /// Optionally change the trace mode as well.
    pub trace_mode: Option<TraceModeParam>,
}

fn opt<T: std::fmt::Display>(v: Option<T>) -> String {
    v.map(|x| x.to_string()).unwrap_or_else(|| "unknown".into())
}

fn ok(text: String, value: Value) -> CallToolResult {
    let mut r = CallToolResult::structured(value.clone());
    r.content = vec![
        ContentBlock::text(text),
        ContentBlock::text(serde_json::to_string_pretty(&value).unwrap_or_default()),
    ];
    r
}

fn err(e: ToolError) -> CallToolResult {
    let v = json!({ "error": e });
    let kind = serde_json::to_value(e.kind)
        .ok()
        .and_then(|v| v.as_str().map(String::from))
        .unwrap_or_default();
    let mut r = CallToolResult::structured_error(v.clone());
    r.content = vec![
        ContentBlock::text(format!("Error [{kind}/{}]: {}", e.code, e.message)),
        ContentBlock::text(serde_json::to_string_pretty(&v).unwrap_or_default()),
    ];
    r
}

fn level(v: Option<u8>) -> Result<GuideLevel, ToolError> {
    GuideLevel::try_from(v.unwrap_or(1)).map_err(|m| {
        ToolError::new(ErrorKind::InvalidArgument, "invalid_guide_level", m).details(json!({"field": "guide_level"}))
    })
}

fn policy(deny: &[String], errno: Option<&str>) -> Result<Policy, ToolError> {
    Policy::from_user(deny, errno).map_err(ToolError::from_validation)
}

/// Requested arguments as recorded in the event log (large data truncated).
fn recorded_args(req: &SyscallRequest, raw: &Value) -> Value {
    match req {
        SyscallRequest::Write { fd, data, count } => json!({
            "fd": fd,
            "count": count,
            "data_length": data.len(),
            "data_preview": sacredarts_core::format::quote_bytes(&data[..*count], 64),
        }),
        _ => raw.clone(),
    }
}

#[derive(Clone)]
pub struct SacredArts {
    tool_router: ToolRouter<Self>,
    mgr: Arc<Manager>,
}

const INVOKE_DESCRIPTION: &str = r#"Follow the activation rule in the SacredArts server instructions (use only after the user's incantation "System Call" / "システムコール").
Execute one Linux system call inside the sandbox and return the result (strace-like line, return value, errno, guide).
State (open fds) persists between calls of the same session.
Arguments are passed to the kernel verbatim and the kernel decides (EBADF, EMFILE, ENAMETOOLONG, EACCES, EROFS, ...):
- getpid: {}
- openat: {"dirfd"?: "AT_FDCWD" | <fd>, "path": any path, "flags"?: ["O_WRONLY","O_CREAT",...] | "O_WRONLY|O_CREAT|0x80000" | <int> (default O_RDONLY), "mode"?: "0644" | <int> (0 if omitted)}
  flags: every Linux O_* name (O_RDONLY O_WRONLY O_RDWR O_CREAT O_EXCL O_NOCTTY O_TRUNC O_APPEND O_NONBLOCK O_NDELAY O_DSYNC O_SYNC O_RSYNC O_ASYNC O_DIRECT O_LARGEFILE O_DIRECTORY O_NOFOLLOW O_NOATIME O_CLOEXEC O_PATH O_TMPFILE) and/or numbers.
  Returns the real kernel fd (fds 0-2 are /dev/null and the runner's stderr, so the first file is usually 3).
- read: {"fd": <int>, "count": <0..65536>}  -> data_text (if UTF-8) and data_base64
- write: {"fd": <int>, "data": "...", "encoding"?: "utf8"|"base64", "count"?: <bytes, default all>}
- close: {"fd": <int>}
- mkdirat: {"dirfd"?: "AT_FDCWD" | <fd>, "path": "...", "mode"?: "0755" | <int>}
Any fd number may be used except the runner's own socket to the supervisor (rejected as reserved_fd). RLIMIT_NOFILE is 256. cwd is /workspace; the container is non-root with a read-only root filesystem (/workspace and /tmp are writable). A failing syscall (errno) is a normal result with success=false; tool errors are only for arguments that cannot be marshalled or infrastructure problems."#;

#[tool_router(router = tool_router)]
impl SacredArts {
    pub fn new(mgr: Arc<Manager>) -> Self {
        SacredArts {
            tool_router: Self::tool_router(),
            mgr,
        }
    }

    #[tool(
        description = "Create a Linux sandbox (one Docker container) with a resident syscall runner traced by strace. Returns session_id. Options: guide_level 1-3, trace_mode requested|all, policy {deny: [...], errno}. Follow the activation rule in the SacredArts server instructions (use only after the user's incantation \"System Call\" / \"システムコール\")."
    )]
    async fn sandbox_create(&self, params: Parameters<SandboxCreateParams>) -> Result<CallToolResult, McpError> {
        let p = params.0;
        let g = match level(p.guide_level) {
            Ok(g) => g,
            Err(e) => return Ok(err(e)),
        };
        let pol = match &p.policy {
            Some(x) => match policy(&x.deny, x.errno.as_deref()) {
                Ok(v) => v,
                Err(e) => return Ok(err(e)),
            },
            None => Policy::default(),
        };
        let tm: TraceMode = p.trace_mode.map(Into::into).unwrap_or_default();
        let s = match self.mgr.create(g, tm, pol.clone()).await {
            Ok(s) => s,
            Err(e) => return Ok(err(e)),
        };
        let st = s.state.lock().await;
        let r = &st.runner;
        let v = json!({
            "session_id": s.id,
            "status": "ready",
            "architecture": r.arch,
            "guide_level": g,
            "trace_mode": tm,
            "policy": pol,
            "workspace": sacredarts_core::limits::WORKSPACE_ROOT,
            "container": s.container,
            "runner": { "pid": r.pid, "generation": r.generation, "pid_namespace": "container" },
            "tracing": r.tracing,
            "seccomp": r.seccomp,
            "seccomp_evidence": r.seccomp_evidence.iter().map(|e| &e.raw).collect::<Vec<_>>(),
        });
        let text = format!(
            "Sandbox ready: session_id={} arch={} guide_level={} trace_mode={:?} policy.deny={:?}\nworkspace: /workspace (cwd), runner pid {} (container PID namespace)",
            s.id,
            r.arch,
            g.as_u8(),
            tm,
            pol.deny.iter().map(|n| n.as_str()).collect::<Vec<_>>(),
            r.pid
        );
        Ok(ok(text, v))
    }

    #[tool(description = INVOKE_DESCRIPTION)]
    async fn syscall_invoke(&self, params: Parameters<SyscallInvokeParams>) -> Result<CallToolResult, McpError> {
        let p = params.0;
        let raw = Value::Object(p.args.unwrap_or_default());
        let req = match SyscallRequest::from_user(&p.name, &raw) {
            Ok(r) => r,
            Err(v) => return Ok(err(ToolError::from_validation(v))),
        };
        let inv = match self
            .mgr
            .invoke(&p.session_id, req.clone(), recorded_args(&req, &raw))
            .await
        {
            Ok(i) => i,
            Err(e) => return Ok(err(e)),
        };
        Ok(render_invoked(&p.session_id, &req, inv))
    }

    #[tool(
        description = "Describe a syscall from structured guide data (Linux man-pages based). Works without a sandbox. Includes `open` (description only) to explain open vs openat. Follow the activation rule in the SacredArts server instructions (use only after the user's incantation \"System Call\" / \"システムコール\")."
    )]
    async fn syscall_describe(&self, params: Parameters<SyscallDescribeParams>) -> Result<CallToolResult, McpError> {
        let p = params.0;
        let g = match level(p.guide_level) {
            Ok(g) => g,
            Err(e) => return Ok(err(e)),
        };
        let guides = Guides::builtin();
        let Some(guide) = guides.get(&p.name) else {
            return Ok(err(ToolError::new(
                ErrorKind::UnsupportedSyscall,
                "unknown_syscall",
                format!("no guide for {:?}; available: {}", p.name, guides.names().join(", ")),
            )));
        };
        let text = render_describe(guide, g);
        let mut v = json!({
            "name": guide.name,
            "executable": guide.executable,
            "category": guide.category,
            "summary": guide.summary,
            "signature": guide.signature.trim(),
            "guide_level": g,
            "related": guide.related,
            "man_pages": guide.man_pages,
        });
        if g >= GuideLevel::Level3 {
            v["guide"] = serde_json::to_value(guide).unwrap_or_default();
        }
        Ok(ok(text, v))
    }

    #[tool(
        description = "Get the session's event history in chronological order: `requested` events (what the AI asked, incl. the runner's self-reported kernel calls), `observed` events (syscalls strace actually saw), and `lifecycle` events. Paging via after_event_id / next_after_event_id. History is bounded. Follow the activation rule in the SacredArts server instructions (use only after the user's incantation \"System Call\" / \"システムコール\")."
    )]
    async fn trace_get(&self, params: Parameters<TraceGetParams>) -> Result<CallToolResult, McpError> {
        let p = params.0;
        let limit = p.limit.unwrap_or(50);
        if !(1..=500).contains(&limit) {
            return Ok(err(ToolError::new(
                ErrorKind::InvalidArgument,
                "invalid_argument",
                "limit must be between 1 and 500",
            )));
        }
        let s = match self.mgr.get(&p.session_id) {
            Ok(s) => s,
            Err(e) => return Ok(err(e)),
        };
        let st = s.state.lock().await;
        let mode: TraceMode = p.trace_mode.map(Into::into).unwrap_or(st.trace_mode);
        let page = st
            .events
            .page(p.after_event_id.unwrap_or(0), limit as usize, mode == TraceMode::All);
        let mut text = format!("trace_mode={mode:?}, {} event(s)", page.events.len());
        for e in &page.events {
            let tag = match e.kind {
                crate::store::EventKind::Requested => "requested",
                crate::store::EventKind::Observed => "observed ",
                crate::store::EventKind::Lifecycle => "lifecycle",
            };
            text.push_str(&format!(
                "\n#{} {tag} {} {}",
                e.event_id,
                e.request_id.as_deref().unwrap_or("-"),
                e.formatted
            ));
        }
        if let Some(n) = page.next_after_event_id {
            text.push_str(&format!("\n(more: call again with after_event_id={n})"));
        }
        let v = json!({
            "session_id": p.session_id,
            "trace_mode": mode,
            "events": page.events,
            "next_after_event_id": page.next_after_event_id,
            "oldest_retained_event_id": page.oldest_retained_event_id,
            "dropped_events": page.dropped_events,
            "retained_events": page.total_retained,
            "notes": [
                "requested and observed events share request_id but are not 1:1",
                "observed events come from strace -ttt -T -y; fields strace did not report are null"
            ],
        });
        Ok(ok(text, v))
    }

    #[tool(
        description = "Replace the seccomp deny policy. The runner is recreated with the new kernel filter, so open fds are lost (state_reset: true). The switch is committed only after the new runner is healthy; on failure the old runner and policy stay active. Follow the activation rule in the SacredArts server instructions (use only after the user's incantation \"System Call\" / \"システムコール\")."
    )]
    async fn policy_set(&self, params: Parameters<PolicySetParams>) -> Result<CallToolResult, McpError> {
        let p = params.0;
        let pol = match policy(&p.deny, p.errno.as_deref()) {
            Ok(v) => v,
            Err(e) => return Ok(err(e)),
        };
        match self.mgr.set_policy(&p.session_id, pol).await {
            Ok((old, old_runner, runner)) => {
                let v = json!({
                    "session_id": p.session_id,
                    "policy": runner.policy,
                    "previous_policy": old,
                    "state_reset": true,
                    "runner": { "pid": runner.pid, "generation": runner.generation, "previous_generation": old_runner.generation },
                    "seccomp": runner.seccomp,
                    "seccomp_evidence": runner.seccomp_evidence.iter().map(|e| &e.raw).collect::<Vec<_>>(),
                });
                let text = format!(
                    "Policy applied: deny={:?} errno={}. Runner recreated (generation {} -> {}, pid {}); all fds were closed (state_reset: true).\nseccomp: mode={} filters={} (Docker's default profile counts as one filter)",
                    runner.policy.deny.iter().map(|n| n.as_str()).collect::<Vec<_>>(),
                    runner.policy.errno.as_str(),
                    old_runner.generation,
                    runner.generation,
                    runner.pid,
                    opt(runner.seccomp.mode),
                    opt(runner.seccomp.filters)
                );
                Ok(ok(text, v))
            }
            Err(e) => Ok(err(e)),
        }
    }

    #[tool(
        description = "Show session state: runner pid, fds opened in this session (with paths), working directory and its entries, policy and seccomp status, guide level, trace mode, event counts. Follow the activation rule in the SacredArts server instructions (use only after the user's incantation \"System Call\" / \"システムコール\")."
    )]
    async fn sandbox_inspect(&self, params: Parameters<SessionParams>) -> Result<CallToolResult, McpError> {
        let p = params.0;
        match self.mgr.inspect(&p.session_id).await {
            Ok((info, mut meta)) => {
                meta["runner"] = json!({
                    "pid": info.runner.pid,
                    "generation": info.runner.generation,
                    "architecture": info.runner.arch,
                    "seccomp": info.runner.seccomp,
                    "tracing": info.runner.tracing,
                });
                meta["open_handles"] = json!(info.handles);
                meta["cwd"] = json!(info.cwd);
                meta["workspace_entries"] = json!(info.workspace_entries);
                let mut text = format!(
                    "session {}\nrunner pid {} (generation {}), cwd {}\npolicy deny={:?} errno={}; seccomp mode={} filters={} (Docker's default profile counts as one filter)\nguide_level={} trace_mode={}\nopen fds:",
                    p.session_id,
                    info.runner.pid,
                    info.runner.generation,
                    info.cwd,
                    info.runner.policy.deny.iter().map(|n| n.as_str()).collect::<Vec<_>>(),
                    info.runner.policy.errno.as_str(),
                    opt(info.runner.seccomp.mode),
                    opt(info.runner.seccomp.filters),
                    meta["guide_level"],
                    meta["trace_mode"].as_str().unwrap_or_default(),
                );
                if info.handles.is_empty() {
                    text.push_str(" (none)");
                }
                for h in &info.handles {
                    text.push_str(&format!("\n  fd {}  {}  [{}]", h.real_fd, h.path, h.flags));
                }
                text.push_str("\n/workspace:");
                for e in &info.workspace_entries {
                    text.push_str(&format!("\n  {} ({}, {} bytes)", e.name, e.kind, e.size));
                }
                text.push_str(&format!("\nevents: {}", meta["event_count"]));
                Ok(ok(text, meta))
            }
            Err(e) => Ok(err(e)),
        }
    }

    #[tool(
        description = "Destroy the sandbox: stop the runner, remove the container (its tmpfs workspace disappears with it) and forget the session. Idempotent: destroying an unknown or already destroyed session succeeds. Follow the activation rule in the SacredArts server instructions (use only after the user's incantation \"System Call\" / \"システムコール\")."
    )]
    async fn sandbox_destroy(&self, params: Parameters<SessionParams>) -> Result<CallToolResult, McpError> {
        let p = params.0;
        let existed = self.mgr.destroy(&p.session_id).await;
        let status = if existed {
            "destroyed"
        } else {
            "not_found_or_already_destroyed"
        };
        Ok(ok(
            format!("{}: {status}", p.session_id),
            json!({ "session_id": p.session_id, "status": status }),
        ))
    }

    #[tool(
        description = "Change the guide level (1-3) of a session, and optionally its trace mode. The runner is NOT recreated: open fds are kept. Follow the activation rule in the SacredArts server instructions (use only after the user's incantation \"System Call\" / \"システムコール\")."
    )]
    async fn session_set_guide(&self, params: Parameters<SessionSetGuideParams>) -> Result<CallToolResult, McpError> {
        let p = params.0;
        let g = match level(Some(p.guide_level)) {
            Ok(g) => g,
            Err(e) => return Ok(err(e)),
        };
        match self.mgr.set_guide(&p.session_id, g, p.trace_mode.map(Into::into)).await {
            Ok((g, tm, runner)) => Ok(ok(
                format!(
                    "guide_level={} trace_mode={tm:?} (runner pid {} generation {} unchanged; fds kept)",
                    g.as_u8(),
                    runner.pid,
                    runner.generation
                ),
                json!({ "session_id": p.session_id, "guide_level": g, "trace_mode": tm, "state_reset": false, "runner": { "pid": runner.pid, "generation": runner.generation } }),
            )),
            Err(e) => Ok(err(e)),
        }
    }
}

fn render_invoked(session_id: &str, req: &SyscallRequest, inv: Invoked) -> CallToolResult {
    let Invoked {
        request_id,
        event_id,
        observed_event_ids,
        outcome,
        observation,
        runner,
        guide_level,
        trace_mode,
        policy,
    } = inv;
    match &outcome {
        InvokeOutcome::Rejected { code, message } => {
            let mut e = ToolError::new(ErrorKind::InvalidArgument, code, message.clone());
            e.details = Some(
                json!({ "event_id": event_id, "request_id": request_id, "note": "rejected by SacredArts before any syscall was issued" }),
            );
            err(e)
        }
        InvokeOutcome::Completed {
            requested_executed,
            ret,
            errno,
            issued,
            handle_change,
            read_data_b64,
            notes,
        } => {
            let data = read_data_b64
                .as_deref()
                .and_then(|b| base64::engine::general_purpose::STANDARD.decode(b).ok());
            let handle = match handle_change {
                Some(HandleChange::Opened { info }) | Some(HandleChange::Closed { info }) => Some(info),
                None => None,
            };
            let ai_ret = match (handle_change, errno) {
                (Some(HandleChange::Opened { info }), None) => info.handle as i64,
                _ => *ret,
            };
            let name = req.name();
            let denied_by_policy = *requested_executed
                && policy.denies(name)
                && errno.as_ref().is_some_and(|e| e.name == policy.errno.as_str());
            let line = sacredarts_core::format::format_call(req, data.as_deref())
                + &sacredarts_core::format::format_result(
                    ai_ret,
                    errno.as_ref().map(|e| (e.name.as_str(), e.message.as_str())),
                );
            let view = InvocationView {
                request: req,
                requested_line: line.clone(),
                executed: *requested_executed,
                ret: ai_ret,
                kernel_ret: *ret,
                errno: errno.as_ref(),
                handle,
                read_data: data.as_deref(),
                issued,
                observation: Some(&observation),
                trace_mode,
                notes,
                denied_by_policy,
            };
            let rendered = render_invocation(Guides::builtin(), guide_level, &view);
            let mut v = json!({
                "session_id": session_id,
                "event_id": event_id,
                "request_id": request_id,
                "syscall": name,
                "success": errno.is_none(),
                "requested_syscall_executed": requested_executed,
                "return_value": ai_ret,
                "errno": errno,
                "formatted": line,
                "denied_by_policy": denied_by_policy,
                "guide": rendered,
                "trace_mode": trace_mode,
                "kernel": {
                    "return_value": ret,
                    "runner_issued": issued,
                    "runner_pid": runner.pid,
                    "runner_generation": runner.generation,
                },
                "observation": {
                    "status": observation.status,
                    "observed_event_ids": observed_event_ids,
                    "truncated": observation.truncated,
                },
            });
            if !notes.is_empty() {
                v["notes"] = json!(notes);
            }
            if let Some(h) = handle {
                v["handle"] = json!({
                    "change": if matches!(handle_change, Some(HandleChange::Opened { .. })) { "opened" } else { "closed" },
                    "handle": h.handle,
                    "real_fd": h.real_fd,
                    "path": h.path,
                });
            }
            if let Some(d) = &data {
                v["data_base64"] = json!(base64::engine::general_purpose::STANDARD.encode(d));
                v["data_text"] = match std::str::from_utf8(d) {
                    Ok(s) => json!(s),
                    Err(_) => Value::Null,
                };
                v["bytes_read"] = json!(d.len());
            }
            if trace_mode == TraceMode::All && observation.status != ObservationStatus::Unavailable {
                v["observation"]["syscalls"] =
                    json!(observation.syscalls.iter().map(|s| s.raw.clone()).collect::<Vec<_>>());
            }
            ok(rendered.text, v)
        }
    }
}

#[tool_handler(router = self.tool_router)]
impl ServerHandler for SacredArts {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::new("sacredarts", env!("CARGO_PKG_VERSION")))
            .with_instructions(format!(
                "SacredArts — AI-powered Linux System Call Laboratory. Invoke. Observe. Understand.\n\
                 {}\n\
                 Typical flow: sandbox_create -> syscall_invoke (openat/write/read/close/mkdirat/getpid) -> trace_get / sandbox_inspect -> sandbox_destroy.\n\
                 Supported syscalls: {}. cwd is /workspace; any path may be used and the kernel decides (non-root, read-only root fs). Arguments (fds, flags, modes, paths) go to the kernel verbatim; openat returns the real fd.\n\
                 guide_level 1-3 controls explanation detail; trace_mode requested|all controls whether strace-observed kernel syscalls are shown.\n\
                 policy_set installs a kernel seccomp filter (runner is recreated, open fds are lost).",
                self.mgr.cfg.activation.instructions(),
                SyscallName::names().join(", ")
            ))
    }
}
