//! Acceptance tests (spec §12, Test 1-10) against the real MCP server binary,
//! real Docker Desktop, and the real sandbox image.
//!
//! They are `#[ignore]`d by default because they need Docker and the image:
//!
//! ```sh
//! docker build -t sacredarts-sandbox:0.1.0 .
//! cargo test -p sacredarts-mcp --test acceptance -- --ignored --test-threads=1
//! ```

use serde_json::{Value, json};
use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::time::{Duration, Instant};

const IMAGE: &str = concat!("sacredarts-sandbox:", env!("CARGO_PKG_VERSION"));

struct Mcp {
    child: Child,
    stdin: Option<ChildStdin>,
    rx: Receiver<String>,
    next: u64,
}

struct Res {
    is_error: bool,
    v: Value,
    text: String,
}

impl Res {
    fn ok(self) -> Res {
        assert!(!self.is_error, "unexpected tool error: {}", self.text);
        self
    }
    fn err(self, code: &str) -> Res {
        assert!(self.is_error, "expected error {code}, got success: {}", self.text);
        assert_eq!(self.v["error"]["code"], code, "{}", self.text);
        self
    }
}

impl Mcp {
    fn start(env: &[(&str, &str)]) -> Mcp {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_sacredarts"));
        cmd.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::null());
        for (k, v) in env {
            cmd.env(k, v);
        }
        let mut child = cmd.spawn().expect("spawn sacredarts");
        let stdout = child.stdout.take().unwrap();
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            for l in BufReader::new(stdout).lines().map_while(Result::ok) {
                if tx.send(l).is_err() {
                    break;
                }
            }
        });
        let mut mcp = Mcp {
            stdin: child.stdin.take(),
            child,
            rx,
            next: 0,
        };
        let init = mcp.rpc(
            "initialize",
            &json!({"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "acceptance", "version": "0"}}),
        );
        assert_eq!(init["result"]["serverInfo"]["name"], "sacredarts");
        let ins = init["result"]["instructions"].as_str().unwrap_or_default();
        assert!(
            ins.contains("ACTIVATION RULE"),
            "activation rule is sent to the client: {ins}"
        );
        mcp.notify("notifications/initialized");
        mcp
    }

    fn write(&mut self, v: &Value) {
        let s = self.stdin.as_mut().expect("stdin open");
        writeln!(s, "{v}").unwrap();
        s.flush().unwrap();
    }

    fn notify(&mut self, method: &str) {
        self.write(&json!({"jsonrpc": "2.0", "method": method}));
    }

    fn rpc(&mut self, method: &str, params: &Value) -> Value {
        self.next += 1;
        let id = self.next;
        self.write(&json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params}));
        let deadline = Instant::now() + Duration::from_secs(120);
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            let line = self.rx.recv_timeout(left).expect("MCP response in time");
            let v: Value = serde_json::from_str(&line).expect("stdout must carry only JSON-RPC");
            if v["id"] == id {
                return v;
            }
        }
    }

    fn tool(&mut self, name: &str, args: &Value) -> Res {
        let r = self.rpc("tools/call", &json!({"name": name, "arguments": args}));
        let res = &r["result"];
        assert!(res.is_object(), "protocol error: {r}");
        Res {
            is_error: res["isError"].as_bool().unwrap_or(false),
            v: res["structuredContent"].clone(),
            text: res["content"][0]["text"].as_str().unwrap_or_default().to_string(),
        }
    }

    fn invoke(&mut self, sid: &str, name: &str, args: &Value) -> Res {
        self.tool(
            "syscall_invoke",
            &json!({"session_id": sid, "name": name, "args": args}),
        )
    }

    fn create(&mut self, args: &Value) -> String {
        let r = self.tool("sandbox_create", args).ok();
        r.v["session_id"].as_str().unwrap().to_string()
    }

    /// Close stdin and wait for a clean exit.
    fn shutdown(mut self) {
        self.stdin.take();
        let deadline = Instant::now() + Duration::from_secs(60);
        while Instant::now() < deadline {
            if let Ok(Some(_)) = self.child.try_wait() {
                return;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        let _ = self.child.kill();
        panic!("server did not exit after stdin closed");
    }
}

impl Drop for Mcp {
    fn drop(&mut self) {
        let _ = self.child.kill();
    }
}

fn docker(args: &[&str]) -> (bool, String) {
    let o = Command::new("docker").args(args).output().expect("docker CLI");
    (
        o.status.success(),
        String::from_utf8_lossy(&o.stdout).trim().to_string() + &String::from_utf8_lossy(&o.stderr),
    )
}

fn container_of(sid: &str) -> String {
    format!("sacredarts-{}", &sid[..8])
}

fn container_exists(name: &str) -> bool {
    let (_, out) = docker(&[
        "ps",
        "-a",
        "--filter",
        &format!("name=^{name}$"),
        "--format",
        "{{.Names}}",
    ]);
    out.lines().any(|l| l.trim() == name)
}

fn wait_gone(name: &str, secs: u64) -> bool {
    let deadline = Instant::now() + Duration::from_secs(secs);
    while Instant::now() < deadline {
        if !container_exists(name) {
            return true;
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    false
}

fn preflight() {
    let (ok, out) = docker(&["image", "inspect", "--format", "{{.Id}}", IMAGE]);
    assert!(
        ok,
        "Docker and the image {IMAGE} are required (docker build -t {IMAGE} .): {out}"
    );
}

/// Test 1-4: create, write, read back, state across calls.
#[test]
#[ignore = "requires Docker Desktop and the sandbox image"]
fn t01_04_create_write_read_state() {
    preflight();
    let mut mcp = Mcp::start(&[]);
    let created = mcp.tool("sandbox_create", &json!({"guide_level": 1})).ok();
    let sid = created.v["session_id"].as_str().unwrap().to_string();
    assert_eq!(created.v["status"], "ready");
    assert_eq!(
        created.v["architecture"],
        std::env::consts::ARCH.replace("arm64", "aarch64")
    );
    let name = container_of(&sid);
    assert!(container_exists(&name), "Test 1: container exists");
    let (_, labels) = docker(&["inspect", "--format", "{{json .Config.Labels}}", &name]);
    assert!(labels.contains(&sid), "session label set: {labels}");

    // Test 2
    let opened = mcp
        .invoke(
            &sid,
            "openat",
            &json!({"path": "/workspace/hello.txt", "flags": ["O_CREAT", "O_WRONLY"], "mode": "0644"}),
        )
        .ok();
    assert_eq!(opened.v["success"], true);
    let fd = opened.v["return_value"].as_i64().unwrap();
    assert_eq!(fd, 3);
    assert!(opened.v["handle"]["real_fd"].as_i64().unwrap() >= 0);
    assert_eq!(
        opened.text,
        r#"openat(AT_FDCWD, "/workspace/hello.txt", O_WRONLY|O_CREAT, 0644) = 3"#
    );
    // Test 4: the handle survives across separate MCP calls
    let inspected = mcp.tool("sandbox_inspect", &json!({"session_id": sid})).ok();
    assert_eq!(inspected.v["open_handles"][0]["handle"], 3);
    assert_eq!(inspected.v["cwd"], "/workspace");
    let written = mcp.invoke(&sid, "write", &json!({"fd": fd, "data": "Hello"})).ok();
    assert_eq!(written.v["return_value"], 5);
    assert_eq!(written.text, r#"write(3, "Hello", 5) = 5"#);
    let closed = mcp.invoke(&sid, "close", &json!({"fd": fd})).ok();
    assert_eq!(closed.v["return_value"], 0);

    // Test 3
    let opened = mcp
        .invoke(&sid, "openat", &json!({"path": "hello.txt", "flags": ["O_RDONLY"]}))
        .ok();
    assert_eq!(opened.v["return_value"], 3, "closed handle number is reused");
    let rd = mcp.invoke(&sid, "read", &json!({"fd": 3, "count": 64})).ok();
    assert_eq!(rd.v["return_value"], 5);
    assert_eq!(rd.v["data_text"], "Hello");
    assert_eq!(rd.text, r#"read(3, "Hello", 64) = 5"#);
    let rd = mcp.invoke(&sid, "read", &json!({"fd": 3, "count": 64})).ok();
    assert_eq!(rd.v["return_value"], 0, "EOF");

    mcp.tool("sandbox_destroy", &json!({"session_id": sid})).ok();
    assert!(wait_gone(&name, 20));
    mcp.shutdown();
}

/// Test 5: the same operation rendered at guide levels 1, 2, 3.
#[test]
#[ignore = "requires Docker Desktop and the sandbox image"]
fn t05_guide_levels() {
    preflight();
    let mut mcp = Mcp::start(&[]);
    let sid = mcp.create(&json!({}));
    let args = json!({"path": "/workspace/g.txt", "flags": ["O_CREAT", "O_WRONLY"], "mode": "0644"});
    let mut texts = vec![];
    for level in 1..=3 {
        mcp.tool("session_set_guide", &json!({"session_id": sid, "guide_level": level}))
            .ok();
        let rendered = mcp.invoke(&sid, "openat", &args).ok();
        assert_eq!(rendered.v["guide"]["level"], level);
        texts.push(rendered.text);
    }
    // handles 3,4,5 -> state kept across guide changes (runner not recreated)
    let inspected = mcp.tool("sandbox_inspect", &json!({"session_id": sid})).ok();
    assert_eq!(inspected.v["open_handles"].as_array().unwrap().len(), 3);
    assert_eq!(inspected.v["runner"]["generation"], 1);

    let strip = |text: &str| text.lines().next().unwrap().rsplit_once(" = ").unwrap().0.to_string();
    assert!(
        texts.iter().all(|text| strip(text) == strip(&texts[0])),
        "same call line"
    );
    assert_eq!(texts[0].lines().count(), 1, "Level 1: syscall only:\n{}", texts[0]);
    assert!(!texts[0].contains("解説"));
    assert!(texts[1].contains("解説") && texts[1].contains("ファイルディスクリプタ"));
    assert!(!texts[1].contains("シグネチャ"));
    for needle in [
        "int openat(",
        "## 引数",
        "`flags`",
        "## 戻り値",
        "## errno",
        "Virtual File System",
        "【実測】",
        "【一般的な仕様】",
        "openat(2)",
    ] {
        assert!(texts[2].contains(needle), "Level 3 lacks {needle}");
    }
    // describe works without a sandbox, incl. open vs openat
    let described = mcp
        .tool("syscall_describe", &json!({"name": "open", "guide_level": 3}))
        .ok();
    assert_eq!(described.v["executable"], false);
    assert!(described.text.contains("openat(AT_FDCWD"));
    mcp.tool("sandbox_destroy", &json!({"session_id": sid})).ok();
    mcp.shutdown();
}

/// Test 6: strace observation, requested vs observed events.
#[test]
#[ignore = "requires Docker Desktop and the sandbox image"]
fn t06_strace_observation() {
    preflight();
    let mut mcp = Mcp::start(&[]);
    let created = mcp.tool("sandbox_create", &json!({"trace_mode": "all"})).ok();
    let sid = created.v["session_id"].as_str().unwrap().to_string();
    assert_eq!(
        created.v["tracing"]["state"], "active",
        "strace must work on Docker Desktop: {}",
        created.text
    );
    let opened = mcp
        .invoke(
            &sid,
            "openat",
            &json!({"path": "obs.txt", "flags": ["O_CREAT", "O_RDWR"], "mode": "0600"}),
        )
        .ok();
    assert_eq!(opened.v["observation"]["status"], "complete");
    let real_fd = opened.v["handle"]["real_fd"].as_i64().unwrap();
    assert!(opened.text.contains("# kernel (strace):"));
    let obs: Vec<String> = opened.v["observation"]["syscalls"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s.as_str().unwrap().to_string())
        .collect();
    assert!(
        obs.iter().any(
            |l| l.contains(r#"openat(AT_FDCWD</workspace>, "obs.txt", O_RDWR|O_CREAT, 0600)"#)
                && l.contains(&format!("= {real_fd}<"))
        ),
        "{obs:?}"
    );

    let trace = mcp.tool("trace_get", &json!({"session_id": sid, "limit": 100})).ok();
    let ev = trace.v["events"].as_array().unwrap();
    let req: Vec<&Value> = ev.iter().filter(|e| e["kind"] == "requested").collect();
    let seen: Vec<&Value> = ev.iter().filter(|e| e["kind"] == "observed").collect();
    assert_eq!(req.len(), 1);
    assert_ne!(seen, [] as [&serde_json::Value; 0]);
    assert_eq!(req[0]["source"], "ai_request");
    assert_eq!(
        req[0]["return_value"], 3,
        "requested event shows the fd the kernel returned"
    );
    assert_eq!(req[0]["details"]["kernel_return_value"], real_fd);
    assert!(req[0]["duration_ns"].is_null(), "not measured -> null");
    for s in &seen {
        assert_eq!(s["source"], "strace");
        assert_eq!(s["request_id"], req[0]["request_id"]);
        assert!(s["duration_ns"].is_u64());
    }
    // trace_mode=requested hides observed events
    let trace = mcp
        .tool("trace_get", &json!({"session_id": sid, "trace_mode": "requested"}))
        .ok();
    assert!(
        trace.v["events"]
            .as_array()
            .unwrap()
            .iter()
            .all(|e| e["kind"] != "observed")
    );
    // paging
    let trace = mcp.tool("trace_get", &json!({"session_id": sid, "limit": 1})).ok();
    let cursor = trace.v["next_after_event_id"].as_u64().unwrap();
    let t2 = mcp
        .tool(
            "trace_get",
            &json!({"session_id": sid, "limit": 1, "after_event_id": cursor}),
        )
        .ok();
    assert!(t2.v["events"][0]["event_id"].as_u64().unwrap() > cursor);
    // brackets in a file name appear unescaped in strace's fd annotations;
    // the write must still be observed
    let opened = mcp
        .invoke(
            &sid,
            "openat",
            &json!({"path": "a(b>c[d", "flags": "O_WRONLY|O_CREAT", "mode": "0644"}),
        )
        .ok();
    let fd = opened.v["return_value"].as_i64().unwrap();
    let written = mcp.invoke(&sid, "write", &json!({"fd": fd, "data": "x"})).ok();
    let syscalls = written.v["observation"]["syscalls"].as_array().unwrap();
    assert!(
        syscalls.iter().any(|l| l.as_str().unwrap().contains("write(")),
        "{syscalls:?}"
    );
    mcp.tool("sandbox_destroy", &json!({"session_id": sid})).ok();
    mcp.shutdown();
}

/// Test 7: seccomp denies mkdirat in the kernel; a fresh runner without the
/// policy succeeds.
#[test]
#[ignore = "requires Docker Desktop and the sandbox image"]
fn t07_seccomp() {
    preflight();
    let mut mcp = Mcp::start(&[]);
    let created = mcp
        .tool(
            "sandbox_create",
            &json!({"guide_level": 2, "trace_mode": "all", "policy": {"deny": ["mkdirat"], "errno": "EPERM"}}),
        )
        .ok();
    let sid = created.v["session_id"].as_str().unwrap().to_string();
    let filters_with = created.v["seccomp"]["filters"].as_u64().unwrap();
    assert_eq!(created.v["seccomp"]["sacredarts_filter_installed"], true);
    let ev = created.v["seccomp_evidence"].to_string();
    assert!(
        ev.contains("seccomp(SECCOMP_SET_MODE_FILTER"),
        "strace saw the filter being installed: {ev}"
    );

    let made = mcp
        .invoke(&sid, "mkdirat", &json!({"path": "test", "mode": "0755"}))
        .ok();
    assert_eq!(made.v["success"], false);
    assert_eq!(made.v["errno"]["name"], "EPERM");
    assert_eq!(made.v["denied_by_policy"], true);
    assert_eq!(
        made.v["requested_syscall_executed"], true,
        "runner issued mkdirat; no app-level branch"
    );
    assert!(
        made.text
            .starts_with(r#"mkdirat(AT_FDCWD, "test", 0755) = -1 EPERM (Operation not permitted)"#),
        "{}",
        made.text
    );
    assert!(made.text.contains("seccomp"));
    let kernel = made.v["observation"]["syscalls"].to_string();
    assert!(
        kernel.contains(r"mkdirat(") && kernel.contains("= -1 EPERM"),
        "strace saw the kernel reject it: {kernel}"
    );
    let inspected = mcp.tool("sandbox_inspect", &json!({"session_id": sid})).ok();
    assert!(
        inspected.v["workspace_entries"]
            .as_array()
            .unwrap()
            .iter()
            .all(|failure| failure["name"] != "test")
    );

    let applied = mcp.tool("policy_set", &json!({"session_id": sid, "deny": []})).ok();
    assert_eq!(applied.v["state_reset"], true);
    assert_eq!(applied.v["runner"]["generation"], 2);
    assert_eq!(
        applied.v["seccomp"]["filters"].as_u64().unwrap(),
        filters_with - 1,
        "our filter is gone in the new runner"
    );
    let made = mcp
        .invoke(&sid, "mkdirat", &json!({"path": "test", "mode": "0755"}))
        .ok();
    assert_eq!(made.v["success"], true);
    assert_eq!(made.v["return_value"], 0);

    // invalid policies are rejected and do not touch the session
    mcp.tool("policy_set", &json!({"session_id": sid, "deny": ["sendto"]}))
        .err("unsupported_syscall");
    // any errno name works; an unknown one fails inside the sandbox and the old policy stays
    mcp.tool(
        "policy_set",
        &json!({"session_id": sid, "deny": ["getpid"], "errno": "EIO"}),
    )
    .ok();
    let getpid = mcp.invoke(&sid, "getpid", &json!({})).ok();
    assert_eq!(getpid.v["errno"]["name"], "EIO");
    let failure = mcp
        .tool(
            "policy_set",
            &json!({"session_id": sid, "deny": ["getpid"], "errno": "ENOTANERRNO"}),
        )
        .err("invalid_policy");
    assert_eq!(failure.v["error"]["kind"], "invalid_argument");
    let getpid = mcp.invoke(&sid, "getpid", &json!({})).ok();
    assert_eq!(getpid.v["errno"]["name"], "EIO", "previous policy still active");
    // aliases are accepted and stored by their canonical name
    let applied = mcp
        .tool(
            "policy_set",
            &json!({"session_id": sid, "deny": ["getpid"], "errno": "EWOULDBLOCK"}),
        )
        .ok();
    assert_eq!(applied.v["policy"]["errno"], "EAGAIN");
    let getpid = mcp.invoke(&sid, "getpid", &json!({})).ok();
    assert_eq!(getpid.v["errno"]["name"], "EAGAIN");
    assert_eq!(getpid.v["denied_by_policy"], true);
    mcp.tool("sandbox_destroy", &json!({"session_id": sid})).ok();
    mcp.shutdown();
}

/// Test 8: error handling.
#[test]
#[ignore = "requires Docker Desktop and the sandbox image"]
fn t08_errors() {
    preflight();
    let mut mcp = Mcp::start(&[("SACREDARTS_REQUEST_TIMEOUT_MS", "1500")]);
    let sid = mcp.create(&json!({}));
    // invalid fd: the kernel answers EBADF (a Linux error, not a tool error)
    let reply = mcp.invoke(&sid, "close", &json!({"fd": 99})).ok();
    assert_eq!(reply.v["success"], false);
    assert_eq!(reply.v["errno"]["name"], "EBADF");
    // invalid argument
    mcp.invoke(
        &sid,
        "openat",
        &json!({"path": "x", "flags": ["O_CREAT"], "mode": "nope"}),
    )
    .err("invalid_mode");
    mcp.invoke(&sid, "read", &json!({"fd": 3})).err("missing_argument");
    mcp.tool("sandbox_create", &json!({"guide_level": 7}))
        .err("invalid_guide_level");
    mcp.tool(
        "sandbox_create",
        &json!({"policy": {"deny": ["getpid"], "errno": "ENOPE"}}),
    )
    .err("invalid_policy");
    // unsupported syscall
    let failure = mcp.invoke(&sid, "execve", &json!({})).err("unsupported_syscall");
    assert_eq!(failure.v["error"]["kind"], "unsupported_syscall");
    // missing file: a Linux error, not a tool error
    let reply = mcp.invoke(&sid, "openat", &json!({"path": "nope.txt"})).ok();
    assert_eq!(reply.v["success"], false);
    assert_eq!(reply.v["errno"]["name"], "ENOENT");
    // unknown session
    mcp.invoke("00000000-0000-0000-0000-000000000000", "getpid", &json!({}))
        .err("session_not_found");

    // execution timeout: opening a FIFO for reading blocks until a writer appears
    let name = container_of(&sid);
    let (ok, out) = docker(&["exec", &name, "mkfifo", "/workspace/fifo"]);
    assert!(ok, "{out}");
    mcp.invoke(
        &sid,
        "openat",
        &json!({"path": "keep.txt", "flags": ["O_CREAT", "O_WRONLY"], "mode": "0644"}),
    )
    .ok();
    let t0 = Instant::now();
    let failure = mcp
        .invoke(&sid, "openat", &json!({"path": "fifo"}))
        .err("syscall_timeout");
    assert_eq!(failure.v["error"]["kind"], "timeout");
    assert_eq!(failure.v["error"]["details"]["state_reset"], true);
    assert!(t0.elapsed() < Duration::from_secs(15));
    // the session still works with a fresh runner; old handles are gone
    let inspected = mcp.tool("sandbox_inspect", &json!({"session_id": sid})).ok();
    assert_eq!(inspected.v["runner"]["generation"], 2);
    assert_eq!(inspected.v["open_handles"].as_array().unwrap().len(), 0);
    mcp.invoke(&sid, "getpid", &json!({})).ok();
    mcp.tool("sandbox_destroy", &json!({"session_id": sid})).ok();
    assert!(
        wait_gone(&name, 20),
        "Test 10: no container left after a timeout + destroy"
    );
    mcp.shutdown();

    // Docker unavailable
    let mut mcp = Mcp::start(&[("DOCKER_HOST", "unix:///nonexistent/sacredarts-test.sock")]);
    let failure = mcp.tool("sandbox_create", &json!({})).err("docker_unavailable");
    assert_eq!(failure.v["error"]["kind"], "infrastructure");
    mcp.shutdown();
}

/// Test 9: isolation.
#[test]
#[ignore = "requires Docker Desktop and the sandbox image"]
fn t09_isolation() {
    preflight();
    let mut mcp = Mcp::start(&[]);
    let sid = mcp.create(&json!({}));
    let name = container_of(&sid);
    paths_are_decided_by_the_kernel(&mut mcp, &sid);
    fds_flags_and_limits_are_the_kernels(&mut mcp, &sid);
    control_channels_survive_abuse(&mut mcp, &sid);
    container_is_hardened(&name);

    // state is discarded on destroy
    mcp.invoke(
        &sid,
        "openat",
        &json!({"path": "secret.txt", "flags": ["O_CREAT", "O_WRONLY"], "mode": "0600"}),
    )
    .ok();
    mcp.tool("sandbox_destroy", &json!({"session_id": sid})).ok();
    assert!(wait_gone(&name, 20));
    mcp.invoke(&sid, "getpid", &json!({})).err("session_not_found");
    mcp.shutdown();
}

/// Paths are not confined by SacredArts: the kernel decides, inside the
/// container (non-root, read-only root filesystem).
fn paths_are_decided_by_the_kernel(mcp: &mut Mcp, sid: &str) {
    let errno = |mcp: &mut Mcp, name: &str, args: &Value| {
        let reply = mcp.invoke(sid, name, args).ok();
        assert_eq!(reply.v["requested_syscall_executed"], true);
        reply.v["errno"]["name"].as_str().map(str::to_string)
    };
    assert_eq!(
        errno(mcp, "openat", &json!({"path": "/etc/passwd"})),
        None,
        "world-readable"
    );
    assert_eq!(
        errno(mcp, "openat", &json!({"path": "../etc/hostname"})),
        None,
        "'..' resolved by the kernel"
    );
    assert_eq!(
        errno(mcp, "openat", &json!({"path": "/etc/shadow"})).as_deref(),
        Some("EACCES"),
        "not root"
    );
    assert_eq!(
        errno(
            mcp,
            "openat",
            &json!({"path": "/etc/x", "flags": ["O_WRONLY", "O_CREAT"], "mode": "0644"})
        )
        .as_deref(),
        Some("EROFS"),
        "read-only root filesystem"
    );
    assert_eq!(
        errno(mcp, "mkdirat", &json!({"path": "/usr/x"})).as_deref(),
        Some("EROFS")
    );
    assert_eq!(
        errno(mcp, "openat", &json!({"path": "/usr/bin/sh", "flags": ["O_WRONLY"]})).as_deref(),
        Some("EACCES")
    );
    assert_eq!(
        errno(mcp, "mkdirat", &json!({"path": "/tmp/t"})),
        None,
        "tmpfs is writable"
    );
}

fn fds_flags_and_limits_are_the_kernels(mcp: &mut Mcp, sid: &str) {
    // fds, flags and limits are the kernel's
    let reply = mcp.invoke(sid, "read", &json!({"fd": 0, "count": 1})).ok();
    assert_eq!(reply.v["return_value"], 0, "fd 0 is /dev/null");
    let reply = mcp
        .invoke(
            sid,
            "openat",
            &json!({"path": "/tmp", "flags": "O_RDWR|O_TMPFILE", "mode": "0600"}),
        )
        .ok();
    assert_eq!(reply.v["success"], true, "O_TMPFILE on tmpfs: {:?}", reply.v);
    let fd = reply.v["return_value"].as_i64().unwrap();
    mcp.invoke(sid, "close", &json!({"fd": fd})).ok();
    let reply = mcp.invoke(sid, "openat", &json!({"path": "x".repeat(5000)})).ok();
    assert_eq!(reply.v["errno"]["name"], "ENAMETOOLONG");
    // the request reaches the kernel verbatim
    let reply = mcp.invoke(sid, "openat", &json!({"path": "/proc/self/status"})).ok();
    let issued = reply.v["kernel"]["runner_issued"].as_array().unwrap();
    assert_eq!(issued.len(), 1);
    assert_eq!(issued[0]["args"], r#"AT_FDCWD, "/proc/self/status", O_RDONLY"#);
}

/// The learner can write into the supervisor's channels (/proc/1/fd/1, 2);
/// the host must neither break nor buffer without bound.
fn control_channels_survive_abuse(mcp: &mut Mcp, sid: &str) {
    // writing junk into the supervisor's channel (/proc/1/fd/1) does not break the host
    let host_out = mcp
        .invoke(sid, "openat", &json!({"path": "/proc/1/fd/1", "flags": ["O_WRONLY"]}))
        .ok();
    let host_out = host_out.v["return_value"].as_i64().unwrap();
    mcp.invoke(
        sid,
        "write",
        &json!({"fd": host_out, "data": "junk\n{\"type\":\"bogus\"}\n"}),
    )
    .ok();
    mcp.invoke(sid, "getpid", &json!({})).ok();
    // stderr without newlines (/proc/1/fd/2 reaches the host's stderr reader)
    // and many inspect-only requests must not make anything buffer unboundedly
    let host_err = mcp
        .invoke(sid, "openat", &json!({"path": "/proc/1/fd/2", "flags": ["O_WRONLY"]}))
        .ok();
    let host_err = host_err.v["return_value"].as_i64().unwrap();
    for _ in 0..8 {
        mcp.invoke(sid, "write", &json!({"fd": host_err, "data": "y".repeat(65536)}))
            .ok();
    }
    for _ in 0..50 {
        mcp.tool("sandbox_inspect", &json!({"session_id": sid})).ok();
    }
    mcp.invoke(sid, "getpid", &json!({})).ok();
}

/// Container hardening as actually applied by Docker.
fn container_is_hardened(name: &str) {
    let (_, hc) = docker(&["inspect", "--format", "{{json .HostConfig}}", name]);
    let hc: Value = serde_json::from_str(&hc).unwrap();
    assert_eq!(hc["NetworkMode"], "none");
    assert_eq!(hc["ReadonlyRootfs"], true);
    assert_eq!(hc["Privileged"], false);
    assert_eq!(hc["CapDrop"], json!(["ALL"]));
    assert!(hc["CapAdd"].is_null() || hc["CapAdd"] == json!([]));
    assert!(hc["SecurityOpt"].to_string().contains("no-new-privileges"));
    assert!(hc["PidsLimit"].as_i64().unwrap() > 0);
    assert!(hc["Memory"].as_i64().unwrap() > 0);
    assert!(hc["NanoCpus"].as_i64().unwrap() > 0);
    assert!(hc["Binds"].is_null(), "no host mounts (and no docker.sock)");
    let (_, user) = docker(&["inspect", "--format", "{{.Config.User}}", name]);
    assert_eq!(user, "10001:10001");
    // inside: no capabilities, only loopback, no docker socket
    let (_, st) = docker(&["exec", name, "grep", "-E", "^Cap(Eff|Prm|Bnd)", "/proc/1/status"]);
    assert!(st.lines().all(|l| l.ends_with("0000000000000000")), "{st}");
    // no routes at all, and every interface except loopback is down
    // (linuxkit creates inert tunnel fallback devices in each netns)
    let (_, routes) = docker(&["exec", name, "cat", "/proc/net/route"]);
    assert_eq!(routes.lines().count(), 1, "only the header, no routes: {routes}");
    let (_, states) = docker(&[
        "exec",
        name,
        "sh",
        "-c",
        "for i in /sys/class/net/*; do echo $(basename $i) $(cat $i/operstate 2>/dev/null); done",
    ]);
    for l in states.lines() {
        let (ifname, state) = l.split_once(' ').unwrap_or((l, ""));
        assert!(
            ifname == "lo" || ifname == "bonding_masters" || state == "down",
            "interface up: {l}"
        );
    }
    assert!(!docker(&["exec", name, "test", "-e", "/var/run/docker.sock"]).0);
}

/// Test 10: resource cleanup on server exit, crash, and orphan sweep.
#[test]
#[ignore = "requires Docker Desktop and the sandbox image"]
fn t10_cleanup() {
    preflight();
    // graceful: stdin closed -> all sandboxes destroyed
    let mut mcp = Mcp::start(&[]);
    let first = container_of(&mcp.create(&json!({})));
    let second = container_of(&mcp.create(&json!({})));
    mcp.shutdown();
    assert!(
        wait_gone(&first, 20) && wait_gone(&second, 20),
        "containers removed after server exit"
    );

    // crash: SIGKILL the server -> container sees stdin EOF and removes itself
    let mut mcp = Mcp::start(&[]);
    let leftover = container_of(&mcp.create(&json!({})));
    let _ = mcp.child.kill();
    let _ = mcp.child.wait();
    assert!(wait_gone(&leftover, 30), "container exits when its server dies");

    // orphan sweep at start-up: first container labelled for first dead server
    let orphan = "sacredarts-orphan-test";
    let _ = docker(&["rm", "-f", orphan]);
    let (ok, out) = docker(&[
        "create",
        "--name",
        orphan,
        "--label",
        "io.sacredarts.managed=true",
        "--label",
        "io.sacredarts.host-pid=999999",
        "--network",
        "none",
        IMAGE,
    ]);
    assert!(ok, "{out}");
    let mcp = Mcp::start(&[]);
    assert!(wait_gone(orphan, 30), "orphan removed at start-up");
    mcp.shutdown();

    // session limit
    let mut mcp = Mcp::start(&[("SACREDARTS_MAX_SESSIONS", "1")]);
    let sid = mcp.create(&json!({}));
    mcp.tool("sandbox_create", &json!({})).err("too_many_sessions");
    mcp.tool("sandbox_destroy", &json!({"session_id": sid})).ok();
    mcp.create(&json!({}));
    mcp.shutdown();
}
