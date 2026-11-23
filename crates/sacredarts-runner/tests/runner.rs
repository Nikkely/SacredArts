//! End-to-end tests of the runner binary (Linux only).
//!
//! Each test spawns `sacredarts-runner` with a socketpair on fd 0 and a
//! temporary directory as its working directory, exactly like the supervisor
//! does (minus strace).
#![cfg(target_os = "linux")]

use base64::Engine;
use sacredarts_core::ipc::{
    HandleChange, InvokeOutcome, RunnerHello, RunnerOp, RunnerReply, RunnerReplyBody, RunnerRequest,
};
use sacredarts_core::{Policy, SyscallRequest};
use serde_json::{Value, json};
use std::io::{BufRead, BufReader, Write};
use std::os::fd::OwnedFd;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};

struct Rn {
    child: Child,
    w: UnixStream,
    r: BufReader<UnixStream>,
    hello: RunnerHello,
    dir: PathBuf,
    next: u64,
}

fn tempdir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!(
        "sc-runner-{tag}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&d).unwrap();
    d
}

impl Rn {
    fn start(tag: &str, policy: &Policy) -> Rn {
        let dir = tempdir(tag);
        let (ours, theirs) = UnixStream::pair().unwrap();
        let child = Command::new(env!("CARGO_BIN_EXE_sacredarts-runner"))
            .arg("--workspace")
            .arg(&dir)
            .arg("--policy")
            .arg(serde_json::to_string(policy).unwrap())
            .current_dir(&dir)
            .stdin(Stdio::from(OwnedFd::from(theirs)))
            .stdout(Stdio::null())
            .spawn()
            .unwrap();
        ours.set_read_timeout(Some(std::time::Duration::from_secs(10))).unwrap();
        let mut r = BufReader::new(ours.try_clone().unwrap());
        let mut line = String::new();
        r.read_line(&mut line).unwrap();
        let hello: RunnerHello = serde_json::from_str(&line).unwrap();
        Rn {
            child,
            w: ours,
            r,
            hello,
            dir,
            next: 1,
        }
    }

    fn op(&mut self, op: RunnerOp) -> RunnerReplyBody {
        let id = self.next;
        self.next += 1;
        let s = serde_json::to_string(&RunnerRequest { id, op }).unwrap();
        self.w.write_all(s.as_bytes()).unwrap();
        self.w.write_all(b"\n").unwrap();
        let mut line = String::new();
        self.r.read_line(&mut line).unwrap();
        let rep: RunnerReply = serde_json::from_str(&line).unwrap();
        assert_eq!(rep.id, id);
        rep.body
    }

    fn call(&mut self, name: &str, args: &Value) -> InvokeOutcome {
        let request = SyscallRequest::from_user(name, args).expect("valid request");
        match self.op(RunnerOp::Invoke { request }) {
            RunnerReplyBody::Invoked { outcome } => *outcome,
            other => panic!("unexpected {other:?}"),
        }
    }

    /// The runner's socket to the supervisor (the only fd it refuses to use).
    fn ipc_fd(&self) -> i32 {
        std::fs::read_dir(format!("/proc/{}/fd", self.hello.pid))
            .unwrap()
            .filter_map(|e| {
                let e = e.ok()?;
                let target = std::fs::read_link(e.path()).ok()?;
                target
                    .to_string_lossy()
                    .starts_with("socket:")
                    .then(|| e.file_name().to_string_lossy().parse().unwrap())
            })
            .max()
            .unwrap()
    }

    fn seccomp_filters(&self) -> u32 {
        let s = std::fs::read_to_string(format!("/proc/{}/status", self.hello.pid)).unwrap();
        s.lines()
            .find_map(|l| l.strip_prefix("Seccomp_filters:"))
            .map_or(0, |v| v.trim().parse().unwrap())
    }
}

impl Drop for Rn {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// (executed, ret, errno-name)
fn res(o: &InvokeOutcome) -> (bool, i64, Option<String>) {
    match o {
        InvokeOutcome::Completed {
            requested_executed,
            ret,
            errno,
            ..
        } => (*requested_executed, *ret, errno.as_ref().map(|e| e.name.clone())),
        InvokeOutcome::Rejected { code, message } => panic!("rejected {code}: {message}"),
    }
}

fn ok(o: &InvokeOutcome) -> i64 {
    let (exec, ret, errno) = res(o);
    assert!(exec && errno.is_none(), "expected success, got {o:?}");
    ret
}

/// fd created by a successful openat.
fn opened(o: &InvokeOutcome) -> i32 {
    ok(o);
    match o {
        InvokeOutcome::Completed {
            handle_change: Some(HandleChange::Opened { info }),
            ret,
            ..
        } => {
            assert_eq!(i64::from(info.real_fd), *ret, "ret is the real kernel fd");
            assert_eq!(info.handle, info.real_fd);
            info.handle
        }
        other => panic!("no handle: {other:?}"),
    }
}

fn errno_of(o: &InvokeOutcome) -> String {
    res(o).2.unwrap_or_else(|| panic!("expected failure, got {o:?}"))
}

fn rejected(o: &InvokeOutcome) -> String {
    match o {
        InvokeOutcome::Rejected { code, .. } => code.clone(),
        other @ InvokeOutcome::Completed { .. } => panic!("expected rejection, got {other:?}"),
    }
}

fn read_data(o: &InvokeOutcome) -> Vec<u8> {
    match o {
        InvokeOutcome::Completed {
            read_data_b64: Some(b), ..
        } => base64::engine::general_purpose::STANDARD.decode(b).unwrap(),
        other => panic!("no data: {other:?}"),
    }
}

#[test]
fn hello_reports_pid_and_policy() {
    let rn = Rn::start("hello", &Policy::default());
    assert!(rn.hello.pid > 0);
    assert!(!rn.hello.seccomp_filter_installed);
    assert_eq!(rn.hello.arch, std::env::consts::ARCH);
}

#[test]
fn getpid_matches_runner_pid() {
    let mut rn = Rn::start("getpid", &Policy::default());
    let pid = i64::from(rn.hello.pid);
    assert_eq!(ok(&rn.call("getpid", &json!({}))), pid);
}

#[test]
fn write_then_read_roundtrip_with_state() {
    let mut rn = Rn::start("rw", &Policy::default());
    let o = rn.call(
        "openat",
        &json!({"path": "hello.txt", "flags": ["O_CREAT", "O_WRONLY"], "mode": "0644"}),
    );
    let h = opened(&o);
    assert_eq!(h, 3, "fds 0-2 are taken (stdio), so the kernel returns 3");
    if let InvokeOutcome::Completed {
        handle_change: Some(HandleChange::Opened { info }),
        issued,
        ..
    } = &o
    {
        assert_eq!(info.path, format!("{}/hello.txt", rn.dir.display()));
        assert!(info.real_fd >= 0);
        // the request is passed to the kernel verbatim: one openat, nothing added
        assert_eq!(issued.len(), 1);
        assert_eq!(issued[0].syscall, "openat");
        assert_eq!(issued[0].args, r#"AT_FDCWD, "hello.txt", O_WRONLY|O_CREAT, 0644"#);
    } else {
        panic!("{o:?}")
    }
    assert_eq!(ok(&rn.call("write", &json!({"fd": 3, "data": "Hello"}))), 5);
    assert_eq!(ok(&rn.call("close", &json!({"fd": 3}))), 0);
    assert_eq!(std::fs::read(rn.dir.join("hello.txt")).unwrap(), b"Hello");
    let mode =
        std::os::unix::fs::PermissionsExt::mode(&std::fs::metadata(rn.dir.join("hello.txt")).unwrap().permissions());
    assert_eq!(mode & 0o777, 0o644 & !0o022);

    // re-open and read; fd 3 is reused (lowest free)
    assert_eq!(opened(&rn.call("openat", &json!({"path": "hello.txt"}))), 3);
    let o = rn.call("read", &json!({"fd": 3, "count": 2}));
    assert_eq!(ok(&o), 2, "partial read returns what was asked");
    assert_eq!(read_data(&o), b"He");
    let o = rn.call("read", &json!({"fd": 3, "count": 100}));
    assert_eq!(ok(&o), 3, "short read at end of data");
    assert_eq!(read_data(&o), b"llo");
    assert_eq!(ok(&rn.call("read", &json!({"fd": 3, "count": 100}))), 0, "EOF");
}

#[test]
fn binary_data_with_nul_bytes() {
    let mut rn = Rn::start("bin", &Policy::default());
    ok(&rn.call(
        "openat",
        &json!({"path": "b.bin", "flags": "O_RDWR|O_CREAT|O_TRUNC", "mode": "0600"}),
    ));
    let data = base64::engine::general_purpose::STANDARD.encode([0u8, 1, 2, 0, 255]);
    assert_eq!(
        ok(&rn.call("write", &json!({"fd": 3, "data": data, "encoding": "base64"}))),
        5
    );
    ok(&rn.call("close", &json!({"fd": 3})));
    ok(&rn.call("openat", &json!({"path": "b.bin"})));
    assert_eq!(
        read_data(&rn.call("read", &json!({"fd": 3, "count": 10}))),
        vec![0, 1, 2, 0, 255]
    );
}

#[test]
fn fds_are_passed_to_the_kernel() {
    let mut rn = Rn::start("fds", &Policy::default());
    // fds that were never opened: the kernel says EBADF
    assert_eq!(errno_of(&rn.call("write", &json!({"fd": 42, "data": "x"}))), "EBADF");
    assert_eq!(errno_of(&rn.call("close", &json!({"fd": 3}))), "EBADF");
    assert_eq!(errno_of(&rn.call("read", &json!({"fd": -1, "count": 1}))), "EBADF");
    // stdio exists like in any process: fd 0 is /dev/null, fd 1 too
    assert_eq!(
        ok(&rn.call("read", &json!({"fd": 0, "count": 1}))),
        0,
        "EOF from /dev/null"
    );
    assert_eq!(ok(&rn.call("write", &json!({"fd": 1, "data": "hi"}))), 2);
    // only the runner's own socket to the supervisor is refused
    let ipc = rn.ipc_fd();
    assert!(ipc > 2, "the IPC socket was moved away from fd 0");
    assert_eq!(rejected(&rn.call("close", &json!({"fd": ipc}))), "reserved_fd");
    assert_eq!(
        rejected(&rn.call("openat", &json!({"dirfd": ipc, "path": "x"}))),
        "reserved_fd"
    );
    assert!(matches!(rn.op(RunnerOp::Ping), RunnerReplyBody::Pong));
    // kernel-level permission errors are real errnos
    std::fs::write(rn.dir.join("r.txt"), b"data").unwrap();
    ok(&rn.call("openat", &json!({"path": "r.txt", "flags": ["O_RDONLY"]})));
    assert_eq!(errno_of(&rn.call("write", &json!({"fd": 3, "data": "x"}))), "EBADF");
    ok(&rn.call("close", &json!({"fd": 3})));
    assert_eq!(
        errno_of(&rn.call("close", &json!({"fd": 3}))),
        "EBADF",
        "use after close"
    );
    // read on a directory fd
    ok(&rn.call("openat", &json!({"path": ".", "flags": ["O_RDONLY", "O_DIRECTORY"]})));
    assert_eq!(errno_of(&rn.call("read", &json!({"fd": 3, "count": 4}))), "EISDIR");
}

#[test]
fn flags_and_modes_are_passed_verbatim() {
    let mut rn = Rn::start("flags", &Policy::default());
    let args = |o: &InvokeOutcome| match o {
        InvokeOutcome::Completed { issued, .. } => issued[0].args.clone(),
        other @ InvokeOutcome::Rejected { .. } => panic!("{other:?}"),
    };
    // numeric flags are decoded like strace (0o101 = O_WRONLY|O_CREAT on every Linux arch)
    let o = rn.call("openat", &json!({"path": "n.txt", "flags": 0o101, "mode": "0640"}));
    opened(&o);
    assert_eq!(args(&o), r#"AT_FDCWD, "n.txt", O_WRONLY|O_CREAT, 0640"#);
    // O_CREAT without a mode: the kernel gets 0 and creates a 0000 file
    let o = rn.call("openat", &json!({"path": "z.txt", "flags": "O_WRONLY|O_CREAT"}));
    opened(&o);
    assert_eq!(args(&o), r#"AT_FDCWD, "z.txt", O_WRONLY|O_CREAT, 0000"#);
    let meta = std::fs::metadata(rn.dir.join("z.txt")).unwrap();
    assert_eq!(std::os::unix::fs::PermissionsExt::mode(&meta.permissions()) & 0o7777, 0);
    // O_PATH: an fd that cannot be read
    let p = opened(&rn.call("openat", &json!({"path": ".", "flags": ["O_PATH"]})));
    assert_eq!(errno_of(&rn.call("read", &json!({"fd": p, "count": 1}))), "EBADF");
    // access mode 3 (O_WRONLY|O_RDWR) is accepted by Linux; neither read nor write works
    std::fs::write(rn.dir.join("m3"), b"x").unwrap();
    let o = rn.call("openat", &json!({"path": "m3", "flags": ["O_WRONLY", "O_RDWR"]}));
    let m3 = opened(&o);
    assert_eq!(args(&o), r#"AT_FDCWD, "m3", 0x3"#);
    assert_eq!(errno_of(&rn.call("read", &json!({"fd": m3, "count": 1}))), "EBADF");
    // bits without a name are passed on and shown in hex
    let o = rn.call("openat", &json!({"path": "m3", "flags": "O_RDONLY|0x40000000"}));
    opened(&o);
    assert_eq!(args(&o), r#"AT_FDCWD, "m3", O_RDONLY|0x40000000"#);
    // the sticky bit is fine for a directory we own
    ok(&rn.call("mkdirat", &json!({"path": "sticky", "mode": "01777"})));
    let meta = std::fs::metadata(rn.dir.join("sticky")).unwrap();
    assert_eq!(
        std::os::unix::fs::PermissionsExt::mode(&meta.permissions()) & 0o1000,
        0o1000
    );
    // path limits are the kernel's
    assert_eq!(errno_of(&rn.call("openat", &json!({"path": ""}))), "ENOENT");
    assert_eq!(
        errno_of(&rn.call("openat", &json!({"path": "x".repeat(300)}))),
        "ENAMETOOLONG"
    );
    assert_eq!(
        errno_of(&rn.call("openat", &json!({"path": "a/".repeat(3000)}))),
        "ENAMETOOLONG"
    );
}

#[test]
fn filesystem_errors() {
    let mut rn = Rn::start("fserr", &Policy::default());
    assert_eq!(errno_of(&rn.call("openat", &json!({"path": "missing.txt"}))), "ENOENT");
    assert_eq!(ok(&rn.call("mkdirat", &json!({"path": "d", "mode": "0755"}))), 0);
    assert!(rn.dir.join("d").is_dir());
    assert_eq!(errno_of(&rn.call("mkdirat", &json!({"path": "d"}))), "EEXIST");
    let abs = format!("{}/d/e", rn.dir.display());
    assert_eq!(ok(&rn.call("mkdirat", &json!({"path": abs}))), 0);
    assert!(rn.dir.join("d/e").is_dir());
    assert_eq!(
        errno_of(&rn.call("openat", &json!({"path": "d", "flags": ["O_WRONLY"]}))),
        "EISDIR"
    );
    ok(&rn.call(
        "openat",
        &json!({"path": "f", "flags": ["O_WRONLY", "O_CREAT"], "mode": "0644"}),
    ));
    assert_eq!(
        errno_of(&rn.call(
            "openat",
            &json!({"path": "f", "flags": ["O_WRONLY", "O_CREAT", "O_EXCL"], "mode": "0644"})
        )),
        "EEXIST"
    );
}

#[test]
fn dirfd_handles() {
    let mut rn = Rn::start("dirfd", &Policy::default());
    ok(&rn.call("mkdirat", &json!({"path": "sub"})));
    assert_eq!(
        opened(&rn.call("openat", &json!({"path": "sub", "flags": ["O_RDONLY", "O_DIRECTORY"]}))),
        3
    );
    assert_eq!(
        opened(&rn.call(
            "openat",
            &json!({"dirfd": 3, "path": "in.txt", "flags": ["O_WRONLY", "O_CREAT"], "mode": "0644"})
        )),
        4
    );
    assert!(rn.dir.join("sub/in.txt").exists());
    assert_eq!(ok(&rn.call("mkdirat", &json!({"dirfd": 3, "path": "deeper"}))), 0);
    assert!(rn.dir.join("sub/deeper").is_dir());
    // ".." from a dirfd is resolved by the kernel like for any process
    std::fs::write(rn.dir.join("top.txt"), b"top").unwrap();
    let h = opened(&rn.call("openat", &json!({"dirfd": 3, "path": "../top.txt"})));
    assert_eq!(read_data(&rn.call("read", &json!({"fd": h, "count": 10}))), b"top");
    // a regular-file handle is not a directory
    assert_eq!(
        errno_of(&rn.call("mkdirat", &json!({"dirfd": 4, "path": "x/y"}))),
        "ENOTDIR"
    );
    assert_eq!(errno_of(&rn.call("openat", &json!({"dirfd": 9, "path": "x"}))), "EBADF");
}

#[test]
fn paths_are_passed_to_the_kernel_verbatim() {
    let mut rn = Rn::start("paths", &Policy::default());
    std::fs::write(rn.dir.join("t.txt"), b"target").unwrap();
    std::os::unix::fs::symlink("t.txt", rn.dir.join("link")).unwrap();

    // absolute paths anywhere, "..", /proc: whatever the kernel allows
    let pw = opened(&rn.call("openat", &json!({"path": "/etc/passwd"})));
    assert!(read_data(&rn.call("read", &json!({"fd": pw, "count": 5}))).starts_with(b"root"));
    let st = opened(&rn.call("openat", &json!({"path": "/proc/self/status"})));
    assert!(read_data(&rn.call("read", &json!({"fd": st, "count": 5}))).starts_with(b"Name:"));
    let up = format!("../{}/t.txt", rn.dir.file_name().unwrap().to_str().unwrap());
    ok(&rn.call("openat", &json!({"path": up})));
    assert_eq!(
        errno_of(&rn.call("openat", &json!({"path": "/no/such/file"}))),
        "ENOENT"
    );

    // symlinks are followed unless the caller asks for O_NOFOLLOW
    let l = opened(&rn.call("openat", &json!({"path": "link"})));
    assert_eq!(read_data(&rn.call("read", &json!({"fd": l, "count": 10}))), b"target");
    assert_eq!(
        errno_of(&rn.call("openat", &json!({"path": "link", "flags": ["O_RDONLY", "O_NOFOLLOW"]}))),
        "ELOOP"
    );
    if let InvokeOutcome::Completed { issued, .. } = rn.call("openat", &json!({"path": "/etc/hostname"})) {
        assert_eq!(issued.len(), 1);
        assert_eq!(issued[0].args, r#"AT_FDCWD, "/etc/hostname", O_RDONLY"#);
    }
}

#[test]
fn emfile_comes_from_the_kernel() {
    let mut rn = Rn::start("limit", &Policy::default());
    std::fs::write(rn.dir.join("f"), b"").unwrap();
    // lower RLIMIT_NOFILE of the running runner to 16 (fds 0..15)
    let lim = libc::rlimit {
        rlim_cur: 16,
        rlim_max: 16,
    };
    // SAFETY: prlimit on our own child with a valid rlimit struct.
    assert_eq!(
        unsafe { libc::prlimit(rn.hello.pid, libc::RLIMIT_NOFILE, &raw const lim, std::ptr::null_mut()) },
        0
    );
    for fd in 3..16 {
        assert_eq!(opened(&rn.call("openat", &json!({"path": "f"}))), fd);
    }
    assert_eq!(errno_of(&rn.call("openat", &json!({"path": "f"}))), "EMFILE");
    ok(&rn.call("close", &json!({"fd": 10})));
    assert_eq!(opened(&rn.call("openat", &json!({"path": "f"}))), 10);
    // the IPC socket above the limit keeps working
    assert!(matches!(rn.op(RunnerOp::Ping), RunnerReplyBody::Pong));
}

#[test]
fn seccomp_denies_mkdirat_in_kernel() {
    let mut plain = Rn::start("nosec", &Policy::default());
    let base_filters = plain.seccomp_filters();
    assert_eq!(ok(&plain.call("mkdirat", &json!({"path": "test"}))), 0);

    let policy = Policy::from_user(&["mkdirat".into()], Some("EPERM")).unwrap();
    let mut rn = Rn::start("sec", &policy);
    assert!(rn.hello.seccomp_filter_installed);
    assert_eq!(
        rn.seccomp_filters(),
        base_filters + 1,
        "one extra kernel filter installed"
    );
    let o = rn.call("mkdirat", &json!({"path": "test"}));
    // the runner really issued mkdirat (no application-level branch) ...
    if let InvokeOutcome::Completed {
        requested_executed,
        issued,
        ..
    } = &o
    {
        assert!(*requested_executed);
        assert_eq!(issued.last().unwrap().syscall, "mkdirat");
    }
    // ... and the kernel answered EPERM
    assert_eq!(errno_of(&o), "EPERM");
    assert!(!rn.dir.join("test").exists());
    // other syscalls still work
    ok(&rn.call(
        "openat",
        &json!({"path": "x", "flags": ["O_WRONLY", "O_CREAT"], "mode": "0644"}),
    ));
}

#[test]
fn denying_io_syscalls_does_not_break_ipc() {
    let policy = Policy::from_user(
        &["read".into(), "write".into(), "close".into(), "getpid".into()],
        Some("EACCES"),
    )
    .unwrap();
    let mut rn = Rn::start("io", &policy);
    ok(&rn.call(
        "openat",
        &json!({"path": "x", "flags": ["O_RDWR", "O_CREAT"], "mode": "0644"}),
    ));
    assert_eq!(errno_of(&rn.call("write", &json!({"fd": 3, "data": "hi"}))), "EACCES");
    assert_eq!(errno_of(&rn.call("read", &json!({"fd": 3, "count": 1}))), "EACCES");
    assert_eq!(errno_of(&rn.call("getpid", &json!({}))), "EACCES");
    drop(rn);
    // any errno name the C library knows can be used
    let mut rn = Rn::start("eio", &Policy::from_user(&["getpid".into()], Some("EIO")).unwrap());
    assert_eq!(errno_of(&rn.call("getpid", &json!({}))), "EIO");
    drop(rn);
    let mut rn = Rn::start(
        "io2",
        &Policy::from_user(&["read".into(), "write".into(), "close".into()], Some("EACCES")).unwrap(),
    );
    ok(&rn.call(
        "openat",
        &json!({"path": "x", "flags": ["O_RDWR", "O_CREAT"], "mode": "0644"}),
    ));
    // close denied: the handle must survive (kernel did not release the fd)
    assert_eq!(errno_of(&rn.call("close", &json!({"fd": 3}))), "EACCES");
    if let RunnerReplyBody::Handles { handles } = rn.op(RunnerOp::ListHandles) {
        assert_eq!(handles.len(), 1);
    }
    ok(&rn.call("mkdirat", &json!({"path": "a"})));
    ok(&rn.call("mkdirat", &json!({"path": "a/b"})));
    assert!(matches!(rn.op(RunnerOp::Ping), RunnerReplyBody::Pong));
}

#[test]
fn denying_openat_keeps_mkdirat() {
    let policy = Policy::from_user(&["openat".into()], None).unwrap();
    let mut rn = Rn::start("noopen", &policy);
    assert_eq!(errno_of(&rn.call("openat", &json!({"path": "x"}))), "EPERM");
    ok(&rn.call("mkdirat", &json!({"path": "a"})));
    ok(&rn.call("mkdirat", &json!({"path": "a/b"})));
}

/// Field `n` (1-based) of `/proc/<pid>/stat`, counting after the `(comm)`.
fn stat_field(pid: i32, n: usize) -> i64 {
    let s = std::fs::read_to_string(format!("/proc/{pid}/stat")).unwrap();
    let after = &s[s.rfind(')').unwrap() + 2..];
    after.split(' ').nth(n - 3).unwrap().parse().unwrap()
}

#[test]
fn nice_is_set_raw_and_clamped_by_the_kernel() {
    let mut rn = Rn::start("nice", &Policy::default());
    let pid = rn.hello.pid;
    // the raw syscall returns 20 - nice
    assert_eq!(ok(&rn.call("getpriority", &json!({}))), 20 - stat_field(pid, 19));
    assert_eq!(ok(&rn.call("setpriority", &json!({"prio": 10}))), 0);
    assert_eq!(ok(&rn.call("getpriority", &json!({}))), 10);
    assert_eq!(stat_field(pid, 19), 10, "nice field of /proc/<pid>/stat");
    assert_eq!(stat_field(pid, 18), 30, "priority = 20 + nice");
    // out of range: no error, clamped to 19
    assert_eq!(
        ok(&rn.call(
            "setpriority",
            &json!({"which": "PRIO_PROCESS", "who": pid, "prio": 100})
        )),
        0
    );
    assert_eq!(ok(&rn.call("getpriority", &json!({"who": pid}))), 1);
    // lowering nice needs CAP_SYS_NICE (or RLIMIT_NICE)
    // SAFETY: geteuid cannot fail.
    if unsafe { libc::geteuid() } != 0 {
        assert_eq!(errno_of(&rn.call("setpriority", &json!({"prio": 0}))), "EACCES");
    }
    assert_eq!(errno_of(&rn.call("getpriority", &json!({"which": 9}))), "EINVAL");
    assert_eq!(errno_of(&rn.call("getpriority", &json!({"who": 999_999}))), "ESRCH");
}

#[test]
fn seccomp_denies_setpriority_in_kernel() {
    let policy = Policy::from_user(&["setpriority".into()], Some("EPERM")).unwrap();
    let mut rn = Rn::start("nicesec", &policy);
    assert_eq!(errno_of(&rn.call("setpriority", &json!({"prio": 5}))), "EPERM");
    assert_eq!(stat_field(rn.hello.pid, 19), 0, "nice unchanged");
    assert_eq!(ok(&rn.call("getpriority", &json!({}))), 20);
}
