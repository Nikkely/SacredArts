//! `sacredarts-runner --workspace <dir> --policy <json>`
//!
//! fd 0 must be a connected AF_UNIX stream socket to the supervisor.
//! Start-up order matters because seccomp filters are irreversible:
//!
//! 0. move the socket to the highest allowed fd and put /dev/null on fd 0, so
//!    fds 0-2 look like any process's stdio and new files start at fd 3
//! 1. cache the pid (the policy may deny `getpid`)
//! 2. install the seccomp filter (if the policy is non-empty)
//! 3. emit the `ready` marker and send the hello line
//! 4. serve requests until EOF

#[cfg(target_os = "linux")]
fn main() {
    std::process::exit(linux::run());
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("sacredarts-runner only runs on Linux (inside the SacredArts sandbox container)");
    std::process::exit(2);
}

#[cfg(target_os = "linux")]
mod linux {
    use sacredarts_core::Policy;
    use sacredarts_core::ipc::{RunnerHello, RunnerOp, RunnerReply, RunnerReplyBody, RunnerRequest};
    use sacredarts_runner::exec::{Runner, marker};
    use sacredarts_runner::sockio::SockIo;
    use std::path::PathBuf;

    struct Args {
        workspace: PathBuf,
        policy: Policy,
    }

    fn parse_args() -> Result<Args, String> {
        let mut workspace = PathBuf::from(sacredarts_core::limits::WORKSPACE_ROOT);
        let mut policy = Policy::default();
        let mut it = std::env::args().skip(1);
        while let Some(a) = it.next() {
            match a.as_str() {
                "--workspace" => workspace = it.next().ok_or("--workspace needs a value")?.into(),
                "--policy" => {
                    let v = it.next().ok_or("--policy needs a value")?;
                    policy = serde_json::from_str(&v).map_err(|e| format!("bad --policy: {e}"))?;
                }
                other => return Err(format!("unknown argument {other:?}")),
            }
        }
        Ok(Args { workspace, policy })
    }

    /// Move the supervisor socket from fd 0 to the top of the fd range
    /// (RLIMIT_NOFILE - 1) and replace fd 0 with /dev/null. Returns the
    /// socket's fd (0 if it could not be moved).
    fn move_ipc_socket() -> i32 {
        let mut lim = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // SAFETY: getrlimit writes into `lim`.
        let top = if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut lim) } == 0 {
            lim.rlim_cur.min(1 << 20) as i32 - 1
        } else {
            255
        };
        // SAFETY: plain fd duplication / replacement on fds this process owns.
        unsafe {
            let fd = libc::fcntl(0, libc::F_DUPFD_CLOEXEC, top.max(3));
            if fd < 0 {
                return 0;
            }
            let null = libc::open(c"/dev/null".as_ptr(), libc::O_RDWR | libc::O_CLOEXEC);
            if null >= 0 {
                libc::dup2(null, 0);
                libc::close(null);
            }
            fd
        }
    }

    pub fn run() -> i32 {
        let args = match parse_args() {
            Ok(a) => a,
            Err(e) => {
                eprintln!("sacredarts-runner: {e}");
                return 2;
            }
        };
        // The working directory is set by the supervisor; relative paths with
        // AT_FDCWD resolve against it, exactly as for any Linux process.
        let cwd = std::env::current_dir().unwrap_or_else(|_| args.workspace.clone());
        let ipc_fd = move_ipc_socket();
        let mut runner = Runner::new(&cwd, ipc_fd);
        // SAFETY: getpid has no preconditions. Cached before seccomp because the
        // policy may deny getpid.
        let pid = unsafe { libc::syscall(libc::SYS_getpid) } as i32;
        let installed = match sacredarts_policy::apply(&args.policy) {
            Ok(b) => b,
            Err(e) => {
                eprintln!("sacredarts-runner: {e}");
                return 1;
            }
        };
        let mut io = SockIo::new(ipc_fd);
        marker("ready", 0);
        let hello = RunnerHello {
            pid,
            arch: std::env::consts::ARCH.to_string(),
            policy: args.policy.clone(),
            seccomp_filter_installed: installed,
            workspace: args.workspace.display().to_string(),
        };
        if io
            .send_line(&serde_json::to_string(&hello).unwrap_or_default())
            .is_err()
        {
            return 1;
        }
        loop {
            let line = match io.recv_line() {
                Ok(Some(l)) => l,
                Ok(None) => return 0, // supervisor closed the socket
                Err(e) => {
                    eprintln!("sacredarts-runner: ipc error: {e}");
                    return 1;
                }
            };
            let reply = match serde_json::from_str::<RunnerRequest>(&line) {
                Ok(req) => {
                    let body = match req.op {
                        RunnerOp::Invoke { request } => {
                            marker("begin", req.id);
                            let outcome = runner.invoke(&request);
                            marker("end", req.id);
                            RunnerReplyBody::Invoked { outcome }
                        }
                        RunnerOp::ListHandles => RunnerReplyBody::Handles {
                            handles: runner.handles().list(),
                        },
                        RunnerOp::Ping => RunnerReplyBody::Pong,
                    };
                    RunnerReply { id: req.id, body }
                }
                Err(e) => RunnerReply {
                    id: 0,
                    body: RunnerReplyBody::Error {
                        message: format!("bad request: {e}"),
                    },
                },
            };
            let s = serde_json::to_string(&reply)
                .unwrap_or_else(|e| format!(r#"{{"id":{},"reply":"error","message":"serialize: {e}"}}"#, reply.id));
            if io.send_line(&s).is_err() {
                return 1;
            }
        }
    }
}
