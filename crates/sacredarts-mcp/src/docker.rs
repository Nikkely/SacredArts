//! Docker backend.
//!
//! Only the fixed operations below are ever executed. No option, image name
//! or argument comes from the AI; the only per-session values are the
//! server-generated container name and labels.

use crate::config::Config;
use crate::errors::ToolError;
use sacredarts_core::ipc::{HostMessage, SupervisorMessage};
use sacredarts_core::limits::MAX_IPC_LINE_BYTES;
use std::collections::VecDeque;
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, ChildStdin, ChildStdout, Command};

pub const LABEL_MANAGED: &str = "io.sacredarts.managed";
pub const LABEL_SESSION: &str = "io.sacredarts.session";
pub const LABEL_HOST_PID: &str = "io.sacredarts.host-pid";

/// UID/GID of the unprivileged sandbox user (created in the Dockerfile).
const SANDBOX_UID: u32 = 10001;

#[derive(Clone)]
pub struct Docker {
    cfg: Config,
}

/// Map docker CLI stderr to a precise infrastructure error.
pub fn classify(stderr: &str, image: &str) -> ToolError {
    let s = stderr.to_lowercase();
    if s.contains("cannot connect to the docker daemon")
        || s.contains("is the docker daemon running")
        || s.contains("error during connect")
        || s.contains("docker desktop is not running")
        || s.contains("connect: no such file or directory")
        || s.contains("connection refused")
    {
        ToolError::infra(
            "docker_unavailable",
            "Docker is not running or not reachable. Start Docker Desktop and try again.",
        )
        .details(serde_json::json!({ "docker_stderr": stderr.trim() }))
    } else if s.contains("no such image") || s.contains("unable to find image") || s.contains("pull access denied") {
        ToolError::infra(
            "image_missing",
            format!(
                "sandbox image {image} is not built. Run `docker build -t {image} .` in the SacredArts repository."
            ),
        )
    } else {
        ToolError::infra("docker_error", format!("docker failed: {}", stderr.trim()))
    }
}

impl Docker {
    pub fn new(cfg: Config) -> Self {
        Docker { cfg }
    }

    /// `Command`'s builder methods take `&mut self`, so the command is
    /// configured in place.
    fn cmd(&self) -> Command {
        let mut c = Command::new(&self.cfg.docker_bin);
        c.stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        c
    }

    async fn run(&self, args: &[&str], timeout: Duration) -> Result<String, ToolError> {
        let out = match tokio::time::timeout(timeout, self.cmd().args(args).output()).await {
            Err(_) => {
                return Err(ToolError::infra(
                    "docker_timeout",
                    format!(
                        "`docker {}` did not finish within {}s",
                        args.first().unwrap_or(&""),
                        timeout.as_secs()
                    ),
                ));
            }
            Ok(Err(e)) => {
                return Err(ToolError::infra(
                    "docker_unavailable",
                    format!("cannot execute docker CLI at {}: {e}", self.cfg.docker_bin.display()),
                ));
            }
            Ok(Ok(o)) => o,
        };
        if out.status.success() {
            Ok(String::from_utf8_lossy(&out.stdout).into_owned())
        } else {
            Err(classify(&String::from_utf8_lossy(&out.stderr), &self.cfg.image))
        }
    }

    /// Daemon reachable and image present.
    pub async fn preflight(&self) -> Result<(), ToolError> {
        self.run(&["version", "--format", "{{.Server.Version}}"], Duration::from_secs(15))
            .await?;
        self.run(
            &["image", "inspect", "--format", "{{.Id}}", &self.cfg.image],
            Duration::from_secs(15),
        )
        .await
        .map_err(|e| {
            if e.code == "docker_unavailable" {
                e
            } else {
                classify("No such image", &self.cfg.image)
            }
        })?;
        Ok(())
    }

    /// The fixed, hardened `docker run` argument list.
    pub fn run_args(&self, name: &str, session_id: &str) -> Vec<String> {
        let tmpfs = |path: &str| {
            format!("{path}:rw,nosuid,nodev,noexec,size=16m,uid={SANDBOX_UID},gid={SANDBOX_UID},mode=0700")
        };
        vec![
            "run".into(),
            "-i".into(), // stdin/stdout = IPC with the supervisor; no ports are published
            "--rm".into(),
            "--pull".into(),
            "never".into(),
            "--name".into(),
            name.into(),
            "--label".into(),
            format!("{LABEL_MANAGED}=true"),
            "--label".into(),
            format!("{LABEL_SESSION}={session_id}"),
            "--label".into(),
            format!("{LABEL_HOST_PID}={}", std::process::id()),
            "--hostname".into(),
            "sacredarts".into(),
            "--network".into(),
            "none".into(),
            "--ipc".into(),
            "none".into(),
            "--read-only".into(),
            "--tmpfs".into(),
            tmpfs("/workspace"),
            "--tmpfs".into(),
            tmpfs("/tmp"),
            "--user".into(),
            format!("{SANDBOX_UID}:{SANDBOX_UID}"),
            "--cap-drop".into(),
            "ALL".into(),
            "--security-opt".into(),
            "no-new-privileges".into(),
            "--cpus".into(),
            "0.5".into(),
            "--memory".into(),
            "128m".into(),
            "--memory-swap".into(),
            "128m".into(),
            "--pids-limit".into(),
            "32".into(),
            "--ulimit".into(),
            "nofile=256:256".into(),
            "--ulimit".into(),
            "core=0".into(),
            "--log-driver".into(),
            "none".into(),
            "--init".into(),
            self.cfg.image.clone(),
        ]
    }

    pub async fn spawn_sandbox(&self, name: &str, session_id: &str) -> Result<SupervisorConn, ToolError> {
        let mut child = self
            .cmd()
            .args(self.run_args(name, session_id))
            .stdin(Stdio::piped())
            .spawn()
            .map_err(|e| ToolError::infra("docker_unavailable", format!("cannot execute docker CLI: {e}")))?;
        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| ToolError::infra("ipc_failed", "no stdin"))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| ToolError::infra("ipc_failed", "no stdout"))?;
        let stderr_tail = Arc::new(Mutex::new(VecDeque::<String>::new()));
        if let Some(err) = child.stderr.take() {
            let tail = stderr_tail.clone();
            let sid = session_id.to_string();
            tokio::spawn(async move {
                let mut lines = BufReader::new(err).lines();
                while let Ok(Some(l)) = lines.next_line().await {
                    tracing::debug!(session = %sid, "sandbox: {l}");
                    if let Ok(mut t) = tail.lock() {
                        if t.len() >= 30 {
                            t.pop_front();
                        }
                        t.push_back(l);
                    }
                }
            });
        }
        Ok(SupervisorConn {
            child,
            stdin,
            stdout: BufReader::new(stdout),
            stderr_tail,
            image: self.cfg.image.clone(),
        })
    }

    /// Idempotent forced removal.
    pub async fn remove(&self, name: &str) {
        match self.run(&["rm", "-f", name], Duration::from_secs(20)).await {
            Ok(_) => {}
            Err(e) if e.message.contains("No such container") => {}
            Err(e) => tracing::warn!("docker rm -f {name}: {e}"),
        }
    }

    /// (container name, host pid label) of every SacredArts container.
    pub async fn list_managed(&self) -> Result<Vec<(String, Option<i32>)>, ToolError> {
        let out = self
            .run(
                &[
                    "ps",
                    "-a",
                    "--filter",
                    &format!("label={LABEL_MANAGED}=true"),
                    "--format",
                    &format!("{{{{.Names}}}}\t{{{{.Label \"{LABEL_HOST_PID}\"}}}}"),
                ],
                Duration::from_secs(15),
            )
            .await?;
        Ok(out
            .lines()
            .filter_map(|l| {
                let (n, p) = l.split_once('\t').unwrap_or((l, ""));
                (!n.trim().is_empty()).then(|| (n.trim().to_string(), p.trim().parse().ok()))
            })
            .collect())
    }
}

pub struct SupervisorConn {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
    stderr_tail: Arc<Mutex<VecDeque<String>>>,
    image: String,
}

impl SupervisorConn {
    pub fn stderr_text(&self) -> String {
        self.stderr_tail
            .lock()
            .map(|t| t.iter().cloned().collect::<Vec<_>>().join("\n"))
            .unwrap_or_default()
    }

    /// Turn a dead channel into the most specific error available.
    async fn dead(&mut self, what: &str) -> ToolError {
        // give the stderr reader a moment to collect docker's message
        tokio::time::sleep(Duration::from_millis(150)).await;
        let stderr = self.stderr_text();
        if !stderr.trim().is_empty() && !stderr.contains("[sacredarts-supervisor]") {
            return match classify(&stderr, &self.image) {
                e if e.code == "docker_error" => {
                    ToolError::infra("sandbox_terminated", format!("{what}; docker: {}", stderr.trim()))
                }
                e => e,
            };
        }
        ToolError::infra(
            "sandbox_terminated",
            format!("{what}; the sandbox container has exited"),
        )
        .details(serde_json::json!({ "sandbox_stderr": stderr }))
    }

    pub async fn send(&mut self, msg: &HostMessage) -> Result<(), ToolError> {
        let json = serde_json::to_string(msg).map_err(|e| ToolError::infra("ipc_failed", e.to_string()))?;
        if let Err(e) = self.stdin.write_all(format!("{json}\n").as_bytes()).await {
            return Err(self.dead(&format!("writing to the sandbox failed: {e}")).await);
        }
        if let Err(e) = self.stdin.flush().await {
            return Err(self.dead(&format!("writing to the sandbox failed: {e}")).await);
        }
        Ok(())
    }

    /// Next protocol message, or an error on EOF / timeout.
    pub async fn recv(&mut self, timeout: Duration) -> Result<SupervisorMessage, ToolError> {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            let mut line = String::new();
            let mut limited = (&mut self.stdout).take(MAX_IPC_LINE_BYTES as u64);
            let read = limited.read_line(&mut line);
            match tokio::time::timeout_at(deadline, read).await {
                Err(_) => {
                    return Err(ToolError::new(
                        crate::errors::ErrorKind::Timeout,
                        "ipc_timeout",
                        format!("the sandbox did not answer within {}s", timeout.as_secs()),
                    ));
                }
                Ok(Err(e)) => return Err(self.dead(&format!("reading from the sandbox failed: {e}")).await),
                Ok(Ok(0)) => return Err(self.dead("the sandbox closed the connection").await),
                Ok(Ok(_)) => match serde_json::from_str::<SupervisorMessage>(line.trim()) {
                    Ok(m) => return Ok(m),
                    Err(e) => {
                        tracing::warn!("ignoring malformed line from sandbox: {e}");
                        continue;
                    }
                },
            }
        }
    }

    /// Send a request with id `id` and wait for the reply with that id.
    pub async fn call(
        &mut self,
        msg: &HostMessage,
        id: u64,
        timeout: Duration,
    ) -> Result<SupervisorMessage, ToolError> {
        self.send(msg).await?;
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            let left = deadline.saturating_duration_since(tokio::time::Instant::now());
            let m = self.recv(left).await?;
            if m.id() == Some(id) {
                return Ok(m);
            }
            tracing::warn!("discarding unexpected sandbox message {:?}", m.id());
        }
    }

    pub async fn kill(&mut self) {
        let _ = self.child.start_kill();
        let _ = tokio::time::timeout(Duration::from_secs(5), self.child.wait()).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hardened_run_args() {
        let d = Docker::new(Config::from_env());
        let a = d.run_args("sacredarts-x", "sid").join(" ");
        for needle in [
            "--network none",
            "--read-only",
            "--cap-drop ALL",
            "--security-opt no-new-privileges",
            "--user 10001:10001",
            "--pids-limit 32",
            "--memory 128m",
            "--cpus 0.5",
            "--rm",
            "--pull never",
            "io.sacredarts.managed=true",
        ] {
            assert!(a.contains(needle), "missing {needle}");
        }
        for forbidden in [
            "--privileged",
            "docker.sock",
            "seccomp=unconfined",
            "-p ",
            "--publish",
            "-v ",
            "--volume",
            "--cap-add",
        ] {
            assert!(!a.contains(forbidden), "must not contain {forbidden}");
        }
    }

    #[test]
    fn classifies_docker_errors() {
        assert_eq!(
            classify(
                "Cannot connect to the Docker daemon at unix:///x.sock. Is the docker daemon running?",
                "img"
            )
            .code,
            "docker_unavailable"
        );
        assert_eq!(
            classify("Unable to find image 'img' locally", "img").code,
            "image_missing"
        );
        assert_eq!(classify("something else", "img").code, "docker_error");
    }
}
