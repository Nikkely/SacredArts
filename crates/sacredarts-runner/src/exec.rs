//! Execution of learning syscalls.
//!
//! Every requested syscall is issued with `libc::syscall(SYS_<name>, ...)`, so
//! the kernel sees exactly that syscall number (no libc wrapper substitutes a
//! different one), and a seccomp filter on that number applies.

//!
//! Paths are passed to the kernel exactly as requested: no rewriting, no
//! added flags, no confinement to /workspace. What a path may reach is
//! decided by the kernel (permissions, read-only root filesystem, ...) inside
//! the sandbox container, which is the security boundary.

use crate::errno;
use crate::handles::HandleTable;
use base64::Engine;
use sacredarts_core::format::{DISPLAY_BYTES, format_flags, format_mode, quote_bytes, quote_str};
use sacredarts_core::ipc::{HandleChange, InvokeOutcome, IssuedCall, IssuedPurpose};
use sacredarts_core::limits::{MARKER_PREFIX, MAX_HANDLES};
use sacredarts_core::{Dirfd, OpenFlag, SyscallRequest, ValidationError};
use std::ffi::CString;
use std::os::fd::RawFd;
use std::path::{Path, PathBuf};

pub struct Runner {
    /// Working directory of the runner; relative paths with `AT_FDCWD`
    /// resolve against it (used only to label handles).
    cwd: PathBuf,
    handles: HandleTable,
}

type Stop = ValidationError;

fn reject(code: &str, msg: impl Into<String>) -> Stop {
    ValidationError::new(code, msg)
}

/// Lexically join `base` and `path` for display (".." is kept as written;
/// the kernel, not this label, decides what was opened).
fn label(base: &str, path: &str) -> String {
    if path.starts_with('/') {
        path.to_string()
    } else if base.ends_with('/') {
        format!("{base}{path}")
    } else {
        format!("{base}/{path}")
    }
}

fn flag_bits(f: OpenFlag) -> libc::c_int {
    match f {
        OpenFlag::O_RDONLY => libc::O_RDONLY,
        OpenFlag::O_WRONLY => libc::O_WRONLY,
        OpenFlag::O_RDWR => libc::O_RDWR,
        OpenFlag::O_CREAT => libc::O_CREAT,
        OpenFlag::O_EXCL => libc::O_EXCL,
        OpenFlag::O_TRUNC => libc::O_TRUNC,
        OpenFlag::O_APPEND => libc::O_APPEND,
        OpenFlag::O_DIRECTORY => libc::O_DIRECTORY,
        OpenFlag::O_NOFOLLOW => libc::O_NOFOLLOW,
        OpenFlag::O_CLOEXEC => libc::O_CLOEXEC,
    }
}

/// Convert a raw `syscall(2)` return into (ret, errno).
#[allow(clippy::unnecessary_cast)] // c_long is i64 on all supported targets
fn result(ret: libc::c_long) -> (i64, Option<i32>) {
    if ret < 0 {
        (-1, Some(errno::last()))
    } else {
        (ret as i64, None)
    }
}

fn cstring(s: &str) -> Result<CString, Stop> {
    CString::new(s).map_err(|_| reject("invalid_path", "path contains a NUL byte"))
}

/// Issue the boundary marker `faccessat(AT_FDCWD, "/.sacredarts-marker/<kind>/<id>", F_OK)`.
/// It always fails with ENOENT and has no side effects; its only purpose is
/// to appear in the strace output so the supervisor can attribute lines.
pub fn marker(kind: &str, id: u64) {
    if let Ok(p) = CString::new(format!("{MARKER_PREFIX}{kind}/{id}")) {
        // SAFETY: `p` is a valid NUL-terminated string that outlives the call;
        // faccessat only reads it.
        unsafe {
            libc::syscall(libc::SYS_faccessat, libc::AT_FDCWD, p.as_ptr(), libc::F_OK);
        }
    }
}

impl Runner {
    pub fn new(cwd: &Path) -> Self {
        Self {
            cwd: cwd.to_path_buf(),
            handles: HandleTable::new(),
        }
    }

    pub fn handles(&self) -> &HandleTable {
        &self.handles
    }

    pub fn invoke(&mut self, req: &SyscallRequest) -> InvokeOutcome {
        if let Err(v) = req.validate() {
            return InvokeOutcome::Rejected {
                code: v.code,
                message: v.message,
            };
        }
        let mut issued = Vec::new();
        let r = match req {
            SyscallRequest::Getpid => Ok(self.getpid(&mut issued)),
            SyscallRequest::Openat {
                dirfd,
                path,
                flags,
                mode,
            } => self.openat(*dirfd, path, flags, *mode, &mut issued),
            SyscallRequest::Read { fd, count } => self.read(*fd, *count, &mut issued),
            SyscallRequest::Write { fd, data, count } => self.write(*fd, &data[..*count], &mut issued),
            SyscallRequest::Close { fd } => self.close(*fd, &mut issued),
            SyscallRequest::Mkdirat { dirfd, path, mode } => self.mkdirat(*dirfd, path, *mode, &mut issued),
        };
        match r {
            Ok(c) => c,
            Err(v) => InvokeOutcome::Rejected {
                code: v.code,
                message: v.message,
            },
        }
    }

    fn completed(ret: (i64, Option<i32>), issued: Vec<IssuedCall>) -> InvokeOutcome {
        InvokeOutcome::Completed {
            requested_executed: true,
            ret: ret.0,
            errno: ret.1.map(errno::info),
            issued,
            handle_change: None,
            read_data_b64: None,
            notes: vec![],
        }
    }

    fn issue(issued: &mut Vec<IssuedCall>, syscall: &str, purpose: IssuedPurpose, args: String, r: (i64, Option<i32>)) {
        issued.push(IssuedCall {
            syscall: syscall.to_string(),
            purpose,
            args,
            ret: r.0,
            errno: r.1.map(|e| errno::name(e).to_string()),
        });
    }

    fn getpid(&mut self, issued: &mut Vec<IssuedCall>) -> InvokeOutcome {
        // SAFETY: getpid takes no arguments and cannot fail.
        let r = result(unsafe { libc::syscall(libc::SYS_getpid) });
        Self::issue(issued, "getpid", IssuedPurpose::Requested, String::new(), r);
        Self::completed(r, std::mem::take(issued))
    }

    fn handle_fd(&self, h: u32) -> Result<(RawFd, String), Stop> {
        self.handles.get(h).map(|i| (i.real_fd, i.path.clone())).ok_or_else(|| {
            reject(
                "bad_handle",
                format!(
                    "handle {h} is not open in this session (Linux would report EBADF). \
                     Learning handles are created by openat; see sandbox_inspect"
                ),
            )
        })
    }

    /// The dirfd argument as passed to the kernel, plus a display label.
    fn dirfd(&self, dirfd: Dirfd) -> Result<(RawFd, String, String), Stop> {
        match dirfd {
            Dirfd::AtFdcwd => Ok((libc::AT_FDCWD, "AT_FDCWD".into(), self.cwd.display().to_string())),
            Dirfd::Handle(h) => {
                let (fd, path) = self.handle_fd(h)?;
                Ok((fd, format!("{fd}<{path}>"), path))
            }
        }
    }

    fn openat(
        &mut self,
        dirfd: Dirfd,
        path: &str,
        flags: &[OpenFlag],
        mode: Option<u32>,
        issued: &mut Vec<IssuedCall>,
    ) -> Result<InvokeOutcome, Stop> {
        if self.handles.is_full() {
            return Err(reject(
                "limit_exceeded",
                format!("at most {MAX_HANDLES} handles may be open; close some first"),
            ));
        }
        let (fd, shown, base) = self.dirfd(dirfd)?;
        let c = cstring(path)?;
        let bits = flags.iter().fold(0, |acc, f| acc | flag_bits(*f));
        let m = mode.unwrap_or(0);
        // SAFETY: `c` is a valid NUL-terminated path; `fd` is AT_FDCWD or a
        // descriptor owned by the handle table.
        let r = result(unsafe { libc::syscall(libc::SYS_openat, fd, c.as_ptr(), bits, m as libc::c_uint) });
        let mut args = format!("{shown}, {}, {}", quote_str(path), format_flags(flags));
        if mode.is_some() {
            args.push_str(&format!(", {}", format_mode(m)));
        }
        Self::issue(issued, "openat", IssuedPurpose::Requested, args, r);

        let mut out = Self::completed(r, std::mem::take(issued));
        if r.1.is_none() {
            let real_fd = r.0 as RawFd;
            match self.handles.insert(real_fd, label(&base, path), flags.to_vec()) {
                Some(info) => {
                    if let InvokeOutcome::Completed { handle_change, .. } = &mut out {
                        *handle_change = Some(HandleChange::Opened { info });
                    }
                }
                None => {
                    // Unreachable in practice (checked above); never leak the fd.
                    // SAFETY: real_fd was just opened by us and is not shared.
                    unsafe { libc::syscall(libc::SYS_close_range, real_fd as u32, real_fd as u32, 0u32) };
                    return Err(reject("limit_exceeded", "handle table is full"));
                }
            }
        }
        Ok(out)
    }

    fn read(&mut self, h: u32, count: usize, issued: &mut Vec<IssuedCall>) -> Result<InvokeOutcome, Stop> {
        let (fd, path) = self.handle_fd(h)?;
        let mut buf = vec![0u8; count];
        // SAFETY: `buf` has exactly `count` writable bytes and outlives the call.
        let r = result(unsafe { libc::syscall(libc::SYS_read, fd, buf.as_mut_ptr(), count) });
        let shown = if r.1.is_none() {
            quote_bytes(&buf[..r.0 as usize], DISPLAY_BYTES)
        } else {
            "<buf>".to_string()
        };
        Self::issue(
            issued,
            "read",
            IssuedPurpose::Requested,
            format!("{fd}<{path}>, {shown}, {count}"),
            r,
        );
        let mut out = Self::completed(r, std::mem::take(issued));
        if r.1.is_none()
            && let InvokeOutcome::Completed { read_data_b64, .. } = &mut out
        {
            *read_data_b64 = Some(base64::engine::general_purpose::STANDARD.encode(&buf[..r.0 as usize]));
        }
        Ok(out)
    }

    fn write(&mut self, h: u32, data: &[u8], issued: &mut Vec<IssuedCall>) -> Result<InvokeOutcome, Stop> {
        let (fd, path) = self.handle_fd(h)?;
        // SAFETY: `data` is a valid readable slice for the duration of the call.
        let r = result(unsafe { libc::syscall(libc::SYS_write, fd, data.as_ptr(), data.len()) });
        Self::issue(
            issued,
            "write",
            IssuedPurpose::Requested,
            format!("{fd}<{path}>, {}, {}", quote_bytes(data, DISPLAY_BYTES), data.len()),
            r,
        );
        // A short write is reported as-is; the runner never loops to "fix" it.
        Ok(Self::completed(r, std::mem::take(issued)))
    }

    fn close(&mut self, h: u32, issued: &mut Vec<IssuedCall>) -> Result<InvokeOutcome, Stop> {
        let (fd, path) = self.handle_fd(h)?;
        // SAFETY: `fd` belongs to the handle table; on success we drop the entry.
        let r = result(unsafe { libc::syscall(libc::SYS_close, fd) });
        Self::issue(issued, "close", IssuedPurpose::Requested, format!("{fd}<{path}>"), r);
        let gone = if r.1.is_none() {
            true
        } else {
            // On Linux close() releases the fd even when it reports an error,
            // except when the syscall never ran (e.g. denied by seccomp).
            // Ask the kernel instead of guessing.
            // SAFETY: F_GETFD only queries descriptor flags.
            let probe = result(unsafe { libc::syscall(libc::SYS_fcntl, fd, libc::F_GETFD) });
            Self::issue(
                issued,
                "fcntl",
                IssuedPurpose::StateCheck,
                format!("{fd}, F_GETFD"),
                probe,
            );
            probe.1 == Some(libc::EBADF)
        };
        let mut out = Self::completed(r, std::mem::take(issued));
        if gone
            && let Some(info) = self.handles.remove(h)
            && let InvokeOutcome::Completed { handle_change, .. } = &mut out
        {
            *handle_change = Some(HandleChange::Closed { info });
        }
        Ok(out)
    }

    fn mkdirat(
        &mut self,
        dirfd: Dirfd,
        path: &str,
        mode: u32,
        issued: &mut Vec<IssuedCall>,
    ) -> Result<InvokeOutcome, Stop> {
        let (fd, shown, _) = self.dirfd(dirfd)?;
        let c = cstring(path)?;
        // SAFETY: `c` is a valid NUL-terminated path; `fd` is AT_FDCWD or a valid dirfd.
        let r = result(unsafe { libc::syscall(libc::SYS_mkdirat, fd, c.as_ptr(), mode as libc::c_uint) });
        Self::issue(
            issued,
            "mkdirat",
            IssuedPurpose::Requested,
            format!("{shown}, {}, {}", quote_str(path), format_mode(mode)),
            r,
        );
        Ok(Self::completed(r, std::mem::take(issued)))
    }
}
