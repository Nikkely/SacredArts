//! Execution of learning syscalls.
//!
//! Every requested syscall is issued with `libc::syscall(SYS_<name>, ...)`, so
//! the kernel sees exactly that syscall number (no libc wrapper substitutes a
//! different one), and a seccomp filter on that number applies.

//!
//! Arguments are passed to the kernel exactly as requested: paths are not
//! rewritten or confined, flags and modes are not filtered, and any fd number
//! reaches the kernel (EBADF, EMFILE, ENAMETOOLONG, ... come from there).
//! The kernel inside the sandbox container is the security boundary. The one
//! exception is the runner's own IPC socket, which keeps the session alive.

use crate::errno;
use crate::handles::HandleTable;
use base64::Engine;
use sacredarts_core::format::{DISPLAY_BYTES, format_mode, quote_bytes, quote_str};
use sacredarts_core::ipc::{HandleChange, InvokeOutcome, IssuedCall, IssuedPurpose};
use sacredarts_core::limits::MARKER_PREFIX;
use sacredarts_core::{DecodedFlags, Dirfd, OpenFlag, SyscallRequest, ValidationError};
use std::ffi::CString;
use std::os::fd::RawFd;
use std::path::{Path, PathBuf};
use strum::IntoEnumIterator;

pub struct Runner {
    /// Working directory of the runner; relative paths with `AT_FDCWD`
    /// resolve against it (used only to label handles).
    cwd: PathBuf,
    handles: HandleTable,
    /// The runner's socket to the supervisor (see `main.rs`).
    ipc_fd: RawFd,
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
        OpenFlag::O_NOCTTY => libc::O_NOCTTY,
        OpenFlag::O_TRUNC => libc::O_TRUNC,
        OpenFlag::O_APPEND => libc::O_APPEND,
        OpenFlag::O_NONBLOCK => libc::O_NONBLOCK,
        OpenFlag::O_NDELAY => libc::O_NDELAY,
        OpenFlag::O_DSYNC => libc::O_DSYNC,
        OpenFlag::O_SYNC => libc::O_SYNC,
        OpenFlag::O_RSYNC => libc::O_RSYNC,
        OpenFlag::O_ASYNC => libc::O_ASYNC,
        OpenFlag::O_DIRECT => libc::O_DIRECT,
        OpenFlag::O_LARGEFILE => libc::O_LARGEFILE,
        OpenFlag::O_DIRECTORY => libc::O_DIRECTORY,
        OpenFlag::O_NOFOLLOW => libc::O_NOFOLLOW,
        OpenFlag::O_NOATIME => libc::O_NOATIME,
        OpenFlag::O_CLOEXEC => libc::O_CLOEXEC,
        OpenFlag::O_PATH => libc::O_PATH,
        OpenFlag::O_TMPFILE => libc::O_TMPFILE,
    }
}

/// Decode open flags the way strace does: the access mode, the named bits
/// (multi-bit flags such as O_TMPFILE and O_SYNC first), then the rest.
pub fn decode_flags(bits: libc::c_int) -> DecodedFlags {
    // Multi-bit flags first; an alias (O_NDELAY, O_RSYNC) never matches
    // because its canonical name comes first and clears the bits.
    let named = || OpenFlag::iter().filter(|f| !f.is_access_mode());
    let multi_bit_first = named()
        .filter(|f| flag_bits(*f).count_ones() > 1)
        .chain(named().filter(|f| flag_bits(*f).count_ones() <= 1));
    let (named, rest) = multi_bit_first.fold((Vec::new(), bits & !libc::O_ACCMODE), |(mut names, rest), f| {
        let v = flag_bits(f);
        if v != 0 && rest & v == v {
            names.push(f);
            (names, rest & !v)
        } else {
            (names, rest)
        }
    });
    DecodedFlags {
        access_mode: (bits & libc::O_ACCMODE) as u32,
        named,
        unnamed: rest as u32,
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
    pub fn new(cwd: &Path, ipc_fd: RawFd) -> Self {
        Self {
            cwd: cwd.to_path_buf(),
            handles: HandleTable::new(),
            ipc_fd,
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
        let r = match req {
            SyscallRequest::Getpid => Ok(self.getpid()),
            SyscallRequest::Openat {
                dirfd,
                path,
                flags,
                raw_flags,
                mode,
            } => self.openat(*dirfd, path, flags, *raw_flags, *mode),
            SyscallRequest::Read { fd, count } => self.read(*fd, *count),
            SyscallRequest::Write { fd, data, count } => self.write(*fd, &data[..*count]),
            SyscallRequest::Close { fd } => self.close(*fd),
            SyscallRequest::Mkdirat { dirfd, path, mode } => self.mkdirat(*dirfd, path, *mode),
        };
        r.unwrap_or_else(|v| InvokeOutcome::Rejected {
            code: v.code,
            message: v.message,
        })
    }

    fn completed(
        ret: (i64, Option<i32>),
        issued: Vec<IssuedCall>,
        handle_change: Option<HandleChange>,
        read_data: Option<&[u8]>,
        open_flags: Option<DecodedFlags>,
    ) -> InvokeOutcome {
        InvokeOutcome::Completed {
            requested_executed: true,
            ret: ret.0,
            errno: ret.1.map(errno::info),
            issued,
            handle_change,
            read_data_b64: read_data.map(|d| base64::engine::general_purpose::STANDARD.encode(d)),
            notes: vec![],
            open_flags,
        }
    }

    /// The single requested call, with nothing else to report.
    fn plain(syscall: &str, args: String, r: (i64, Option<i32>)) -> InvokeOutcome {
        Self::completed(
            r,
            vec![call(syscall, IssuedPurpose::Requested, args, r)],
            None,
            None,
            None,
        )
    }

    fn getpid(&mut self) -> InvokeOutcome {
        // SAFETY: getpid takes no arguments and cannot fail.
        let r = result(unsafe { libc::syscall(libc::SYS_getpid) });
        Self::plain("getpid", String::new(), r)
    }

    /// Any fd goes to the kernel, except the runner's IPC socket: using it
    /// would cut this session off from the supervisor.
    fn fd(&self, fd: i32) -> Result<(RawFd, String), Stop> {
        if fd == self.ipc_fd {
            return Err(reject(
                "reserved_fd",
                format!(
                    "fd {fd} is the runner's socket to the SacredArts supervisor; using it would break this \
                     session, so it is not passed to the kernel. Every other fd number is."
                ),
            ));
        }
        let shown = match self.handles.get(fd) {
            Some(i) => format!("{fd}<{}>", i.path),
            None => fd.to_string(),
        };
        Ok((fd, shown))
    }

    /// The dirfd argument as passed to the kernel, a display label, and the
    /// directory path (if known) used to label the new fd.
    fn dirfd(&self, dirfd: Dirfd) -> Result<(RawFd, String, Option<String>), Stop> {
        match dirfd {
            Dirfd::AtFdcwd => Ok((libc::AT_FDCWD, "AT_FDCWD".into(), Some(self.cwd.display().to_string()))),
            Dirfd::Fd(n) => {
                let (fd, shown) = self.fd(n)?;
                Ok((fd, shown, self.handles.get(n).map(|i| i.path.clone())))
            }
        }
    }

    fn openat(
        &mut self,
        dirfd: Dirfd,
        path: &str,
        flags: &[OpenFlag],
        raw_flags: u32,
        mode: Option<u32>,
    ) -> Result<InvokeOutcome, Stop> {
        let (fd, shown, base) = self.dirfd(dirfd)?;
        let c = cstring(path)?;
        let bits = flags
            .iter()
            .fold(raw_flags as libc::c_int, |acc, f| acc | flag_bits(*f));
        // Without a mode argument C passes whatever is in the register; we pass 0.
        let m = mode.unwrap_or(0);
        // SAFETY: `c` is a valid NUL-terminated path; the kernel validates `fd`.
        let r = result(unsafe { libc::syscall(libc::SYS_openat, fd, c.as_ptr(), bits, m as libc::c_uint) });
        let decoded = decode_flags(bits);
        let uses_mode = bits & libc::O_CREAT != 0 || bits & libc::O_TMPFILE == libc::O_TMPFILE;
        let mode_arg = if mode.is_some() || uses_mode {
            format!(", {}", format_mode(m))
        } else {
            String::new()
        };
        let args = format!("{shown}, {}, {decoded}{mode_arg}", quote_str(path));
        let issued = vec![call("openat", IssuedPurpose::Requested, args, r)];
        let opened = r.1.is_none().then(|| {
            let label = base.map(|b| label(&b, path)).unwrap_or_else(|| path.to_string());
            HandleChange::Opened {
                info: self.handles.insert(r.0 as RawFd, label, decoded.to_string()),
            }
        });
        Ok(Self::completed(r, issued, opened, None, Some(decoded)))
    }

    fn read(&mut self, fd: i32, count: usize) -> Result<InvokeOutcome, Stop> {
        let (fd, shown_fd) = self.fd(fd)?;
        // The kernel writes into this buffer, so it has to be mutable.
        let mut buf = vec![0u8; count];
        // SAFETY: `buf` has exactly `count` writable bytes and outlives the call.
        let r = result(unsafe { libc::syscall(libc::SYS_read, fd, buf.as_mut_ptr(), count) });
        let data = r.1.is_none().then(|| &buf[..r.0 as usize]);
        let shown = data
            .map(|d| quote_bytes(d, DISPLAY_BYTES))
            .unwrap_or_else(|| "<buf>".to_string());
        let issued = vec![call(
            "read",
            IssuedPurpose::Requested,
            format!("{shown_fd}, {shown}, {count}"),
            r,
        )];
        Ok(Self::completed(r, issued, None, data, None))
    }

    fn write(&mut self, fd: i32, data: &[u8]) -> Result<InvokeOutcome, Stop> {
        let (fd, shown_fd) = self.fd(fd)?;
        // SAFETY: `data` is a valid readable slice for the duration of the call.
        let r = result(unsafe { libc::syscall(libc::SYS_write, fd, data.as_ptr(), data.len()) });
        // A short write is reported as-is; the runner never loops to "fix" it.
        Ok(Self::plain(
            "write",
            format!("{shown_fd}, {}, {}", quote_bytes(data, DISPLAY_BYTES), data.len()),
            r,
        ))
    }

    fn close(&mut self, fd: i32) -> Result<InvokeOutcome, Stop> {
        let (fd, shown) = self.fd(fd)?;
        // SAFETY: closing an fd is memory-safe; the runner's own IPC socket is excluded above.
        let r = result(unsafe { libc::syscall(libc::SYS_close, fd) });
        let requested = call("close", IssuedPurpose::Requested, shown, r);
        let (gone, probe) = if r.1.is_none() {
            (true, None)
        } else if self.handles.get(fd).is_none() {
            (false, None)
        } else {
            // On Linux close() releases the fd even when it reports an error,
            // except when the syscall never ran (e.g. denied by seccomp).
            // Ask the kernel instead of guessing.
            // SAFETY: F_GETFD only queries descriptor flags.
            let p = result(unsafe { libc::syscall(libc::SYS_fcntl, fd, libc::F_GETFD) });
            let probe = call("fcntl", IssuedPurpose::StateCheck, format!("{fd}, F_GETFD"), p);
            (p.1 == Some(libc::EBADF), Some(probe))
        };
        let issued = std::iter::once(requested).chain(probe).collect();
        let closed = gone
            .then(|| self.handles.remove(fd))
            .flatten()
            .map(|info| HandleChange::Closed { info });
        Ok(Self::completed(r, issued, closed, None, None))
    }

    fn mkdirat(&mut self, dirfd: Dirfd, path: &str, mode: u32) -> Result<InvokeOutcome, Stop> {
        let (fd, shown, _) = self.dirfd(dirfd)?;
        let c = cstring(path)?;
        // SAFETY: `c` is a valid NUL-terminated path; the kernel validates `fd`.
        let r = result(unsafe { libc::syscall(libc::SYS_mkdirat, fd, c.as_ptr(), mode as libc::c_uint) });
        Ok(Self::plain(
            "mkdirat",
            format!("{shown}, {}, {}", quote_str(path), format_mode(mode)),
            r,
        ))
    }
}

/// One syscall the runner issued, as reported back to the host.
fn call(syscall: &str, purpose: IssuedPurpose, args: String, r: (i64, Option<i32>)) -> IssuedCall {
    IssuedCall {
        syscall: syscall.to_string(),
        purpose,
        args,
        ret: r.0,
        errno: r.1.map(errno::name),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decode_flags_str(bits: libc::c_int) -> String {
        decode_flags(bits).to_string()
    }

    #[test]
    fn decode_like_strace() {
        assert_eq!(
            decode_flags_str(libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC),
            "O_WRONLY|O_CREAT|O_TRUNC"
        );
        // multi-bit flags are named once, not as their parts
        assert_eq!(decode_flags_str(libc::O_RDWR | libc::O_TMPFILE), "O_RDWR|O_TMPFILE");
        assert_eq!(decode_flags_str(libc::O_WRONLY | libc::O_SYNC), "O_WRONLY|O_SYNC");
        assert_eq!(decode_flags_str(libc::O_DSYNC), "O_RDONLY|O_DSYNC");
        // aliases use the canonical name
        assert_eq!(decode_flags_str(libc::O_NDELAY), "O_RDONLY|O_NONBLOCK");
        // access mode 3 and unnamed bits in hex
        assert_eq!(decode_flags_str(3 | 0x4000_0000), "0x3|0x40000000");
    }
}
