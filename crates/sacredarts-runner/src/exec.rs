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
use sacredarts_core::process::{
    CPU_SET_BYTES, ChildProgram, KernelOutput, format_cpus, format_timeval, format_wait_options, signal_name,
};
use sacredarts_core::{DecodedFlags, Dirfd, OpenFlag, PrioWhich, SyscallRequest, ValidationError};
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
#[must_use]
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
        // flag words are bit patterns; reinterpret, don't convert
        access_mode: (bits & libc::O_ACCMODE).cast_unsigned(),
        named,
        unnamed: rest.cast_unsigned(),
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
    #[must_use]
    pub fn new(cwd: &Path, ipc_fd: RawFd) -> Self {
        Self {
            cwd: cwd.to_path_buf(),
            handles: HandleTable::new(),
            ipc_fd,
        }
    }

    #[must_use]
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
            SyscallRequest::Getpid => Ok(Self::getpid()),
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
            SyscallRequest::Getpriority { which, who } => Ok(Self::getpriority(*which, *who)),
            SyscallRequest::Setpriority { which, who, prio } => Ok(Self::setpriority(*which, *who, *prio)),
            SyscallRequest::Fork { child, seconds } => Ok(self.fork(*child, *seconds)),
            SyscallRequest::Kill { pid, sig } => Ok(Self::kill(*pid, *sig)),
            SyscallRequest::Wait4 { pid, options } => Ok(Self::wait4(*pid, *options)),
            SyscallRequest::SchedSetaffinity { pid, cpus } => Ok(Self::sched_setaffinity(*pid, cpus)),
            SyscallRequest::SchedGetaffinity { pid } => Ok(Self::sched_getaffinity(*pid)),
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
        output: Option<KernelOutput>,
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
            output: output.map(Box::new),
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
            None,
        )
    }

    fn getpid() -> InvokeOutcome {
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
        let bits = flags.iter().fold(raw_flags.cast_signed(), |acc, f| acc | flag_bits(*f));
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
            let label = base.map_or_else(|| path.to_string(), |b| label(&b, path));
            HandleChange::Opened {
                info: self.handles.insert(r.0 as RawFd, label, decoded.to_string()),
            }
        });
        Ok(Self::completed(r, issued, opened, None, Some(decoded), None))
    }

    fn read(&mut self, fd: i32, count: usize) -> Result<InvokeOutcome, Stop> {
        let (fd, shown_fd) = self.fd(fd)?;
        // The kernel writes into this buffer, so it has to be mutable.
        let mut buf = vec![0u8; count];
        // SAFETY: `buf` has exactly `count` writable bytes and outlives the call.
        let r = result(unsafe { libc::syscall(libc::SYS_read, fd, buf.as_mut_ptr(), count) });
        // On success the kernel returns 0..=count bytes read.
        let data = usize::try_from(r.0).ok().filter(|_| r.1.is_none()).map(|n| &buf[..n]);
        let shown = data.map_or_else(|| "<buf>".to_string(), |d| quote_bytes(d, DISPLAY_BYTES));
        let issued = vec![call(
            "read",
            IssuedPurpose::Requested,
            format!("{shown_fd}, {shown}, {count}"),
            r,
        )];
        Ok(Self::completed(r, issued, None, data, None, None))
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
        Ok(Self::completed(r, issued, closed, None, None, None))
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

    /// The raw syscall, not glibc's wrapper: the kernel returns `20 - nice`
    /// (1..=40) so that a valid result is never negative; glibc subtracts it
    /// back. SacredArts shows the kernel's value.
    fn getpriority(which: i32, who: u32) -> InvokeOutcome {
        // SAFETY: getpriority only takes integers.
        let r = result(unsafe { libc::syscall(libc::SYS_getpriority, which, who) });
        Self::plain("getpriority", format!("{}, {who}", PrioWhich::display(which)), r)
    }

    /// `prio` goes to the kernel verbatim; out-of-range values are clamped there.
    fn setpriority(which: i32, who: u32, prio: i32) -> InvokeOutcome {
        // SAFETY: setpriority only takes integers.
        let r = result(unsafe { libc::syscall(libc::SYS_setpriority, which, who, prio) });
        Self::plain(
            "setpriority",
            format!("{}, {who}, {prio}", PrioWhich::display(which)),
            r,
        )
    }

    /// `fork()` as glibc does it: `clone(SIGCHLD)` with no new stack, so the
    /// child is a copy of the runner (memory, fds, nice, CPU affinity,
    /// seccomp filter). The child closes the IPC socket, runs `child` and
    /// calls `_exit`; it never returns to the runner's loop.
    fn fork(&mut self, child: ChildProgram, seconds: u32) -> InvokeOutcome {
        let flags = libc::c_ulong::try_from(libc::SIGCHLD).unwrap_or_default();
        // SAFETY: the runner is single-threaded, so the child is a complete
        // copy; it only calls async-signal-safe functions and then `_exit`.
        let r = result(unsafe { libc::syscall(libc::SYS_clone, flags, 0, 0, 0, 0) });
        if r.1.is_none() && r.0 == 0 {
            child_main(self.ipc_fd, child, seconds);
        }
        Self::plain("clone", "child_stack=NULL, flags=SIGCHLD".into(), r)
    }

    fn kill(pid: i32, sig: i32) -> InvokeOutcome {
        // SAFETY: kill only takes integers; the kernel checks permissions.
        let r = result(unsafe { libc::syscall(libc::SYS_kill, pid, sig) });
        Self::plain("kill", format!("{pid}, {}", signal_name(sig)), r)
    }

    /// Reap a child. The kernel fills the status word and `struct rusage`
    /// (the child's CPU time). Without `WNOHANG` this blocks until a child
    /// changes state, which can exceed the request timeout.
    fn wait4(pid: i32, options: i32) -> InvokeOutcome {
        let mut status: libc::c_int = 0;
        // SAFETY: rusage is plain data; all-zero is a valid value.
        let mut ru: libc::rusage = unsafe { std::mem::zeroed() };
        // SAFETY: `status` and `ru` are valid writable locations for the call.
        let r = result(unsafe { libc::syscall(libc::SYS_wait4, pid, &raw mut status, options, &raw mut ru) });
        let us = |t: libc::timeval| i64::from(t.tv_sec) * 1_000_000 + i64::from(t.tv_usec);
        // ret 0 (WNOHANG, nothing changed) leaves status and rusage untouched.
        let output = (r.1.is_none() && r.0 > 0).then(|| KernelOutput::Wait {
            status,
            utime_us: us(ru.ru_utime),
            stime_us: us(ru.ru_stime),
        });
        let args = match &output {
            Some(KernelOutput::Wait { utime_us, stime_us, .. }) => format!(
                "{pid}, {status:#x}, {}, {{ru_utime={}, ru_stime={}}}",
                format_wait_options(options),
                format_timeval(*utime_us),
                format_timeval(*stime_us)
            ),
            _ => format!("{pid}, <status>, {}, <rusage>", format_wait_options(options)),
        };
        let issued = vec![call("wait4", IssuedPurpose::Requested, args, r)];
        Self::completed(r, issued, None, None, None, output)
    }

    fn sched_setaffinity(pid: i32, cpus: &[u32]) -> InvokeOutcome {
        let mut mask = [0u8; CPU_SET_BYTES];
        for c in cpus {
            let c = *c as usize;
            if let Some(b) = mask.get_mut(c / 8) {
                *b |= 1 << (c % 8);
            }
        }
        // SAFETY: `mask` has CPU_SET_BYTES readable bytes.
        let r = result(unsafe { libc::syscall(libc::SYS_sched_setaffinity, pid, CPU_SET_BYTES, mask.as_ptr()) });
        Self::plain(
            "sched_setaffinity",
            format!("{pid}, {CPU_SET_BYTES}, {}", format_cpus(cpus)),
            r,
        )
    }

    /// The raw syscall returns the number of mask bytes the kernel copied.
    fn sched_getaffinity(pid: i32) -> InvokeOutcome {
        let mut mask = [0u8; CPU_SET_BYTES];
        // SAFETY: `mask` has CPU_SET_BYTES writable bytes.
        let r = result(unsafe { libc::syscall(libc::SYS_sched_getaffinity, pid, CPU_SET_BYTES, mask.as_mut_ptr()) });
        let output = r.1.is_none().then(|| {
            let n = usize::try_from(r.0).unwrap_or(0).min(CPU_SET_BYTES);
            let cpus = (0..n * 8)
                .filter(|i| mask[i / 8] & (1 << (i % 8)) != 0)
                .filter_map(|i| u32::try_from(i).ok())
                .collect();
            KernelOutput::Cpus { cpus }
        });
        let shown = match &output {
            Some(KernelOutput::Cpus { cpus }) => format_cpus(cpus),
            _ => "<mask>".into(),
        };
        let issued = vec![call(
            "sched_getaffinity",
            IssuedPurpose::Requested,
            format!("{pid}, {CPU_SET_BYTES}, {shown}"),
            r,
        )];
        Self::completed(r, issued, None, None, None, output)
    }
}

/// What a forked child runs. Never returns.
fn child_main(ipc_fd: RawFd, child: ChildProgram, seconds: u32) -> ! {
    // SAFETY: the child must not keep the supervisor's socket open (the
    // supervisor detects a dead runner by EOF on it).
    unsafe {
        libc::close(ipc_fd);
    }
    match child {
        ChildProgram::Exit => {}
        ChildProgram::Sleep => {
            let ts = libc::timespec {
                tv_sec: libc::time_t::from(seconds),
                tv_nsec: 0,
            };
            // SAFETY: `ts` is valid for the call; the remaining time is not needed.
            unsafe {
                libc::nanosleep(&raw const ts, std::ptr::null_mut());
            }
        }
        ChildProgram::Spin => {
            // Pure user-space work; the clock is read through the vDSO.
            let end = std::time::Instant::now() + std::time::Duration::from_secs(seconds.into());
            let mut x = 0u64;
            while std::time::Instant::now() < end {
                for _ in 0..100_000 {
                    x = std::hint::black_box(x.wrapping_add(1));
                }
            }
        }
    }
    // SAFETY: _exit ends the child without running the runner's destructors.
    unsafe { libc::_exit(0) }
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
