//! Policy engine: turns a [`Policy`] (deny-list of learning syscalls) into a
//! seccomp-BPF program that the *kernel* enforces.
//!
//! The deny decision is never made by an application-level `if`: the runner
//! installs the compiled filter on itself, and from then on the kernel
//! returns the configured errno for the listed syscall numbers.
//!
//! Syscall numbers are taken from the target's `libc::SYS_*` constants, so the
//! same code is correct on aarch64 and x86_64 (where the numbers differ).

pub use sacredarts_core::{DenyErrno, Policy, SyscallName};

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use seccompiler::{BpfProgram, SeccompAction, SeccompFilter, TargetArch};
    use std::collections::BTreeMap;

    /// Kernel syscall number of a learning syscall on the build target.
    // `c_long` is `i64` on every supported (64-bit) target; the cast keeps
    // the code explicit about the width the BPF compiler expects.
    #[allow(clippy::unnecessary_cast)]
    #[must_use]
    pub fn syscall_number(name: SyscallName) -> i64 {
        (match name {
            SyscallName::Getpid => libc::SYS_getpid,
            SyscallName::Openat => libc::SYS_openat,
            SyscallName::Read => libc::SYS_read,
            SyscallName::Write => libc::SYS_write,
            SyscallName::Close => libc::SYS_close,
            SyscallName::Mkdirat => libc::SYS_mkdirat,
        }) as i64
    }

    /// Canonical errno name for a number (glibc's `strerrorname_np`).
    #[must_use]
    pub fn errno_name(n: i32) -> Option<String> {
        #[cfg(target_env = "gnu")]
        {
            unsafe extern "C" {
                fn strerrorname_np(errnum: libc::c_int) -> *const libc::c_char;
            }
            // SAFETY: returns NULL or a pointer to a static NUL-terminated string.
            let p = unsafe { strerrorname_np(n) };
            if !p.is_null() {
                return Some(unsafe { std::ffi::CStr::from_ptr(p) }.to_string_lossy().into_owned());
            }
        }
        #[cfg(not(target_env = "gnu"))]
        let _ = n;
        None
    }

    /// Names that are aliases of another errno. `strerrorname_np` only returns
    /// the canonical name, so these cannot be found by searching its output.
    const ERRNO_ALIASES: [(&str, i32); 3] = [
        ("EWOULDBLOCK", libc::EWOULDBLOCK),
        ("ENOTSUP", libc::ENOTSUP),
        ("EDEADLOCK", libc::EDEADLOCK),
    ];

    /// errno number for a name (canonical names and their aliases).
    ///
    /// # Errors
    ///
    /// If the C library does not know the name.
    pub fn errno_value(e: &DenyErrno) -> Result<u32, String> {
        let name = e.as_str();
        ERRNO_ALIASES
            .iter()
            .find(|(alias, _)| *alias == name)
            .map(|(_, n)| *n)
            // errno values are small positive ints; 4095 is the kernel's MAX_ERRNO.
            .or_else(|| (1..4096).find(|n| errno_name(*n).as_deref() == Some(name)))
            .map(|n| n as u32)
            .ok_or_else(|| format!("unknown errno name {name:?}"))
    }

    /// The policy with its errno written by its canonical name (`EWOULDBLOCK`
    /// becomes `EAGAIN`), which is what the kernel's errno is reported as.
    ///
    /// # Errors
    ///
    /// If the errno name is unknown or the policy cannot be compiled into a
    /// seccomp filter (see [`compile`]).
    pub fn canonicalize(policy: &Policy) -> Result<Policy, String> {
        let n = errno_value(&policy.errno)?;
        let name = errno_name(n as i32).ok_or_else(|| format!("errno {n} has no name"))?;
        let canonical = Policy {
            deny: policy.deny.clone(),
            errno: DenyErrno::new(&name),
        };
        compile(&canonical)?;
        Ok(canonical)
    }

    fn target_arch() -> Result<TargetArch, String> {
        if cfg!(target_arch = "aarch64") {
            Ok(TargetArch::aarch64)
        } else if cfg!(target_arch = "x86_64") {
            Ok(TargetArch::x86_64)
        } else {
            Err(format!("unsupported architecture {}", std::env::consts::ARCH))
        }
    }

    /// Compile the policy. Returns `None` for an empty policy (no filter).
    ///
    /// The filter allows everything by default and returns `errno` for the
    /// denied syscall numbers. seccompiler also embeds an architecture check;
    /// a syscall from a foreign ABI kills the process.
    ///
    /// # Errors
    ///
    /// If the errno name is unknown, the architecture is not supported
    /// (aarch64 and x86_64 are), or seccompiler rejects the filter.
    pub fn compile(policy: &Policy) -> Result<Option<BpfProgram>, String> {
        if policy.is_empty() {
            return Ok(None);
        }
        let rules: BTreeMap<i64, Vec<seccompiler::SeccompRule>> =
            policy.deny.iter().map(|n| (syscall_number(*n), vec![])).collect();
        let filter = SeccompFilter::new(
            rules,
            SeccompAction::Allow,
            SeccompAction::Errno(errno_value(&policy.errno)?),
            target_arch()?,
        )
        .map_err(|e| format!("building seccomp filter: {e}"))?;
        let prog: BpfProgram = filter
            .try_into()
            .map_err(|e| format!("compiling seccomp filter: {e:?}"))?;
        Ok(Some(prog))
    }

    /// Install the compiled filter on the calling thread (and, because the
    /// runner is single-threaded, on the whole process). Irreversible.
    /// seccompiler sets `PR_SET_NO_NEW_PRIVS` before `seccomp(2)`.
    ///
    /// # Errors
    ///
    /// If the policy cannot be compiled (see [`compile`]) or the kernel
    /// refuses to install the filter.
    pub fn apply(policy: &Policy) -> Result<bool, String> {
        match compile(policy)? {
            None => Ok(false),
            Some(prog) => {
                seccompiler::apply_filter(&prog).map_err(|e| format!("seccomp: {e}"))?;
                Ok(true)
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn compiles_for_each_syscall() {
            assert!(compile(&Policy::default()).unwrap().is_none());
            for n in <SyscallName as strum::IntoEnumIterator>::iter() {
                let p = Policy {
                    deny: vec![n],
                    errno: DenyErrno::default(),
                };
                let prog = compile(&p).unwrap().unwrap();
                assert!(!prog.is_empty());
            }
        }

        #[test]
        fn any_errno_name_resolves() {
            let v = |s: &str| errno_value(&DenyErrno::new(s));
            assert_eq!(v("EPERM").unwrap(), libc::EPERM as u32);
            assert_eq!(v("EIO").unwrap(), libc::EIO as u32);
            assert_eq!(v("EHWPOISON").unwrap(), libc::EHWPOISON as u32);
            assert!(v("ENOTANERRNO").is_err());
            // aliases resolve to the canonical errno
            assert_eq!(v("EWOULDBLOCK").unwrap(), libc::EAGAIN as u32);
            assert_eq!(v("ENOTSUP").unwrap(), libc::EOPNOTSUPP as u32);
            let p = Policy {
                deny: vec![SyscallName::Getpid],
                errno: DenyErrno::new("EWOULDBLOCK"),
            };
            assert_eq!(canonicalize(&p).unwrap().errno.as_str(), "EAGAIN");
            let bad = Policy {
                deny: vec![SyscallName::Getpid],
                errno: DenyErrno::new("ENOTANERRNO"),
            };
            assert!(compile(&bad).is_err());
        }

        #[test]
        fn numbers_are_target_specific() {
            // openat is 56 on aarch64 and 257 on x86_64; never hard-code.
            #[cfg(target_arch = "aarch64")]
            assert_eq!(syscall_number(SyscallName::Openat), 56);
            #[cfg(target_arch = "x86_64")]
            assert_eq!(syscall_number(SyscallName::Openat), 257);
        }
    }
}

#[cfg(target_os = "linux")]
pub use linux::{apply, canonicalize, compile, errno_name, errno_value, syscall_number};
