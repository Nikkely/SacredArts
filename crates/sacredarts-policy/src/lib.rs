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

    /// errno number for a name, resolved by the C library of the target
    /// (glibc's `strerrorname_np`), so every errno it knows can be used.
    pub fn errno_value(e: &DenyErrno) -> Result<u32, String> {
        #[cfg(target_env = "gnu")]
        {
            unsafe extern "C" {
                fn strerrorname_np(errnum: libc::c_int) -> *const libc::c_char;
            }
            // errno values are small positive ints; 4095 is the kernel's MAX_ERRNO.
            for n in 1..4096 {
                // SAFETY: returns NULL or a pointer to a static NUL-terminated string.
                let p = unsafe { strerrorname_np(n) };
                if !p.is_null() && unsafe { std::ffi::CStr::from_ptr(p) }.to_bytes() == e.as_str().as_bytes() {
                    return Ok(n as u32);
                }
            }
        }
        Err(format!("unknown errno name {:?}", e.as_str()))
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
            let v = |s: &str| errno_value(&DenyErrno::parse(s).unwrap());
            assert_eq!(v("EPERM").unwrap(), libc::EPERM as u32);
            assert_eq!(v("EIO").unwrap(), libc::EIO as u32);
            assert_eq!(v("EHWPOISON").unwrap(), libc::EHWPOISON as u32);
            assert!(v("ENOTANERRNO").is_err());
            let bad = Policy {
                deny: vec![SyscallName::Getpid],
                errno: DenyErrno::parse("ENOTANERRNO").unwrap(),
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
pub use linux::{apply, compile, errno_value, syscall_number};
