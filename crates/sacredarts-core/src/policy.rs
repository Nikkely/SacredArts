//! Learning-level seccomp policy (data only; compilation lives in `sacredarts-policy`).

use crate::request::ValidationError;
use crate::syscall::SyscallName;
use serde::{Deserialize, Serialize};

/// errno returned by the kernel when a denied syscall is attempted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum DenyErrno {
    #[default]
    EPERM,
    EACCES,
    ENOSYS,
}

impl DenyErrno {
    pub fn as_str(self) -> &'static str {
        match self {
            DenyErrno::EPERM => "EPERM",
            DenyErrno::EACCES => "EACCES",
            DenyErrno::ENOSYS => "ENOSYS",
        }
    }

    pub fn parse(s: &str) -> Result<Self, ValidationError> {
        match s {
            "EPERM" => Ok(DenyErrno::EPERM),
            "EACCES" => Ok(DenyErrno::EACCES),
            "ENOSYS" => Ok(DenyErrno::ENOSYS),
            other => Err(ValidationError::new(
                "invalid_errno",
                format!("unsupported errno {other:?}; allowed: EPERM, EACCES, ENOSYS"),
            )
            .field("errno")),
        }
    }
}

/// Deny-list policy. Only the MVP learning syscalls may be listed, so the
/// runner's internal IPC (sendto/recvfrom), memory management and exit can
/// never be denied by the user.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct Policy {
    pub deny: Vec<SyscallName>,
    pub errno: DenyErrno,
}

impl Policy {
    /// Build a policy from untrusted user input. Unknown names are rejected,
    /// duplicates removed, and the list sorted for a stable representation.
    pub fn from_user(deny: &[String], errno: Option<&str>) -> Result<Self, ValidationError> {
        let mut out = Vec::new();
        for name in deny {
            let n = SyscallName::parse(name).ok_or_else(|| {
                ValidationError::new(
                    "unsupported_syscall",
                    format!(
                        "cannot deny {name:?}: policies may only list the MVP learning syscalls ({})",
                        SyscallName::names().join(", ")
                    ),
                )
                .field("deny")
            })?;
            out.push(n);
        }
        out.sort();
        out.dedup();
        let errno = match errno {
            Some(e) => DenyErrno::parse(e)?,
            None => DenyErrno::EPERM,
        };
        Ok(Policy { deny: out, errno })
    }

    pub fn is_empty(&self) -> bool {
        self.deny.is_empty()
    }

    pub fn denies(&self, name: SyscallName) -> bool {
        self.deny.contains(&name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_user_validates() {
        let p = Policy::from_user(&["mkdirat".into(), "getpid".into(), "mkdirat".into()], None).unwrap();
        assert_eq!(p.deny, vec![SyscallName::Getpid, SyscallName::Mkdirat]);
        assert_eq!(p.errno, DenyErrno::EPERM);
        assert!(Policy::from_user(&["sendto".into()], None).is_err());
        assert!(Policy::from_user(&[], Some("EBADF")).is_err());
        assert_eq!(Policy::from_user(&[], Some("EACCES")).unwrap().errno, DenyErrno::EACCES);
    }
}
