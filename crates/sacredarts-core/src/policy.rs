//! Learning-level seccomp policy (data only; compilation lives in `sacredarts-policy`).

use crate::request::ValidationError;
use crate::syscall::SyscallName;
use serde::{Deserialize, Serialize};

/// errno returned by the kernel when a denied syscall is attempted, by name
/// (`EPERM`, `ENOSYS`, `EIO`, ...). Any errno the C library inside the sandbox
/// knows is accepted; the name is resolved to its number there, so an unknown
/// name makes `policy_set` fail and the previous policy stays active.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct DenyErrno(String);

impl Default for DenyErrno {
    fn default() -> Self {
        DenyErrno("EPERM".into())
    }
}

impl DenyErrno {
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Lexical check only (`E` followed by upper-case letters / digits).
    pub fn parse(s: &str) -> Result<Self, ValidationError> {
        let t = s.trim();
        let ok =
            t.len() > 1 && t.starts_with('E') && t[1..].bytes().all(|b| b.is_ascii_uppercase() || b.is_ascii_digit());
        if ok {
            Ok(DenyErrno(t.to_string()))
        } else {
            Err(ValidationError::new(
                "invalid_errno",
                format!("{s:?} is not an errno name (expected something like EPERM, ENOSYS, EIO)"),
            )
            .field("errno"))
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
            None => DenyErrno::default(),
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
        assert_eq!(p.errno.as_str(), "EPERM");
        assert!(Policy::from_user(&["sendto".into()], None).is_err());
        for e in ["EBADF", "EIO", "ENOSYS", "E2BIG"] {
            assert_eq!(Policy::from_user(&[], Some(e)).unwrap().errno.as_str(), e);
        }
        assert!(Policy::from_user(&[], Some("eperm")).is_err());
        assert!(Policy::from_user(&[], Some("E")).is_err());
        assert_eq!(serde_json::to_string(&DenyErrno::default()).unwrap(), "\"EPERM\"");
    }
}
