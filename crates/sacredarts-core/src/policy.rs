//! Learning-level seccomp policy (data only; compilation lives in `sacredarts-policy`).

use crate::request::ValidationError;
use crate::syscall::SyscallName;
use serde::{Deserialize, Serialize};
use strum::VariantNames;

/// errno returned by the kernel when a denied syscall is attempted, by name
/// (`EPERM`, `ENOSYS`, `EIO`, ...). The name is not checked here: only the C
/// library inside the sandbox knows which names exist, so it is resolved there
/// and an unknown name is reported as `invalid_policy` (nothing changes).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct DenyErrno(String);

impl Default for DenyErrno {
    fn default() -> Self {
        DenyErrno("EPERM".into())
    }
}

impl DenyErrno {
    pub fn new(name: &str) -> Self {
        DenyErrno(name.trim().to_string())
    }

    pub fn as_str(&self) -> &str {
        &self.0
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
            let n = name.parse::<SyscallName>().map_err(|_| {
                ValidationError::new(
                    "unsupported_syscall",
                    format!(
                        "cannot deny {name:?}: policies may only list the MVP learning syscalls ({})",
                        SyscallName::VARIANTS.join(", ")
                    ),
                )
                .field("deny")
            })?;
            out.push(n);
        }
        out.sort();
        out.dedup();
        let errno = errno.map(DenyErrno::new).unwrap_or_default();
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
        // errno names are passed through; the sandbox resolves them
        for e in ["EBADF", "EIO", "E2BIG", "ENOTANERRNO"] {
            assert_eq!(Policy::from_user(&[], Some(e)).unwrap().errno.as_str(), e);
        }
        assert_eq!(serde_json::to_string(&DenyErrno::default()).unwrap(), "\"EPERM\"");
    }
}
