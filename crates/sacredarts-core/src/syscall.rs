use serde::{Deserialize, Serialize};
use std::fmt;

/// Learning syscalls that SacredArts can execute (MVP set).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SyscallName {
    Getpid,
    Openat,
    Read,
    Write,
    Close,
    Mkdirat,
}

impl SyscallName {
    pub const ALL: [SyscallName; 6] = [
        SyscallName::Getpid,
        SyscallName::Openat,
        SyscallName::Read,
        SyscallName::Write,
        SyscallName::Close,
        SyscallName::Mkdirat,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            SyscallName::Getpid => "getpid",
            SyscallName::Openat => "openat",
            SyscallName::Read => "read",
            SyscallName::Write => "write",
            SyscallName::Close => "close",
            SyscallName::Mkdirat => "mkdirat",
        }
    }

    /// Exact, case-sensitive lookup (syscall names are lowercase in Linux).
    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|n| n.as_str() == s)
    }

    pub fn names() -> Vec<&'static str> {
        Self::ALL.iter().map(|n| n.as_str()).collect()
    }
}

impl fmt::Display for SyscallName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_roundtrip() {
        for n in SyscallName::ALL {
            assert_eq!(SyscallName::parse(n.as_str()), Some(n));
        }
        assert_eq!(SyscallName::parse("open"), None);
        assert_eq!(SyscallName::parse("OPENAT"), None);
        assert_eq!(SyscallName::parse("execve"), None);
    }
}
