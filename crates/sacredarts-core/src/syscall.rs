use serde::{Deserialize, Serialize};
use strum::{Display, EnumIter, EnumString, IntoStaticStr, VariantNames};

/// Syscalls SacredArts can execute. Names are the Linux (lowercase) names;
/// parsing is exact and case-sensitive (`"openat".parse()`).
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    PartialOrd,
    Ord,
    Serialize,
    Deserialize,
    Display,
    EnumIter,
    EnumString,
    IntoStaticStr,
    VariantNames,
)]
#[serde(rename_all = "lowercase")]
#[strum(serialize_all = "lowercase")]
pub enum SyscallName {
    Getpid,
    Openat,
    Read,
    Write,
    Close,
    Mkdirat,
    Getpriority,
    Setpriority,
}

impl SyscallName {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        self.into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use strum::IntoEnumIterator;

    #[test]
    fn parse_roundtrip() {
        for n in SyscallName::iter() {
            assert_eq!(n.as_str().parse(), Ok(n));
            assert_eq!(serde_json::to_value(n).unwrap(), n.as_str(), "serde and strum agree");
        }
        assert_eq!(
            SyscallName::VARIANTS.join(","),
            "getpid,openat,read,write,close,mkdirat,getpriority,setpriority"
        );
        assert!("open".parse::<SyscallName>().is_err());
        assert!("OPENAT".parse::<SyscallName>().is_err());
        assert!("execve".parse::<SyscallName>().is_err());
    }
}
