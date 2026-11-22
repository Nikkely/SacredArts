//! Presentation modes. GuideLevel = how much explanation; TraceMode = which
//! events are shown. They are deliberately independent.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Default)]
#[serde(try_from = "u8", into = "u8")]
pub enum GuideLevel {
    /// strace-like lines only.
    #[default]
    Level1,
    /// + short explanation for beginners.
    Level2,
    /// + signature, arguments, flags, errno, internals, related, man pages.
    Level3,
}

impl GuideLevel {
    pub fn as_u8(self) -> u8 {
        match self {
            GuideLevel::Level1 => 1,
            GuideLevel::Level2 => 2,
            GuideLevel::Level3 => 3,
        }
    }
}

impl TryFrom<u8> for GuideLevel {
    type Error = String;
    fn try_from(v: u8) -> Result<Self, String> {
        match v {
            1 => Ok(GuideLevel::Level1),
            2 => Ok(GuideLevel::Level2),
            3 => Ok(GuideLevel::Level3),
            _ => Err(format!("guide_level must be 1, 2 or 3 (got {v})")),
        }
    }
}

impl From<GuideLevel> for u8 {
    fn from(g: GuideLevel) -> u8 {
        g.as_u8()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum TraceMode {
    /// Show only what the AI requested.
    #[default]
    Requested,
    /// Also show every syscall strace observed for the request.
    All,
}
