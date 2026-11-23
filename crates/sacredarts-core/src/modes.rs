//! Presentation modes. GuideLevel = how much explanation; TraceMode = which
//! events are shown. They are deliberately independent.

use serde::{Deserialize, Serialize};
use strum::{EnumIter, FromRepr, IntoEnumIterator};

/// The number is the external `guide_level` value (1-3); variants are
/// ordered from least to most detail.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Default, FromRepr, EnumIter)]
#[serde(try_from = "u8", into = "u8")]
#[repr(u8)]
pub enum GuideLevel {
    #[default]
    LineOnly = 1,
    Explained = 2,
    Detailed = 3,
}

impl GuideLevel {
    #[must_use]
    pub fn as_u8(self) -> u8 {
        self as u8
    }
}

impl TryFrom<u8> for GuideLevel {
    type Error = String;
    fn try_from(v: u8) -> Result<Self, String> {
        Self::from_repr(v).ok_or_else(|| {
            let valid: Vec<String> = Self::iter().map(|g| g.as_u8().to_string()).collect();
            format!("guide_level must be one of {} (got {v})", valid.join(", "))
        })
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guide_level_numbers() {
        assert_eq!(GuideLevel::default().as_u8(), 1);
        assert_eq!(GuideLevel::try_from(3), Ok(GuideLevel::Detailed));
        assert_eq!(
            GuideLevel::try_from(7).unwrap_err(),
            "guide_level must be one of 1, 2, 3 (got 7)"
        );
        assert_eq!(serde_json::to_string(&GuideLevel::Explained).unwrap(), "2");
        assert!(GuideLevel::LineOnly < GuideLevel::Detailed);
    }
}
