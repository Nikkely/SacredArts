//! Process-related values: signals, `wait4` options and status, CPU sets,
//! and the output arguments the kernel fills in for these syscalls.

use serde::{Deserialize, Serialize};
use strum::{EnumIter, EnumString, IntoStaticStr, VariantNames};

/// Signal names with their numbers. These numbers are the same on x86_64
/// and aarch64 Linux (the targets SacredArts supports).
pub const SIGNALS: &[(&str, i32)] = &[
    ("SIGHUP", 1),
    ("SIGINT", 2),
    ("SIGQUIT", 3),
    ("SIGILL", 4),
    ("SIGTRAP", 5),
    ("SIGABRT", 6),
    ("SIGBUS", 7),
    ("SIGFPE", 8),
    ("SIGKILL", 9),
    ("SIGUSR1", 10),
    ("SIGSEGV", 11),
    ("SIGUSR2", 12),
    ("SIGPIPE", 13),
    ("SIGALRM", 14),
    ("SIGTERM", 15),
    ("SIGSTKFLT", 16),
    ("SIGCHLD", 17),
    ("SIGCONT", 18),
    ("SIGSTOP", 19),
    ("SIGTSTP", 20),
    ("SIGTTIN", 21),
    ("SIGTTOU", 22),
    ("SIGURG", 23),
    ("SIGXCPU", 24),
    ("SIGXFSZ", 25),
    ("SIGVTALRM", 26),
    ("SIGPROF", 27),
    ("SIGWINCH", 28),
    ("SIGIO", 29),
    ("SIGPWR", 30),
    ("SIGSYS", 31),
];

#[must_use]
pub fn signal_number(name: &str) -> Option<i32> {
    let n = name.trim();
    let n = if n.starts_with("SIG") {
        n.to_string()
    } else {
        format!("SIG{n}")
    };
    SIGNALS.iter().find(|(s, _)| *s == n).map(|(_, v)| *v)
}

/// `SIGKILL`, or the number for signals without a name (e.g. 0 or real-time signals).
#[must_use]
pub fn signal_name(sig: i32) -> String {
    SIGNALS
        .iter()
        .find(|(_, v)| *v == sig)
        .map_or_else(|| sig.to_string(), |(s, _)| (*s).to_string())
}

/// Named `wait4` option bits (same values on every Linux architecture).
#[allow(non_camel_case_types)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, EnumIter, EnumString, IntoStaticStr, VariantNames)]
pub enum WaitOption {
    WNOHANG,
    WUNTRACED,
    WCONTINUED,
}

impl WaitOption {
    #[must_use]
    pub fn bits(self) -> i32 {
        match self {
            WaitOption::WNOHANG => 1,
            WaitOption::WUNTRACED => 2,
            WaitOption::WCONTINUED => 8,
        }
    }
}

/// `WNOHANG|WUNTRACED`, unnamed bits in hex, `0` for none.
#[must_use]
pub fn format_wait_options(options: i32) -> String {
    use strum::IntoEnumIterator;
    let named: Vec<WaitOption> = WaitOption::iter().filter(|o| options & o.bits() != 0).collect();
    let rest = named.iter().fold(options, |acc, o| acc & !o.bits());
    let parts: Vec<String> = named
        .iter()
        .map(|o| <&str>::from(*o).to_string())
        .chain((rest != 0).then(|| format!("{rest:#x}")))
        .collect();
    if parts.is_empty() { "0".into() } else { parts.join("|") }
}

/// How a child changed state, decoded from a `wait4` status word.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WaitStatus {
    Exited(i32),
    Signaled(i32),
    Stopped(i32),
    Continued,
    Unknown(i32),
}

impl WaitStatus {
    #[must_use]
    pub fn decode(status: i32) -> Self {
        let low = status & 0x7f;
        if low == 0 {
            WaitStatus::Exited((status >> 8) & 0xff)
        } else if status & 0xff == 0x7f {
            WaitStatus::Stopped((status >> 8) & 0xff)
        } else if status == 0xffff {
            WaitStatus::Continued
        } else if low != 0x7f {
            WaitStatus::Signaled(low)
        } else {
            WaitStatus::Unknown(status)
        }
    }

    /// strace style: `{WIFSIGNALED(s) && WTERMSIG(s) == SIGKILL}`.
    #[must_use]
    pub fn strace(self) -> String {
        match self {
            WaitStatus::Exited(c) => format!("{{WIFEXITED(s) && WEXITSTATUS(s) == {c}}}"),
            WaitStatus::Signaled(s) => format!("{{WIFSIGNALED(s) && WTERMSIG(s) == {}}}", signal_name(s)),
            WaitStatus::Stopped(s) => format!("{{WIFSTOPPED(s) && WSTOPSIG(s) == {}}}", signal_name(s)),
            WaitStatus::Continued => "{WIFCONTINUED(s)}".into(),
            WaitStatus::Unknown(v) => format!("{v:#x}"),
        }
    }

    /// Japanese description for the guide.
    #[must_use]
    pub fn ja(self) -> String {
        match self {
            WaitStatus::Exited(c) => format!("終了コード {c} で正常終了した"),
            WaitStatus::Signaled(s) => format!("シグナル {} で強制終了された", signal_name(s)),
            WaitStatus::Stopped(s) => format!("シグナル {} で一時停止した", signal_name(s)),
            WaitStatus::Continued => "SIGCONT で再開した".into(),
            WaitStatus::Unknown(v) => format!("不明な状態 {v:#x}"),
        }
    }
}

/// Size of the CPU mask SacredArts passes to the kernel (glibc's `cpu_set_t`).
pub const CPU_SET_BYTES: usize = 128;
pub const CPU_SET_BITS: u32 = 1024;

/// `[0 1 3]` like strace.
#[must_use]
pub fn format_cpus(cpus: &[u32]) -> String {
    let list: Vec<String> = cpus.iter().map(u32::to_string).collect();
    format!("[{}]", list.join(" "))
}

/// Output arguments the kernel wrote (shown in the call line, like strace).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum KernelOutput {
    /// `wait4`: the status word and the child's CPU time (`struct rusage`).
    Wait { status: i32, utime_us: i64, stime_us: i64 },
    /// `sched_getaffinity`: the CPUs in the mask.
    Cpus { cpus: Vec<u32> },
}

/// `{tv_sec=4, tv_usec=812000}`.
#[must_use]
pub fn format_timeval(us: i64) -> String {
    format!("{{tv_sec={}, tv_usec={}}}", us / 1_000_000, us % 1_000_000)
}

/// Seconds with millisecond precision (`4.812`).
#[must_use]
pub fn secs(us: i64) -> String {
    format!("{}.{:03}", us / 1_000_000, (us % 1_000_000) / 1000)
}

/// What a forked child does. The child never returns to the runner's code:
/// it runs one of these and calls `_exit`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, EnumString, IntoStaticStr, VariantNames)]
#[serde(rename_all = "lowercase")]
#[strum(serialize_all = "lowercase")]
pub enum ChildProgram {
    /// Busy loop in user space (no syscalls) until `seconds` have passed.
    Spin,
    /// `nanosleep` for `seconds`.
    Sleep,
    /// `_exit(0)` immediately (it stays a zombie until reaped by `wait4`).
    Exit,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signals_and_status() {
        assert_eq!(signal_number("SIGKILL"), Some(9));
        assert_eq!(signal_number("STOP"), Some(19));
        assert_eq!(signal_name(15), "SIGTERM");
        assert_eq!(signal_name(40), "40");
        assert_eq!(WaitStatus::decode(0), WaitStatus::Exited(0));
        assert_eq!(WaitStatus::decode(3 << 8), WaitStatus::Exited(3));
        assert_eq!(WaitStatus::decode(9), WaitStatus::Signaled(9));
        assert_eq!(
            WaitStatus::decode(0x80 | 0xb),
            WaitStatus::Signaled(11),
            "core dump bit"
        );
        assert_eq!(WaitStatus::decode((19 << 8) | 0x7f), WaitStatus::Stopped(19));
        assert_eq!(WaitStatus::decode(0xffff), WaitStatus::Continued);
        assert_eq!(
            WaitStatus::decode(9).strace(),
            "{WIFSIGNALED(s) && WTERMSIG(s) == SIGKILL}"
        );
        assert_eq!(format_wait_options(0), "0");
        assert_eq!(format_wait_options(1 | 8 | 0x40), "WNOHANG|WCONTINUED|0x40");
        assert_eq!(format_cpus(&[0, 2]), "[0 2]");
        assert_eq!(format_timeval(4_812_000), "{tv_sec=4, tv_usec=812000}");
        assert_eq!(secs(4_812_345), "4.812");
    }
}
