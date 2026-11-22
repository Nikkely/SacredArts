//! Parser for `strace -ttt -T -y` output lines.
//!
//! Only what strace actually printed is extracted. If a value is missing or
//! not understood it stays `None`; the raw line is always kept.

use sacredarts_core::ipc::ObservedSyscall;
use sacredarts_core::limits::MARKER_PREFIX;

#[derive(Debug, Clone, PartialEq)]
pub enum TraceLine {
    Syscall(ObservedSyscall),
    /// Boundary marker emitted by the runner (`faccessat` on a marker path).
    Marker {
        kind: String,
        id: u64,
    },
    /// Signals (`--- SIGCHLD ...`), exit notices (`+++ exited ...`), or
    /// anything not recognised.
    Other(String),
}

pub fn parse_line(line: &str) -> TraceLine {
    let line = line.trim_end_matches(['\n', '\r']);
    let (timestamp, rest) = split_timestamp(line);
    if rest.starts_with("---") || rest.starts_with("+++") {
        return TraceLine::Other(line.to_string());
    }
    let Some(open) = rest.find('(') else {
        return TraceLine::Other(line.to_string());
    };
    let name = &rest[..open];
    if name.is_empty() || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') {
        return TraceLine::Other(line.to_string());
    }
    let Some(close) = matching_paren(rest, open) else {
        return TraceLine::Other(line.to_string());
    };
    let args = &rest[open + 1..close];

    if (name == "faccessat" || name == "faccessat2")
        && let Some(m) = parse_marker(args)
    {
        return m;
    }

    let after = rest[close + 1..].trim_start();
    let Some(ret_part) = after.strip_prefix('=') else {
        return TraceLine::Other(line.to_string());
    };
    let mut ret_part = ret_part.trim();
    let mut duration_ns = None;
    if ret_part.ends_with('>')
        && let Some(i) = ret_part.rfind(" <")
    {
        let inner = &ret_part[i + 2..ret_part.len() - 1];
        if let Ok(secs) = inner.parse::<f64>() {
            duration_ns = Some((secs * 1e9).round() as u64);
            ret_part = ret_part[..i].trim_end();
        }
    }
    let (ret, errno, errno_message, return_raw) = parse_return(ret_part);
    TraceLine::Syscall(ObservedSyscall {
        timestamp_epoch: timestamp,
        syscall: name.to_string(),
        args: args.to_string(),
        return_raw,
        ret,
        errno,
        errno_message,
        duration_ns,
        raw: line.to_string(),
    })
}

fn split_timestamp(line: &str) -> (Option<f64>, &str) {
    if let Some((first, rest)) = line.split_once(' ')
        && first.contains('.')
        && first.bytes().all(|b| b.is_ascii_digit() || b == b'.')
        && let Ok(t) = first.parse::<f64>()
    {
        return (Some(t), rest);
    }
    (None, line)
}

/// Index of the `)` matching the `(` at `open`, skipping quoted strings
/// (strace escapes `"` inside strings as `\"`) and nested brackets.
fn matching_paren(s: &str, open: usize) -> Option<usize> {
    let bytes = s.as_bytes();
    let mut depth = 0i32;
    let mut in_str = false;
    let mut i = open;
    while i < bytes.len() {
        let b = bytes[i];
        if in_str {
            match b {
                b'\\' => i += 1,
                b'"' => in_str = false,
                _ => {}
            }
        } else {
            match b {
                b'"' => in_str = true,
                b'(' | b'[' | b'{' => depth += 1,
                b')' | b']' | b'}' => {
                    depth -= 1;
                    if depth == 0 && b == b')' {
                        return Some(i);
                    }
                }
                _ => {}
            }
        }
        i += 1;
    }
    None
}

fn parse_marker(args: &str) -> Option<TraceLine> {
    let start = args.find(MARKER_PREFIX)? + MARKER_PREFIX.len();
    let tail = &args[start..];
    let end = tail.find('"')?;
    let (kind, id) = tail[..end].split_once('/')?;
    Some(TraceLine::Marker {
        kind: kind.to_string(),
        id: id.parse().ok()?,
    })
}

type Ret = (Option<i64>, Option<String>, Option<String>, String);

/// `3</workspace/a>` | `0` | `-1 ENOENT (No such file or directory)` | `?` | `0x1234`
fn parse_return(s: &str) -> Ret {
    let raw = s.to_string();
    let (num_tok, tail) = match s.find([' ', '<']) {
        Some(i) => (&s[..i], s[i..].trim_start()),
        None => (s, ""),
    };
    let ret = if let Some(hex) = num_tok.strip_prefix("0x") {
        i64::from_str_radix(hex, 16).ok()
    } else {
        num_tok.parse::<i64>().ok()
    };
    let mut errno = None;
    let mut msg = None;
    if ret.is_some_and(|r| r < 0) || num_tok == "?" {
        let name: String = tail
            .chars()
            .take_while(|c| c.is_ascii_uppercase() || c.is_ascii_digit())
            .collect();
        if name.starts_with('E') && name.len() > 1 {
            errno = Some(name);
            if let (Some(a), Some(b)) = (tail.find('('), tail.rfind(')'))
                && a < b
            {
                msg = Some(tail[a + 1..b].to_string());
            }
        }
    }
    (ret, errno, msg, raw)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sys(l: &str) -> ObservedSyscall {
        match parse_line(l) {
            TraceLine::Syscall(s) => s,
            other => panic!("not a syscall: {other:?}"),
        }
    }

    #[test]
    fn success_with_fd_path_and_duration() {
        let s = sys(
            r#"1795316523.562415 openat(5</workspace>, "hello.txt", O_WRONLY|O_CREAT|O_NOFOLLOW, 0644) = 3</workspace/hello.txt> <0.000055>"#,
        );
        assert_eq!(s.syscall, "openat");
        assert_eq!(
            s.args,
            r#"5</workspace>, "hello.txt", O_WRONLY|O_CREAT|O_NOFOLLOW, 0644"#
        );
        assert_eq!(s.ret, Some(3));
        assert_eq!(s.return_raw, "3</workspace/hello.txt>");
        assert_eq!(s.errno, None);
        assert_eq!(s.duration_ns, Some(55_000));
        assert!((s.timestamp_epoch.unwrap() - 1795316523.562415).abs() < 1e-6);
    }

    #[test]
    fn failure_with_errno() {
        let s =
            sys(r#"1795316523.5 mkdirat(5</workspace>, "test", 0755) = -1 EPERM (Operation not permitted) <0.000010>"#);
        assert_eq!(s.ret, Some(-1));
        assert_eq!(s.errno.as_deref(), Some("EPERM"));
        assert_eq!(s.errno_message.as_deref(), Some("Operation not permitted"));
        assert_eq!(s.duration_ns, Some(10_000));
    }

    #[test]
    fn strings_with_parens_and_equals() {
        let s = sys(r#"1.0 write(3</workspace/a>, ") = 5 \"(x\"", 11) = 11 <0.000004>"#);
        assert_eq!(s.syscall, "write");
        assert_eq!(s.ret, Some(11));
        assert!(s.args.ends_with(", 11"));
    }

    #[test]
    fn struct_args_and_unknown_return() {
        let s = sys(
            r#"1.0 openat2(5</workspace>, "a/b", {flags=O_RDONLY|O_CLOEXEC|O_DIRECTORY|O_PATH, resolve=RESOLVE_NO_MAGICLINKS|RESOLVE_BENEATH}, 24) = -1 EXDEV (Invalid cross-device link) <0.000012>"#,
        );
        assert_eq!(s.syscall, "openat2");
        assert_eq!(s.errno.as_deref(), Some("EXDEV"));
        let s = sys("1.0 exit_group(0) = ?");
        assert_eq!(s.ret, None);
        assert_eq!(s.return_raw, "?");
        let s = sys(
            "1.0 mmap(NULL, 8192, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0xffff8a3c0000 <0.000006>",
        );
        assert_eq!(s.ret, Some(0xffff8a3c0000));
    }

    #[test]
    fn markers_and_noise() {
        assert_eq!(
            parse_line(
                r#"1.0 faccessat(AT_FDCWD</workspace>, "/.sacredarts-marker/begin/42", F_OK) = -1 ENOENT (No such file or directory) <0.000005>"#
            ),
            TraceLine::Marker {
                kind: "begin".into(),
                id: 42
            }
        );
        assert!(matches!(parse_line("1.0 +++ exited with 0 +++"), TraceLine::Other(_)));
        assert!(matches!(
            parse_line("1.0 --- SIGCHLD {si_signo=SIGCHLD} ---"),
            TraceLine::Other(_)
        ));
        assert!(matches!(parse_line("garbage"), TraceLine::Other(_)));
        // a normal faccessat is not a marker
        assert!(matches!(
            parse_line(r#"1.0 faccessat(AT_FDCWD, "/etc", F_OK) = 0 <0.000001>"#),
            TraceLine::Syscall(_)
        ));
    }
}
