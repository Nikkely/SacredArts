//! strace-like one-line formatting of requested syscalls.

use crate::request::{Dirfd, OpenFlag, SyscallRequest};

/// Number of bytes of a buffer shown in formatted output (like `strace -s`).
pub const DISPLAY_BYTES: usize = 32;

/// C-style quoted and escaped byte string, truncated like strace (`"abc"...`).
pub fn quote_bytes(data: &[u8], max: usize) -> String {
    let mut s = String::from("\"");
    for &b in data.iter().take(max) {
        match b {
            b'"' => s.push_str("\\\""),
            b'\\' => s.push_str("\\\\"),
            b'\n' => s.push_str("\\n"),
            b'\t' => s.push_str("\\t"),
            b'\r' => s.push_str("\\r"),
            0 => s.push_str("\\0"),
            0x20..=0x7e => s.push(b as char),
            _ => s.push_str(&format!("\\x{b:02x}")),
        }
    }
    s.push('"');
    if data.len() > max {
        s.push_str("...");
    }
    s
}

pub fn quote_str(s: &str) -> String {
    quote_bytes(s.as_bytes(), usize::MAX)
}

pub fn format_dirfd(d: Dirfd) -> String {
    match d {
        Dirfd::AtFdcwd => "AT_FDCWD".to_string(),
        Dirfd::Handle(h) => h.to_string(),
    }
}

pub fn format_flags(flags: &[OpenFlag]) -> String {
    flags.iter().map(|f| f.as_str()).collect::<Vec<_>>().join("|")
}

pub fn format_mode(mode: u32) -> String {
    format!("{mode:04o}")
}

/// Format the call part, e.g. `openat(AT_FDCWD, "a", O_RDONLY)`.
/// For `read`, the buffer is an output argument; pass the bytes actually read.
pub fn format_call(req: &SyscallRequest, read_data: Option<&[u8]>) -> String {
    match req {
        SyscallRequest::Getpid => "getpid()".to_string(),
        SyscallRequest::Openat {
            dirfd,
            path,
            flags,
            mode,
        } => {
            let mut s = format!(
                "openat({}, {}, {}",
                format_dirfd(*dirfd),
                quote_str(path),
                format_flags(flags)
            );
            if let Some(m) = mode {
                s.push_str(&format!(", {}", format_mode(*m)));
            }
            s.push(')');
            s
        }
        SyscallRequest::Read { fd, count } => {
            let buf = match read_data {
                Some(d) => quote_bytes(d, DISPLAY_BYTES),
                None => "<buf>".to_string(),
            };
            format!("read({fd}, {buf}, {count})")
        }
        SyscallRequest::Write { fd, data, count } => {
            format!("write({fd}, {}, {count})", quote_bytes(&data[..*count], DISPLAY_BYTES))
        }
        SyscallRequest::Close { fd } => format!("close({fd})"),
        SyscallRequest::Mkdirat { dirfd, path, mode } => format!(
            "mkdirat({}, {}, {})",
            format_dirfd(*dirfd),
            quote_str(path),
            format_mode(*mode)
        ),
    }
}

/// Format the result part, e.g. ` = 3` or ` = -1 ENOENT (No such file or directory)`.
pub fn format_result(ret: i64, errno: Option<(&str, &str)>) -> String {
    match errno {
        Some((name, msg)) => format!(" = {ret} {name} ({msg})"),
        None => format!(" = {ret}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_like_strace() {
        let r = SyscallRequest::Openat {
            dirfd: Dirfd::AtFdcwd,
            path: "hello.txt".into(),
            flags: vec![OpenFlag::O_WRONLY, OpenFlag::O_CREAT],
            mode: Some(0o644),
        };
        assert_eq!(
            format_call(&r, None) + &format_result(3, None),
            "openat(AT_FDCWD, \"hello.txt\", O_WRONLY|O_CREAT, 0644) = 3"
        );
        let w = SyscallRequest::Write {
            fd: 3,
            data: b"Hello\n\0".to_vec(),
            count: 7,
        };
        assert_eq!(format_call(&w, None), "write(3, \"Hello\\n\\0\", 7)");
        let r = SyscallRequest::Read { fd: 3, count: 100 };
        assert_eq!(format_call(&r, Some(b"Hello")), "read(3, \"Hello\", 100)");
        assert_eq!(
            format_result(-1, Some(("EPERM", "Operation not permitted"))),
            " = -1 EPERM (Operation not permitted)"
        );
        assert_eq!(quote_bytes(&[b'a'; 40], 32), format!("\"{}\"...", "a".repeat(32)));
    }
}
