//! strace-like one-line formatting of requested syscalls.

use crate::request::{Dirfd, OpenFlag, SyscallRequest};

/// Number of bytes of a buffer shown in formatted output (like `strace -s`).
pub const DISPLAY_BYTES: usize = 32;

/// C-style quoted and escaped byte string, truncated like strace (`"abc"...`).
#[must_use]
pub fn quote_bytes(data: &[u8], max: usize) -> String {
    let body: String = data
        .iter()
        .take(max)
        .map(|&b| match b {
            b'"' => "\\\"".to_string(),
            b'\\' => "\\\\".to_string(),
            b'\n' => "\\n".to_string(),
            b'\t' => "\\t".to_string(),
            b'\r' => "\\r".to_string(),
            0 => "\\0".to_string(),
            0x20..=0x7e => (b as char).to_string(),
            _ => format!("\\x{b:02x}"),
        })
        .collect();
    let more = if data.len() > max { "..." } else { "" };
    format!("\"{body}\"{more}")
}

#[must_use]
pub fn quote_str(s: &str) -> String {
    quote_bytes(s.as_bytes(), usize::MAX)
}

#[must_use]
pub fn format_dirfd(d: Dirfd) -> String {
    match d {
        Dirfd::AtFdcwd => "AT_FDCWD".to_string(),
        Dirfd::Fd(n) => n.to_string(),
    }
}

/// Named flags followed by any numeric bits (`O_RDWR|0x200000`).
#[must_use]
pub fn format_flags(flags: &[OpenFlag], raw: u32) -> String {
    let bits = (raw != 0 || flags.is_empty()).then(|| format!("{raw:#x}"));
    flags
        .iter()
        .map(|f| f.as_str().to_string())
        .chain(bits)
        .collect::<Vec<_>>()
        .join("|")
}

/// Octal with a leading 0, like strace (`0644`, `04755`, `0000`).
#[must_use]
pub fn format_mode(mode: u32) -> String {
    format!("0{mode:03o}")
}

/// Format the call part, e.g. `openat(AT_FDCWD, "a", O_RDONLY)`.
/// For `read`, the buffer is an output argument; pass the bytes actually read.
#[must_use]
pub fn format_call(req: &SyscallRequest, read_data: Option<&[u8]>) -> String {
    match req {
        SyscallRequest::Getpid => "getpid()".to_string(),
        SyscallRequest::Openat {
            dirfd,
            path,
            flags,
            raw_flags,
            mode,
        } => format!(
            "openat({}, {}, {}{})",
            format_dirfd(*dirfd),
            quote_str(path),
            format_flags(flags, *raw_flags),
            mode.map(|m| format!(", {}", format_mode(m))).unwrap_or_default()
        ),
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
#[must_use]
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
            raw_flags: 0,
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
        assert_eq!(format_flags(&[OpenFlag::O_RDWR], 0x20_0000), "O_RDWR|0x200000");
        assert_eq!(format_flags(&[], 66), "0x42");
        assert_eq!(format_mode(0o4755), "04755");
        assert_eq!(format_mode(0), "0000");
        assert_eq!(quote_bytes(&[b'a'; 40], 32), format!("\"{}\"...", "a".repeat(32)));
    }
}
