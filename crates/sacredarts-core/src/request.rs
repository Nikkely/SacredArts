//! Typed syscall requests and validation of untrusted (AI-provided) arguments.
//!
//! The host validates every request here before it is sent to the sandbox, and
//! the runner validates the typed request again (defence in depth).

use crate::limits::{MAX_IO_BYTES, MAX_PATH_BYTES};
use crate::syscall::SyscallName;
use base64::Engine;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::fmt;
use strum::{EnumIter, EnumString, IntoEnumIterator, IntoStaticStr, VariantNames};

/// Application-level validation failure. No syscall was issued.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidationError {
    pub code: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub field: Option<String>,
}

impl ValidationError {
    pub fn new(code: &str, message: impl Into<String>) -> Self {
        Self {
            code: code.to_string(),
            message: message.into(),
            field: None,
        }
    }

    pub fn field(mut self, field: &str) -> Self {
        self.field = Some(field.to_string());
        self
    }
}

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for ValidationError {}

/// Directory file descriptor argument of `*at` syscalls.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Dirfd {
    /// `AT_FDCWD`: resolve relative paths against the current working
    /// directory, which is `/workspace` inside the sandbox.
    AtFdcwd,
    /// Any file descriptor number; the kernel decides whether it is valid.
    Fd(i32),
}

/// Every `open(2)` flag name Linux defines, in canonical display order.
/// Numeric values are architecture dependent (e.g. `O_DIRECTORY` differs
/// between x86_64 and aarch64), so the conversion happens in the runner using
/// the target's libc constants. Bits without a name can be passed as numbers
/// (see `raw_flags`).
#[allow(non_camel_case_types)]
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, EnumIter, EnumString, IntoStaticStr, VariantNames,
)]
pub enum OpenFlag {
    O_RDONLY,
    O_WRONLY,
    O_RDWR,
    O_CREAT,
    O_EXCL,
    O_NOCTTY,
    O_TRUNC,
    O_APPEND,
    O_NONBLOCK,
    O_NDELAY,
    O_DSYNC,
    O_SYNC,
    O_RSYNC,
    O_ASYNC,
    O_DIRECT,
    O_LARGEFILE,
    O_DIRECTORY,
    O_NOFOLLOW,
    O_NOATIME,
    O_CLOEXEC,
    O_PATH,
    O_TMPFILE,
}

impl OpenFlag {
    pub fn as_str(self) -> &'static str {
        self.into()
    }

    pub fn is_access_mode(self) -> bool {
        matches!(self, OpenFlag::O_RDONLY | OpenFlag::O_WRONLY | OpenFlag::O_RDWR)
    }
}

/// `O_ACCMODE` (the access-mode bits); 3 on every Linux architecture.
pub const O_ACCMODE: u32 = 3;

/// A parsed syscall request. Arguments are passed to the kernel as given;
/// only what cannot be marshalled (NUL in a path, oversized buffers, a
/// `count` larger than the supplied data) is rejected here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "syscall", rename_all = "lowercase")]
pub enum SyscallRequest {
    Getpid,
    Openat {
        dirfd: Dirfd,
        path: String,
        /// Named flags in a canonical order without duplicates. `O_RDONLY`
        /// is added when no access mode is given (it is 0, as in C).
        flags: Vec<OpenFlag>,
        /// Extra bits given as numbers, OR-ed in verbatim.
        #[serde(default, skip_serializing_if = "is_zero")]
        raw_flags: u32,
        /// `None` is passed to the kernel as 0.
        mode: Option<u32>,
    },
    Read {
        fd: i32,
        count: usize,
    },
    Write {
        fd: i32,
        #[serde(with = "b64")]
        data: Vec<u8>,
        count: usize,
    },
    Close {
        fd: i32,
    },
    Mkdirat {
        dirfd: Dirfd,
        path: String,
        mode: u32,
    },
}

fn is_zero(v: &u32) -> bool {
    *v == 0
}

impl SyscallRequest {
    pub fn name(&self) -> SyscallName {
        match self {
            SyscallRequest::Getpid => SyscallName::Getpid,
            SyscallRequest::Openat { .. } => SyscallName::Openat,
            SyscallRequest::Read { .. } => SyscallName::Read,
            SyscallRequest::Write { .. } => SyscallName::Write,
            SyscallRequest::Close { .. } => SyscallName::Close,
            SyscallRequest::Mkdirat { .. } => SyscallName::Mkdirat,
        }
    }

    /// Parse untrusted arguments for the syscall `name`.
    pub fn from_user(name: &str, args: &Value) -> Result<Self, ValidationError> {
        let Ok(sys) = name.parse::<SyscallName>() else {
            return Err(ValidationError::new(
                "unsupported_syscall",
                format!(
                    "{name:?} is not supported. Supported syscalls: {}",
                    SyscallName::VARIANTS.join(", ")
                ),
            )
            .field("name"));
        };
        let obj = as_object(args)?;
        let req = match sys {
            SyscallName::Getpid => {
                allow_keys(&obj, &[])?;
                SyscallRequest::Getpid
            }
            SyscallName::Openat => {
                allow_keys(&obj, &["dirfd", "path", "flags", "mode"])?;
                let dirfd = parse_dirfd(obj.get("dirfd"))?;
                let path = parse_path(obj.get("path"))?;
                let (flags, raw_flags) = parse_flags(obj.get("flags"))?;
                let mode = match obj.get("mode") {
                    None | Some(Value::Null) => None,
                    Some(v) => Some(parse_mode(v, "mode")?),
                };
                SyscallRequest::Openat {
                    dirfd,
                    path,
                    flags,
                    raw_flags,
                    mode,
                }
            }
            SyscallName::Read => {
                allow_keys(&obj, &["fd", "count"])?;
                let fd = parse_fd(obj.get("fd"), "fd")?;
                let count = parse_count(obj.get("count"), "count")?.ok_or_else(|| missing("count"))?;
                SyscallRequest::Read { fd, count }
            }
            SyscallName::Write => {
                allow_keys(&obj, &["fd", "data", "encoding", "count"])?;
                let fd = parse_fd(obj.get("fd"), "fd")?;
                let data = parse_data(obj.get("data"), obj.get("encoding"))?;
                let count = parse_count(obj.get("count"), "count")?.unwrap_or(data.len());
                if count > data.len() {
                    return Err(ValidationError::new(
                        "invalid_argument",
                        format!(
                            "count ({count}) exceeds the size of data ({} bytes); \
                             reading past the buffer is not allowed",
                            data.len()
                        ),
                    )
                    .field("count"));
                }
                SyscallRequest::Write { fd, data, count }
            }
            SyscallName::Close => {
                allow_keys(&obj, &["fd"])?;
                SyscallRequest::Close {
                    fd: parse_fd(obj.get("fd"), "fd")?,
                }
            }
            SyscallName::Mkdirat => {
                allow_keys(&obj, &["dirfd", "path", "mode"])?;
                let dirfd = parse_dirfd(obj.get("dirfd"))?;
                let path = parse_path(obj.get("path"))?;
                let mode = match obj.get("mode") {
                    None | Some(Value::Null) => 0o755,
                    Some(v) => parse_mode(v, "mode")?,
                };
                SyscallRequest::Mkdirat { dirfd, path, mode }
            }
        };
        req.validate()?;
        Ok(req)
    }

    /// Re-validate a typed request (used by the runner for defence in depth).
    /// Only marshalling constraints are checked.
    pub fn validate(&self) -> Result<(), ValidationError> {
        match self {
            SyscallRequest::Getpid | SyscallRequest::Close { .. } => Ok(()),
            SyscallRequest::Openat { path, .. } | SyscallRequest::Mkdirat { path, .. } => validate_path(path),
            SyscallRequest::Read { count, .. } => check_count(*count, "count"),
            SyscallRequest::Write { data, count, .. } => {
                check_count(data.len(), "data")?;
                if *count > data.len() {
                    return Err(ValidationError::new("invalid_argument", "count exceeds data length").field("count"));
                }
                Ok(())
            }
        }
    }
}

/// Only rejects paths that cannot be passed to the kernel at all (NUL bytes)
/// or are too large to marshal. Empty paths, overlong names and where a path
/// leads are all decided by the kernel (ENOENT, ENAMETOOLONG, EACCES, ...).
pub fn validate_path(path: &str) -> Result<(), ValidationError> {
    if path.len() > MAX_PATH_BYTES {
        return Err(ValidationError::new(
            "limit_exceeded",
            format!("path is longer than {MAX_PATH_BYTES} bytes (the kernel's PATH_MAX is 4096)"),
        )
        .field("path"));
    }
    if path.contains('\0') {
        return Err(ValidationError::new(
            "invalid_path",
            "path must not contain NUL bytes (a C string ends at the first NUL)",
        )
        .field("path"));
    }
    Ok(())
}

fn as_object(args: &Value) -> Result<Map<String, Value>, ValidationError> {
    match args {
        Value::Null => Ok(Map::new()),
        Value::Object(m) => Ok(m.clone()),
        _ => Err(ValidationError::new("invalid_argument", "args must be a JSON object").field("args")),
    }
}

fn allow_keys(obj: &Map<String, Value>, allowed: &[&str]) -> Result<(), ValidationError> {
    for k in obj.keys() {
        if !allowed.contains(&k.as_str()) {
            let hint = if allowed.is_empty() {
                "this syscall takes no arguments".to_string()
            } else {
                format!("allowed keys: {}", allowed.join(", "))
            };
            return Err(ValidationError::new("unknown_argument", format!("unknown argument {k:?}; {hint}")).field(k));
        }
    }
    Ok(())
}

fn missing(field: &str) -> ValidationError {
    ValidationError::new("missing_argument", format!("{field} is required")).field(field)
}

fn parse_dirfd(v: Option<&Value>) -> Result<Dirfd, ValidationError> {
    match v {
        None | Some(Value::Null) => Ok(Dirfd::AtFdcwd),
        Some(Value::String(s)) if s.trim() == "AT_FDCWD" => Ok(Dirfd::AtFdcwd),
        Some(v) => match parse_fd(Some(v), "dirfd")? {
            // AT_FDCWD is -100 on Linux; show it by name.
            -100 => Ok(Dirfd::AtFdcwd),
            n => Ok(Dirfd::Fd(n)),
        },
    }
}

/// Any `int` is accepted; the kernel decides whether it is an open fd.
fn parse_fd(v: Option<&Value>, field: &str) -> Result<i32, ValidationError> {
    let v = v.ok_or_else(|| missing(field))?;
    let n = match v {
        Value::Number(n) => n.as_i64(),
        Value::String(s) => s.trim().parse::<i64>().ok(),
        _ => None,
    }
    .and_then(|n| i32::try_from(n).ok())
    .ok_or_else(|| {
        ValidationError::new("invalid_argument", format!("{field} must be an integer (C int)")).field(field)
    })?;
    Ok(n)
}

fn parse_path(v: Option<&Value>) -> Result<String, ValidationError> {
    match v {
        Some(Value::String(s)) => {
            validate_path(s)?;
            Ok(s.clone())
        }
        None | Some(Value::Null) => Err(missing("path")),
        _ => Err(ValidationError::new("invalid_argument", "path must be a string").field("path")),
    }
}

/// Parse a C integer literal: `0x1f`, `0o17`, `017` (octal, as in C) or decimal.
fn parse_c_int(t: &str) -> Option<u64> {
    let t = t.trim();
    if let Some(h) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        u64::from_str_radix(h, 16).ok()
    } else if let Some(o) = t.strip_prefix("0o") {
        u64::from_str_radix(o, 8).ok()
    } else if t.len() > 1 && t.starts_with('0') {
        u64::from_str_radix(&t[1..], 8).ok()
    } else {
        t.parse().ok()
    }
}

fn flag_bits_from_number(n: &serde_json::Number) -> Option<u32> {
    if let Some(u) = n.as_u64() {
        u32::try_from(u).ok()
    } else {
        // negative ints are passed as their two's complement bits, like C
        n.as_i64().and_then(|i| i32::try_from(i).ok()).map(|i| i as u32)
    }
}

fn bad_flags(msg: impl Into<String>) -> ValidationError {
    ValidationError::new("invalid_flags", msg).field("flags")
}

/// One piece of the `flags` argument.
enum FlagPart {
    Name(OpenFlag),
    Bits(u32),
}

/// One `|`-separated token: a flag name or a C integer literal.
fn flag_token(t: &str) -> Result<FlagPart, ValidationError> {
    if let Ok(f) = t.parse::<OpenFlag>() {
        return Ok(FlagPart::Name(f));
    }
    parse_c_int(t)
        .and_then(|n| u32::try_from(n).ok())
        .map(FlagPart::Bits)
        .ok_or_else(|| {
            bad_flags(format!(
                "unknown flag {t:?}; use O_* names ({}) or numbers like 0x80000",
                OpenFlag::VARIANTS.join(" ")
            ))
        })
}

fn flag_parts(v: &Value) -> Result<Vec<FlagPart>, ValidationError> {
    match v {
        Value::String(s) => s
            .split('|')
            .map(str::trim)
            .filter(|t| !t.is_empty())
            .map(flag_token)
            .collect(),
        Value::Number(n) => flag_bits_from_number(n)
            .map(|b| vec![FlagPart::Bits(b)])
            .ok_or_else(|| bad_flags("flags must fit in a C int")),
        _ => Err(bad_flags("flags must be names like \"O_CREAT\" or numbers")),
    }
}

/// Flags may be names, numbers, or a mix (`"O_RDWR|0x200000"`, `[2, "O_CREAT"]`, `66`).
fn parse_flags(v: Option<&Value>) -> Result<(Vec<OpenFlag>, u32), ValidationError> {
    let parts: Vec<FlagPart> = match v {
        None | Some(Value::Null) => vec![],
        Some(Value::Array(items)) => items
            .iter()
            .map(flag_parts)
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .flatten()
            .collect(),
        Some(x @ (Value::String(_) | Value::Number(_))) => flag_parts(x)?,
        _ => return Err(bad_flags("flags must be an array, a \"O_A|O_B\" string or a number")),
    };
    let raw = parts.iter().fold(0, |acc, p| match p {
        FlagPart::Bits(b) => acc | b,
        FlagPart::Name(_) => acc,
    });
    let given: Vec<OpenFlag> = parts
        .iter()
        .filter_map(|p| match p {
            FlagPart::Name(f) => Some(*f),
            FlagPart::Bits(_) => None,
        })
        .collect();
    // O_RDONLY is 0, so "no access mode" means read-only, exactly as in C.
    let implicit_rdonly = !given.iter().any(|f| f.is_access_mode()) && raw & O_ACCMODE == 0;
    let names = OpenFlag::iter()
        .filter(|f| given.contains(f) || (implicit_rdonly && *f == OpenFlag::O_RDONLY))
        .collect();
    Ok((names, raw))
}

/// `mode_t` is passed verbatim (including setuid/setgid/sticky bits); the
/// kernel applies the umask and decides what is allowed.
fn parse_mode(v: &Value, field: &str) -> Result<u32, ValidationError> {
    let bad = || {
        ValidationError::new(
            "invalid_mode",
            format!("{field} must be an octal string like \"0644\" or an integer"),
        )
        .field(field)
    };
    match v {
        // Strings are octal, like in C source ("0644" or "644").
        Value::String(s) => {
            let t = s.trim().trim_start_matches("0o");
            u32::from_str_radix(t, 8).map_err(|_| bad())
        }
        // Integers are taken literally (420 == 0o644).
        Value::Number(n) => flag_bits_from_number(n).ok_or_else(bad),
        _ => Err(bad()),
    }
}

fn parse_count(v: Option<&Value>, field: &str) -> Result<Option<usize>, ValidationError> {
    match v {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Number(n)) => {
            let c = n
                .as_u64()
                .ok_or_else(|| ValidationError::new("invalid_argument", format!("{field} must be >= 0")).field(field))?
                as usize;
            check_count(c, field)?;
            Ok(Some(c))
        }
        _ => Err(ValidationError::new("invalid_argument", format!("{field} must be an integer")).field(field)),
    }
}

fn check_count(c: usize, field: &str) -> Result<(), ValidationError> {
    if c > MAX_IO_BYTES {
        return Err(ValidationError::new(
            "limit_exceeded",
            format!("{field} is limited to {MAX_IO_BYTES} bytes per call (got {c})"),
        )
        .field(field));
    }
    Ok(())
}

fn parse_data(data: Option<&Value>, enc: Option<&Value>) -> Result<Vec<u8>, ValidationError> {
    let s = match data {
        Some(Value::String(s)) => s,
        None | Some(Value::Null) => return Err(missing("data")),
        _ => {
            return Err(ValidationError::new("invalid_argument", "data must be a string").field("data"));
        }
    };
    let enc = match enc {
        None | Some(Value::Null) => "utf8",
        Some(Value::String(e)) => e.as_str(),
        _ => "",
    };
    let bytes = match enc {
        "utf8" | "utf-8" => s.as_bytes().to_vec(),
        "base64" => base64::engine::general_purpose::STANDARD.decode(s).map_err(|e| {
            ValidationError::new("invalid_argument", format!("data is not valid base64: {e}")).field("data")
        })?,
        _ => {
            return Err(
                ValidationError::new("invalid_argument", "encoding must be \"utf8\" or \"base64\"").field("encoding"),
            );
        }
    };
    check_count(bytes.len(), "data")?;
    Ok(bytes)
}

/// serde helper: `Vec<u8>` as standard base64.
pub mod b64 {
    use base64::Engine;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&base64::engine::general_purpose::STANDARD.encode(v))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        base64::engine::general_purpose::STANDARD
            .decode(s)
            .map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn openat_parsing() {
        let r = SyscallRequest::from_user(
            "openat",
            &json!({"path": "/workspace/hello.txt", "flags": ["O_CREAT", "O_WRONLY"], "mode": "0644"}),
        )
        .unwrap();
        assert_eq!(
            r,
            SyscallRequest::Openat {
                dirfd: Dirfd::AtFdcwd,
                path: "/workspace/hello.txt".into(),
                flags: vec![OpenFlag::O_WRONLY, OpenFlag::O_CREAT],
                raw_flags: 0,
                mode: Some(0o644),
            }
        );
        let flags = |v: Value| match SyscallRequest::from_user("openat", &json!({"path": "a", "flags": v})).unwrap() {
            SyscallRequest::Openat { flags, raw_flags, .. } => (flags, raw_flags),
            _ => unreachable!(),
        };
        // default access mode
        assert_eq!(
            flags(json!("O_DIRECTORY")),
            (vec![OpenFlag::O_RDONLY, OpenFlag::O_DIRECTORY], 0)
        );
        // every Linux flag name is accepted
        assert_eq!(
            flags(json!("O_PATH|O_TMPFILE|O_NONBLOCK")).0,
            vec![
                OpenFlag::O_RDONLY,
                OpenFlag::O_NONBLOCK,
                OpenFlag::O_PATH,
                OpenFlag::O_TMPFILE
            ]
        );
        // contradictory access modes are passed on (the kernel decides)
        assert_eq!(
            flags(json!(["O_WRONLY", "O_RDWR"])).0,
            vec![OpenFlag::O_WRONLY, OpenFlag::O_RDWR]
        );
        // numbers, mixed with names, in C notation
        assert_eq!(flags(json!(66)), (vec![], 66));
        assert_eq!(flags(json!("O_RDWR|0x200000")), (vec![OpenFlag::O_RDWR], 0x20_0000));
        assert_eq!(flags(json!([0o100, "O_WRONLY"])), (vec![OpenFlag::O_WRONLY], 0o100));
        assert_eq!(flags(json!("0100")), (vec![OpenFlag::O_RDONLY], 0o100));
        assert_eq!(flags(json!(-1)), (vec![], u32::MAX));
    }

    #[test]
    fn openat_passes_odd_arguments_to_the_kernel() {
        let ok = |v: Value| SyscallRequest::from_user("openat", &v).unwrap();
        // O_CREAT without mode: mode 0 is passed, as the kernel would see it
        assert!(matches!(
            ok(json!({"path": "a", "flags": ["O_CREAT", "O_WRONLY"]})),
            SyscallRequest::Openat { mode: None, .. }
        ));
        assert!(matches!(
            ok(json!({"path": "a", "mode": "4755"})),
            SyscallRequest::Openat { mode: Some(0o4755), .. }
        ));
        assert!(matches!(
            ok(json!({"path": "a", "dirfd": -5})),
            SyscallRequest::Openat {
                dirfd: Dirfd::Fd(-5),
                ..
            }
        ));
        assert!(matches!(
            ok(json!({"path": "a", "dirfd": -100})),
            SyscallRequest::Openat {
                dirfd: Dirfd::AtFdcwd,
                ..
            }
        ));
        // empty and overlong paths are the kernel's business (ENOENT / ENAMETOOLONG)
        ok(json!({"path": ""}));
        ok(json!({"path": "x".repeat(300)}));
        ok(json!({"path": "a/".repeat(3000)}));
        // Any path is accepted; the kernel decides.
        for p in ["/etc/passwd", "/", "../etc/passwd", "/workspace/../etc"] {
            ok(json!({ "path": p }));
        }
    }

    #[test]
    fn openat_rejections() {
        let e = |v: Value| SyscallRequest::from_user("openat", &v).unwrap_err().code;
        assert_eq!(e(json!({"path": "a\u{0}b"})), "invalid_path");
        assert_eq!(e(json!({"path": "x".repeat(70_000)})), "limit_exceeded");
        assert_eq!(e(json!({"path": "a", "flags": ["O_BOGUS"]})), "invalid_flags");
        assert_eq!(e(json!({"path": "a", "flags": 1u64 << 40})), "invalid_flags");
        assert_eq!(e(json!({"path": "a", "mode": "08"})), "invalid_mode");
        assert_eq!(e(json!({"path": "a", "bogus": 1})), "unknown_argument");
        assert_eq!(e(json!({"path": "a", "dirfd": 1u64 << 40})), "invalid_argument");
    }

    #[test]
    fn rw_parsing() {
        let r = SyscallRequest::from_user("write", &json!({"fd": 3, "data": "Hello"})).unwrap();
        assert_eq!(
            r,
            SyscallRequest::Write {
                fd: 3,
                data: b"Hello".to_vec(),
                count: 5
            }
        );
        let r = SyscallRequest::from_user(
            "write",
            &json!({"fd": 3, "data": "AGhp", "encoding": "base64", "count": 2}),
        )
        .unwrap();
        assert_eq!(
            r,
            SyscallRequest::Write {
                fd: 3,
                data: vec![0, b'h', b'i'],
                count: 2
            }
        );
        assert_eq!(
            SyscallRequest::from_user("write", &json!({"fd": 3, "data": "ab", "count": 3}))
                .unwrap_err()
                .code,
            "invalid_argument"
        );
        assert_eq!(
            SyscallRequest::from_user("read", &json!({"fd": 3, "count": 1_000_000}))
                .unwrap_err()
                .code,
            "limit_exceeded"
        );
        assert_eq!(
            SyscallRequest::from_user("read", &json!({"fd": 3})).unwrap_err().code,
            "missing_argument"
        );
        // any int is passed to the kernel (EBADF comes from there)
        assert_eq!(
            SyscallRequest::from_user("close", &json!({"fd": -1})).unwrap(),
            SyscallRequest::Close { fd: -1 }
        );
        assert_eq!(
            SyscallRequest::from_user("close", &json!({"fd": "x"}))
                .unwrap_err()
                .code,
            "invalid_argument"
        );
    }

    #[test]
    fn other_parsing() {
        assert_eq!(
            SyscallRequest::from_user("getpid", &Value::Null).unwrap(),
            SyscallRequest::Getpid
        );
        assert_eq!(
            SyscallRequest::from_user("getpid", &json!({"x": 1})).unwrap_err().code,
            "unknown_argument"
        );
        assert_eq!(
            SyscallRequest::from_user("execve", &json!({})).unwrap_err().code,
            "unsupported_syscall"
        );
        let r = SyscallRequest::from_user("mkdirat", &json!({"path": "d", "dirfd": "AT_FDCWD"})).unwrap();
        assert_eq!(
            r,
            SyscallRequest::Mkdirat {
                dirfd: Dirfd::AtFdcwd,
                path: "d".into(),
                mode: 0o755
            }
        );
        let r = SyscallRequest::from_user("mkdirat", &json!({"path": "d", "dirfd": 4, "mode": 448})).unwrap();
        assert_eq!(
            r,
            SyscallRequest::Mkdirat {
                dirfd: Dirfd::Fd(4),
                path: "d".into(),
                mode: 0o700
            }
        );
    }

    #[test]
    fn serde_roundtrip() {
        let r = SyscallRequest::Write {
            fd: 3,
            data: vec![0, 1, 2, 255],
            count: 4,
        };
        let s = serde_json::to_string(&r).unwrap();
        assert_eq!(serde_json::from_str::<SyscallRequest>(&s).unwrap(), r);
    }
}
