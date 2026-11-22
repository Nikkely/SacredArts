//! Typed syscall requests and validation of untrusted (AI-provided) arguments.
//!
//! The host validates every request here before it is sent to the sandbox, and
//! the runner validates the typed request again (defence in depth).

use crate::limits::{MAX_COMPONENT_BYTES, MAX_IO_BYTES, MAX_PATH_BYTES};
use crate::syscall::SyscallName;
use base64::Engine;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::fmt;
use std::path::{Component, Path};

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
    /// directory, which is always `/workspace` inside the sandbox.
    AtFdcwd,
    /// A learning handle previously returned by `openat`.
    Handle(u32),
}

/// `openat` flags supported by the MVP. Numeric values are architecture
/// dependent (e.g. `O_DIRECTORY` differs between x86_64 and aarch64), so the
/// conversion happens in the runner using the target's libc constants.
#[allow(non_camel_case_types)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum OpenFlag {
    O_RDONLY,
    O_WRONLY,
    O_RDWR,
    O_CREAT,
    O_EXCL,
    O_TRUNC,
    O_APPEND,
    O_DIRECTORY,
    O_NOFOLLOW,
    O_CLOEXEC,
}

impl OpenFlag {
    pub const ALL: [OpenFlag; 10] = [
        OpenFlag::O_RDONLY,
        OpenFlag::O_WRONLY,
        OpenFlag::O_RDWR,
        OpenFlag::O_CREAT,
        OpenFlag::O_EXCL,
        OpenFlag::O_TRUNC,
        OpenFlag::O_APPEND,
        OpenFlag::O_DIRECTORY,
        OpenFlag::O_NOFOLLOW,
        OpenFlag::O_CLOEXEC,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            OpenFlag::O_RDONLY => "O_RDONLY",
            OpenFlag::O_WRONLY => "O_WRONLY",
            OpenFlag::O_RDWR => "O_RDWR",
            OpenFlag::O_CREAT => "O_CREAT",
            OpenFlag::O_EXCL => "O_EXCL",
            OpenFlag::O_TRUNC => "O_TRUNC",
            OpenFlag::O_APPEND => "O_APPEND",
            OpenFlag::O_DIRECTORY => "O_DIRECTORY",
            OpenFlag::O_NOFOLLOW => "O_NOFOLLOW",
            OpenFlag::O_CLOEXEC => "O_CLOEXEC",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|f| f.as_str() == s)
    }

    pub fn is_access_mode(self) -> bool {
        matches!(self, OpenFlag::O_RDONLY | OpenFlag::O_WRONLY | OpenFlag::O_RDWR)
    }
}

/// A fully validated syscall request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "syscall", rename_all = "lowercase")]
pub enum SyscallRequest {
    Getpid,
    Openat {
        dirfd: Dirfd,
        path: String,
        /// Normalised: exactly one access mode first, then the other flags
        /// in a canonical order without duplicates.
        flags: Vec<OpenFlag>,
        mode: Option<u32>,
    },
    Read {
        fd: u32,
        count: usize,
    },
    Write {
        fd: u32,
        #[serde(with = "b64")]
        data: Vec<u8>,
        count: usize,
    },
    Close {
        fd: u32,
    },
    Mkdirat {
        dirfd: Dirfd,
        path: String,
        mode: u32,
    },
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

    /// Parse and validate untrusted arguments for the syscall `name`.
    pub fn from_user(name: &str, args: &Value) -> Result<Self, ValidationError> {
        let Some(sys) = SyscallName::parse(name) else {
            return Err(ValidationError::new(
                "unsupported_syscall",
                format!(
                    "{name:?} is not supported. Supported syscalls: {}",
                    SyscallName::names().join(", ")
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
                let flags = parse_flags(obj.get("flags"))?;
                let mode = match obj.get("mode") {
                    None | Some(Value::Null) => None,
                    Some(v) => Some(parse_mode(v, "mode")?),
                };
                if flags.contains(&OpenFlag::O_CREAT) && mode.is_none() {
                    return Err(ValidationError::new(
                        "missing_argument",
                        "mode is required when O_CREAT is set (e.g. \"0644\")",
                    )
                    .field("mode"));
                }
                SyscallRequest::Openat {
                    dirfd,
                    path,
                    flags,
                    mode,
                }
            }
            SyscallName::Read => {
                allow_keys(&obj, &["fd", "count"])?;
                let fd = parse_handle(obj.get("fd"), "fd")?;
                let count = parse_count(obj.get("count"), "count")?.ok_or_else(|| missing("count"))?;
                SyscallRequest::Read { fd, count }
            }
            SyscallName::Write => {
                allow_keys(&obj, &["fd", "data", "encoding", "count"])?;
                let fd = parse_handle(obj.get("fd"), "fd")?;
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
                    fd: parse_handle(obj.get("fd"), "fd")?,
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
    pub fn validate(&self) -> Result<(), ValidationError> {
        match self {
            SyscallRequest::Getpid => Ok(()),
            SyscallRequest::Openat { path, flags, mode, .. } => {
                validate_path(path)?;
                let access = flags.iter().filter(|f| f.is_access_mode()).count();
                if access != 1 {
                    return Err(ValidationError::new(
                        "invalid_flags",
                        "exactly one of O_RDONLY, O_WRONLY, O_RDWR must be given",
                    )
                    .field("flags"));
                }
                if let Some(m) = mode {
                    check_mode(*m, "mode")?;
                }
                Ok(())
            }
            SyscallRequest::Read { count, .. } => check_count(*count, "count"),
            SyscallRequest::Write { data, count, .. } => {
                check_count(data.len(), "data")?;
                if *count > data.len() {
                    return Err(ValidationError::new("invalid_argument", "count exceeds data length").field("count"));
                }
                Ok(())
            }
            SyscallRequest::Close { .. } => Ok(()),
            SyscallRequest::Mkdirat { path, mode, .. } => {
                validate_path(path)?;
                check_mode(*mode, "mode")
            }
        }
    }
}

/// Lexical path validation. Only rejects paths that cannot be passed to the
/// kernel sensibly (empty, NUL, oversized). Where a path may lead is decided
/// by the kernel inside the sandbox container, not here.
pub fn validate_path(path: &str) -> Result<(), ValidationError> {
    if path.is_empty() {
        return Err(ValidationError::new("invalid_path", "path must not be empty").field("path"));
    }
    if path.len() > MAX_PATH_BYTES {
        return Err(
            ValidationError::new("invalid_path", format!("path is longer than {MAX_PATH_BYTES} bytes")).field("path"),
        );
    }
    if path.contains('\0') {
        return Err(ValidationError::new("invalid_path", "path must not contain NUL bytes").field("path"));
    }
    let p = Path::new(path);
    for c in p.components() {
        if let Component::Normal(s) = c
            && s.len() > MAX_COMPONENT_BYTES
        {
            return Err(ValidationError::new(
                "invalid_path",
                format!("a path component is longer than {MAX_COMPONENT_BYTES} bytes"),
            )
            .field("path"));
        }
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
        Some(Value::String(s)) if s == "AT_FDCWD" => Ok(Dirfd::AtFdcwd),
        Some(Value::Number(n)) if n.as_i64() == Some(-100) => Ok(Dirfd::AtFdcwd),
        Some(v) => Ok(Dirfd::Handle(parse_handle(Some(v), "dirfd")?)),
    }
}

fn parse_handle(v: Option<&Value>, field: &str) -> Result<u32, ValidationError> {
    let v = v.ok_or_else(|| missing(field))?;
    let n = match v {
        Value::Number(n) => n.as_i64(),
        Value::String(s) => s.trim().parse::<i64>().ok(),
        _ => None,
    }
    .ok_or_else(|| {
        ValidationError::new("invalid_argument", format!("{field} must be an integer handle")).field(field)
    })?;
    if !(0..=i64::from(i32::MAX)).contains(&n) {
        return Err(ValidationError::new(
            "invalid_argument",
            format!("{field} must be a non-negative handle number"),
        )
        .field(field));
    }
    Ok(n as u32)
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

fn parse_flags(v: Option<&Value>) -> Result<Vec<OpenFlag>, ValidationError> {
    let names: Vec<String> = match v {
        None | Some(Value::Null) => vec!["O_RDONLY".into()],
        Some(Value::String(s)) => s.split('|').map(|x| x.trim().to_string()).collect(),
        Some(Value::Array(a)) => a
            .iter()
            .map(|x| {
                x.as_str().map(|s| s.trim().to_string()).ok_or_else(|| {
                    ValidationError::new("invalid_flags", "flags must be strings like \"O_CREAT\"").field("flags")
                })
            })
            .collect::<Result<_, _>>()?,
        _ => {
            return Err(ValidationError::new(
                "invalid_flags",
                "flags must be an array of names or a \"O_A|O_B\" string",
            )
            .field("flags"));
        }
    };
    let mut set = Vec::new();
    for n in names.iter().filter(|n| !n.is_empty()) {
        let f = OpenFlag::parse(n).ok_or_else(|| {
            ValidationError::new(
                "invalid_flags",
                format!(
                    "unsupported flag {n:?}; supported: {}",
                    OpenFlag::ALL.map(|f| f.as_str()).join(", ")
                ),
            )
            .field("flags")
        })?;
        if !set.contains(&f) {
            set.push(f);
        }
    }
    let access: Vec<OpenFlag> = set.iter().copied().filter(|f| f.is_access_mode()).collect();
    if access.len() > 1 {
        return Err(
            ValidationError::new("invalid_flags", "only one of O_RDONLY, O_WRONLY, O_RDWR may be given").field("flags"),
        );
    }
    // O_RDONLY is 0, so "no access mode" means read-only, exactly as in C.
    let mut out = vec![access.first().copied().unwrap_or(OpenFlag::O_RDONLY)];
    for f in OpenFlag::ALL {
        if !f.is_access_mode() && set.contains(&f) {
            out.push(f);
        }
    }
    Ok(out)
}

fn parse_mode(v: &Value, field: &str) -> Result<u32, ValidationError> {
    let m = match v {
        // Strings are octal, like in C source ("0644" or "644").
        Value::String(s) => {
            let t = s.trim().trim_start_matches("0o");
            u32::from_str_radix(t, 8).map_err(|_| {
                ValidationError::new(
                    "invalid_mode",
                    format!("{field} must be an octal string like \"0644\"; got {s:?}"),
                )
                .field(field)
            })?
        }
        // Integers are taken literally (420 == 0o644).
        Value::Number(n) => n.as_u64().and_then(|x| u32::try_from(x).ok()).ok_or_else(|| {
            ValidationError::new("invalid_mode", format!("{field} must be non-negative")).field(field)
        })?,
        _ => {
            return Err(
                ValidationError::new("invalid_mode", format!("{field} must be an octal string like \"0644\""))
                    .field(field),
            );
        }
    };
    check_mode(m, field)?;
    Ok(m)
}

fn check_mode(m: u32, field: &str) -> Result<(), ValidationError> {
    // setuid/setgid/sticky bits are deliberately not supported.
    if m > 0o777 {
        return Err(ValidationError::new(
            "invalid_mode",
            format!("{field} must be between 0000 and 0777 (got {m:#o})"),
        )
        .field(field));
    }
    Ok(())
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
                mode: Some(0o644),
            }
        );
        // string flags, default access mode
        let r = SyscallRequest::from_user("openat", &json!({"path": "a", "flags": "O_DIRECTORY"})).unwrap();
        assert!(
            matches!(r, SyscallRequest::Openat { ref flags, .. } if flags == &vec![OpenFlag::O_RDONLY, OpenFlag::O_DIRECTORY])
        );
    }

    #[test]
    fn openat_rejections() {
        let e = |v: Value| SyscallRequest::from_user("openat", &v).unwrap_err().code;
        assert_eq!(e(json!({"path": ""})), "invalid_path");
        assert_eq!(e(json!({"path": "a\u{0}b"})), "invalid_path");
        assert_eq!(e(json!({"path": "a", "flags": ["O_PATH"]})), "invalid_flags");
        assert_eq!(
            e(json!({"path": "a", "flags": ["O_RDONLY", "O_WRONLY"]})),
            "invalid_flags"
        );
        assert_eq!(
            e(json!({"path": "a", "flags": ["O_CREAT", "O_WRONLY"]})),
            "missing_argument"
        );
        assert_eq!(e(json!({"path": "a", "mode": "4755"})), "invalid_mode");
        assert_eq!(e(json!({"path": "a", "mode": "08"})), "invalid_mode");
        assert_eq!(e(json!({"path": "a", "bogus": 1})), "unknown_argument");
        assert_eq!(e(json!({"path": "a", "dirfd": -5})), "invalid_argument");
        assert_eq!(e(json!({"path": "x".repeat(300)})), "invalid_path");
        assert_eq!(e(json!({"path": "a/".repeat(600)})), "invalid_path");
        // Any path is accepted; the kernel decides.
        assert!(SyscallRequest::from_user("openat", &json!({"path": "/etc/passwd"})).is_ok());
        assert!(SyscallRequest::from_user("openat", &json!({"path": "/"})).is_ok());
        assert!(SyscallRequest::from_user("openat", &json!({"path": "../etc/passwd"})).is_ok());
        assert!(SyscallRequest::from_user("openat", &json!({"path": "/workspace/../etc"})).is_ok());
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
                dirfd: Dirfd::Handle(4),
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
