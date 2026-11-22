//! errno number -> symbolic name / message (target libc constants).

use sacredarts_core::ipc::ErrnoInfo;

pub fn name(e: i32) -> &'static str {
    match e {
        libc::EPERM => "EPERM",
        libc::ENOENT => "ENOENT",
        libc::ESRCH => "ESRCH",
        libc::EINTR => "EINTR",
        libc::EIO => "EIO",
        libc::ENXIO => "ENXIO",
        libc::E2BIG => "E2BIG",
        libc::EBADF => "EBADF",
        libc::EAGAIN => "EAGAIN",
        libc::ENOMEM => "ENOMEM",
        libc::EACCES => "EACCES",
        libc::EFAULT => "EFAULT",
        libc::EBUSY => "EBUSY",
        libc::EEXIST => "EEXIST",
        libc::EXDEV => "EXDEV",
        libc::ENODEV => "ENODEV",
        libc::ENOTDIR => "ENOTDIR",
        libc::EISDIR => "EISDIR",
        libc::EINVAL => "EINVAL",
        libc::ENFILE => "ENFILE",
        libc::EMFILE => "EMFILE",
        libc::ETXTBSY => "ETXTBSY",
        libc::EFBIG => "EFBIG",
        libc::ENOSPC => "ENOSPC",
        libc::ESPIPE => "ESPIPE",
        libc::EROFS => "EROFS",
        libc::EMLINK => "EMLINK",
        libc::EPIPE => "EPIPE",
        libc::ENAMETOOLONG => "ENAMETOOLONG",
        libc::ENOSYS => "ENOSYS",
        libc::ENOTEMPTY => "ENOTEMPTY",
        libc::ELOOP => "ELOOP",
        libc::EOVERFLOW => "EOVERFLOW",
        libc::EOPNOTSUPP => "EOPNOTSUPP",
        libc::EDQUOT => "EDQUOT",
        _ => "EUNKNOWN",
    }
}

pub fn message(e: i32) -> String {
    let s = std::io::Error::from_raw_os_error(e).to_string();
    // "No such file or directory (os error 2)" -> "No such file or directory"
    match s.rfind(" (os error ") {
        Some(i) => s[..i].to_string(),
        None => s,
    }
}

pub fn info(e: i32) -> ErrnoInfo {
    ErrnoInfo {
        name: name(e).to_string(),
        code: e,
        message: message(e),
    }
}

/// errno of the last failed libc call on this thread.
pub fn last() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}
