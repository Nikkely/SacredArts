//! errno number -> symbolic name / message.
//!
//! Both come from the C library inside the sandbox, so every errno the kernel
//! can return is named (no hand-maintained table that silently drops values).

use sacredarts_core::ipc::ErrnoInfo;

/// Symbolic name such as `ENOENT`.
///
/// glibc's `strerrorname_np` (glibc >= 2.32) knows every errno of the target
/// architecture. Values it does not know are shown as `errno <n>` rather than
/// being replaced by a made-up name.
#[must_use]
pub fn name(e: i32) -> String {
    #[cfg(target_env = "gnu")]
    {
        unsafe extern "C" {
            fn strerrorname_np(errnum: libc::c_int) -> *const libc::c_char;
        }
        // SAFETY: returns NULL or a pointer to a static NUL-terminated string.
        let p = unsafe { strerrorname_np(e) };
        if !p.is_null() {
            return unsafe { std::ffi::CStr::from_ptr(p) }.to_string_lossy().into_owned();
        }
    }
    format!("errno {e}")
}

#[must_use]
pub fn message(e: i32) -> String {
    let s = std::io::Error::from_raw_os_error(e).to_string();
    // "No such file or directory (os error 2)" -> "No such file or directory"
    match s.rfind(" (os error ") {
        Some(i) => s[..i].to_string(),
        None => s,
    }
}

#[must_use]
pub fn info(e: i32) -> ErrnoInfo {
    ErrnoInfo {
        name: name(e),
        code: e,
        message: message(e),
    }
}

/// errno of the last failed libc call on this thread.
#[must_use]
pub fn last() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_come_from_libc() {
        assert_eq!(name(libc::ENOENT), "ENOENT");
        assert_eq!(name(libc::EROFS), "EROFS");
        // not in the old hand-written table
        assert_eq!(name(libc::ECONNREFUSED), "ECONNREFUSED");
        assert_eq!(name(libc::ENOTCONN), "ENOTCONN");
        assert_eq!(name(libc::EHWPOISON), "EHWPOISON");
        // every errno the kernel defines (1..=133) has a real name;
        // 41 and 58 are unused numbers on Linux
        for e in (1..=libc::EHWPOISON).filter(|e| ![41, 58].contains(e)) {
            let n = name(e);
            assert!(n.starts_with('E'), "{e} -> {n}");
        }
    }

    #[test]
    fn unknown_values_keep_the_number() {
        assert_eq!(name(9999), "errno 9999");
    }
}
