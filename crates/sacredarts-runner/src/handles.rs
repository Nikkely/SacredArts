//! Bookkeeping of the file descriptors this session opened.
//!
//! This is *only* a label table (fd -> path and flags for display and
//! `sandbox_inspect`). It never decides anything: every fd number the AI
//! passes goes to the kernel, which returns EBADF for fds that are not open
//! and EMFILE when RLIMIT_NOFILE is reached.

use sacredarts_core::ipc::HandleInfo;
use std::collections::BTreeMap;

#[derive(Debug, Default)]
pub struct HandleTable {
    entries: BTreeMap<i32, HandleInfo>,
}

impl HandleTable {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record an fd the kernel just returned (replacing any stale label).
    pub fn insert(&mut self, fd: i32, path: String, flags: String) -> HandleInfo {
        let info = HandleInfo {
            handle: fd,
            real_fd: fd,
            path,
            flags,
        };
        self.entries.insert(fd, info.clone());
        info
    }

    pub fn get(&self, fd: i32) -> Option<&HandleInfo> {
        self.entries.get(&fd)
    }

    pub fn remove(&mut self, fd: i32) -> Option<HandleInfo> {
        self.entries.remove(&fd)
    }

    pub fn list(&self) -> Vec<HandleInfo> {
        self.entries.values().cloned().collect()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn labels_follow_kernel_fds() {
        let mut t = HandleTable::new();
        assert_eq!(t.insert(3, "a".into(), "O_RDONLY".into()).handle, 3);
        assert_eq!(t.insert(4, "b".into(), "O_RDONLY".into()).real_fd, 4);
        assert_eq!(t.remove(3).unwrap().path, "a");
        assert!(t.get(3).is_none());
        // the kernel reuses the lowest free fd; the label is simply replaced
        t.insert(4, "c".into(), "O_RDWR".into());
        assert_eq!(t.get(4).unwrap().path, "c");
        assert_eq!(t.len(), 1);
        assert!(t.remove(99).is_none());
    }
}
