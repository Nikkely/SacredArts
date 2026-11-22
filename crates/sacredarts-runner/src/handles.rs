//! Learning handle table.
//!
//! The AI never sees or names real file descriptors directly. It gets
//! *learning handles* that the runner maps to real fds. This keeps the
//! runner's own descriptors (IPC socket, stdio, the /workspace dirfd) out of
//! reach: a request for handle 0 or for a handle that was never opened is
//! rejected without touching the kernel.
//!
//! Handles are allocated like POSIX fds: the lowest free number starting at 3.

use sacredarts_core::OpenFlag;
use sacredarts_core::ipc::HandleInfo;
use sacredarts_core::limits::{FIRST_HANDLE, MAX_HANDLES};
use std::collections::BTreeMap;

#[derive(Debug, Default)]
pub struct HandleTable {
    entries: BTreeMap<u32, HandleInfo>,
}

impl HandleTable {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn is_full(&self) -> bool {
        self.entries.len() >= MAX_HANDLES
    }

    /// Register a real fd and return its handle. `None` if the table is full.
    pub fn insert(&mut self, real_fd: i32, path: String, flags: Vec<OpenFlag>) -> Option<HandleInfo> {
        if self.is_full() {
            return None;
        }
        let mut h = FIRST_HANDLE;
        while self.entries.contains_key(&h) {
            h += 1;
        }
        let info = HandleInfo {
            handle: h,
            real_fd,
            path,
            flags,
        };
        self.entries.insert(h, info.clone());
        Some(info)
    }

    pub fn get(&self, handle: u32) -> Option<&HandleInfo> {
        self.entries.get(&handle)
    }

    pub fn remove(&mut self, handle: u32) -> Option<HandleInfo> {
        self.entries.remove(&handle)
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
    fn lowest_free_handle_is_reused() {
        let mut t = HandleTable::new();
        let a = t.insert(10, "a".into(), vec![]).unwrap();
        let b = t.insert(11, "b".into(), vec![]).unwrap();
        assert_eq!((a.handle, b.handle), (3, 4));
        t.remove(3).unwrap();
        assert!(t.get(3).is_none());
        assert_eq!(t.insert(12, "c".into(), vec![]).unwrap().handle, 3);
        assert_eq!(t.insert(13, "d".into(), vec![]).unwrap().handle, 5);
        assert!(t.remove(99).is_none());
    }

    #[test]
    fn table_is_bounded() {
        let mut t = HandleTable::new();
        for i in 0..MAX_HANDLES {
            assert!(t.insert(i as i32 + 100, String::new(), vec![]).is_some());
        }
        assert!(t.is_full());
        assert!(t.insert(1, String::new(), vec![]).is_none());
    }
}
