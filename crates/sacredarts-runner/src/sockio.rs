//! Newline-delimited JSON over the runner's AF_UNIX socket (fd 0).
//!
//! Deliberately uses `recv(2)`/`send(2)` (kernel: `recvfrom`/`sendto`) instead
//! of `read(2)`/`write(2)`. The learning policy may deny `read`, `write` or
//! `close`, and the runner must still be able to talk to the supervisor.

use sacredarts_core::limits::MAX_IPC_LINE_BYTES;
use std::io;
use std::os::fd::RawFd;

pub struct SockIo {
    fd: RawFd,
    buf: Vec<u8>,
}

impl SockIo {
    #[must_use]
    pub fn new(fd: RawFd) -> Self {
        Self { fd, buf: Vec::new() }
    }

    /// Next line without the trailing newline; `None` on EOF.
    ///
    /// # Errors
    ///
    /// `recv(2)` failures (except EINTR, which is retried), a line that is
    /// not UTF-8, or a line longer than `MAX_IPC_LINE_BYTES`.
    pub fn recv_line(&mut self) -> io::Result<Option<String>> {
        loop {
            if let Some(pos) = self.buf.iter().position(|&b| b == b'\n') {
                let line: Vec<u8> = self.buf.drain(..=pos).collect();
                let s = String::from_utf8(line[..line.len() - 1].to_vec())
                    .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "non-UTF-8 IPC line"))?;
                return Ok(Some(s));
            }
            if self.buf.len() > MAX_IPC_LINE_BYTES {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "IPC line too long"));
            }
            let mut chunk = vec![0u8; 65536];
            // SAFETY: `chunk` is a valid writable buffer of `chunk.len()` bytes
            // that outlives the call; `self.fd` is the socket we own.
            let n = unsafe { libc::recv(self.fd, chunk.as_mut_ptr().cast(), chunk.len(), 0) };
            // A negative return is an error; anything else is a byte count.
            let Ok(n) = usize::try_from(n) else {
                let e = io::Error::last_os_error();
                if e.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(e);
            };
            if n == 0 {
                return Ok(None);
            }
            self.buf.extend_from_slice(&chunk[..n]);
        }
    }

    /// Send `line` followed by a newline, retrying short sends.
    ///
    /// # Errors
    ///
    /// `send(2)` failures (except EINTR), e.g. EPIPE when the supervisor is gone.
    pub fn send_line(&self, line: &str) -> io::Result<()> {
        let mut data = Vec::with_capacity(line.len() + 1);
        data.extend_from_slice(line.as_bytes());
        data.push(b'\n');
        let mut off = 0;
        while off < data.len() {
            // SAFETY: the pointer/length pair describes the initialised tail of
            // `data`, which lives until the call returns. MSG_NOSIGNAL turns a
            // closed peer into EPIPE instead of SIGPIPE.
            let n = unsafe {
                libc::send(
                    self.fd,
                    data[off..].as_ptr().cast(),
                    data.len() - off,
                    libc::MSG_NOSIGNAL,
                )
            };
            let Ok(n) = usize::try_from(n) else {
                let e = io::Error::last_os_error();
                if e.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(e);
            };
            off += n;
        }
        Ok(())
    }
}
