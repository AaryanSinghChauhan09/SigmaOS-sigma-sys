//! Safe syscall API — wrappers matching `sigma_kernel::syscall::nr`.

use crate::errno::{check, SysResult};
use crate::raw;
use alloc::string::String;
use alloc::boxed::Box;
use alloc::vec::Vec;

/// Syscall numbers — must match the kernel ABI exactly.
pub mod nr {
    pub const READ: u64 = 0;
    pub const WRITE: u64 = 1;
    pub const OPEN: u64 = 2;
    pub const CLOSE: u64 = 3;
    pub const STAT: u64 = 4;
    pub const IOCTL: u64 = 5;
    pub const MMAP: u64 = 6;
    pub const MUNMAP: u64 = 7;
    pub const BRK: u64 = 8;
    pub const EXIT: u64 = 9;
    pub const SPAWN: u64 = 10;
    pub const WAIT: u64 = 11;
    pub const GETPID: u64 = 12;
    pub const GETTID: u64 = 13;
    pub const KERNEL_INFO: u64 = 14;
    pub const FB_INFO: u64 = 15;
    pub const FB_PUTPIXEL: u64 = 16;
    pub const FB_FLUSH: u64 = 17;
    pub const TIME: u64 = 18;
    pub const RAND: u64 = 19;
    pub const LISTDIR: u64 = 20;
}

fn args(a: &[u64]) -> [u64; 6] {
    let mut out = [0u64; 6];
    out[..a.len().min(6)].copy_from_slice(&a[..a.len().min(6)]);
    out
}

/// Read up to `buf.len()` bytes from fd into buf. Returns bytes read.
pub fn read(fd: i64, buf: &mut [u8]) -> SysResult<usize> {
    // SAFETY boundary: kernel writes into user buffer; buf must be valid
    // for the duration of the call — guaranteed by safe slice.
    let ptr = buf.as_mut_ptr() as u64;
    let n = check(raw(nr::READ, &args(&[fd as u64, ptr, buf.len() as u64])))?;
    Ok(n as usize)
}

/// Write bytes to fd. Returns bytes written.
pub fn write(fd: i64, buf: &[u8]) -> SysResult<usize> {
    let ptr = buf.as_ptr() as u64;
    let n = check(raw(nr::WRITE, &args(&[fd as u64, ptr, buf.len() as u64])))?;
    Ok(n as usize)
}

/// Write a string to stdout (fd 1).
pub fn print(s: &str) -> SysResult<usize> {
    write(1, s.as_bytes())
}

/// Open a path. Returns fd or error.
pub fn open(path: &str, flags: u32) -> SysResult<i64> {
    let c = path.as_bytes();
    let ptr = c.as_ptr() as u64;
    check(raw(nr::OPEN, &args(&[ptr, c.len() as u64, flags as u64])))
}

/// Close an fd.
pub fn close(fd: i64) -> SysResult<()> {
    check(raw(nr::CLOSE, &args(&[fd as u64])))?;
    Ok(())
}

/// List a directory into `buf` as newline-separated names.
pub fn listdir(path: &str, buf: &mut [u8]) -> SysResult<usize> {
    let p = path.as_bytes();
    let n = check(raw(nr::LISTDIR, &args(&[
        p.as_ptr() as u64,
        p.len() as u64,
        buf.as_mut_ptr() as u64,
        buf.len() as u64,
    ])))?;
    Ok(n as usize)
}

/// Exit the current process with a status code.
pub fn exit(code: i32) -> ! {
    let _ = raw(nr::EXIT, &args(&[code as u32 as u64]));
    // If the kernel returns (shouldn't), trap.
    loop {
        core::hint::spin_loop();
    }
}

/// Spawn a program by path with argv. Returns child pid.
pub fn spawn(path: &str, argv: &[&str]) -> SysResult<i64> {
    let path_ptr = path.as_bytes().as_ptr() as u64;
    // argv marshaling: kernel expects a pointer to a pointer array;
    // for the ABI v1 we pass a packed buffer: count, then offsets.
    // Simplified: pass argv count and a contiguous blob.
    let mut blob = Vec::new();
    blob.extend_from_slice(&(argv.len() as u64).to_le_bytes());
    for a in argv {
        blob.extend_from_slice(&(a.len() as u64).to_le_bytes());
        blob.extend_from_slice(a.as_bytes());
    }
    let blob_ptr = blob.as_ptr() as u64;
    check(raw(nr::SPAWN, &args(&[path_ptr, blob_ptr, blob.len() as u64])))
}

/// Wait for a child pid; returns exit status.
pub fn wait(pid: i64) -> SysResult<i64> {
    check(raw(nr::WAIT, &args(&[pid as u64])))
}

/// Current process id.
pub fn getpid() -> SysResult<i64> {
    check(raw(nr::GETPID, &args(&[])))
}

/// Kernel version string info (writes into provided buffer via pointer).
/// Returns number of bytes written.
pub fn kernel_info(buf: &mut [u8]) -> SysResult<usize> {
    let ptr = buf.as_mut_ptr() as u64;
    let n = check(raw(nr::KERNEL_INFO, &args(&[ptr, buf.len() as u64])))?;
    Ok(n as usize)
}

/// Current time in seconds since boot.
pub fn time() -> SysResult<u64> {
    check(raw(nr::TIME, &args(&[]))).map(|v| v as u64)
}

/// Fill buf with random bytes; returns count.
pub fn rand_bytes(buf: &mut [u8]) -> SysResult<usize> {
    let ptr = buf.as_mut_ptr() as u64;
    let n = check(raw(nr::RAND, &args(&[ptr, buf.len() as u64])))?;
    Ok(n as usize)
}

/// Query or adjust the program break. `addr == 0` returns the
/// current break; otherwise grows (or shrinks) to `addr`.
/// Returns the resulting break address.
pub fn brk(addr: u64) -> SysResult<u64> {
    let n = check(raw(nr::BRK, &args(&[addr])))?;
    Ok(n as u64)
}

/// Map `len` bytes of anonymous memory. `addr == 0` lets the kernel
/// pick; otherwise `addr` must be page-aligned. Returns the mapping
/// base address.
pub fn mmap(addr: u64, len: u64) -> SysResult<u64> {
    let n = check(raw(nr::MMAP, &args(&[addr, len])))?;
    Ok(n as u64)
}

/// Get a String from kernel info buffer.
pub fn kernel_version() -> SysResult<String> {
    let mut buf = [0u8; 64];
    let n = kernel_info(&mut buf)?;
    Ok(String::from_utf8_lossy(&buf[..n]).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{register, Syscall};
    use alloc::vec::Vec;
    use alloc::sync::Arc;
    use std::sync::{Mutex, Once};

    type Log = Arc<Mutex<Vec<(u64, [u64; 6])>>>;

    /// One shared mock for the whole test binary — register() is
    /// first-write-wins, so tests must share a single backend.
    struct Mock {
        log: Log,
    }
    impl Syscall for Mock {
        fn call(&self, nr: u64, args: &[u64; 6]) -> i64 {
            self.log.lock().unwrap().push((nr, *args));
            match nr {
                nr::GETPID => 42,
                nr::TIME => 1000,
                nr::WRITE => args[2] as i64,
                _ => 0,
            }
        }
    }

    fn shared() -> Log {
        static LOG: std::sync::OnceLock<Log> = std::sync::OnceLock::new();
        static ONCE: Once = Once::new();
        let log = LOG.get_or_init(|| Arc::new(Mutex::new(Vec::new())));
        ONCE.call_once(|| {
            let mock = Box::leak(Box::new(Mock { log: log.clone() }));
            register(mock);
        });
        log.clone()
    }

    #[test]
    fn wrappers_dispatch() {
        let log = shared();
        log.lock().unwrap().clear();

        assert_eq!(getpid().unwrap(), 42);
        assert_eq!(time().unwrap(), 1000);
        assert_eq!(write(1, b"hi").unwrap(), 2);

        let calls = log.lock().unwrap();
        assert_eq!(calls[0].0, nr::GETPID);
        assert_eq!(calls[1].0, nr::TIME);
        assert_eq!(calls[2].0, nr::WRITE);
    }

    #[test]
    fn print_writes_stdout() {
        let log = shared();
        log.lock().unwrap().clear();
        let _ = print("x");
        let calls = log.lock().unwrap();
        assert_eq!(calls.last().unwrap().1[0], 1); // fd 1
    }
}
