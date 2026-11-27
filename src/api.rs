//! Safe syscall API — wrappers matching `sigma_kernel::syscall::nr`.

use crate::errno::{check, SysResult};
use crate::raw;
use alloc::string::String;
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
    pub const FORK: u64 = 21;
    pub const EXEC: u64 = 22;
    pub const PIPE: u64 = 23;
    pub const DUP: u64 = 24;
    pub const DUP2: u64 = 25;
    pub const KILL: u64 = 26;
    pub const MOUNT: u64 = 27;
    pub const UMOUNT: u64 = 28;
    pub const MEMINFO: u64 = 29;
    pub const PROCINFO: u64 = 30;
    pub const MKDIR: u64 = 31;
    pub const UNLINK: u64 = 32;
    pub const RMDIR: u64 = 33;
    pub const CHDIR: u64 = 34;
    pub const GETCWD: u64 = 35;
    pub const DMESG: u64 = 36;
    pub const STATFS: u64 = 37;
    pub const MOUNTLIST: u64 = 38;
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

/// File metadata returned by [`stat`]. `mode` uses Linux-ish bits
/// (0o040755 dir / 0o100644 file); `size` is bytes (0 for dirs).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileStat {
    pub mode: u64,
    pub size: u64,
}

impl FileStat {
    pub fn is_dir(&self) -> bool {
        self.mode & 0o170000 == 0o040000
    }
}

/// Stat a path in the VFS.
pub fn stat(path: &str) -> SysResult<FileStat> {
    let c = path.as_bytes();
    let mut buf = [0u8; 16];
    let n = check(raw(
        nr::STAT,
        &args(&[
            c.as_ptr() as u64,
            c.len() as u64,
            buf.as_mut_ptr() as u64,
            buf.len() as u64,
        ]),
    ))?;
    if n < 16 {
        return Err(-22); // EINVAL — truncated stat buffer
    }
    Ok(FileStat {
        mode: u64::from_le_bytes(buf[0..8].try_into().unwrap()),
        size: u64::from_le_bytes(buf[8..16].try_into().unwrap()),
    })
}

/// Create a directory in the VFS (parents must exist).
pub fn mkdir(path: &str) -> SysResult<()> {
    let c = path.as_bytes();
    check(raw(nr::MKDIR, &args(&[c.as_ptr() as u64, c.len() as u64])))?;
    Ok(())
}

/// Remove a file from the VFS.
pub fn unlink(path: &str) -> SysResult<()> {
    let c = path.as_bytes();
    check(raw(nr::UNLINK, &args(&[c.as_ptr() as u64, c.len() as u64])))?;
    Ok(())
}

/// Remove an empty directory from the VFS.
pub fn remove_dir(path: &str) -> SysResult<()> {
    let c = path.as_bytes();
    check(raw(nr::RMDIR, &args(&[c.as_ptr() as u64, c.len() as u64])))?;
    Ok(())
}

/// Change the calling process's working directory (absolute path that
/// exists and is a directory).
pub fn chdir(path: &str) -> SysResult<()> {
    let c = path.as_bytes();
    check(raw(nr::CHDIR, &args(&[c.as_ptr() as u64, c.len() as u64])))?;
    Ok(())
}

/// Read the calling process's working directory into `buf`.
pub fn getcwd(buf: &mut [u8]) -> SysResult<usize> {
    let n = check(raw(
        nr::GETCWD,
        &args(&[buf.as_mut_ptr() as u64, buf.len() as u64]),
    ))?;
    Ok(n as usize)
}

/// List a directory into `buf` as newline-separated names.
pub fn listdir(path: &str, buf: &mut [u8]) -> SysResult<usize> {
    let p = path.as_bytes();
    let n = check(raw(
        nr::LISTDIR,
        &args(&[
            p.as_ptr() as u64,
            p.len() as u64,
            buf.as_mut_ptr() as u64,
            buf.len() as u64,
        ]),
    ))?;
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

/// Spawn a new process from an ELF file in the VFS.
/// `path` is the file path bytes (e.g. b"/child"). Returns the child pid.
pub fn spawn(path: &[u8]) -> SysResult<u64> {
    let ptr = path.as_ptr() as u64;
    let n = check(raw(nr::SPAWN, &args(&[ptr, path.len() as u64, 0])))?;
    Ok(n as u64)
}

/// Spawn `path` with `argv` and `envp` — the kernel builds a real
/// {argc, argv[], NULL, envp[], NULL} stack image (argv[0] = path).
/// Descriptor ABI: {u64 argc, argc x {ptr,len}, u64 envc,
/// envc x {ptr,len}}.
/// `stdout_fd` >= 3 redirects the child's fd 1/2 writes to that
/// (inherited, writable) fd — the `> file` mechanism. 0 = console.
/// `stdin_fd` >= 3 feeds the child's fd 0 reads from that fd —
/// the `< file` mechanism. 0 = console.
/// `stderr_fd` >= 3 sends the child's fd 2 writes there; 0 falls
/// back to stdout_fd. The `2> file` mechanism.
pub fn spawn_args(
    path: &[u8],
    argv: &[&[u8]],
    envp: &[&[u8]],
    stdout_fd: u64,
    stdin_fd: u64,
    stderr_fd: u64,
) -> SysResult<u64> {
    let mut desc = Vec::with_capacity(16 + (argv.len() + envp.len()) * 16);
    desc.extend_from_slice(&(argv.len() as u64).to_le_bytes());
    for a in argv {
        desc.extend_from_slice(&(a.as_ptr() as u64).to_le_bytes());
        desc.extend_from_slice(&(a.len() as u64).to_le_bytes());
    }
    desc.extend_from_slice(&(envp.len() as u64).to_le_bytes());
    for e in envp {
        desc.extend_from_slice(&(e.as_ptr() as u64).to_le_bytes());
        desc.extend_from_slice(&(e.len() as u64).to_le_bytes());
    }
    let n = check(raw(
        nr::SPAWN,
        &args(&[
            path.as_ptr() as u64,
            path.len() as u64,
            desc.as_ptr() as u64,
            stdout_fd,
            stdin_fd,
            stderr_fd,
        ]),
    ))?;
    Ok(n as u64)
}

/// Wait for `pid` to exit; returns its exit status.
pub fn wait(pid: u64) -> SysResult<i64> {
    check(raw(nr::WAIT, &args(&[pid, 0, 0])))
}

/// Wait for ANY child to exit (POSIX `wait`/`waitpid(-1)`); returns
/// the exit status of whichever child finished first.
pub fn wait_any() -> SysResult<i64> {
    check(raw(nr::WAIT, &args(&[u64::MAX, 0, 0])))
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

/// Frame allocator stats: (total_frames, free_frames).
pub fn meminfo() -> SysResult<(u64, u64)> {
    let mut buf = [0u64; 2];
    let ptr = buf.as_mut_ptr() as u64;
    check(raw(nr::MEMINFO, &args(&[ptr, 16])))?;
    Ok((buf[0], buf[1]))
}

/// Process table snapshot: (pid, flags, exit_code) per slot.
/// flags: bit0 exited, bit1 sleeping, bit2 reaped. pid==0 = unused.
pub const NPROC_SLOTS: usize = 8;
pub fn procinfo() -> SysResult<[(u64, u64, u64); NPROC_SLOTS]> {
    let mut buf = [0u64; NPROC_SLOTS * 3];
    let ptr = buf.as_mut_ptr() as u64;
    check(raw(nr::PROCINFO, &args(&[ptr, (buf.len() * 8) as u64])))?;
    let mut out = [(0u64, 0u64, 0u64); NPROC_SLOTS];
    for i in 0..NPROC_SLOTS {
        out[i] = (buf[i * 3], buf[i * 3 + 1], buf[i * 3 + 2]);
    }
    Ok(out)
}

/// Kernel ring-buffer size exposed by DMESG.
pub const DMESG_CAP: usize = 16384;

/// Read the kernel log ring buffer (dmesg). Returns up to `buf.len()`
/// of the most recent bytes.
pub fn dmesg(buf: &mut [u8]) -> SysResult<usize> {
    if buf.is_empty() {
        return Ok(0);
    }
    let n = check(raw(
        nr::DMESG,
        &args(&[buf.as_mut_ptr() as u64, buf.len() as u64]),
    ))?;
    Ok(n as usize)
}

/// One entry from the kernel mount table (MOUNTLIST record).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MountInfo {
    pub kind: u64,
    pub dev: u64,
    pub path: String,
}

/// List registered mounts (the `/proc/mounts` analogue). Kernel
/// record layout: u64 count, then {u64 kind, u64 dev, u8 path[64]}.
pub fn mountlist() -> SysResult<Vec<MountInfo>> {
    const REC: usize = 80;
    const CAP: usize = 16;
    let mut buf = [0u8; 8 + CAP * REC];
    let n = check(raw(
        nr::MOUNTLIST,
        &args(&[buf.as_mut_ptr() as u64, buf.len() as u64]),
    ))?;
    debug_assert_eq!(n, 0);
    let count = u64::from_le_bytes(buf[0..8].try_into().unwrap()) as usize;
    let mut out = Vec::with_capacity(count.min(CAP));
    for i in 0..count.min(CAP) {
        let r = &buf[8 + i * REC..8 + (i + 1) * REC];
        let kind = u64::from_le_bytes(r[0..8].try_into().unwrap());
        let dev = u64::from_le_bytes(r[8..16].try_into().unwrap());
        let end = r[16..].iter().position(|&b| b == 0).unwrap_or(64);
        out.push(MountInfo {
            kind,
            dev,
            path: String::from_utf8_lossy(&r[16..16 + end]).into_owned(),
        });
    }
    Ok(out)
}

/// Filesystem kind codes returned by statfs (kernel FsKind).
pub const FS_INITRAMFS: u64 = 1;
pub const FS_FAT32: u64 = 2;
pub const FS_OTHER: u64 = 3;

/// statfs(2) analogue: filesystem stats for `path`.
/// Returns (kind, node_count) of the mount covering `path`.
pub fn statfs(path: &str) -> SysResult<(u64, u64)> {
    let p = path.as_bytes();
    let mut buf = [0u64; 2];
    let n = check(raw(
        nr::STATFS,
        &args(&[
            p.as_ptr() as u64,
            p.len() as u64,
            buf.as_mut_ptr() as u64,
            16,
        ]),
    ))?;
    debug_assert_eq!(n, 0);
    Ok((buf[0], buf[1]))
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

/// Unmap `len` bytes at `addr` (must be page-aligned). Returns 0.
pub fn munmap(addr: u64, len: u64) -> SysResult<u64> {
    let n = check(raw(nr::MUNMAP, &args(&[addr, len])))?;
    Ok(n as u64)
}

/// Fork current process. Returns child pid in parent, 0 in child.
pub fn fork() -> SysResult<i64> {
    check(raw(nr::FORK, &args(&[])))
}

/// Execute a new program, replacing the current process image.
/// `path` is the executable path, `argv` the argument vector
/// (excluding argv[0] — the kernel prepends `path`), `envp` the
/// environment. Does not return on success; `Err` on failure.
pub fn exec(path: &str, argv: &[&str], envp: &[&str]) -> SysResult<()> {
    let path_bytes = path.as_bytes();
    // Same packed descriptor ABI as spawn_args:
    // {u64 argc, argc x {ptr,len}, u64 envc, envc x {ptr,len}}.
    let mut desc = Vec::with_capacity(16 + (argv.len() + envp.len()) * 16);
    desc.extend_from_slice(&(argv.len() as u64).to_le_bytes());
    for a in argv {
        desc.extend_from_slice(&(a.as_ptr() as u64).to_le_bytes());
        desc.extend_from_slice(&(a.len() as u64).to_le_bytes());
    }
    desc.extend_from_slice(&(envp.len() as u64).to_le_bytes());
    for e in envp {
        desc.extend_from_slice(&(e.as_ptr() as u64).to_le_bytes());
        desc.extend_from_slice(&(e.len() as u64).to_le_bytes());
    }
    check(raw(
        nr::EXEC,
        &args(&[
            path_bytes.as_ptr() as u64,
            path_bytes.len() as u64,
            desc.as_ptr() as u64,
            0,
            0,
            0,
        ]),
    ))?;
    Ok(())
}

/// Create a pipe. Returns (read_fd, write_fd).
pub fn pipe() -> SysResult<(i64, i64)> {
    let n = check(raw(nr::PIPE, &args(&[])))?;
    let read_fd = (n & 0xFFFFFFFF) as i64;
    let write_fd = ((n >> 32) & 0xFFFFFFFF) as i64;
    Ok((read_fd, write_fd))
}

/// Duplicate a file descriptor.
pub fn dup(fd: i64) -> SysResult<i64> {
    check(raw(nr::DUP, &args(&[fd as u64])))
}

/// Duplicate a file descriptor to a specific fd number.
pub fn dup2(oldfd: i64, newfd: i64) -> SysResult<i64> {
    check(raw(nr::DUP2, &args(&[oldfd as u64, newfd as u64])))
}

/// Send a signal to a process.
pub fn kill(pid: i64, signal: i64) -> SysResult<()> {
    check(raw(nr::KILL, &args(&[pid as u64, signal as u64])))?;
    Ok(())
}

/// Mount a filesystem.
pub fn mount(source: &str, target: &str, fstype: &str) -> SysResult<()> {
    let s = source.as_bytes();
    let t = target.as_bytes();
    let f = fstype.as_bytes();
    check(raw(
        nr::MOUNT,
        &args(&[
            s.as_ptr() as u64,
            s.len() as u64,
            t.as_ptr() as u64,
            t.len() as u64,
            f.as_ptr() as u64,
            f.len() as u64,
        ]),
    ))?;
    Ok(())
}

/// Unmount a filesystem.
pub fn umount(target: &str) -> SysResult<()> {
    let t = target.as_bytes();
    check(raw(nr::UMOUNT, &args(&[t.as_ptr() as u64, t.len() as u64])))?;
    Ok(())
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
    use alloc::boxed::Box;
    use alloc::sync::Arc;
    use alloc::vec::Vec;
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
