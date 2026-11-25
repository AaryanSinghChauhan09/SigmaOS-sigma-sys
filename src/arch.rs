//! x86_64 syscall entry — isolated unsafe boundary.

use crate::Syscall;

/// Raw syscall via `syscall` instruction.
/// Convention: nr in rax, args rdi/rsi/rdx/r10/r8/r9, return rax.
pub struct X86_64Syscall;

#[allow(unsafe_code)]
impl Syscall for X86_64Syscall {
    fn call(&self, nr: u64, args: &[u64; 6]) -> i64 {
        let ret: i64;
        unsafe {
            core::arch::asm!(
                "syscall",
                inlateout("rax") nr => ret,
                in("rdi") args[0],
                in("rsi") args[1],
                in("rdx") args[2],
                in("r10") args[3],
                in("r8") args[4],
                in("r9") args[5],
                out("rcx") _,
                out("r11") _,
                options(nostack)
            );
        }
        ret
    }
}

/// Install the x86_64 backend (call once at process start).
pub fn install() {
    crate::register(&X86_64Syscall);
}
