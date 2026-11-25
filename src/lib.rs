//! SigmaOS sigma-sys — userspace syscall shim.
//!
//! Safe wrappers over the kernel syscall ABI (see `sigma_kernel::syscall`).
//! The raw `syscall` instruction is isolated in `arch` behind the
//! `x86_64` feature; on host builds a pluggable `Syscall` impl is used
//! so the API is fully testable.

#![no_std]
#![deny(unsafe_code)]

extern crate alloc;

pub mod api;
pub mod errno;

#[cfg(feature = "x86_64")]
#[allow(unsafe_code)]
pub mod arch;

pub use api::*;
pub use errno::SysResult;

/// Low-level syscall invocation — one method, six args max.
pub trait Syscall {
    /// Invoke syscall `nr` with up to 6 args; returns raw rax value.
    fn call(&self, nr: u64, args: &[u64; 6]) -> i64;
}

#[allow(static_mut_refs)]
static mut ACTIVE: Option<&'static dyn Syscall> = None;

/// Register the syscall backend. Called once during process init.
#[allow(unsafe_code)]
pub fn register(sys: &'static dyn Syscall) {
    unsafe {
        ACTIVE = Some(sys);
    }
}

#[allow(unsafe_code)]
fn active() -> &'static dyn Syscall {
    unsafe { ACTIVE.expect("sigma_sys::register() not called") }
}

/// Raw syscall entry point used by `api`.
pub(crate) fn raw(nr: u64, args: &[u64; 6]) -> i64 {
    active().call(nr, args)
}

#[cfg(test)]
extern crate std;
