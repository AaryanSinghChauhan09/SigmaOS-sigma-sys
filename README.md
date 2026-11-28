# SigmaOS-sigma-sys

SigmaOS syscall ABI & userspace interface — a `no_std` userspace shim
that standardizes memory, IPC, and I/O across SigmaOS components.

- Safe wrappers over the kernel syscall ABI (`sigma_kernel::syscall`)
- The raw `syscall` instruction is isolated in `arch` behind the
  `x86_64` feature; on host builds a pluggable `Syscall` impl keeps
  the API fully testable
- `#![no_std]` + `#![deny(unsafe_code)]`; errno-style `SysResult`
  returns

## Build & Test

```sh
cargo test --offline --lib
```

## See Also

Related SigmaOS **Core System** repositories:

- [SigmaOS-sigma-kernel](../SigmaOS-sigma-kernel/README.md) — SigmaOS microkernel / x86_64 kernel
- [SigmaOS-sigma-sh](../SigmaOS-sigma-sh/README.md) — SigmaOS interactive userspace shell
- [SigmaOS-initramfs](../SigmaOS-initramfs/README.md) — SigmaOS initramfs builder & hook planner
- [SigmaOS-sigma-bootloader](../SigmaOS-sigma-bootloader/README.md) — SigmaOS bootloader
- [SigmaOS-installer](../SigmaOS-installer/README.md) — SigmaOS system installer
- [SigmaOS-ISO](../SigmaOS-ISO/README.md) — SigmaOS live & installable ISO builder
