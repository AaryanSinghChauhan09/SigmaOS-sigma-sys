//! Syscall result type — negative values are kernel error codes.

/// Result of a syscall: Ok(value) or Err(kernel error code).
pub type SysResult<T> = Result<T, i64>;

/// Kernel error codes (mirror `sigma_kernel::error::KernelError::code`).
pub mod codes {
    pub const BOOT_INFO: i64 = -1;
    pub const OUT_OF_MEMORY: i64 = -2;
    pub const INVALID_ARG: i64 = -3;
    pub const HARDWARE_MISSING: i64 = -4;
    pub const FS: i64 = -5;
    pub const DRIVER: i64 = -6;
}

/// Convert a raw syscall return into SysResult.
pub fn check(raw: i64) -> SysResult<i64> {
    if raw < 0 {
        Err(raw)
    } else {
        Ok(raw)
    }
}

/// Human-readable name for an error code.
pub fn describe(code: i64) -> &'static str {
    match code {
        codes::BOOT_INFO => "boot info error",
        codes::OUT_OF_MEMORY => "out of memory",
        codes::INVALID_ARG => "invalid argument",
        codes::HARDWARE_MISSING => "hardware missing",
        codes::FS => "filesystem error",
        codes::DRIVER => "driver error",
        _ => "unknown error",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_maps_sign() {
        assert_eq!(check(0), Ok(0));
        assert_eq!(check(42), Ok(42));
        assert_eq!(check(-2), Err(-2));
    }

    #[test]
    fn describe_known() {
        assert_eq!(describe(codes::OUT_OF_MEMORY), "out of memory");
        assert_eq!(describe(-99), "unknown error");
    }
}
