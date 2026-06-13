//! Portable endian conversion helpers matching `include/portable-endian.h`.
//!
//! The C header normalizes platform-specific byte-order macros such as
//! `htobe16`, `le32toh`, and `be64toh`. This Rust module exposes the same
//! conversion responsibilities through dependency-free, host-aware helpers.

/// Conventional value used by C endian headers for little-endian byte order.
pub const LITTLE_ENDIAN: u32 = 1234;

/// Conventional value used by C endian headers for big-endian byte order.
pub const BIG_ENDIAN: u32 = 4321;

/// Conventional value used by C endian headers for PDP-endian byte order.
pub const PDP_ENDIAN: u32 = 3412;

/// Conventional C-style byte-order value for the current target.
#[cfg(target_endian = "little")]
pub const BYTE_ORDER: u32 = LITTLE_ENDIAN;

/// Conventional C-style byte-order value for the current target.
#[cfg(target_endian = "big")]
pub const BYTE_ORDER: u32 = BIG_ENDIAN;

/// Converts a 16-bit integer from big-endian representation to host order.
#[must_use]
pub const fn be16_to_host(value: u16) -> u16 {
    u16::from_be(value)
}

/// Converts a 16-bit integer from host order to big-endian representation.
#[must_use]
pub const fn host_to_be16(value: u16) -> u16 {
    value.to_be()
}

/// Converts a 16-bit integer from host order to little-endian representation.
#[must_use]
pub const fn host_to_le16(value: u16) -> u16 {
    value.to_le()
}

/// Converts a 16-bit integer from little-endian representation to host order.
#[must_use]
pub const fn le16_to_host(value: u16) -> u16 {
    u16::from_le(value)
}

/// Converts a 32-bit integer from big-endian representation to host order.
#[must_use]
pub const fn be32_to_host(value: u32) -> u32 {
    u32::from_be(value)
}

/// Converts a 32-bit integer from host order to big-endian representation.
#[must_use]
pub const fn host_to_be32(value: u32) -> u32 {
    value.to_be()
}

/// Converts a 32-bit integer from host order to little-endian representation.
#[must_use]
pub const fn host_to_le32(value: u32) -> u32 {
    value.to_le()
}

/// Converts a 32-bit integer from little-endian representation to host order.
#[must_use]
pub const fn le32_to_host(value: u32) -> u32 {
    u32::from_le(value)
}

/// Converts a 64-bit integer from big-endian representation to host order.
#[must_use]
pub const fn be64_to_host(value: u64) -> u64 {
    u64::from_be(value)
}

/// Converts a 64-bit integer from host order to big-endian representation.
#[must_use]
pub const fn host_to_be64(value: u64) -> u64 {
    value.to_be()
}

/// Converts a 64-bit integer from host order to little-endian representation.
#[must_use]
pub const fn host_to_le64(value: u64) -> u64 {
    value.to_le()
}

/// Converts a 64-bit integer from little-endian representation to host order.
#[must_use]
pub const fn le64_to_host(value: u64) -> u64 {
    u64::from_le(value)
}
