//! SHA private macro helpers migrated from `lib/sha-private.h`.

/// FIPS SHA choice function `Ch(x, y, z)`.
#[must_use]
pub const fn sha_ch(x: u64, y: u64, z: u64) -> u64 {
    (x & y) ^ ((!x) & z)
}

/// FIPS SHA majority function `Maj(x, y, z)`.
#[must_use]
pub const fn sha_maj(x: u64, y: u64, z: u64) -> u64 {
    (x & y) ^ (x & z) ^ (y & z)
}

/// Equivalent modified choice function used by optional C macros.
#[must_use]
pub const fn sha_ch_modified(x: u64, y: u64, z: u64) -> u64 {
    (x & (y ^ z)) ^ z
}

/// Equivalent modified majority function used by optional C macros.
#[must_use]
pub const fn sha_maj_modified(x: u64, y: u64, z: u64) -> u64 {
    (x & (y | z)) | (y & z)
}

/// FIPS SHA parity function.
#[must_use]
pub const fn sha_parity(x: u64, y: u64, z: u64) -> u64 {
    x ^ y ^ z
}
