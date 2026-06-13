//! Rust migration skeleton for libsmb2.
//!
//! The module tree mirrors the legacy C project relative paths under
//! `include/` and `lib/`. Files that contain `-` in the legacy name are kept on
//! disk with the same stem and exposed through snake_case Rust module names.

#[cfg(feature = "migration_modules")]
pub mod include;
#[cfg(feature = "migration_modules")]
#[path = "lib/mod.rs"]
pub mod legacy_lib;

#[cfg(feature = "migration_modules")]
pub use legacy_lib as lib;

#[cfg(feature = "migration_modules")]
pub use include::libsmb2_private::{Context, IoVectors, Pdu, RecvState, Smb2Header};
#[cfg(feature = "migration_modules")]
pub use include::smb2::libsmb2::{
    ErrorCode, FileHandle, Result, Smb2Client, Smb2Url, Stat, StatVfs,
};
