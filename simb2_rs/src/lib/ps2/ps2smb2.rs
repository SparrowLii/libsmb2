//! PS2 SMB2 public device-control definitions migrated from `lib/ps2/ps2smb2.h`.

/// Maximum PS2 SMB2 path length.
pub const SMB2_PATH_MAX: usize = 1024;
/// Connect devctl command id.
pub const SMB2_DEVCTL_CONNECT: u32 = 0xC0DE_0001;
/// Disconnect-all devctl command id.
pub const SMB2_DEVCTL_DISCONNECT_ALL: u32 = 0xC0DE_0002;
/// Maximum fixed field length for PS2 SMB2 names.
pub const SMB2_MAX_NAME_LEN: usize = 32;
/// Fixed username length in the C connect input struct.
pub const SMB2_USERNAME_LEN: usize = 32;
/// Fixed password length in the C connect input struct.
pub const SMB2_PASSWORD_LEN: usize = 32;
/// Fixed URL length in the C connect input struct.
pub const SMB2_URL_LEN: usize = 256;

/// Rust-owned form of `smb2Connect_in_t`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Smb2ConnectIn {
    /// Connection name.
    pub name: String,
    /// Username.
    pub username: String,
    /// Password.
    pub password: String,
    /// SMB2 URL.
    pub url: String,
}

impl Smb2ConnectIn {
    /// Returns whether all fixed C buffers can hold the stored strings.
    #[must_use]
    pub fn fits_fixed_buffers(&self) -> bool {
        self.name.len() < SMB2_MAX_NAME_LEN
            && self.username.len() < SMB2_USERNAME_LEN
            && self.password.len() < SMB2_PASSWORD_LEN
            && self.url.len() < SMB2_URL_LEN
    }
}

/// Rust-owned form of `smb2Connect_out_t`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Smb2ConnectOut {
    /// Opaque context handle represented as an address-sized value.
    pub ctx: Option<usize>,
}

/// Rust-owned form of `smb2Disconnect_in_t`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Smb2DisconnectIn {
    /// Opaque context handle represented as an address-sized value.
    pub ctx: Option<usize>,
}
