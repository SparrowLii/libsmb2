//! Context initialization migrated from `lib/init.c`.

use crate::include::libsmb2_private::{
    Context, IoVec, IoVectors, RecvState, Smb2Header, SMB2_MAX_VECTORS,
};
use crate::include::smb2::libsmb2::Smb2Url;

/// Maximum URL payload accepted by the legacy parser after `smb://`.
pub const MAX_URL_SIZE: usize = 1024;
/// Size of the SMB2 client GUID buffer.
pub const SMB2_GUID_SIZE: usize = 16;
/// Size of the SMB3 salt buffer initialized with the context.
pub const SMB2_SALT_SIZE: usize = 32;
/// Maximum stored error string length used by `lib/init.c`.
pub const MAX_ERROR_SIZE: usize = 256;

/// Result type for initialization helpers migrated from `lib/init.c`.
pub type InitResult<T> = core::result::Result<T, InitError>;

/// Errors reported by the Rust initialization skeleton.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InitError {
    /// The URL does not start with the expected `smb://` scheme.
    InvalidScheme,
    /// The URL exceeds the fixed legacy parser buffer.
    UrlTooLong,
    /// The URL is missing server or share components.
    WrongUrlFormat,
    /// A query argument is unknown or has an unsupported value.
    UnknownArgument(String),
    /// The current dialect selection is incompatible with SMB3 sealing.
    SealRequiresSmb3,
    /// The I/O vector list is at its legacy capacity.
    TooManyIoVectors,
    /// The accumulated I/O vector size overflowed `usize`.
    IoVectorSizeOverflow,
}

/// Authentication selector corresponding to `enum smb2_sec`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AuthenticationMethod {
    /// Let later negotiation choose the authentication method.
    #[default]
    Undefined,
    /// Use NTLMSSP authentication.
    NtlmSsp,
    /// Use Kerberos authentication.
    Krb5,
}

/// SMB dialect selector corresponding to `enum smb2_negotiate_version`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum NegotiateVersion {
    /// Let the server choose any supported SMB2 or SMB3 dialect.
    #[default]
    Any,
    /// Let the server choose any SMB2 dialect.
    Any2,
    /// Let the server choose any SMB3 dialect.
    Any3,
    /// SMB 2.0.2.
    V0202,
    /// SMB 2.1.0.
    V0210,
    /// SMB 3.0.0.
    V0300,
    /// SMB 3.0.2.
    V0302,
    /// SMB 3.1.1.
    V0311,
}

impl NegotiateVersion {
    /// Returns true when the selector is limited to an SMB3-capable dialect.
    #[must_use]
    pub fn supports_seal(self) -> bool {
        matches!(self, Self::Any3 | Self::V0300 | Self::V0302 | Self::V0311)
    }
}

/// NDR transfer syntax preference configured by URL arguments.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum NdrMode {
    /// Accept both NDR32 and NDR64.
    Ndr3264,
    /// Prefer NDR32.
    #[default]
    Ndr32,
    /// Prefer NDR64.
    Ndr64,
}

/// DCE/RPC byte order configured by URL arguments.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Endianness {
    /// Little endian transfer encoding.
    #[default]
    Little,
    /// Big endian transfer encoding.
    Big,
}

/// Mutable configuration fields initialized and updated by `lib/init.c` helpers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InitConfig {
    /// Authentication mechanism selector.
    pub authentication: AuthenticationMethod,
    /// Dialect version selector.
    pub version: NegotiateVersion,
    /// DCE/RPC NDR width selector.
    pub ndr: NdrMode,
    /// DCE/RPC byte order selector.
    pub endianness: Endianness,
    /// Enable SMB3 sealing.
    pub seal: bool,
    /// Require SMB2 signing.
    pub sign: bool,
    /// Use cached Kerberos credentials.
    pub use_cached_creds: bool,
    /// Operation timeout in seconds.
    pub timeout: i32,
    /// Negotiated or requested security mode bitmask.
    pub security_mode: u16,
    /// Pass through opaque command payloads.
    pub passthrough: bool,
}

impl Default for InitConfig {
    fn default() -> Self {
        Self {
            authentication: AuthenticationMethod::Undefined,
            version: NegotiateVersion::Any,
            ndr: NdrMode::Ndr32,
            endianness: Endianness::Little,
            seal: false,
            sign: false,
            use_cached_creds: false,
            timeout: 0,
            security_mode: 0,
            passthrough: false,
        }
    }
}

/// Rust-owned context skeleton for responsibilities implemented in `lib/init.c`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InitState {
    /// Mutable initialization and negotiation configuration.
    pub config: InitConfig,
    /// Optional server name copied from a parsed URL or setter.
    pub server: Option<String>,
    /// Optional share name copied from a parsed URL or setter.
    pub share: Option<String>,
    /// Optional authentication user.
    pub user: Option<String>,
    /// Optional authentication password.
    pub password: Option<String>,
    /// Optional authentication domain.
    pub domain: Option<String>,
    /// Optional client workstation name.
    pub workstation: Option<String>,
    /// Caller-defined opaque data represented as an address-sized value.
    pub opaque: Option<usize>,
    /// Client challenge bytes created during context initialization.
    pub client_challenge: [u8; 8],
    /// SMB3 salt bytes created during context initialization.
    pub salt: [u8; SMB2_SALT_SIZE],
    /// Client GUID buffer.
    pub client_guid: [u8; SMB2_GUID_SIZE],
    /// Negotiated dialect value.
    pub dialect: u16,
    /// Last NT status associated with the context.
    pub nterror: i32,
    error_string: String,
}

impl Default for InitState {
    fn default() -> Self {
        Self {
            config: InitConfig::default(),
            server: None,
            share: None,
            user: Some(String::from("Guest")),
            password: None,
            domain: None,
            workstation: None,
            opaque: None,
            client_challenge: [0; 8],
            salt: [0; SMB2_SALT_SIZE],
            client_guid: default_client_guid(),
            dialect: 0,
            nterror: 0,
            error_string: String::new(),
        }
    }
}

impl InitState {
    /// Creates context initialization state with legacy defaults.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Parses an SMB URL, updates URL arguments on the state, and returns fields.
    ///
    /// # Errors
    ///
    /// Returns an [`InitError`] when the URL shape or query arguments are invalid.
    pub fn parse_url(&mut self, url: &str) -> InitResult<Smb2Url> {
        let body = url.strip_prefix("smb://").ok_or_else(|| {
            self.set_error("URL does not start with 'smb://'");
            InitError::InvalidScheme
        })?;

        if body.len() >= MAX_URL_SIZE {
            self.set_error("URL is too long");
            return Err(InitError::UrlTooLong);
        }

        let (path_part, args) = match body.split_once('?') {
            Some((path_part, args)) => (path_part, Some(args)),
            None => (body, None),
        };

        if let Some(args) = args {
            self.parse_args(args)?;
        }

        let first_slash = match path_part.find('/') {
            Some(index) => index,
            None => {
                self.set_error("Wrong URL format");
                return Err(InitError::WrongUrlFormat);
            }
        };
        let auth_server = &path_part[..first_slash];
        let share_path = &path_part[first_slash + 1..];
        let (share, path) = match share_path.split_once('/') {
            Some((share, path)) => (share, Some(path.to_owned())),
            None => (share_path, None),
        };

        if auth_server.is_empty() || share.is_empty() {
            self.set_error("Wrong URL format");
            return Err(InitError::WrongUrlFormat);
        }

        let (domain, auth_server) = match auth_server.split_once(';') {
            Some((domain, rest)) if !domain.is_empty() && !rest.is_empty() => {
                (Some(domain.to_owned()), rest)
            }
            _ => (None, auth_server),
        };
        let (user, server) = match auth_server.split_once('@') {
            Some((user, server)) if !user.is_empty() && !server.is_empty() => {
                (Some(user.to_owned()), server)
            }
            _ => (None, auth_server),
        };

        if server.is_empty() {
            self.set_error("Wrong URL format");
            return Err(InitError::WrongUrlFormat);
        }

        let parsed = Smb2Url {
            domain,
            user,
            server: server.to_owned(),
            share: share.to_owned(),
            path,
        };
        self.apply_url(&parsed);
        Ok(parsed)
    }

    /// Clears a parsed URL value; ownership makes this a no-op in Rust.
    pub fn destroy_url(&mut self, url: Smb2Url) {
        drop(url);
    }

    /// Stores an error string and clears NT status when the message is empty.
    pub fn set_error(&mut self, error_string: &str) {
        self.error_string = error_string.chars().take(MAX_ERROR_SIZE).collect();
        if error_string.is_empty() {
            self.nterror = 0;
        }
    }

    /// Stores an NT status and matching error string.
    pub fn set_nterror(&mut self, nterror: i32, error_string: &str) {
        self.set_error(error_string);
        self.nterror = nterror;
    }

    /// Returns the last stored error string.
    #[must_use]
    pub fn error(&self) -> &str {
        &self.error_string
    }

    /// Returns the last stored NT status.
    #[must_use]
    pub fn nterror(&self) -> i32 {
        self.nterror
    }

    /// Replaces the client GUID buffer.
    pub fn set_client_guid(&mut self, guid: [u8; SMB2_GUID_SIZE]) {
        self.client_guid = guid;
    }

    /// Returns the client GUID buffer.
    #[must_use]
    pub fn client_guid(&self) -> [u8; SMB2_GUID_SIZE] {
        self.client_guid
    }

    /// Returns the negotiated dialect value.
    #[must_use]
    pub fn dialect(&self) -> u16 {
        self.dialect
    }

    /// Sets the configured security mode bitmask.
    pub fn set_security_mode(&mut self, security_mode: u16) {
        self.config.security_mode = security_mode;
    }

    /// Sets the authentication user.
    pub fn set_user(&mut self, user: Option<&str>) {
        self.user = user.map(str::to_owned);
    }

    /// Returns the configured authentication user.
    #[must_use]
    pub fn user(&self) -> Option<&str> {
        self.user.as_deref()
    }

    /// Sets the authentication password.
    pub fn set_password(&mut self, password: Option<&str>) {
        self.password = password.map(str::to_owned);
    }

    /// Sets the authentication domain.
    pub fn set_domain(&mut self, domain: Option<&str>) {
        self.domain = domain.map(str::to_owned);
    }

    /// Returns the configured authentication domain.
    #[must_use]
    pub fn domain(&self) -> Option<&str> {
        self.domain.as_deref()
    }

    /// Sets the workstation name.
    pub fn set_workstation(&mut self, workstation: Option<&str>) {
        self.workstation = workstation.map(str::to_owned);
    }

    /// Returns the configured workstation name.
    #[must_use]
    pub fn workstation(&self) -> Option<&str> {
        self.workstation.as_deref()
    }

    /// Stores caller-defined opaque data.
    pub fn set_opaque(&mut self, opaque: Option<usize>) {
        self.opaque = opaque;
    }

    /// Returns caller-defined opaque data.
    #[must_use]
    pub fn opaque(&self) -> Option<usize> {
        self.opaque
    }

    /// Enables or disables SMB3 sealing.
    pub fn set_seal(&mut self, val: bool) {
        self.config.seal = val;
    }

    /// Enables or disables SMB2 signing.
    pub fn set_sign(&mut self, val: bool) {
        self.config.sign = val;
    }

    /// Sets the authentication method.
    pub fn set_authentication(&mut self, val: AuthenticationMethod) {
        self.config.authentication = val;
    }

    /// Sets the operation timeout in seconds.
    pub fn set_timeout(&mut self, seconds: i32) {
        self.config.timeout = seconds;
    }

    /// Sets the dialect version selector.
    pub fn set_version(&mut self, version: NegotiateVersion) {
        self.config.version = version;
    }

    /// Sets pass-through decoding for complex command payloads.
    pub fn set_passthrough(&mut self, passthrough: bool) {
        self.config.passthrough = passthrough;
    }

    /// Returns the pass-through decoding setting.
    #[must_use]
    pub fn passthrough(&self) -> bool {
        self.config.passthrough
    }

    fn apply_url(&mut self, url: &Smb2Url) {
        self.domain = url.domain.clone();
        self.user = url.user.clone().or_else(|| self.user.clone());
        self.server = Some(url.server.clone());
        self.share = Some(url.share.clone());
    }

    fn parse_args(&mut self, args: &str) -> InitResult<()> {
        for arg in args.split('&').filter(|arg| !arg.is_empty()) {
            let (name, value) = match arg.split_once('=') {
                Some((name, value)) => (name, Some(value)),
                None => (arg, None),
            };

            match name {
                "seal" => self.config.seal = true,
                "sign" => self.config.sign = true,
                "ndr3264" => self.config.ndr = NdrMode::Ndr3264,
                "ndr32" => self.config.ndr = NdrMode::Ndr32,
                "ndr64" => self.config.ndr = NdrMode::Ndr64,
                "le" => self.config.endianness = Endianness::Little,
                "be" => self.config.endianness = Endianness::Big,
                "sec" => self.parse_security_arg(value)?,
                "vers" => self.parse_version_arg(value)?,
                "timeout" => self.config.timeout = parse_i32(value),
                other => {
                    self.set_error(&format!("Unknown argument: {other}"));
                    return Err(InitError::UnknownArgument(other.to_owned()));
                }
            }
        }

        if self.config.seal {
            match self.config.version {
                NegotiateVersion::Any => self.config.version = NegotiateVersion::Any3,
                version if version.supports_seal() => {}
                _ => {
                    self.set_error("Can only use seal with SMB3");
                    return Err(InitError::SealRequiresSmb3);
                }
            }
        }

        Ok(())
    }

    fn parse_security_arg(&mut self, value: Option<&str>) -> InitResult<()> {
        match value {
            Some("krb5") => self.config.authentication = AuthenticationMethod::Krb5,
            Some("krb5cc") => {
                self.config.authentication = AuthenticationMethod::Krb5;
                self.config.use_cached_creds = true;
            }
            Some("ntlmssp") => self.config.authentication = AuthenticationMethod::NtlmSsp,
            Some(other) => {
                self.set_error(&format!("Unknown sec= argument: {other}"));
                return Err(InitError::UnknownArgument(String::from("sec")));
            }
            None => {
                self.set_error("Unknown sec= argument: ");
                return Err(InitError::UnknownArgument(String::from("sec")));
            }
        }
        Ok(())
    }

    fn parse_version_arg(&mut self, value: Option<&str>) -> InitResult<()> {
        self.config.version = match value {
            Some("2") => NegotiateVersion::Any2,
            Some("3") => NegotiateVersion::Any3,
            Some("2.02") => NegotiateVersion::V0202,
            Some("2.10") => NegotiateVersion::V0210,
            Some("3.0" | "3.00") => NegotiateVersion::V0300,
            Some("3.02") => NegotiateVersion::V0302,
            Some("3.1.1") => NegotiateVersion::V0311,
            Some(other) => {
                self.set_error(&format!("Unknown vers= argument: {other}"));
                return Err(InitError::UnknownArgument(String::from("vers")));
            }
            None => {
                self.set_error("Unknown vers= argument: ");
                return Err(InitError::UnknownArgument(String::from("vers")));
            }
        };
        Ok(())
    }
}

/// Creates default internal context state.
#[must_use]
pub fn init_context() -> Context {
    Context {
        recv_state: RecvState::Spl,
        credits: 0,
        message_id: 0,
        session_id: 0,
        tree_ids: Vec::new(),
        input: IoVectors::default(),
        header: Smb2Header {
            protocol_id: crate::include::smb2::smb2::SMB2_PROTOCOL_ID,
            struct_size: 64,
            credit_charge: 0,
            status: 0,
            command: 0,
            credit_request_response: 0,
            flags: 0,
            next_command: 0,
            message_id: 0,
            process_id: 0,
            tree_id: 0,
            async_id: 0,
            session_id: 0,
            signature: [0; crate::include::libsmb2_private::SMB2_SIGNATURE_SIZE],
        },
        outqueue: Vec::new(),
        waitqueue: Vec::new(),
    }
}

/// Releases all Rust-owned I/O vectors and resets their counters.
pub fn free_iovector(v: &mut IoVectors) {
    v.vectors.clear();
    v.done = 0;
    v.total_size = 0;
}

/// Adds an owned buffer to an I/O vector list.
///
/// # Errors
///
/// Returns [`InitError::TooManyIoVectors`] when the legacy vector limit is
/// reached, or [`InitError::IoVectorSizeOverflow`] if the total size overflows.
pub fn add_iovector(v: &mut IoVectors, buf: Vec<u8>) -> InitResult<()> {
    if v.vectors.len() >= SMB2_MAX_VECTORS {
        return Err(InitError::TooManyIoVectors);
    }
    v.total_size = v
        .total_size
        .checked_add(buf.len())
        .ok_or(InitError::IoVectorSizeOverflow)?;
    v.vectors.push(IoVec { buf });
    Ok(())
}

fn default_client_guid() -> [u8; SMB2_GUID_SIZE] {
    let mut guid = [0; SMB2_GUID_SIZE];
    let prefix = b"libsmb2-rs";
    guid[..prefix.len()].copy_from_slice(prefix);
    guid
}

fn parse_i32(value: Option<&str>) -> i32 {
    value
        .and_then(|value| value.parse().ok())
        .unwrap_or_default()
}
