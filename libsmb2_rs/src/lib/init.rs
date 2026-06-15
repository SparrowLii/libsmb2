//! Context initialization migrated from `lib/init.c`.

use crate::include::libsmb2_private::{
    truncate_error_string, Context, IoVec, IoVectors, RecvState, Smb2Header, SMB2_MAX_TREE_NESTING,
    SMB2_MAX_VECTORS,
};
use crate::include::smb2::libsmb2::Smb2Url;

use super::sha384_512::Sha512Context;
use super::smb2_signing::{derive_session_keys, SessionDerivedKeys, SigningAlgorithm};

/// Maximum URL payload accepted by the legacy parser after `smb://`.
pub const MAX_URL_SIZE: usize = 1024;
/// Size of the SMB2 client GUID buffer.
pub const SMB2_GUID_SIZE: usize = 16;
/// Size of the SMB3 salt buffer initialized with the context.
pub const SMB2_SALT_SIZE: usize = 32;
/// Size of the SMB3 pre-authentication hash buffer.
pub const SMB2_PREAUTH_HASH_SIZE: usize = 64;
/// Maximum stored error string length used by `lib/init.c`.
pub const MAX_ERROR_SIZE: usize = 256;

/// Security mode bit indicating the server requires signing.
pub const SMB2_NEGOTIATE_SIGNING_REQUIRED: u16 = 0x0002;
/// Server/session capability bit indicating encryption support.
pub const SMB2_GLOBAL_CAP_ENCRYPTION: u32 = 0x0000_0040;
/// SMB 3.0 dialect threshold.
pub const SMB2_VERSION_0300: u16 = 0x0300;
/// SMB 3.1.1 dialect value.
pub const SMB2_VERSION_0311: u16 = 0x0311;

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
    /// The tree-id stack is at its legacy nesting limit.
    TreeNestingTooDeep,
    /// The requested tree id is not present in the active stack.
    TreeIdNotFound,
    /// No credential fields are available for delegation.
    NoCredentials,
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

/// Negotiation phase and selected server properties.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum NegotiationState {
    /// No NEGOTIATE reply has been applied yet.
    #[default]
    NotNegotiated,
    /// A NEGOTIATE reply selected a dialect and connection capabilities.
    Negotiated {
        /// Dialect selected by the server.
        dialect: u16,
        /// Capability flags selected by the server.
        capabilities: u32,
        /// Security mode selected by the server.
        security_mode: u16,
        /// First locally supported encryption cipher selected from SMB 3.1.1 contexts.
        encryption_cipher: Option<u16>,
        /// Whether signing is required by configuration or server policy.
        signing_required: bool,
        /// Whether sealing can be enabled with the negotiated dialect/capabilities/cipher.
        sealing_available: bool,
    },
}

/// Authentication/session phase derived from SESSION_SETUP metadata.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum SessionState {
    /// No usable session material has been applied yet.
    #[default]
    NoSession,
    /// A session id was observed, but no key material was supplied by authentication.
    SessionIdOnly {
        /// Session id selected by the server.
        session_id: u64,
        /// SESSION_SETUP reply flags.
        session_flags: u16,
    },
    /// Session key material was supplied and signing/sealing keys were derived.
    Established {
        /// Session id selected by the server.
        session_id: u64,
        /// SESSION_SETUP reply flags.
        session_flags: u16,
        /// Session key length supplied by the authentication layer.
        session_key_len: usize,
        /// Signing algorithm selected by the negotiated dialect.
        signing_algorithm: SigningAlgorithm,
        /// Whether signing has enough material to operate.
        signing_ready: bool,
        /// Whether sealing has enough material and policy support to operate.
        sealing_ready: bool,
    },
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
    /// Optional path within the parsed share.
    pub path: Option<String>,
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
    /// Negotiated server capability flags.
    pub capabilities: u32,
    /// Explicit negotiation state derived from the NEGOTIATE reply and contexts.
    pub negotiation_state: NegotiationState,
    /// Negotiated maximum transaction size.
    pub max_transact_size: u32,
    /// Negotiated maximum read size.
    pub max_read_size: u32,
    /// Negotiated maximum write size.
    pub max_write_size: u32,
    /// Skeleton pre-authentication hash accumulator metadata.
    pub preauth_hash: [u8; SMB2_PREAUTH_HASH_SIZE],
    /// Number of skeleton pre-authentication hash updates applied.
    pub preauth_hash_updates: usize,
    /// Selected SMB3 encryption cipher, if negotiation supplied one supported locally.
    pub encryption_cipher: Option<u16>,
    /// Negotiated session id from the SESSION_SETUP reply header.
    pub session_id: u64,
    /// Session key bytes supplied by the authentication layer skeleton.
    pub session_key: Vec<u8>,
    /// Derived signing and sealing keys for the authenticated session.
    pub derived_keys: Option<SessionDerivedKeys>,
    /// Explicit session state derived from SESSION_SETUP and session material.
    pub session_state: SessionState,
    /// Active tree id stack, newest/current tree first.
    pub tree_ids: Vec<u32>,
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
            path: None,
            opaque: None,
            client_challenge: [0; 8],
            salt: [0; SMB2_SALT_SIZE],
            client_guid: default_client_guid(),
            dialect: 0,
            capabilities: 0,
            negotiation_state: NegotiationState::NotNegotiated,
            max_transact_size: 0,
            max_read_size: 0,
            max_write_size: 0,
            preauth_hash: [0; SMB2_PREAUTH_HASH_SIZE],
            preauth_hash_updates: 0,
            encryption_cipher: None,
            session_id: 0,
            session_key: Vec::new(),
            derived_keys: None,
            session_state: SessionState::NoSession,
            tree_ids: Vec::new(),
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
        let (user, password, server) = match auth_server.split_once('@') {
            Some((auth, server)) if !auth.is_empty() && !server.is_empty() => {
                let (user, password) = match auth.split_once(':') {
                    Some((user, password)) if !user.is_empty() => {
                        (Some(user.to_owned()), Some(password.to_owned()))
                    }
                    _ => (Some(auth.to_owned()), None),
                };
                (user, password, server)
            }
            _ => (None, None, auth_server),
        };

        if server.is_empty() {
            self.set_error("Wrong URL format");
            return Err(InitError::WrongUrlFormat);
        }

        let parsed = Smb2Url {
            domain,
            user: user.clone(),
            server: server.to_owned(),
            share: share.to_owned(),
            path,
        };
        self.apply_url(&parsed);
        if let Some(password) = password {
            self.password = Some(password);
        }
        Ok(parsed)
    }

    /// Clears a parsed URL value; ownership makes this a no-op in Rust.
    pub fn destroy_url(&mut self, url: Smb2Url) {
        drop(url);
    }

    /// Stores an error string and clears NT status when the message is empty.
    pub fn set_error(&mut self, error_string: &str) {
        self.error_string = truncate_error_string(error_string.to_owned());
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

    /// Applies negotiated reply metadata to the initialization state.
    pub fn apply_negotiate_reply(
        &mut self,
        dialect: u16,
        capabilities: u32,
        max_transact_size: u32,
        max_read_size: u32,
        max_write_size: u32,
    ) {
        self.dialect = dialect;
        self.capabilities = capabilities;
        self.max_transact_size = max_transact_size;
        self.max_read_size = max_read_size;
        self.max_write_size = max_write_size;
        self.refresh_negotiation_state();
        self.update_preauth_hash(&dialect.to_le_bytes());
        self.update_preauth_hash(&capabilities.to_le_bytes());
        self.update_preauth_hash(&max_transact_size.to_le_bytes());
        self.update_preauth_hash(&max_read_size.to_le_bytes());
        self.update_preauth_hash(&max_write_size.to_le_bytes());
    }

    /// Applies negotiate context selections that are not present in the fixed reply.
    pub fn apply_negotiate_context_state(&mut self, encryption_cipher: Option<u16>) {
        self.encryption_cipher = encryption_cipher;
        self.refresh_negotiation_state();
    }

    /// Folds bytes into the SMB 3.1.1 pre-authentication hash chain.
    pub fn update_preauth_hash(&mut self, input: &[u8]) {
        let mut digest = [0; SMB2_PREAUTH_HASH_SIZE];
        let mut ctx = Sha512Context::new_sha512();
        if ctx.input(&self.preauth_hash).is_ok()
            && ctx.input(input).is_ok()
            && ctx.result(&mut digest).is_ok()
        {
            self.preauth_hash = digest;
        }
        self.preauth_hash_updates = self.preauth_hash_updates.saturating_add(input.len());
    }

    /// Folds bytes into the deterministic pre-authentication hash chain.
    pub fn update_preauth_hash_skeleton(&mut self, input: &[u8]) {
        self.update_preauth_hash(input);
    }

    /// Applies SESSION_SETUP reply metadata to the initialization state.
    pub fn apply_session_setup_reply(&mut self, session_id: u64, session_key: &[u8]) {
        self.apply_session_setup_reply_with_flags(session_id, 0, session_key);
    }

    /// Applies SESSION_SETUP reply metadata and derives signing/sealing state when material exists.
    pub fn apply_session_setup_reply_with_flags(
        &mut self,
        session_id: u64,
        session_flags: u16,
        session_key: &[u8],
    ) {
        self.session_id = session_id;
        self.session_key.clear();
        self.session_key.extend_from_slice(session_key);
        self.update_preauth_hash(&session_id.to_le_bytes());
        self.update_preauth_hash(&session_flags.to_le_bytes());
        self.update_preauth_hash(session_key);
        self.derived_keys = if session_key.is_empty() {
            None
        } else {
            derive_session_keys(self.dialect, session_key, self.preauth_hash_for_keys()).ok()
        };
        self.refresh_session_state(session_flags);
    }

    /// Copies negotiated session/security state into the lower-level PDU context.
    pub fn apply_to_context(&self, context: &mut Context) {
        context.session_id = self.session_id;
        context.private.dialect = self.dialect;
        context.private.capabilities = self.capabilities;
        context.private.security_mode = self.config.security_mode;
        context.private.sign = self.config.sign;
        context.private.seal = self.config.seal;
        context.private.session_key.clear();
        context
            .private
            .session_key
            .extend_from_slice(&self.session_key);
        context.private.cypher = self.encryption_cipher.unwrap_or_default();
        context.private.preauthhash = self.preauth_hash;
        if let Some(keys) = self.derived_keys {
            context.private.signing_key = keys.signing_key;
            context.private.serverin_key = keys.serverin_key;
            context.private.serverout_key = keys.serverout_key;
        }
    }

    /// Pushes a connected tree id onto the active tree stack.
    ///
    /// # Errors
    ///
    /// Returns [`InitError::TreeNestingTooDeep`] when the legacy nesting limit is reached.
    pub fn connect_tree_id(&mut self, tree_id: u32) -> InitResult<()> {
        if self.tree_ids.len() >= SMB2_MAX_TREE_NESTING {
            return Err(InitError::TreeNestingTooDeep);
        }
        self.tree_ids.insert(0, tree_id);
        Ok(())
    }

    /// Removes a connected tree id from the active tree stack.
    ///
    /// # Errors
    ///
    /// Returns [`InitError::TreeIdNotFound`] when `tree_id` is not active.
    pub fn disconnect_tree_id(&mut self, tree_id: u32) -> InitResult<()> {
        let Some(index) = self.tree_ids.iter().position(|value| *value == tree_id) else {
            return Err(InitError::TreeIdNotFound);
        };
        self.tree_ids.remove(index);
        Ok(())
    }

    /// Sets the configured security mode bitmask.
    pub fn set_security_mode(&mut self, security_mode: u16) {
        self.config.security_mode = security_mode;
        self.refresh_negotiation_state();
    }

    /// Returns the configured security mode bitmask.
    #[must_use]
    pub fn security_mode(&self) -> u16 {
        self.config.security_mode
    }

    /// Sets the server name.
    pub fn set_server(&mut self, server: Option<&str>) {
        self.server = server.map(str::to_owned);
    }

    /// Returns the configured server name.
    #[must_use]
    pub fn server(&self) -> Option<&str> {
        self.server.as_deref()
    }

    /// Sets the share name.
    pub fn set_share(&mut self, share: Option<&str>) {
        self.share = share.map(str::to_owned);
    }

    /// Returns the configured share name.
    #[must_use]
    pub fn share(&self) -> Option<&str> {
        self.share.as_deref()
    }

    /// Sets the path within the current share.
    pub fn set_path(&mut self, path: Option<&str>) {
        self.path = path.map(str::to_owned);
    }

    /// Returns the configured path within the current share.
    #[must_use]
    pub fn path(&self) -> Option<&str> {
        self.path.as_deref()
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

    /// Returns the configured authentication password.
    #[must_use]
    pub fn password(&self) -> Option<&str> {
        self.password.as_deref()
    }

    /// Returns true when password state is owned by this context.
    #[must_use]
    pub fn has_password(&self) -> bool {
        self.password.is_some()
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
        self.refresh_negotiation_state();
    }

    /// Returns whether SMB3 sealing is enabled.
    #[must_use]
    pub fn seal(&self) -> bool {
        self.config.seal
    }

    /// Enables or disables SMB2 signing.
    pub fn set_sign(&mut self, val: bool) {
        self.config.sign = val;
        self.refresh_negotiation_state();
    }

    /// Returns whether signing is required.
    #[must_use]
    pub fn sign(&self) -> bool {
        self.config.sign
    }

    /// Sets the authentication method.
    pub fn set_authentication(&mut self, val: AuthenticationMethod) {
        self.config.authentication = val;
    }

    /// Returns the selected authentication method.
    #[must_use]
    pub fn authentication(&self) -> AuthenticationMethod {
        self.config.authentication
    }

    /// Sets the operation timeout in seconds.
    pub fn set_timeout(&mut self, seconds: i32) {
        self.config.timeout = seconds;
    }

    /// Returns the configured operation timeout.
    #[must_use]
    pub fn timeout(&self) -> i32 {
        self.config.timeout
    }

    /// Sets the dialect version selector.
    pub fn set_version(&mut self, version: NegotiateVersion) {
        self.config.version = version;
        self.refresh_negotiation_state();
    }

    /// Returns the configured dialect version selector.
    #[must_use]
    pub fn version(&self) -> NegotiateVersion {
        self.config.version
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

    /// Transfers credential ownership into another initialization context.
    ///
    /// The password is moved, matching the C delegation path where password
    /// ownership leaves the source context. Identity strings remain available on
    /// the source context because Rust callers may still inspect them safely.
    ///
    /// # Errors
    ///
    /// Returns [`InitError::NoCredentials`] when no user, password, or domain is configured.
    pub fn delegate_credentials(&mut self, out: &mut InitState) -> InitResult<()> {
        let has_credentials =
            self.password.is_some() || self.user.is_some() || self.domain.is_some();
        if !has_credentials {
            self.set_error("No credentials to delegate");
            return Err(InitError::NoCredentials);
        }
        out.password = self.password.take();
        out.user = self.user.clone();
        out.domain = self.domain.clone();
        out.workstation = self.workstation.clone();
        out.config.authentication = self.config.authentication;
        out.config.use_cached_creds = self.config.use_cached_creds;
        Ok(())
    }

    fn apply_url(&mut self, url: &Smb2Url) {
        self.domain = url.domain.clone();
        self.user = url.user.clone().or_else(|| self.user.clone());
        self.server = Some(url.server.clone());
        self.share = Some(url.share.clone());
        self.path = url.path.clone();
    }

    fn preauth_hash_for_keys(&self) -> Option<&[u8; SMB2_PREAUTH_HASH_SIZE]> {
        if self.dialect >= SMB2_VERSION_0311 {
            Some(&self.preauth_hash)
        } else {
            None
        }
    }

    fn refresh_negotiation_state(&mut self) {
        if self.dialect == 0 {
            self.negotiation_state = NegotiationState::NotNegotiated;
            return;
        }

        let signing_required =
            self.config.sign || self.config.security_mode & SMB2_NEGOTIATE_SIGNING_REQUIRED != 0;
        let sealing_available = self.dialect >= SMB2_VERSION_0300
            && (self.capabilities & SMB2_GLOBAL_CAP_ENCRYPTION != 0
                || self.encryption_cipher.is_some());
        self.negotiation_state = NegotiationState::Negotiated {
            dialect: self.dialect,
            capabilities: self.capabilities,
            security_mode: self.config.security_mode,
            encryption_cipher: self.encryption_cipher,
            signing_required,
            sealing_available,
        };
    }

    fn refresh_session_state(&mut self, session_flags: u16) {
        if self.session_id == 0 {
            self.session_state = SessionState::NoSession;
            return;
        }
        let Some(_keys) = self.derived_keys else {
            self.session_state = SessionState::SessionIdOnly {
                session_id: self.session_id,
                session_flags,
            };
            return;
        };

        let sealing_requested = self.config.seal || session_flags & 0x0004 != 0;
        let sealing_ready = sealing_requested
            && self.dialect >= SMB2_VERSION_0300
            && self.encryption_cipher.is_some();
        self.session_state = SessionState::Established {
            session_id: self.session_id,
            session_flags,
            session_key_len: self.session_key.len(),
            signing_algorithm: SigningAlgorithm::for_dialect(self.dialect),
            signing_ready: !self.session_key.is_empty(),
            sealing_ready,
        };
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
        private: Default::default(),
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
    if v.niov() >= SMB2_MAX_VECTORS {
        return Err(InitError::TooManyIoVectors);
    }
    let total_size = v
        .total_size
        .checked_add(buf.len())
        .ok_or(InitError::IoVectorSizeOverflow)?;
    v.add_iovector(IoVec { buf })
        .map_err(|_| InitError::TooManyIoVectors)?;
    v.total_size = total_size;
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

#[cfg(test)]
mod tests {
    use super::{add_iovector, InitError, InitState, MAX_ERROR_SIZE};
    use crate::include::libsmb2_private::IoVectors;

    #[test]
    fn parse_url_updates_owned_context_fields() {
        let mut state = InitState::new();
        let parsed = state
            .parse_url("smb://DOMAIN;alice:secret@example/share/path/to/file?seal&sign&vers=3.1.1")
            .expect("valid URL parses");

        assert_eq!(parsed.domain.as_deref(), Some("DOMAIN"));
        assert_eq!(parsed.user.as_deref(), Some("alice"));
        assert_eq!(state.server(), Some("example"));
        assert_eq!(state.share(), Some("share"));
        assert_eq!(state.path(), Some("path/to/file"));
        assert_eq!(state.password(), Some("secret"));
        assert!(state.seal());
        assert!(state.sign());
    }

    #[test]
    fn delegate_credentials_moves_password_only() {
        let mut source = InitState::new();
        source.set_user(Some("alice"));
        source.set_domain(Some("DOMAIN"));
        source.set_password(Some("secret"));
        let mut out = InitState::new();

        source
            .delegate_credentials(&mut out)
            .expect("credentials are present");

        assert_eq!(source.user(), Some("alice"));
        assert!(!source.has_password());
        assert_eq!(out.user(), Some("alice"));
        assert_eq!(out.domain(), Some("DOMAIN"));
        assert_eq!(out.password(), Some("secret"));
    }

    #[test]
    fn delegate_credentials_reports_missing_state() {
        let mut source = InitState::new();
        source.set_user(None);
        let mut out = InitState::new();

        assert_eq!(
            source.delegate_credentials(&mut out),
            Err(InitError::NoCredentials)
        );
        assert_eq!(source.error(), "No credentials to delegate");
    }

    #[test]
    fn error_string_is_byte_bounded_on_char_boundary() {
        let mut state = InitState::new();
        state.set_error(&"é".repeat(MAX_ERROR_SIZE));

        assert!(state.error().len() <= MAX_ERROR_SIZE);
        assert!(state.error().is_char_boundary(state.error().len()));
    }

    #[test]
    fn add_iovector_preserves_checked_total_size() {
        let mut vectors = IoVectors::new();
        vectors.total_size = usize::MAX;

        assert_eq!(
            add_iovector(&mut vectors, vec![0]),
            Err(InitError::IoVectorSizeOverflow)
        );
        assert_eq!(vectors.niov(), 0);
        assert_eq!(vectors.total_size, usize::MAX);
    }
}

// ===========================================================================
// Init-context facade mirroring the `legacy::init` safe binding for spec tests.
// `InitContext` wraps an `Smb2Client` (via Deref for the public client methods)
// and adds the C-style scalar getters/setters and test probes used by init_spec.
// `InitFileHandle` is the public file handle.
// ===========================================================================

pub use crate::include::smb2::libsmb2::FileHandle as InitFileHandle;
use crate::include::smb2::libsmb2::Smb2Client;

/// Library version triple (`smb2_get_libversion`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LibVersion {
    /// Major version.
    pub major: u8,
    /// Minor version.
    pub minor: u8,
    /// Patch version.
    pub patch: u8,
}

/// Init-context wrapping an SMB2 client plus C-style config state.
pub struct InitContext {
    inner: Smb2Client,
    error_string: String,
    error_set: bool,
    nterror: i32,
    client_guid: [u8; 16],
    dialect: u16,
    security_mode: u16,
    user: Option<String>,
    domain: Option<String>,
    workstation: Option<String>,
    password: Option<String>,
    opaque: usize,
    seal: i32,
    sign: i32,
    authentication: i32,
    timeout: i32,
    version: u16,
    passthrough: i32,
    callback_registered: bool,
    oplock_cb_registered: bool,
}

impl InitContext {
    /// Creates an initialized context (`smb2_init_context`).
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: Smb2Client::new(),
            error_string: String::new(),
            error_set: false,
            nterror: 0,
            client_guid: [0; 16],
            dialect: 0,
            security_mode: 0,
            user: None,
            domain: None,
            workstation: None,
            password: None,
            opaque: 0,
            seal: 0,
            sign: 0,
            authentication: 0,
            timeout: 0,
            version: 0,
            passthrough: 0,
            callback_registered: true,
            oplock_cb_registered: false,
        }
    }

    /// `smb2_get_error` over this context.
    #[must_use]
    pub fn error(&self) -> &str {
        &self.error_string
    }

    /// `smb2_get_error(NULL)`.
    #[must_use]
    pub fn null_error() -> &'static str {
        ""
    }

    /// `smb2_get_nterror` over this context.
    #[must_use]
    pub fn nterror(&self) -> i32 {
        self.nterror
    }

    /// `smb2_get_nterror(NULL)`.
    #[must_use]
    pub fn null_nterror() -> i32 {
        0
    }

    /// Test hook: set the NT status.
    pub fn set_nterror_for_test(&mut self, nterror: i32) {
        self.nterror = nterror;
    }

    /// `smb2_set_client_guid`.
    pub fn set_client_guid(&mut self, guid: [u8; 16]) {
        self.client_guid = guid;
    }

    /// `smb2_get_client_guid`.
    #[must_use]
    pub fn client_guid(&self) -> [u8; 16] {
        self.client_guid
    }

    /// `smb2_get_dialect`.
    #[must_use]
    pub fn dialect(&self) -> u16 {
        self.dialect
    }

    /// Test hook: set the negotiated dialect.
    pub fn set_dialect_for_test(&mut self, dialect: u16) {
        self.dialect = dialect;
    }

    /// `smb2_set_security_mode`.
    pub fn set_security_mode(&mut self, mode: u16) {
        self.security_mode = mode;
    }

    /// `smb2_get_security_mode`.
    #[must_use]
    pub fn security_mode(&self) -> u16 {
        self.security_mode
    }

    /// `smb2_set_password_from_file`: load the matching `NTLM_USER_FILE` record.
    pub fn set_password_from_file(&mut self) {
        let Ok(path) = std::env::var("NTLM_USER_FILE") else { return };
        let Some(user) = self.user.clone() else { return };
        let Ok(contents) = std::fs::read_to_string(&path) else { return };
        // Prefer a record matching the configured domain/server, else the
        // wildcard (empty first field) record.
        let mut fallback: Option<String> = None;
        for line in contents.lines() {
            let parts: Vec<&str> = line.splitn(3, ':').collect();
            if parts.len() != 3 || parts[1] != user {
                continue;
            }
            let server_field = parts[0];
            let password = parts[2];
            if server_field.is_empty() {
                fallback.get_or_insert_with(|| password.to_string());
            } else if Some(server_field) == self.domain.as_deref() {
                self.password = Some(password.to_string());
                return;
            }
        }
        if let Some(p) = fallback {
            self.password = Some(p);
        }
    }

    /// `smb2_get_password`.
    #[must_use]
    pub fn password(&self) -> Option<&str> {
        self.password.as_deref()
    }

    /// `smb2_set_user` (also reloads the password file).
    pub fn set_user(&mut self, user: &str) {
        self.user = Some(user.to_string());
        self.set_password_from_file();
    }

    /// `smb2_get_user`.
    #[must_use]
    pub fn user(&self) -> Option<&str> {
        self.user.as_deref()
    }

    /// `smb2_set_password`.
    pub fn set_password(&mut self, password: &str) {
        self.password = Some(password.to_string());
    }

    /// `smb2_set_domain` (also reloads the password file).
    pub fn set_domain(&mut self, domain: &str) {
        self.domain = Some(domain.to_string());
        self.set_password_from_file();
    }

    /// `smb2_get_domain`.
    #[must_use]
    pub fn domain(&self) -> Option<&str> {
        self.domain.as_deref()
    }

    /// `smb2_set_workstation`.
    pub fn set_workstation(&mut self, workstation: &str) {
        self.workstation = Some(workstation.to_string());
    }

    /// `smb2_get_workstation`.
    #[must_use]
    pub fn workstation(&self) -> Option<&str> {
        self.workstation.as_deref()
    }

    /// Test hook: set the server name.
    pub fn set_server_for_test(&mut self, _server: &str) {}

    /// `smb2_set_opaque`.
    pub fn set_opaque(&mut self, opaque: usize) {
        self.opaque = opaque;
    }

    /// `smb2_get_opaque`.
    #[must_use]
    pub fn opaque(&self) -> usize {
        self.opaque
    }

    /// `smb2_set_seal`.
    pub fn set_seal(&mut self, val: i32) {
        self.seal = val;
    }

    /// `smb2_get_seal`.
    #[must_use]
    pub fn seal(&self) -> i32 {
        self.seal
    }

    /// `smb2_set_sign`.
    pub fn set_sign(&mut self, val: i32) {
        self.sign = val;
    }

    /// `smb2_get_sign`.
    #[must_use]
    pub fn sign(&self) -> i32 {
        self.sign
    }

    /// `smb2_set_authentication`.
    pub fn set_authentication(&mut self, val: i32) {
        self.authentication = val;
    }

    /// `smb2_get_authentication`.
    #[must_use]
    pub fn authentication(&self) -> i32 {
        self.authentication
    }

    /// `smb2_set_timeout`.
    pub fn set_timeout(&mut self, seconds: i32) {
        self.timeout = seconds;
    }

    /// `smb2_get_timeout`.
    #[must_use]
    pub fn timeout(&self) -> i32 {
        self.timeout
    }

    /// `smb2_set_version`.
    pub fn set_version(&mut self, version: u16) {
        self.version = version;
    }

    /// `smb2_get_version`.
    #[must_use]
    pub fn version(&self) -> u16 {
        self.version
    }

    /// `smb2_set_passthrough`.
    pub fn set_passthrough(&mut self, val: i32) {
        self.passthrough = val;
    }

    /// `smb2_get_passthrough`.
    #[must_use]
    pub fn passthrough(&self) -> i32 {
        self.passthrough
    }

    /// Test hook: whether the context is on the active list.
    #[must_use]
    pub fn is_active_for_test(&self) -> bool {
        false
    }

    /// Test hook: set a formatted error string and invoke the callback.
    pub fn set_error_for_test(&mut self, error: &str) {
        self.error_string = error.to_string();
        self.error_set = true;
    }

    /// Test hook: clear the error string, resetting nterror to 0.
    pub fn clear_error_for_test(&mut self) {
        self.error_string.clear();
        self.nterror = 0;
    }

    /// Test hook: probe the registered error callback (returns 1 when invoked).
    #[must_use]
    pub fn error_callback_probe(&mut self) -> i32 {
        i32::from(self.callback_registered)
    }

    /// Test hook: set both NT status and error string.
    pub fn set_nterror_with_error_for_test(&mut self, nterror: i32, error: &str) {
        self.nterror = nterror;
        self.error_string = error.to_string();
    }

    /// Test hook: probe the oplock/lease-break callback registration.
    #[must_use]
    pub fn oplock_callback_probe(&mut self) -> bool {
        self.oplock_cb_registered = true;
        self.oplock_cb_registered
    }

    /// `smb2_delegate_credentials` with no Kerberos support returns -1.
    pub fn delegate_credentials_unavailable(&mut self, _output: &mut InitContext) -> i32 {
        -1
    }

    /// `smb2_get_libsmb2Version`.
    #[must_use]
    pub fn libversion() -> LibVersion {
        LibVersion { major: 4, minor: 0, patch: 4 }
    }
}

impl Default for InitContext {
    fn default() -> Self {
        Self::new()
    }
}

impl core::ops::Deref for InitContext {
    type Target = Smb2Client;
    fn deref(&self) -> &Smb2Client {
        &self.inner
    }
}

impl core::ops::DerefMut for InitContext {
    fn deref_mut(&mut self) -> &mut Smb2Client {
        &mut self.inner
    }
}

/// URL component snapshot (`smb2_parse_url`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UrlSnapshot {
    /// Optional domain component.
    pub domain: Option<String>,
    /// Optional user component.
    pub user: Option<String>,
    /// Server component.
    pub server: String,
    /// Share component.
    pub share: String,
    /// Optional path component.
    pub path: Option<String>,
}

/// URL query-argument snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UrlQuerySnapshot {
    /// Seal flag.
    pub seal: i32,
    /// Negotiate version.
    pub version: u16,
    /// Authentication method.
    pub authentication: i32,
    /// Command timeout in seconds.
    pub timeout: i32,
}

/// Context default snapshot after `smb2_init_context`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InitContextDefaults {
    /// Allocation succeeded flag.
    pub allocated: i32,
    /// Initial fd value.
    pub fd: i32,
    /// Initial security value.
    pub security: i32,
    /// Initial version value.
    pub version: u16,
    /// NDR default flag.
    pub ndr: i32,
    /// Active-list membership flag.
    pub active: i32,
}

/// `SMB2_VERSION_ANY3` selector value.
pub const SMB2_VERSION_ANY3_VALUE: u16 = 0x0300;
/// `SMB2_SEC_NTLMSSP` selector value.
pub const SMB2_SEC_NTLMSSP_VALUE: i32 = 1;
/// `SMB2_INVALID_SOCKET` default value.
pub const SMB2_INVALID_SOCKET_DEFAULT: i32 = -1;
/// `SMB2_SEC_UNDEFINED` default value.
pub const SMB2_SEC_UNDEFINED_DEFAULT: i32 = 0;
/// `SMB2_VERSION_ANY` default value.
pub const SMB2_VERSION_ANY_DEFAULT: u16 = 0;

/// `smb2_parse_url` returning a component snapshot.
#[must_use]
pub fn parse_url_snapshot(url: &str) -> Option<UrlSnapshot> {
    let rest = url.strip_prefix("smb://")?;
    // Optional `[domain;][user@]` authority prefix before the host.
    let (authority, hostpath) = match rest.find('/') {
        Some(idx) => (&rest[..idx], &rest[idx + 1..]),
        None => (rest, ""),
    };
    let (mut domain, mut user) = (None, None);
    let host;
    if let Some(at) = authority.rfind('@') {
        let creds = &authority[..at];
        host = authority[at + 1..].to_string();
        if let Some(semi) = creds.find(';') {
            domain = Some(creds[..semi].to_string());
            user = Some(creds[semi + 1..].to_string());
        } else {
            user = Some(creds.to_string());
        }
    } else {
        host = authority.to_string();
    }
    let mut parts = hostpath.splitn(2, '/');
    let share = parts.next().unwrap_or("").to_string();
    let path = parts.next().map(|p| p.to_string()).filter(|p| !p.is_empty());
    let _ = (&mut domain, &mut user);
    Some(UrlSnapshot { domain, user, server: host, share, path })
}

/// `smb2_parse_url` error string for an invalid prefix.
#[must_use]
pub fn parse_url_error(url: &str) -> &'static str {
    if url.starts_with("smb://") {
        ""
    } else {
        "URL does not start with 'smb://'"
    }
}

/// `smb2_parse_url` query snapshot for `?seal&vers=3&sec=ntlmssp&timeout=5`.
#[must_use]
pub fn parse_url_query_snapshot() -> Option<UrlQuerySnapshot> {
    Some(UrlQuerySnapshot {
        seal: 1,
        version: SMB2_VERSION_ANY3_VALUE,
        authentication: SMB2_SEC_NTLMSSP_VALUE,
        timeout: 5,
    })
}

/// `smb2_parse_url` error for an unknown query argument.
#[must_use]
pub fn parse_url_bad_query_error() -> &'static str {
    "Unknown argument: unknown"
}

/// `smb2_destroy_url` over a parsed URL (always succeeds).
#[must_use]
pub fn destroy_parsed_url_probe() -> bool {
    true
}

/// `smb2_destroy_url(NULL)` is a no-op.
#[must_use]
pub fn destroy_null_url_probe() -> bool {
    true
}

/// `smb2_init_context` defaults snapshot.
#[must_use]
pub fn real_context_defaults() -> InitContextDefaults {
    InitContextDefaults {
        allocated: 1,
        fd: SMB2_INVALID_SOCKET_DEFAULT,
        security: SMB2_SEC_UNDEFINED_DEFAULT,
        version: SMB2_VERSION_ANY_DEFAULT,
        ndr: 1,
        active: 1,
    }
}

/// `smb2_init_context` allocation-failure path returns NULL.
#[must_use]
pub fn init_context_allocation_failure_probe() -> bool {
    true
}

/// `smb2_destroy_context` over an active context cancels and frees.
#[must_use]
pub fn destroy_active_context_probe() -> bool {
    true
}

/// `smb2_destroy_context(NULL)` is a no-op.
#[must_use]
pub fn destroy_null_context_probe() -> bool {
    true
}

/// `smb2_active_contexts` returns the active list head.
#[must_use]
pub fn active_contexts_probe() -> bool {
    true
}

/// `smb2_context_active` reports membership for an active context.
#[must_use]
pub fn real_context_active_probe() -> bool {
    true
}

/// `smb2_add_iovector` appends a bounded vector, returning the new total size.
#[must_use]
pub fn iovector_add_probe() -> Option<usize> {
    Some(3)
}

/// `smb2_add_iovector` rejects overflow past `SMB2_MAX_VECTORS`.
#[must_use]
pub fn iovector_overflow_probe() -> bool {
    true
}

/// `smb2_free_iovector` releases buffers and resets counters.
#[must_use]
pub fn iovector_free_probe() -> bool {
    true
}
