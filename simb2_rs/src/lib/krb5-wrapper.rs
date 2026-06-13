//! Kerberos wrapper migrated from `lib/krb5-wrapper.c`.
//!
//! This module mirrors the state and function responsibilities of the legacy C
//! Kerberos/GSSAPI wrapper. It intentionally does not call Kerberos or GSSAPI
//! libraries yet; methods that would require protocol work return structured
//! skeleton errors instead.

/// GSS request flag matching the legacy sequence flag usage.
pub const GSS_SEQUENCE_FLAG: u32 = 1 << 0;

/// GSS request flag matching the legacy mutual-authentication flag usage.
pub const GSS_MUTUAL_FLAG: u32 = 1 << 1;

/// GSS request flag matching the legacy replay-detection flag usage.
pub const GSS_REPLAY_FLAG: u32 = 1 << 2;

/// Request flags set by `krb5_session_request` in the C implementation.
pub const DEFAULT_SESSION_REQUEST_FLAGS: u32 =
    GSS_SEQUENCE_FLAG | GSS_MUTUAL_FLAG | GSS_REPLAY_FLAG;

/// Result type used by Kerberos wrapper skeleton APIs.
pub type Krb5Result<T> = core::result::Result<T, Krb5Error>;

/// Errors returned by Kerberos wrapper skeleton helpers.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Krb5Error {
    /// A required server, user, domain, password, or keytab value was absent.
    MissingParameter(&'static str),
    /// A host name was empty after stripping any port suffix.
    EmptyHost,
    /// A requested operation depends on Kerberos/GSSAPI logic not migrated yet.
    ProtocolLogicNotImplemented,
    /// A session key was requested before one had been established.
    MissingSessionKey,
}

/// Security mechanism selected for a Kerberos-backed exchange.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum Krb5Mechanism {
    /// Let the platform GSSAPI choose its default mechanism.
    #[default]
    Default,
    /// Kerberos V5 mechanism.
    Kerberos5,
    /// SPNEGO wrapper mechanism.
    Spnego,
    /// NTLMSSP through a Kerberos/SPNEGO provider when available.
    NtlmSsp,
}

/// Current side and progress of a GSS security context.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum Krb5ContextState {
    /// No context has been initialized.
    #[default]
    Empty,
    /// Client-side initiator context has been prepared.
    Initiating,
    /// Server-side acceptor context has been prepared.
    Accepting,
    /// Additional token exchange is required.
    ContinueNeeded,
    /// Context establishment completed.
    Complete,
}

/// Raw token exchanged with SMB session setup messages.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GssToken {
    bytes: Vec<u8>,
}

impl GssToken {
    /// Creates an empty GSS token.
    #[must_use]
    pub const fn new() -> Self {
        Self { bytes: Vec::new() }
    }

    /// Creates a token from raw bytes.
    #[must_use]
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }

    /// Returns the token bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns the token length in bytes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Returns whether this token is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Replaces the token contents.
    pub fn replace(&mut self, bytes: Vec<u8>) {
        self.bytes = bytes;
    }

    /// Clears the token contents.
    pub fn clear(&mut self) {
        self.bytes.clear();
    }

    /// Consumes the token and returns its bytes.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}

/// Client-side inputs corresponding to `krb5_negotiate_reply`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Krb5NegotiateConfig {
    /// Server host name, optionally including a port suffix.
    pub server: String,
    /// Optional authentication domain or realm.
    pub domain: Option<String>,
    /// Optional user name.
    pub user_name: Option<String>,
    /// Optional password used when a memory credentials cache is requested.
    pub password: Option<String>,
    /// Whether to use the cached-credentials path from the C implementation.
    pub use_cached_creds: bool,
    /// Whether SPNEGO should be selected instead of raw Kerberos.
    pub use_spnego: bool,
    /// Optional delegated credential marker from an existing SMB context.
    pub delegated_credential: Option<String>,
}

/// Server-side inputs corresponding to `krb5_init_server_client_cred`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Krb5ServerClientCredConfig {
    /// Server host name, optionally including a port suffix.
    pub hostname: String,
    /// Whether constrained delegation should be attempted later.
    pub proxy_authentication: bool,
    /// Security mechanism selected by the SMB negotiation layer.
    pub mechanism: Krb5Mechanism,
    /// Optional server keytab path already initialized for server credentials.
    pub keytab_path: Option<String>,
    /// Optional memory credentials cache name already initialized for the server.
    pub ccache_name: Option<String>,
}

/// Server keytab initialization inputs matching `krb5_init_server_credentials`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Krb5ServerCredentialsConfig {
    /// Server host name, optionally including a port suffix.
    pub hostname: String,
    /// Keytab path used for server credential renewal.
    pub keytab_path: Option<String>,
}

/// Result returned by a client-side session request step.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Krb5SessionRequest {
    /// Whether another session setup round trip is expected.
    pub continue_needed: bool,
    /// Output token that should be sent to the peer.
    pub output_token: GssToken,
}

/// Result returned by a server-side session reply step.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Krb5SessionReply {
    /// Whether the peer must send another token.
    pub more_processing_needed: bool,
    /// Authenticated user name when it has been extracted.
    pub user: Option<String>,
    /// Authenticated domain when it has been extracted.
    pub domain: Option<String>,
    /// Output token that should be sent to the peer.
    pub output_token: GssToken,
}

/// Mutable authentication data corresponding to C `struct private_auth_data`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PrivateAuthData {
    g_server: Option<String>,
    target_name: Option<String>,
    user_name: Option<String>,
    credential: Option<String>,
    delegated_credential: Option<String>,
    keytab_path: Option<String>,
    principal_name: Option<String>,
    ccache_name: Option<String>,
    output_token: GssToken,
    input_token: GssToken,
    session_key: Vec<u8>,
    req_flags: u32,
    mechanism: Krb5Mechanism,
    context_state: Krb5ContextState,
    use_spnego: bool,
    get_proxy_cred: bool,
}

impl PrivateAuthData {
    /// Creates an empty Kerberos authentication-data skeleton.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Builds client-side authentication data matching `krb5_negotiate_reply`.
    ///
    /// # Errors
    ///
    /// Returns [`Krb5Error::MissingParameter`] when required client inputs are
    /// absent, [`Krb5Error::EmptyHost`] when the server host is empty, and
    /// [`Krb5Error::ProtocolLogicNotImplemented`] when credential acquisition
    /// would be required.
    pub fn negotiate_reply(config: Krb5NegotiateConfig) -> Krb5Result<Self> {
        let host = strip_port(&config.server)?;
        if config.use_cached_creds {
            require_some(config.domain.as_deref(), "domain")?;
            require_some(config.password.as_deref(), "password")?;
        }

        let g_server = service_name(&host);
        let mechanism = if config.use_spnego {
            Krb5Mechanism::Spnego
        } else {
            Krb5Mechanism::Kerberos5
        };

        let user_name = match (config.use_cached_creds, config.user_name, config.domain) {
            (true, Some(user), Some(domain)) => Some(format!("{user}@{domain}")),
            (_, user, _) => user,
        };

        if let Some(delegated_credential) = config.delegated_credential {
            return Ok(Self {
                g_server: Some(g_server.clone()),
                target_name: Some(g_server),
                delegated_credential: Some(delegated_credential),
                mechanism,
                context_state: Krb5ContextState::Initiating,
                use_spnego: config.use_spnego,
                ..Self::default()
            });
        }

        let Some(user_name) = user_name else {
            return Err(Krb5Error::MissingParameter("user_name"));
        };

        let mut auth_data = Self {
            g_server: Some(g_server.clone()),
            target_name: Some(g_server),
            user_name: Some(user_name),
            mechanism,
            context_state: Krb5ContextState::Initiating,
            use_spnego: config.use_spnego,
            ..Self::default()
        };

        if config.use_cached_creds {
            auth_data.ccache_name = Some(String::from("MEMORY"));
        }

        Err(Krb5Error::ProtocolLogicNotImplemented)
    }

    /// Builds server/client credential data matching `krb5_init_server_client_cred`.
    ///
    /// # Errors
    ///
    /// Returns [`Krb5Error::EmptyHost`] when the configured host is empty and
    /// [`Krb5Error::ProtocolLogicNotImplemented`] because GSS credential
    /// acquisition is not migrated yet.
    pub fn init_server_client_cred(config: Krb5ServerClientCredConfig) -> Krb5Result<Self> {
        let host = strip_port(&config.hostname)?;
        let g_server = service_name(&host);
        let _auth_data = Self {
            g_server: Some(g_server.clone()),
            target_name: Some(g_server),
            keytab_path: config.keytab_path,
            ccache_name: config.ccache_name,
            mechanism: config.mechanism,
            context_state: Krb5ContextState::Accepting,
            get_proxy_cred: config.proxy_authentication,
            ..Self::default()
        };

        Err(Krb5Error::ProtocolLogicNotImplemented)
    }

    /// Builds server credential state matching `krb5_init_server_credentials`.
    ///
    /// # Errors
    ///
    /// Returns [`Krb5Error::EmptyHost`] when the host is empty. Returns
    /// [`Krb5Error::ProtocolLogicNotImplemented`] when a keytab path is present,
    /// because keytab login and cache initialization are not migrated yet.
    pub fn init_server_credentials(
        config: Krb5ServerCredentialsConfig,
    ) -> Krb5Result<Option<Self>> {
        let Some(keytab_path) = config.keytab_path else {
            return Ok(None);
        };
        if keytab_path.is_empty() {
            return Ok(None);
        }

        let host = strip_port(&config.hostname)?;
        let principal_name = format!("cifs/{host}");
        let _auth_data = Self {
            g_server: Some(service_name(&host)),
            target_name: Some(service_name(&host)),
            keytab_path: Some(keytab_path),
            principal_name: Some(principal_name),
            ccache_name: Some(String::from("MEMORY")),
            mechanism: Krb5Mechanism::Kerberos5,
            context_state: Krb5ContextState::Accepting,
            ..Self::default()
        };

        Err(Krb5Error::ProtocolLogicNotImplemented)
    }

    /// Clears token, credential, cache, and identity state like `krb5_free_auth_data`.
    pub fn free_auth_data(&mut self) {
        self.g_server = None;
        self.target_name = None;
        self.user_name = None;
        self.credential = None;
        self.delegated_credential = None;
        self.keytab_path = None;
        self.principal_name = None;
        self.ccache_name = None;
        self.output_token.clear();
        self.input_token.clear();
        self.session_key.clear();
        self.req_flags = 0;
        self.context_state = Krb5ContextState::Empty;
        self.get_proxy_cred = false;
    }

    /// Saves an input token and prepares request flags for `krb5_session_request`.
    ///
    /// # Errors
    ///
    /// Returns [`Krb5Error::ProtocolLogicNotImplemented`] because
    /// `gss_init_sec_context` is not migrated yet.
    pub fn session_request(&mut self, input: Option<&[u8]>) -> Krb5Result<Krb5SessionRequest> {
        self.output_token.clear();
        self.req_flags = DEFAULT_SESSION_REQUEST_FLAGS;
        if let Some(input) = input {
            self.input_token.replace(input.to_vec());
        }

        Err(Krb5Error::ProtocolLogicNotImplemented)
    }

    /// Accepts an input token for `krb5_session_reply`.
    ///
    /// # Errors
    ///
    /// Returns [`Krb5Error::ProtocolLogicNotImplemented`] because
    /// `gss_accept_sec_context`, user display, and delegation are not migrated yet.
    pub fn session_reply(&mut self, input: &[u8]) -> Krb5Result<Krb5SessionReply> {
        self.output_token.clear();
        self.input_token.replace(input.to_vec());
        self.context_state = Krb5ContextState::Accepting;

        Err(Krb5Error::ProtocolLogicNotImplemented)
    }

    /// Returns the established session key like `krb5_session_get_session_key`.
    ///
    /// # Errors
    ///
    /// Returns [`Krb5Error::MissingSessionKey`] when no key has been stored yet.
    pub fn session_get_session_key(&self) -> Krb5Result<&[u8]> {
        if self.session_key.is_empty() {
            return Err(Krb5Error::MissingSessionKey);
        }

        Ok(&self.session_key)
    }

    /// Replaces the stored session key for future migrated GSS inquiry plumbing.
    pub fn set_session_key(&mut self, session_key: Vec<u8>) {
        self.session_key = session_key;
    }

    /// Renews server credentials matching `krb5_renew_server_credentials`.
    ///
    /// # Errors
    ///
    /// Returns [`Krb5Error::ProtocolLogicNotImplemented`] when a keytab-backed
    /// credential exists, because keytab renewal is not migrated yet.
    pub fn renew_server_credentials(&self) -> Krb5Result<()> {
        if self.keytab_path.is_none() {
            return Ok(());
        }

        Err(Krb5Error::ProtocolLogicNotImplemented)
    }

    /// Returns the current output token length in bytes.
    #[must_use]
    pub fn get_output_token_length(&self) -> usize {
        self.output_token.len()
    }

    /// Returns the current output token bytes.
    #[must_use]
    pub fn get_output_token_buffer(&self) -> &[u8] {
        self.output_token.as_bytes()
    }

    /// Returns the service principal name stored in this authentication data.
    #[must_use]
    pub fn g_server(&self) -> Option<&str> {
        self.g_server.as_deref()
    }

    /// Returns the target name imported from the service principal skeleton.
    #[must_use]
    pub fn target_name(&self) -> Option<&str> {
        self.target_name.as_deref()
    }

    /// Returns the user name associated with this authentication data.
    #[must_use]
    pub fn user_name(&self) -> Option<&str> {
        self.user_name.as_deref()
    }

    /// Returns the selected mechanism.
    #[must_use]
    pub const fn mechanism(&self) -> Krb5Mechanism {
        self.mechanism
    }

    /// Returns the current context state.
    #[must_use]
    pub const fn context_state(&self) -> Krb5ContextState {
        self.context_state
    }

    /// Returns whether SPNEGO is selected for this authentication data.
    #[must_use]
    pub const fn use_spnego(&self) -> bool {
        self.use_spnego
    }

    /// Returns whether proxy credentials should be acquired for this context.
    #[must_use]
    pub const fn get_proxy_cred(&self) -> bool {
        self.get_proxy_cred
    }
}

/// Formats a GSS status pair for callers that mirror `krb5_set_gss_error`.
#[must_use]
pub fn krb5_set_gss_error_message(function: &str, major: u32, minor: u32) -> String {
    format!("{function}: ({major}, {minor})")
}

/// Returns whether the current skeleton can use Kerberos for NTLMSSP.
#[must_use]
pub const fn krb5_can_do_ntlmssp() -> bool {
    false
}

fn require_some(value: Option<&str>, name: &'static str) -> Krb5Result<()> {
    match value {
        Some(_) => Ok(()),
        None => Err(Krb5Error::MissingParameter(name)),
    }
}

fn service_name(host: &str) -> String {
    format!("cifs@{host}")
}

fn strip_port(server: &str) -> Krb5Result<String> {
    let host = server.split_once(':').map_or(server, |(host, _port)| host);
    if host.is_empty() {
        return Err(Krb5Error::EmptyHost);
    }

    Ok(host.to_owned())
}
