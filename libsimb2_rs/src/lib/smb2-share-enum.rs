//! Share enumeration helpers migrated from `lib/smb2-share-enum.c`.
//!
//! The C source builds a SRVSVC `NetrShareEnum` request, binds to the `srvsvc`
//! DCERPC interface, dispatches the request asynchronously, and forwards either
//! transport status or the SRVSVC reply status to the caller callback. This Rust
//! module keeps only the data-shaping and callback-state skeleton so protocol
//! wiring can be added later without changing the public request model.

/// Operation number used by SRVSVC `NetrShareEnum`.
pub const SRVSVC_NETR_SHARE_ENUM_OPNUM: u16 = 15;

/// Preferred maximum response length used by the legacy share enum request.
pub const NETR_SHARE_ENUM_PREFERRED_MAXIMUM_LENGTH: u32 = u32::MAX;

/// Share information level accepted by the legacy `smb2_share_enum_async` entry point.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShareInfoLevel {
    /// `SHARE_INFO_0`, returning share names only.
    ShareInfo0,
    /// `SHARE_INFO_1`, returning share names, type, and remark fields.
    ShareInfo1,
}

impl ShareInfoLevel {
    /// Returns the numeric level value used by the SRVSVC request union.
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        match self {
            Self::ShareInfo0 => 0,
            Self::ShareInfo1 => 1,
        }
    }
}

/// Share info union arm selected for `NetrShareEnum`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShareInfoContainer {
    /// Empty level-0 share info array placeholder.
    Level0 { entries_read: u32 },
    /// Empty level-1 share info array placeholder.
    Level1 { entries_read: u32 },
}

impl ShareInfoContainer {
    /// Creates the empty union arm that corresponds to a requested share info level.
    #[must_use]
    pub const fn empty_for_level(level: ShareInfoLevel) -> Self {
        match level {
            ShareInfoLevel::ShareInfo0 => Self::Level0 { entries_read: 0 },
            ShareInfoLevel::ShareInfo1 => Self::Level1 { entries_read: 0 },
        }
    }

    /// Returns the selected share information level.
    #[must_use]
    pub const fn level(self) -> ShareInfoLevel {
        match self {
            Self::Level0 { .. } => ShareInfoLevel::ShareInfo0,
            Self::Level1 { .. } => ShareInfoLevel::ShareInfo1,
        }
    }

    /// Returns the number of entries currently represented by this skeleton container.
    #[must_use]
    pub const fn entries_read(self) -> u32 {
        match self {
            Self::Level0 { entries_read } | Self::Level1 { entries_read } => entries_read,
        }
    }
}

/// Server name prepared for the SRVSVC `NetrShareEnum` request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShareEnumServerName {
    utf8: String,
}

impl ShareEnumServerName {
    /// Builds the UNC-style server name expected by SRVSVC, using the `\\server` form.
    #[must_use]
    pub fn from_server(server: &str) -> Self {
        let mut utf8 = String::with_capacity(server.len() + 2);
        utf8.push_str("\\\\");
        utf8.push_str(server);
        Self { utf8 }
    }

    /// Returns the UTF-8 server name as it would be placed in `ServerName.utf8`.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.utf8
    }

    /// Consumes the wrapper and returns the owned UTF-8 server name.
    #[must_use]
    pub fn into_string(self) -> String {
        self.utf8
    }
}

/// Request body skeleton corresponding to `srvsvc_NetrShareEnum_req`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetrShareEnumRequest {
    /// Server name passed through `ServerName.utf8` in the C request.
    pub server_name: ShareEnumServerName,
    /// Requested share information level.
    pub level: ShareInfoLevel,
    /// Selected share info union arm with an empty result buffer placeholder.
    pub share_info: ShareInfoContainer,
    /// Preferred maximum response length for the RPC call.
    pub preferred_maximum_length: u32,
    /// Resume handle value for paginated enumeration.
    pub resume_handle: u32,
}

impl NetrShareEnumRequest {
    /// Creates the initial `NetrShareEnum` request skeleton used before DCERPC dispatch.
    #[must_use]
    pub fn new(server: &str, level: ShareInfoLevel) -> Self {
        Self {
            server_name: ShareEnumServerName::from_server(server),
            level,
            share_info: ShareInfoContainer::empty_for_level(level),
            preferred_maximum_length: NETR_SHARE_ENUM_PREFERRED_MAXIMUM_LENGTH,
            resume_handle: 0,
        }
    }

    /// Returns the operation number that should be used when this request is dispatched.
    #[must_use]
    pub const fn opnum(&self) -> u16 {
        SRVSVC_NETR_SHARE_ENUM_OPNUM
    }
}

/// Callback status forwarded by the share enumeration callback skeleton.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShareEnumStatus(i32);

impl ShareEnumStatus {
    /// Creates a callback status from a raw SMB2 or SRVSVC status value.
    #[must_use]
    pub const fn new(raw: i32) -> Self {
        Self(raw)
    }

    /// Returns the raw status value forwarded to the callback.
    #[must_use]
    pub const fn raw(self) -> i32 {
        self.0
    }
}

/// Reply placeholder passed to the callback after a successful DCERPC transport call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShareEnumReply {
    /// SRVSVC status carried by the reply body.
    pub status: ShareEnumStatus,
}

impl ShareEnumReply {
    /// Creates a reply placeholder from the SRVSVC status field.
    #[must_use]
    pub const fn new(status: ShareEnumStatus) -> Self {
        Self { status }
    }
}

/// Result shape forwarded by `srvsvc_ioctl_cb` after an RPC call completes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShareEnumCallbackResult {
    /// DCERPC transport or bind failed before a SRVSVC reply was available.
    TransportError(ShareEnumStatus),
    /// SRVSVC returned a reply; its own status is forwarded separately from transport status.
    Reply(ShareEnumReply),
}

impl ShareEnumCallbackResult {
    /// Builds the callback result for the ioctl completion stage.
    #[must_use]
    pub const fn from_ioctl_status(
        transport_status: ShareEnumStatus,
        reply: Option<ShareEnumReply>,
    ) -> Self {
        if transport_status.raw() == 0 {
            match reply {
                Some(reply) => Self::Reply(reply),
                None => Self::TransportError(transport_status),
            }
        } else {
            Self::TransportError(transport_status)
        }
    }
}

/// State carried between share enumeration setup, bind completion, and ioctl completion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Smb2Nse {
    request: NetrShareEnumRequest,
}

impl Smb2Nse {
    /// Creates the share enumeration state corresponding to the C `struct smb2nse` allocation.
    #[must_use]
    pub fn new(server: &str, level: ShareInfoLevel) -> Self {
        Self {
            request: NetrShareEnumRequest::new(server, level),
        }
    }

    /// Returns the prepared `NetrShareEnum` request.
    #[must_use]
    pub const fn request(&self) -> &NetrShareEnumRequest {
        &self.request
    }

    /// Consumes the state and returns the prepared `NetrShareEnum` request.
    #[must_use]
    pub fn into_request(self) -> NetrShareEnumRequest {
        self.request
    }
}

/// Creates share enumeration state for a future `smb2_share_enum_async` implementation.
#[must_use]
pub fn smb2_share_enum_async_skeleton(server: &str, level: ShareInfoLevel) -> Smb2Nse {
    Smb2Nse::new(server, level)
}
