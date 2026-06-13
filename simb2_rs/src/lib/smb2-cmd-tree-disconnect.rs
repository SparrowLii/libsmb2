//! TREE_DISCONNECT command pack/unpack skeleton migrated from `lib/smb2-cmd-tree-disconnect.c`.

/// SMB2 command number used by TREE_DISCONNECT PDUs.
pub const SMB2_TREE_DISCONNECT: u16 = 0x0004;

/// Fixed TREE_DISCONNECT request structure size from the SMB2 wire format.
pub const SMB2_TREE_DISCONNECT_REQUEST_SIZE: u16 = 4;

/// Fixed TREE_DISCONNECT reply structure size from the SMB2 wire format.
pub const SMB2_TREE_DISCONNECT_REPLY_SIZE: u16 = 4;

/// Result type used by the TREE_DISCONNECT migration skeleton.
pub type TreeDisconnectResult<T> = Result<T, TreeDisconnectError>;

/// Errors returned by the TREE_DISCONNECT pack/unpack skeleton.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TreeDisconnectError {
    /// A fixed-size buffer did not match the expected SMB2 structure size.
    InvalidStructureSize { expected: u16, actual: usize },
    /// The request or reply buffer is too short for the requested field.
    BufferTooShort { needed: usize, actual: usize },
}

/// Minimal context state touched by TREE_DISCONNECT handling in the C source.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Smb2TreeDisconnectContext {
    tree_id: u32,
}

impl Smb2TreeDisconnectContext {
    /// Creates an empty TREE_DISCONNECT context skeleton.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns the currently connected tree id tracked by this skeleton.
    #[must_use]
    pub fn tree_id(&self) -> u32 {
        self.tree_id
    }

    /// Records an active tree id for tests or higher-level skeleton code.
    pub fn connect_tree_id(&mut self, tree_id: u32) {
        self.tree_id = tree_id;
    }

    /// Clears the tracked tree id like `smb2_disconnect_tree_id` in the C code.
    pub fn disconnect_tree_id(&mut self, tree_id: u32) {
        if self.tree_id == tree_id {
            self.tree_id = 0;
        }
    }
}

/// Minimal PDU shape needed by the TREE_DISCONNECT skeleton methods.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Smb2TreeDisconnectPdu {
    /// SMB2 command carried by this PDU.
    pub command: u16,
    /// Tree id associated with the PDU header.
    pub tree_id: u32,
    /// Encoded output vectors mirroring the C `pdu->out` list.
    pub out: Vec<Vec<u8>>,
    /// Decoded request payload, when processing an incoming request.
    pub request: Option<Smb2TreeDisconnectRequest>,
    /// Decoded reply payload, when processing an incoming reply.
    pub reply: Option<Smb2TreeDisconnectReply>,
}

impl Smb2TreeDisconnectPdu {
    /// Allocates a TREE_DISCONNECT PDU skeleton.
    #[must_use]
    pub fn new_tree_disconnect() -> Self {
        Self {
            command: SMB2_TREE_DISCONNECT,
            tree_id: 0,
            out: Vec::new(),
            request: None,
            reply: None,
        }
    }

    /// Pads the encoded output to an 8-byte boundary.
    pub fn pad_to_64bit(&mut self) {
        let total_len = self.out.iter().map(Vec::len).sum::<usize>();
        let padding = (8 - (total_len % 8)) % 8;
        if padding != 0 {
            self.out.push(vec![0; padding]);
        }
    }
}

/// TREE_DISCONNECT request payload marker.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Smb2TreeDisconnectRequest;

impl Smb2TreeDisconnectRequest {
    /// Creates an empty TREE_DISCONNECT request skeleton.
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

/// TREE_DISCONNECT reply payload marker.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Smb2TreeDisconnectReply;

impl Smb2TreeDisconnectReply {
    /// Creates an empty TREE_DISCONNECT reply skeleton.
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

/// Encodes the fixed TREE_DISCONNECT request buffer.
///
/// # Errors
///
/// Returns [`TreeDisconnectError`] if the fixed buffer cannot be written.
pub fn smb2_encode_tree_disconnect_request() -> TreeDisconnectResult<Vec<u8>> {
    encode_fixed_payload(SMB2_TREE_DISCONNECT_REQUEST_SIZE)
}

/// Builds a TREE_DISCONNECT request PDU skeleton.
///
/// # Errors
///
/// Returns [`TreeDisconnectError`] if request encoding fails.
pub fn smb2_cmd_tree_disconnect_async() -> TreeDisconnectResult<Smb2TreeDisconnectPdu> {
    let mut pdu = Smb2TreeDisconnectPdu::new_tree_disconnect();
    pdu.out.push(smb2_encode_tree_disconnect_request()?);
    pdu.pad_to_64bit();
    Ok(pdu)
}

/// Encodes the fixed TREE_DISCONNECT reply buffer.
///
/// # Errors
///
/// Returns [`TreeDisconnectError`] if the fixed buffer cannot be written.
pub fn smb2_encode_tree_disconnect_reply() -> TreeDisconnectResult<Vec<u8>> {
    encode_fixed_payload(SMB2_TREE_DISCONNECT_REPLY_SIZE)
}

/// Builds a TREE_DISCONNECT reply PDU skeleton.
///
/// # Errors
///
/// Returns [`TreeDisconnectError`] if reply encoding fails.
pub fn smb2_cmd_tree_disconnect_reply_async() -> TreeDisconnectResult<Smb2TreeDisconnectPdu> {
    let mut pdu = Smb2TreeDisconnectPdu::new_tree_disconnect();
    pdu.out.push(smb2_encode_tree_disconnect_reply()?);
    pdu.pad_to_64bit();
    Ok(pdu)
}

/// Processes a fixed TREE_DISCONNECT reply and clears the active tree id.
///
/// # Errors
///
/// Returns [`TreeDisconnectError`] if the fixed reply buffer has an unexpected size.
pub fn smb2_process_tree_disconnect_fixed(
    context: &mut Smb2TreeDisconnectContext,
    pdu: &mut Smb2TreeDisconnectPdu,
    fixed: &[u8],
    header_tree_id: u32,
) -> TreeDisconnectResult<()> {
    validate_fixed_size(fixed, SMB2_TREE_DISCONNECT_REPLY_SIZE)?;
    context.disconnect_tree_id(header_tree_id);
    pdu.reply = Some(Smb2TreeDisconnectReply::new());
    Ok(())
}

/// Processes a fixed TREE_DISCONNECT request payload.
///
/// # Errors
///
/// Returns [`TreeDisconnectError`] if the fixed request buffer has an unexpected size.
pub fn smb2_process_tree_disconnect_request_fixed(
    pdu: &mut Smb2TreeDisconnectPdu,
    fixed: &[u8],
) -> TreeDisconnectResult<()> {
    validate_fixed_size(fixed, SMB2_TREE_DISCONNECT_REQUEST_SIZE)?;
    pdu.request = Some(Smb2TreeDisconnectRequest::new());
    Ok(())
}

fn encode_fixed_payload(structure_size: u16) -> TreeDisconnectResult<Vec<u8>> {
    let mut fixed = vec![0; usize::from(structure_size)];
    write_u16(&mut fixed, 0, structure_size)?;
    Ok(fixed)
}

fn validate_fixed_size(buf: &[u8], expected: u16) -> TreeDisconnectResult<()> {
    let wire_size = read_u16(buf, 0)?;
    if wire_size != expected || buf.len() != usize::from(expected) {
        return Err(TreeDisconnectError::InvalidStructureSize {
            expected,
            actual: buf.len(),
        });
    }
    Ok(())
}

fn read_u16(buf: &[u8], offset: usize) -> TreeDisconnectResult<u16> {
    let end = offset + 2;
    let bytes = buf
        .get(offset..end)
        .ok_or(TreeDisconnectError::BufferTooShort {
            needed: end,
            actual: buf.len(),
        })?;
    Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
}

fn write_u16(buf: &mut [u8], offset: usize, value: u16) -> TreeDisconnectResult<()> {
    let end = offset + 2;
    let actual = buf.len();
    let dst = buf
        .get_mut(offset..end)
        .ok_or(TreeDisconnectError::BufferTooShort {
            needed: end,
            actual,
        })?;
    dst.copy_from_slice(&value.to_le_bytes());
    Ok(())
}
