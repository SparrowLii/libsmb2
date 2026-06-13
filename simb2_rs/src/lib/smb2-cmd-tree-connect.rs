//! TREE_CONNECT command pack/unpack skeleton migrated from `lib/smb2-cmd-tree-connect.c`.

/// SMB2 command number used by TREE_CONNECT PDUs.
pub const SMB2_TREE_CONNECT: u16 = 0x0003;

/// Fixed TREE_CONNECT request structure size from the SMB2 wire format.
pub const SMB2_TREE_CONNECT_REQUEST_SIZE: u16 = 9;

/// Fixed TREE_CONNECT reply structure size from the SMB2 wire format.
pub const SMB2_TREE_CONNECT_REPLY_SIZE: u16 = 16;

/// SMB2 header size used when calculating the request path offset.
pub const SMB2_HEADER_SIZE: u16 = 64;

/// Share flag that asks clients to encrypt traffic for this tree.
pub const SMB2_SHAREFLAG_ENCRYPT_DATA: u32 = 0x0000_8000;
/// Maximum active tree-id nesting tracked by the skeleton context.
pub const SMB2_MAX_TREE_NESTING: usize = 32;

const GENERATED_TREE_ID_START: u32 = 0xfeed_face;

/// Result type used by the TREE_CONNECT migration skeleton.
pub type TreeConnectResult<T> = Result<T, TreeConnectError>;

/// Errors returned by the TREE_CONNECT pack/unpack skeleton.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TreeConnectError {
    /// A fixed-size buffer did not match the expected SMB2 structure size.
    InvalidStructureSize { expected: u16, actual: usize },
    /// The request or reply buffer is too short for the requested field.
    BufferTooShort { needed: usize, actual: usize },
    /// The variable request path length does not fit in the SMB2 length field.
    PathTooLong { length: usize },
    /// The active tree-id stack reached the legacy nesting limit.
    TreeNestingTooDeep,
}

/// Minimal context state touched by TREE_CONNECT handling in the C source.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Smb2TreeConnectContext {
    tree_ids: Vec<u32>,
    seal: bool,
    next_generated_tree_id: u32,
}

impl Default for Smb2TreeConnectContext {
    fn default() -> Self {
        Self {
            tree_ids: Vec::new(),
            seal: false,
            next_generated_tree_id: GENERATED_TREE_ID_START,
        }
    }
}

impl Smb2TreeConnectContext {
    /// Creates an empty TREE_CONNECT context skeleton.
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns the current connected tree id.
    pub fn tree_id(&self) -> u32 {
        match self.tree_ids.first().copied() {
            Some(tree_id) => tree_id,
            None => 0,
        }
    }

    /// Returns the active tree-id stack, newest/current tree first.
    pub fn tree_ids(&self) -> &[u32] {
        &self.tree_ids
    }

    /// Returns whether sealing is enabled for the tree.
    pub fn seal(&self) -> bool {
        self.seal
    }

    /// Records the active tree id like `smb2_connect_tree_id` in the C code.
    pub fn connect_tree_id(&mut self, tree_id: u32) -> TreeConnectResult<()> {
        if self.tree_ids.len() >= SMB2_MAX_TREE_NESTING {
            return Err(TreeConnectError::TreeNestingTooDeep);
        }
        self.tree_ids.insert(0, tree_id);
        Ok(())
    }

    /// Enables or keeps sealing according to the TREE_CONNECT reply flags.
    pub fn apply_reply_flags(&mut self, share_flags: u32) {
        if !self.seal {
            self.seal = (share_flags & SMB2_SHAREFLAG_ENCRYPT_DATA) != 0;
        }
    }

    fn next_tree_id(&mut self) -> u32 {
        let tree_id = self.next_generated_tree_id;
        self.next_generated_tree_id = self.next_generated_tree_id.wrapping_add(1);
        tree_id
    }
}

/// Minimal PDU shape needed by the TREE_CONNECT skeleton methods.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Smb2TreeConnectPdu {
    /// SMB2 command carried by this PDU.
    pub command: u16,
    /// Tree id written into the PDU header for replies.
    pub tree_id: u32,
    /// Encoded output vectors mirroring the C `pdu->out` list.
    pub out: Vec<Vec<u8>>,
    /// Decoded request payload, when processing an incoming request.
    pub request: Option<Smb2TreeConnectRequest>,
    /// Decoded reply payload, when processing an incoming reply.
    pub reply: Option<Smb2TreeConnectReply>,
}

impl Smb2TreeConnectPdu {
    /// Allocates a TREE_CONNECT PDU skeleton.
    pub fn new_tree_connect() -> Self {
        Self {
            command: SMB2_TREE_CONNECT,
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

/// TREE_CONNECT request fields and variable path bytes.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Smb2TreeConnectRequest {
    /// Request flags at fixed offset 2.
    pub flags: u16,
    /// Path offset from the start of the SMB2 header.
    pub path_offset: u16,
    /// Path byte length.
    pub path_length: u16,
    /// Raw UTF-16LE path bytes from the variable portion.
    pub path: Vec<u8>,
}

impl Smb2TreeConnectRequest {
    /// Creates a request skeleton from flags and raw path bytes.
    pub fn new(flags: u16, path: Vec<u8>) -> TreeConnectResult<Self> {
        let path_length = u16::try_from(path.len())
            .map_err(|_| TreeConnectError::PathTooLong { length: path.len() })?;
        Ok(Self {
            flags,
            path_offset: SMB2_HEADER_SIZE + fixed_request_len(),
            path_length,
            path,
        })
    }
}

/// TREE_CONNECT reply fields decoded from or encoded into the fixed payload.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Smb2TreeConnectReply {
    /// Share type byte at fixed offset 2.
    pub share_type: u8,
    /// Share flags at fixed offset 4.
    pub share_flags: u32,
    /// Share capabilities at fixed offset 8.
    pub capabilities: u32,
    /// Maximal access mask at fixed offset 12.
    pub maximal_access: u32,
}

impl Smb2TreeConnectReply {
    /// Creates a reply skeleton from fixed TREE_CONNECT reply fields.
    pub fn new(share_type: u8, share_flags: u32, capabilities: u32, maximal_access: u32) -> Self {
        Self {
            share_type,
            share_flags,
            capabilities,
            maximal_access,
        }
    }
}

/// Encodes the TREE_CONNECT request fixed and variable buffers.
pub fn smb2_encode_tree_connect_request(
    req: &Smb2TreeConnectRequest,
) -> TreeConnectResult<Vec<Vec<u8>>> {
    let mut fixed = vec![0; usize::from(fixed_request_len())];
    write_u16(&mut fixed, 0, SMB2_TREE_CONNECT_REQUEST_SIZE)?;
    write_u16(&mut fixed, 2, req.flags)?;
    write_u16(&mut fixed, 4, SMB2_HEADER_SIZE + fixed_request_len())?;
    write_u16(&mut fixed, 6, req.path_length)?;

    Ok(vec![fixed, req.path.clone()])
}

/// Builds a TREE_CONNECT request PDU skeleton.
pub fn smb2_cmd_tree_connect_async(
    req: &Smb2TreeConnectRequest,
) -> TreeConnectResult<Smb2TreeConnectPdu> {
    let mut pdu = Smb2TreeConnectPdu::new_tree_connect();
    pdu.out = smb2_encode_tree_connect_request(req)?;
    pdu.pad_to_64bit();
    Ok(pdu)
}

/// Encodes the TREE_CONNECT reply fixed buffer.
pub fn smb2_encode_tree_connect_reply(rep: &Smb2TreeConnectReply) -> TreeConnectResult<Vec<u8>> {
    let mut fixed = vec![0; usize::from(SMB2_TREE_CONNECT_REPLY_SIZE)];
    write_u16(&mut fixed, 0, SMB2_TREE_CONNECT_REPLY_SIZE)?;
    write_u8(&mut fixed, 2, rep.share_type)?;
    write_u8(&mut fixed, 3, 0)?;
    write_u32(&mut fixed, 4, rep.share_flags)?;
    write_u32(&mut fixed, 8, rep.capabilities)?;
    write_u32(&mut fixed, 12, rep.maximal_access)?;
    Ok(fixed)
}

/// Builds a TREE_CONNECT reply PDU skeleton and records the tree id in context.
pub fn smb2_cmd_tree_connect_reply_async(
    context: &mut Smb2TreeConnectContext,
    rep: &Smb2TreeConnectReply,
    tree_id: u32,
) -> TreeConnectResult<Smb2TreeConnectPdu> {
    let mut pdu = Smb2TreeConnectPdu::new_tree_connect();
    let connected_tree_id = if tree_id == 0 {
        context.next_tree_id()
    } else {
        tree_id
    };
    context.connect_tree_id(connected_tree_id)?;
    pdu.tree_id = context.tree_id();
    pdu.out.push(smb2_encode_tree_connect_reply(rep)?);
    pdu.pad_to_64bit();
    Ok(pdu)
}

/// Decodes the fixed TREE_CONNECT reply payload and updates context state.
pub fn smb2_process_tree_connect_fixed(
    context: &mut Smb2TreeConnectContext,
    pdu: &mut Smb2TreeConnectPdu,
    fixed: &[u8],
    header_tree_id: u32,
) -> TreeConnectResult<()> {
    validate_fixed_size(fixed, SMB2_TREE_CONNECT_REPLY_SIZE)?;
    let rep = Smb2TreeConnectReply {
        share_type: read_u8(fixed, 2)?,
        share_flags: read_u32(fixed, 4)?,
        capabilities: read_u32(fixed, 8)?,
        maximal_access: read_u32(fixed, 12)?,
    };
    context.connect_tree_id(header_tree_id)?;
    context.apply_reply_flags(rep.share_flags);
    pdu.reply = Some(rep);
    Ok(())
}

/// Decodes the fixed TREE_CONNECT request payload and returns the variable path length.
pub fn smb2_process_tree_connect_request_fixed(
    pdu: &mut Smb2TreeConnectPdu,
    fixed: &[u8],
) -> TreeConnectResult<usize> {
    validate_fixed_size(fixed, SMB2_TREE_CONNECT_REQUEST_SIZE)?;
    let req = Smb2TreeConnectRequest {
        flags: read_u16(fixed, 2)?,
        path_offset: read_u16(fixed, 4)?,
        path_length: read_u16(fixed, 6)?,
        path: Vec::new(),
    };
    let path_length = usize::from(req.path_length);
    pdu.request = Some(req);
    Ok(path_length)
}

/// Attaches the TREE_CONNECT request variable path bytes to the decoded request.
pub fn smb2_process_tree_connect_request_variable(
    pdu: &mut Smb2TreeConnectPdu,
    variable: &[u8],
) -> TreeConnectResult<()> {
    if let Some(req) = pdu.request.as_mut() {
        let needed = usize::from(req.path_length);
        if variable.len() < needed {
            return Err(TreeConnectError::BufferTooShort {
                needed,
                actual: variable.len(),
            });
        }
        req.path = variable[..needed].to_vec();
    }
    Ok(())
}

fn fixed_request_len() -> u16 {
    SMB2_TREE_CONNECT_REQUEST_SIZE & 0xfffe
}

fn validate_fixed_size(buf: &[u8], expected: u16) -> TreeConnectResult<()> {
    let wire_size = read_u16(buf, 0)?;
    let expected_len = usize::from(expected & 0xfffe);
    if wire_size != expected || buf.len() != expected_len {
        return Err(TreeConnectError::InvalidStructureSize {
            expected,
            actual: buf.len(),
        });
    }
    Ok(())
}

fn read_u8(buf: &[u8], offset: usize) -> TreeConnectResult<u8> {
    buf.get(offset)
        .copied()
        .ok_or(TreeConnectError::BufferTooShort {
            needed: offset + 1,
            actual: buf.len(),
        })
}

fn read_u16(buf: &[u8], offset: usize) -> TreeConnectResult<u16> {
    let end = offset + 2;
    let bytes = buf
        .get(offset..end)
        .ok_or(TreeConnectError::BufferTooShort {
            needed: end,
            actual: buf.len(),
        })?;
    Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
}

fn read_u32(buf: &[u8], offset: usize) -> TreeConnectResult<u32> {
    let end = offset + 4;
    let bytes = buf
        .get(offset..end)
        .ok_or(TreeConnectError::BufferTooShort {
            needed: end,
            actual: buf.len(),
        })?;
    Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn write_u8(buf: &mut [u8], offset: usize, value: u8) -> TreeConnectResult<()> {
    let actual = buf.len();
    let slot = buf
        .get_mut(offset)
        .ok_or(TreeConnectError::BufferTooShort {
            needed: offset + 1,
            actual,
        })?;
    *slot = value;
    Ok(())
}

fn write_u16(buf: &mut [u8], offset: usize, value: u16) -> TreeConnectResult<()> {
    let end = offset + 2;
    let actual = buf.len();
    let dst = buf
        .get_mut(offset..end)
        .ok_or(TreeConnectError::BufferTooShort {
            needed: end,
            actual,
        })?;
    dst.copy_from_slice(&value.to_le_bytes());
    Ok(())
}

fn write_u32(buf: &mut [u8], offset: usize, value: u32) -> TreeConnectResult<()> {
    let end = offset + 4;
    let actual = buf.len();
    let dst = buf
        .get_mut(offset..end)
        .ok_or(TreeConnectError::BufferTooShort {
            needed: end,
            actual,
        })?;
    dst.copy_from_slice(&value.to_le_bytes());
    Ok(())
}
