//! WRITE command pack/unpack skeleton migrated from `lib/smb2-cmd-write.c`.

const SMB2_HEADER_SIZE: usize = 64;
const SMB2_MULTI_CREDIT_MAX_WRITE: u32 = 64 * 1024;

/// Size of the SMB2 WRITE request structure, including the SMB2 structure-size field.
pub const SMB2_WRITE_REQUEST_SIZE: u16 = 49;

/// Size of the SMB2 WRITE reply structure, including the SMB2 structure-size field.
pub const SMB2_WRITE_REPLY_SIZE: u16 = 17;

/// Size of an SMB2 file identifier carried by WRITE requests.
pub const SMB2_FD_SIZE: usize = 16;

/// Errors returned by the WRITE command migration skeleton.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Smb2WriteError {
    /// A fixed or variable input buffer is shorter than the C decoder expects.
    BufferTooSmall,
    /// The structure-size field does not match the expected SMB2 WRITE shape.
    InvalidStructureSize { expected: u16, actual: u16 },
    /// The write-channel-info range overlaps the fixed WRITE request area.
    ChannelInfoOverlapsRequest,
    /// A declared payload length cannot fit in the Rust target type.
    LengthOverflow,
}

/// Result type used by the WRITE command skeleton.
pub type Smb2WriteResult<T> = Result<T, Smb2WriteError>;

/// Options that mirror the context flags consumed by `smb2_encode_write_request`.
#[derive(Debug, Copy, Clone, Default, PartialEq, Eq)]
pub struct WriteEncodeOptions {
    /// Whether the peer supports multi-credit writes larger than 64 KiB.
    pub supports_multi_credit: bool,
    /// Compatibility flag retained while raw channel-info is preserved either way.
    pub passthrough: bool,
}

/// Ownership policy corresponding to the C `pass_buf_ownership` flag.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Default)]
pub enum WriteBufferOwnership {
    /// The caller retains ownership of the write buffer.
    #[default]
    Borrowed,
    /// Ownership is transferred to the command PDU.
    Transferred,
}

/// Rust-side representation of `struct smb2_write_request` for skeleton migration work.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Smb2WriteRequest<'a> {
    /// Offset from the SMB2 header to the write data buffer.
    pub data_offset: u16,
    /// Number of bytes requested for the WRITE payload.
    pub length: u32,
    /// File offset where the write starts.
    pub offset: u64,
    /// Opaque SMB2 file identifier.
    pub file_id: [u8; SMB2_FD_SIZE],
    /// WRITE channel value from the fixed request body.
    pub channel: u32,
    /// Remaining bytes value advertised by the caller.
    pub remaining_bytes: u32,
    /// Offset of optional write-channel information from the SMB2 header.
    pub write_channel_info_offset: u16,
    /// Length of optional write-channel information.
    pub write_channel_info_length: u16,
    /// Optional write-channel information slice.
    pub write_channel_info: Option<&'a [u8]>,
    /// WRITE flags from the fixed request body.
    pub flags: u32,
    /// Application write payload.
    pub buffer: &'a [u8],
}

impl<'a> Smb2WriteRequest<'a> {
    /// Creates a minimal WRITE request skeleton for `file_id`, `offset`, and `buffer`.
    #[must_use]
    pub fn new(file_id: [u8; SMB2_FD_SIZE], offset: u64, buffer: &'a [u8]) -> Self {
        let length = u32::try_from(buffer.len()).map_or(u32::MAX, |len| len);

        Self {
            data_offset: (SMB2_HEADER_SIZE + fixed_write_request_len()) as u16,
            length,
            offset,
            file_id,
            channel: 0,
            remaining_bytes: 0,
            write_channel_info_offset: 0,
            write_channel_info_length: 0,
            write_channel_info: None,
            flags: 0,
            buffer,
        }
    }

    /// Returns the C encoder's effective WRITE length after multi-credit clamping.
    #[must_use]
    pub fn effective_length(&self, supports_multi_credit: bool) -> u32 {
        if supports_multi_credit {
            self.length
        } else {
            self.length.min(SMB2_MULTI_CREDIT_MAX_WRITE)
        }
    }

    /// Returns the offset used by the C `IOVREQ_OFFSET_WRITE` macro.
    #[must_use]
    pub fn write_channel_iov_offset(&self) -> usize {
        if self.write_channel_info_length == 0 {
            return 0;
        }

        usize::from(self.write_channel_info_offset)
            .saturating_sub(SMB2_HEADER_SIZE + fixed_write_request_len())
    }

    /// Returns the number of variable bytes requested by the fixed request decoder.
    ///
    /// # Errors
    ///
    /// Returns [`Smb2WriteError::LengthOverflow`] if a declared field cannot fit in `usize`.
    pub fn expected_variable_len(&self) -> Smb2WriteResult<usize> {
        let write_len = usize::try_from(self.length).map_err(|_| Smb2WriteError::LengthOverflow)?;
        let channel_info_len = usize::from(self.write_channel_info_length);
        let channel_offset = self.write_channel_iov_offset();

        if write_len > 0 {
            Ok(channel_offset + pad_to_64bit(channel_info_len) + write_len)
        } else if channel_info_len > 0 {
            Ok(channel_offset + channel_info_len)
        } else {
            Ok(0)
        }
    }
}

/// Rust-side representation of `struct smb2_write_reply`.
#[derive(Debug, Copy, Clone, Default, PartialEq, Eq)]
pub struct Smb2WriteReply {
    /// Number of bytes written by the peer.
    pub count: u32,
    /// Remaining bytes reported by the peer.
    pub remaining: u32,
}

/// Variable payload slices associated with a decoded WRITE request.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct Smb2WriteRequestVariable<'a> {
    /// Optional write-channel information bytes.
    pub write_channel_info: &'a [u8],
    /// WRITE data bytes.
    pub buffer: &'a [u8],
}

/// Minimal PDU skeleton produced by `smb2_cmd_write_async` responsibilities.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Smb2WritePdu<'a> {
    /// Request captured by the skeleton PDU.
    pub request: Smb2WriteRequest<'a>,
    /// Buffer ownership policy requested by the caller.
    pub buffer_ownership: WriteBufferOwnership,
    /// Credit charge calculated for large multi-credit writes.
    pub credit_charge: u16,
    /// Encoded output vectors: fixed body, optional channel info, and write data.
    pub out: Vec<Vec<u8>>,
}

/// Encodes the fixed WRITE request fields into a standalone byte buffer.
pub fn encode_write_request_fixed(
    options: WriteEncodeOptions,
    request: &Smb2WriteRequest<'_>,
) -> Smb2WriteResult<Vec<u8>> {
    let mut out = vec![0; fixed_write_request_len()];
    let effective_length = request.effective_length(options.supports_multi_credit);

    put_u16(&mut out, 0, SMB2_WRITE_REQUEST_SIZE);
    put_u16(
        &mut out,
        2,
        (SMB2_HEADER_SIZE + fixed_write_request_len()) as u16,
    );
    put_u32(&mut out, 4, effective_length);
    put_u64(&mut out, 8, request.offset);
    out[16..32].copy_from_slice(&request.file_id);
    put_u32(&mut out, 32, request.channel);
    put_u32(&mut out, 36, request.remaining_bytes);

    if request.write_channel_info_length > 0 && request.write_channel_info.is_some() {
        put_u16(
            &mut out,
            40,
            (SMB2_HEADER_SIZE + fixed_write_request_len()) as u16,
        );
    } else {
        put_u16(&mut out, 40, request.write_channel_info_offset);
    }

    put_u16(&mut out, 42, request.write_channel_info_length);
    put_u32(&mut out, 44, request.flags);

    Ok(out)
}

/// Encodes WRITE request fixed and variable vectors in the same order as C `pdu->out`.
pub fn encode_write_request_vectors(
    options: WriteEncodeOptions,
    request: &Smb2WriteRequest<'_>,
) -> Smb2WriteResult<Vec<Vec<u8>>> {
    let mut fixed = encode_write_request_fixed(options, request)?;
    let mut vectors = Vec::new();

    if request.write_channel_info_length > 0 {
        let Some(info) = request.write_channel_info else {
            let data_len = request.effective_length(options.supports_multi_credit) as usize;
            if request.buffer.len() < data_len {
                return Err(Smb2WriteError::BufferTooSmall);
            }
            vectors.push(fixed);
            vectors.push(request.buffer[..data_len].to_vec());
            return Ok(vectors);
        };
        if info.len() < usize::from(request.write_channel_info_length) {
            return Err(Smb2WriteError::BufferTooSmall);
        }
        put_u16(
            &mut fixed,
            40,
            (SMB2_HEADER_SIZE + fixed_write_request_len()) as u16,
        );
        vectors.push(fixed);
        vectors.push(padded_copy(
            info,
            pad_to_64bit(usize::from(request.write_channel_info_length)),
        ));
    } else {
        vectors.push(fixed);
    }

    let data_len = request.effective_length(options.supports_multi_credit) as usize;
    if request.buffer.len() < data_len {
        return Err(Smb2WriteError::BufferTooSmall);
    }
    vectors.push(request.buffer[..data_len].to_vec());
    Ok(vectors)
}

/// Creates a WRITE PDU skeleton from the C `smb2_cmd_write_async` responsibilities.
pub fn smb2_cmd_write_async<'a>(
    options: WriteEncodeOptions,
    mut request: Smb2WriteRequest<'a>,
    buffer_ownership: WriteBufferOwnership,
) -> Smb2WriteResult<Smb2WritePdu<'a>> {
    request.length = request.effective_length(options.supports_multi_credit);
    let credit_charge = if options.supports_multi_credit {
        ((request.length.saturating_sub(1)) / 65_536 + 1) as u16
    } else {
        1
    };

    let out = encode_write_request_vectors(options, &request)?;
    Ok(Smb2WritePdu {
        request,
        buffer_ownership,
        credit_charge,
        out,
    })
}

/// Encodes the fixed WRITE reply fields into a standalone byte buffer.
#[must_use]
pub fn encode_write_reply_fixed(reply: Smb2WriteReply) -> Vec<u8> {
    let mut out = vec![0; fixed_write_reply_len()];
    put_u16(&mut out, 0, SMB2_WRITE_REPLY_SIZE);
    put_u32(&mut out, 4, reply.count);
    put_u32(&mut out, 8, reply.remaining);
    out
}

fn padded_copy(bytes: &[u8], padded_len: usize) -> Vec<u8> {
    let mut out = vec![0; padded_len];
    let copy_len = bytes.len().min(out.len());
    out[..copy_len].copy_from_slice(&bytes[..copy_len]);
    out
}

/// Creates a WRITE reply PDU skeleton from `smb2_cmd_write_reply_async` responsibilities.
#[must_use]
pub fn smb2_cmd_write_reply_async(reply: Smb2WriteReply) -> Smb2WriteReply {
    reply
}

/// Parses the fixed WRITE reply body handled by `smb2_process_write_fixed`.
///
/// # Errors
///
/// Returns an error when `fixed` is too small or its structure-size field is invalid.
pub fn smb2_process_write_fixed(fixed: &[u8]) -> Smb2WriteResult<Smb2WriteReply> {
    if fixed.len() < fixed_write_reply_len() {
        return Err(Smb2WriteError::BufferTooSmall);
    }

    let struct_size = get_u16(fixed, 0)?;
    if struct_size != SMB2_WRITE_REPLY_SIZE || usize::from(struct_size & 0xfffe) != fixed.len() {
        return Err(Smb2WriteError::InvalidStructureSize {
            expected: SMB2_WRITE_REPLY_SIZE,
            actual: struct_size,
        });
    }

    Ok(Smb2WriteReply {
        count: get_u32(fixed, 4)?,
        remaining: get_u32(fixed, 8)?,
    })
}

/// Parses the fixed WRITE request body handled by `smb2_process_write_request_fixed`.
///
/// # Errors
///
/// Returns an error when `fixed` is too small, has an invalid structure size, or describes
/// channel-info bytes that overlap the fixed request area.
pub fn smb2_process_write_request_fixed<'a>(
    fixed: &'a [u8],
) -> Smb2WriteResult<Smb2WriteRequest<'a>> {
    if fixed.len() < fixed_write_request_len() {
        return Err(Smb2WriteError::BufferTooSmall);
    }

    let struct_size = get_u16(fixed, 0)?;
    if struct_size != SMB2_WRITE_REQUEST_SIZE || usize::from(struct_size & 0xfffe) != fixed.len() {
        return Err(Smb2WriteError::InvalidStructureSize {
            expected: SMB2_WRITE_REQUEST_SIZE,
            actual: struct_size,
        });
    }

    let mut file_id = [0; SMB2_FD_SIZE];
    file_id.copy_from_slice(&fixed[16..32]);

    let write_channel_info_offset = get_u16(fixed, 40)?;
    let write_channel_info_length = get_u16(fixed, 42)?;

    if write_channel_info_length > 0
        && usize::from(write_channel_info_offset) < SMB2_HEADER_SIZE + fixed_write_request_len()
    {
        return Err(Smb2WriteError::ChannelInfoOverlapsRequest);
    }

    Ok(Smb2WriteRequest {
        data_offset: get_u16(fixed, 2)?,
        length: get_u32(fixed, 4)?,
        offset: get_u64(fixed, 8)?,
        file_id,
        channel: get_u32(fixed, 32)?,
        remaining_bytes: get_u32(fixed, 36)?,
        write_channel_info_offset,
        write_channel_info_length,
        write_channel_info: None,
        flags: get_u32(fixed, 44)?,
        buffer: &[],
    })
}

/// Splits the variable WRITE request body handled by `smb2_process_write_request_variable`.
///
/// # Errors
///
/// Returns an error when `variable` cannot satisfy the lengths declared by `request`.
pub fn smb2_process_write_request_variable<'a>(
    request: &Smb2WriteRequest<'_>,
    variable: &'a [u8],
) -> Smb2WriteResult<Smb2WriteRequestVariable<'a>> {
    let channel_offset = request.write_channel_iov_offset();
    let channel_len = usize::from(request.write_channel_info_length);
    let data_offset = channel_offset + pad_to_64bit(channel_len);
    let data_len = usize::try_from(request.length).map_err(|_| Smb2WriteError::LengthOverflow)?;
    let required_len = if data_len > 0 {
        data_offset + data_len
    } else {
        channel_offset + channel_len
    };

    if variable.len() < required_len {
        return Err(Smb2WriteError::BufferTooSmall);
    }

    let write_channel_info = &variable[channel_offset..channel_offset + channel_len];
    let buffer = &variable[data_offset..data_offset + data_len];

    Ok(Smb2WriteRequestVariable {
        write_channel_info,
        buffer,
    })
}

#[must_use]
fn fixed_write_request_len() -> usize {
    usize::from(SMB2_WRITE_REQUEST_SIZE & 0xfffe)
}

#[must_use]
fn fixed_write_reply_len() -> usize {
    usize::from(SMB2_WRITE_REPLY_SIZE & 0xfffe)
}

#[must_use]
fn pad_to_64bit(len: usize) -> usize {
    (len + 7) & !7
}

fn put_u16(out: &mut [u8], offset: usize, value: u16) {
    out[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn put_u32(out: &mut [u8], offset: usize, value: u32) {
    out[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn put_u64(out: &mut [u8], offset: usize, value: u64) {
    out[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn get_u16(input: &[u8], offset: usize) -> Smb2WriteResult<u16> {
    let bytes = input
        .get(offset..offset + 2)
        .ok_or(Smb2WriteError::BufferTooSmall)?;
    Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
}

fn get_u32(input: &[u8], offset: usize) -> Smb2WriteResult<u32> {
    let bytes = input
        .get(offset..offset + 4)
        .ok_or(Smb2WriteError::BufferTooSmall)?;
    Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn get_u64(input: &[u8], offset: usize) -> Smb2WriteResult<u64> {
    let bytes = input
        .get(offset..offset + 8)
        .ok_or(Smb2WriteError::BufferTooSmall)?;
    Ok(u64::from_le_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ]))
}
