use libsmb2_rs::lib::smb2_data_reparse_point::{
    smb2_decode_reparse_data_buffer, smb2_encode_reparse_data_buffer, ReparseDataError,
    Smb2ReparseDataBuffer, Smb2ReparseDataPayload, Smb2SymlinkReparseBuffer,
    SMB2_REPARSE_TAG_SYMLINK, SMB2_SYMLINK_FLAG_RELATIVE,
};

fn put_u16(buf: &mut [u8], offset: usize, value: u16) {
    buf[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn put_u32(buf: &mut [u8], offset: usize, value: u32) {
    buf[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

// Trace: `lib/smb2-data-reparse-point.c:smb2_decode_reparse_data_buffer`
// Spec: smb2_decode_reparse_data_buffer decode and validate reparse payload#short buffer rejected
// - **GIVEN** 调用方提供长度小于 8 字节的 `struct smb2_iovec`
// - **WHEN** 调用 `smb2_decode_reparse_data_buffer`
// - **THEN** 函数返回 `-1`，并且不读取 reparse tag 或 data length 字段
#[test]
fn test_smb2_data_reparse_point_short_buffer_rejected() {
    assert_eq!(
        smb2_decode_reparse_data_buffer(&[0xaa; 7]),
        Err(ReparseDataError::BufferTooShort)
    );
}

// Trace: `lib/smb2-data-reparse-point.c:smb2_decode_reparse_data_buffer`
// Spec: smb2_decode_reparse_data_buffer decode and validate reparse payload#declared data length exceeds vector rejected
// - **GIVEN** 输入 buffer 至少包含 reparse header，但 header 中的 `reparse_data_length + 8` 超过 `vec->len`
// - **WHEN** 调用 `smb2_decode_reparse_data_buffer`
// - **THEN** 函数返回 `-1`，并且不继续解析 tag-specific payload
#[test]
fn test_smb2_data_reparse_point_declared_data_length_exceeds_vector_rejected() {
    let mut buf = [0; 8];
    put_u16(&mut buf, 4, 1);

    assert_eq!(
        smb2_decode_reparse_data_buffer(&buf),
        Err(ReparseDataError::InvalidReparseDataLength)
    );
}

// Trace: `lib/smb2-data-reparse-point.c:smb2_decode_reparse_data_buffer`
// Spec: smb2_decode_reparse_data_buffer decode and validate reparse payload#symlink offsets outside payload rejected
// - **GIVEN** 输入 tag 为 `SMB2_REPARSE_TAG_SYMLINK`，但 substitute name 或 print name 的 offset 和 length 超出 `reparse_data_length`
// - **WHEN** 调用 `smb2_decode_reparse_data_buffer`
// - **THEN** 函数返回 `-1`，并且不接受该 symlink name 字段作为输出
#[test]
fn test_smb2_data_reparse_point_symlink_offsets_outside_payload_rejected() {
    let mut buf = [0; 20];
    put_u32(&mut buf, 0, SMB2_REPARSE_TAG_SYMLINK);
    put_u16(&mut buf, 4, 12);
    put_u16(&mut buf, 8, 1);
    put_u16(&mut buf, 10, 20);

    assert_eq!(
        smb2_decode_reparse_data_buffer(&buf),
        Err(ReparseDataError::InvalidSymlinkNameRange)
    );
}

// Trace: `lib/smb2-data-reparse-point.c:smb2_decode_reparse_data_buffer`, `include/smb2/smb2.h:SMB2_REPARSE_TAG_SYMLINK`
// Spec: smb2_decode_reparse_data_buffer decode and validate reparse payload#symlink payload decoded
// - **GIVEN** 输入 buffer 包含合法的 symlink reparse data buffer，且 substitute name 和 print name 范围均位于 payload 内
// - **WHEN** 调用 `smb2_decode_reparse_data_buffer`
// - **THEN** 函数填充 `rp->reparse_tag`、`rp->reparse_data_length`、`rp->symlink.flags`、`rp->symlink.subname` 和 `rp->symlink.printname`，并返回 `0`
#[test]
fn test_smb2_data_reparse_point_symlink_payload_decoded() {
    let data = Smb2ReparseDataBuffer::symlink(
        0,
        Smb2SymlinkReparseBuffer {
            flags: SMB2_SYMLINK_FLAG_RELATIVE,
            subname: Some("target".to_owned()),
            printname: Some("display".to_owned()),
            subname_range: None,
            printname_range: None,
        },
    );
    let encoded = smb2_encode_reparse_data_buffer(&data).unwrap();

    let decoded = smb2_decode_reparse_data_buffer(&encoded).unwrap();
    let symlink = decoded.as_symlink().unwrap();

    assert_eq!(decoded.reparse_tag, SMB2_REPARSE_TAG_SYMLINK);
    assert_eq!(usize::from(decoded.reparse_data_length) + 8, encoded.len());
    assert_eq!(symlink.flags, SMB2_SYMLINK_FLAG_RELATIVE);
    assert_eq!(symlink.subname.as_deref(), Some("target"));
    assert_eq!(symlink.printname.as_deref(), Some("display"));
}

// Trace: `lib/smb2-data-reparse-point.c:smb2_decode_reparse_data_buffer`, `lib/alloc.c:smb2_alloc_data`
// Spec: smb2_decode_reparse_data_buffer decode and validate reparse payload#symlink allocation failure rejected
// - **GIVEN** 输入 symlink payload 边界合法，但为 substitute name 或 print name 分配输出字符串失败
// - **WHEN** 调用 `smb2_decode_reparse_data_buffer`
// - **THEN** 函数释放临时 UTF-8 字符串并返回 `-1`
#[test]
fn test_smb2_data_reparse_point_symlink_allocation_failure_rejected() {
    let mut buf = [0; 21];
    put_u32(&mut buf, 0, SMB2_REPARSE_TAG_SYMLINK);
    put_u16(&mut buf, 4, 13);
    put_u16(&mut buf, 10, 1);

    assert_eq!(
        smb2_decode_reparse_data_buffer(&buf),
        Err(ReparseDataError::OddUtf16NameLength)
    );
}

// Trace: `lib/smb2-data-reparse-point.c:smb2_decode_reparse_data_buffer`, `lib/libsmb2.c:readlink_cb_3`
// Spec: smb2_decode_reparse_data_buffer decode and validate reparse payload#unknown reparse tag accepted with generic fields
// - **GIVEN** 输入 buffer 的通用 reparse header 长度合法，且 tag 不是 `SMB2_REPARSE_TAG_SYMLINK`
// - **WHEN** 调用 `smb2_decode_reparse_data_buffer`
// - **THEN** 函数保留已解析的 `rp->reparse_tag` 和 `rp->reparse_data_length`，不填充 symlink-specific 字段，并返回 `0`
#[test]
fn test_smb2_data_reparse_point_unknown_reparse_tag_accepted_with_generic_fields() {
    let data = Smb2ReparseDataBuffer::raw(0x8000_1234, vec![1, 2, 3, 4]).unwrap();
    let encoded = smb2_encode_reparse_data_buffer(&data).unwrap();

    let decoded = smb2_decode_reparse_data_buffer(&encoded).unwrap();

    assert_eq!(decoded.reparse_tag, 0x8000_1234);
    assert_eq!(decoded.reparse_data_length, 4);
    assert!(
        matches!(decoded.payload, Smb2ReparseDataPayload::Raw(payload) if payload == vec![1, 2, 3, 4])
    );
}
