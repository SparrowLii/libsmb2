use libsmb2_rs::lib::smb2_data_security_descriptor::{
    smb2_decode_security_descriptor, SecurityDescriptorDecodeError, SMB2_ACCESS_ALLOWED_ACE_TYPE,
    SMB2_ACL_REVISION, SMB2_SECURITY_DESCRIPTOR_REVISION,
};

fn put_u16(buf: &mut [u8], offset: usize, value: u16) {
    buf[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn put_u32(buf: &mut [u8], offset: usize, value: u32) {
    buf[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn sid(sub_auth: u32) -> Vec<u8> {
    let mut out = vec![0; 12];
    out[0] = SMB2_SECURITY_DESCRIPTOR_REVISION;
    out[1] = 1;
    out[7] = 5;
    put_u32(&mut out, 8, sub_auth);
    out
}

fn dacl() -> Vec<u8> {
    let sid = sid(32);
    let ace_size = 4 + 4 + sid.len();
    let acl_size = 8 + ace_size;
    let mut out = vec![0; acl_size];
    out[0] = SMB2_ACL_REVISION;
    put_u16(&mut out, 2, acl_size as u16);
    put_u16(&mut out, 4, 1);
    out[8] = SMB2_ACCESS_ALLOWED_ACE_TYPE;
    put_u16(&mut out, 10, ace_size as u16);
    put_u32(&mut out, 12, 0x001f_01ff);
    out[16..16 + sid.len()].copy_from_slice(&sid);
    out
}

fn descriptor_with_offsets(
    owner: Option<Vec<u8>>,
    group: Option<Vec<u8>>,
    dacl: Option<Vec<u8>>,
) -> Vec<u8> {
    let mut out = vec![0; 20];
    out[0] = SMB2_SECURITY_DESCRIPTOR_REVISION;
    put_u16(&mut out, 2, 0x8004);
    if let Some(owner) = owner {
        let offset = out.len() as u32;
        put_u32(&mut out, 4, offset);
        out.extend_from_slice(&owner);
    }
    if let Some(group) = group {
        let offset = out.len() as u32;
        put_u32(&mut out, 8, offset);
        out.extend_from_slice(&group);
    }
    if let Some(dacl) = dacl {
        let offset = out.len() as u32;
        put_u32(&mut out, 16, offset);
        out.extend_from_slice(&dacl);
    }
    out
}

// Trace: `lib/smb2-data-security-descriptor.c:smb2_decode_security_descriptor`, `lib/smb2-cmd-query-info.c:smb2_process_query_info_variable`
// Spec: smb2_decode_security_descriptor decodes security descriptor header and referenced owner, group, and DACL#成功解码 revision 和有效偏移
// - **GIVEN** 调用方提供 `vec->len >= 20`、revision 字节为 `1`，并且 owner、group 或 DACL 偏移非零且满足当前实现的最小长度检查
// - **WHEN** 调用 `smb2_decode_security_descriptor(smb2, memctx, sd, vec)`
// - **THEN** 函数返回 `0`，写入 `sd->revision` 和 `sd->control`，并对有效 owner/group SID 与 DACL 分别分配和填充对应输出结构
#[test]
fn test_smb2_data_security_descriptor_successfully_decodes_revision_and_valid_offsets() {
    let input = descriptor_with_offsets(Some(sid(32)), Some(sid(18)), Some(dacl()));

    let decoded = smb2_decode_security_descriptor(&input).unwrap();

    assert_eq!(decoded.revision, SMB2_SECURITY_DESCRIPTOR_REVISION);
    assert_eq!(decoded.control, 0x8004);
    assert_eq!(decoded.owner.unwrap().sub_auth, vec![32]);
    assert_eq!(decoded.group.unwrap().sub_auth, vec![18]);
    assert_eq!(decoded.dacl.unwrap().aces.len(), 1);
}

// Trace: `lib/smb2-data-security-descriptor.c:smb2_decode_security_descriptor`
// Spec: smb2_decode_security_descriptor decodes security descriptor header and referenced owner, group, and DACL#缓冲区短于 security descriptor header
// - **GIVEN** 调用方提供 `vec->len < 20` 的 security descriptor 输入
// - **WHEN** 调用 `smb2_decode_security_descriptor(smb2, memctx, sd, vec)`
// - **THEN** 函数返回 `-1`，且不会读取 header 字段之外的数据
#[test]
fn test_smb2_data_security_descriptor_buffer_shorter_than_security_descriptor_header() {
    assert_eq!(
        smb2_decode_security_descriptor(&[0; 19]),
        Err(SecurityDescriptorDecodeError::BufferTooShort {
            needed: 20,
            actual: 19
        })
    );
}

// Trace: `lib/smb2-data-security-descriptor.c:smb2_decode_security_descriptor`
// Spec: smb2_decode_security_descriptor decodes security descriptor header and referenced owner, group, and DACL#拒绝不支持的 security descriptor revision
// - **GIVEN** 调用方提供至少 20 字节输入，且 security descriptor revision 不是 `1`
// - **WHEN** 调用 `smb2_decode_security_descriptor(smb2, memctx, sd, vec)`
// - **THEN** 函数 MUST 返回 `-1`，并通过 `smb2_set_error` 记录包含 revision 值的解码错误
#[test]
fn test_smb2_data_security_descriptor_rejects_unsupported_security_descriptor_revision() {
    let mut input = [0; 20];
    input[0] = 2;

    assert_eq!(
        smb2_decode_security_descriptor(&input),
        Err(SecurityDescriptorDecodeError::UnsupportedRevision {
            structure: "security descriptor",
            revision: 2
        })
    );
}

// Trace: `lib/smb2-data-security-descriptor.c:smb2_decode_security_descriptor`, `lib/smb2-data-security-descriptor.c:decode_sid`
// Spec: smb2_decode_security_descriptor decodes security descriptor header and referenced owner, group, and DACL#解码 SID 时校验 revision 和 sub-authority 边界
// - **GIVEN** owner 或 group 偏移指向 SID 数据，且该 SID 长度、revision 或 sub-authority 数量不满足源码检查
// - **WHEN** `smb2_decode_security_descriptor` 尝试解码该 SID
// - **THEN** 函数 MUST 返回 `-1`，并通过错误字符串标识 owner 或 group SID 解码失败原因
#[test]
fn test_smb2_data_security_descriptor_validates_sid_revision_and_sub_authority_bounds() {
    let mut bad_sid = sid(32);
    bad_sid[0] = 2;
    let input = descriptor_with_offsets(Some(bad_sid), None, None);

    assert_eq!(
        smb2_decode_security_descriptor(&input),
        Err(SecurityDescriptorDecodeError::UnsupportedRevision {
            structure: "sid",
            revision: 2
        })
    );
}

// Trace: `lib/smb2-data-security-descriptor.c:smb2_decode_security_descriptor`, `lib/smb2-data-security-descriptor.c:decode_acl`, `lib/smb2-data-security-descriptor.c:decode_ace`
// Spec: smb2_decode_security_descriptor decodes security descriptor header and referenced owner, group, and DACL#解码 DACL 时校验 ACL revision 和 ACE 边界
// - **GIVEN** DACL 偏移非零且 ACL header 可读，但 ACL revision、ACL size、ACE header、ACE size 或 ACE body 不满足源码检查
// - **WHEN** `smb2_decode_security_descriptor` 尝试解码 DACL
// - **THEN** 函数 MUST 返回 `-1`，并通过错误字符串标识 DACL、ACL 或 ACE 解码失败原因
#[test]
fn test_smb2_data_security_descriptor_validates_dacl_acl_revision_and_ace_bounds() {
    let mut bad_dacl = dacl();
    bad_dacl[0] = 3;
    let input = descriptor_with_offsets(None, None, Some(bad_dacl));

    assert_eq!(
        smb2_decode_security_descriptor(&input),
        Err(SecurityDescriptorDecodeError::UnsupportedRevision {
            structure: "acl",
            revision: 3
        })
    );
}
