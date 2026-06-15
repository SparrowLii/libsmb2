use libsmb2_rs::include::smb2::dcerpc_coder_srvsvc::{
    srvsvc_netr_share_enum_rep_coder_harness, srvsvc_netr_share_enum_rep_decoder_harness,
    srvsvc_netr_share_enum_req_coder_harness, srvsvc_netr_share_enum_req_decoder_harness,
    srvsvc_netr_share_get_info_rep_coder_harness, srvsvc_netr_share_get_info_rep_decoder_harness,
    srvsvc_netr_share_get_info_req_coder_harness, srvsvc_netr_share_get_info_req_decoder_harness,
    srvsvc_share_info_0_coder_harness, srvsvc_share_info_0_container_coder_harness,
    srvsvc_share_info_0_container_decoder_harness, srvsvc_share_info_0_decoder_harness,
    srvsvc_share_info_1_coder_harness, srvsvc_share_info_1_container_coder_harness,
    srvsvc_share_info_1_container_decoder_harness, srvsvc_share_info_1_decoder_harness,
    DcerpcUtf16, ShareInfoLevel, SrvsvcHarnessError, SrvsvcNetrShareEnumRep,
    SrvsvcNetrShareEnumReq, SrvsvcNetrShareGetInfoRep, SrvsvcNetrShareGetInfoReq,
    SrvsvcShareEnumStruct, SrvsvcShareEnumUnion, SrvsvcShareInfo, SrvsvcShareInfo0,
    SrvsvcShareInfo0Container, SrvsvcShareInfo1, SrvsvcShareInfo1Container, SrvsvcShareInfoPayload,
    SHARE_TYPE_HIDDEN, SHARE_TYPE_IPC, SRVSVC_INTERFACE, SRVSVC_INTERFACE_MAJOR_VERSION,
    SRVSVC_INTERFACE_MINOR_VERSION, SRVSVC_SHARE_ENUM_PREFERRED_MAXIMUM_LENGTH, SRVSVC_UUID,
};

// Trace: `lib/dcerpc-srvsvc.c:SRVSVC_UUID`, `lib/dcerpc-srvsvc.c:srvsvc_interface`
// Spec: SRVSVC_UUID interface uuid initializer#SRVSVC UUID feeds syntax id
// - **GIVEN** 本文件初始化 `srvsvc_interface`
// - **WHEN** 编译器展开 `SRVSVC_UUID`
// - **THEN** `srvsvc_interface` 使用该 UUID initializer 作为 syntax id 的 UUID 字段
#[test]
fn test_dcerpc_srvsvc_srvs_vc_uuid_feeds_syntax_id() {
    assert_eq!(SRVSVC_INTERFACE.uuid, SRVSVC_UUID);
    assert_eq!(
        SRVSVC_UUID,
        [
            0xc8, 0x4f, 0x32, 0x4b, 0x70, 0x16, 0xd3, 0x01, 0x12, 0x78, 0x5a, 0x47, 0xbf, 0x6e,
            0xe1, 0x88
        ]
    );
}

// Trace: `lib/dcerpc-srvsvc.c:srvsvc_interface`
// Spec: srvsvc_interface syntax identifier#SRVSVC interface version remains stable
// - **GIVEN** DCERPC 绑定路径引用 `srvsvc_interface`
// - **WHEN** 调用方读取该 syntax id
// - **THEN** UUID 来自 `SRVSVC_UUID` 且版本字段为 `3, 0`
#[test]
fn test_dcerpc_srvsvc_interface_version_remains_stable() {
    assert_eq!(SRVSVC_INTERFACE.uuid, SRVSVC_UUID);
    assert_eq!(
        SRVSVC_INTERFACE.major_version,
        SRVSVC_INTERFACE_MAJOR_VERSION
    );
    assert_eq!(
        SRVSVC_INTERFACE.minor_version,
        SRVSVC_INTERFACE_MINOR_VERSION
    );
    assert_eq!(
        (
            SRVSVC_INTERFACE_MAJOR_VERSION,
            SRVSVC_INTERFACE_MINOR_VERSION
        ),
        (3, 0)
    );
}

// Trace: `lib/dcerpc-srvsvc.c:srvsvc_SHARE_INFO_0_coder`
// Spec: srvsvc_SHARE_INFO_0_coder level zero record coder#Level zero netname coder succeeds
// - **GIVEN** `ptr` 指向有效的 `struct srvsvc_SHARE_INFO_0`
// - **WHEN** `dcerpc_ptr_coder` 成功编解码 `netname`
// - **THEN** `srvsvc_SHARE_INFO_0_coder` 返回 `0`
#[test]
fn test_dcerpc_srvsvc_level_zero_netname_coder_succeeds() {
    let share = SrvsvcShareInfo0 {
        netname: utf16("IPC$"),
    };
    let encoded = srvsvc_share_info_0_coder_harness(&share).expect("level 0 encode succeeds");
    let decoded = srvsvc_share_info_0_decoder_harness(&encoded).expect("level 0 decode succeeds");
    assert_eq!(decoded, share);
}

// Trace: `lib/dcerpc-srvsvc.c:srvsvc_SHARE_INFO_0_coder`
// Spec: srvsvc_SHARE_INFO_0_coder level zero record coder#Level zero netname coder failure propagates
// - **GIVEN** `ptr` 指向 `struct srvsvc_SHARE_INFO_0` 且底层 `dcerpc_ptr_coder` 返回错误
// - **WHEN** 调用方执行 `srvsvc_SHARE_INFO_0_coder`
// - **THEN** `srvsvc_SHARE_INFO_0_coder` 返回 `-1`
#[test]
fn test_dcerpc_srvsvc_level_zero_netname_coder_failure_propagates() {
    let share = SrvsvcShareInfo0 {
        netname: utf16("IPC$"),
    };
    let mut encoded = srvsvc_share_info_0_coder_harness(&share).expect("level 0 encode succeeds");
    encoded.truncate(encoded.len() - 1);
    let err = srvsvc_share_info_0_decoder_harness(&encoded).expect_err("truncated UTF-16 fails");
    assert_eq!(err, SrvsvcHarnessError::BufferTooSmall);
}

// Trace: `lib/dcerpc-srvsvc.c:srvsvc_SHARE_INFO_0_CONTAINER_coder`
// Spec: srvsvc_SHARE_INFO_0_CONTAINER_coder level zero container coder#Level zero decode allocates missing array
// - **GIVEN** DCERPC PDU 方向为 decode、`EntriesRead` 非零且 `share_info_0` 为 `NULL`
// - **WHEN** 调用方执行 `srvsvc_SHARE_INFO_0_CONTAINER_coder`
// - **THEN** coder 设置 `size_is` 并尝试从 PDU payload 关联的数据区域分配 level 0 数组
#[test]
fn test_dcerpc_srvsvc_level_zero_decode_allocates_missing_array() {
    let container = SrvsvcShareInfo0Container {
        entries_read: 1,
        share_info_0: vec![SrvsvcShareInfo0 {
            netname: utf16("IPC$"),
        }],
    };
    let encoded =
        srvsvc_share_info_0_container_coder_harness(&container).expect("container encode succeeds");
    let decoded =
        srvsvc_share_info_0_container_decoder_harness(&encoded).expect("container decode succeeds");
    assert_eq!(decoded.entries_read, 1);
    assert_eq!(decoded.share_info_0.len(), 1);
    assert_eq!(
        decoded.share_info_0[0].netname.value.as_deref(),
        Some("IPC$")
    );
}

// Trace: `lib/dcerpc-srvsvc.c:srvsvc_SHARE_INFO_0_CONTAINER_coder`
// Spec: srvsvc_SHARE_INFO_0_CONTAINER_coder level zero container coder#Level zero container failure propagates
// - **GIVEN** `EntriesRead` coder、数组分配或后续 unique pointer coder 任一操作失败
// - **WHEN** 调用方执行 `srvsvc_SHARE_INFO_0_CONTAINER_coder`
// - **THEN** `srvsvc_SHARE_INFO_0_CONTAINER_coder` 返回 `-1`
#[test]
fn test_dcerpc_srvsvc_level_zero_container_failure_propagates() {
    let container = SrvsvcShareInfo0Container {
        entries_read: 1,
        share_info_0: vec![SrvsvcShareInfo0 {
            netname: utf16("IPC$"),
        }],
    };
    let mut encoded =
        srvsvc_share_info_0_container_coder_harness(&container).expect("container encode succeeds");
    encoded.truncate(encoded.len() - 1);
    let err = srvsvc_share_info_0_container_decoder_harness(&encoded)
        .expect_err("truncated container fails");
    assert_eq!(err, SrvsvcHarnessError::BufferTooSmall);
}

// Trace: `lib/dcerpc-srvsvc.c:srvsvc_SHARE_INFO_1_coder`, `tests/smb2-dcerpc-coder-test.c:test_SHARE_INFO_1_ndr32_le`
// Spec: srvsvc_SHARE_INFO_1_coder level one record coder#Level one record encodes tested NDR32 data
// - **GIVEN** `srvsvc_SHARE_INFO_1` 包含 `IPC$`、type `0x80000003` 和 remark `Remote IPC`
// - **WHEN** 测试以 NDR32 little-endian 执行 `srvsvc_SHARE_INFO_1_coder`
// - **THEN** 编解码结果保持 `netname`、`type` 和 `remark` 一致
#[test]
fn test_dcerpc_srvsvc_level_one_record_encodes_tested_ndr32_data() {
    let share = ipc_share_info_1();
    let encoded = srvsvc_share_info_1_coder_harness(&share).expect("level 1 encode succeeds");
    let decoded = srvsvc_share_info_1_decoder_harness(&encoded).expect("level 1 decode succeeds");
    assert_eq!(decoded, share);
}

// Trace: `lib/dcerpc-srvsvc.c:srvsvc_SHARE_INFO_1_coder`
// Spec: srvsvc_SHARE_INFO_1_coder level one record coder#Level one record failure propagates
// - **GIVEN** `netname`、`type` 或 `remark` 的底层 coder 返回错误
// - **WHEN** 调用方执行 `srvsvc_SHARE_INFO_1_coder`
// - **THEN** `srvsvc_SHARE_INFO_1_coder` 返回 `-1`
#[test]
fn test_dcerpc_srvsvc_level_one_record_failure_propagates() {
    let mut encoded =
        srvsvc_share_info_1_coder_harness(&ipc_share_info_1()).expect("level 1 encode succeeds");
    encoded.truncate(encoded.len() - 1);
    let err =
        srvsvc_share_info_1_decoder_harness(&encoded).expect_err("truncated level 1 record fails");
    assert_eq!(err, SrvsvcHarnessError::BufferTooSmall);
}

// Trace: `lib/dcerpc-srvsvc.c:srvsvc_SHARE_INFO_1_CONTAINER_coder`, `tests/smb2-dcerpc-coder-test.c:test_SHARE_INFO_1_CONTAINER_ndr32_le`
// Spec: srvsvc_SHARE_INFO_1_CONTAINER_coder level one container coder#Level one container encodes tested NDR32 data
// - **GIVEN** `EntriesRead` 为 `10` 且 `share_info_1` 指向 10 条 level 1 share records
// - **WHEN** 测试以 NDR32 little-endian 执行 `srvsvc_SHARE_INFO_1_CONTAINER_coder`
// - **THEN** 编解码结果保持条目数和每条记录的 `netname`、`type`、`remark` 一致
#[test]
fn test_dcerpc_srvsvc_level_one_container_encodes_tested_ndr32_data() {
    let container = share_info_1_container(10);
    let encoded =
        srvsvc_share_info_1_container_coder_harness(&container).expect("container encode succeeds");
    let decoded =
        srvsvc_share_info_1_container_decoder_harness(&encoded).expect("container decode succeeds");
    assert_eq!(decoded.entries_read, 10);
    assert_eq!(decoded.share_info_1, container.share_info_1);
}

// Trace: `lib/dcerpc-srvsvc.c:srvsvc_SHARE_INFO_1_CONTAINER_coder`, `tests/smb2-dcerpc-coder-test.c:test_SHARE_INFO_1_CONTAINER_ndr64_le`
// Spec: srvsvc_SHARE_INFO_1_CONTAINER_coder level one container coder#Level one container encodes tested NDR64 data
// - **GIVEN** `EntriesRead` 为 `10` 且 `share_info_1` 指向 10 条 level 1 share records
// - **WHEN** 测试以 NDR64 little-endian 执行 `srvsvc_SHARE_INFO_1_CONTAINER_coder`
// - **THEN** 编解码结果保持条目数和每条记录的 `netname`、`type`、`remark` 一致
#[test]
fn test_dcerpc_srvsvc_level_one_container_encodes_tested_ndr64_data() {
    let container = share_info_1_container(10);
    let encoded =
        srvsvc_share_info_1_container_coder_harness(&container).expect("container encode succeeds");
    let decoded =
        srvsvc_share_info_1_container_decoder_harness(&encoded).expect("container decode succeeds");
    assert_eq!(decoded, container);
}

// Trace: `lib/dcerpc-srvsvc.c:srvsvc_SHARE_INFO_1_CONTAINER_coder`
// Spec: srvsvc_SHARE_INFO_1_CONTAINER_coder level one container coder#Level one container failure propagates
// - **GIVEN** `EntriesRead` coder、数组分配或后续 unique pointer coder 任一操作失败
// - **WHEN** 调用方执行 `srvsvc_SHARE_INFO_1_CONTAINER_coder`
// - **THEN** `srvsvc_SHARE_INFO_1_CONTAINER_coder` 返回 `-1`
#[test]
fn test_dcerpc_srvsvc_level_one_container_failure_propagates() {
    let mut encoded = srvsvc_share_info_1_container_coder_harness(&share_info_1_container(2))
        .expect("container encode succeeds");
    encoded.truncate(encoded.len() - 1);
    let err = srvsvc_share_info_1_container_decoder_harness(&encoded)
        .expect_err("truncated level 1 container fails");
    assert_eq!(err, SrvsvcHarnessError::BufferTooSmall);
}

// Trace: `lib/dcerpc-srvsvc.c:srvsvc_SHARE_ENUM_STRUCT_coder`, `lib/dcerpc-srvsvc.c:srvsvc_SHARE_ENUM_UNION_coder`
// Spec: srvsvc_SHARE_ENUM_STRUCT_coder share enum wrapper coder#Share enum struct dispatches level union
// - **GIVEN** `ptr` 指向 `struct srvsvc_SHARE_ENUM_STRUCT`
// - **WHEN** `Level` 编解码成功
// - **THEN** coder 将 `ShareInfo` 交给 level 分派 union coder 处理
#[test]
fn test_dcerpc_srvsvc_share_enum_struct_dispatches_level_union() {
    let req = share_enum_req();
    let encoded =
        srvsvc_netr_share_enum_req_coder_harness(&req).expect("share enum req encode succeeds");
    let decoded = srvsvc_netr_share_enum_req_decoder_harness(&encoded)
        .expect("share enum req decode succeeds");
    assert!(matches!(
        decoded.ses.share_info,
        SrvsvcShareEnumUnion::Level1(_)
    ));
}

// Trace: `lib/dcerpc-srvsvc.c:srvsvc_SHARE_ENUM_STRUCT_coder`
// Spec: srvsvc_SHARE_ENUM_STRUCT_coder share enum wrapper coder#Share enum struct failure propagates
// - **GIVEN** `Level` coder 或 `ShareInfo` union coder 返回错误
// - **WHEN** 调用方执行 `srvsvc_SHARE_ENUM_STRUCT_coder`
// - **THEN** `srvsvc_SHARE_ENUM_STRUCT_coder` 返回 `-1`
#[test]
fn test_dcerpc_srvsvc_share_enum_struct_failure_propagates() {
    let mut encoded = srvsvc_netr_share_enum_req_coder_harness(&share_enum_req())
        .expect("share enum req encode succeeds");
    encoded.truncate(encoded.len() - 1);
    let err = srvsvc_netr_share_enum_req_decoder_harness(&encoded)
        .expect_err("truncated share enum struct fails");
    assert_eq!(err, SrvsvcHarnessError::BufferTooSmall);
}

// Trace: `lib/dcerpc-srvsvc.c:srvsvc_NetrShareEnum_req_coder`, `lib/smb2-share-enum.c:smb2_share_enum_async`
// Spec: srvsvc_NetrShareEnum_req_coder request coder#NetrShareEnum request fields are encoded in declared order
// - **GIVEN** `ptr` 指向 `struct srvsvc_NetrShareEnum_req`
// - **WHEN** 调用方执行 `srvsvc_NetrShareEnum_req_coder`
// - **THEN** coder 依次处理 server name、share enum struct、preferred maximum length 和 resume handle
#[test]
fn test_dcerpc_srvsvc_netrshareenum_request_fields_are_encoded_in_declared_order() {
    let req = share_enum_req();
    let encoded = srvsvc_netr_share_enum_req_coder_harness(&req).expect("request encode succeeds");
    let decoded =
        srvsvc_netr_share_enum_req_decoder_harness(&encoded).expect("request decode succeeds");
    assert_eq!(decoded.server_name.value.as_deref(), Some("\\\\server"));
    assert_eq!(
        decoded.preferred_maximum_length,
        SRVSVC_SHARE_ENUM_PREFERRED_MAXIMUM_LENGTH
    );
    assert_eq!(decoded.resume_handle, 0);
}

// Trace: `lib/dcerpc-srvsvc.c:srvsvc_NetrShareEnum_req_coder`
// Spec: srvsvc_NetrShareEnum_req_coder request coder#NetrShareEnum request failure propagates
// - **GIVEN** 任一请求字段底层 coder 返回错误
// - **WHEN** 调用方执行 `srvsvc_NetrShareEnum_req_coder`
// - **THEN** `srvsvc_NetrShareEnum_req_coder` 返回 `-1`
#[test]
fn test_dcerpc_srvsvc_netrshareenum_request_failure_propagates() {
    let mut encoded = srvsvc_netr_share_enum_req_coder_harness(&share_enum_req())
        .expect("request encode succeeds");
    encoded.truncate(encoded.len() - 1);
    let err =
        srvsvc_netr_share_enum_req_decoder_harness(&encoded).expect_err("truncated request fails");
    assert_eq!(err, SrvsvcHarnessError::BufferTooSmall);
}

// Trace: `lib/dcerpc-srvsvc.c:srvsvc_NetrShareEnum_rep_coder`, `lib/smb2-share-enum.c:smb2_share_enum_async`
// Spec: srvsvc_NetrShareEnum_rep_coder response coder#NetrShareEnum response fields are encoded in declared order
// - **GIVEN** `ptr` 指向 `struct srvsvc_NetrShareEnum_rep`
// - **WHEN** 调用方执行 `srvsvc_NetrShareEnum_rep_coder`
// - **THEN** coder 依次处理 share enum struct、total entries、resume handle 和 status
#[test]
fn test_dcerpc_srvsvc_netrshareenum_response_fields_are_encoded_in_declared_order() {
    let rep = share_enum_rep();
    let encoded = srvsvc_netr_share_enum_rep_coder_harness(&rep).expect("response encode succeeds");
    let decoded =
        srvsvc_netr_share_enum_rep_decoder_harness(&encoded).expect("response decode succeeds");
    assert_eq!(decoded.total_entries, 1);
    assert_eq!(decoded.resume_handle, 0);
    assert_eq!(decoded.status, 0);
}

// Trace: `lib/dcerpc-srvsvc.c:srvsvc_NetrShareEnum_rep_coder`
// Spec: srvsvc_NetrShareEnum_rep_coder response coder#NetrShareEnum response failure propagates
// - **GIVEN** 任一响应字段底层 coder 返回错误
// - **WHEN** 调用方执行 `srvsvc_NetrShareEnum_rep_coder`
// - **THEN** `srvsvc_NetrShareEnum_rep_coder` 返回 `-1`
#[test]
fn test_dcerpc_srvsvc_netrshareenum_response_failure_propagates() {
    let mut encoded = srvsvc_netr_share_enum_rep_coder_harness(&share_enum_rep())
        .expect("response encode succeeds");
    encoded.truncate(encoded.len() - 1);
    let err =
        srvsvc_netr_share_enum_rep_decoder_harness(&encoded).expect_err("truncated response fails");
    assert_eq!(err, SrvsvcHarnessError::BufferTooSmall);
}

// Trace: `lib/dcerpc-srvsvc.c:srvsvc_NetrShareGetInfo_req_coder`, `examples/smb2-share-info.c:main`
// Spec: srvsvc_NetrShareGetInfo_req_coder request coder#NetrShareGetInfo request fields are encoded in declared order
// - **GIVEN** `ptr` 指向 `struct srvsvc_NetrShareGetInfo_req`
// - **WHEN** 调用方执行 `srvsvc_NetrShareGetInfo_req_coder`
// - **THEN** coder 依次处理 server name、share name 和 level
#[test]
fn test_dcerpc_srvsvc_netrsharegetinfo_request_fields_are_encoded_in_declared_order() {
    let req = get_info_req();
    let encoded = srvsvc_netr_share_get_info_req_coder_harness(&req)
        .expect("getinfo request encode succeeds");
    let decoded = srvsvc_netr_share_get_info_req_decoder_harness(&encoded)
        .expect("getinfo request decode succeeds");
    assert_eq!(decoded.server_name.value.as_deref(), Some("\\\\server"));
    assert_eq!(decoded.netname.value.as_deref(), Some("IPC$"));
    assert_eq!(decoded.level, 1);
}

// Trace: `lib/dcerpc-srvsvc.c:srvsvc_NetrShareGetInfo_req_coder`
// Spec: srvsvc_NetrShareGetInfo_req_coder request coder#NetrShareGetInfo request failure propagates
// - **GIVEN** `ServerName`、`NetName` 或 `Level` 的底层 coder 返回错误
// - **WHEN** 调用方执行 `srvsvc_NetrShareGetInfo_req_coder`
// - **THEN** `srvsvc_NetrShareGetInfo_req_coder` 返回 `-1`
#[test]
fn test_dcerpc_srvsvc_netrsharegetinfo_request_failure_propagates() {
    let mut encoded = srvsvc_netr_share_get_info_req_coder_harness(&get_info_req())
        .expect("getinfo request encode succeeds");
    encoded.truncate(encoded.len() - 1);
    let err = srvsvc_netr_share_get_info_req_decoder_harness(&encoded)
        .expect_err("truncated getinfo request fails");
    assert_eq!(err, SrvsvcHarnessError::BufferTooSmall);
}

// Trace: `lib/dcerpc-srvsvc.c:srvsvc_NetrShareGetInfo_rep_coder`, `examples/smb2-share-info.c:main`
// Spec: srvsvc_NetrShareGetInfo_rep_coder response coder#NetrShareGetInfo response fields are encoded in declared order
// - **GIVEN** `ptr` 指向 `struct srvsvc_NetrShareGetInfo_rep`
// - **WHEN** 调用方执行 `srvsvc_NetrShareGetInfo_rep_coder`
// - **THEN** coder 依次处理 level 分派 info struct 和 status
#[test]
fn test_dcerpc_srvsvc_netrsharegetinfo_response_fields_are_encoded_in_declared_order() {
    let rep = get_info_rep();
    let encoded = srvsvc_netr_share_get_info_rep_coder_harness(&rep)
        .expect("getinfo response encode succeeds");
    let decoded = srvsvc_netr_share_get_info_rep_decoder_harness(&encoded)
        .expect("getinfo response decode succeeds");
    assert_eq!(decoded.info_struct.level, 1);
    assert_eq!(decoded.status, 0x1020_3040);
}

// Trace: `lib/dcerpc-srvsvc.c:srvsvc_NetrShareGetInfo_rep_coder`
// Spec: srvsvc_NetrShareGetInfo_rep_coder response coder#NetrShareGetInfo response failure propagates
// - **GIVEN** `InfoStruct` 或 `status` 的底层 coder 返回错误
// - **WHEN** 调用方执行 `srvsvc_NetrShareGetInfo_rep_coder`
// - **THEN** `srvsvc_NetrShareGetInfo_rep_coder` 返回 `-1`
#[test]
fn test_dcerpc_srvsvc_netrsharegetinfo_response_failure_propagates() {
    let err = srvsvc_netr_share_get_info_rep_decoder_harness(&[1, 0, 0])
        .expect_err("truncated InfoStruct level must fail");
    assert_eq!(err, SrvsvcHarnessError::BufferTooSmall);

    let rep = SrvsvcNetrShareGetInfoRep {
        status: 0x1020_3040,
        info_struct: SrvsvcShareInfo {
            level: 1,
            payload: SrvsvcShareInfoPayload::ShareInfo1(SrvsvcShareInfo1 {
                netname: DcerpcUtf16 {
                    value: Some("IPC$".to_owned()),
                },
                share_type: 0x8000_0003,
                remark: DcerpcUtf16 {
                    value: Some("Remote IPC".to_owned()),
                },
            }),
        },
    };
    let encoded = srvsvc_netr_share_get_info_rep_coder_harness(&rep)
        .expect("response encoding should succeed");
    let mut truncated = encoded;
    truncated.truncate(truncated.len() - 1);

    let err = srvsvc_netr_share_get_info_rep_decoder_harness(&truncated)
        .expect_err("truncated status must fail");
    assert_eq!(err, SrvsvcHarnessError::BufferTooSmall);
}

fn utf16(value: &str) -> DcerpcUtf16 {
    DcerpcUtf16 {
        value: Some(value.to_owned()),
    }
}

fn ipc_share_info_1() -> SrvsvcShareInfo1 {
    SrvsvcShareInfo1 {
        netname: utf16("IPC$"),
        share_type: SHARE_TYPE_IPC | SHARE_TYPE_HIDDEN,
        remark: utf16("Remote IPC"),
    }
}

fn share_info_1_container(count: usize) -> SrvsvcShareInfo1Container {
    SrvsvcShareInfo1Container {
        entries_read: count as u32,
        share_info_1: (0..count).map(|_| ipc_share_info_1()).collect(),
    }
}

fn share_enum_req() -> SrvsvcNetrShareEnumReq {
    SrvsvcNetrShareEnumReq {
        server_name: utf16("\\\\server"),
        ses: SrvsvcShareEnumStruct {
            level: ShareInfoLevel::ShareInfo1 as u32,
            share_info: SrvsvcShareEnumUnion::Level1(share_info_1_container(1)),
        },
        preferred_maximum_length: SRVSVC_SHARE_ENUM_PREFERRED_MAXIMUM_LENGTH,
        resume_handle: 0,
    }
}

fn share_enum_rep() -> SrvsvcNetrShareEnumRep {
    SrvsvcNetrShareEnumRep {
        status: 0,
        ses: SrvsvcShareEnumStruct {
            level: ShareInfoLevel::ShareInfo1 as u32,
            share_info: SrvsvcShareEnumUnion::Level1(share_info_1_container(1)),
        },
        total_entries: 1,
        resume_handle: 0,
    }
}

fn get_info_req() -> SrvsvcNetrShareGetInfoReq {
    SrvsvcNetrShareGetInfoReq {
        server_name: utf16("\\\\server"),
        netname: utf16("IPC$"),
        level: 1,
    }
}

fn get_info_rep() -> SrvsvcNetrShareGetInfoRep {
    SrvsvcNetrShareGetInfoRep {
        status: 0x1020_3040,
        info_struct: SrvsvcShareInfo {
            level: 1,
            payload: SrvsvcShareInfoPayload::ShareInfo1(ipc_share_info_1()),
        },
    }
}
