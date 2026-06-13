use libsmb2_sys::smb2::libsmb2_dcerpc_srvsvc::*;

// Trace: `include/smb2/libsmb2-dcerpc-srvsvc.h:SRVSVC_NETRSHAREENUM`, `lib/smb2-share-enum.c:share_enum_bind_cb`
// Spec: SRVSVC_NETRSHAREENUM operation number#NetrShareEnum opcode is stable
// - **GIVEN** 调用方包含 `include/smb2/libsmb2-dcerpc-srvsvc.h`
// - **WHEN** 调用方读取 `SRVSVC_NETRSHAREENUM`
// - **THEN** 该宏展开结果为 `0x0f`
#[test]
fn test_libsmb2_dcerpc_srvsvc_netrshareenum_opcode_is_stable() {
    assert_eq!(SRVSVC_NETRSHAREENUM, 0x0f);
}

// Trace: `include/smb2/libsmb2-dcerpc-srvsvc.h:SRVSVC_NETRSHAREGETINFO`, `lib/dcerpc-srvsvc.c:srvsvc_NetrShareGetInfo_req_coder`
// Spec: SRVSVC_NETRSHAREGETINFO operation number#NetrShareGetInfo opcode is stable
// - **GIVEN** 调用方包含 `include/smb2/libsmb2-dcerpc-srvsvc.h`
// - **WHEN** 调用方读取 `SRVSVC_NETRSHAREGETINFO`
// - **THEN** 该宏展开结果为 `0x10`
#[test]
fn test_libsmb2_dcerpc_srvsvc_netrsharegetinfo_opcode_is_stable() {
    assert_eq!(SRVSVC_NETRSHAREGETINFO, 0x10);
}

// Trace: `include/smb2/libsmb2-dcerpc-srvsvc.h:SHARE_TYPE_DISKTREE`
// Spec: SHARE_TYPE_DISKTREE share type code#Disk tree share type is encoded as zero
// - **GIVEN** 调用方处理 `srvsvc_SHARE_INFO_1.type`
// - **WHEN** 调用方比较 `SHARE_TYPE_DISKTREE`
// - **THEN** 该宏值为 `0`
#[test]
fn test_libsmb2_dcerpc_srvsvc_disk_tree_share_type_is_encoded_as_zero() {
    assert_eq!(SHARE_TYPE_DISKTREE, 0);
}

// Trace: `include/smb2/libsmb2-dcerpc-srvsvc.h:SHARE_TYPE_PRINTQ`
// Spec: SHARE_TYPE_PRINTQ share type code#Print queue share type is encoded as one
// - **GIVEN** 调用方处理 `srvsvc_SHARE_INFO_1.type`
// - **WHEN** 调用方比较 `SHARE_TYPE_PRINTQ`
// - **THEN** 该宏值为 `1`
#[test]
fn test_libsmb2_dcerpc_srvsvc_print_queue_share_type_is_encoded_as_one() {
    assert_eq!(SHARE_TYPE_PRINTQ, 1);
}

// Trace: `include/smb2/libsmb2-dcerpc-srvsvc.h:SHARE_TYPE_DEVICE`
// Spec: SHARE_TYPE_DEVICE share type code#Device share type is encoded as two
// - **GIVEN** 调用方处理 `srvsvc_SHARE_INFO_1.type`
// - **WHEN** 调用方比较 `SHARE_TYPE_DEVICE`
// - **THEN** 该宏值为 `2`
#[test]
fn test_libsmb2_dcerpc_srvsvc_device_share_type_is_encoded_as_two() {
    assert_eq!(SHARE_TYPE_DEVICE, 2);
}

// Trace: `include/smb2/libsmb2-dcerpc-srvsvc.h:SHARE_TYPE_IPC`
// Spec: SHARE_TYPE_IPC share type code#IPC share type is encoded as three
// - **GIVEN** 调用方处理 `srvsvc_SHARE_INFO_1.type`
// - **WHEN** 调用方比较 `SHARE_TYPE_IPC`
// - **THEN** 该宏值为 `3`
#[test]
fn test_libsmb2_dcerpc_srvsvc_ipc_share_type_is_encoded_as_three() {
    assert_eq!(SHARE_TYPE_IPC, 3);
}

// Trace: `include/smb2/libsmb2-dcerpc-srvsvc.h:SHARE_TYPE_TEMPORARY`
// Spec: SHARE_TYPE_TEMPORARY share type flag#Temporary share flag is stable
// - **GIVEN** 调用方处理 `srvsvc_SHARE_INFO_1.type`
// - **WHEN** 调用方测试 `SHARE_TYPE_TEMPORARY`
// - **THEN** 该宏值为 `0x40000000`
#[test]
fn test_libsmb2_dcerpc_srvsvc_temporary_share_flag_is_stable() {
    assert_eq!(SHARE_TYPE_TEMPORARY, 0x4000_0000);
}

// Trace: `include/smb2/libsmb2-dcerpc-srvsvc.h:SHARE_TYPE_HIDDEN`
// Spec: SHARE_TYPE_HIDDEN share type flag#Hidden share flag is stable
// - **GIVEN** 调用方处理 `srvsvc_SHARE_INFO_1.type`
// - **WHEN** 调用方测试 `SHARE_TYPE_HIDDEN`
// - **THEN** 该宏值为 `0x80000000`
#[test]
fn test_libsmb2_dcerpc_srvsvc_hidden_share_flag_is_stable() {
    assert_eq!(SHARE_TYPE_HIDDEN, 0x8000_0000);
}

// Trace: `include/smb2/libsmb2-dcerpc-srvsvc.h:SHARE_INFO_enum`, `lib/smb2-share-enum.c:smb2_share_enum_async`
// Spec: SHARE_INFO_enum supported levels#Share enum levels map to declared numeric values
// - **GIVEN** 调用方调用 share enum API
// - **WHEN** 调用方传入 `SHARE_INFO_0` 或 `SHARE_INFO_1`
// - **THEN** `SHARE_INFO_0` 值为 `0` 且 `SHARE_INFO_1` 值为 `1`
#[test]
fn test_libsmb2_dcerpc_srvsvc_share_enum_levels_map_to_declared_numeric_values() {
    assert_eq!(ShareInfoLevel::ShareInfo0 as u32, 0);
    assert_eq!(ShareInfoLevel::ShareInfo1 as u32, 1);
}

// Trace: `include/smb2/libsmb2-dcerpc-srvsvc.h:srvsvc_SHARE_INFO_0`, `lib/dcerpc-srvsvc.c:srvsvc_SHARE_INFO_0_coder`
// Spec: srvsvc_SHARE_INFO_0 level zero record layout#Level zero record carries share name
// - **GIVEN** 调用方接收 `srvsvc_SHARE_INFO_0`
// - **WHEN** 调用方读取该结构
// - **THEN** 调用方可以通过 `netname` 获取 share 名称字段
#[test]
fn test_libsmb2_dcerpc_srvsvc_level_zero_record_carries_share_name() {
    let share = SrvsvcShareInfo0 {
        netname: DcerpcUtf16 {
            value: Some("IPC$".to_string()),
        },
    };
    assert_eq!(share.netname.value.as_deref(), Some("IPC$"));
}

// Trace: `include/smb2/libsmb2-dcerpc-srvsvc.h:srvsvc_SHARE_INFO_0_CONTAINER`, `lib/dcerpc-srvsvc.c:srvsvc_SHARE_INFO_0_CONTAINER_coder`
// Spec: srvsvc_SHARE_INFO_0_CONTAINER level zero container layout#Level zero container carries count and buffer
// - **GIVEN** 调用方接收 level 0 share enum 响应
// - **WHEN** 调用方读取 `srvsvc_SHARE_INFO_0_CONTAINER`
// - **THEN** `EntriesRead` 表示条目数量且 `share_info_0` 指向对应记录数组
#[test]
fn test_libsmb2_dcerpc_srvsvc_level_zero_container_carries_count_and_buffer() {
    let container = SrvsvcShareInfo0Container {
        entries_read: 1,
        share_info_0: vec![SrvsvcShareInfo0::default()],
    };
    assert_eq!(container.entries_read, 1);
    assert_eq!(container.share_info_0.len(), 1);
}

// Trace: `include/smb2/libsmb2-dcerpc-srvsvc.h:srvsvc_SHARE_INFO_1`, `lib/dcerpc-srvsvc.c:srvsvc_SHARE_INFO_1_coder`
// Spec: srvsvc_SHARE_INFO_1 level one record layout#Level one record carries name type and remark
// - **GIVEN** 调用方接收 `srvsvc_SHARE_INFO_1`
// - **WHEN** 调用方读取该结构
// - **THEN** 调用方可以访问 share 名称、类型和备注字段
#[test]
fn test_libsmb2_dcerpc_srvsvc_level_one_record_carries_name_type_and_remark() {
    let share = SrvsvcShareInfo1 {
        netname: DcerpcUtf16 {
            value: Some("share".to_string()),
        },
        share_type: SHARE_TYPE_DISKTREE,
        remark: DcerpcUtf16 {
            value: Some("remark".to_string()),
        },
    };
    assert_eq!(share.netname.value.as_deref(), Some("share"));
    assert_eq!(share.share_type, SHARE_TYPE_DISKTREE);
    assert_eq!(share.remark.value.as_deref(), Some("remark"));
}

// Trace: `include/smb2/libsmb2-dcerpc-srvsvc.h:srvsvc_SHARE_INFO_1_CONTAINER`, `lib/dcerpc-srvsvc.c:srvsvc_SHARE_INFO_1_CONTAINER_coder`
// Spec: srvsvc_SHARE_INFO_1_CONTAINER level one container layout#Level one container carries count and buffer
// - **GIVEN** 调用方接收 level 1 share enum 响应
// - **WHEN** 调用方读取 `srvsvc_SHARE_INFO_1_CONTAINER`
// - **THEN** `EntriesRead` 表示条目数量且 `share_info_1` 指向对应记录数组
#[test]
fn test_libsmb2_dcerpc_srvsvc_level_one_container_carries_count_and_buffer() {
    let container = SrvsvcShareInfo1Container {
        entries_read: 1,
        share_info_1: vec![SrvsvcShareInfo1::default()],
    };
    assert_eq!(container.entries_read, 1);
    assert_eq!(container.share_info_1.len(), 1);
}

// Trace: `include/smb2/libsmb2-dcerpc-srvsvc.h:srvsvc_SHARE_ENUM_UNION`, `lib/dcerpc-srvsvc.c:srvsvc_SHARE_ENUM_UNION_coder`
// Spec: srvsvc_SHARE_ENUM_UNION level selected union#Share enum union exposes level-specific containers
// - **GIVEN** 调用方接收 `srvsvc_SHARE_ENUM_UNION`
// - **WHEN** `Level` 为 `0` 或 `1`
// - **THEN** 调用方可以分别通过 `Level0` 或 `Level1` 访问对应容器
#[test]
fn test_libsmb2_dcerpc_srvsvc_share_enum_union_exposes_level_specific_containers() {
    let level0 = SrvsvcShareEnumUnion::Level0(SrvsvcShareInfo0Container::default());
    let level1 = SrvsvcShareEnumUnion::Level1(SrvsvcShareInfo1Container::default());
    assert!(matches!(level0, SrvsvcShareEnumUnion::Level0(_)));
    assert!(matches!(level1, SrvsvcShareEnumUnion::Level1(_)));
}

// Trace: `include/smb2/libsmb2-dcerpc-srvsvc.h:srvsvc_SHARE_ENUM_STRUCT`, `lib/dcerpc-srvsvc.c:srvsvc_SHARE_ENUM_STRUCT_coder`
// Spec: srvsvc_SHARE_ENUM_STRUCT share enum wrapper#Share enum struct carries level and union
// - **GIVEN** 调用方处理 NetrShareEnum 请求或响应
// - **WHEN** 调用方读取 `srvsvc_SHARE_ENUM_STRUCT`
// - **THEN** 调用方可以读取 `Level` 并通过 `ShareInfo` 访问 level 对应数据
#[test]
fn test_libsmb2_dcerpc_srvsvc_share_enum_struct_carries_level_and_union() {
    let value = SrvsvcShareEnumStruct {
        level: 1,
        share_info: SrvsvcShareEnumUnion::Level1(SrvsvcShareInfo1Container::default()),
    };
    assert_eq!(value.level, 1);
    assert!(matches!(value.share_info, SrvsvcShareEnumUnion::Level1(_)));
}

// Trace: `include/smb2/libsmb2-dcerpc-srvsvc.h:srvsvc_NetrShareEnum_req`, `lib/dcerpc-srvsvc.c:srvsvc_NetrShareEnum_req_coder`
// Spec: srvsvc_NetrShareEnum_req request layout#NetrShareEnum request carries server and paging fields
// - **GIVEN** 调用方准备 NetrShareEnum 请求
// - **WHEN** 调用方填充 `srvsvc_NetrShareEnum_req`
// - **THEN** 请求结构提供 server 名称、share enum 结构、最大长度和 resume handle 字段
#[test]
fn test_libsmb2_dcerpc_srvsvc_netrshareenum_request_carries_server_and_paging_fields() {
    let request = SrvsvcNetrShareEnumReq {
        server_name: DcerpcUtf16 {
            value: Some("server".to_string()),
        },
        ses: SrvsvcShareEnumStruct {
            level: 1,
            share_info: SrvsvcShareEnumUnion::Level1(SrvsvcShareInfo1Container::default()),
        },
        preferred_maximum_length: u32::MAX,
        resume_handle: 7,
    };
    assert_eq!(request.server_name.value.as_deref(), Some("server"));
    assert_eq!(request.ses.level, 1);
    assert_eq!(request.preferred_maximum_length, u32::MAX);
    assert_eq!(request.resume_handle, 7);
}

// Trace: `include/smb2/libsmb2-dcerpc-srvsvc.h:srvsvc_NetrShareEnum_rep`, `lib/dcerpc-srvsvc.c:srvsvc_NetrShareEnum_rep_coder`
// Spec: srvsvc_NetrShareEnum_rep response layout#NetrShareEnum response carries status and enumeration data
// - **GIVEN** share enum 操作完成并返回响应
// - **WHEN** 调用方读取 `srvsvc_NetrShareEnum_rep`
// - **THEN** 调用方可以读取状态、share enum 数据、总条目数和 resume handle
#[test]
fn test_libsmb2_dcerpc_srvsvc_netrshareenum_response_carries_status_and_enumeration_data() {
    let response = SrvsvcNetrShareEnumRep {
        status: 0,
        ses: SrvsvcShareEnumStruct {
            level: 0,
            share_info: SrvsvcShareEnumUnion::Level0(SrvsvcShareInfo0Container::default()),
        },
        total_entries: 2,
        resume_handle: 3,
    };
    assert_eq!(response.status, 0);
    assert!(matches!(
        response.ses.share_info,
        SrvsvcShareEnumUnion::Level0(_)
    ));
    assert_eq!(response.total_entries, 2);
    assert_eq!(response.resume_handle, 3);
}

// Trace: `include/smb2/libsmb2-dcerpc-srvsvc.h:srvsvc_SHARE_INFO`, `lib/dcerpc-srvsvc.c:srvsvc_SHARE_INFO_coder`
// Spec: srvsvc_SHARE_INFO getinfo union layout#GetInfo share info carries level one data
// - **GIVEN** 调用方接收 `srvsvc_SHARE_INFO`
// - **WHEN** `level` 为 `1`
// - **THEN** 调用方可以通过 `ShareInfo1` 访问 level 1 share 信息
#[test]
fn test_libsmb2_dcerpc_srvsvc_getinfo_share_info_carries_level_one_data() {
    let info = SrvsvcShareInfo {
        level: 1,
        payload: SrvsvcShareInfoPayload::ShareInfo1(SrvsvcShareInfo1::default()),
    };
    assert_eq!(info.level, 1);
    assert!(matches!(
        info.payload,
        SrvsvcShareInfoPayload::ShareInfo1(_)
    ));
}

// Trace: `include/smb2/libsmb2-dcerpc-srvsvc.h:srvsvc_NetrShareGetInfo_req`, `lib/dcerpc-srvsvc.c:srvsvc_NetrShareGetInfo_req_coder`
// Spec: srvsvc_NetrShareGetInfo_req request layout#NetrShareGetInfo request carries target share
// - **GIVEN** 调用方准备 NetrShareGetInfo 请求
// - **WHEN** 调用方填充 `srvsvc_NetrShareGetInfo_req`
// - **THEN** 请求结构提供 server 名称、share 名称和请求 level 字段
#[test]
fn test_libsmb2_dcerpc_srvsvc_netrsharegetinfo_request_carries_target_share() {
    let request = SrvsvcNetrShareGetInfoReq {
        server_name: DcerpcUtf16 {
            value: Some("server".to_string()),
        },
        netname: DcerpcUtf16 {
            value: Some("IPC$".to_string()),
        },
        level: 1,
    };
    assert_eq!(request.server_name.value.as_deref(), Some("server"));
    assert_eq!(request.netname.value.as_deref(), Some("IPC$"));
    assert_eq!(request.level, 1);
}

// Trace: `include/smb2/libsmb2-dcerpc-srvsvc.h:srvsvc_NetrShareGetInfo_rep`, `lib/dcerpc-srvsvc.c:srvsvc_NetrShareGetInfo_rep_coder`
// Spec: srvsvc_NetrShareGetInfo_rep response layout#NetrShareGetInfo response carries status and info
// - **GIVEN** NetrShareGetInfo 操作完成并返回响应
// - **WHEN** 调用方读取 `srvsvc_NetrShareGetInfo_rep`
// - **THEN** 调用方可以读取状态和 level 分派的 share 信息
#[test]
fn test_libsmb2_dcerpc_srvsvc_netrsharegetinfo_response_carries_status_and_info() {
    let response = SrvsvcNetrShareGetInfoRep {
        status: 0,
        info_struct: SrvsvcShareInfo {
            level: 1,
            payload: SrvsvcShareInfoPayload::ShareInfo1(SrvsvcShareInfo1::default()),
        },
    };
    assert_eq!(response.status, 0);
    assert_eq!(response.info_struct.level, 1);
}

// Trace: `include/smb2/libsmb2-dcerpc-srvsvc.h:srvsvc_rep`, `lib/smb2-share-enum.c:srvsvc_ioctl_cb`
// Spec: srvsvc_rep generic status response#Generic SRVSVC response carries status
// - **GIVEN** 调用方接收通用 SRVSVC 响应
// - **WHEN** 调用方读取 `srvsvc_rep`
// - **THEN** 调用方可以通过 `status` 获取 32 位响应状态
#[test]
fn test_libsmb2_dcerpc_srvsvc_generic_srvsvc_response_carries_status() {
    let response = SrvsvcRep {
        status: 0xC000_0001,
    };
    assert_eq!(response.status, 0xC000_0001);
}
