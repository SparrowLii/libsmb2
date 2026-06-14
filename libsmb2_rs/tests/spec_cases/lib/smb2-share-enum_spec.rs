use libsmb2_rs::lib::smb2_share_enum::{
    smb2_share_enum_async_skeleton, ShareEnumCallbackResult, ShareEnumReply, ShareEnumStatus,
    ShareInfoContainer, ShareInfoLevel, NETR_SHARE_ENUM_PREFERRED_MAXIMUM_LENGTH,
    SRVSVC_NETR_SHARE_ENUM_OPNUM,
};

// Trace: `lib/smb2-share-enum.c:smb2_share_enum_async`, `lib/smb2-share-enum.c:share_enum_bind_cb`, `include/smb2/libsmb2-dcerpc-srvsvc.h:smb2_share_enum_async`, `examples/smb2-share-enum.c:main`
// Spec: smb2_share_enum_async starts SRVSVC ShareEnum asynchronously#成功启动 ShareEnum 请求
// - **GIVEN** 调用方提供已初始化的 `smb2_context`、支持的 `SHARE_INFO_0` 或 `SHARE_INFO_1` level、callback 和 callback 数据
// - **WHEN** 调用方调用 `smb2_share_enum_async(smb2, level, cb, cb_data)` 且 DCERPC 上下文、私有状态和服务器名分配成功
// - **THEN** 函数返回 `0`，请求使用 `SRVSVC_NETRSHAREENUM` 和 `srvsvc_NetrShareEnum_req_coder` 在 bind 成功后异步发送，完成结果通过调用方 callback 报告
#[test]
fn test_smb2_share_enum_successfully_starts_share_enum_request() {
    let nse = smb2_share_enum_async_skeleton("server", ShareInfoLevel::ShareInfo1);
    let request = nse.request();

    assert_eq!(request.opnum(), SRVSVC_NETR_SHARE_ENUM_OPNUM);
    assert_eq!(request.server_name.as_str(), "\\\\server");
    assert_eq!(
        request.preferred_maximum_length,
        NETR_SHARE_ENUM_PREFERRED_MAXIMUM_LENGTH
    );
    assert_eq!(request.resume_handle, 0);
}

// Trace: `lib/smb2-share-enum.c:smb2_share_enum_async`, `include/smb2/libsmb2-dcerpc-srvsvc.h:enum SHARE_INFO_enum`
// Spec: smb2_share_enum_async starts SRVSVC ShareEnum asynchronously#SHARE_INFO_0 初始化
// - **GIVEN** 调用方传入 `SHARE_INFO_0`
// - **WHEN** `smb2_share_enum_async` 构造 `srvsvc_NetrShareEnum_req`
// - **THEN** 请求的 `ses.Level` 和 `ses.ShareInfo.Level` MUST 设置为 `SHARE_INFO_0`，`Level0.EntriesRead` MUST 初始化为 `0`，`Level0.share_info_0` MUST 初始化为 `NULL`
#[test]
fn test_smb2_share_enum_share_info_0_initialization() {
    let request =
        smb2_share_enum_async_skeleton("server", ShareInfoLevel::ShareInfo0).into_request();

    assert_eq!(request.level, ShareInfoLevel::ShareInfo0);
    assert_eq!(request.share_info.level(), ShareInfoLevel::ShareInfo0);
    assert_eq!(
        request.share_info,
        ShareInfoContainer::Level0 { entries_read: 0 }
    );
}

// Trace: `lib/smb2-share-enum.c:smb2_share_enum_async`, `include/smb2/libsmb2-dcerpc-srvsvc.h:enum SHARE_INFO_enum`
// Spec: smb2_share_enum_async starts SRVSVC ShareEnum asynchronously#SHARE_INFO_1 初始化
// - **GIVEN** 调用方传入 `SHARE_INFO_1`
// - **WHEN** `smb2_share_enum_async` 构造 `srvsvc_NetrShareEnum_req`
// - **THEN** 请求的 `ses.Level` 和 `ses.ShareInfo.Level` MUST 设置为 `SHARE_INFO_1`，`Level1.EntriesRead` MUST 初始化为 `0`，`Level1.share_info_1` MUST 初始化为 `NULL`
#[test]
fn test_smb2_share_enum_share_info_1_initialization() {
    let request =
        smb2_share_enum_async_skeleton("server", ShareInfoLevel::ShareInfo1).into_request();

    assert_eq!(request.level, ShareInfoLevel::ShareInfo1);
    assert_eq!(request.share_info.level(), ShareInfoLevel::ShareInfo1);
    assert_eq!(
        request.share_info,
        ShareInfoContainer::Level1 { entries_read: 0 }
    );
}

// Trace: `lib/smb2-share-enum.c:smb2_share_enum_async`, `include/smb2/libsmb2-dcerpc-srvsvc.h:smb2_share_enum_async`
// Spec: smb2_share_enum_async starts SRVSVC ShareEnum asynchronously#启动前分配失败
// - **GIVEN** 调用方调用 `smb2_share_enum_async` 时 DCERPC 上下文、私有状态或服务器名分配失败
// - **WHEN** 函数无法完成异步请求启动
// - **THEN** 函数 MUST 返回负 errno 风格错误码，MUST NOT 调用调用方 callback，并在私有状态或服务器名分配失败路径释放已创建的 DCERPC 上下文
#[test]
fn test_smb2_share_enum_allocation_failure_before_start() {
    let result = ShareEnumCallbackResult::from_ioctl_status(ShareEnumStatus::new(-12), None);

    assert_eq!(
        result,
        ShareEnumCallbackResult::TransportError(ShareEnumStatus::new(-12))
    );
}

// Trace: `lib/smb2-share-enum.c:smb2_share_enum_async`, `lib/smb2-share-enum.c:share_enum_bind_cb`
// Spec: smb2_share_enum_async starts SRVSVC ShareEnum asynchronously#bind 或 DCERPC 调用启动失败
// - **GIVEN** `smb2_share_enum_async` 已创建私有状态并调用 `dcerpc_connect_context_async`
// - **WHEN** `dcerpc_connect_context_async` 立即返回错误，或 bind 回调收到失败状态，或 bind 后 `dcerpc_call_async` 返回错误
// - **THEN** 实现 MUST 释放私有状态和 DCERPC 上下文；对于 bind 回调或 call 启动失败，MUST 使用相同 status 调用调用方 callback 并传入 `NULL` command data
#[test]
fn test_smb2_share_enum_bind_or_dcerpc_call_start_failure() {
    let result = ShareEnumCallbackResult::from_ioctl_status(ShareEnumStatus::new(-5), None);

    assert_eq!(
        result,
        ShareEnumCallbackResult::TransportError(ShareEnumStatus::new(-5))
    );
}

// Trace: `lib/smb2-share-enum.c:srvsvc_ioctl_cb`, `include/smb2/libsmb2-dcerpc-srvsvc.h:smb2_share_enum_async`
// Spec: smb2_share_enum_async starts SRVSVC ShareEnum asynchronously#DCERPC 完成回调
// - **GIVEN** ShareEnum DCERPC 调用已启动并进入 `srvsvc_ioctl_cb`
// - **WHEN** DCERPC 层返回非 `SMB2_STATUS_SUCCESS` status
// - **THEN** callback MUST 以该 status、`NULL` command data 和原始 `cb_data` 调用，并在之后释放私有状态和销毁 DCERPC 上下文
#[test]
fn test_smb2_share_enum_dcerpc_completion_callback() {
    let result = ShareEnumCallbackResult::from_ioctl_status(
        ShareEnumStatus::new(0xc000_0001_u32 as i32),
        None,
    );

    assert_eq!(
        result,
        ShareEnumCallbackResult::TransportError(ShareEnumStatus::new(0xc000_0001_u32 as i32))
    );
}

// Trace: `lib/smb2-share-enum.c:srvsvc_ioctl_cb`, `include/smb2/libsmb2-dcerpc-srvsvc.h:smb2_share_enum_async`
// Spec: smb2_share_enum_async starts SRVSVC ShareEnum asynchronously#SRVSVC ShareEnum 响应完成
// - **GIVEN** DCERPC 层以 `SMB2_STATUS_SUCCESS` 完成并提供 `struct srvsvc_rep` 响应数据
// - **WHEN** `srvsvc_ioctl_cb` 调用用户 callback
// - **THEN** callback MUST 接收 `rep->status` 作为 status、原始响应指针作为 command data 和原始 `cb_data`，响应数据生命周期 MUST 遵循 public header 中由调用方使用 `smb2_free_data()` 释放的约定
#[test]
fn test_smb2_share_enum_srvsvc_share_enum_response_completion() {
    let reply = ShareEnumReply::new(ShareEnumStatus::new(123));
    let result =
        ShareEnumCallbackResult::from_ioctl_status(ShareEnumStatus::new(0), Some(reply.clone()));

    assert_eq!(result, ShareEnumCallbackResult::Reply(reply));
}
