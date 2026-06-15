use libsmb2_rs::lib::errors::nterror_to_str as nt_error_to_str;
use libsmb2_rs::include::smb2::smb2_errors as errors;

// Trace: `include/smb2/smb2-errors.h:SMB2_STATUS_SEVERITY_MASK`, `lib/pdu.c:smb2_is_error_response`
// Spec: SMB2_STATUS_SEVERITY_MASK preserve severity bits#classify error severity
// - **GIVEN** 调用方或解析代码持有一个 SMB2 header status 值。
// - **WHEN** 该 status 与 `SMB2_STATUS_SEVERITY_MASK` 做按位与运算。
// - **THEN** 结果为 status 的高两位 severity 编码，可与 `SMB2_STATUS_SEVERITY_ERROR` 或 `SMB2_STATUS_SEVERITY_WARNING` 比较。
#[test]
fn test_smb2_errors_classify_error_severity() {
    let status = errors::SMB2_STATUS_ACCESS_DENIED;

    assert_eq!(
        status & errors::SMB2_STATUS_SEVERITY_MASK,
        errors::SMB2_STATUS_SEVERITY_ERROR
    );
    assert_ne!(
        status & errors::SMB2_STATUS_SEVERITY_MASK,
        errors::SMB2_STATUS_SEVERITY_WARNING
    );
}

// Trace: `include/smb2/smb2-errors.h:SMB2_STATUS_SEVERITY_SUCCESS`
// Spec: SMB2_STATUS_SEVERITY_SUCCESS expose success severity#identify success severity constant
// - **GIVEN** 调用方包含 `include/smb2/smb2-errors.h`。
// - **WHEN** 调用方读取 `SMB2_STATUS_SEVERITY_SUCCESS`。
// - **THEN** 该宏展开为 `0x00000000`，与 success severity 的高位编码一致。
#[test]
fn test_smb2_errors_identify_success_severity_constant() {
    assert_eq!(errors::SMB2_STATUS_SEVERITY_SUCCESS, 0x0000_0000);
}

// Trace: `include/smb2/smb2-errors.h:SMB2_STATUS_SEVERITY_INFO`
// Spec: SMB2_STATUS_SEVERITY_INFO expose informational severity#identify informational severity constant
// - **GIVEN** 调用方包含 `include/smb2/smb2-errors.h`。
// - **WHEN** 调用方读取 `SMB2_STATUS_SEVERITY_INFO`。
// - **THEN** 该宏展开为 `0x40000000`，与 informational severity 的高位编码一致。
#[test]
fn test_smb2_errors_identify_informational_severity_constant() {
    assert_eq!(errors::SMB2_STATUS_SEVERITY_INFO, 0x4000_0000);
}

// Trace: `include/smb2/smb2-errors.h:SMB2_STATUS_SEVERITY_WARNING`, `lib/pdu.c:smb2_is_error_response`
// Spec: SMB2_STATUS_SEVERITY_WARNING expose warning severity#classify warning severity
// - **GIVEN** SMB2 reply status 的高位匹配 warning severity。
// - **WHEN** 解析代码使用 `SMB2_STATUS_SEVERITY_MASK` 提取高位并与 `SMB2_STATUS_SEVERITY_WARNING` 比较。
// - **THEN** warning status 可进入 warning 分类分支，特定 warning 值可被判定为错误响应。
#[test]
fn test_smb2_errors_classify_warning_severity() {
    let status = errors::SMB2_STATUS_NO_MORE_FILES;

    assert_eq!(
        status & errors::SMB2_STATUS_SEVERITY_MASK,
        errors::SMB2_STATUS_SEVERITY_WARNING
    );
}

// Trace: `include/smb2/smb2-errors.h:SMB2_STATUS_SEVERITY_ERROR`, `lib/pdu.c:smb2_is_error_response`
// Spec: SMB2_STATUS_SEVERITY_ERROR expose error severity#classify error severity
// - **GIVEN** SMB2 reply status 的高位匹配 error severity。
// - **WHEN** 解析代码使用 `SMB2_STATUS_SEVERITY_MASK` 提取高位并与 `SMB2_STATUS_SEVERITY_ERROR` 比较。
// - **THEN** 除显式例外状态外，该 reply 可被归类为 SMB2 error response。
#[test]
fn test_smb2_errors_classify_error_severity_2() {
    let status = errors::SMB2_STATUS_INVALID_PARAMETER;

    assert_eq!(
        status & errors::SMB2_STATUS_SEVERITY_MASK,
        errors::SMB2_STATUS_SEVERITY_ERROR
    );
}

// Trace: `include/smb2/smb2-errors.h:SMB2_STATUS_CUSTOMER_MASK`
// Spec: SMB2_STATUS_CUSTOMER_MASK expose customer bit#isolate customer bit
// - **GIVEN** 调用方持有一个 SMB2/NTSTATUS 值。
// - **WHEN** 调用方使用 `SMB2_STATUS_CUSTOMER_MASK` 做按位过滤。
// - **THEN** 结果只保留 customer 标志位对应的 `0x20000000` 位。
#[test]
fn test_smb2_errors_isolate_customer_bit() {
    let status = errors::SMB2_STATUS_CUSTOMER_MASK | errors::SMB2_STATUS_ACCESS_DENIED;

    assert_eq!(status & errors::SMB2_STATUS_CUSTOMER_MASK, 0x2000_0000);
}

// Trace: `include/smb2/smb2-errors.h:SMB2_STATUS_FACILITY_MASK`
// Spec: SMB2_STATUS_FACILITY_MASK expose facility bits#isolate facility bits
// - **GIVEN** 调用方持有一个 SMB2/NTSTATUS 值。
// - **WHEN** 调用方使用 `SMB2_STATUS_FACILITY_MASK` 做按位过滤。
// - **THEN** 结果只保留 facility 字段对应的 `0x0fff0000` 位。
#[test]
fn test_smb2_errors_isolate_facility_bits() {
    let status = 0xC123_4567;

    assert_eq!(status & errors::SMB2_STATUS_FACILITY_MASK, 0x0123_0000);
}

// Trace: `include/smb2/smb2-errors.h:SMB2_STATUS_CODE_MASK`
// Spec: SMB2_STATUS_CODE_MASK expose code bits#isolate code bits
// - **GIVEN** 调用方持有一个 SMB2/NTSTATUS 值。
// - **WHEN** 调用方使用 `SMB2_STATUS_CODE_MASK` 做按位过滤。
// - **THEN** 结果只保留低 16 位 code 字段。
#[test]
fn test_smb2_errors_isolate_code_bits() {
    let status = 0xC123_4567;

    assert_eq!(status & errors::SMB2_STATUS_CODE_MASK, 0x0000_4567);
}

// Trace: `include/smb2/smb2-errors.h:SMB2_STATUS_SUCCESS`, `lib/errors.c:nterror_to_str`
// Spec: SMB2_STATUS_SUCCESS expose success code#map success status to string
// - **GIVEN** 错误字符串映射函数收到 `SMB2_STATUS_SUCCESS`。
// - **WHEN** 映射函数按 status 值进入 switch 分支。
// - **THEN** 返回字符串 `STATUS_SUCCESS`。
#[test]
fn test_smb2_errors_map_success_status_to_string() {
    assert_eq!(
        nt_error_to_str(errors::SMB2_STATUS_SUCCESS),
        "STATUS_SUCCESS"
    );
}

// Trace: `include/smb2/smb2-errors.h:SMB2_STATUS_PENDING`, `lib/socket.c:smb2_service`
// Spec: SMB2_STATUS_PENDING expose pending interim code#defer pending response processing
// - **GIVEN** 客户端收到 header status 等于 `SMB2_STATUS_PENDING` 的 SMB2 reply。
// - **WHEN** socket 接收状态机处理该 reply。
// - **THEN** 该 reply 的剩余 payload 被当作 padding 或 passthrough 中间响应处理，等待后续最终 reply。
#[test]
fn test_smb2_errors_defer_pending_response_processing() {
    assert_eq!(errors::SMB2_STATUS_PENDING, 0x0000_0103);
    assert_eq!(
        errors::SMB2_STATUS_PENDING & errors::SMB2_STATUS_SEVERITY_MASK,
        errors::SMB2_STATUS_SEVERITY_SUCCESS
    );
}

// Trace: `include/smb2/smb2-errors.h:SMB2_STATUS_ACCESS_DENIED`, `lib/errors.c:nterror_to_str`
// Spec: SMB2_STATUS_ACCESS_DENIED expose access denied code#map access denied status to string
// - **GIVEN** 错误字符串映射函数收到 `SMB2_STATUS_ACCESS_DENIED`。
// - **WHEN** 映射函数按 status 值进入 switch 分支。
// - **THEN** 返回字符串 `STATUS_ACCESS_DENIED`。
#[test]
fn test_smb2_errors_map_access_denied_status_to_string() {
    assert_eq!(
        nt_error_to_str(errors::SMB2_STATUS_ACCESS_DENIED),
        "STATUS_ACCESS_DENIED"
    );
}

// Trace: `include/smb2/smb2-errors.h:SMB2_STATUS_INVALID_PARAMETER`, `lib/libsmb2.c:smb2_negotiate_request_cb`
// Spec: SMB2_STATUS_INVALID_PARAMETER expose invalid parameter code#emit invalid negotiate parameter response
// - **GIVEN** 服务端协商请求存在源码确认的无效参数条件。
// - **WHEN** 协商回调构造 SMB2 error reply。
// - **THEN** error reply 使用 `SMB2_STATUS_INVALID_PARAMETER` 作为协议状态码。
#[test]
fn test_smb2_errors_emit_invalid_negotiate_parameter_response() {
    assert_eq!(errors::SMB2_STATUS_INVALID_PARAMETER, 0xC000_000D);
}

// Trace: `include/smb2/smb2-errors.h:SMB2_STATUS_*`, `lib/errors.c:nterror_to_str`
// Spec: Other SMB2_STATUS_* constants preserve declared NTSTATUS values#map declared status constants
// - **GIVEN** 调用方或内部错误映射代码使用文件中任一已声明 `SMB2_STATUS_*` 状态码。
// - **WHEN** 该宏被预处理器展开并按数值参与比较或 switch 分支。
// - **THEN** 展开值与 `include/smb2/smb2-errors.h` 中声明的十六进制 NTSTATUS 值一致。
#[test]
fn test_smb2_errors_map_declared_status_constants() {
    assert_eq!(errors::SMB2_STATUS_SHUTDOWN, 0xFFFF_FFFF);
    assert_eq!(errors::SMB2_STATUS_NO_MORE_FILES, 0x8000_0006);
    assert_eq!(errors::SMB2_STATUS_UNSUCCESSFUL, 0xC000_0001);
    assert_eq!(errors::SMB2_STATUS_NOT_IMPLEMENTED, 0xC000_0002);
    assert_eq!(errors::SMB2_STATUS_INVALID_INFO_CLASS, 0xC000_0003);
    assert_eq!(errors::SMB2_STATUS_INFO_LENGTH_MISMATCH, 0xC000_0004);
    assert_eq!(errors::SMB2_STATUS_ACCESS_VIOLATION, 0xC000_0005);
    assert_eq!(errors::SMB2_STATUS_INVALID_HANDLE, 0xC000_0008);
    assert_eq!(errors::SMB2_STATUS_NO_SUCH_FILE, 0xC000_000F);
    assert_eq!(errors::SMB2_STATUS_MORE_PROCESSING_REQUIRED, 0xC000_0016);
    assert_eq!(errors::SMB2_STATUS_NO_MEMORY, 0xC000_0017);
    assert_eq!(errors::SMB2_STATUS_BUFFER_TOO_SMALL, 0xC000_0023);
    assert_eq!(errors::SMB2_STATUS_OBJECT_NAME_NOT_FOUND, 0xC000_0034);
    assert_eq!(errors::SMB2_STATUS_OBJECT_NAME_COLLISION, 0xC000_0035);
    assert_eq!(errors::SMB2_STATUS_SHARING_VIOLATION, 0xC000_0043);
    assert_eq!(errors::SMB2_STATUS_FILE_LOCK_CONFLICT, 0xC000_0054);
    assert_eq!(errors::SMB2_STATUS_DELETE_PENDING, 0xC000_0056);
    assert_eq!(errors::SMB2_STATUS_LOGON_FAILURE, 0xC000_006D);
    assert_eq!(errors::SMB2_STATUS_NOT_FOUND, 0xC000_0225);
}
