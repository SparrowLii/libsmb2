use libsmb2_rs::lib::errors;
use libsmb2_rs::include::smb2::smb2_errors;

// Trace: `lib/errors.c:nterror_to_str`, `include/smb2/libsmb2.h:nterror_to_str`
// Spec: nterror_to_str map NTSTATUS to stable names#Known status name conversion
// - **GIVEN** 调用方持有 `lib/errors.c` switch 表中显式列出的 SMB2/NTSTATUS 状态码。
// - **WHEN** 调用方调用 `nterror_to_str(status)`。
// - **THEN** 函数返回该 case 语句指定的静态字符串指针，不分配内存且不修改调用方状态。
#[test]
fn test_errors_known_status_name_conversion() {
    assert_eq!(
        errors::nterror_to_str(smb2_errors::SMB2_STATUS_SUCCESS),
        "STATUS_SUCCESS"
    );
    assert_eq!(
        errors::nterror_to_str(smb2_errors::SMB2_STATUS_ACCESS_DENIED),
        "STATUS_ACCESS_DENIED"
    );
    assert_eq!(
        errors::nterror_to_str(smb2_errors::SMB2_STATUS_INVALID_PARAMETER),
        "STATUS_INVALID_PARAMETER"
    );
}

// Trace: `lib/errors.c:nterror_to_str`, `include/smb2/libsmb2.h:nterror_to_str`
// Spec: nterror_to_str map NTSTATUS to stable names#Unknown status name conversion
// - **GIVEN** 调用方传入未被 `lib/errors.c` switch 表显式匹配的状态码。
// - **WHEN** 调用方调用 `nterror_to_str(status)`。
// - **THEN** 函数返回字符串 `Unknown`。
#[test]
fn test_errors_unknown_status_name_conversion() {
    assert_eq!(errors::nterror_to_str(0x1234_5678), "Unknown");
}

// Trace: `lib/errors.c:nterror_to_errno`, `include/smb2/libsmb2.h:nterror_to_errno`
// Spec: nterror_to_errno map NTSTATUS to POSIX errno#Successful and EOF status conversion
// - **GIVEN** 调用方传入 `SMB2_STATUS_SUCCESS` 或 `SMB2_STATUS_END_OF_FILE`。
// - **WHEN** 调用方调用 `nterror_to_errno(status)`。
// - **THEN** 函数返回 `0`。
// Note: The current safe binding exposes `SMB2_STATUS_SUCCESS`; `SMB2_STATUS_END_OF_FILE` is not exposed yet.
#[test]
fn test_errors_successful_and_eof_status_conversion() {
    assert_eq!(
        errors::nterror_to_errno(smb2_errors::SMB2_STATUS_SUCCESS),
        0
    );
}

// Trace: `lib/errors.c:nterror_to_errno`, `include/smb2/libsmb2.h:nterror_to_errno`
// Spec: nterror_to_errno map NTSTATUS to POSIX errno#Retryable network reset conversion
// - **GIVEN** 调用方传入 `SMB2_STATUS_CANCELLED`、`SMB2_STATUS_FILE_CLOSED`、`SMB2_STATUS_VOLUME_DISMOUNTED`、连接断开/重置/无效/中止状态、`SMB2_STATUS_NETWORK_NAME_DELETED` 或 `SMB2_STATUS_INVALID_NETWORK_RESPONSE`。
// - **WHEN** 调用方调用 `nterror_to_errno(status)`。
// - **THEN** 函数返回 `ENETRESET`，以便上层将这些状态作为可重试网络复位错误处理。
// Note: POSIX `ENETRESET` is 102 on this Linux target; the safe binding does not expose errno constants.
#[test]
fn test_errors_retryable_network_reset_conversion() {
    assert_eq!(errors::nterror_to_errno(0xc000_0120), 102);
    assert_eq!(errors::nterror_to_errno(0xc000_020c), 102);
}

// Trace: `lib/errors.c:nterror_to_errno`, `include/smb2/libsmb2.h:nterror_to_errno`
// Spec: nterror_to_errno map NTSTATUS to POSIX errno#Unknown or internal status conversion
// - **GIVEN** 调用方传入未被 `lib/errors.c` switch 表显式匹配的状态码，或传入 `SMB2_STATUS_INTERNAL_ERROR`。
// - **WHEN** 调用方调用 `nterror_to_errno(status)`。
// - **THEN** 函数返回 `EIO`。
// Note: POSIX `EIO` is 5 on this target; the safe binding does not expose errno constants.
#[test]
fn test_errors_unknown_or_internal_status_conversion() {
    assert_eq!(errors::nterror_to_errno(0x1234_5678), 5);
}
