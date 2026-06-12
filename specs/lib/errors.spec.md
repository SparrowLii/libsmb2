# lib/errors.c Specification

## Source Context

- Source: `lib/errors.c`
- Related Headers: `include/smb2/libsmb2.h`, `include/smb2/smb2-errors.h`, `lib/smb2.h`, `lib/compat.h`
- Related Tests: `examples/smb2-raw-fsstat-async.c`, `examples/smb2-raw-getsd-async.c`, `examples/smb2-raw-stat-async.c`
- Related Dependencies: `nterror_to_str` is called by multiple `lib/libsmb2.c` callbacks; `nterror_to_errno` is called by `lib/libsmb2.c`, `lib/dcerpc.c`, and raw example callbacks according to GitNexus context/impact.
- Build/Compile Context: C project; includes `config.h` when `HAVE_CONFIG_H` is defined, conditionally includes standard/platform headers such as `stdint.h`, socket/time headers, and depends on errno macros from `<errno.h>`.

## Interface Summary

| Interface | Kind | Signature | Decision | Reason |
| --- | --- | --- | --- | --- |
| nterror_to_str | function | const char *nterror_to_str(uint32_t status); | Include | 公开声明的 NTSTATUS 到字符串转换接口，被多个 SMB2 回调用于错误文本生成。 |
| nterror_to_errno | function | int nterror_to_errno(uint32_t status); | Include | 公开声明的 NTSTATUS 到 POSIX errno 转换接口，被 SMB2、DCERPC 和示例错误路径调用。 |

## Data Model Summary

| Type/Macro | Kind | Definition | Notes |
| --- | --- | --- | --- |
| SMB2_STATUS_* | macro | include/smb2/smb2-errors.h | 本文件按状态码宏进行字符串和 errno 映射，宏定义由公共错误头提供。 |

## ADDED Requirements

### Requirement: nterror_to_str map NTSTATUS to stable names
系统 MUST 将已显式列出的 SMB2/NTSTATUS 状态码转换为源码中对应的静态字符串，并 MUST 在未匹配任何状态码时返回 `Unknown`。

#### Scenario: Known status name conversion
- **GIVEN** 调用方持有 `lib/errors.c` switch 表中显式列出的 SMB2/NTSTATUS 状态码。
- **WHEN** 调用方调用 `nterror_to_str(status)`。
- **THEN** 函数返回该 case 语句指定的静态字符串指针，不分配内存且不修改调用方状态。

Trace: `lib/errors.c:nterror_to_str`, `include/smb2/libsmb2.h:nterror_to_str`

#### Scenario: Unknown status name conversion
- **GIVEN** 调用方传入未被 `lib/errors.c` switch 表显式匹配的状态码。
- **WHEN** 调用方调用 `nterror_to_str(status)`。
- **THEN** 函数返回字符串 `Unknown`。

Trace: `lib/errors.c:nterror_to_str`, `include/smb2/libsmb2.h:nterror_to_str`

### Requirement: nterror_to_errno map NTSTATUS to POSIX errno
系统 MUST 将已显式列出的 SMB2/NTSTATUS 状态码转换为源码中对应的 POSIX errno 值，并 MUST 对未匹配状态码和 `SMB2_STATUS_INTERNAL_ERROR` 返回 `EIO`。

#### Scenario: Successful and EOF status conversion
- **GIVEN** 调用方传入 `SMB2_STATUS_SUCCESS` 或 `SMB2_STATUS_END_OF_FILE`。
- **WHEN** 调用方调用 `nterror_to_errno(status)`。
- **THEN** 函数返回 `0`。

Trace: `lib/errors.c:nterror_to_errno`, `include/smb2/libsmb2.h:nterror_to_errno`

#### Scenario: Retryable network reset conversion
- **GIVEN** 调用方传入 `SMB2_STATUS_CANCELLED`、`SMB2_STATUS_FILE_CLOSED`、`SMB2_STATUS_VOLUME_DISMOUNTED`、连接断开/重置/无效/中止状态、`SMB2_STATUS_NETWORK_NAME_DELETED` 或 `SMB2_STATUS_INVALID_NETWORK_RESPONSE`。
- **WHEN** 调用方调用 `nterror_to_errno(status)`。
- **THEN** 函数返回 `ENETRESET`，以便上层将这些状态作为可重试网络复位错误处理。

Trace: `lib/errors.c:nterror_to_errno`, `include/smb2/libsmb2.h:nterror_to_errno`

#### Scenario: Unknown or internal status conversion
- **GIVEN** 调用方传入未被 `lib/errors.c` switch 表显式匹配的状态码，或传入 `SMB2_STATUS_INTERNAL_ERROR`。
- **WHEN** 调用方调用 `nterror_to_errno(status)`。
- **THEN** 函数返回 `EIO`。

Trace: `lib/errors.c:nterror_to_errno`, `include/smb2/libsmb2.h:nterror_to_errno`

## Open Questions

| ID | Question | Related Interface | Reason |
| --- | --- | --- | --- |
| Q-001 | `nterror_to_str` 的字符串前缀在部分 case 中使用 `STATUS_`，部分使用 `SMB2_STATUS_`，这种差异是否属于对外兼容契约？ | nterror_to_str | 源码保留混合字符串，未发现测试锁定具体文本全集。 |
| Q-002 | `SMB2_STATUS_SHUTDOWN` 转换为负 NTSTATUS 数值而不是 POSIX errno 是否属于稳定 ABI 约定？ | nterror_to_errno | 源码明确返回 `-(int)SMB2_STATUS_SHUTDOWN`，但声明注释只说明转换为 errno 值。 |
