# include/smb2/smb2-errors.h Specification

## Source Context

- Source: `include/smb2/smb2-errors.h`
- Related Headers: `include/smb2/smb2.h`
- Related Tests: `none`
- Related Dependencies: `lib/pdu.c` uses severity macros to classify SMB2 replies; `lib/socket.c` uses `SMB2_STATUS_PENDING` for interim reply handling; `lib/libsmb2.c` emits `SMB2_STATUS_INVALID_PARAMETER` for invalid negotiate input; `lib/errors.c` maps many status constants to stable strings.
- Build/Compile Context: `CMakeLists.txt` exposes public headers under `include/smb2`; primary project language is C; no source-level compile conditions guard these macros.

## Interface Summary

| Interface | Kind | Signature | Decision | Reason |
| --- | --- | --- | --- | --- |
| SMB2_STATUS_SEVERITY_MASK | macro | #define SMB2_STATUS_SEVERITY_MASK    0xc0000000 | Include | 公开 NTSTATUS severity 位掩码，`lib/pdu.c` 依赖它区分错误与警告响应。 |
| SMB2_STATUS_SEVERITY_SUCCESS | macro | #define SMB2_STATUS_SEVERITY_SUCCESS 0x00000000 | Include | 公开 NTSTATUS success severity 编码，属于同一组调用方可见状态字段常量。 |
| SMB2_STATUS_SEVERITY_INFO | macro | #define SMB2_STATUS_SEVERITY_INFO    0x40000000 | Include | 公开 NTSTATUS informational severity 编码，属于同一组调用方可见状态字段常量。 |
| SMB2_STATUS_SEVERITY_WARNING | macro | #define SMB2_STATUS_SEVERITY_WARNING 0x80000000 | Include | 公开 NTSTATUS warning severity 编码，`lib/pdu.c` 用它识别特定警告响应。 |
| SMB2_STATUS_SEVERITY_ERROR | macro | #define SMB2_STATUS_SEVERITY_ERROR   0xc0000000 | Include | 公开 NTSTATUS error severity 编码，`lib/pdu.c` 用它选择 SMB2 error reply 解析路径。 |
| SMB2_STATUS_CUSTOMER_MASK | macro | #define SMB2_STATUS_CUSTOMER_MASK    0x20000000 | Include | 公开 NTSTATUS customer 位掩码，属于调用方可见状态字段常量。 |
| SMB2_STATUS_FACILITY_MASK | macro | #define SMB2_STATUS_FACILITY_MASK    0x0fff0000 | Include | 公开 NTSTATUS facility 位掩码，属于调用方可见状态字段常量。 |
| SMB2_STATUS_CODE_MASK | macro | #define SMB2_STATUS_CODE_MASK        0x0000ffff | Include | 公开 NTSTATUS code 位掩码，属于调用方可见状态字段常量。 |
| SMB2_STATUS_SUCCESS | macro | #define SMB2_STATUS_SUCCESS                            0x00000000 | Include | 公开成功状态码，`lib/errors.c` 将其映射为 `STATUS_SUCCESS`。 |
| SMB2_STATUS_PENDING | macro | #define SMB2_STATUS_PENDING                            0x00000103 | Include | 公开 pending 状态码，`lib/socket.c` 和 `lib/pdu.c` 依赖它处理异步中间响应。 |
| SMB2_STATUS_ACCESS_DENIED | macro | #define SMB2_STATUS_ACCESS_DENIED                      0xC0000022 | Include | 公开拒绝访问状态码，`lib/errors.c` 将其映射为 `STATUS_ACCESS_DENIED`。 |
| SMB2_STATUS_INVALID_PARAMETER | macro | #define SMB2_STATUS_INVALID_PARAMETER                  0xC000000D | Include | 公开无效参数状态码，`lib/libsmb2.c` 服务端协商错误路径会发送该值。 |
| Other SMB2_STATUS_* constants | macro | #define SMB2_STATUS_<name> <ntstatus-value> | Include | 文件内其余公开状态码均以宏常量形式暴露给调用方并由错误映射或协议处理代码按值使用。 |

## Data Model Summary

| Type/Macro | Kind | Definition | Notes |
| --- | --- | --- | --- |
| SMB2_STATUS_SEVERITY_MASK | macro | include/smb2/smb2-errors.h:22 | NTSTATUS severity 字段掩码 `0xc0000000`。 |
| SMB2_STATUS_SEVERITY_SUCCESS | macro | include/smb2/smb2-errors.h:23 | NTSTATUS success severity 编码 `0x00000000`。 |
| SMB2_STATUS_SEVERITY_INFO | macro | include/smb2/smb2-errors.h:24 | NTSTATUS informational severity 编码 `0x40000000`。 |
| SMB2_STATUS_SEVERITY_WARNING | macro | include/smb2/smb2-errors.h:25 | NTSTATUS warning severity 编码 `0x80000000`。 |
| SMB2_STATUS_SEVERITY_ERROR | macro | include/smb2/smb2-errors.h:26 | NTSTATUS error severity 编码 `0xc0000000`。 |
| SMB2_STATUS_CUSTOMER_MASK | macro | include/smb2/smb2-errors.h:28 | NTSTATUS customer 字段掩码 `0x20000000`。 |
| SMB2_STATUS_FACILITY_MASK | macro | include/smb2/smb2-errors.h:30 | NTSTATUS facility 字段掩码 `0x0fff0000`。 |
| SMB2_STATUS_CODE_MASK | macro | include/smb2/smb2-errors.h:32 | NTSTATUS code 字段掩码 `0x0000ffff`。 |
| SMB2_STATUS_* | macro | include/smb2/smb2-errors.h:35 | 公开 SMB2/NTSTATUS 状态码集合，包含 success、pending、error 和 warning 码。 |

## ADDED Requirements

### Requirement: SMB2_STATUS_SEVERITY_MASK preserve severity bits
系统 MUST 将 `SMB2_STATUS_SEVERITY_MASK` 暴露为 `0xc0000000`，以便调用方和内部解析代码从 NTSTATUS 值中提取 severity 字段。

#### Scenario: classify error severity
- **GIVEN** 调用方或解析代码持有一个 SMB2 header status 值。
- **WHEN** 该 status 与 `SMB2_STATUS_SEVERITY_MASK` 做按位与运算。
- **THEN** 结果为 status 的高两位 severity 编码，可与 `SMB2_STATUS_SEVERITY_ERROR` 或 `SMB2_STATUS_SEVERITY_WARNING` 比较。

Trace: `include/smb2/smb2-errors.h:SMB2_STATUS_SEVERITY_MASK`, `lib/pdu.c:smb2_is_error_response`

### Requirement: SMB2_STATUS_SEVERITY_SUCCESS expose success severity
系统 MUST 将 `SMB2_STATUS_SEVERITY_SUCCESS` 暴露为 `0x00000000`，表示 NTSTATUS success severity 编码。

#### Scenario: identify success severity constant
- **GIVEN** 调用方包含 `include/smb2/smb2-errors.h`。
- **WHEN** 调用方读取 `SMB2_STATUS_SEVERITY_SUCCESS`。
- **THEN** 该宏展开为 `0x00000000`，与 success severity 的高位编码一致。

Trace: `include/smb2/smb2-errors.h:SMB2_STATUS_SEVERITY_SUCCESS`

### Requirement: SMB2_STATUS_SEVERITY_INFO expose informational severity
系统 MUST 将 `SMB2_STATUS_SEVERITY_INFO` 暴露为 `0x40000000`，表示 NTSTATUS informational severity 编码。

#### Scenario: identify informational severity constant
- **GIVEN** 调用方包含 `include/smb2/smb2-errors.h`。
- **WHEN** 调用方读取 `SMB2_STATUS_SEVERITY_INFO`。
- **THEN** 该宏展开为 `0x40000000`，与 informational severity 的高位编码一致。

Trace: `include/smb2/smb2-errors.h:SMB2_STATUS_SEVERITY_INFO`

### Requirement: SMB2_STATUS_SEVERITY_WARNING expose warning severity
系统 MUST 将 `SMB2_STATUS_SEVERITY_WARNING` 暴露为 `0x80000000`，表示 NTSTATUS warning severity 编码。

#### Scenario: classify warning severity
- **GIVEN** SMB2 reply status 的高位匹配 warning severity。
- **WHEN** 解析代码使用 `SMB2_STATUS_SEVERITY_MASK` 提取高位并与 `SMB2_STATUS_SEVERITY_WARNING` 比较。
- **THEN** warning status 可进入 warning 分类分支，特定 warning 值可被判定为错误响应。

Trace: `include/smb2/smb2-errors.h:SMB2_STATUS_SEVERITY_WARNING`, `lib/pdu.c:smb2_is_error_response`

### Requirement: SMB2_STATUS_SEVERITY_ERROR expose error severity
系统 MUST 将 `SMB2_STATUS_SEVERITY_ERROR` 暴露为 `0xc0000000`，表示 NTSTATUS error severity 编码。

#### Scenario: classify error severity
- **GIVEN** SMB2 reply status 的高位匹配 error severity。
- **WHEN** 解析代码使用 `SMB2_STATUS_SEVERITY_MASK` 提取高位并与 `SMB2_STATUS_SEVERITY_ERROR` 比较。
- **THEN** 除显式例外状态外，该 reply 可被归类为 SMB2 error response。

Trace: `include/smb2/smb2-errors.h:SMB2_STATUS_SEVERITY_ERROR`, `lib/pdu.c:smb2_is_error_response`

### Requirement: SMB2_STATUS_CUSTOMER_MASK expose customer bit
系统 MUST 将 `SMB2_STATUS_CUSTOMER_MASK` 暴露为 `0x20000000`，以便调用方识别 NTSTATUS customer 位。

#### Scenario: isolate customer bit
- **GIVEN** 调用方持有一个 SMB2/NTSTATUS 值。
- **WHEN** 调用方使用 `SMB2_STATUS_CUSTOMER_MASK` 做按位过滤。
- **THEN** 结果只保留 customer 标志位对应的 `0x20000000` 位。

Trace: `include/smb2/smb2-errors.h:SMB2_STATUS_CUSTOMER_MASK`

### Requirement: SMB2_STATUS_FACILITY_MASK expose facility bits
系统 MUST 将 `SMB2_STATUS_FACILITY_MASK` 暴露为 `0x0fff0000`，以便调用方识别 NTSTATUS facility 字段。

#### Scenario: isolate facility bits
- **GIVEN** 调用方持有一个 SMB2/NTSTATUS 值。
- **WHEN** 调用方使用 `SMB2_STATUS_FACILITY_MASK` 做按位过滤。
- **THEN** 结果只保留 facility 字段对应的 `0x0fff0000` 位。

Trace: `include/smb2/smb2-errors.h:SMB2_STATUS_FACILITY_MASK`

### Requirement: SMB2_STATUS_CODE_MASK expose code bits
系统 MUST 将 `SMB2_STATUS_CODE_MASK` 暴露为 `0x0000ffff`，以便调用方识别 NTSTATUS code 字段。

#### Scenario: isolate code bits
- **GIVEN** 调用方持有一个 SMB2/NTSTATUS 值。
- **WHEN** 调用方使用 `SMB2_STATUS_CODE_MASK` 做按位过滤。
- **THEN** 结果只保留低 16 位 code 字段。

Trace: `include/smb2/smb2-errors.h:SMB2_STATUS_CODE_MASK`

### Requirement: SMB2_STATUS_SUCCESS expose success code
系统 MUST 将 `SMB2_STATUS_SUCCESS` 暴露为 `0x00000000`，并保持它作为成功状态的稳定数值。

#### Scenario: map success status to string
- **GIVEN** 错误字符串映射函数收到 `SMB2_STATUS_SUCCESS`。
- **WHEN** 映射函数按 status 值进入 switch 分支。
- **THEN** 返回字符串 `STATUS_SUCCESS`。

Trace: `include/smb2/smb2-errors.h:SMB2_STATUS_SUCCESS`, `lib/errors.c:nterror_to_str`

### Requirement: SMB2_STATUS_PENDING expose pending interim code
系统 MUST 将 `SMB2_STATUS_PENDING` 暴露为 `0x00000103`，并保持它作为异步中间响应的稳定数值。

#### Scenario: defer pending response processing
- **GIVEN** 客户端收到 header status 等于 `SMB2_STATUS_PENDING` 的 SMB2 reply。
- **WHEN** socket 接收状态机处理该 reply。
- **THEN** 该 reply 的剩余 payload 被当作 padding 或 passthrough 中间响应处理，等待后续最终 reply。

Trace: `include/smb2/smb2-errors.h:SMB2_STATUS_PENDING`, `lib/socket.c:smb2_service`

### Requirement: SMB2_STATUS_ACCESS_DENIED expose access denied code
系统 MUST 将 `SMB2_STATUS_ACCESS_DENIED` 暴露为 `0xC0000022`，并保持它作为拒绝访问状态的稳定数值。

#### Scenario: map access denied status to string
- **GIVEN** 错误字符串映射函数收到 `SMB2_STATUS_ACCESS_DENIED`。
- **WHEN** 映射函数按 status 值进入 switch 分支。
- **THEN** 返回字符串 `STATUS_ACCESS_DENIED`。

Trace: `include/smb2/smb2-errors.h:SMB2_STATUS_ACCESS_DENIED`, `lib/errors.c:nterror_to_str`

### Requirement: SMB2_STATUS_INVALID_PARAMETER expose invalid parameter code
系统 MUST 将 `SMB2_STATUS_INVALID_PARAMETER` 暴露为 `0xC000000D`，并保持它作为无效参数状态的稳定数值。

#### Scenario: emit invalid negotiate parameter response
- **GIVEN** 服务端协商请求存在源码确认的无效参数条件。
- **WHEN** 协商回调构造 SMB2 error reply。
- **THEN** error reply 使用 `SMB2_STATUS_INVALID_PARAMETER` 作为协议状态码。

Trace: `include/smb2/smb2-errors.h:SMB2_STATUS_INVALID_PARAMETER`, `lib/libsmb2.c:smb2_negotiate_request_cb`

### Requirement: Other SMB2_STATUS_* constants preserve declared NTSTATUS values
系统 MUST 将 `include/smb2/smb2-errors.h` 中所有其他 `SMB2_STATUS_*` 状态码作为公开宏常量暴露，并保持源码声明的 NTSTATUS 数值不变。

#### Scenario: map declared status constants
- **GIVEN** 调用方或内部错误映射代码使用文件中任一已声明 `SMB2_STATUS_*` 状态码。
- **WHEN** 该宏被预处理器展开并按数值参与比较或 switch 分支。
- **THEN** 展开值与 `include/smb2/smb2-errors.h` 中声明的十六进制 NTSTATUS 值一致。

Trace: `include/smb2/smb2-errors.h:SMB2_STATUS_*`, `lib/errors.c:nterror_to_str`

## Open Questions

| ID | Question | Related Interface | Reason |
| --- | --- | --- | --- |
| Q-001 | 是否需要将每一个 `SMB2_STATUS_*` 状态码拆成独立 Requirement，而不是使用 `Other SMB2_STATUS_* constants` 覆盖其余同构常量？ | Other SMB2_STATUS_* constants | 该头文件包含数百个同构常量；源码证据显示其契约为稳定数值暴露，但当前批次未为每个常量逐一建立独立行为场景。 |
| Q-002 | GitNexus 未索引出宏的上游调用者，但源码搜索确认存在直接使用；是否需要重新分析以补齐宏引用关系？ | file-level | `gitnexus impact` 对代表性宏返回 LOW/0 callers，与 `lib/pdu.c`、`lib/socket.c`、`lib/errors.c` 中的源码使用不一致。 |
