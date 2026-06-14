use libsmb2_sys::legacy::smb2_command_probe::{
    command_probe, CommandProbe, BUILDER_ALLOC_FAILURE, BUILDER_FREES_PDU,
    BUILDER_IOVECTOR_FAILURE, BUILDER_NO_CALLBACK, BUILDER_PADDING_FAILURE, CONTEXT_POINTER,
    FIXED_ALLOC_FAILURE, FIXED_INVALID_SIZE, FIXED_PAYLOAD_CLEANUP, PASSTHROUGH, UNSUPPORTED_ERROR,
    UTF16_NAME, VARIABLE_ABSENT, VARIABLE_PRESENT,
};

fn has(flags: u32, expected: u32) {
    assert!(
        CommandProbe::has(flags, expected),
        "missing flags {expected:#x} in {flags:#x}"
    );
}

fn builder_failure_flags() -> u32 {
    BUILDER_ALLOC_FAILURE | BUILDER_IOVECTOR_FAILURE | BUILDER_PADDING_FAILURE | BUILDER_FREES_PDU
}

// Trace: `lib/smb2-cmd-close.c:smb2_cmd_close_async`, `lib/smb2-cmd-close.c:smb2_encode_close_request`
// Spec: smb2_cmd_close_async close request PDU construction#close request allocation or padding failure
// - **GIVEN** PDU 分配、close request buffer/iovector 分配或 64-bit padding 任一步失败
// - **WHEN** 调用 `smb2_cmd_close_async`
// - **THEN** 函数 MUST 返回 `NULL`，并在已分配 PDU 的失败路径释放该 PDU
#[test]
fn test_smb2_command_ffi_close_request_allocation_or_padding_failure() {
    has(
        command_probe().close_flags,
        builder_failure_flags() | BUILDER_NO_CALLBACK,
    );
}

// Trace: `lib/smb2-cmd-close.c:smb2_cmd_close_reply_async`, `lib/smb2-cmd-close.c:smb2_encode_close_reply`
// Spec: smb2_cmd_close_reply_async close reply PDU construction#close reply allocation or padding failure
// - **GIVEN** PDU 分配、close reply buffer/iovector 分配或 64-bit padding 任一步失败
// - **WHEN** 调用 `smb2_cmd_close_reply_async`
// - **THEN** 函数 MUST 返回 `NULL`，并在已分配 PDU 的失败路径释放该 PDU
#[test]
fn test_smb2_command_ffi_close_reply_allocation_or_padding_failure() {
    has(command_probe().close_flags, builder_failure_flags());
}

// Trace: `lib/smb2-cmd-close.c:smb2_process_close_fixed`
// Spec: smb2_process_close_fixed close reply fixed payload parsing#close reply payload allocation failure
// - **GIVEN** close reply fixed payload 尺寸有效但 `malloc(sizeof(*rep))` 失败
// - **WHEN** 调用 `smb2_process_close_fixed`
// - **THEN** 函数 MUST 设置 `Failed to allocate close reply` 错误消息并返回 `-1`
#[test]
fn test_smb2_command_ffi_close_reply_payload_allocation_failure() {
    has(command_probe().close_flags, FIXED_ALLOC_FAILURE);
}

// Trace: `lib/smb2-cmd-close.c:smb2_process_close_request_fixed`
// Spec: smb2_process_close_request_fixed close request fixed payload parsing#close request payload allocation failure
// - **GIVEN** close request fixed payload 尺寸有效但 `malloc(sizeof(*req))` 失败
// - **WHEN** 调用 `smb2_process_close_request_fixed`
// - **THEN** 函数 MUST 设置 `Failed to allocate close request` 错误消息并返回 `-1`
#[test]
fn test_smb2_command_ffi_close_request_payload_allocation_failure() {
    has(command_probe().close_flags, FIXED_ALLOC_FAILURE);
}

// Trace: `lib/smb2-cmd-create.c:smb2_cmd_create_async`, `lib/smb2-cmd-create.c:smb2_encode_create_request`, `include/smb2/libsmb2-raw.h:smb2_cmd_create_async`
// Spec: smb2_cmd_create_async create request PDU construction#encode create request with name and context
// - **GIVEN** 调用方提供包含 UTF-8 `req->name`、可选 `req->create_context` 和 create 字段的 `struct smb2_create_request`
// - **WHEN** 调用 `smb2_cmd_create_async(smb2, req, cb, cb_data)` 构造 RAW create 请求
// - **THEN** 返回的 PDU MUST 使用 SMB2_CREATE command，fixed request 写入安全标志、oplock、访问掩码、共享模式、处置和选项，非空名称 MUST 转为 UTF-16 并将 `/` 替换为 `\`，name 和 create context MUST 按 64-bit 边界 padding 后追加到输出 iovec
#[test]
fn test_smb2_command_ffi_encode_create_request_with_name_and_context() {
    let probe = command_probe();
    assert_eq!(probe.create_request_size, 57);
    has(probe.create_flags, UTF16_NAME | CONTEXT_POINTER);
}

// Trace: `lib/smb2-cmd-create.c:smb2_cmd_create_async`, `lib/smb2-cmd-create.c:smb2_encode_create_request`, `include/smb2/libsmb2-raw.h:smb2_cmd_create_async`
// Spec: smb2_cmd_create_async create request PDU construction#fail without invoking callback on local setup error
// - **GIVEN** PDU allocation、request buffer allocation、UTF-16 conversion、iovector append 或 final padding 任一步失败
// - **WHEN** 调用 `smb2_cmd_create_async(smb2, req, cb, cb_data)`
// - **THEN** 函数 MUST 返回 `NULL`，本地已分配的 PDU MUST 释放，且 header 注释承诺 callback 不会被调用
#[test]
fn test_smb2_command_ffi_fail_without_invoking_callback_on_local_setup_error() {
    has(
        command_probe().create_flags,
        builder_failure_flags() | BUILDER_NO_CALLBACK | UTF16_NAME,
    );
}

// Trace: `lib/smb2-cmd-create.c:smb2_cmd_create_reply_async`, `lib/smb2-cmd-create.c:smb2_encode_create_reply`, `include/smb2/libsmb2-raw.h:smb2_cmd_create_reply_async`
// Spec: smb2_cmd_create_reply_async create reply PDU construction#encode create reply with file id and optional context
// - **GIVEN** 调用方提供包含 oplock、flags、create_action、时间戳、大小、属性、`file_id` 和可选 create context 的 `struct smb2_create_reply`
// - **WHEN** 调用 `smb2_cmd_create_reply_async(smb2, rep, cb, cb_data)`
// - **THEN** 返回的 PDU MUST 写入 SMB2_CREATE reply fixed fields，MUST 复制 `SMB2_FD_SIZE` 字节 file id，MUST 将 `create_context_offset` 设为 fixed reply 后的 64-bit aligned offset，并在存在 create context 时追加 padded context buffer
#[test]
fn test_smb2_command_ffi_encode_create_reply_with_file_id_and_optional_context() {
    let probe = command_probe();
    assert_eq!(probe.create_reply_size, 89);
    has(
        probe.create_flags,
        CONTEXT_POINTER | VARIABLE_PRESENT | VARIABLE_ABSENT,
    );
}

// Trace: `lib/smb2-cmd-create.c:smb2_cmd_create_reply_async`, `lib/smb2-cmd-create.c:smb2_encode_create_reply`
// Spec: smb2_cmd_create_reply_async create reply PDU construction#release PDU on reply encoding failure
// - **GIVEN** reply PDU allocation 后，fixed reply buffer、context buffer、iovector append 或 final padding 失败
// - **WHEN** 调用 `smb2_cmd_create_reply_async(smb2, rep, cb, cb_data)`
// - **THEN** 函数 MUST 释放已分配 PDU 并返回 `NULL`
#[test]
fn test_smb2_command_ffi_release_pdu_on_reply_encoding_failure() {
    has(command_probe().create_flags, builder_failure_flags());
}

// Trace: `lib/smb2-cmd-create.c:smb2_process_create_fixed`, `include/libsmb2-private.h:smb2_process_create_fixed`
// Spec: smb2_process_create_fixed parse create reply fixed payload#reject invalid create reply fixed size
// - **GIVEN** 当前输入 iovec 的 structure size 不等于 `SMB2_CREATE_REPLY_SIZE` 或 masked structure size 不等于 iovec 长度
// - **WHEN** 调用 `smb2_process_create_fixed(smb2, pdu)`
// - **THEN** 函数 MUST 设置错误并返回 `-1`，且不得向调用方暴露成功解析的 reply payload
#[test]
fn test_smb2_command_ffi_reject_invalid_create_reply_fixed_size() {
    has(
        command_probe().create_flags,
        FIXED_INVALID_SIZE | FIXED_PAYLOAD_CLEANUP,
    );
}

// Trace: `lib/smb2-cmd-create.c:smb2_process_create_fixed`, `include/libsmb2-private.h:smb2_process_create_fixed`
// Spec: smb2_process_create_fixed parse create reply fixed payload#parse reply fixed fields and return variable byte count
// - **GIVEN** create reply fixed payload 长度有效且包含非零 create context length
// - **WHEN** 调用 `smb2_process_create_fixed(smb2, pdu)`
// - **THEN** 函数 MUST 读取 oplock、flags、create_action、时间戳、大小、属性、file_id、context offset 和 length；当 context offset 不覆盖 fixed header 时 MUST 返回 context 前 padding 加 context length 的字节数
#[test]
fn test_smb2_command_ffi_parse_reply_fixed_fields_and_return_variable_byte_count() {
    has(command_probe().create_flags, VARIABLE_PRESENT);
}

// Trace: `lib/smb2-cmd-create.c:smb2_process_create_variable`, `include/libsmb2-private.h:smb2_process_create_variable`
// Spec: smb2_process_create_variable expose create reply context#bind reply context pointer when length is present
// - **GIVEN** `pdu->payload` 是已解析的 `struct smb2_create_reply` 且 `rep->create_context_length` 非零
// - **WHEN** 调用 `smb2_process_create_variable(smb2, pdu)`
// - **THEN** 函数 MUST 将 `rep->create_context` 设置为当前输入 iovec 中由 `rep->create_context_offset` 推导出的位置，并返回 `0`
#[test]
fn test_smb2_command_ffi_bind_reply_context_pointer_when_length_is_present() {
    has(
        command_probe().create_flags,
        VARIABLE_PRESENT | CONTEXT_POINTER,
    );
}

// Trace: `lib/smb2-cmd-create.c:smb2_process_create_variable`
// Spec: smb2_process_create_variable expose create reply context#clear reply context pointer when length is absent
// - **GIVEN** `pdu->payload` 是已解析的 `struct smb2_create_reply` 且 `rep->create_context_length` 为 0
// - **WHEN** 调用 `smb2_process_create_variable(smb2, pdu)`
// - **THEN** 函数 MUST 将 `rep->create_context` 保持为 `NULL` 并返回 `0`
#[test]
fn test_smb2_command_ffi_clear_reply_context_pointer_when_length_is_absent() {
    has(command_probe().create_flags, VARIABLE_ABSENT);
}

// Trace: `lib/smb2-cmd-create.c:smb2_process_create_request_fixed`, `include/libsmb2-private.h:smb2_process_create_request_fixed`
// Spec: smb2_process_create_request_fixed parse create request fixed payload#reject invalid request fixed size or overlapping variable offsets
// - **GIVEN** 当前输入 iovec 的 structure size 无效，或非零 name/create context offset 指向 SMB2 header 加 fixed request 区域之前
// - **WHEN** 调用 `smb2_process_create_request_fixed(smb2, pdu)`
// - **THEN** 函数 MUST 设置错误并返回 `-1`；对于 offset overlap 失败，函数 MUST 清除 `pdu->payload` 并释放已分配 request
#[test]
fn test_smb2_command_ffi_reject_invalid_request_fixed_size_or_overlapping_variable_offsets() {
    has(
        command_probe().create_flags,
        FIXED_INVALID_SIZE | FIXED_PAYLOAD_CLEANUP,
    );
}

// Trace: `lib/smb2-cmd-create.c:smb2_process_create_request_fixed`, `include/libsmb2-private.h:smb2_process_create_request_fixed`
// Spec: smb2_process_create_request_fixed parse create request fixed payload#parse request fixed fields and compute variable byte count
// - **GIVEN** create request fixed payload 长度有效，name 或 create context length 非零且 offsets 未覆盖 header
// - **WHEN** 调用 `smb2_process_create_request_fixed(smb2, pdu)`
// - **THEN** 函数 MUST 读取 request fixed fields，MUST 初始设置 `req->name` 为 `NULL`，并返回 name 区域、padding 和 create context length 所需的 remaining 字节数
#[test]
fn test_smb2_command_ffi_parse_request_fixed_fields_and_compute_variable_byte_count() {
    has(
        command_probe().create_flags,
        VARIABLE_PRESENT | VARIABLE_ABSENT,
    );
}

// Trace: `lib/smb2-cmd-create.c:smb2_process_create_request_variable`, `include/libsmb2-private.h:smb2_process_create_request_variable`
// Spec: smb2_process_create_request_variable decode request name and context#convert request name into SMB2-owned UTF-8 buffer
// - **GIVEN** `pdu->payload` 是已解析的 `struct smb2_create_request` 且 `req->name_length` 非零
// - **WHEN** 调用 `smb2_process_create_request_variable(smb2, pdu)`
// - **THEN** 函数 MUST 将 UTF-16 name 转为 UTF-8，MUST 使用 `smb2_alloc_init` 分配 SMB2-owned name buffer 并复制包含 NUL 结尾的字符串，转换或分配失败时 MUST 设置错误并返回 `-1`
#[test]
fn test_smb2_command_ffi_convert_request_name_into_smb2_owned_utf8_buffer() {
    has(command_probe().create_flags, UTF16_NAME);
}

// Trace: `lib/smb2-cmd-create.c:smb2_process_create_request_variable`
// Spec: smb2_process_create_request_variable decode request name and context#attach request create context without parsing it
// - **GIVEN** `req->create_context_length` 和 `req->create_context_offset` 均非零
// - **WHEN** 调用 `smb2_process_create_request_variable(smb2, pdu)`
// - **THEN** 函数 MUST 将 `req->create_context` 设置为当前输入 iovec 中 offset 指向的位置，且 MUST NOT 解析 create context 内容
#[test]
fn test_smb2_command_ffi_attach_request_create_context_without_parsing_it() {
    has(command_probe().create_flags, CONTEXT_POINTER);
}

// Trace: `lib/smb2-cmd-echo.c:smb2_cmd_echo_async`, `lib/smb2-cmd-echo.c:smb2_encode_echo_request`
// Spec: smb2_cmd_echo_async build echo request PDU#request 构造失败释放 PDU
// - **GIVEN** PDU 已分配但 echo request 编码或 64-bit padding 返回失败
// - **WHEN** `smb2_cmd_echo_async` 处理该失败路径
// - **THEN** 系统 MUST 调用 `smb2_free_pdu` 释放该 PDU 并返回 `NULL`
#[test]
fn test_smb2_command_ffi_echo_request_construction_failure_releases_pdu() {
    has(command_probe().echo_flags, builder_failure_flags());
}

// Trace: `lib/smb2-cmd-echo.c:smb2_cmd_echo_reply_async`, `lib/smb2-cmd-echo.c:smb2_encode_echo_reply`
// Spec: smb2_cmd_echo_reply_async build echo reply PDU#reply 构造失败释放 PDU
// - **GIVEN** PDU 已分配但 echo reply 编码或 64-bit padding 返回失败
// - **WHEN** `smb2_cmd_echo_reply_async` 处理该失败路径
// - **THEN** 系统 MUST 调用 `smb2_free_pdu` 释放该 PDU 并返回 `NULL`
#[test]
fn test_smb2_command_ffi_echo_reply_construction_failure_releases_pdu() {
    has(command_probe().echo_flags, builder_failure_flags());
}

// Trace: `lib/smb2-cmd-echo.c:smb2_process_echo_request_fixed`, `include/libsmb2-private.h:smb2_process_echo_request_fixed`
// Spec: smb2_process_echo_request_fixed validate echo request fixed segment#request payload allocation failure
// - **GIVEN** ECHO request 固定段尺寸校验通过但 `malloc(sizeof(*req))` 返回 `NULL`
// - **WHEN** `smb2_process_echo_request_fixed` 分配请求 payload
// - **THEN** 函数 MUST 调用 `smb2_set_error` 记录 allocation failure 并返回 `-1`
#[test]
fn test_smb2_command_ffi_echo_request_payload_allocation_failure() {
    has(command_probe().echo_flags, FIXED_ALLOC_FAILURE);
}

// Trace: `lib/smb2-cmd-error.c:smb2_cmd_error_reply_async`, `lib/smb2-cmd-error.c:smb2_encode_error_reply`
// Spec: smb2_cmd_error_reply_async build SMB2 error response PDU#Allocation or encoding failure
// - **GIVEN** PDU 分配、error reply buffer 分配、iovector 添加或 64-bit padding 任一步失败。
// - **WHEN** 调用方调用 `smb2_cmd_error_reply_async(smb2, rep, causing_command, status, cb, cb_data)`。
// - **THEN** 函数返回 `NULL`，并在已分配 PDU 后发生失败时释放该 PDU。
#[test]
fn test_smb2_command_ffi_error_allocation_or_encoding_failure() {
    has(command_probe().error_flags, builder_failure_flags());
}

// Trace: `lib/smb2-cmd-error.c:smb2_process_error_fixed`
// Spec: smb2_process_error_fixed validate and decode fixed error reply#Payload allocation failure
// - **GIVEN** fixed payload size 校验通过，但分配 `struct smb2_error_reply` 失败。
// - **WHEN** `smb2_process_error_fixed(smb2, pdu)` 继续处理 payload。
// - **THEN** 函数设置上下文错误消息 `Failed to allocate error reply` 并返回 `-1`。
#[test]
fn test_smb2_command_ffi_error_payload_allocation_failure() {
    has(command_probe().error_flags, FIXED_ALLOC_FAILURE);
}

// Trace: `lib/smb2-cmd-flush.c:smb2_cmd_flush_async`, `lib/smb2-cmd-flush.c:smb2_encode_flush_request`
// Spec: smb2_cmd_flush_async 构造客户端 FLUSH PDU#PDU 分配或编码失败
// - **GIVEN** PDU 分配、flush request 缓冲区分配、iovector 添加或 64-bit padding 任一步失败
// - **WHEN** 调用 `smb2_cmd_flush_async(smb2, req, cb, cb_data)`
// - **THEN** 返回值 MUST 为 `NULL`，且已分配的 PDU MUST 在编码或 padding 失败路径释放
#[test]
fn test_smb2_command_ffi_flush_pdu_allocation_or_encoding_failure() {
    has(command_probe().flush_flags, builder_failure_flags());
}

// Trace: `lib/smb2-cmd-flush.c:smb2_cmd_flush_reply_async`, `lib/smb2-cmd-flush.c:smb2_encode_flush_reply`
// Spec: smb2_cmd_flush_reply_async 构造服务端 FLUSH reply PDU#Reply 构造失败
// - **GIVEN** PDU 分配、flush reply 缓冲区分配、iovector 添加或 64-bit padding 任一步失败
// - **WHEN** 调用 `smb2_cmd_flush_reply_async(smb2, cb, cb_data)`
// - **THEN** 返回值 MUST 为 `NULL`，且已分配的 PDU MUST 在编码或 padding 失败路径释放
#[test]
fn test_smb2_command_ffi_flush_reply_construction_failure() {
    has(command_probe().flush_flags, builder_failure_flags());
}

// Trace: `lib/smb2-cmd-flush.c:smb2_process_flush_request_fixed`, `lib/pdu.c:smb2_process_request_payload_fixed`
// Spec: smb2_process_flush_request_fixed 解析 FLUSH request 固定区#Request 固定区大小无效或分配失败
// - **GIVEN** `StructureSize` 不等于 `SMB2_FLUSH_REQUEST_SIZE`、偶数化长度不匹配，或 `struct smb2_flush_request` 分配失败
// - **WHEN** 调用 `smb2_process_flush_request_fixed(smb2, pdu)`
// - **THEN** 函数 MUST 返回 `-1`，大小无效时 MUST 记录 unexpected flush request size，分配失败时 MUST 记录 failed to allocate flush request
#[test]
fn test_smb2_command_ffi_flush_request_fixed_size_invalid_or_allocation_failure() {
    has(
        command_probe().flush_flags,
        FIXED_INVALID_SIZE | FIXED_ALLOC_FAILURE,
    );
}

// Trace: `lib/smb2-cmd-ioctl.c:smb2_cmd_ioctl_async`, `lib/smb2-cmd-ioctl.c:smb2_encode_ioctl_request`, `include/smb2/libsmb2-raw.h:smb2_cmd_ioctl_async`
// Spec: smb2_cmd_ioctl_async build ioctl request PDU#request with optional input buffer
// - **GIVEN** a valid `struct smb2_ioctl_request` whose `ctl_code`, `file_id`, `input_count`, `input`, and `flags` describe an ioctl request
// - **WHEN** `smb2_cmd_ioctl_async` is called with a context, request, callback, and callback data
// - **THEN** the returned PDU MUST use command `SMB2_IOCTL`, encode `SMB2_IOCTL_REQUEST_SIZE`, `ctl_code`, `file_id`, input offset, input count, max input response `0`, max output response `65535`, and flags, and append the input buffer only when `input_count` is nonzero
#[test]
fn test_smb2_command_ffi_ioctl_request_with_optional_input_buffer() {
    let probe = command_probe();
    assert_eq!(probe.ioctl_request_size, 57);
    has(probe.ioctl_flags, VARIABLE_PRESENT | VARIABLE_ABSENT);
}

// Trace: `lib/smb2-cmd-ioctl.c:smb2_cmd_ioctl_async`, `lib/smb2-cmd-ioctl.c:smb2_encode_ioctl_request`, `include/smb2/libsmb2-raw.h:smb2_cmd_ioctl_async`
// Spec: smb2_cmd_ioctl_async build ioctl request PDU#request construction failure
// - **GIVEN** PDU allocation, ioctl fixed-buffer allocation, iovector append, or final padding fails
// - **WHEN** `smb2_cmd_ioctl_async` attempts to construct the ioctl request PDU
// - **THEN** the function MUST return `NULL`, free an allocated PDU on encode or padding failure, and preserve the documented no-callback-on-error contract
#[test]
fn test_smb2_command_ffi_ioctl_request_construction_failure() {
    has(
        command_probe().ioctl_flags,
        builder_failure_flags() | BUILDER_NO_CALLBACK,
    );
}

// Trace: `lib/smb2-cmd-ioctl.c:smb2_cmd_ioctl_reply_async`, `lib/smb2-cmd-ioctl.c:smb2_encode_ioctl_reply`, `lib/libsmb2.c:smb2_ioctl_request_cb`
// Spec: smb2_cmd_ioctl_reply_async build ioctl reply PDU#validate negotiate reply encoding
// - **GIVEN** a reply with `ctl_code` equal to `SMB2_FSCTL_VALIDATE_NEGOTIATE_INFO` and an output pointer to `struct smb2_ioctl_validate_negotiate_info`
// - **WHEN** `smb2_cmd_ioctl_reply_async` builds the reply PDU
// - **THEN** the output payload MUST be encoded as capabilities, 16-byte GUID, security mode, and dialect, and the fixed reply MUST report output count `SMB2_IOCTL_VALIDIATE_NEGOTIATE_INFO_SIZE`
#[test]
fn test_smb2_command_ffi_ioctl_validate_negotiate_reply_encoding() {
    has(command_probe().ioctl_flags, VARIABLE_PRESENT);
}

// Trace: `lib/smb2-cmd-ioctl.c:smb2_cmd_ioctl_reply_async`, `lib/smb2-cmd-ioctl.c:smb2_encode_ioctl_reply`, `lib/libsmb2.c:smb2_ioctl_request_cb`
// Spec: smb2_cmd_ioctl_reply_async build ioctl reply PDU#passthrough reply encoding
// - **GIVEN** a reply with nonzero `output_count` and a control code not handled locally
// - **WHEN** `smb2_cmd_ioctl_reply_async` builds the reply while `smb2->passthrough` is enabled
// - **THEN** the output payload MUST be copied byte-for-byte from `rep->output`, the iovector length MUST match `rep->output_count`, and the fixed reply MUST include the original flags and file id
#[test]
fn test_smb2_command_ffi_ioctl_passthrough_reply_encoding() {
    has(command_probe().ioctl_flags, PASSTHROUGH);
}

// Trace: `lib/smb2-cmd-ioctl.c:smb2_cmd_ioctl_reply_async`, `lib/smb2-cmd-ioctl.c:smb2_encode_ioctl_reply`
// Spec: smb2_cmd_ioctl_reply_async build ioctl reply PDU#unsupported non-passthrough reply output
// - **GIVEN** a reply with nonzero `output_count`, an unhandled control code, and `smb2->passthrough` disabled
// - **WHEN** `smb2_cmd_ioctl_reply_async` attempts to encode the output payload
// - **THEN** the function MUST set an error for the unhandled code, free the allocated PDU through the caller path, and return `NULL`
#[test]
fn test_smb2_command_ffi_ioctl_unsupported_non_passthrough_reply_output() {
    has(
        command_probe().ioctl_flags,
        UNSUPPORTED_ERROR | BUILDER_FREES_PDU,
    );
}

// Trace: `lib/smb2-cmd-ioctl.c:smb2_process_ioctl_fixed`, `lib/pdu.c:smb2_process_reply_payload_fixed`
// Spec: smb2_process_ioctl_fixed parse ioctl reply fixed body#fixed reply without output
// - **GIVEN** an incoming SMB2 ioctl reply fixed body with structure size `SMB2_IOCTL_REPLY_SIZE`, matching even wire length, and `output_count` equal to zero
// - **WHEN** `smb2_process_ioctl_fixed` parses the payload
// - **THEN** it MUST allocate the reply payload, populate `ctl_code`, `file_id`, offsets, counts, and flags, store it in `pdu->payload`, and return `0`
#[test]
fn test_smb2_command_ffi_ioctl_fixed_reply_without_output() {
    has(command_probe().ioctl_flags, VARIABLE_ABSENT);
}

// Trace: `lib/smb2-cmd-ioctl.c:smb2_process_ioctl_fixed`, `lib/pdu.c:smb2_process_reply_payload_fixed`
// Spec: smb2_process_ioctl_fixed parse ioctl reply fixed body#fixed reply with output buffer
// - **GIVEN** an incoming SMB2 ioctl reply fixed body with nonzero `output_count` and an `output_offset` at or after the end of the fixed ioctl reply body
// - **WHEN** `smb2_process_ioctl_fixed` parses the payload
// - **THEN** it MUST return `IOV_OFFSET_IOCTL + PAD_TO_64BIT(rep->input_count) + rep->output_count` so the caller reads the complete variable payload including passthrough input padding
#[test]
fn test_smb2_command_ffi_ioctl_fixed_reply_with_output_buffer() {
    has(command_probe().ioctl_flags, VARIABLE_PRESENT);
}

// Trace: `lib/smb2-cmd-ioctl.c:smb2_process_ioctl_fixed`, `lib/pdu.c:smb2_process_reply_payload_fixed`
// Spec: smb2_process_ioctl_fixed parse ioctl reply fixed body#malformed fixed reply
// - **GIVEN** an incoming fixed reply with an unexpected structure size, mismatched fixed body length, allocation failure, or output offset overlapping the fixed header
// - **WHEN** `smb2_process_ioctl_fixed` validates the fixed body
// - **THEN** it MUST return `-1`, set an error for size, allocation, or overlap failures where implemented, and clear/free `pdu->payload` when overlap is detected after allocation
#[test]
fn test_smb2_command_ffi_ioctl_malformed_fixed_reply() {
    has(
        command_probe().ioctl_flags,
        FIXED_INVALID_SIZE | FIXED_PAYLOAD_CLEANUP,
    );
}

// Trace: `lib/smb2-cmd-ioctl.c:smb2_process_ioctl_variable`, `lib/smb2-data-reparse-point.c:smb2_decode_reparse_data_buffer`, `lib/pdu.c:smb2_process_reply_payload_variable`
// Spec: smb2_process_ioctl_variable parse ioctl reply variable body#reparse-point output decoding
// - **GIVEN** `pdu->payload` is an ioctl reply whose `ctl_code` is `SMB2_FSCTL_GET_REPARSE_POINT` and whose variable payload fits the iovector
// - **WHEN** `smb2_process_ioctl_variable` parses the variable payload
// - **THEN** it MUST allocate a `struct smb2_reparse_data_buffer`, decode the reparse data buffer from the computed output vector, assign it to `rep->output`, and return `0` when decoding succeeds
#[test]
fn test_smb2_command_ffi_ioctl_reparse_point_output_decoding() {
    has(command_probe().ioctl_flags, VARIABLE_PRESENT);
}

// Trace: `lib/smb2-cmd-ioctl.c:smb2_process_ioctl_variable`, `lib/pdu.c:smb2_process_reply_payload_variable`
// Spec: smb2_process_ioctl_variable parse ioctl reply variable body#default output copy
// - **GIVEN** `pdu->payload` is an ioctl reply with an unhandled control code and the output payload fits the iovector
// - **WHEN** `smb2_process_ioctl_variable` parses the variable payload
// - **THEN** it MUST allocate `rep->output_count` bytes from the SMB2 memory context, copy bytes from the computed output offset, assign the allocation to `rep->output`, and return `0`
#[test]
fn test_smb2_command_ffi_ioctl_default_output_copy() {
    has(command_probe().ioctl_flags, VARIABLE_PRESENT);
}

// Trace: `lib/smb2-cmd-ioctl.c:smb2_process_ioctl_variable`, `lib/pdu.c:smb2_process_reply_payload_variable`
// Spec: smb2_process_ioctl_variable parse ioctl reply variable body#invalid reply variable length
// - **GIVEN** `rep->output_count` is greater than the bytes available after `IOV_OFFSET_IOCTL`
// - **WHEN** `smb2_process_ioctl_variable` validates the variable payload
// - **THEN** it MUST return `-EINVAL` without assigning a decoded output pointer
#[test]
fn test_smb2_command_ffi_ioctl_invalid_reply_variable_length() {
    has(command_probe().ioctl_flags, FIXED_INVALID_SIZE);
}

// Trace: `lib/smb2-cmd-ioctl.c:smb2_process_ioctl_request_fixed`, `lib/pdu.c:smb2_process_request_payload_fixed`
// Spec: smb2_process_ioctl_request_fixed parse ioctl request fixed body#fixed request without input
// - **GIVEN** an incoming SMB2 ioctl request fixed body with structure size `SMB2_IOCTL_REQUEST_SIZE`, matching even wire length, and `input_count` equal to zero
// - **WHEN** `smb2_process_ioctl_request_fixed` parses the payload
// - **THEN** it MUST allocate the request payload, populate `ctl_code`, `file_id`, offsets, counts, response limits, and flags, store it in `pdu->payload`, and return `0`
#[test]
fn test_smb2_command_ffi_ioctl_fixed_request_without_input() {
    has(command_probe().ioctl_flags, VARIABLE_ABSENT);
}

// Trace: `lib/smb2-cmd-ioctl.c:smb2_process_ioctl_request_fixed`, `lib/pdu.c:smb2_process_request_payload_fixed`
// Spec: smb2_process_ioctl_request_fixed parse ioctl request fixed body#fixed request with input buffer
// - **GIVEN** an incoming SMB2 ioctl request fixed body with nonzero `input_count` and an `input_offset` at or after the end of the fixed ioctl request body
// - **WHEN** `smb2_process_ioctl_request_fixed` parses the payload
// - **THEN** it MUST return `IOVREQ_OFFSET_IOCTL + req->input_count` so the caller reads the complete input variable payload
#[test]
fn test_smb2_command_ffi_ioctl_fixed_request_with_input_buffer() {
    has(command_probe().ioctl_flags, VARIABLE_PRESENT);
}

// Trace: `lib/smb2-cmd-ioctl.c:smb2_process_ioctl_request_fixed`, `lib/pdu.c:smb2_process_request_payload_fixed`
// Spec: smb2_process_ioctl_request_fixed parse ioctl request fixed body#malformed fixed request
// - **GIVEN** an incoming fixed request with an unexpected structure size, mismatched fixed body length, allocation failure, or input offset overlapping the fixed header
// - **WHEN** `smb2_process_ioctl_request_fixed` validates the fixed body
// - **THEN** it MUST return `-1`, set an error for size, allocation, or overlap failures where implemented, and clear/free `pdu->payload` when overlap is detected after allocation
#[test]
fn test_smb2_command_ffi_ioctl_malformed_fixed_request() {
    has(
        command_probe().ioctl_flags,
        FIXED_INVALID_SIZE | FIXED_PAYLOAD_CLEANUP,
    );
}

// Trace: `lib/smb2-cmd-ioctl.c:smb2_process_ioctl_request_variable`, `lib/libsmb2.c:smb2_ioctl_request_cb`, `lib/pdu.c:smb2_process_request_payload_variable`
// Spec: smb2_process_ioctl_request_variable parse ioctl request variable body#validate negotiate request decoding
// - **GIVEN** `pdu->payload` is an ioctl request whose `ctl_code` is `SMB2_FSCTL_VALIDATE_NEGOTIATE_INFO` and whose input payload fits the iovector
// - **WHEN** `smb2_process_ioctl_request_variable` parses the variable payload
// - **THEN** it MUST allocate a `struct smb2_ioctl_validate_negotiate_info`, decode capabilities, GUID, security mode, and dialect from the input vector, set `req->input_count` to the structure size, assign the allocation to `req->input`, and return `0`
#[test]
fn test_smb2_command_ffi_ioctl_validate_negotiate_request_decoding() {
    has(command_probe().ioctl_flags, VARIABLE_PRESENT);
}

// Trace: `lib/smb2-cmd-ioctl.c:smb2_process_ioctl_request_variable`, `lib/libsmb2.c:smb2_ioctl_request_cb`, `lib/pdu.c:smb2_process_request_payload_variable`
// Spec: smb2_process_ioctl_request_variable parse ioctl request variable body#unknown passthrough request input
// - **GIVEN** `pdu->payload` is an ioctl request with an unhandled control code, the input payload fits the iovector, and `smb2->passthrough` is enabled
// - **WHEN** `smb2_process_ioctl_request_variable` parses the variable payload
// - **THEN** it MUST set `req->input` to the incoming vector buffer, set `req->input_count` to the available vector length, and return `0` so the server handler can decode the bytes
#[test]
fn test_smb2_command_ffi_ioctl_unknown_passthrough_request_input() {
    has(command_probe().ioctl_flags, PASSTHROUGH);
}

// Trace: `lib/smb2-cmd-ioctl.c:smb2_process_ioctl_request_variable`, `lib/pdu.c:smb2_process_request_payload_variable`
// Spec: smb2_process_ioctl_request_variable parse ioctl request variable body#unsupported non-passthrough request input
// - **GIVEN** `pdu->payload` is an ioctl request with an unhandled control code and `smb2->passthrough` disabled
// - **WHEN** `smb2_process_ioctl_request_variable` parses the variable payload
// - **THEN** it MUST set an error for the unhandled ioctl request, leave `req->input` as `NULL`, and return `0`
#[test]
fn test_smb2_command_ffi_ioctl_unsupported_non_passthrough_request_input() {
    has(command_probe().ioctl_flags, UNSUPPORTED_ERROR);
}

// Trace: `lib/smb2-cmd-ioctl.c:smb2_process_ioctl_request_variable`, `lib/pdu.c:smb2_process_request_payload_variable`
// Spec: smb2_process_ioctl_request_variable parse ioctl request variable body#invalid request variable length
// - **GIVEN** `req->input_count` is greater than the bytes available after `IOVREQ_OFFSET_IOCTL`
// - **WHEN** `smb2_process_ioctl_request_variable` validates the variable payload
// - **THEN** it MUST return `-EINVAL` without assigning a decoded input pointer
#[test]
fn test_smb2_command_ffi_ioctl_invalid_request_variable_length() {
    has(command_probe().ioctl_flags, FIXED_INVALID_SIZE);
}

// Trace: `lib/smb2-cmd-lock.c:smb2_cmd_lock_async`, `lib/smb2-cmd-lock.c:smb2_encode_lock_request`
// Spec: smb2_cmd_lock_async build lock request PDU#fail request allocation or padding
// - **GIVEN** PDU allocation, request body allocation, iovector attachment, lock element allocation, or 64-bit padding fails
// - **WHEN** `smb2_cmd_lock_async` attempts to build the request PDU
// - **THEN** the function returns `NULL`, frees any allocated PDU after encode or padding failure, and records an error for encode allocation or iovector failures
#[test]
fn test_smb2_command_ffi_lock_fail_request_allocation_or_padding() {
    has(command_probe().lock_flags, builder_failure_flags());
}

// Trace: `lib/smb2-cmd-lock.c:smb2_cmd_lock_reply_async`, `lib/smb2-cmd-lock.c:smb2_encode_lock_reply`
// Spec: smb2_cmd_lock_reply_async build lock reply PDU#fail reply allocation or padding
// - **GIVEN** PDU allocation, reply buffer allocation, iovector attachment, or 64-bit padding fails
// - **WHEN** `smb2_cmd_lock_reply_async` attempts to build the reply PDU
// - **THEN** the function returns `NULL`, frees any allocated PDU after encode or padding failure, and records an error for encode allocation or iovector failures
#[test]
fn test_smb2_command_ffi_lock_fail_reply_allocation_or_padding() {
    has(command_probe().lock_flags, builder_failure_flags());
}

// Trace: `lib/smb2-cmd-lock.c:smb2_process_lock_request_fixed`, `lib/alloc.c:smb2_alloc_init`
// Spec: smb2_process_lock_request_fixed parse lock request fixed body#fail lock request allocation
// - **GIVEN** allocation of the request payload or lock element array fails
// - **WHEN** `smb2_process_lock_request_fixed` parses the fixed request payload
// - **THEN** the function records an allocation error, returns `-1`, and clears/frees the request payload when the element array allocation fails
#[test]
fn test_smb2_command_ffi_lock_fail_lock_request_allocation() {
    has(command_probe().lock_flags, FIXED_ALLOC_FAILURE);
}

// Trace: `lib/smb2-cmd-logoff.c:smb2_cmd_logoff_async`, `lib/smb2-cmd-logoff.c:smb2_encode_logoff_request`
// Spec: smb2_cmd_logoff_async build logoff request PDU#logoff 请求构造失败释放 PDU
// - **GIVEN** LOGOFF PDU 已分配但 request 编码或 64-bit padding 失败
// - **WHEN** `smb2_cmd_logoff_async` 处理该失败路径
// - **THEN** 函数 MUST 释放已分配 PDU 并返回 `NULL`
#[test]
fn test_smb2_command_ffi_logoff_request_construction_failure() {
    has(command_probe().logoff_flags, builder_failure_flags());
}

// Trace: `lib/smb2-cmd-logoff.c:smb2_cmd_logoff_reply_async`, `lib/smb2-cmd-logoff.c:smb2_encode_logoff_reply`
// Spec: smb2_cmd_logoff_reply_async build logoff reply PDU#logoff 响应构造失败释放 PDU
// - **GIVEN** LOGOFF reply PDU 已分配但 reply 编码或 64-bit padding 失败
// - **WHEN** `smb2_cmd_logoff_reply_async` 处理该失败路径
// - **THEN** 函数 MUST 释放已分配 PDU 并返回 `NULL`
#[test]
fn test_smb2_command_ffi_logoff_reply_construction_failure() {
    has(command_probe().logoff_flags, builder_failure_flags());
}

// Trace: `lib/smb2-cmd-logoff.c:smb2_process_logoff_request_fixed`, `lib/pdu.c:smb2_process_request_payload_fixed`
// Spec: smb2_process_logoff_request_fixed validate and attach logoff request payload#logoff request payload 分配失败
// - **GIVEN** fixed payload 大小检查通过但 `struct smb2_logoff_request` 分配失败
// - **WHEN** 调用 `smb2_process_logoff_request_fixed(smb2, pdu)`
// - **THEN** 函数 MUST 设置错误信息并返回 `-1`
#[test]
fn test_smb2_command_ffi_logoff_request_payload_allocation_failure() {
    has(command_probe().logoff_flags, FIXED_ALLOC_FAILURE);
}

// Trace: `lib/smb2-cmd-negotiate.c:smb2_cmd_negotiate_async`
// Spec: smb2_cmd_negotiate_async builds negotiate request PDU#request PDU construction fails
// - **GIVEN** PDU 分配成功但 request 编码或 64-bit padding 返回失败
// - **WHEN** 调用 `smb2_cmd_negotiate_async`
// - **THEN** 系统 MUST 释放已分配 PDU 并返回 `NULL`，且不会向调用方返回部分构造的 PDU
#[test]
fn test_smb2_command_ffi_negotiate_request_pdu_construction_fails() {
    has(command_probe().negotiate_flags, builder_failure_flags());
}

// Trace: `lib/smb2-cmd-negotiate.c:smb2_cmd_negotiate_reply_async`
// Spec: smb2_cmd_negotiate_reply_async builds negotiate reply PDU#reply PDU construction fails
// - **GIVEN** PDU 分配成功但 reply 编码或 64-bit padding 返回失败
// - **WHEN** 调用 `smb2_cmd_negotiate_reply_async`
// - **THEN** 系统 MUST 释放已分配 PDU 并返回 `NULL`
#[test]
fn test_smb2_command_ffi_negotiate_reply_pdu_construction_fails() {
    has(command_probe().negotiate_flags, builder_failure_flags());
}

// Trace: `lib/smb2-cmd-notify-change.c:smb2_cmd_change_notify_async`, `lib/smb2-cmd-notify-change.c:smb2_encode_change_notify_request`
// Spec: smb2_cmd_change_notify_async request PDU construction#request PDU allocation or encoding failure
// - **GIVEN** PDU 分配、请求缓冲区分配、iovector 添加或 64-bit padding 任一环节失败
// - **WHEN** 调用 `smb2_cmd_change_notify_async`
// - **THEN** 接口 MUST 返回 `NULL`，并且在 PDU 已分配时释放该 PDU
#[test]
fn test_smb2_command_ffi_notify_change_request_pdu_allocation_or_encoding_failure() {
    has(command_probe().notify_change_flags, builder_failure_flags());
}

// Trace: `lib/smb2-cmd-oplock-break.c:smb2_cmd_oplock_break_async`, `lib/smb2-cmd-oplock-break.c:smb2_encode_oplock_break_acknowledgement`
// Spec: smb2_cmd_oplock_break_async builds acknowledgement PDU#构造 acknowledgement 失败
// - **GIVEN** PDU 分配、payload iovector 添加或 64-bit padding 任一步骤失败
// - **WHEN** 调用 `smb2_cmd_oplock_break_async`
// - **THEN** 函数 MUST 返回 NULL，且在已分配 PDU 后发生失败时释放该 PDU
#[test]
fn test_smb2_command_ffi_oplock_acknowledgement_construction_failure() {
    has(command_probe().oplock_break_flags, builder_failure_flags());
}

// Trace: `lib/smb2-cmd-oplock-break.c:smb2_cmd_oplock_break_reply_async`, `lib/smb2-cmd-oplock-break.c:smb2_encode_oplock_break_reply`
// Spec: smb2_cmd_oplock_break_reply_async builds reply PDU#构造 reply 失败
// - **GIVEN** PDU 分配、reply buffer 分配、iovector 添加或 padding 失败
// - **WHEN** 调用 `smb2_cmd_oplock_break_reply_async`
// - **THEN** 函数 MUST 返回 NULL，且已分配 PDU 的失败路径释放 PDU
#[test]
fn test_smb2_command_ffi_oplock_reply_construction_failure() {
    has(command_probe().oplock_break_flags, builder_failure_flags());
}

// Trace: `lib/smb2-cmd-oplock-break.c:smb2_cmd_lease_break_async`, `lib/smb2-cmd-oplock-break.c:smb2_encode_lease_break_acknowledgement`
// Spec: smb2_cmd_lease_break_async builds lease acknowledgement PDU#构造 lease acknowledgement 失败
// - **GIVEN** PDU 分配、buffer 分配、iovector 添加或 padding 失败
// - **WHEN** 调用 `smb2_cmd_lease_break_async`
// - **THEN** 函数 MUST 返回 NULL，且已分配 PDU 的失败路径释放 PDU
#[test]
fn test_smb2_command_ffi_lease_acknowledgement_construction_failure() {
    has(command_probe().oplock_break_flags, builder_failure_flags());
}

#[test]
fn test_smb2_command_ffi_tree_disconnect_request_pdu_success() {
    let probe = command_probe();
    assert_eq!(probe.tree_disconnect_request_size, 4);
    has(probe.tree_disconnect_flags, builder_failure_flags());
}

// Trace: `lib/smb2-cmd-tree-disconnect.c:smb2_cmd_tree_disconnect_async`, `lib/smb2-cmd-tree-disconnect.c:smb2_encode_tree_disconnect_request`
// Spec: smb2_cmd_tree_disconnect_async request PDU creation#创建请求 PDU 失败
// - **GIVEN** PDU 分配、请求编码或 64 位填充任一步骤失败
// - **WHEN** 调用 `smb2_cmd_tree_disconnect_async`
// - **THEN** 函数 MUST 返回 `NULL`，并且在 PDU 已分配的失败路径上 MUST 调用 `smb2_free_pdu` 释放该 PDU
#[test]
fn test_smb2_command_ffi_tree_disconnect_request_pdu_failure() {
    has(
        command_probe().tree_disconnect_flags,
        builder_failure_flags(),
    );
}

#[test]
fn test_smb2_command_ffi_tree_disconnect_reply_pdu_success() {
    let probe = command_probe();
    assert_eq!(probe.tree_disconnect_reply_size, 4);
    has(probe.tree_disconnect_flags, builder_failure_flags());
}

// Trace: `lib/smb2-cmd-tree-disconnect.c:smb2_cmd_tree_disconnect_reply_async`, `lib/smb2-cmd-tree-disconnect.c:smb2_encode_tree_disconnect_reply`
// Spec: smb2_cmd_tree_disconnect_reply_async reply PDU creation#创建响应 PDU 失败
// - **GIVEN** PDU 分配、响应编码或 64 位填充任一步骤失败
// - **WHEN** 调用 `smb2_cmd_tree_disconnect_reply_async`
// - **THEN** 函数 MUST 返回 `NULL`，并且在 PDU 已分配的失败路径上 MUST 调用 `smb2_free_pdu` 释放该 PDU
#[test]
fn test_smb2_command_ffi_tree_disconnect_reply_pdu_failure() {
    has(
        command_probe().tree_disconnect_flags,
        builder_failure_flags(),
    );
}

// Trace: `lib/smb2-cmd-write.c:smb2_cmd_write_async`, `lib/smb2-cmd-write.c:smb2_encode_write_request`
// Spec: smb2_cmd_write_async builds write request PDU#write request construction failure returns NULL
// - **GIVEN** PDU 分配、固定区编码、padding 或 payload iovec 追加任一步失败
// - **WHEN** 调用 `smb2_cmd_write_async(smb2, req, pass_buf_ownership, cb, cb_data)`
// - **THEN** 系统 MUST 释放已分配的 PDU 并返回 `NULL`，且不会返回部分构造的 WRITE PDU
#[test]
fn test_smb2_command_ffi_write_request_construction_failure() {
    has(command_probe().write_flags, builder_failure_flags());
}

// Trace: `lib/smb2-cmd-write.c:smb2_cmd_write_reply_async`, `lib/smb2-cmd-write.c:smb2_encode_write_reply`
// Spec: smb2_cmd_write_reply_async builds write reply PDU#write reply construction failure returns NULL
// - **GIVEN** PDU 分配、reply 固定区编码或 padding 失败
// - **WHEN** 调用 `smb2_cmd_write_reply_async(smb2, rep, cb, cb_data)`
// - **THEN** 系统 MUST 释放已分配的 PDU 并返回 `NULL`
#[test]
fn test_smb2_command_ffi_write_reply_construction_failure() {
    has(command_probe().write_flags, builder_failure_flags());
}

#[test]
fn test_smb2_command_ffi_write_fixed_payload_allocation_or_invalid_size() {
    has(
        command_probe().write_flags,
        FIXED_ALLOC_FAILURE | FIXED_INVALID_SIZE,
    );
}
