# lib/ntlmssp.c Specification

## Source Context

- Source: `lib/ntlmssp.c`
- Related Headers: `lib/ntlmssp.h`, `include/smb2/libsmb2.h`, `include/smb2/libsmb2-raw.h`, `include/libsmb2-private.h`, `lib/spnego-wrapper.h`, `lib/md4.h`, `lib/md5.h`, `lib/hmac-md5.h`
- Related Tests: `tests/ntlmssp_generate_blob.c`
- Related Dependencies: GitNexus context shows callers from `lib/libsmb2.c` session setup and `tests/ntlmssp_generate_blob.c`; outgoing dependencies include `lib/spnego-wrapper.c`, `lib/init.c`, `lib/hmac-md5.c`, `lib/compat.c`, and internal NTLM helpers.
- Build/Compile Context: C project with optional `HAVE_CONFIG_H`, standard/header feature macros, and optional SPNEGO/GSSAPI wrapping through included wrapper code.

## Interface Summary

| Interface | Kind | Signature | Decision | Reason |
| --- | --- | --- | --- | --- |
| `ntlmssp_init_context` | function | `struct auth_data * ntlmssp_init_context(const char *user, const char *password, const char *domain, const char *workstation, const char *client_challenge);` | Include | 公开声明的 NTLMSSP 上下文生命周期入口，分配认证状态、复制凭据并初始化 challenge/session-key 状态。 |
| `ntlmssp_destroy_context` | function | `void ntlmssp_destroy_context(struct auth_data *auth);` | Include | 公开声明的生命周期清理入口，释放上下文拥有的动态字段和上下文本身。 |
| `ntlmssp_set_spnego_wrapping` | function | `void ntlmssp_set_spnego_wrapping(struct auth_data *auth, int wrap);` | Include | 公开声明的状态设置入口，影响后续 blob 是否经 SPNEGO 包装。 |
| `ntlmssp_get_spnego_wrapping` | function | `int ntlmssp_get_spnego_wrapping(struct auth_data *auth);` | Include | 公开声明的状态查询入口，返回当前 SPNEGO 包装标志。 |
| `ntlmssp_get_message_type` | function | `int ntlmssp_get_message_type(struct smb2_context *smb2, uint8_t *ntlmssp_buffer, int len, int suppress_errors, uint32_t *message_type, uint8_t **ntlmssp_ptr, int *ntlmssp_len, int *is_wrapped);` | Include | 公开声明的 NTLMSSP/SPNEGO 解析入口，调用方可观察输出参数、错误码和 wrapped 标志。 |
| `ntlmssp_generate_blob` | function | `int ntlmssp_generate_blob(struct smb2_server *server, struct smb2_context *smb2, time_t t, struct auth_data *auth_data, unsigned char *input_buf, int input_len, unsigned char **output_buf, uint16_t *output_len);` | Include | 公开声明的客户端/服务端 NTLMSSP 握手核心入口，生成 negotiate、challenge、authenticate 或 auth-result blob。 |
| `ntlmssp_authenticate_blob` | function | `int ntlmssp_authenticate_blob(struct smb2_server *server, struct smb2_context *smb2, struct auth_data *auth_data, unsigned char *input_buf, int input_len);` | Include | 公开声明的服务端认证校验入口，解析 AUTHENTICATION_MESSAGE、调用授权处理器并验证 NT proof。 |
| `ntlmssp_get_authenticated` | function | `int ntlmssp_get_authenticated(struct auth_data *auth);` | Include | 公开声明的认证状态查询入口，被 session setup 路径用于判断服务端认证结果。 |
| `ntlmssp_get_session_key` | function | `int ntlmssp_get_session_key(struct auth_data *auth, uint8_t **key, uint8_t *key_size);` | Include | 公开声明的会话密钥导出入口，分配并返回 `SMB2_KEY_SIZE` 字节 key 副本。 |
| `ntlmssp_get_utf16_field` | function | `void ntlmssp_get_utf16_field(uint8_t *input_buf, int input_len, int offset, char **result);` | Skip | 仅在本实现文件内部使用，未在 `lib/ntlmssp.h` 声明，行为归属到 `ntlmssp_authenticate_blob`。 |
| `auth_data_set_password` | function | `static int auth_data_set_password(struct auth_data *auth_data, const char *password);` | Skip | `static` 内部 helper，仅管理上下文字段，行为归属到初始化和认证 blob 编码 Requirement。 |
| `auth_data_set_domain` | function | `static int auth_data_set_domain(struct auth_data *auth_data, const char *domain);` | Skip | `static` 内部 helper，仅管理上下文字段，行为归属到初始化和认证 blob 编码 Requirement。 |
| `encoder` | function | `static int encoder(const void *buffer, size_t size, void *ptr);` | Skip | `static` 内部缓冲追加 helper，调用方不可直接观察，错误语义归属到上层 blob 生成接口。 |
| `encode_ntlm_negotiate_message` | function | `static int encode_ntlm_negotiate_message(struct smb2_context *smb2, struct auth_data *auth_data);` | Skip | `static` 内部编码 helper，协商消息行为归属到 `ntlmssp_generate_blob`。 |
| `ntlm_decode_challenge_message` | function | `static int ntlm_decode_challenge_message(struct smb2_context *smb2, struct auth_data *auth_data, unsigned char *buf, size_t len);` | Skip | `static` 内部解析 helper，challenge 解析行为归属到 `ntlmssp_generate_blob`。 |
| `ntlm_convert_password_hash` | function | `static int ntlm_convert_password_hash(const char *password, unsigned char password_hash[16]);` | Skip | `static` 内部密码 hash helper，认证计算行为归属到 `ntlmssp_generate_blob` 和 `ntlmssp_authenticate_blob`。 |
| `NTOWFv1` | function | `static int NTOWFv1(const char *password, unsigned char password_hash[16]);` | Skip | `static` 内部 NT hash helper，认证计算行为归属到上层认证接口。 |
| `NTOWFv2` | function | `static int NTOWFv2(const char *user, const char *password, const char *domain, unsigned char ntlmv2_hash[16]);` | Skip | `static` 内部 NTLMv2 hash helper，认证计算行为归属到上层认证接口。 |
| `encode_temp` | function | `static int encode_temp(struct auth_data *auth_data, uint64_t t, uint8_t *client_challenge, size_t client_challenge_len, uint8_t *server_challenge, uint8_t *server_name, size_t server_name_len);` | Skip | `static` 内部 NTLMv2 temp buffer helper，输出归属到 `ntlmssp_generate_blob`。 |
| `encode_ntlm_auth` | function | `static int encode_ntlm_auth(struct smb2_context *smb2, time_t ti, struct auth_data *auth_data, char *server_challenge);` | Skip | `static` 内部 AUTHENTICATION_MESSAGE 编码 helper，行为归属到 `ntlmssp_generate_blob`。 |
| `encode_ntlm_challenge` | function | `static int encode_ntlm_challenge(struct smb2_context *smb2, struct auth_data *auth_data);` | Skip | `static` 内部 CHALLENGE_MESSAGE 编码 helper，行为归属到 `ntlmssp_generate_blob`。 |

## Data Model Summary

| Type/Macro | Kind | Definition | Notes |
| --- | --- | --- | --- |
| `struct auth_data` | struct | `lib/ntlmssp.c:84` | NTLMSSP 私有上下文，保存编码缓冲区、凭据、challenge、target info、认证状态和导出会话密钥。 |
| `NEGOTIATE_MESSAGE` | macro | `lib/ntlmssp.h:33` | NTLMSSP message type 常量，值为 `0x00000001`。 |
| `CHALLENGE_MESSAGE` | macro | `lib/ntlmssp.h:34` | NTLMSSP message type 常量，值为 `0x00000002`。 |
| `AUTHENTICATION_MESSAGE` | macro | `lib/ntlmssp.h:35` | NTLMSSP message type 常量，值为 `0x00000003`。 |
| `NTLMSSP_NEGOTIATE_56` | macro | `lib/ntlmssp.c:109` | 内部 negotiate flag，值为 `0x80000000`。 |
| `NTLMSSP_NEGOTIATE_KEY_EXCH` | macro | `lib/ntlmssp.c:110` | 内部 negotiate flag，值为 `0x40000000`。 |
| `NTLMSSP_NEGOTIATE_128` | macro | `lib/ntlmssp.c:111` | 内部 negotiate flag，值为 `0x20000000`。 |
| `NTLMSSP_NEGOTIATE_VERSION` | macro | `lib/ntlmssp.c:112` | 内部 negotiate flag，值为 `0x02000000`。 |
| `NTLMSSP_NEGOTIATE_TARGET_INFO` | macro | `lib/ntlmssp.c:113` | 内部 negotiate flag，值为 `0x00800000`。 |
| `NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY` | macro | `lib/ntlmssp.c:114` | 内部 negotiate flag，值为 `0x00080000`。 |
| `NTLMSSP_TARGET_TYPE_SERVER` | macro | `lib/ntlmssp.c:115` | 内部 target type flag，值为 `0x00020000`。 |
| `NTLMSSP_NEGOTIATE_ALWAYS_SIGN` | macro | `lib/ntlmssp.c:116` | 内部 negotiate flag，值为 `0x00008000`。 |
| `NTLMSSP_NEGOTIATE_ANONYMOUS` | macro | `lib/ntlmssp.c:117` | 内部 negotiate flag，值为 `0x00000800`。 |
| `NTLMSSP_NEGOTIATE_NTLM` | macro | `lib/ntlmssp.c:118` | 内部 negotiate flag，值为 `0x00000200`。 |
| `NTLMSSP_NEGOTIATE_SEAL` | macro | `lib/ntlmssp.c:119` | 内部 negotiate flag，值为 `0x00000020`。 |
| `NTLMSSP_NEGOTIATE_SIGN` | macro | `lib/ntlmssp.c:120` | 内部 negotiate flag，值为 `0x00000010`。 |
| `NTLMSSP_REQUEST_TARGET` | macro | `lib/ntlmssp.c:121` | 内部 negotiate flag，值为 `0x00000004`。 |
| `NTLMSSP_NEGOTIATE_OEM` | macro | `lib/ntlmssp.c:122` | 内部 negotiate flag，值为 `0x00000002`。 |
| `NTLMSSP_NEGOTIATE_UNICODE` | macro | `lib/ntlmssp.c:123` | 内部 negotiate flag，值为 `0x00000001`。 |

## ADDED Requirements

### Requirement: ntlmssp_init_context initializes NTLMSSP state
系统 MUST 在内存分配和字段复制成功时返回新的 `struct auth_data`，复制非空 user、password、domain、workstation，复制 8 字节 `client_challenge`，将认证状态置为未认证，将导出会话密钥清零，并记录当前 Windows time。

#### Scenario: successful initialization
- **GIVEN** 调用方提供 user、password、domain、workstation 和至少 8 字节 client challenge
- **WHEN** 调用方调用 `ntlmssp_init_context`
- **THEN** 返回值为非空上下文，后续握手使用复制后的凭据、challenge、未认证状态和清零的导出会话密钥

Trace: `lib/ntlmssp.c:ntlmssp_init_context`, `tests/ntlmssp_generate_blob.c:main`

#### Scenario: allocation failure
- **GIVEN** 上下文、凭据字段或 client challenge 分配失败
- **WHEN** 调用方调用 `ntlmssp_init_context`
- **THEN** 函数 MUST 释放已分配的字段并返回 `NULL`

Trace: `lib/ntlmssp.c:ntlmssp_init_context`

### Requirement: ntlmssp_destroy_context releases NTLMSSP state
系统 MUST 释放 `struct auth_data` 拥有的 NTLM buffer、输出 buffer、凭据字符串、target 字段、client challenge、target info 和上下文本身。

#### Scenario: destroy populated context
- **GIVEN** 调用方持有由 `ntlmssp_init_context` 返回且可能已执行握手的上下文
- **WHEN** 调用方调用 `ntlmssp_destroy_context`
- **THEN** 上下文拥有的动态内存被释放，调用方不再使用该上下文指针

Trace: `lib/ntlmssp.c:ntlmssp_destroy_context`

### Requirement: ntlmssp_set_spnego_wrapping stores wrapping flag
系统 MUST 将传入的 `wrap` 值保存为上下文的 SPNEGO wrapping 状态，后续 blob 生成根据该状态选择是否包装输出。

#### Scenario: enable wrapping
- **GIVEN** 调用方持有有效 `struct auth_data` 上下文
- **WHEN** 调用方调用 `ntlmssp_set_spnego_wrapping(auth, wrap)`
- **THEN** 上下文保存 `wrap` 值供后续 `ntlmssp_generate_blob` 使用

Trace: `lib/ntlmssp.c:ntlmssp_set_spnego_wrapping`

### Requirement: ntlmssp_get_spnego_wrapping returns wrapping flag
系统 MUST 返回上下文当前保存的 SPNEGO wrapping 状态。

#### Scenario: read wrapping state
- **GIVEN** 调用方持有有效 `struct auth_data` 上下文
- **WHEN** 调用方调用 `ntlmssp_get_spnego_wrapping`
- **THEN** 返回值等于上下文中保存的 `spnego_wrap` 字段

Trace: `lib/ntlmssp.c:ntlmssp_get_spnego_wrapping`

### Requirement: ntlmssp_get_message_type unwraps and reports NTLMSSP type
系统 MUST 初始化可选输出参数，在输入 buffer 非空且长度至少 12 字节时调用 SPNEGO unwrap，并在解出的 payload 以 `NTLMSSP` 签名开头时返回 message type、payload 指针、payload 长度和 wrapped 标志。

#### Scenario: valid raw or wrapped NTLMSSP message
- **GIVEN** 调用方提供 raw NTLMSSP buffer 或可由 SPNEGO unwrap 得到 NTLMSSP payload 的 buffer
- **WHEN** 调用方调用 `ntlmssp_get_message_type`
- **THEN** 函数返回 `0`，`message_type` 写入 little-endian message type，`ntlmssp_ptr` 和 `ntlmssp_len` 指向有效 payload，`is_wrapped` 表示 payload 是否不同于输入 buffer

Trace: `lib/ntlmssp.c:ntlmssp_get_message_type`

#### Scenario: invalid or too-short message
- **GIVEN** 输入 buffer 为空、长度小于 12、unwrap 失败或 payload 不含 `NTLMSSP` 签名
- **WHEN** 调用方调用 `ntlmssp_get_message_type`
- **THEN** 函数 MUST 返回 `-1`，并在提供输出参数时保持初始化后的失败默认值

Trace: `lib/ntlmssp.c:ntlmssp_get_message_type`

### Requirement: ntlmssp_generate_blob drives NTLMSSP handshakes
系统 MUST 根据输入消息、客户端/服务端模式和 SPNEGO wrapping 状态生成下一步 NTLMSSP blob，成功时将 `*output_buf` 指向上下文拥有的输出 buffer，并将 `*output_len` 设置为输出长度。

#### Scenario: client starts negotiation
- **GIVEN** SMB2 context 处于客户端模式且 `input_buf` 为 `NULL`
- **WHEN** 调用方调用 `ntlmssp_generate_blob`
- **THEN** 函数生成 NTLMSSP NEGOTIATE_MESSAGE；如果 SPNEGO wrapping 已启用，输出 MUST 为 GSSAPI 包装后的 negotiate blob

Trace: `lib/ntlmssp.c:ntlmssp_generate_blob`

#### Scenario: client responds to challenge
- **GIVEN** SMB2 context 处于客户端模式且输入为 CHALLENGE_MESSAGE
- **WHEN** 调用方调用 `ntlmssp_generate_blob`
- **THEN** 函数解析 challenge，必要时从 target name 更新 domain 和 password file，然后生成 AUTHENTICATION_MESSAGE；已启用 wrapping 时输出为 SPNEGO 包装后的 auth blob

Trace: `lib/ntlmssp.c:ntlmssp_generate_blob`, `tests/ntlmssp_generate_blob.c:main`

#### Scenario: server responds to negotiate or authenticate
- **GIVEN** SMB2 context 处于服务端模式且输入为 NEGOTIATE_MESSAGE 或 AUTHENTICATION_MESSAGE
- **WHEN** 调用方调用 `ntlmssp_generate_blob`
- **THEN** NEGOTIATE_MESSAGE 输入生成 CHALLENGE_MESSAGE，AUTHENTICATION_MESSAGE 输入校验认证并在启用 wrapping 时生成认证结果 blob

Trace: `lib/ntlmssp.c:ntlmssp_generate_blob`

#### Scenario: invalid handshake input
- **GIVEN** 输入消息缺少 NTLMSSP message type、服务端收到非 negotiate/authenticate 消息，或客户端收到非 challenge 消息
- **WHEN** 调用方调用 `ntlmssp_generate_blob`
- **THEN** 函数 MUST 返回 `-1`，并在可定位错误的路径上通过 `smb2_set_error` 记录错误文本

Trace: `lib/ntlmssp.c:ntlmssp_generate_blob`

### Requirement: ntlmssp_authenticate_blob validates AUTHENTICATION_MESSAGE
系统 MUST 仅接受带 `NTLMSSP` 签名且 message type 为 AUTHENTICATION_MESSAGE 的输入，解析 domain、user 和 workstation，调用服务端授权处理器，按 NTLMv2 proof 验证响应，并在成功时导出 session key。

#### Scenario: successful authenticated user
- **GIVEN** 输入 AUTHENTICATION_MESSAGE 包含有效用户字段、NTLMv2 response 和服务端已设置密码
- **WHEN** 服务端调用 `ntlmssp_authenticate_blob`
- **THEN** 函数返回 `0`，擦除 SMB2 context 中已使用的 password，并把计算出的 key exchange key 保存为 exported session key

Trace: `lib/ntlmssp.c:ntlmssp_authenticate_blob`

#### Scenario: anonymous allowed
- **GIVEN** 输入认证消息缺少 user 或 password 且 `server->allow_anonymous` 非零
- **WHEN** 服务端调用 `ntlmssp_authenticate_blob`
- **THEN** 函数 MAY 返回 `0` 表示匿名认证成功且不执行 NT proof 校验

Trace: `lib/ntlmssp.c:ntlmssp_authenticate_blob`

#### Scenario: invalid proof or authorization
- **GIVEN** 输入签名或 type 无效、授权处理器拒绝用户、缺少 password 且匿名未启用、challenge 长度不足，或 NT proof 与响应不匹配
- **WHEN** 服务端调用 `ntlmssp_authenticate_blob`
- **THEN** 函数 MUST 返回 `-1`，并在已设置错误文本的路径上保留认证失败原因

Trace: `lib/ntlmssp.c:ntlmssp_authenticate_blob`

### Requirement: ntlmssp_get_authenticated reports authentication state
系统 MUST 在上下文非空时返回 `is_authenticated` 状态，并在上下文为空时返回 `0`。

#### Scenario: query authentication state
- **GIVEN** 调用方需要检查服务端认证结果
- **WHEN** 调用方调用 `ntlmssp_get_authenticated`
- **THEN** 非空上下文返回内部认证状态，空上下文返回 `0`

Trace: `lib/ntlmssp.c:ntlmssp_get_authenticated`

### Requirement: ntlmssp_get_session_key copies exported key
系统 MUST 在参数有效且分配成功时分配 `SMB2_KEY_SIZE` 字节缓冲区，复制上下文导出的 session key，并通过输出参数返回缓冲区和 key size。

#### Scenario: successful key export
- **GIVEN** 调用方提供非空 auth、key 和 key_size 指针
- **WHEN** 调用方调用 `ntlmssp_get_session_key`
- **THEN** 函数返回 `0`，`*key` 指向调用方需释放的 `SMB2_KEY_SIZE` 字节副本，`*key_size` 等于 `SMB2_KEY_SIZE`

Trace: `lib/ntlmssp.c:ntlmssp_get_session_key`

#### Scenario: invalid arguments or allocation failure
- **GIVEN** auth、key 或 key_size 为空，或 key 缓冲区分配失败
- **WHEN** 调用方调用 `ntlmssp_get_session_key`
- **THEN** 函数 MUST 返回 `-1` 且不返回有效 key 副本

Trace: `lib/ntlmssp.c:ntlmssp_get_session_key`

## Open Questions

| ID | Question | Related Interface | Reason |
| --- | --- | --- | --- |
| Q-001 | `ntlmssp_init_context` 对 `client_challenge == NULL` 没有显式检查但会 `memcpy` 8 字节，调用方前置条件是否应在头文件中声明？ | `ntlmssp_init_context` | 源码显示直接复制 8 字节，测试传入固定 8 字节数组，但未发现防御路径。 |
| Q-002 | `ntlmssp_destroy_context` 是否允许 `auth == NULL`？ | `ntlmssp_destroy_context` | 源码直接解引用 `auth`，未发现空指针保护或声明侧约束。 |
| Q-003 | `ntlmssp_authenticate_blob` 在 `server == NULL` 且用户或密码为空时会读取 `server->allow_anonymous`，该调用形态是否被外部禁止？ | `ntlmssp_authenticate_blob` | 源码无空 server 防护；GitNexus context 仅显示由服务端路径和 `ntlmssp_generate_blob` 调用。 |
| Q-004 | `ntlmssp_generate_blob` 直接将 `auth_data->len` 截断为 `uint16_t` 写入 `output_len`，大于 65535 的输出是否可能或是否应失败？ | `ntlmssp_generate_blob` | 源码无长度上限检查，未发现测试覆盖超长 target-info/SPNEGO 输出。 |
| Q-005 | GitNexus `impact ntlmssp_generate_blob --include-tests` 在定义和头文件声明之间返回 ambiguous，后续主 Agent 是否应使用 UID 复查精确风险？ | `ntlmssp_generate_blob` | 本 worker 记录了 `context` 调用者，但 impact 命令未能消歧。 |
