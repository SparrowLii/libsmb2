# lib/krb5-wrapper.c Specification

## Source Context

- Source: `lib/krb5-wrapper.c`
- Related Headers: `lib/krb5-wrapper.h`
- Related Tests: `none`
- Related Dependencies: `lib/libsmb2.c:negotiate_cb`, `lib/libsmb2.c:send_session_setup_request`, `lib/libsmb2.c:session_setup_cb`, `lib/libsmb2.c:smb2_session_setup_request_cb`, `lib/libsmb2.c:smb2_serve_port`, `lib/libsmb2.c:smb2_destroy_server`, `lib/init.c:smb2_set_error`, `lib/init.c:smb2_set_user`, `lib/init.c:smb2_set_domain`, GSSAPI/Kerberos runtime libraries
- Build/Compile Context: `lib/krb5-wrapper.c` is compiled only under `HAVE_LIBKRB5`; Apple builds use `<GSS/GSS.h>` and skip NTLMSSP/proxy helper paths guarded by `#ifndef __APPLE__`; non-Apple builds use `<gssapi/gssapi_krb5.h>` and `<gssapi/gssapi.h>`.

## Interface Summary

| Interface | Kind | Signature | Decision | Reason |
| --- | --- | --- | --- | --- |
| krb5_free_auth_data | function | void krb5_free_auth_data(struct private_auth_data *auth); | Include | 释放 Kerberos/GSSAPI 私有认证状态、票据缓存、上下文、名称、凭据和输出 token，影响客户端和服务端认证生命周期。 |
| display_status | function | static char *display_status(int type, uint32_t err) | Skip | 纯内部错误字符串 helper，仅由 `krb5_set_gss_error` 使用，不形成独立调用方契约。 |
| krb5_set_gss_error | function | void krb5_set_gss_error(struct smb2_context *smb2, char *func, uint32_t maj, uint32_t min); | Include | 将 GSS major/minor 状态转换为 SMB2 错误文本，是多个公开 Kerberos 路径的错误报告边界。 |
| krb5_negotiate_reply | function | struct private_auth_data *krb5_negotiate_reply(struct smb2_context *smb2, const char *server, const char *domain, const char *user_name, const char *password); | Include | 客户端协商阶段创建目标服务名、用户凭据和可选内存 credential cache，被 `negotiate_cb` 调用。 |
| krb5_session_get_session_key | function | int krb5_session_get_session_key(struct smb2_context *smb2, struct private_auth_data *auth_data); | Include | 从已建立 GSS context 提取会话密钥并写入 `smb2_context`，影响 SMB2 签名/加密后续流程。 |
| krb5_session_request | function | int krb5_session_request(struct smb2_context *smb2, struct private_auth_data *auth_data, unsigned char *buf, int len); | Include | 客户端 session setup 期间生成或推进 GSS init token，并维护输出 token。 |
| establish_contexts | function | static OM_uint32 establish_contexts(struct smb2_context *smb2, gss_OID imech, gss_cred_id_t icred, gss_cred_id_t acred, gss_name_t tname, OM_uint32 flags, gss_ctx_id_t *ictx, gss_ctx_id_t *actx, gss_name_t *src_name, gss_OID *amech, gss_cred_id_t *deleg_cred) | Skip | 非 Apple 内部 helper，仅为 S4U/proxy credential 建立临时 initiator/acceptor context，无外部直接调用契约。 |
| init_accept_sec_context | function | static OM_uint32 init_accept_sec_context(struct smb2_context *smb2, gss_OID mech, gss_cred_id_t claimant_cred_handle, gss_cred_id_t verifier_cred_handle, gss_cred_id_t *deleg_cred_handle) | Skip | 非 Apple 内部 helper，仅由 `krb5_session_reply` 的 proxy credential 路径使用，行为归属到该接口。 |
| krb5_init_server_client_cred | function | struct private_auth_data *krb5_init_server_client_cred(struct smb2_server *server, struct smb2_context *smb2, const char *password); | Include | 服务端 session setup 为接受端创建 GSS 凭据，并可沿用服务端 keytab/ccache 进行受限委派。 |
| krb5_session_reply | function | int krb5_session_reply(struct smb2_context *smb2, struct private_auth_data *auth_data, unsigned char *buf, int len, int *more_processing_needed); | Include | 服务端接受客户端 GSS token、解析用户/域、处理继续标志和 proxy credential，是认证状态机核心入口。 |
| krb5_renew_server_credentials | function | int krb5_renew_server_credentials(struct smb2_server *server); | Include | 服务端 keytab 模式下续期并存储 Kerberos 初始凭据，被服务端循环路径调用。 |
| krb5_init_server_credentials | function | int krb5_init_server_credentials(struct smb2_server *server, const char *keytab_path); | Include | 服务端监听启动时初始化 keytab、principal 和内存 credential cache，并写入 `server->auth_data`。 |
| krb5_free_server_credentials | function | void krb5_free_server_credentials(struct smb2_server *server); | Include | 服务端关闭时释放 `server->auth_data` 并清空指针，影响服务端资源生命周期。 |
| krb5_get_output_token_length | function | int krb5_get_output_token_length(struct private_auth_data *auth_data); | Include | 向 session setup 调用方暴露当前 GSS output token 长度。 |
| krb5_get_output_token_buffer | function | unsigned char *krb5_get_output_token_buffer(struct private_auth_data *auth_data); | Include | 向 session setup 调用方暴露当前 GSS output token buffer 指针。 |
| krb5_can_do_ntlmssp | function | int krb5_can_do_ntlmssp(void); | Include | 检测 Kerberos/GSSAPI 运行时是否支持 NTLMSSP 机制，影响认证机制选择能力。 |

## Data Model Summary

| Type/Macro | Kind | Definition | Notes |
| --- | --- | --- | --- |
| struct private_auth_data | struct | lib/krb5-wrapper.h:56 | 保存 GSS context、credential、name、output token、SPNEGO/KRB5 机制选择、Kerberos context/cache/principal/keytab/server creds。 |
| gss_mech_spnego | macro | lib/krb5-wrapper.h:43 | 非 Apple 构建中的 SPNEGO OID 描述符。 |
| spnego_mech_krb5 | macro | lib/krb5-wrapper.h:48 | KRB5 OID 描述符。 |
| spnego_mech_ntlmssp | macro | lib/krb5-wrapper.h:52 | NTLMSSP OID 描述符，供 `krb5_can_do_ntlmssp` 和非 Apple proxy/negotiation paths 使用。 |

## ADDED Requirements

### Requirement: krb5_free_auth_data releases private authentication resources
系统 MUST 释放传入 `struct private_auth_data` 持有的 GSS output token、Kerberos credential cache/context、GSS security context、target/user names、credential、server string 和结构本身。

#### Scenario: release populated auth data
- **GIVEN** `auth` 指向包含 output token、Kerberos cache、GSS context、names、credential 和 `g_server` 的认证状态
- **WHEN** 调用 `krb5_free_auth_data(auth)`
- **THEN** 函数释放这些资源并最终释放 `auth` 结构

Trace: `lib/krb5-wrapper.c:krb5_free_auth_data`, `lib/libsmb2.c:free_c_data`, `lib/krb5-wrapper.c:krb5_init_server_credentials`, `lib/krb5-wrapper.c:krb5_free_server_credentials`

### Requirement: krb5_set_gss_error records formatted GSS failure details
系统 MUST 将 GSS major/minor 状态格式化为错误文本，并在 `smb2` 非空时通过 `smb2_set_error` 记录 `<func>: (<major text>, <minor text>)`。

#### Scenario: record GSS error on context
- **GIVEN** `smb2` 非空且 GSSAPI 返回 major/minor 错误码
- **WHEN** 调用 `krb5_set_gss_error(smb2, func, maj, min)`
- **THEN** `smb2` 的错误状态包含函数名和两个 GSS status 文本，临时 status 字符串被释放

Trace: `lib/krb5-wrapper.c:krb5_set_gss_error`, `lib/krb5-wrapper.c:display_status`

#### Scenario: ignore NULL SMB2 context
- **GIVEN** `smb2` 为 `NULL`
- **WHEN** 调用 `krb5_set_gss_error(NULL, func, maj, min)`
- **THEN** 函数释放格式化出的 status 字符串且不写入 SMB2 错误状态

Trace: `lib/krb5-wrapper.c:krb5_set_gss_error`, `lib/krb5-wrapper.c:krb5_can_do_ntlmssp`

### Requirement: krb5_negotiate_reply initializes client-side Kerberos authentication
系统 MUST 为客户端 Kerberos 协商创建 `private_auth_data`，构造去除端口后的 `cifs@<server>` target name，导入用户 name，并获取 initiator credential。

#### Scenario: create credentials with delegated handle
- **GIVEN** `smb2->cred_handle` 已包含委派 credential，且 server target name 可导入
- **WHEN** 调用 `krb5_negotiate_reply(smb2, server, domain, user_name, password)`
- **THEN** 返回的 `auth_data->cred` 使用原 `smb2->cred_handle`，并将 `smb2->cred_handle` 清空

Trace: `lib/krb5-wrapper.c:krb5_negotiate_reply`, `lib/libsmb2.c:negotiate_cb`

#### Scenario: reject cached credentials without domain or password
- **GIVEN** `smb2->use_cached_creds` 为真且 `domain` 或 `password` 为 `NULL`
- **WHEN** 调用 `krb5_negotiate_reply(smb2, server, domain, user_name, password)`
- **THEN** 函数返回 `NULL` 并设置错误 `domain and password must be set while using krb5cc mode`

Trace: `lib/krb5-wrapper.c:krb5_negotiate_reply`, `lib/libsmb2.c:negotiate_cb`

#### Scenario: create temporary memory credential cache
- **GIVEN** `smb2->use_cached_creds` 为真且 Kerberos context、memory ccache 和 password credential 获取均成功
- **WHEN** 调用 `krb5_negotiate_reply(smb2, server, domain, user_name, password)`
- **THEN** 返回的认证状态包含新建 memory credential cache 和 acquired initiator credential

Trace: `lib/krb5-wrapper.c:krb5_negotiate_reply`, `lib/libsmb2.c:negotiate_cb`

### Requirement: krb5_session_get_session_key stores the negotiated session key
系统 MUST 从 `auth_data->context` 查询 `GSS_C_INQ_SSPI_SESSION_KEY`，验证第一个 buffer 元素非空，并把会话密钥复制到 `smb2->session_key` 与 `smb2->session_key_size`。

#### Scenario: copy valid session key
- **GIVEN** GSS context 返回至少一个非空 session key buffer
- **WHEN** 调用 `krb5_session_get_session_key(smb2, auth_data)`
- **THEN** 函数分配 `smb2->session_key`、复制 key bytes、设置 `smb2->session_key_size` 并返回 `0`

Trace: `lib/krb5-wrapper.c:krb5_session_get_session_key`, `lib/libsmb2.c:session_setup_cb`, `lib/libsmb2.c:smb2_session_setup_request_cb`

#### Scenario: reject invalid session key
- **GIVEN** GSS 查询失败或返回空 session key set、空元素、零长度 key 或内存分配失败
- **WHEN** 调用 `krb5_session_get_session_key(smb2, auth_data)`
- **THEN** 函数设置 SMB2/GSS 错误并返回 `-1`

Trace: `lib/krb5-wrapper.c:krb5_session_get_session_key`, `lib/init.c:smb2_set_error`, `lib/krb5-wrapper.c:krb5_set_gss_error`

### Requirement: krb5_session_request advances client GSS session setup
系统 MUST 使用 `auth_data->cred`、target name、mechanism 和 sequence/mutual/replay flags 调用 `gss_init_sec_context`，并通过 `auth_data->output_token` 暴露生成的 token。

#### Scenario: consume server token and continue
- **GIVEN** `buf` 非空且 GSSAPI 返回 `GSS_S_CONTINUE_NEEDED`
- **WHEN** 调用 `krb5_session_request(smb2, auth_data, buf, len)`
- **THEN** 函数先释放旧 output token，再以 `buf/len` 作为 input token 推进上下文并返回 `0`

Trace: `lib/krb5-wrapper.c:krb5_session_request`, `lib/libsmb2.c:send_session_setup_request`, `lib/libsmb2.c:session_setup_cb`

#### Scenario: report GSS init failure
- **GIVEN** `gss_init_sec_context` 返回 GSS error
- **WHEN** 调用 `krb5_session_request(smb2, auth_data, buf, len)`
- **THEN** 函数通过 `krb5_set_gss_error` 记录错误并返回 `-1`

Trace: `lib/krb5-wrapper.c:krb5_session_request`, `lib/krb5-wrapper.c:krb5_set_gss_error`

### Requirement: krb5_init_server_client_cred creates server acceptor credentials
系统 MUST 为服务端 session setup 创建 `private_auth_data`，导入 `cifs@<server-host>` target name，并根据 proxy authentication 与可用 keytab/ccache 获取 acceptor 或 both-use GSS credential。

#### Scenario: acquire server credential from keytab-backed server auth data
- **GIVEN** `server->auth_data` 包含 keytab 和 credential cache，且平台不是 Apple
- **WHEN** 调用 `krb5_init_server_client_cred(server, smb2, password)`
- **THEN** 函数从现有 keytab/cache 构造 key-value set，并使用 `gss_acquire_cred_from` 获取 credential

Trace: `lib/krb5-wrapper.c:krb5_init_server_client_cred`, `lib/libsmb2.c:smb2_session_setup_request_cb`

#### Scenario: acquire default server credential
- **GIVEN** 没有 keytab-backed `server->auth_data`
- **WHEN** 调用 `krb5_init_server_client_cred(server, smb2, password)`
- **THEN** 函数使用 `gss_acquire_cred` 获取 acceptor 或 both-use credential，失败时设置错误并返回 `NULL`

Trace: `lib/krb5-wrapper.c:krb5_init_server_client_cred`, `lib/krb5-wrapper.c:krb5_set_gss_error`

### Requirement: krb5_session_reply accepts server-side GSS tokens
系统 MUST 接受客户端 GSS token，更新 output token，维护 `more_processing_needed`，成功完成后把 GSS display name 拆分为 SMB2 user/domain，并按委派策略保存或释放 delegated credential。

#### Scenario: request more processing
- **GIVEN** `gss_accept_sec_context` 返回 `GSS_S_CONTINUE_NEEDED`
- **WHEN** 调用 `krb5_session_reply(smb2, auth_data, buf, len, more_processing_needed)`
- **THEN** 函数将 `*more_processing_needed` 设置为 `1` 并返回 `0`

Trace: `lib/krb5-wrapper.c:krb5_session_reply`, `lib/libsmb2.c:smb2_session_setup_request_cb`

#### Scenario: complete server authentication and set identity
- **GIVEN** GSS accept 成功且 display name 为 `user@domain`
- **WHEN** 调用 `krb5_session_reply(smb2, auth_data, buf, len, more_processing_needed)`
- **THEN** 函数将 SMB2 user 设置为 `user`、domain 设置为 `domain`，并把 `auth_data->user_name` 重建为不含 domain 的用户 name

Trace: `lib/krb5-wrapper.c:krb5_session_reply`, `lib/init.c:smb2_set_user`, `lib/init.c:smb2_set_domain`

#### Scenario: reject unavailable proxy credentials on Apple
- **GIVEN** `auth_data->get_proxy_cred` 为真、没有 delegated credential 且平台为 Apple
- **WHEN** 调用 `krb5_session_reply(smb2, auth_data, buf, len, more_processing_needed)`
- **THEN** 函数设置错误 `Apple has no way to proxy credentials` 并返回 `-1`

Trace: `lib/krb5-wrapper.c:krb5_session_reply`, `lib/init.c:smb2_set_error`

### Requirement: krb5_renew_server_credentials refreshes keytab-backed server tickets
系统 MUST 在 `server->auth_data` 存在且包含 keytab 时使用 keytab 获取初始凭据，并把凭据存入该 auth data 的 Kerberos credential cache。

#### Scenario: no keytab requires no renewal
- **GIVEN** `server->auth_data` 为空或其 `keytab` 为空
- **WHEN** 调用 `krb5_renew_server_credentials(server)`
- **THEN** 函数返回 `0` 且不修改 Kerberos cache

Trace: `lib/krb5-wrapper.c:krb5_renew_server_credentials`, `lib/libsmb2.c:smb2_serve_port`

#### Scenario: renewal failure records server error
- **GIVEN** keytab-backed auth data 存在但 `krb5_get_init_creds_keytab` 或 `krb5_cc_store_cred` 返回错误
- **WHEN** 调用 `krb5_renew_server_credentials(server)`
- **THEN** 函数在 `server->error` 中写入失败原因并返回 Kerberos 错误码

Trace: `lib/krb5-wrapper.c:krb5_renew_server_credentials`, `lib/libsmb2.c:smb2_serve_port`

### Requirement: krb5_init_server_credentials initializes keytab-backed server state
系统 MUST 在提供非空 keytab 路径时创建服务端 Kerberos auth data，构造 `cifs/<hostname>` principal 和 `cifs@<hostname>` GSS name，解析 keytab，创建 memory credential cache，并在成功时写入 `server->auth_data`。

#### Scenario: no keytab path is a no-op success
- **GIVEN** `keytab_path` 为 `NULL`、空字符串或无需显式 keytab
- **WHEN** 调用 `krb5_init_server_credentials(server, keytab_path)`
- **THEN** 函数返回 `0` 且不要求创建 `server->auth_data`

Trace: `lib/krb5-wrapper.c:krb5_init_server_credentials`, `lib/libsmb2.c:smb2_serve_port`

#### Scenario: initialize memory cache and server auth data
- **GIVEN** `server` 和非空 `keytab_path` 有效，Kerberos/GSSAPI 调用成功
- **WHEN** 调用 `krb5_init_server_credentials(server, keytab_path)`
- **THEN** 函数初始化 keytab-backed auth data、memory credential cache 和 principal，并返回 `0`

Trace: `lib/krb5-wrapper.c:krb5_init_server_credentials`, `lib/libsmb2.c:smb2_serve_port`

#### Scenario: cleanup on initialization failure
- **GIVEN** 初始化流程中任一分配、GSS name import、Kerberos context、principal、keytab 或 cache 操作失败
- **WHEN** 调用 `krb5_init_server_credentials(server, keytab_path)`
- **THEN** 函数写入 `server->error`、释放已分配 auth data、将 `server->auth_data` 置为 `NULL` 并返回非零错误

Trace: `lib/krb5-wrapper.c:krb5_init_server_credentials`, `lib/krb5-wrapper.c:krb5_free_auth_data`

### Requirement: krb5_free_server_credentials clears server auth data
系统 MUST 在 `server` 和 `server->auth_data` 非空时释放服务端 Kerberos auth data，并将 `server->auth_data` 置为 `NULL`。

#### Scenario: free server credentials
- **GIVEN** `server->auth_data` 指向 Kerberos auth data
- **WHEN** 调用 `krb5_free_server_credentials(server)`
- **THEN** 函数调用 `krb5_free_auth_data` 释放资源并清空 `server->auth_data`

Trace: `lib/krb5-wrapper.c:krb5_free_server_credentials`, `lib/libsmb2.c:smb2_destroy_server`

### Requirement: krb5_get_output_token_length returns current output token length
系统 MUST 返回 `auth_data->output_token.length` 的当前值。

#### Scenario: expose generated token length
- **GIVEN** `auth_data->output_token.length` 已由 GSSAPI session step 设置
- **WHEN** 调用 `krb5_get_output_token_length(auth_data)`
- **THEN** 返回值等于当前 output token length

Trace: `lib/krb5-wrapper.c:krb5_get_output_token_length`, `lib/libsmb2.c:session_setup_cb`, `lib/libsmb2.c:smb2_session_setup_request_cb`

### Requirement: krb5_get_output_token_buffer returns current output token buffer
系统 MUST 返回 `auth_data->output_token.value` 的当前指针，不复制 token 内容。

#### Scenario: expose generated token buffer
- **GIVEN** `auth_data->output_token.value` 已由 GSSAPI session step 设置
- **WHEN** 调用 `krb5_get_output_token_buffer(auth_data)`
- **THEN** 返回值等于当前 output token buffer 指针

Trace: `lib/krb5-wrapper.c:krb5_get_output_token_buffer`, `lib/libsmb2.c:session_setup_cb`, `lib/libsmb2.c:smb2_session_setup_request_cb`

### Requirement: krb5_can_do_ntlmssp reports runtime NTLMSSP mechanism availability
系统 MUST 在非 Apple 构建中通过 `gss_inquire_attrs_for_mech` 查询 NTLMSSP OID，并在查询成功时返回 `1`、失败时返回 `0`；Apple 构建 MUST 返回 `0`。

#### Scenario: non-Apple NTLMSSP mechanism is available
- **GIVEN** 平台不是 Apple 且 GSSAPI 成功查询 `spnego_mech_ntlmssp`
- **WHEN** 调用 `krb5_can_do_ntlmssp()`
- **THEN** 函数释放返回的 OID set 并返回 `1`

Trace: `lib/krb5-wrapper.c:krb5_can_do_ntlmssp`, `lib/krb5-wrapper.h:spnego_mech_ntlmssp`

#### Scenario: Apple or GSS failure reports unavailable
- **GIVEN** 平台为 Apple 或 GSSAPI 查询 NTLMSSP OID 失败
- **WHEN** 调用 `krb5_can_do_ntlmssp()`
- **THEN** 函数返回 `0`，非 Apple GSS failure 路径还通过 `krb5_set_gss_error(NULL, ...)` 丢弃错误文本

Trace: `lib/krb5-wrapper.c:krb5_can_do_ntlmssp`, `lib/krb5-wrapper.c:krb5_set_gss_error`

## Open Questions

| ID | Question | Related Interface | Reason |
| --- | --- | --- | --- |
| Q-001 | `krb5_free_auth_data(NULL)` 是否被调用方视为非法前置条件，还是应具备空指针容忍语义？ | krb5_free_auth_data | `krb5_negotiate_reply` 在 `calloc` 失败路径会以 `NULL` 调用该函数，但实现会解引用 `auth`；源码与调用路径存在冲突。 |
| Q-002 | `krb5_negotiate_reply` 中 `snprintf` 生成 cached principal 失败、`krb5_init_context` 失败、`strdup(password)` 失败路径是否需要释放已分配的 `auth_data` 和 `nc_password`？ | krb5_negotiate_reply | 部分失败路径直接返回 `NULL`，源码未统一调用 `krb5_free_auth_data` 或检查 `strdup` 返回值。 |
| Q-003 | `krb5_session_get_session_key` 在 invalid session key 或 malloc failure 路径是否应释放 `sessionKey` buffer set？ | krb5_session_get_session_key | 成功路径释放 `sessionKey`，多个错误路径返回前未释放。 |
| Q-004 | `krb5_session_reply` 中 `ret_delegated_cred_handle` 在 GSS accept 未返回 delegated credential 时是否有确定初始值？ | krb5_session_reply | 局部变量未显式初始化，后续条件读取依赖 GSSAPI 输出约定。 |
| Q-005 | `krb5_init_server_client_cred` 失败路径是否应释放已分配的 `auth_data`、`g_server` 和 target name？ | krb5_init_server_client_cred | 多个错误路径返回 `NULL` 但未调用 `krb5_free_auth_data`。 |
| Q-006 | `krb5_init_server_credentials` 开头在检查 `server` 是否为 `NULL` 前写入 `server->error[0]` 是否要求调用方保证 `server` 非空？ | krb5_init_server_credentials | 源码先解引用 `server`，随后才检查 `!server`。 |
