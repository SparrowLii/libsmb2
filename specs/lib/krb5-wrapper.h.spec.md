# lib/krb5-wrapper.h Specification

## Source Context

- Source: `lib/krb5-wrapper.h`
- Related Headers: `krb5/krb5.h`, `GSS/GSS.h`, `gssapi/gssapi.h`, `gssapi/gssapi_ext.h`, `lib/krb5-wrapper.c`
- Related Tests: `none`
- Related Dependencies: `lib/libsmb2.c` calls the Kerberos wrapper interfaces for SMB client and server authentication; `lib/krb5-wrapper.c` implements the declarations and calls GSSAPI/Kerberos routines such as `gss_import_name`, `gss_acquire_cred`, `gss_init_sec_context`, `gss_accept_sec_context`, `krb5_cc_new_unique`, and `krb5_get_init_creds_keytab`.
- Build/Compile Context: `HAVE_LIBKRB5` gates this header and implementation; `_GNU_SOURCE` is defined when absent; `__APPLE__` selects `GSS/GSS.h` and otherwise includes `gssapi/gssapi.h` plus `gssapi/gssapi_ext.h`.

## Interface Summary

| Interface | Kind | Signature | Decision | Reason |
| --- | --- | --- | --- | --- |
| `private_auth_data` | type | `struct private_auth_data` | Include | 认证状态对象承载 GSS/Kerberos 句柄、输出 token、服务器名和服务端凭据，跨多个 Kerberos wrapper 接口传递。 |
| `gss_mech_spnego` | constant | `static const gss_OID_desc gss_mech_spnego = { 6, "\\x2b\\x06\\x01\\x05\\x05\\x02" };` | Include | 非 Apple 平台公开 SPNEGO OID 常量供本头文件内的 Kerberos wrapper 选择机制。 |
| `spnego_mech_krb5` | constant | `static const gss_OID_desc spnego_mech_krb5 = { 9, "\\x2a\\x86\\x48\\x86\\xf7\\x12\\x01\\x02\\x02" };` | Include | Kerberos SPNEGO OID 常量影响 GSS mechanism 选择。 |
| `spnego_mech_ntlmssp` | constant | `static const gss_OID_desc spnego_mech_ntlmssp = { 10, "\\x2b\\x06\\x01\\x04\\x01\\x82\\x37\\x02\\x02\\x0a" };` | Include | NTLMSSP SPNEGO OID 常量影响 NTLMSSP 能力探测和机制限制。 |
| `krb5_free_auth_data` | function | `void krb5_free_auth_data(struct private_auth_data *auth);` | Include | 释放认证状态及其 GSS/Kerberos 资源，是生命周期终点。 |
| `krb5_get_output_token_buffer` | function | `unsigned char * krb5_get_output_token_buffer(struct private_auth_data *auth_data);` | Include | 调用方通过该访问器取得最近一次 GSS 输出 token 缓冲区。 |
| `krb5_get_output_token_length` | function | `int krb5_get_output_token_length(struct private_auth_data *auth_data);` | Include | 调用方通过该访问器取得最近一次 GSS 输出 token 长度。 |
| `krb5_negotiate_reply` | function | `struct private_auth_data * krb5_negotiate_reply(struct smb2_context *smb2, const char *server, const char *domain, const char *user_name, const char *password);` | Include | SMB 客户端协商使用该接口创建 Kerberos/GSS initiator 凭据和目标名称。 |
| `krb5_negotiate_request` | function | `int krb5_negotiate_request(struct smb2_context *smb2, void **neg_init_token);` | Include | 头文件声明 SMB negotiate request 初始化入口，但当前实现文件未发现定义。 |
| `krb5_session_get_session_key` | function | `int krb5_session_get_session_key(struct smb2_context *smb2, struct private_auth_data *auth_data);` | Include | 会话建立后该接口导出 GSS session key 到 SMB 上下文。 |
| `krb5_session_request` | function | `int krb5_session_request(struct smb2_context *smb2, struct private_auth_data *auth_data, unsigned char *buf, int len);` | Include | 客户端侧 GSS token 交换入口，产生后续 SMB session setup token。 |
| `krb5_init_server_client_cred` | function | `struct private_auth_data * krb5_init_server_client_cred(struct smb2_server *server, struct smb2_context *smb2, const char *password);` | Include | 服务端为客户端上下文初始化 acceptor 或代理凭据。 |
| `krb5_session_reply` | function | `int krb5_session_reply(struct smb2_context *smb2, struct private_auth_data *auth_data, unsigned char *buf, int len, int *more_processing_needed);` | Include | 服务端侧 GSS token 接收入口，更新用户、域和可选委派凭据。 |
| `krb5_set_gss_error` | function | `void krb5_set_gss_error(struct smb2_context *smb2, char *func, uint32_t maj, uint32_t min);` | Include | GSS major/minor 状态转换为 SMB 错误文本。 |
| `krb5_can_do_ntlmssp` | function | `int krb5_can_do_ntlmssp(void);` | Include | 调用方使用该能力探测判断 Kerberos/GSSAPI 是否可处理 NTLMSSP。 |
| `krb5_init_server_credentials` | function | `int krb5_init_server_credentials(struct smb2_server *server, const char *keytab_path);` | Include | 服务端 keytab 凭据初始化入口，建立私有 credential cache。 |
| `krb5_renew_server_credentials` | function | `int krb5_renew_server_credentials(struct smb2_server *server);` | Include | 服务端使用 keytab 刷新 credential cache 中的凭据。 |
| `krb5_free_server_credentials` | function | `void krb5_free_server_credentials(struct smb2_server *server);` | Include | 服务端释放并清空保存的 Kerberos auth_data。 |

## Data Model Summary

| Type/Macro | Kind | Definition | Notes |
| --- | --- | --- | --- |
| `HAVE_LIBKRB5` | macro | `lib/krb5-wrapper.h:25` | 该宏启用整个 Kerberos/GSSAPI wrapper 声明面。 |
| `_GNU_SOURCE` | macro | `lib/krb5-wrapper.h:27` | 未定义时由头文件定义，以启用 GNU 扩展声明。 |
| `gss_mech_spnego` | constant | `lib/krb5-wrapper.h:43` | 非 Apple 平台 SPNEGO OID，长度为 6 字节。 |
| `spnego_mech_krb5` | constant | `lib/krb5-wrapper.h:48` | Kerberos SPNEGO OID，长度为 9 字节。 |
| `spnego_mech_ntlmssp` | constant | `lib/krb5-wrapper.h:52` | NTLMSSP SPNEGO OID，长度为 10 字节。 |
| `private_auth_data` | struct | `lib/krb5-wrapper.h:56` | 保存 GSS context、credential、names、mechanism、request flags、output token、proxy/SPNEGO flags、server name、Kerberos context/cache/principal/keytab/server credentials。 |

## ADDED Requirements

### Requirement: private_auth_data auth state carrier
系统 MUST 使用 `private_auth_data` 保存一次 Kerberos/GSSAPI 认证流程所需的上下文、凭据、名称、mechanism、输出 token 和 Kerberos credential cache 状态。

#### Scenario: authentication state is shared across wrapper calls
- **GIVEN** Kerberos wrapper 创建或接收一个 `private_auth_data` 实例
- **WHEN** 调用方把该实例传给 session request、session reply、session key 或释放接口
- **THEN** 接口 MUST 通过该实例中的 GSS/Kerberos 句柄和 output token 字段传递认证状态

Trace: `lib/krb5-wrapper.h:private_auth_data`, `lib/krb5-wrapper.c:krb5_session_request`, `lib/krb5-wrapper.c:krb5_session_reply`

### Requirement: gss_mech_spnego non-Apple SPNEGO OID
系统 MUST 在非 Apple 构建中提供 `gss_mech_spnego` 常量作为 SPNEGO mechanism OID。

#### Scenario: non-Apple SPNEGO mechanism is available
- **GIVEN** 构建平台未定义 `__APPLE__`
- **WHEN** 代码包含 `lib/krb5-wrapper.h`
- **THEN** 头文件 MUST 定义长度为 6、值为 `2b 06 01 05 05 02` 的 `gss_mech_spnego`

Trace: `lib/krb5-wrapper.h:gss_mech_spnego`, `lib/krb5-wrapper.c:krb5_negotiate_reply`

### Requirement: spnego_mech_krb5 Kerberos OID
系统 MUST 提供 `spnego_mech_krb5` 常量表示 Kerberos SPNEGO mechanism OID。

#### Scenario: Kerberos mechanism restriction uses declared OID
- **GIVEN** 调用方选择 Kerberos security mechanism
- **WHEN** wrapper 需要限制 GSS negotiation mechanism
- **THEN** 代码 MUST 能使用长度为 9、值为 `2a 86 48 86 f7 12 01 02 02` 的 `spnego_mech_krb5`

Trace: `lib/krb5-wrapper.h:spnego_mech_krb5`, `lib/krb5-wrapper.c:krb5_negotiate_reply`

### Requirement: spnego_mech_ntlmssp NTLMSSP OID
系统 MUST 提供 `spnego_mech_ntlmssp` 常量表示 NTLMSSP SPNEGO mechanism OID。

#### Scenario: NTLMSSP mechanism selection uses declared OID
- **GIVEN** 调用方选择 NTLMSSP security mechanism or requests NTLMSSP capability detection
- **WHEN** wrapper restricts negotiation or probes GSSAPI attributes
- **THEN** 代码 MUST use length 10 OID bytes `2b 06 01 04 01 82 37 02 02 0a` from `spnego_mech_ntlmssp`

Trace: `lib/krb5-wrapper.h:spnego_mech_ntlmssp`, `lib/krb5-wrapper.c:krb5_can_do_ntlmssp`

### Requirement: krb5_free_auth_data releases auth resources
系统 MUST 释放 `private_auth_data` 持有的 output token、GSS context、GSS names、GSS credential、server string、Kerberos credential cache 和 Kerberos context。

#### Scenario: caller destroys auth state
- **GIVEN** 调用方传入一个已初始化的 `private_auth_data` 指针
- **WHEN** 调用 `krb5_free_auth_data(auth)`
- **THEN** 函数 MUST release owned GSS/Kerberos resources and free the auth object

Trace: `lib/krb5-wrapper.h:krb5_free_auth_data`, `lib/krb5-wrapper.c:krb5_free_auth_data`

### Requirement: krb5_get_output_token_buffer exposes current token buffer
系统 MUST 返回 `private_auth_data.output_token.value` 作为当前 GSS output token 缓冲区。

#### Scenario: caller reads output token bytes
- **GIVEN** `auth_data` 包含最近一次 GSS operation 生成的 output token
- **WHEN** 调用 `krb5_get_output_token_buffer(auth_data)`
- **THEN** 函数 MUST return the current `output_token.value` pointer without copying it

Trace: `lib/krb5-wrapper.h:krb5_get_output_token_buffer`, `lib/krb5-wrapper.c:krb5_get_output_token_buffer`

### Requirement: krb5_get_output_token_length exposes current token length
系统 MUST 返回 `private_auth_data.output_token.length` 作为当前 GSS output token 长度。

#### Scenario: caller reads output token length
- **GIVEN** `auth_data` 包含最近一次 GSS operation 生成的 output token
- **WHEN** 调用 `krb5_get_output_token_length(auth_data)`
- **THEN** 函数 MUST return the current `output_token.length` value as an `int`

Trace: `lib/krb5-wrapper.h:krb5_get_output_token_length`, `lib/krb5-wrapper.c:krb5_get_output_token_length`

### Requirement: krb5_negotiate_reply creates client initiator credentials
系统 MUST 为 SMB 客户端 Kerberos negotiation 创建 `private_auth_data`，导入目标服务名和用户名，并获取 initiator credential。

#### Scenario: client credentials are created successfully
- **GIVEN** `smb2`, `server`, `user_name` and required credential inputs are valid
- **WHEN** 调用 `krb5_negotiate_reply(smb2, server, domain, user_name, password)`
- **THEN** 函数 MUST return a populated `private_auth_data` with target name, user name and initiator credential available for session setup

Trace: `lib/krb5-wrapper.h:krb5_negotiate_reply`, `lib/krb5-wrapper.c:krb5_negotiate_reply`

#### Scenario: cached credentials require domain and password
- **GIVEN** `smb2->use_cached_creds` is enabled
- **WHEN** `domain` or `password` is `NULL`
- **THEN** 函数 MUST fail by returning `NULL` and setting an SMB error about required domain and password

Trace: `lib/krb5-wrapper.h:krb5_negotiate_reply`, `lib/krb5-wrapper.c:krb5_negotiate_reply`

### Requirement: krb5_negotiate_request negotiate token initialization
系统 MUST expose `krb5_negotiate_request` as the SMB negotiate request Kerberos initialization entry point when `HAVE_LIBKRB5` is enabled.

#### Scenario: header declares negotiate request entry
- **GIVEN** Kerberos support is compiled with `HAVE_LIBKRB5`
- **WHEN** a translation unit includes `lib/krb5-wrapper.h`
- **THEN** the declaration for `krb5_negotiate_request(struct smb2_context *smb2, void **neg_init_token)` MUST be visible to callers

Trace: `lib/krb5-wrapper.h:krb5_negotiate_request`

### Requirement: krb5_session_get_session_key exports GSS session key
系统 MUST query the established GSS security context for the SSPI session key and store it on the SMB context.

#### Scenario: session key query succeeds
- **GIVEN** `auth_data->context` is an established GSS context with a non-empty session key
- **WHEN** 调用 `krb5_session_get_session_key(smb2, auth_data)`
- **THEN** 函数 MUST allocate `smb2->session_key`, copy the first returned key element, set `smb2->session_key_size`, release the GSS buffer set and return `0`

Trace: `lib/krb5-wrapper.h:krb5_session_get_session_key`, `lib/krb5-wrapper.c:krb5_session_get_session_key`

#### Scenario: session key query fails
- **GIVEN** GSSAPI does not return a complete, non-empty session key
- **WHEN** 调用 `krb5_session_get_session_key(smb2, auth_data)`
- **THEN** 函数 MUST set an SMB error and return `-1`

Trace: `lib/krb5-wrapper.h:krb5_session_get_session_key`, `lib/krb5-wrapper.c:krb5_session_get_session_key`

### Requirement: krb5_session_request advances client GSS token exchange
系统 MUST advance the client-side GSS security context and publish any output token in `auth_data->output_token`.

#### Scenario: client session token processing succeeds
- **GIVEN** `auth_data` contains initiator credentials and target name
- **WHEN** 调用 `krb5_session_request(smb2, auth_data, buf, len)` with an optional input token
- **THEN** 函数 MUST call GSS init security context with sequence, mutual and replay flags, preserve the output token in `auth_data`, and return `0` for complete or continue-needed states

Trace: `lib/krb5-wrapper.h:krb5_session_request`, `lib/krb5-wrapper.c:krb5_session_request`

#### Scenario: client session token processing fails
- **GIVEN** GSSAPI returns an error from security context initialization
- **WHEN** 调用 `krb5_session_request(smb2, auth_data, buf, len)`
- **THEN** 函数 MUST set a GSS-derived SMB error and return `-1`

Trace: `lib/krb5-wrapper.h:krb5_session_request`, `lib/krb5-wrapper.c:krb5_session_request`

### Requirement: krb5_init_server_client_cred creates server-side client credential state
系统 MUST create server-side `private_auth_data` with acceptor credentials and target name derived from the server hostname.

#### Scenario: server client credential initialization succeeds
- **GIVEN** a server and SMB context with supported security settings
- **WHEN** 调用 `krb5_init_server_client_cred(server, smb2, password)`
- **THEN** 函数 MUST return `private_auth_data` configured for GSS acceptor use and proxy-credential mode according to server settings

Trace: `lib/krb5-wrapper.h:krb5_init_server_client_cred`, `lib/krb5-wrapper.c:krb5_init_server_client_cred`

#### Scenario: server credential acquisition fails
- **GIVEN** GSSAPI cannot import the service name or acquire server credentials
- **WHEN** 调用 `krb5_init_server_client_cred(server, smb2, password)`
- **THEN** 函数 MUST set an SMB GSS error and return `NULL`

Trace: `lib/krb5-wrapper.h:krb5_init_server_client_cred`, `lib/krb5-wrapper.c:krb5_init_server_client_cred`

### Requirement: krb5_session_reply accepts server GSS token exchange
系统 MUST accept client GSS tokens, expose continuation state, and update SMB user/domain identity when the context completes.

#### Scenario: server needs more processing
- **GIVEN** GSSAPI reports `GSS_S_CONTINUE_NEEDED` while accepting a token
- **WHEN** 调用 `krb5_session_reply(smb2, auth_data, buf, len, more_processing_needed)`
- **THEN** 函数 MUST set `*more_processing_needed` to `1` and return `0`

Trace: `lib/krb5-wrapper.h:krb5_session_reply`, `lib/krb5-wrapper.c:krb5_session_reply`

#### Scenario: server accepts complete context
- **GIVEN** GSSAPI accepts the client token and returns a display name
- **WHEN** 调用 `krb5_session_reply(smb2, auth_data, buf, len, more_processing_needed)`
- **THEN** 函数 MUST set `*more_processing_needed` to `0`, update SMB user and domain from the displayed `user@domain` form when available, and return `0`

Trace: `lib/krb5-wrapper.h:krb5_session_reply`, `lib/krb5-wrapper.c:krb5_session_reply`

### Requirement: krb5_set_gss_error records GSS status text
系统 MUST convert GSS major and mechanism minor status codes to display strings and store them on the SMB context when a context is supplied.

#### Scenario: caller reports GSS error with SMB context
- **GIVEN** a non-NULL `smb2` context and GSS major/minor status values
- **WHEN** 调用 `krb5_set_gss_error(smb2, func, maj, min)`
- **THEN** 函数 MUST set an SMB error containing the function name and decoded major/minor status text

Trace: `lib/krb5-wrapper.h:krb5_set_gss_error`, `lib/krb5-wrapper.c:krb5_set_gss_error`

#### Scenario: caller reports GSS error without SMB context
- **GIVEN** `smb2` is `NULL`
- **WHEN** 调用 `krb5_set_gss_error(NULL, func, maj, min)`
- **THEN** 函数 MUST release any allocated status text and MUST NOT dereference the missing SMB context

Trace: `lib/krb5-wrapper.h:krb5_set_gss_error`, `lib/krb5-wrapper.c:krb5_set_gss_error`

### Requirement: krb5_can_do_ntlmssp reports NTLMSSP mechanism support
系统 MUST report whether the current GSSAPI/Kerberos stack can inquire attributes for the NTLMSSP SPNEGO mechanism.

#### Scenario: non-Apple NTLMSSP capability succeeds
- **GIVEN** the platform is not Apple and `gss_inquire_attrs_for_mech` succeeds for `spnego_mech_ntlmssp`
- **WHEN** 调用 `krb5_can_do_ntlmssp()`
- **THEN** 函数 MUST release returned OID sets and return `1`

Trace: `lib/krb5-wrapper.h:krb5_can_do_ntlmssp`, `lib/krb5-wrapper.c:krb5_can_do_ntlmssp`

#### Scenario: Apple or GSSAPI capability failure reports unsupported
- **GIVEN** the platform is Apple or GSSAPI reports an error for the NTLMSSP mechanism
- **WHEN** 调用 `krb5_can_do_ntlmssp()`
- **THEN** 函数 MUST return `0`

Trace: `lib/krb5-wrapper.h:krb5_can_do_ntlmssp`, `lib/krb5-wrapper.c:krb5_can_do_ntlmssp`

### Requirement: krb5_init_server_credentials initializes keytab-backed server credentials
系统 MUST initialize keytab-backed server credential state only when a non-empty keytab path is supplied.

#### Scenario: keytab path is absent
- **GIVEN** `server` is NULL or `keytab_path` is NULL or empty
- **WHEN** 调用 `krb5_init_server_credentials(server, keytab_path)`
- **THEN** 函数 MUST return `0` without creating server auth data

Trace: `lib/krb5-wrapper.h:krb5_init_server_credentials`, `lib/krb5-wrapper.c:krb5_init_server_credentials`

#### Scenario: keytab-backed credentials initialize successfully
- **GIVEN** a server with hostname and a non-empty keytab path
- **WHEN** 调用 `krb5_init_server_credentials(server, keytab_path)`
- **THEN** 函数 MUST create auth data, import `cifs@hostname`, initialize Kerberos context, principal, keytab and memory credential cache, assign `server->auth_data`, and return `0`

Trace: `lib/krb5-wrapper.h:krb5_init_server_credentials`, `lib/krb5-wrapper.c:krb5_init_server_credentials`

### Requirement: krb5_renew_server_credentials refreshes keytab credentials
系统 MUST refresh stored server credentials from the configured keytab when auth data and keytab are available.

#### Scenario: no keytab-backed auth data exists
- **GIVEN** `server->auth_data` is absent or does not contain a keytab
- **WHEN** 调用 `krb5_renew_server_credentials(server)`
- **THEN** 函数 MUST return `0`

Trace: `lib/krb5-wrapper.h:krb5_renew_server_credentials`, `lib/krb5-wrapper.c:krb5_renew_server_credentials`

#### Scenario: keytab credential renewal fails
- **GIVEN** keytab-backed auth data exists but Kerberos initialization or cache storage fails
- **WHEN** 调用 `krb5_renew_server_credentials(server)`
- **THEN** 函数 MUST write a descriptive `server->error` message and return the Kerberos error code

Trace: `lib/krb5-wrapper.h:krb5_renew_server_credentials`, `lib/krb5-wrapper.c:krb5_renew_server_credentials`

### Requirement: krb5_free_server_credentials clears server auth data
系统 MUST release stored server Kerberos credentials and clear `server->auth_data` when present.

#### Scenario: server credentials are present
- **GIVEN** `server` is non-NULL and `server->auth_data` is non-NULL
- **WHEN** 调用 `krb5_free_server_credentials(server)`
- **THEN** 函数 MUST free the auth data and set `server->auth_data` to `NULL`

Trace: `lib/krb5-wrapper.h:krb5_free_server_credentials`, `lib/krb5-wrapper.c:krb5_free_server_credentials`

## Open Questions

| ID | Question | Related Interface | Reason |
| --- | --- | --- | --- |
| Q-001 | `krb5_negotiate_request` 在当前源码回读中只有声明未发现实现，是否为过期声明或条件编译遗漏？ | `krb5_negotiate_request` | `lib/krb5-wrapper.h` 声明该接口，但 `lib/krb5-wrapper.c` 和仓库搜索未定位到定义。 |
| Q-002 | GitNexus 对 `lib/krb5-wrapper.h` 声明级 symbol 的 upstream impact 返回 0 个直接调用者，是否需要把实现文件 symbol 作为主归属补充到 `lib/krb5-wrapper.c` spec？ | file-level | 调用关系实际存在于 `lib/libsmb2.c` 到实现函数之间，头文件 symbol 索引未反映这些调用。 |
