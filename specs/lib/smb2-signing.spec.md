# lib/smb2-signing.c Specification

## Source Context

- Source: `lib/smb2-signing.c`
- Related Headers: `lib/smb2-signing.h`, `include/libsmb2-private.h`, `include/smb2/smb2.h`, `lib/aes.h`, `lib/sha.h`, `lib/sha-private.h`, `lib/compat.h`
- Related Tests: `tests/prog_cat.c`, `tests/prog_cat_cancel.c`
- Related Dependencies: GitNexus context shows `smb2_calc_signature` is called by `lib/libsmb2.c:session_setup_cb` and `lib/smb2-signing.c:smb2_pdu_add_signature`; `smb2_pdu_add_signature` is called by `lib/pdu.c:smb2_queue_pdu`; `smb3_aes_cmac_128` is called by `smb2_calc_signature` and calls `AES128_ECB_encrypt`, `aes_cmac_sub_keys`, and `aes_cmac_xor`; `smb2_pdu_check_signature` has no indexed callers.
- Build/Compile Context: C source compiled with optional `HAVE_CONFIG_H`, `_GNU_SOURCE`, `HAVE_STDINT_H`, `HAVE_STDLIB_H`, `HAVE_STRING_H`, `STDC_HEADERS`, `HAVE_SYS_TYPES_H`, `HAVE_SYS_STAT_H`, `HAVE_UNISTD_H`, and `HAVE_SYS_UNISTD_H`; file-local `EBC` is set to `1` and `CBC` defaults to `1` before including AES/SHA dependencies.

## Interface Summary

| Interface | Kind | Signature | Decision | Reason |
| --- | --- | --- | --- | --- |
| `smb3_aes_cmac_128` | function | `void smb3_aes_cmac_128(uint8_t key[AES128_KEY_LEN], uint8_t * msg, uint64_t msg_len, uint8_t mac[AES128_KEY_LEN])` | Include | AES-CMAC 结果被 SMB3 签名路径调用，影响调用方可观察的 SMB2/3 signature bytes。 |
| `smb2_calc_signature` | function | `int smb2_calc_signature(struct smb2_context *smb2, uint8_t *signature, struct smb2_iovec *iov, size_t niov)` | Include | 由接收校验和发送签名路径跨文件调用，负责选择 HMAC-SHA256 或 AES-CMAC 并写入 16 字节签名。 |
| `smb2_pdu_add_signature` | function | `int smb2_pdu_add_signature(struct smb2_context *smb2, struct smb2_pdu *pdu)` | Include | 由 PDU queue 路径跨文件调用，设置 signed flag、校验输出向量并写回 header signature。 |
| `smb2_pdu_check_signature` | function | `int smb2_pdu_check_signature(struct smb2_context *smb2, struct smb2_pdu *pdu)` | Include | 头文件公开声明且实现固定返回成功，调用方可观察到该占位校验行为。 |
| `aes_cmac_shift_left` | function | `static int aes_cmac_shift_left(uint8_t data[AES128_KEY_LEN])` | Skip | 纯内部 helper，仅服务 AES-CMAC subkey 生成，无独立跨文件契约。 |
| `aes_cmac_xor` | function | `static void aes_cmac_xor(uint8_t data[AES128_KEY_LEN], const uint8_t value[AES128_KEY_LEN])` | Skip | 纯内部 helper，仅执行 CMAC 块异或，无独立跨文件契约。 |
| `aes_cmac_sub_keys` | function | `static void aes_cmac_sub_keys(uint8_t key[AES128_KEY_LEN], uint8_t sub_key1[AES128_KEY_LEN], uint8_t sub_key2[AES128_KEY_LEN])` | Skip | 纯内部 helper，仅生成 CMAC 子密钥并由 `smb3_aes_cmac_128` 覆盖。 |

## Data Model Summary

| Type/Macro | Kind | Definition | Notes |
| --- | --- | --- | --- |
| `EBC` | macro | `lib/smb2-signing.c:62` | 本文件在包含 AES 头之前定义为 `1`；拼写是否应为 ECB 未在源码中确认。 |
| `CBC` | macro | `lib/smb2-signing.c:64` | 如果调用方尚未定义 `CBC`，本文件默认定义为 `1` 以影响 AES 依赖编译路径。 |
| `AES128_KEY_LEN` | macro | `lib/smb2-signing.c:72` | AES-CMAC key、subkey 和 MAC 缓冲区长度固定为 16 字节。 |
| `AES_BLOCK_SIZE` | macro | `lib/smb2-signing.c:73` | AES-CMAC 临时块长度固定为 16 字节。 |

## ADDED Requirements

### Requirement: smb3_aes_cmac_128 computes a 128-bit AES-CMAC
系统 MUST 使用 16 字节 key、消息缓冲区和消息长度计算 16 字节 AES-CMAC，并将最终 MAC 写入调用方提供的 `mac` 缓冲区。

#### Scenario: empty message uses padded final block
- **GIVEN** `msg_len` 为 `0` 且调用方提供 16 字节 key 与 16 字节 `mac` 输出缓冲区
- **WHEN** 调用 `smb3_aes_cmac_128`
- **THEN** 函数 MUST 生成 CMAC 子密钥、清零初始 MAC、按 `0x80` padding 处理一个空最终块，并写入 16 字节 MAC

Trace: `lib/smb2-signing.c:smb3_aes_cmac_128`

#### Scenario: complete final block uses first subkey
- **GIVEN** `msg_len` 大于 `0` 且是 16 字节块长度的整数倍
- **WHEN** 调用 `smb3_aes_cmac_128`
- **THEN** 函数 MUST 对前置完整块迭代异或并 AES-ECB 加密，最后一个完整块 MUST 与 `sub_key1` 异或后参与最终 AES-ECB 加密

Trace: `lib/smb2-signing.c:smb3_aes_cmac_128`

#### Scenario: partial final block uses padding and second subkey
- **GIVEN** `msg_len` 不是 16 字节块长度的整数倍
- **WHEN** 调用 `smb3_aes_cmac_128`
- **THEN** 函数 MUST 复制剩余字节、追加 `0x80`、用零填满 16 字节块，并将该块与 `sub_key2` 异或后输出最终 MAC

Trace: `lib/smb2-signing.c:smb3_aes_cmac_128`

### Requirement: smb2_calc_signature chooses dialect-specific signing
系统 MUST 在写入签名前先清零 SMB2 header signature 字段，并根据 dialect 选择 SMB3 AES-CMAC 或 SMB2 HMAC-SHA256 签名算法。

#### Scenario: SMB3 dialect signs concatenated iovectors
- **GIVEN** `smb2->dialect` 大于 `SMB2_VERSION_0210`，且 `iov` 中包含待签名 SMB2 header 与 payload 向量
- **WHEN** 调用 `smb2_calc_signature`
- **THEN** 函数 MUST 清零 `iov[0].buf + 48` 处的 16 字节 signature 字段，分配连续缓冲区拼接全部 iovec 内容，使用 `smb3_aes_cmac_128` 计算 MAC，并复制 `SMB2_SIGNATURE_SIZE` 字节到 `signature`

Trace: `lib/smb2-signing.c:smb2_calc_signature`, `lib/libsmb2.c:session_setup_cb`, `lib/socket.c:smb2_service`

#### Scenario: SMB3 allocation failure reports signing error
- **GIVEN** `smb2->dialect` 大于 `SMB2_VERSION_0210` 且连续消息缓冲区分配失败
- **WHEN** 调用 `smb2_calc_signature`
- **THEN** 函数 MUST 通过 `smb2_set_error` 记录 signature calculation 分配失败，并返回 `-1`

Trace: `lib/smb2-signing.c:smb2_calc_signature`

#### Scenario: SMB2 dialect signs with HMAC-SHA256
- **GIVEN** `smb2->dialect` 小于或等于 `SMB2_VERSION_0210`，且 `iov` 指向待签名数据
- **WHEN** 调用 `smb2_calc_signature`
- **THEN** 函数 MUST 使用 `smb2->signing_key` 和 `SMB2_KEY_SIZE` 初始化 SHA256 HMAC，将每个 iovec 输入 HMAC，并复制前 `SMB2_SIGNATURE_SIZE` 字节 digest 到 `signature`

Trace: `lib/smb2-signing.c:smb2_calc_signature`, `lib/libsmb2.c:session_setup_cb`, `lib/socket.c:smb2_service`

### Requirement: smb2_pdu_add_signature applies signing to eligible PDUs
系统 MUST 对具备会话、签名 key 和有效输出向量的 PDU 设置 signed flag、计算签名并同步更新内存 header 与 wire header。

#### Scenario: first successful session setup response may be signed
- **GIVEN** PDU command 为 `SMB2_SESSION_SETUP`
- **WHEN** PDU status 非零或 PDU flags 不包含 `SMB2_FLAGS_SERVER_TO_REDIR`
- **THEN** `smb2_pdu_add_signature` MUST 返回 `0` 且不签名该 PDU

Trace: `lib/smb2-signing.c:smb2_pdu_add_signature`

#### Scenario: output vector shape is rejected
- **GIVEN** PDU 输出向量少于两个，或第一个输出向量长度不是 `SMB2_HEADER_SIZE`
- **WHEN** 调用 `smb2_pdu_add_signature`
- **THEN** 函数 MUST 设置描述性错误并返回 `-1`

Trace: `lib/smb2-signing.c:smb2_pdu_add_signature`, `lib/pdu.c:smb2_queue_pdu`

#### Scenario: unsigned session state is skipped or rejected
- **GIVEN** PDU 输出向量有效
- **WHEN** `smb2->session_id` 为 `0`
- **THEN** 函数 MUST 返回 `0` 且不设置签名

Trace: `lib/smb2-signing.c:smb2_pdu_add_signature`

#### Scenario: missing session key rejects signing
- **GIVEN** PDU 输出向量有效且 `smb2->session_id` 非零
- **WHEN** `smb2->session_key_size` 为 `0`
- **THEN** 函数 MUST 返回 `-1` 且不写入签名

Trace: `lib/smb2-signing.c:smb2_pdu_add_signature`

#### Scenario: eligible PDU receives signature bytes
- **GIVEN** PDU 输出向量有效、`smb2->session_id` 非零且 `smb2->session_key_size` 非零
- **WHEN** 调用 `smb2_pdu_add_signature`
- **THEN** 函数 MUST 在 header flags 中设置 `SMB2_FLAGS_SIGNED`，通过 `smb2_set_uint32` 写回 wire flags，调用 `smb2_calc_signature`，并把 16 字节 signature 同步到 `pdu->header.signature` 和 `iov[0].buf + 48`

Trace: `lib/smb2-signing.c:smb2_pdu_add_signature`, `lib/pdu.c:smb2_queue_pdu`

### Requirement: smb2_pdu_check_signature reports success
系统 MUST 保持当前占位校验行为：对任意输入返回 `0`，且不修改 PDU 或 context 中的签名状态。

#### Scenario: check signature is a no-op success
- **GIVEN** 调用方传入 `struct smb2_context *smb2` 和 `struct smb2_pdu *pdu`
- **WHEN** 调用 `smb2_pdu_check_signature`
- **THEN** 函数 MUST 返回 `0`

Trace: `lib/smb2-signing.c:smb2_pdu_check_signature`

## Open Questions

| ID | Question | Related Interface | Reason |
| --- | --- | --- | --- |
| Q-001 | `smb3_aes_cmac_128` 对 `msg == NULL` 且 `msg_len == 0` 是否允许？ | `smb3_aes_cmac_128` | 源码在不完整最终块路径会读取 `&msg[i*AES128_KEY_LEN]`，前置条件未由声明或测试确认。 |
| Q-002 | `smb2_calc_signature` 的 SMB3 分支对 `len` 的 size_t 累加溢出是否需要显式错误语义？ | `smb2_calc_signature` | 源码直接累加所有 iov 长度并分配，未确认调用方是否保证长度不会溢出。 |
| Q-003 | `smb2_pdu_add_signature` 在 `session_key_size == 0` 返回 `-1` 时是否应设置 `smb2` 错误信息？ | `smb2_pdu_add_signature` | 其他拒绝路径设置错误字符串，该路径未设置错误，调用方 `smb2_queue_pdu` 会拼接现有错误。 |
| Q-004 | `smb2_pdu_check_signature` 是否计划实现真正的 signature 校验？ | `smb2_pdu_check_signature` | 头文件公开声明但实现固定返回 `0`，GitNexus 未定位调用方。 |
| Q-005 | `EBC` 宏是否为 `ECB` 拼写错误或外部依赖约定？ | file-level | 本文件定义 `EBC 1`，但 AES 语义通常使用 ECB，源码未说明该宏用途。 |
