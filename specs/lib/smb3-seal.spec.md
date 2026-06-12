# lib/smb3-seal.c Specification

## Source Context

- Source: `lib/smb3-seal.c`
- Related Headers: `lib/smb3-seal.h`, `lib/aes128ccm.h`, `include/libsmb2-private.h`, `include/portable-endian.h`
- Related Tests: `tests/prog_cat.c`, `tests/prog_cat_cancel.c`
- Related Dependencies: `smb2_queue_pdu`, `smb2_add_to_outqueue`, `smb2_read_from_buf`, `smb2_add_iovector`, `smb2_free_iovector`, `smb2_set_error`, `aes128ccm_encrypt`, `aes128ccm_decrypt`, `random`
- Build/Compile Context: `CMakeLists.txt` and `lib/CMakeLists.txt` build the C library; `HAVE_CONFIG_H`, `HAVE_STDINT_H`, `HAVE_STDLIB_H`, `HAVE_STRING_H`, `HAVE_SYS_UIO_H`, `HAVE_SYS__IOVEC_H`, `HAVE_TIME_H`, and `HAVE_SYS_TIME_H` conditionally include platform headers.

## Interface Summary

| Interface | Kind | Signature | Decision | Reason |
| --- | --- | --- | --- | --- |
| smb3_encrypt_pdu | function | int smb3_encrypt_pdu(struct smb2_context *smb2, struct smb2_pdu *pdu); | Include | 头文件声明的跨文件 SMB3 sealing 入口，被 `smb2_queue_pdu` 发送路径调用，具有可观察的 transform header、密文缓冲区和错误返回语义。 |
| smb3_decrypt_pdu | function | int smb3_decrypt_pdu(struct smb2_context *smb2); | Include | 头文件声明的跨文件 SMB3 unsealing 入口，被接收状态机用于 transform payload，具有可观察的解密、接收状态重置和错误状态语义。 |
| xfer | data | static const char xfer[4] = {0xFD, 'S', 'M', 'B'}; | Skip | 文件内静态 transform protocol id 常量，行为并入 `smb3_encrypt_pdu` 的 transform header 契约。 |

## Data Model Summary

| Type/Macro | Kind | Definition | Notes |
| --- | --- | --- | --- |
| xfer | macro | `lib/smb3-seal.c:68` | SMB3 transform header 的 4 字节 protocol id `{0xFD, 'S', 'M', 'B'}`，源码为 `static const char`，仅通过加密输出缓冲区对调用方可观察。 |

## ADDED Requirements

### Requirement: smb3_encrypt_pdu SMB3 transform encryption
系统 MUST 在上下文和 PDU 均启用 sealing 时为待发送 PDU 链构造 SMB3 transform buffer，并 MUST 使用 AES-128-CCM 对 transform header 后的 payload 原地加密和写入认证标签。

#### Scenario: sealing 未启用时保持 PDU 未加密
- **GIVEN** 调用方提供有效 `smb2` 和 `pdu`，且 `smb2->seal == 0` 或 `pdu->seal == 0`
- **WHEN** 调用方执行 `smb3_encrypt_pdu(smb2, pdu)`
- **THEN** 函数 MUST 返回 `0`，并且 MUST NOT 分配或填充 `pdu->crypt`

Trace: `lib/smb3-seal.c:smb3_encrypt_pdu`

#### Scenario: transform header and encrypted payload are emitted
- **GIVEN** `smb2->seal == 1`、`pdu->seal == 1`，且当前 PDU 及其 compound 链的 `out.iov` 描述待发送 payload
- **WHEN** 调用方执行 `smb3_encrypt_pdu(smb2, pdu)`
- **THEN** 函数 MUST 分配长度为 52 字节 transform header 加全部 compound 输出向量长度的 `pdu->crypt`，MUST 写入 `{0xFD, 'S', 'M', 'B'}`、original message size、`SMB_ENCRYPTION_AES128_CCM` 和 `smb2->session_id`，并 MUST 将所有 compound 输出向量复制到 header 后再调用 `aes128ccm_encrypt`

Trace: `lib/smb3-seal.c:smb3_encrypt_pdu`, `lib/aes128ccm.c:aes128ccm_encrypt`

#### Scenario: allocation failure disables this PDU sealing
- **GIVEN** `smb2->seal == 1`、`pdu->seal == 1`，且 transform buffer allocation fails
- **WHEN** `smb3_encrypt_pdu(smb2, pdu)` 尝试分配 `pdu->crypt`
- **THEN** 函数 MUST set `pdu->seal` to `0` and MUST return `-1`

Trace: `lib/smb3-seal.c:smb3_encrypt_pdu`

### Requirement: smb3_decrypt_pdu SMB3 transform decryption
系统 MUST 使用 server output key 校验并解密接收的 SMB3 transform payload，并 MUST 将解密后的缓冲区重新送入普通 SMB2 接收状态机。

#### Scenario: authentication failure reports decrypt error
- **GIVEN** 接收 iovector 中倒数第二个元素包含 SMB3 transform header，最后一个元素包含 encrypted payload，且认证标签校验失败
- **WHEN** 调用方执行 `smb3_decrypt_pdu(smb2)`
- **THEN** 函数 MUST 调用 `smb2_set_error(smb2, "Failed to decrypt PDU")` and MUST return `-1`

Trace: `lib/smb3-seal.c:smb3_decrypt_pdu`, `lib/aes128ccm.c:aes128ccm_decrypt`

#### Scenario: first decrypted payload resets receive state
- **GIVEN** `aes128ccm_decrypt` returns `0` and `smb2->in.num_done == 0`
- **WHEN** 调用方执行 `smb3_decrypt_pdu(smb2)`
- **THEN** 函数 MUST transfer ownership of decrypted payload to `smb2->enc`, MUST free the encrypted input iovector without freeing that payload, MUST set `smb2->spl` to decrypted payload length, MUST set `smb2->recv_state` to `SMB2_RECV_HEADER`, and MUST add an input iovector for `smb2->header`

Trace: `lib/smb3-seal.c:smb3_decrypt_pdu`, `lib/init.c:smb2_free_iovector`, `lib/init.c:smb2_add_iovector`

#### Scenario: decrypted buffer is consumed and released
- **GIVEN** decryption succeeded and the receive state has been prepared for a decrypted SMB2 header
- **WHEN** `smb3_decrypt_pdu(smb2)` calls `smb2_read_from_buf(smb2)`
- **THEN** 函数 MUST return the `smb2_read_from_buf` result, MUST free `smb2->enc`, and MUST set `smb2->enc` to `NULL`

Trace: `lib/smb3-seal.c:smb3_decrypt_pdu`, `lib/socket.c:smb2_read_from_buf`

#### Scenario: header iovector setup failure releases decrypted buffer
- **GIVEN** decryption succeeds, `smb2->in.num_done == 0`, and adding the decrypted SMB2 header iovector fails
- **WHEN** `smb3_decrypt_pdu(smb2)` detects `smb2_add_iovector(...) == NULL`
- **THEN** 函数 MUST set error text `Failed to add iovector for decrypted header`, MUST free `smb2->enc`, MUST set `smb2->enc` to `NULL`, and MUST return `-1`

Trace: `lib/smb3-seal.c:smb3_decrypt_pdu`, `lib/init.c:smb2_add_iovector`

## Open Questions

| ID | Question | Related Interface | Reason |
| --- | --- | --- | --- |
| Q-001 | `smb3_encrypt_pdu` 返回 `-1` 时 `smb2_queue_pdu` 当前未检查返回值，是否应继续把已降级为未 sealed 的 PDU 加入 outqueue。 | smb3_encrypt_pdu | 源码中 `smb2_queue_pdu` 直接调用 `smb3_encrypt_pdu(smb2, pdu)` 后继续 `smb2_add_to_outqueue`，错误传播策略未在声明中说明。 |
| Q-002 | transform nonce 只填充 `pdu->crypt[20]` 到 `pdu->crypt[30]` 共 11 字节，`pdu->crypt[31]` 保持 calloc 零值是否是 SMB3 AES-128-CCM 固定要求。 | smb3_encrypt_pdu | `aes128ccm_encrypt` 使用 11 字节 nonce 和 32 字节 AAD，源码未注释 byte 31 的协议含义。 |
| Q-003 | GitNexus `impact` 对 `smb3_decrypt_pdu` 未返回上游调用者，但源码中 `lib/socket.c` 的 `SMB2_RECV_TRFM` 分支调用该函数。 | smb3_decrypt_pdu | GitNexus 上游影响结果与源码回读存在索引差异。 |
