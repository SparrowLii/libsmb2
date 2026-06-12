# lib/smb3-seal.h Specification

## Source Context

- Source: `lib/smb3-seal.h`
- Related Headers: `lib/smb3-seal.c`, `lib/aes128ccm.h`, `lib/smb2.h`, `lib/libsmb2-private.h`
- Related Tests: `tests/prog_cat.c`, `tests/prog_cat_cancel.c`
- Related Dependencies: GitNexus context maps `smb3_encrypt_pdu` implementation to caller `lib/pdu.c:smb2_queue_pdu` and callees `lib/aes128ccm.c:aes128ccm_encrypt`, `lib/compat.c:random`; `smb3_decrypt_pdu` implementation maps to callees `lib/aes128ccm.c:aes128ccm_decrypt`, `lib/init.c:smb2_free_iovector`, `lib/init.c:smb2_add_iovector`, `lib/init.c:smb2_set_error`.
- Build/Compile Context: C project; `HAVE_CONFIG_H` controls optional `config.h` include; `_GNU_SOURCE` is defined by this header when absent; declarations are wrapped in `extern "C"` under `__cplusplus`.

## Interface Summary

| Interface | Kind | Signature | Decision | Reason |
| --- | --- | --- | --- | --- |
| smb3_encrypt_pdu | function | int smb3_encrypt_pdu(struct smb2_context *smb2, struct smb2_pdu *pdu); | Include | SMB3 发送路径加密入口，跨文件由 PDU 出队前流程调用，具有可观察的返回值、密文缓冲区和密封状态语义。 |
| smb3_decrypt_pdu | function | int smb3_decrypt_pdu(struct smb2_context *smb2); | Include | SMB3 接收路径解密入口，跨文件由 socket 接收状态机调用，具有可观察的错误设置、接收状态和解密缓冲区生命周期语义。 |

## Data Model Summary

| Type/Macro | Kind | Definition | Notes |
| --- | --- | --- | --- |
| _SMB3_SEAL_H_ | macro | lib/smb3-seal.h:2 | 头文件 include guard，防止重复声明。 |
| _GNU_SOURCE | macro | lib/smb3-seal.h:25 | 当调用方未定义 `_GNU_SOURCE` 时，本头文件会定义该特性宏。 |

## ADDED Requirements

### Requirement: smb3_encrypt_pdu SMB3 outbound transform sealing
系统 MUST 在连接和 PDU 均启用 sealing 时，为待发送 PDU 链构造 SMB3 transform 加密缓冲区；在任一 sealing 标志未启用时 MUST 返回成功且不创建加密缓冲区。

#### Scenario: sealing disabled is a no-op
- **GIVEN** 调用方提供 `struct smb2_context *smb2` 和 `struct smb2_pdu *pdu`，且 `smb2->seal` 或 `pdu->seal` 为 0
- **WHEN** 调用 `smb3_encrypt_pdu(smb2, pdu)`
- **THEN** 函数返回 0，并保持未执行 SMB3 transform 加密分配路径

Trace: `lib/smb3-seal.h:smb3_encrypt_pdu`, `lib/smb3-seal.c:smb3_encrypt_pdu`

#### Scenario: transform buffer allocation failure disables pdu sealing
- **GIVEN** `smb2->seal` 和 `pdu->seal` 均启用，且 transform 缓冲区分配失败
- **WHEN** 调用 `smb3_encrypt_pdu(smb2, pdu)`
- **THEN** 函数 MUST 将 `pdu->seal` 置为 0，并返回 -1

Trace: `lib/smb3-seal.h:smb3_encrypt_pdu`, `lib/smb3-seal.c:smb3_encrypt_pdu`

#### Scenario: enabled sealing emits AES-128-CCM transform payload
- **GIVEN** `smb2->seal` 和 `pdu->seal` 均启用，且 PDU 及 compound PDU 的输出 iovec 可用于计算明文长度
- **WHEN** 调用 `smb3_encrypt_pdu(smb2, pdu)`
- **THEN** 函数 MUST 创建以 52 字节 transform header 开头的 `pdu->crypt` 缓冲区，写入 `0xFD 'S' 'M' 'B'` protocol id、随机 nonce 字节、原始消息大小、`SMB_ENCRYPTION_AES128_CCM` 算法、`smb2->session_id`，并通过 AES-128-CCM 生成认证标签后设置 `pdu->crypt_len`

Trace: `lib/smb3-seal.h:smb3_encrypt_pdu`, `lib/smb3-seal.c:smb3_encrypt_pdu`, `lib/pdu.c:smb2_queue_pdu`

### Requirement: smb3_decrypt_pdu SMB3 inbound transform unsealing
系统 MUST 使用接收 transform header 和密文 payload 对 SMB3 入站 PDU 执行 AES-128-CCM 解密；认证或解密失败时 MUST 设置错误并返回 -1。

#### Scenario: decryption failure reports error
- **GIVEN** `smb2->in` 包含 SMB3 transform header iovec 和密文 payload iovec，且 AES-128-CCM 解密返回失败
- **WHEN** 调用 `smb3_decrypt_pdu(smb2)`
- **THEN** 函数 MUST 设置错误消息 `Failed to decrypt PDU` 并返回 -1

Trace: `lib/smb3-seal.h:smb3_decrypt_pdu`, `lib/smb3-seal.c:smb3_decrypt_pdu`

#### Scenario: first decrypted fragment resets receive parser
- **GIVEN** AES-128-CCM 解密成功，且 `smb2->in.num_done` 为 0
- **WHEN** 调用 `smb3_decrypt_pdu(smb2)`
- **THEN** 函数 MUST 将解密 payload 转移到 `smb2->enc`，释放旧输入 iovector，将 `smb2->spl` 设置为解密 payload 长度，将 `smb2->recv_state` 设置为 `SMB2_RECV_HEADER`，并添加用于解析 SMB2 header 的 iovector

Trace: `lib/smb3-seal.h:smb3_decrypt_pdu`, `lib/smb3-seal.c:smb3_decrypt_pdu`, `lib/socket.c:smb2_read_data`

#### Scenario: decrypted payload is parsed and released
- **GIVEN** AES-128-CCM 解密成功，且接收解析器已准备从 `smb2->enc` 读取解密 payload
- **WHEN** `smb3_decrypt_pdu(smb2)` 调用 `smb2_read_from_buf(smb2)` 完成解析
- **THEN** 函数 MUST 释放 `smb2->enc`，将 `smb2->enc` 置为 `NULL`，并返回 `smb2_read_from_buf` 的结果

Trace: `lib/smb3-seal.h:smb3_decrypt_pdu`, `lib/smb3-seal.c:smb3_decrypt_pdu`

## Open Questions

| ID | Question | Related Interface | Reason |
| --- | --- | --- | --- |
| Q-001 | `smb3_decrypt_pdu` 的 GitNexus upstream impact 未识别 `lib/socket.c` 中的直接调用，是否为索引解析限制或调用图缺口？ | smb3_decrypt_pdu | 源码回读确认 `lib/socket.c` 调用该接口，但 GitNexus impact 返回 0 个 upstream 影响。 |
| Q-002 | 当前测试是否存在直接覆盖 SMB3 sealing 成功、认证失败和 allocation failure 的断言？ | smb3_encrypt_pdu, smb3_decrypt_pdu | GitNexus impact 仅显示间接受影响测试程序，未定位到针对这些接口的直接单元断言。 |
