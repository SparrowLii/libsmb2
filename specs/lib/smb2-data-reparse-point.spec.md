# lib/smb2-data-reparse-point.c Specification

## Source Context

- Source: `lib/smb2-data-reparse-point.c`
- Related Headers: `include/libsmb2-private.h`, `include/smb2/smb2.h`, `include/smb2/libsmb2.h`, `lib/compat.h`
- Related Tests: `none`
- Related Dependencies: GitNexus context shows caller `smb2_process_ioctl_variable` in `lib/smb2-cmd-ioctl.c` and callees `smb2_alloc_data`, `smb2_get_uint16`, `smb2_get_uint32`, `smb2_utf16_to_utf8`; impact risk LOW with direct caller `smb2_process_ioctl_variable` and upstream reply payload processing.
- Build/Compile Context: C source compiled through the core libsmb2 library; conditional includes depend on `HAVE_CONFIG_H`, `HAVE_STDINT_H`, `HAVE_STDLIB_H`, `HAVE_STRING_H`, `STDC_HEADERS`, `HAVE_TIME_H`, and `HAVE_SYS_TIME_H`.

## Interface Summary

| Interface | Kind | Signature | Decision | Reason |
| --- | --- | --- | --- | --- |
| smb2_decode_reparse_data_buffer | function | `int smb2_decode_reparse_data_buffer(struct smb2_context *smb2, void *memctx, struct smb2_reparse_data_buffer *rp, struct smb2_iovec *vec);` | Include | 内部跨文件解码入口，由 ioctl reply variable parser 调用，向 readlink flow 提供 reparse tag 和 symlink 名称输出。 |
| SMB2_REPARSE_TAG_SYMLINK | macro | `#define SMB2_REPARSE_TAG_SYMLINK                0xa000000c` | Skip | 数据模型常量已在 `include/smb2/smb2.spec.md` 归属，本文件仅消费该 tag。 |
| struct smb2_symlink_reparse_buffer | type | `struct smb2_symlink_reparse_buffer { uint32_t flags; char *subname; char *printname; };` | Skip | 公开数据模型已在 `include/smb2/smb2.spec.md` 归属，本文件仅填充字段。 |
| struct smb2_reparse_data_buffer | type | `struct smb2_reparse_data_buffer { uint32_t reparse_tag; uint16_t reparse_data_length; union { struct smb2_symlink_reparse_buffer symlink; }; };` | Skip | 公开数据模型已在 `include/smb2/smb2.spec.md` 归属，本文件仅填充字段。 |

## Data Model Summary

| Type/Macro | Kind | Definition | Notes |
| --- | --- | --- | --- |
| SMB2_REPARSE_TAG_SYMLINK | macro | `include/smb2/smb2.h:991` | 识别 symlink reparse buffer 的 tag 值。 |
| struct smb2_symlink_reparse_buffer | struct | `include/smb2/smb2.h:985` | 保存 symlink flags、subname 和 printname 输出字段。 |
| struct smb2_reparse_data_buffer | struct | `include/smb2/smb2.h:995` | 保存 reparse tag、payload length 和 symlink union 输出。 |

## ADDED Requirements

### Requirement: smb2_decode_reparse_data_buffer decode and validate reparse payload
系统 MUST 在读取 reparse header、tag-specific header 或 symlink name 字段前验证输入 `vec` 长度与 reparse data length 边界，越界输入返回 `-1`；系统 MUST 对 `SMB2_REPARSE_TAG_SYMLINK` payload 解码 flags、substitute name 和 print name，并将 UTF-16 名称转换为以 NUL 结尾的 UTF-8 字符串存入 `rp->symlink`；系统 MUST 对非 `SMB2_REPARSE_TAG_SYMLINK` 的 tag 只填充通用 `reparse_tag` 和 `reparse_data_length` 字段，在通用 buffer 边界合法时返回 `0`。

#### Scenario: short buffer rejected
- **GIVEN** 调用方提供长度小于 8 字节的 `struct smb2_iovec`
- **WHEN** 调用 `smb2_decode_reparse_data_buffer`
- **THEN** 函数返回 `-1`，并且不读取 reparse tag 或 data length 字段

Trace: `lib/smb2-data-reparse-point.c:smb2_decode_reparse_data_buffer`

#### Scenario: declared data length exceeds vector rejected
- **GIVEN** 输入 buffer 至少包含 reparse header，但 header 中的 `reparse_data_length + 8` 超过 `vec->len`
- **WHEN** 调用 `smb2_decode_reparse_data_buffer`
- **THEN** 函数返回 `-1`，并且不继续解析 tag-specific payload

Trace: `lib/smb2-data-reparse-point.c:smb2_decode_reparse_data_buffer`

#### Scenario: symlink offsets outside payload rejected
- **GIVEN** 输入 tag 为 `SMB2_REPARSE_TAG_SYMLINK`，但 substitute name 或 print name 的 offset 和 length 超出 `reparse_data_length`
- **WHEN** 调用 `smb2_decode_reparse_data_buffer`
- **THEN** 函数返回 `-1`，并且不接受该 symlink name 字段作为输出

Trace: `lib/smb2-data-reparse-point.c:smb2_decode_reparse_data_buffer`

#### Scenario: symlink payload decoded
- **GIVEN** 输入 buffer 包含合法的 symlink reparse data buffer，且 substitute name 和 print name 范围均位于 payload 内
- **WHEN** 调用 `smb2_decode_reparse_data_buffer`
- **THEN** 函数填充 `rp->reparse_tag`、`rp->reparse_data_length`、`rp->symlink.flags`、`rp->symlink.subname` 和 `rp->symlink.printname`，并返回 `0`

Trace: `lib/smb2-data-reparse-point.c:smb2_decode_reparse_data_buffer`, `include/smb2/smb2.h:SMB2_REPARSE_TAG_SYMLINK`

#### Scenario: symlink allocation failure rejected
- **GIVEN** 输入 symlink payload 边界合法，但为 substitute name 或 print name 分配输出字符串失败
- **WHEN** 调用 `smb2_decode_reparse_data_buffer`
- **THEN** 函数释放临时 UTF-8 字符串并返回 `-1`

Trace: `lib/smb2-data-reparse-point.c:smb2_decode_reparse_data_buffer`, `lib/alloc.c:smb2_alloc_data`

#### Scenario: unknown reparse tag accepted with generic fields
- **GIVEN** 输入 buffer 的通用 reparse header 长度合法，且 tag 不是 `SMB2_REPARSE_TAG_SYMLINK`
- **WHEN** 调用 `smb2_decode_reparse_data_buffer`
- **THEN** 函数保留已解析的 `rp->reparse_tag` 和 `rp->reparse_data_length`，不填充 symlink-specific 字段，并返回 `0`

Trace: `lib/smb2-data-reparse-point.c:smb2_decode_reparse_data_buffer`, `lib/libsmb2.c:readlink_cb_3`

## Open Questions

| ID | Question | Related Interface | Reason |
| --- | --- | --- | --- |
| Q-001 | `memctx` 参数未被实现读取；其预期所有权或历史兼容用途是否需要保留为 ABI 契约？ | smb2_decode_reparse_data_buffer | 声明和实现均包含该参数，但实现只使用 `rp` 作为 `smb2_alloc_data` 父对象。 |
| Q-002 | `smb2_utf16_to_utf8` 返回 NULL 时当前实现会继续 `strlen(tmp)`；调用方是否保证转换成功？ | smb2_decode_reparse_data_buffer | 源码未检查转换失败路径，未发现测试证据。 |
| Q-003 | `vec->len` 被转换为 `uint16_t` 后比较 reparse payload length，超过 65535 字节输入的预期行为是否受 SMB2 payload 上限约束？ | smb2_decode_reparse_data_buffer | 源码存在显式 `(uint16_t)vec->len` 比较，外层 ioctl output_count 约束未在本文件内确认。 |
