# lib/smb2-data-security-descriptor.c Specification

## Source Context

- Source: `lib/smb2-data-security-descriptor.c`
- Related Headers: `include/libsmb2-private.h`, `include/smb2/smb2.h`, `include/slist.h`, `include/libsmb2-private.spec.md`, `include/smb2/smb2.spec.md`, `include/slist.spec.md`
- Related Tests: `none`
- Related Dependencies: `lib/smb2-cmd-query-info.c:smb2_process_query_info_variable`, `lib/pdu.c:smb2_get_uint8`, `lib/pdu.c:smb2_get_uint16`, `lib/pdu.c:smb2_get_uint32`, `lib/init.c:smb2_set_error`, `lib/init.c:smb2_get_error`, `lib/alloc.c:smb2_alloc_data`, `lib/alloc.c:smb2_alloc_init`
- Build/Compile Context: `CMakeLists.txt` builds the C library through `lib/CMakeLists.txt`; source uses optional `HAVE_CONFIG_H`, `_GNU_SOURCE`, `HAVE_STDINT_H`, `HAVE_STDLIB_H`, `HAVE_STRING_H`, `STDC_HEADERS`, `HAVE_TIME_H`, and `HAVE_SYS_TIME_H` include guards.

## Interface Summary

| Interface | Kind | Signature | Decision | Reason |
| --- | --- | --- | --- | --- |
| decode_sid | function | `static struct smb2_sid * decode_sid(struct smb2_context *smb2, void *memctx, struct smb2_iovec *v)` | Skip | 文件内 SID 解码 helper；行为由公开的 security descriptor 解码入口统一承载。 |
| decode_ace | function | `static struct smb2_ace * decode_ace(struct smb2_context *smb2, void *memctx, struct smb2_iovec *vec)` | Skip | 文件内 ACE 解码 helper；错误、分配和类型分派语义由公开入口间接暴露。 |
| decode_acl | function | `static struct smb2_acl * decode_acl(struct smb2_context *smb2, void *memctx, struct smb2_iovec *vec)` | Skip | 文件内 ACL 解码 helper；链表追加和 ACE 遍历语义归属到公开入口。 |
| smb2_decode_security_descriptor | function | `int smb2_decode_security_descriptor(struct smb2_context *smb2, void *memctx, struct smb2_security_descriptor *sd, struct smb2_iovec *vec)` | Include | 私有跨文件接口，由 Query Info security reply 解码路径调用并向调用方暴露解析结果和错误返回。 |

## Data Model Summary

| Type/Macro | Kind | Definition | Notes |
| --- | --- | --- | --- |
| SID_ID_AUTH_LEN | macro | `include/smb2/smb2.h:737` | SID identifier authority 固定为 6 字节，SID 边界检查和复制依赖该长度。 |
| struct smb2_sid | struct | `include/smb2/smb2.h:744` | 承载 SID revision、sub-authority count、identifier authority 和变长 sub_auth 数组。 |
| SMB2_ACCESS_ALLOWED_ACE_TYPE | macro | `include/smb2/smb2.h:759` | 与同类 ACE type 宏共同决定 ACE body 按 mask+SID、object ACE、callback data 或 raw blob 解码。 |
| SMB2_OBJECT_TYPE_SIZE | macro | `include/smb2/smb2.h:788` | Object ACE 中 object_type 与 inherited_object_type 字段固定长度。 |
| struct smb2_ace | struct | `include/smb2/smb2.h:790` | 承载 ACE header、mask、flags、SID、object GUID、application data 或未知 raw blob。 |
| SMB2_ACL_REVISION | macro | `include/smb2/smb2.h:820` | ACL decoder 接受的普通 ACL revision。 |
| SMB2_ACL_REVISION_DS | macro | `include/smb2/smb2.h:821` | ACL decoder 接受的 directory service ACL revision。 |
| struct smb2_acl | struct | `include/smb2/smb2.h:823` | 承载 ACL revision、ACE count 和 ACE 链表。 |
| struct smb2_security_descriptor | struct | `include/smb2/smb2.h:850` | 输出 security descriptor revision、control、owner、group 和 DACL 指针；当前实现未填充 SACL。 |

## ADDED Requirements

### Requirement: smb2_decode_security_descriptor decodes security descriptor header and referenced owner, group, and DACL
系统 MUST 从至少 20 字节的 self-relative security descriptor 缓冲区读取 revision、control 和 owner/group/SACL/DACL 偏移，并在 revision 为 1 时按有效偏移填充 `sd->owner`、`sd->group` 和 `sd->dacl`。

#### Scenario: 成功解码 revision 和有效偏移
- **GIVEN** 调用方提供 `vec->len >= 20`、revision 字节为 `1`，并且 owner、group 或 DACL 偏移非零且满足当前实现的最小长度检查
- **WHEN** 调用 `smb2_decode_security_descriptor(smb2, memctx, sd, vec)`
- **THEN** 函数返回 `0`，写入 `sd->revision` 和 `sd->control`，并对有效 owner/group SID 与 DACL 分别分配和填充对应输出结构

Trace: `lib/smb2-data-security-descriptor.c:smb2_decode_security_descriptor`, `lib/smb2-cmd-query-info.c:smb2_process_query_info_variable`

#### Scenario: 缓冲区短于 security descriptor header
- **GIVEN** 调用方提供 `vec->len < 20` 的 security descriptor 输入
- **WHEN** 调用 `smb2_decode_security_descriptor(smb2, memctx, sd, vec)`
- **THEN** 函数返回 `-1`，且不会读取 header 字段之外的数据

Trace: `lib/smb2-data-security-descriptor.c:smb2_decode_security_descriptor`

#### Scenario: 拒绝不支持的 security descriptor revision
- **GIVEN** 调用方提供至少 20 字节输入，且 security descriptor revision 不是 `1`
- **WHEN** 调用 `smb2_decode_security_descriptor(smb2, memctx, sd, vec)`
- **THEN** 函数 MUST 返回 `-1`，并通过 `smb2_set_error` 记录包含 revision 值的解码错误

Trace: `lib/smb2-data-security-descriptor.c:smb2_decode_security_descriptor`

#### Scenario: 解码 SID 时校验 revision 和 sub-authority 边界
- **GIVEN** owner 或 group 偏移指向 SID 数据，且该 SID 长度、revision 或 sub-authority 数量不满足源码检查
- **WHEN** `smb2_decode_security_descriptor` 尝试解码该 SID
- **THEN** 函数 MUST 返回 `-1`，并通过错误字符串标识 owner 或 group SID 解码失败原因

Trace: `lib/smb2-data-security-descriptor.c:smb2_decode_security_descriptor`, `lib/smb2-data-security-descriptor.c:decode_sid`

#### Scenario: 解码 DACL 时校验 ACL revision 和 ACE 边界
- **GIVEN** DACL 偏移非零且 ACL header 可读，但 ACL revision、ACL size、ACE header、ACE size 或 ACE body 不满足源码检查
- **WHEN** `smb2_decode_security_descriptor` 尝试解码 DACL
- **THEN** 函数 MUST 返回 `-1`，并通过错误字符串标识 DACL、ACL 或 ACE 解码失败原因

Trace: `lib/smb2-data-security-descriptor.c:smb2_decode_security_descriptor`, `lib/smb2-data-security-descriptor.c:decode_acl`, `lib/smb2-data-security-descriptor.c:decode_ace`

## Open Questions

| ID | Question | Related Interface | Reason |
| --- | --- | --- | --- |
| Q-001 | SACL 偏移被读取但当前实现未解码 `sd` 中的 SACL；是否属于有意不支持的字段需要确认。 | smb2_decode_security_descriptor | `offset_sacl` 只在 header 中读取，源码没有对应输出字段或解析分支。 |
| Q-002 | owner/group SID 最小长度检查使用 `offset + 2 + SID_ID_AUTH_LEN < vec->len`，边界等于缓冲区末尾时会跳过而非报错；该容忍行为是否为稳定契约需要确认。 | smb2_decode_security_descriptor | 源码只在条件满足时解码，不满足时静默保留对应输出字段。 |
| Q-003 | group SID 解码时使用 `sd` 作为 allocation memctx，而 owner 使用传入 `memctx`；该内存归属差异是否为有意行为需要确认。 | smb2_decode_security_descriptor | 源码第 339 行传入 `sd`，第 326 行传入 `memctx`。 |
