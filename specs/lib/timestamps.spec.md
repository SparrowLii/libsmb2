# lib/timestamps.c Specification

## Source Context

- Source: `lib/timestamps.c`
- Related Headers: `include/smb2/libsmb2.h`, `include/smb2/smb2.h`, `include/libsmb2-private.h`, `include/portable-endian.h`, `lib/compat.h`
- Related Tests: `tests/ntlmssp_generate_blob.c`
- Related Dependencies: GitNexus context shows `smb2_timeval_to_win` is called by `lib/libsmb2.c`, `lib/ntlmssp.c`, `lib/smb2-cmd-query-directory.c`, `lib/smb2-data-file-info.c`, and `lib/smb2-data-filesystem-info.c`; `smb2_win_to_timeval` is called by `lib/smb2-cmd-query-directory.c`, `lib/smb2-data-file-info.c`, and `lib/smb2-data-filesystem-info.c`. GitNexus impact reports CRITICAL upstream impact for both conversion functions because they affect SMB2 query-info, directory decode/encode, NTLMSSP blob generation, examples, and test flows.
- Build/Compile Context: C source in core `smb2` library; guarded includes use `HAVE_CONFIG_H`, `_GNU_SOURCE`, `HAVE_STDINT_H`, `HAVE_STDLIB_H`, `HAVE_STRING_H`, `HAVE_TIME_H`, `HAVE_SYS_TIME_H`, and `STDC_HEADERS`.

## Interface Summary

| Interface | Kind | Signature | Decision | Reason |
| --- | --- | --- | --- | --- |
| smb2_timeval_to_win | function | `uint64_t smb2_timeval_to_win(struct smb2_timeval *tv);` | Include | 公共声明的 Unix timeval 到 Windows FILETIME 时间戳转换接口，被 SMB2 metadata 编码和 NTLMSSP 时间戳生成路径调用。 |
| smb2_win_to_timeval | function | `void smb2_win_to_timeval(uint64_t smb2_time, struct smb2_timeval *tv);` | Include | 公共声明的 Windows FILETIME 到 Unix timeval 转换接口，被 SMB2 metadata 和 directory decode 路径调用。 |

## Data Model Summary

| Type/Macro | Kind | Definition | Notes |
| --- | --- | --- | --- |
| smb2_timeval | struct | `include/smb2/smb2.h:symbol` | 时间转换输入/输出数据模型，包含秒和微秒字段；具体字段定义归属到公共 SMB2 header spec。 |
| WIN epoch offset | constant | `lib/timestamps.c:62` | Windows FILETIME epoch 与 Unix epoch 的 100ns tick 偏移量 `116444736000000000`。 |

## ADDED Requirements

### Requirement: smb2_timeval_to_win convert Unix timeval to Windows FILETIME
系统 MUST 将 `struct smb2_timeval` 表示的 Unix 秒和微秒时间转换为 Windows FILETIME 100ns tick 时间戳，并 MUST 加上 Windows 与 Unix epoch 之间的固定偏移量。

#### Scenario: 正常 timeval 转换为 FILETIME
- **GIVEN** 调用方提供非空 `struct smb2_timeval *tv`，其中 `tv_sec` 表示 Unix epoch 秒数且 `tv_usec` 表示微秒部分
- **WHEN** 调用 `smb2_timeval_to_win(tv)`
- **THEN** implementation MUST 返回 `((uint64_t)tv->tv_sec * 10000000) + 116444736000000000 + tv->tv_usec * 10`

Trace: `lib/timestamps.c:smb2_timeval_to_win`, `include/smb2/libsmb2.h:smb2_timeval_to_win`, `tests/ntlmssp_generate_blob.c:main`

### Requirement: smb2_win_to_timeval convert Windows FILETIME to Unix timeval
系统 MUST 将 Windows FILETIME 100ns tick 时间戳拆分为 `struct smb2_timeval` 的 Unix 秒和微秒字段，并 MUST 使用固定 epoch 偏移量计算秒字段。

#### Scenario: 正常 FILETIME 转换为 timeval
- **GIVEN** 调用方提供 Windows FILETIME 值 `smb2_time` 和非空可写 `struct smb2_timeval *tv`
- **WHEN** 调用 `smb2_win_to_timeval(smb2_time, tv)`
- **THEN** implementation MUST 将 `tv->tv_usec` 设置为 `(smb2_time / 10) % 1000000`，并将 `tv->tv_sec` 设置为 `(smb2_time - 116444736000000000) / 10000000`

Trace: `lib/timestamps.c:smb2_win_to_timeval`, `include/smb2/libsmb2.h:smb2_win_to_timeval`

## Open Questions

| ID | Question | Related Interface | Reason |
| --- | --- | --- | --- |
| Q-001 | `smb2_timeval_to_win` 对 `tv == NULL`、`tv_usec >= 1000000` 或乘法溢出的行为是否属于调用方前置条件？ | smb2_timeval_to_win | 源码未检查输入范围或空指针，公共声明注释未说明参数约束。 |
| Q-002 | `smb2_win_to_timeval` 对小于 Windows/Unix epoch 偏移量的 `smb2_time` 是否应稳定保留无符号下溢后的结果？ | smb2_win_to_timeval | 源码直接用无符号减法后赋值给 `tv_sec`，未发现测试锁定 epoch 前时间语义。 |
