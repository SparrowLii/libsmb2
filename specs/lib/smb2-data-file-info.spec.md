# lib/smb2-data-file-info.c Specification

## Source Context

- Source: `lib/smb2-data-file-info.c`
- Related Headers: `include/libsmb2-private.h`, `include/smb2/smb2.h`
- Related Tests: `none`
- Related Dependencies: GitNexus context shows callers in `lib/smb2-cmd-query-info.c` for query-info reply/request payload handling and `lib/smb2-cmd-set-info.c` for set-info request encoding; dependencies include `lib/pdu.c` integer accessors, `lib/timestamps.c` timestamp conversion, `lib/unicode.c` UTF-8/UTF-16 conversion, and `lib/alloc.c` memctx allocation.
- Build/Compile Context: C source in core `smb2` library; guarded includes use `HAVE_CONFIG_H`, `_GNU_SOURCE`, `HAVE_STDINT_H`, `HAVE_STDLIB_H`, `HAVE_STRING_H`, `STDC_HEADERS`, `HAVE_TIME_H`, and `HAVE_SYS_TIME_H`.

## Interface Summary

| Interface | Kind | Signature | Decision | Reason |
| --- | --- | --- | --- | --- |
| smb2_decode_file_basic_info | function | int smb2_decode_file_basic_info(struct smb2_context *smb2, void *memctx, struct smb2_file_basic_info *fs, struct smb2_iovec *vec); | Include | 解码 FILE_BASIC_INFORMATION 的跨文件私有接口，被 query-info variable parser 和 all-info decoder 调用。 |
| smb2_encode_file_basic_info | function | int smb2_encode_file_basic_info(struct smb2_context *smb2, struct smb2_file_basic_info *fs, struct smb2_iovec *vec); | Include | 编码 FILE_BASIC_INFORMATION 的跨文件私有接口，被 query-info reply、set-info request 和 all-info encoder 调用。 |
| smb2_tv_timeval_to_win | function | static uint64_t smb2_tv_timeval_to_win(struct smb2_timeval *tv); | Skip | 纯内部 helper，仅为本文件 encode 接口处理特殊 timeval 哨兵值，无独立跨文件契约。 |
| smb2_decode_file_standard_info | function | int smb2_decode_file_standard_info(struct smb2_context *smb2, void *memctx, struct smb2_file_standard_info *fs, struct smb2_iovec *vec); | Include | 解码 FILE_STANDARD_INFORMATION 的跨文件私有接口，被 query-info variable parser 和 all-info decoder 调用。 |
| smb2_encode_file_standard_info | function | int smb2_encode_file_standard_info(struct smb2_context *smb2, struct smb2_file_standard_info *fs, struct smb2_iovec *vec); | Include | 编码 FILE_STANDARD_INFORMATION 的跨文件私有接口，被 query-info reply 和 all-info encoder 调用。 |
| smb2_decode_file_stream_info | function | int smb2_decode_file_stream_info(struct smb2_context *smb2, void *memctx, struct smb2_file_stream_info *fs, struct smb2_iovec *vec); | Include | 解码 FILE_STREAM_INFORMATION 链表并分配 stream name，存在资源和截断语义。 |
| smb2_encode_file_stream_info | function | int smb2_encode_file_stream_info(struct smb2_context *smb2, struct smb2_file_stream_info *fs, struct smb2_iovec *vec); | Include | 编码 FILE_STREAM_INFORMATION 链表并执行 UTF-16 转换和 64-bit padding，存在长度和失败语义。 |
| smb2_decode_file_position_info | function | int smb2_decode_file_position_info(struct smb2_context *smb2, void *memctx, struct smb2_file_position_info *fs, struct smb2_iovec *vec); | Include | 解码 FILE_POSITION_INFORMATION 的跨文件私有接口，被 query-info variable parser 调用。 |
| smb2_encode_file_position_info | function | int smb2_encode_file_position_info(struct smb2_context *smb2, struct smb2_file_position_info *fs, struct smb2_iovec *vec); | Include | 编码 FILE_POSITION_INFORMATION 的跨文件私有接口，被 query-info reply 调用。 |
| smb2_decode_file_all_info | function | int smb2_decode_file_all_info(struct smb2_context *smb2, void *memctx, struct smb2_file_all_info *fs, struct smb2_iovec *vec); | Include | 解码 FILE_ALL_INFORMATION 聚合结构，包含最小长度检查、子结构解码和可变名称分配。 |
| smb2_encode_file_all_info | function | int smb2_encode_file_all_info(struct smb2_context *smb2, struct smb2_file_all_info *fs, struct smb2_iovec *vec); | Include | 编码 FILE_ALL_INFORMATION 聚合结构，包含固定区长度检查和可变名称编码。 |
| smb2_decode_file_network_open_info | function | int smb2_decode_file_network_open_info(struct smb2_context *smb2, void *memctx, struct smb2_file_network_open_info *fs, struct smb2_iovec *vec); | Include | 解码 FILE_NETWORK_OPEN_INFORMATION，显式检查 56 字节固定长度。 |
| smb2_encode_file_network_open_info | function | int smb2_encode_file_network_open_info(struct smb2_context *smb2, struct smb2_file_network_open_info *fs, struct smb2_iovec *vec); | Include | 编码 FILE_NETWORK_OPEN_INFORMATION，显式检查 56 字节固定长度并写保留字段。 |
| smb2_decode_file_normalized_name_info | function | int smb2_decode_file_normalized_name_info(struct smb2_context *smb2, void *memctx, struct smb2_file_name_info *fs, struct smb2_iovec *vec); | Include | 解码 FILE_NAME_INFORMATION 名称载荷，包含截断、UTF-16 转 UTF-8 和 memctx 分配语义。 |
| smb2_encode_file_normalized_name_info | function | int smb2_encode_file_normalized_name_info(struct smb2_context *smb2, struct smb2_file_name_info *fs, struct smb2_iovec *vec); | Include | 编码 FILE_NAME_INFORMATION 名称载荷，包含缓冲区检查、UTF-8 转 UTF-16 和零填充语义。 |

## Data Model Summary

| Type/Macro | Kind | Definition | Notes |
| --- | --- | --- | --- |
| smb2_file_basic_info | struct | include/smb2/smb2.h:612 | FILE_BASIC_INFORMATION 数据模型，保存四个 SMB 时间戳和文件属性。 |
| smb2_file_standard_info | struct | include/smb2/smb2.h:623 | FILE_STANDARD_INFORMATION 数据模型，保存 allocation/eof/link/delete/directory 字段。 |
| smb2_file_stream_info | struct | include/smb2/smb2.h:634 | FILE_STREAM_INFORMATION 数据模型，保存 next offset、stream 名称长度、大小和名称指针。 |
| smb2_file_position_info | struct | include/smb2/smb2.h:645 | FILE_POSITION_INFORMATION 数据模型，保存 current byte offset。 |
| smb2_file_name_info | struct | include/smb2/smb2.h:652 | FILE_NAME_INFORMATION 数据模型，保存名称长度和名称指针。 |
| smb2_file_all_info | struct | include/smb2/smb2.h:660 | FILE_ALL_INFORMATION 聚合数据模型，组合 basic、standard、索引、访问、模式、对齐和名称字段。 |
| smb2_file_network_open_info | struct | include/smb2/smb2.h:710 | FILE_NETWORK_OPEN_INFORMATION 数据模型，保存四个 SMB 时间戳、allocation/eof 和属性。 |
| PAD_TO_64BIT | macro | include/libsmb2-private.h:symbol | stream info 编码使用的 64-bit 对齐宏；具体定义归属到 private header spec。 |

## ADDED Requirements

### Requirement: smb2_decode_file_basic_info fixed layout decode
系统 MUST 从 FILE_BASIC_INFORMATION 固定布局解码四个 64-bit SMB 时间戳和 32-bit 文件属性，并把时间戳转换到 `struct smb2_timeval` 输出字段。

#### Scenario: 解码 basic info 固定字段
- **GIVEN** `vec` 指向至少包含 basic info 固定字段的 SMB2 字节序载荷，`fs` 指向可写 `struct smb2_file_basic_info`
- **WHEN** 调用 `smb2_decode_file_basic_info(smb2, memctx, fs, vec)`
- **THEN** implementation MUST 读取偏移 0、8、16、24 的 64-bit 时间戳并写入 creation/access/write/change time，读取偏移 32 的 attributes，并返回 `0`

Trace: `lib/smb2-data-file-info.c:smb2_decode_file_basic_info`

### Requirement: smb2_encode_file_basic_info fixed layout encode
系统 MUST 将 FILE_BASIC_INFORMATION 编码为 40 字节固定载荷，并将保留字段写为零。

#### Scenario: 编码 basic info 固定字段
- **GIVEN** `fs` 包含 basic info 时间戳和属性，`vec` 指向可写输出缓冲区
- **WHEN** 调用 `smb2_encode_file_basic_info(smb2, fs, vec)`
- **THEN** implementation MUST 写入偏移 0、8、16、24 的 64-bit SMB 时间戳、偏移 32 的 attributes、偏移 36 的零值保留字段，并返回 `40`

Trace: `lib/smb2-data-file-info.c:smb2_encode_file_basic_info`

#### Scenario: 编码 timeval 哨兵值
- **GIVEN** 任一输入 `struct smb2_timeval` 为 `{0, 0}` 或 `{0xffffffff, 0xffffffff}`
- **WHEN** 调用 `smb2_encode_file_basic_info(smb2, fs, vec)`
- **THEN** implementation MUST 分别编码为 `0` 或 `0xffffffffffffffffULL`，其他 timeval MUST 通过 `smb2_timeval_to_win` 转换

Trace: `lib/smb2-data-file-info.c:smb2_encode_file_basic_info`

### Requirement: smb2_decode_file_standard_info fixed layout decode
系统 MUST 从 FILE_STANDARD_INFORMATION 固定布局解码 allocation size、EOF、link count、delete pending 和 directory 字段。

#### Scenario: 解码 standard info 固定字段
- **GIVEN** `vec` 指向 standard info 固定字段载荷，`fs` 指向可写 `struct smb2_file_standard_info`
- **WHEN** 调用 `smb2_decode_file_standard_info(smb2, memctx, fs, vec)`
- **THEN** implementation MUST 读取偏移 0、8 的 64-bit 字段、偏移 16 的 32-bit link count、偏移 20 和 21 的 8-bit flags，并返回 `0`

Trace: `lib/smb2-data-file-info.c:smb2_decode_file_standard_info`

### Requirement: smb2_encode_file_standard_info fixed layout encode
系统 MUST 将 FILE_STANDARD_INFORMATION 编码为 24 字节固定载荷，并将尾部保留字段写为零。

#### Scenario: 编码 standard info 固定字段
- **GIVEN** `fs` 包含 standard info 字段，`vec` 指向可写输出缓冲区
- **WHEN** 调用 `smb2_encode_file_standard_info(smb2, fs, vec)`
- **THEN** implementation MUST 写入 allocation size、EOF、link count、delete pending、directory 和偏移 22 的 16-bit 零值保留字段，并返回 `24`

Trace: `lib/smb2-data-file-info.c:smb2_encode_file_standard_info`

### Requirement: smb2_decode_file_stream_info chained stream decode
系统 MUST 解码一个或多个 FILE_STREAM_INFORMATION 条目，并将 UTF-16 stream name 转换为 memctx 关联的 UTF-8 字符串。

#### Scenario: 解码 stream info 链表
- **GIVEN** `vec` 包含一个或多个 stream info 条目，`fs` 指向足够容纳结果条目的数组
- **WHEN** 调用 `smb2_decode_file_stream_info(smb2, memctx, fs, vec)`
- **THEN** implementation MUST 读取每个条目的 next offset、name length、stream size 和 allocation size，成功转换名称时 MUST 设置 UTF-8 `stream_name` 和按 UTF-8 字节数更新 `stream_name_length`

Trace: `lib/smb2-data-file-info.c:smb2_decode_file_stream_info`

#### Scenario: 解码 stream info 截断或失败
- **GIVEN** stream name length 超出剩余 `vec->len`，或 UTF-16 转换/内存分配失败
- **WHEN** 调用 `smb2_decode_file_stream_info(smb2, memctx, fs, vec)`
- **THEN** implementation MUST 将名称读取长度截断到剩余载荷；转换或分配失败时 MUST 返回 `-1`

Trace: `lib/smb2-data-file-info.c:smb2_decode_file_stream_info`

### Requirement: smb2_encode_file_stream_info chained stream encode
系统 MUST 将一个或多个 FILE_STREAM_INFORMATION 条目编码为 SMB2 stream info 载荷，并对非末尾条目执行 64-bit padding。

#### Scenario: 编码 stream info 链表
- **GIVEN** `fs` 指向 stream info 链表，`vec` 指向可写输出缓冲区
- **WHEN** 调用 `smb2_encode_file_stream_info(smb2, fs, vec)`
- **THEN** implementation MUST 将 UTF-8 stream name 转换为 UTF-16，写入名称长度、大小字段和 next offset，非末尾条目 MUST 用零字节填充到 64-bit 对齐并返回写入总字节数

Trace: `lib/smb2-data-file-info.c:smb2_encode_file_stream_info`

#### Scenario: 编码 stream name 转换失败
- **GIVEN** `fs->stream_name` 非空且 UTF-8 到 UTF-16 转换失败
- **WHEN** 调用 `smb2_encode_file_stream_info(smb2, fs, vec)`
- **THEN** implementation MUST 返回 `-1`

Trace: `lib/smb2-data-file-info.c:smb2_encode_file_stream_info`

### Requirement: smb2_decode_file_position_info fixed layout decode
系统 MUST 从 FILE_POSITION_INFORMATION 固定布局解码 current byte offset。

#### Scenario: 解码 position info
- **GIVEN** `vec` 指向包含 64-bit current byte offset 的载荷，`fs` 指向可写 position info
- **WHEN** 调用 `smb2_decode_file_position_info(smb2, memctx, fs, vec)`
- **THEN** implementation MUST 从偏移 0 读取 current byte offset 并返回 `0`

Trace: `lib/smb2-data-file-info.c:smb2_decode_file_position_info`

### Requirement: smb2_encode_file_position_info fixed layout encode
系统 MUST 将 FILE_POSITION_INFORMATION 编码为 8 字节固定载荷。

#### Scenario: 编码 position info
- **GIVEN** `fs` 包含 current byte offset，`vec` 指向可写输出缓冲区
- **WHEN** 调用 `smb2_encode_file_position_info(smb2, fs, vec)`
- **THEN** implementation MUST 在偏移 0 写入 current byte offset 并返回 `8`

Trace: `lib/smb2-data-file-info.c:smb2_encode_file_position_info`

### Requirement: smb2_decode_file_all_info aggregate decode
系统 MUST 解码 FILE_ALL_INFORMATION 聚合结构，并在固定区长度不足、名称转换失败或名称分配失败时返回错误。

#### Scenario: 解码 all info 聚合字段
- **GIVEN** `vec->len` 至少包含 100 字节 fixed/name-length 区域，`fs` 指向可写 all info
- **WHEN** 调用 `smb2_decode_file_all_info(smb2, memctx, fs, vec)`
- **THEN** implementation MUST 先解码 basic 和 standard 子结构，再读取 index、EA size、access flags、position、mode、alignment、name length 和可选 UTF-8 name，并在成功时返回 `0`

Trace: `lib/smb2-data-file-info.c:smb2_decode_file_all_info`

#### Scenario: 解码 all info 长度和名称失败
- **GIVEN** `vec->len` 小于 40 或 64，或名称转换/分配失败
- **WHEN** 调用 `smb2_decode_file_all_info(smb2, memctx, fs, vec)`
- **THEN** implementation MUST 返回 `-1`; 当名称长度超过剩余载荷时 MUST 将名称读取长度截断到 `vec->len - 100`

Trace: `lib/smb2-data-file-info.c:smb2_decode_file_all_info`

### Requirement: smb2_encode_file_all_info aggregate encode
系统 MUST 编码 FILE_ALL_INFORMATION 聚合结构，并根据是否存在名称返回固定区或固定区加名称长度。

#### Scenario: 编码 all info 聚合字段
- **GIVEN** `vec->len` 至少为 64，`fs` 包含 all info 字段
- **WHEN** 调用 `smb2_encode_file_all_info(smb2, fs, vec)`
- **THEN** implementation MUST 编码 basic 和 standard 子结构，写入 index、EA size、access flags、position、mode、alignment；名称存在时 MUST 写入 UTF-16 名称长度和字节并返回 `100 + name_len`，名称为空时 MUST 写入名称长度 `0` 并返回 `100`

Trace: `lib/smb2-data-file-info.c:smb2_encode_file_all_info`

#### Scenario: 编码 all info 长度或转换失败
- **GIVEN** `vec->len` 小于 40 或 64，或名称 UTF-8 到 UTF-16 转换失败
- **WHEN** 调用 `smb2_encode_file_all_info(smb2, fs, vec)`
- **THEN** implementation MUST 返回 `-1`

Trace: `lib/smb2-data-file-info.c:smb2_encode_file_all_info`

### Requirement: smb2_decode_file_network_open_info fixed layout decode
系统 MUST 从 56 字节 FILE_NETWORK_OPEN_INFORMATION 固定布局解码时间戳、allocation size、EOF 和 attributes。

#### Scenario: 解码 network open info
- **GIVEN** `vec->len` 至少为 56，`fs` 指向可写 network open info
- **WHEN** 调用 `smb2_decode_file_network_open_info(smb2, memctx, fs, vec)`
- **THEN** implementation MUST 解码四个 64-bit SMB 时间戳、allocation size、EOF 和 attributes，并返回 `0`

Trace: `lib/smb2-data-file-info.c:smb2_decode_file_network_open_info`

#### Scenario: 拒绝过短 network open info
- **GIVEN** `vec->len` 小于 56
- **WHEN** 调用 `smb2_decode_file_network_open_info(smb2, memctx, fs, vec)`
- **THEN** implementation MUST 返回 `-1`

Trace: `lib/smb2-data-file-info.c:smb2_decode_file_network_open_info`

### Requirement: smb2_encode_file_network_open_info fixed layout encode
系统 MUST 将 FILE_NETWORK_OPEN_INFORMATION 编码为 56 字节固定载荷，并写入零值保留字段。

#### Scenario: 编码 network open info
- **GIVEN** `vec->len` 至少为 56，`fs` 包含 network open info 字段
- **WHEN** 调用 `smb2_encode_file_network_open_info(smb2, fs, vec)`
- **THEN** implementation MUST 编码四个 SMB 时间戳、allocation size、EOF、attributes 和偏移 52 的 32-bit 零值保留字段，并返回 `56`

Trace: `lib/smb2-data-file-info.c:smb2_encode_file_network_open_info`

#### Scenario: 拒绝过短 network open encode buffer
- **GIVEN** `vec->len` 小于 56
- **WHEN** 调用 `smb2_encode_file_network_open_info(smb2, fs, vec)`
- **THEN** implementation MUST 返回 `-1`

Trace: `lib/smb2-data-file-info.c:smb2_encode_file_network_open_info`

### Requirement: smb2_decode_file_normalized_name_info name decode
系统 MUST 解码 FILE_NAME_INFORMATION 名称长度和可选 UTF-8 名称，并将名称分配到 memctx。

#### Scenario: 解码 normalized name
- **GIVEN** `vec->len` 至少为 4，且 name length 指示存在名称载荷
- **WHEN** 调用 `smb2_decode_file_normalized_name_info(smb2, memctx, fs, vec)`
- **THEN** implementation MUST 读取 name length，将 UTF-16 名称转换为 UTF-8，使用 `smb2_alloc_data` 分配输出名称，并在成功时返回 `0`

Trace: `lib/smb2-data-file-info.c:smb2_decode_file_normalized_name_info`

#### Scenario: 解码 normalized name 边界和失败
- **GIVEN** `vec->len` 小于 4，或 UTF-16 转换/名称分配失败
- **WHEN** 调用 `smb2_decode_file_normalized_name_info(smb2, memctx, fs, vec)`
- **THEN** implementation MUST 返回 `-1`; 当声明名称长度超过剩余载荷时 MUST 截断读取长度，名称长度为 0 或截断后无名称时 MUST 设置 `fs->name` 为 `NULL`

Trace: `lib/smb2-data-file-info.c:smb2_decode_file_normalized_name_info`

### Requirement: smb2_encode_file_normalized_name_info name encode
系统 MUST 编码 FILE_NAME_INFORMATION 名称长度和可选 UTF-16 名称，并在名称短于声明长度时用零填充。

#### Scenario: 编码 normalized name
- **GIVEN** `fs->name` 非空，`vec` 可容纳 4 字节长度字段和 UTF-16 名称
- **WHEN** 调用 `smb2_encode_file_normalized_name_info(smb2, fs, vec)`
- **THEN** implementation MUST 将 UTF-8 名称转换为 UTF-16，必要时更新 `fs->file_name_length`，写入名称字节，对声明长度剩余部分写零，并返回 `4 + fs->file_name_length`

Trace: `lib/smb2-data-file-info.c:smb2_encode_file_normalized_name_info`

#### Scenario: 编码 normalized name 空名称或失败
- **GIVEN** `fs->name` 为空、输出缓冲区不足或 UTF-8 到 UTF-16 转换失败
- **WHEN** 调用 `smb2_encode_file_normalized_name_info(smb2, fs, vec)`
- **THEN** implementation MUST 对空名称设置 `fs->file_name_length` 为 `0` 并返回 `4`; 对缓冲区不足或转换失败 MUST 返回 `-1`

Trace: `lib/smb2-data-file-info.c:smb2_encode_file_normalized_name_info`

## Open Questions

| ID | Question | Related Interface | Reason |
| --- | --- | --- | --- |
| Q-001 | 固定布局 decode 接口是否依赖 `smb2_get_uint*` 自行处理越界读取，还是调用方保证 `vec->len` 足够？ | smb2_decode_file_basic_info, smb2_decode_file_standard_info, smb2_decode_file_position_info | 本文件多数简单 decoder 未显式检查长度，需结合 `lib/pdu.c` accessor 契约确认。 |
| Q-002 | `smb2_encode_file_stream_info` 在写入 UTF-16 名称和 padding 前是否要求调用方保证 `vec->len` 足够？ | smb2_encode_file_stream_info | 源码仅在循环条件末尾检查 `offset + 24 <= vec->len`，未在 `memcpy` 前检查完整名称长度。 |
| Q-003 | `smb2_decode_file_stream_info` 的调用方是否总是预分配足够数量的 `struct smb2_file_stream_info` 条目？ | smb2_decode_file_stream_info | 源码通过 `fs++` 写后续条目，未在本函数内接收或检查输出数组容量。 |
