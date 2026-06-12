# lib/asn1-ber.c Specification

## Source Context

- Source: `lib/asn1-ber.c`
- Related Headers: `lib/asn1-ber.h`, `lib/compat.h`
- Related Tests: `tests/ntlmssp_generate_blob.c`
- Related Dependencies: `asn1ber_length_from_ber` is called by `ber_typelen_from_ber`, `asn1ber_oid_from_ber`, and `asn1ber_bytes_from_ber`; `asn1ber_ber_from_typelen` is called by integer and byte encoders; `asn1ber_ber_from_oid` is called by SPNEGO wrapper functions in `lib/spnego-wrapper.c` and has CRITICAL upstream impact through session setup and NTLMSSP blob generation.
- Build/Compile Context: C implementation built by `lib/CMakeLists.txt`; `HAVE_CONFIG_H`, standard header probes, `_GNU_SOURCE`, and platform compatibility includes affect available declarations, while BER behavior is implemented in this file and declared by `lib/asn1-ber.h`.

## Interface Summary

| Interface | Kind | Signature | Decision | Reason |
| --- | --- | --- | --- | --- |
| asn1ber_next_byte | function | int asn1ber_next_byte(struct asn1ber_context *actx, uint8_t *outb) | Skip | 未在 `lib/asn1-ber.h` 声明，作为本实现文件内部解码游标 helper 使用。 |
| asn1ber_out_byte | function | int asn1ber_out_byte(struct asn1ber_context *actx, uint8_t inb) | Skip | 未在 `lib/asn1-ber.h` 声明，作为本实现文件内部编码游标 helper 使用。 |
| asn1ber_save_out_state | function | int asn1ber_save_out_state(struct asn1ber_context *actx, int *out_pos) | Include | 头文件声明的编码状态快照接口，被 SPNEGO 编码路径用于后续长度回填。 |
| asn1ber_annotate_length | function | int asn1ber_annotate_length(struct asn1ber_context *actx, int out_pos, int reserved) | Include | 头文件声明的长度回填接口，影响预留长度字段后的编码缓冲区布局。 |
| asn1ber_length_from_ber | function | int asn1ber_length_from_ber(struct asn1ber_context *actx, uint32_t *len) | Include | 头文件声明的 BER 长度解码接口，被类型长度、OID 和字节串解码复用。 |
| ber_typecode_from_ber | function | int ber_typecode_from_ber(struct asn1ber_context *actx, ber_type_t *typecode) | Include | 头文件声明的 BER 类型码解码接口，支持普通和扩展类型码形式。 |
| ber_typelen_from_ber | function | int ber_typelen_from_ber(struct asn1ber_context *actx, ber_type_t *typecode, uint32_t *len) | Include | 头文件声明的类型和长度组合解码接口，供请求、结构和空值解码复用。 |
| asn1ber_request_from_ber | function | int asn1ber_request_from_ber(struct asn1ber_context *actx, ber_type_t *opcode, uint32_t *len) | Include | 头文件声明的请求头解码包装，调用方可观察到 opcode 与长度输出。 |
| asn1ber_struct_from_ber | function | int asn1ber_struct_from_ber(struct asn1ber_context *actx, uint32_t *len) | Include | 头文件声明的结构类型验证接口，错误语义设置 `last_error`。 |
| asn1ber_null_from_ber | function | int asn1ber_null_from_ber(struct asn1ber_context *actx, uint32_t *len) | Include | 头文件声明的 NULL 类型验证接口，错误语义设置 `last_error`。 |
| asn1ber_int32_from_ber | function | int asn1ber_int32_from_ber(struct asn1ber_context *actx, int32_t *val) | Include | 头文件声明的有符号 32 位 BER 整数解码接口，包含类型、长度和符号扩展语义。 |
| asn1ber_uint32_from_ber | function | int asn1ber_uint32_from_ber(struct asn1ber_context *actx, uint32_t *val) | Include | 头文件声明的无符号 32 位 BER 值解码接口，接受多个应用类型标签。 |
| asn1ber_int64_from_ber | function | int asn1ber_int64_from_ber(struct asn1ber_context *actx, int64_t *val) | Include | 头文件声明的有符号 64 位 BER 整数解码接口，包含长度限制和符号扩展语义。 |
| asn1ber_uint64_from_ber | function | int asn1ber_uint64_from_ber(struct asn1ber_context *actx, uint64_t *val) | Include | 头文件声明的无符号 64 位 BER 值解码接口，接受 `BER_UNSIGNED64` 和 `BER_COUNTER64`。 |
| asn1ber_oid_from_ber | function | int asn1ber_oid_from_ber(struct asn1ber_context *actx, struct asn1ber_oid_value *oid) | Include | 头文件声明的 OID 解码接口，影响 SPNEGO 机制 OID 解析。 |
| asn1ber_bytes_from_ber | function | int asn1ber_bytes_from_ber(struct asn1ber_context *actx, uint8_t *val, uint32_t maxlen, uint32_t *lenout) | Include | 头文件声明的 OCTET STRING 解码接口，处理长度、容量和便利 NUL 终止。 |
| asn1ber_string_from_ber | function | int asn1ber_string_from_ber(struct asn1ber_context *actx, char *val, uint32_t maxlen, uint32_t *lenout) | Include | 头文件声明的字符串解码包装，调用字节串解码并暴露相同行为。 |
| asn1ber_ber_from_length | function | int asn1ber_ber_from_length(struct asn1ber_context *actx, uint32_t lenin, uint32_t *lenout) | Include | 头文件声明的 BER 长度编码接口，被类型长度和长度回填路径复用。 |
| asn1ber_ber_reserve_length | function | int asn1ber_ber_reserve_length(struct asn1ber_context *actx, uint32_t len) | Include | 头文件声明的长度占位写入接口，供后续 `asn1ber_annotate_length` 回填。 |
| asn1ber_ber_from_typecode | function | int asn1ber_ber_from_typecode(struct asn1ber_context *actx, const ber_type_t typecode) | Include | 头文件声明的类型码编码接口，被 SPNEGO 编码路径大量调用。 |
| asn1ber_ber_from_typelen | function | int asn1ber_ber_from_typelen(struct asn1ber_context *actx, const ber_type_t typecode, const uint32_t lenin, uint32_t *lenout) | Include | 头文件声明的类型和长度组合编码接口，影响后续值编码的长度统计。 |
| asn1ber_ber_from_int32 | function | int asn1ber_ber_from_int32(struct asn1ber_context *actx, const ber_type_t type, const int32_t val) | Include | 头文件声明的 32 位有符号整数编码接口，提供最短 BER 值字节编码。 |
| asn1ber_ber_from_uint32 | function | int asn1ber_ber_from_uint32(struct asn1ber_context *actx, const ber_type_t type, const uint32_t val) | Include | 头文件声明的 32 位无符号整数编码接口，提供最短 BER 值字节编码。 |
| asn1ber_ber_from_int64 | function | int asn1ber_ber_from_int64(struct asn1ber_context *actx, const ber_type_t type, const int64_t val) | Include | 头文件声明的 64 位有符号整数编码接口，提供最短 BER 值字节编码。 |
| asn1ber_ber_from_uint64 | function | int asn1ber_ber_from_uint64(struct asn1ber_context *actx, const ber_type_t type, const uint64_t val) | Include | 头文件声明的 64 位无符号整数编码接口，提供最短 BER 值字节编码。 |
| asn1ber_ber_from_single_oid | function | static int asn1ber_ber_from_single_oid(struct asn1ber_context *actx, beroid_type_t oidb) | Skip | `static` 内部 helper，仅服务 `asn1ber_ber_from_oid` 的单个 OID 分量编码。 |
| asn1ber_ber_from_oid | function | int asn1ber_ber_from_oid(struct asn1ber_context *actx, const struct asn1ber_oid_value *oid) | Include | 头文件声明的 OID 编码接口，被 SPNEGO 认证 blob 构造路径调用且影响范围高。 |
| asn1ber_ber_from_bytes | function | int asn1ber_ber_from_bytes(struct asn1ber_context *actx, const ber_type_t type, const uint8_t *val, uint32_t len) | Include | 头文件声明的任意字节串 BER 编码接口，写入类型、长度和值。 |
| asn1ber_ber_from_string | function | int asn1ber_ber_from_string(struct asn1ber_context *actx, const char *val, uint32_t len) | Include | 头文件声明的字符串编码包装，固定使用 `BER_OCTET_STRING`。 |

## Data Model Summary

| Type/Macro | Kind | Definition | Notes |
| --- | --- | --- | --- |
| BER_MAX_OID_ELEMENTS | macro | lib/asn1-ber.h:35 | OID 元素数组容量固定为 32，OID 编解码使用该上限。 |
| beroid_type_t | typedef | lib/asn1-ber.h:36 | OID 元素类型为 `uint32_t`。 |
| ber_type_t | enum | lib/asn1-ber.h:66 | BER/ASN.1 类型标签枚举，供编码和解码接口使用。 |
| ASN1_SEQUENCE | macro | lib/asn1-ber.h:106 | 将结构类型和传入编号组合为 BER sequence 类型码。 |
| ASN1_CONTEXT | macro | lib/asn1-ber.h:107 | 将 context-specific、constructed 标志和编号组合为类型码。 |
| ASN1_CONTEXT_SIMPLE | macro | lib/asn1-ber.h:108 | 将 context-specific 标志和编号组合为简单类型码。 |
| ASN1_PRIVATE | macro | lib/asn1-ber.h:109 | 暴露 private 类型类常量。 |
| asn1ber_context | struct | lib/asn1-ber.h:111 | 保存源缓冲区读取游标、目标缓冲区写入游标和最近错误码。 |
| asn1ber_oid_value | struct | lib/asn1-ber.h:124 | 保存 OID 元素数量和最多 `BER_MAX_OID_ELEMENTS` 个元素。 |

## ADDED Requirements

### Requirement: asn1ber_save_out_state snapshots encoder position
系统 MUST 在输出位置指针、上下文和目标缓冲区有效且 `dst_head < dst_size` 时把当前 `dst_head` 写入 `*out_pos` 并返回 `0`；否则 MUST 返回 `-1` 且不写入快照。

#### Scenario: save valid output state
- **GIVEN** `actx` 指向有效上下文，`actx->dst` 非空，`actx->dst_head < actx->dst_size`，且 `out_pos` 非空
- **WHEN** 调用 `asn1ber_save_out_state(actx, out_pos)`
- **THEN** 函数把当前 `actx->dst_head` 写入 `*out_pos` 并返回 `0`

Trace: `lib/asn1-ber.c:asn1ber_save_out_state`

#### Scenario: reject invalid save state inputs
- **GIVEN** `out_pos`、`actx` 或 `actx->dst` 为空，或输出游标已经到达目标缓冲区容量
- **WHEN** 调用 `asn1ber_save_out_state(actx, out_pos)`
- **THEN** 函数返回 `-1`

Trace: `lib/asn1-ber.c:asn1ber_save_out_state`

### Requirement: asn1ber_annotate_length backfills reserved length bytes
系统 MUST 将 `out_pos` 之后除 `reserved` 字节外新增的数据长度编码到 `out_pos`，并在预留字节多于实际长度编码字节时左移后续内容；编码或上下文无效时 MUST 返回错误。

#### Scenario: backfill reserved length field
- **GIVEN** 输出上下文有效，`out_pos` 是先前保存的位置，且其后已经预留 `reserved` 字节并写入负载
- **WHEN** 调用 `asn1ber_annotate_length(actx, out_pos, reserved)`
- **THEN** 函数根据 `dst_head - out_pos - reserved` 生成 BER 长度，必要时移动负载覆盖未使用预留空间，并把 `dst_head` 恢复到新结束位置

Trace: `lib/asn1-ber.c:asn1ber_annotate_length`

### Requirement: asn1ber_length_from_ber decodes BER length
系统 MUST 从输入流解码短格式或最多 4 字节长格式 BER 长度，成功时写入 `*len` 并返回 `0`；长格式长度字节数超过 4 时 MUST 设置 `last_error` 为 `-E2BIG` 并返回 `-1`。

#### Scenario: decode short form length
- **GIVEN** 输入流下一个字节最高位未置位
- **WHEN** 调用 `asn1ber_length_from_ber(actx, len)`
- **THEN** 函数把该字节值写入 `*len` 并返回 `0`

Trace: `lib/asn1-ber.c:asn1ber_length_from_ber`

#### Scenario: reject oversized long form length
- **GIVEN** 输入流长度首字节最高位置位且低 7 位大于 `4`
- **WHEN** 调用 `asn1ber_length_from_ber(actx, len)`
- **THEN** 函数设置 `actx->last_error` 为 `-E2BIG` 并返回 `-1`

Trace: `lib/asn1-ber.c:asn1ber_length_from_ber`

### Requirement: ber_typecode_from_ber decodes type code
系统 MUST 读取 BER 类型码，并在首字节不是扩展类型标记 `0x1F` 时直接返回该字节；遇到扩展类型标记时 MUST 再读取一个字节并在值大于等于 `0x30` 时减去 `0x30` 后返回。

#### Scenario: decode direct type code
- **GIVEN** 输入流下一个 BER 类型字节的低 5 位不是 `0x1F`
- **WHEN** 调用 `ber_typecode_from_ber(actx, typecode)`
- **THEN** 函数把该字节转换为 `ber_type_t` 写入 `*typecode` 并返回 `0`

Trace: `lib/asn1-ber.c:ber_typecode_from_ber`

### Requirement: ber_typelen_from_ber decodes type and length
系统 MUST 先通过 `ber_typecode_from_ber` 解码类型码，再通过 `asn1ber_length_from_ber` 解码长度，并 MUST 原样传播任一阶段的非零返回值。

#### Scenario: decode type followed by length
- **GIVEN** 输入流包含有效 BER 类型码和长度字段
- **WHEN** 调用 `ber_typelen_from_ber(actx, typecode, len)`
- **THEN** 函数写入 `*typecode` 与 `*len` 并返回 `0`

Trace: `lib/asn1-ber.c:ber_typelen_from_ber`

### Requirement: asn1ber_request_from_ber decodes request header
系统 MUST 使用 BER 类型长度解码结果作为请求 opcode 和 payload 长度，并 MUST 在底层解码失败时返回该失败结果。

#### Scenario: decode request opcode and length
- **GIVEN** 输入流当前位置包含请求类型码和 BER 长度
- **WHEN** 调用 `asn1ber_request_from_ber(actx, opcode, len)`
- **THEN** 函数写入 `*opcode` 和 `*len`，并在成功时返回 `0`

Trace: `lib/asn1-ber.c:asn1ber_request_from_ber`

### Requirement: asn1ber_struct_from_ber validates structure type
系统 MUST 解码 BER 类型和长度，并仅当类型码等于 `asnSTRUCT` 时返回成功；类型不匹配时 MUST 设置 `last_error` 为 `-EINVAL` 并返回 `-1`。

#### Scenario: reject non-structure type
- **GIVEN** 输入流包含的类型长度字段类型码不是 `asnSTRUCT`
- **WHEN** 调用 `asn1ber_struct_from_ber(actx, len)`
- **THEN** 函数设置 `actx->last_error` 为 `-EINVAL` 并返回 `-1`

Trace: `lib/asn1-ber.c:asn1ber_struct_from_ber`

### Requirement: asn1ber_null_from_ber validates NULL type
系统 MUST 解码 BER 类型和长度，并仅当类型码等于 `asnNULL` 时返回成功；类型不匹配时 MUST 设置 `last_error` 为 `-EINVAL` 并返回 `-1`。

#### Scenario: reject non-NULL type
- **GIVEN** 输入流包含的类型长度字段类型码不是 `asnNULL`
- **WHEN** 调用 `asn1ber_null_from_ber(actx, len)`
- **THEN** 函数设置 `actx->last_error` 为 `-EINVAL` 并返回 `-1`

Trace: `lib/asn1-ber.c:asn1ber_null_from_ber`

### Requirement: asn1ber_int32_from_ber decodes signed 32-bit integer
系统 MUST 仅接受 `BER_INTEGER` 或 `BER_COUNTER` 类型，长度必须在 `1..4` 字节内，并 MUST 按首个值字节符号位执行符号扩展后写入 `*val`。

#### Scenario: decode signed 32-bit value
- **GIVEN** 输入流包含 `BER_INTEGER` 或 `BER_COUNTER`，长度为 `1..4`，且后续值字节完整
- **WHEN** 调用 `asn1ber_int32_from_ber(actx, val)`
- **THEN** 函数按大端顺序组合值字节，依据首字节最高位符号扩展，写入 `*val` 并返回 `0`

Trace: `lib/asn1-ber.c:asn1ber_int32_from_ber`

#### Scenario: reject invalid int32 type or length
- **GIVEN** 输入类型不是允许的整数类型，或长度为 `0` 或大于 `4`
- **WHEN** 调用 `asn1ber_int32_from_ber(actx, val)`
- **THEN** 函数设置 `actx->last_error` 为 `-EINVAL` 或 `-E2BIG`，返回 `-1`，并在长度错误路径把 `*val` 置为 `0`

Trace: `lib/asn1-ber.c:asn1ber_int32_from_ber`

### Requirement: asn1ber_uint32_from_ber decodes unsigned 32-bit value
系统 MUST 仅接受源码列出的无符号、计数器、布尔、地址、时间和枚举类型，长度必须在 `1..4` 字节内，并 MUST 按大端顺序组合为 `uint32_t`。

#### Scenario: decode unsigned 32-bit value
- **GIVEN** 输入流包含允许的 32 位无符号兼容类型，长度为 `1..4`，且后续值字节完整
- **WHEN** 调用 `asn1ber_uint32_from_ber(actx, val)`
- **THEN** 函数按大端顺序组合值字节，写入 `*val` 并返回 `0`

Trace: `lib/asn1-ber.c:asn1ber_uint32_from_ber`

### Requirement: asn1ber_int64_from_ber decodes signed 64-bit integer
系统 MUST 仅接受 `BER_INTEGER64` 类型，长度必须在 `1..8` 字节内，并 MUST 按首个值字节符号位执行符号扩展后写入 `*val`。

#### Scenario: decode signed 64-bit value
- **GIVEN** 输入流包含 `BER_INTEGER64`，长度为 `1..8`，且后续值字节完整
- **WHEN** 调用 `asn1ber_int64_from_ber(actx, val)`
- **THEN** 函数按大端顺序组合值字节，依据首字节最高位符号扩展，写入 `*val` 并返回 `0`

Trace: `lib/asn1-ber.c:asn1ber_int64_from_ber`

### Requirement: asn1ber_uint64_from_ber decodes unsigned 64-bit value
系统 MUST 仅接受 `BER_UNSIGNED64` 或 `BER_COUNTER64` 类型，长度必须在 `1..8` 字节内，并 MUST 按大端顺序组合为 `uint64_t`。

#### Scenario: decode unsigned 64-bit value
- **GIVEN** 输入流包含 `BER_UNSIGNED64` 或 `BER_COUNTER64`，长度为 `1..8`，且后续值字节完整
- **WHEN** 调用 `asn1ber_uint64_from_ber(actx, val)`
- **THEN** 函数按大端顺序组合值字节，写入 `*val` 并返回 `0`

Trace: `lib/asn1-ber.c:asn1ber_uint64_from_ber`

### Requirement: asn1ber_oid_from_ber decodes object identifier
系统 MUST 仅接受 `BER_OBJECT_ID` 类型，长度必须大于 `0` 且不超过 `BER_MAX_OID_ELEMENTS`，并 MUST 将首字节拆分为前两个 OID 元素后继续解码后续 base-128 元素。

#### Scenario: decode object identifier elements
- **GIVEN** 输入流包含 `BER_OBJECT_ID`、有效长度和完整 OID value 字节
- **WHEN** 调用 `asn1ber_oid_from_ber(actx, oid)`
- **THEN** 函数写入 `oid->elements`，把 `oid->length` 设置为解码出的元素数量，并返回 `0`

Trace: `lib/asn1-ber.c:asn1ber_oid_from_ber`

#### Scenario: reject oversized or empty OID payload
- **GIVEN** OID 长度为 `0` 或大于 `BER_MAX_OID_ELEMENTS`
- **WHEN** 调用 `asn1ber_oid_from_ber(actx, oid)`
- **THEN** 函数设置 `actx->last_error` 为 `-E2BIG` 并返回 `-1`

Trace: `lib/asn1-ber.c:asn1ber_oid_from_ber`

### Requirement: asn1ber_bytes_from_ber decodes octet string bytes
系统 MUST 仅接受 `asnOCTET_STRING` 类型，并在声明长度不超过 `maxlen` 时复制值字节、写入 `*lenout`；如果输出容量允许，SHALL 在复制值后追加便利 NUL 字节。

#### Scenario: decode non-empty octet string
- **GIVEN** 输入流包含 `asnOCTET_STRING`、长度不超过 `maxlen` 且后续字节完整
- **WHEN** 调用 `asn1ber_bytes_from_ber(actx, val, maxlen, lenout)`
- **THEN** 函数复制所有值字节，写入实际长度到 `*lenout`，并在 `i < maxlen` 时写入一个 NUL 终止字节

Trace: `lib/asn1-ber.c:asn1ber_bytes_from_ber`

### Requirement: asn1ber_string_from_ber delegates to byte decoder
系统 MUST 将字符串解码请求转发给 `asn1ber_bytes_from_ber`，并 MUST 使用相同的缓冲区、最大长度和输出长度语义。

#### Scenario: decode string as octet string
- **GIVEN** 调用方提供字符缓冲区、容量和长度输出指针
- **WHEN** 调用 `asn1ber_string_from_ber(actx, val, maxlen, lenout)`
- **THEN** 函数以 `uint8_t *` 形式转发 `val` 给 `asn1ber_bytes_from_ber` 并返回其结果

Trace: `lib/asn1-ber.c:asn1ber_string_from_ber`

### Requirement: asn1ber_ber_from_length encodes BER length
系统 MUST 对小于 `128` 的长度写入单字节短格式；对更大长度 MUST 写入长格式长度字节数标记和大端长度字节，并把实际写入长度字段字节数写入 `*lenout`。

#### Scenario: encode long form length
- **GIVEN** `lenin` 大于或等于 `128` 且输出缓冲区有足够空间
- **WHEN** 调用 `asn1ber_ber_from_length(actx, lenin, lenout)`
- **THEN** 函数写入 `0x80 | lenbytesneeded` 以及大端长度字节，写入长度字段字节数到 `*lenout` 并返回 `0`

Trace: `lib/asn1-ber.c:asn1ber_ber_from_length`

### Requirement: asn1ber_ber_reserve_length writes zero placeholders
系统 MUST 向输出缓冲区连续写入 `len` 个零字节作为长度占位，并 MUST 在任一字节写入失败时返回该失败结果。

#### Scenario: reserve length bytes
- **GIVEN** 输出缓冲区可写入请求数量的占位字节
- **WHEN** 调用 `asn1ber_ber_reserve_length(actx, len)`
- **THEN** 函数写入 `len` 个 `0` 字节并返回 `0`

Trace: `lib/asn1-ber.c:asn1ber_ber_reserve_length`

### Requirement: asn1ber_ber_from_typecode writes BER type byte
系统 MUST 将传入 `typecode` 转换为单个 `uint8_t` 并写入输出缓冲区，且 MUST 返回底层字节写入结果。

#### Scenario: write type code byte
- **GIVEN** 输出缓冲区可写入一个字节
- **WHEN** 调用 `asn1ber_ber_from_typecode(actx, typecode)`
- **THEN** 函数写入类型码字节并返回 `0`

Trace: `lib/asn1-ber.c:asn1ber_ber_from_typecode`

### Requirement: asn1ber_ber_from_typelen writes type and length
系统 MUST 先写入类型码，再写入 BER 长度字段，并 MUST 将类型码字节加长度字段字节数写入 `*lenout`。

#### Scenario: write BER type and length prefix
- **GIVEN** 输出缓冲区可容纳类型码和 `lenin` 对应的 BER 长度字段
- **WHEN** 调用 `asn1ber_ber_from_typelen(actx, typecode, lenin, lenout)`
- **THEN** 函数写入类型码和长度字段，将 `*lenout` 设置为长度字段字节数加 `1`，并返回 `0`

Trace: `lib/asn1-ber.c:asn1ber_ber_from_typelen`

### Requirement: asn1ber_ber_from_int32 encodes signed 32-bit integer
系统 MUST 选择可表示 `val` 的最短 1 到 4 字节 BER 值长度，写入给定类型的 type-length 前缀，并按大端顺序写入值字节。

#### Scenario: encode signed 32-bit value
- **GIVEN** 输出缓冲区可容纳 type-length 前缀和计算出的值字节
- **WHEN** 调用 `asn1ber_ber_from_int32(actx, type, val)`
- **THEN** 函数写入给定类型、最短 BER 长度和值字节，并返回 `0`

Trace: `lib/asn1-ber.c:asn1ber_ber_from_int32`

### Requirement: asn1ber_ber_from_uint32 encodes unsigned 32-bit integer
系统 MUST 从高位开始剔除前导零字节以选择最短值长度，写入给定类型的 type-length 前缀，并按大端顺序写入剩余值字节。

#### Scenario: encode unsigned 32-bit value
- **GIVEN** 输出缓冲区可容纳 type-length 前缀和计算出的值字节
- **WHEN** 调用 `asn1ber_ber_from_uint32(actx, type, val)`
- **THEN** 函数写入给定类型、最短 BER 长度和值字节，并返回 `0`

Trace: `lib/asn1-ber.c:asn1ber_ber_from_uint32`

### Requirement: asn1ber_ber_from_int64 encodes signed 64-bit integer
系统 MUST 选择可表示 `val` 的最短 1 到 8 字节 BER 值长度，写入给定类型的 type-length 前缀，并按大端顺序写入值字节。

#### Scenario: encode signed 64-bit value
- **GIVEN** 输出缓冲区可容纳 type-length 前缀和计算出的值字节
- **WHEN** 调用 `asn1ber_ber_from_int64(actx, type, val)`
- **THEN** 函数写入给定类型、最短 BER 长度和值字节，并返回 `0`

Trace: `lib/asn1-ber.c:asn1ber_ber_from_int64`

### Requirement: asn1ber_ber_from_uint64 encodes unsigned 64-bit integer
系统 MUST 从高位开始剔除前导零字节以选择值长度，写入给定类型的 type-length 前缀，并按大端顺序写入剩余值字节。

#### Scenario: encode unsigned 64-bit value
- **GIVEN** 输出缓冲区可容纳 type-length 前缀和计算出的值字节
- **WHEN** 调用 `asn1ber_ber_from_uint64(actx, type, val)`
- **THEN** 函数写入给定类型、计算出的 BER 长度和值字节，并返回 `0`

Trace: `lib/asn1-ber.c:asn1ber_ber_from_uint64`

### Requirement: asn1ber_ber_from_oid encodes object identifier
系统 MUST 写入 `BER_OBJECT_ID` 类型、预留并回填长度字段，然后按 BER OID 规则编码 OID 元素；OID 指针为空或元素数量达到上限时 MUST 设置 `last_error` 并返回非零结果。

#### Scenario: encode OID with combined first two elements
- **GIVEN** `oid` 非空，`oid->length` 小于 `BER_MAX_OID_ELEMENTS`，且前两个元素存在并且第一个元素小于 `40`
- **WHEN** 调用 `asn1ber_ber_from_oid(actx, oid)`
- **THEN** 函数写入 `BER_OBJECT_ID`，将前两个元素编码为 `elements[0] * 40 + elements[1]`，编码后续元素，回填长度并返回 `0`

Trace: `lib/asn1-ber.c:asn1ber_ber_from_oid`, `tests/ntlmssp_generate_blob.c:main`

### Requirement: asn1ber_ber_from_bytes encodes byte string
系统 MUST 写入调用方指定的 BER 类型和长度，然后按原顺序写入 `len` 个输入字节，并 MUST 返回首个写入失败结果。

#### Scenario: encode bytes with caller-specified type
- **GIVEN** 输出缓冲区可容纳 type-length 前缀和 `len` 个输入字节
- **WHEN** 调用 `asn1ber_ber_from_bytes(actx, type, val, len)`
- **THEN** 函数写入指定类型、长度和每个输入字节，并返回 `0`

Trace: `lib/asn1-ber.c:asn1ber_ber_from_bytes`

### Requirement: asn1ber_ber_from_string encodes string as octet string
系统 MUST 将字符串编码请求转发给 `asn1ber_ber_from_bytes`，并 MUST 固定使用 `BER_OCTET_STRING` 类型和调用方提供的长度。

#### Scenario: encode string payload
- **GIVEN** 调用方提供字符指针和长度
- **WHEN** 调用 `asn1ber_ber_from_string(actx, val, len)`
- **THEN** 函数以 `BER_OCTET_STRING` 和 `uint8_t *` 形式转发给 `asn1ber_ber_from_bytes` 并返回其结果

Trace: `lib/asn1-ber.c:asn1ber_ber_from_string`

## Open Questions

| ID | Question | Related Interface | Reason |
| --- | --- | --- | --- |
| Q-001 | `asn1ber_ber_from_uint64` 的循环初始 `bytesneeded` 为 `4` 而不是 `8`，这是否为兼容性要求还是实现缺陷？ | asn1ber_ber_from_uint64 | 源码显示 64 位无符号编码从 4 开始计算长度，但无测试或注释说明意图。 |
| Q-002 | `asn1ber_ber_from_oid` 在 `oid == NULL` 时直接写入 `actx->last_error`，调用方是否保证 `actx` 非空？ | asn1ber_ber_from_oid | 源码未先检查 `actx`，缺少空上下文错误路径测试证据。 |
| Q-003 | BER indefinite length `0x80` 是否应被接受为长度 `0`？ | asn1ber_length_from_ber | 源码按长格式且 `vallen == 0` 解码为 `0`，但未找到协议层测试确认。 |
