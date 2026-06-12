# lib/asn1-ber.h Specification

## Source Context

- Source: `lib/asn1-ber.h`
- Related Headers: `none`
- Related Tests: `none`
- Related Dependencies: `lib/asn1-ber.c` implements the declared BER helpers; `lib/spnego-wrapper.c` uses `struct asn1ber_context`, `struct asn1ber_oid_value`, BER type macros, OID helpers, length reservation, and length annotation to build and parse SPNEGO ASN.1 BER payloads.
- Build/Compile Context: C project; header is guarded by `_ASN1_BER_H_`, optionally includes `config.h` under `HAVE_CONFIG_H`, optionally includes `<stdint.h>` under `HAVE_STDINT_H`, and exposes declarations inside `extern "C"` for C++ consumers.

## Interface Summary

| Interface | Kind | Signature | Decision | Reason |
| --- | --- | --- | --- | --- |
| BER_MAX_OID_ELEMENTS | macro | #define BER_MAX_OID_ELEMENTS     (32) | Include | 公开 OID 元素容量限制，`struct asn1ber_oid_value` 和 OID 编解码实现依赖该上限。 |
| beroid_type_t | typedef | typedef uint32_t  beroid_type_t; | Include | 公开 OID 元素基础类型，调用方需要用它初始化和读取 OID 元素数组。 |
| asn tag macros | macro | #define asnUNIVERSAL ... #define asnUTC_TIME ... #define asnPRIVATE | Include | 公开 BER/ASN.1 tag、class 和 constructed 位常量，调用方和编码实现按这些值生成 type octet。 |
| ber_type_t | enum typedef | typedef enum { ... } ber_type_t; | Include | 公开 BER/SNMP 应用类型枚举，多个解码和编码声明使用该类型作为类型码参数或输出。 |
| ASN1_SEQUENCE | macro | #define ASN1_SEQUENCE(n)        (asnSTRUCT \| (n)) | Include | 公开构造 SEQUENCE type octet 的宏，SPNEGO 编码路径直接使用。 |
| ASN1_CONTEXT | macro | #define ASN1_CONTEXT(n)         (asnCONTEXT_SPECIFIC \| asnCONSTRUCTOR \| (n)) | Include | 公开构造 context-specific constructed type octet 的宏，SPNEGO 编码路径直接使用。 |
| ASN1_CONTEXT_SIMPLE | macro | #define ASN1_CONTEXT_SIMPLE(n)  (asnCONTEXT_SPECIFIC \| (n)) | Include | 公开构造 context-specific simple type octet 的宏，供调用方生成非 constructed context tag。 |
| ASN1_PRIVATE | macro | #define ASN1_PRIVATE            (asnPRIVATE) | Include | 公开 private class type octet 常量别名。 |
| struct asn1ber_context | struct | struct asn1ber_context { uint8_t *src; int src_count; int src_tail; uint8_t *dst; int dst_size; int dst_head; int last_error; }; | Include | 公开 BER 编解码游标和错误状态，所有声明函数以该结构携带输入、输出和错误状态。 |
| struct asn1ber_oid_value | struct | struct asn1ber_oid_value { int length; beroid_type_t elements[BER_MAX_OID_ELEMENTS]; }; | Include | 公开 OID 值模型，SPNEGO 代码使用静态实例作为编码输入和解码比较对象。 |
| asn1ber_save_out_state | function | int asn1ber_save_out_state(struct asn1ber_context *actx, int *out_pos); | Include | 公开输出游标快照函数，编码嵌套 BER 长度时调用方需要保存当前位置。 |
| asn1ber_annotate_length | function | int asn1ber_annotate_length(struct asn1ber_context *actx, int out_pos, int reserved); | Include | 公开回填 BER length 的函数，SPNEGO 编码路径依赖它修正预留长度字段。 |
| asn1ber_length_from_ber | function | int asn1ber_length_from_ber(struct asn1ber_context *actx, uint32_t *len); | Include | 公开 BER length 解码函数，是类型长度、OID 和 octet string 解码的基础接口。 |
| ber_typecode_from_ber | function | int ber_typecode_from_ber(struct asn1ber_context *actx, ber_type_t *typecode); | Include | 公开 BER type octet 解码函数，调用方可读取普通和 implicit 类型码。 |
| ber_typelen_from_ber | function | int ber_typelen_from_ber(struct asn1ber_context *actx, ber_type_t *typecode, uint32_t *len); | Include | 公开组合 type 和 length 解码函数，多个高层解码声明复用该契约。 |
| asn1ber_request_from_ber | function | int asn1ber_request_from_ber(struct asn1ber_context *actx, ber_type_t *opcode, uint32_t *len); | Include | 公开 request type/length 解码别名，调用方可用它读取 ASN.1 请求头。 |
| asn1ber_struct_from_ber | function | int asn1ber_struct_from_ber(struct asn1ber_context *actx, uint32_t *len); | Include | 公开 SEQUENCE/STRUCT 解码函数，会校验类型码并输出长度。 |
| asn1ber_null_from_ber | function | int asn1ber_null_from_ber(struct asn1ber_context *actx, uint32_t *len); | Include | 公开 NULL 解码函数，会校验 NULL 类型码并输出长度。 |
| asn1ber_int32_from_ber | function | int asn1ber_int32_from_ber(struct asn1ber_context *actx, int32_t *val); | Include | 公开 signed 32-bit BER integer 解码函数，包含类型、长度和符号扩展语义。 |
| asn1ber_uint32_from_ber | function | int asn1ber_uint32_from_ber(struct asn1ber_context *actx, uint32_t *val); | Include | 公开 unsigned 32-bit BER integer/application value 解码函数，包含类型白名单和长度限制。 |
| asn1ber_int64_from_ber | function | int asn1ber_int64_from_ber(struct asn1ber_context *actx, int64_t *val); | Include | 公开 signed 64-bit BER integer 解码函数，包含类型、长度和符号扩展语义。 |
| asn1ber_uint64_from_ber | function | int asn1ber_uint64_from_ber(struct asn1ber_context *actx, uint64_t *val); | Include | 公开 unsigned 64-bit BER integer/application value 解码函数，包含类型白名单和长度限制。 |
| asn1ber_oid_from_ber | function | int asn1ber_oid_from_ber(struct asn1ber_context *actx, struct asn1ber_oid_value *oid); | Include | 公开 BER object identifier 解码函数，SPNEGO 解析路径依赖该数据模型。 |
| asn1ber_bytes_from_ber | function | int asn1ber_bytes_from_ber(struct asn1ber_context *actx, uint8_t *val, uint32_t maxlen, uint32_t *lenout); | Include | 公开 octet string 解码函数，包含目标缓冲区长度和输出长度语义。 |
| asn1ber_string_from_ber | function | int asn1ber_string_from_ber(struct asn1ber_context *actx, char *val, uint32_t maxlen, uint32_t *lenout); | Include | 公开字符串解码便利函数，行为归属到 octet string 解码。 |
| asn1ber_ber_from_length | function | int asn1ber_ber_from_length(struct asn1ber_context *actx, uint32_t lenin, uint32_t *lenout); | Include | 公开 BER length 编码函数，输出短格式或长格式长度并报告写入字节数。 |
| asn1ber_ber_reserve_length | function | int asn1ber_ber_reserve_length(struct asn1ber_context *actx, uint32_t len); | Include | 公开长度字段预留函数，嵌套编码路径依赖它写入占位字节。 |
| asn1ber_ber_from_typecode | function | int asn1ber_ber_from_typecode(struct asn1ber_context *actx, const ber_type_t typecode); | Include | 公开 BER type octet 编码函数，SPNEGO 代码直接写入上下文、sequence 和 octet tags。 |
| asn1ber_ber_from_typelen | function | int asn1ber_ber_from_typelen(struct asn1ber_context *actx, const ber_type_t typecode, const uint32_t lenin, uint32_t *lenout); | Include | 公开 type+length 组合编码函数，数值和 bytes 编码函数复用该契约。 |
| asn1ber_ber_from_int32 | function | int asn1ber_ber_from_int32(struct asn1ber_context *actx, const ber_type_t type, const int32_t val); | Include | 公开 signed 32-bit BER integer 编码函数，调用方可指定输出类型码。 |
| asn1ber_ber_from_uint32 | function | int asn1ber_ber_from_uint32(struct asn1ber_context *actx, const ber_type_t type, const uint32_t val); | Include | 公开 unsigned 32-bit BER integer/application value 编码函数，调用方可指定输出类型码。 |
| asn1ber_ber_from_int64 | function | int asn1ber_ber_from_int64(struct asn1ber_context *actx, const ber_type_t type, const int64_t val); | Include | 公开 signed 64-bit BER integer 编码函数，调用方可指定输出类型码。 |
| asn1ber_ber_from_uint64 | function | int asn1ber_ber_from_uint64(struct asn1ber_context *actx, const ber_type_t type, const uint64_t val); | Include | 公开 unsigned 64-bit BER integer/application value 编码函数，调用方可指定输出类型码。 |
| asn1ber_ber_from_oid | function | int asn1ber_ber_from_oid(struct asn1ber_context *actx, const struct asn1ber_oid_value *oid); | Include | 公开 BER object identifier 编码函数，SPNEGO token 构造直接依赖它。 |
| asn1ber_ber_from_bytes | function | int asn1ber_ber_from_bytes(struct asn1ber_context *actx, const ber_type_t type, const uint8_t *val, uint32_t len); | Include | 公开带调用方指定类型码的 bytes 编码函数，SPNEGO response token 使用 octet string 类型调用。 |
| asn1ber_ber_from_string | function | int asn1ber_ber_from_string(struct asn1ber_context *actx, const char *val, uint32_t len); | Include | 公开字符串编码便利函数，行为归属到 octet string bytes 编码。 |

## Data Model Summary

| Type/Macro | Kind | Definition | Notes |
| --- | --- | --- | --- |
| BER_MAX_OID_ELEMENTS | macro | lib/asn1-ber.h:35 | OID 元素数组固定容量为 32。 |
| beroid_type_t | typedef | lib/asn1-ber.h:36 | OID 单个元素使用 `uint32_t` 表示。 |
| asn tag macros | macro | lib/asn1-ber.h:44 | BER universal tag、class、constructed 和 private 常量集合。 |
| ber_type_t | enum | lib/asn1-ber.h:66 | BER/SNMP 基础类型、application 类型和 RFC3781 类型枚举。 |
| ASN1_SEQUENCE | macro | lib/asn1-ber.h:106 | 将 `asnSTRUCT` 与调用方参数按位或。 |
| ASN1_CONTEXT | macro | lib/asn1-ber.h:107 | 将 context-specific、constructed 位与调用方参数按位或。 |
| ASN1_CONTEXT_SIMPLE | macro | lib/asn1-ber.h:108 | 将 context-specific 位与调用方参数按位或。 |
| ASN1_PRIVATE | macro | lib/asn1-ber.h:109 | `asnPRIVATE` 的公开别名。 |
| struct asn1ber_context | struct | lib/asn1-ber.h:111 | 输入源、输出目标、游标和最近错误码状态。 |
| struct asn1ber_oid_value | struct | lib/asn1-ber.h:124 | OID 元素数量和最多 32 个元素的固定数组。 |

## ADDED Requirements

### Requirement: BER_MAX_OID_ELEMENTS preserve OID capacity
系统 MUST 将 `BER_MAX_OID_ELEMENTS` 暴露为 `32`，并让 `struct asn1ber_oid_value.elements` 使用该容量作为 OID 元素上限。

#### Scenario: allocate fixed OID storage
- **GIVEN** 调用方包含 `lib/asn1-ber.h` 并声明 `struct asn1ber_oid_value`。
- **WHEN** 调用方访问 `elements` 数组或使用 OID 编解码接口。
- **THEN** 可用元素容量为 `BER_MAX_OID_ELEMENTS` 个 `beroid_type_t` 元素，源码声明的上限为 32。

Trace: `lib/asn1-ber.h:BER_MAX_OID_ELEMENTS`, `lib/asn1-ber.h:struct asn1ber_oid_value`, `lib/asn1-ber.c:asn1ber_oid_from_ber`

### Requirement: beroid_type_t expose OID element type
系统 MUST 将 `beroid_type_t` 暴露为 `uint32_t`，以保持 OID 元素在声明、静态初始化和编解码之间使用同一无符号 32-bit 表示。

#### Scenario: initialize OID elements
- **GIVEN** 调用方需要定义 ASN.1 object identifier 元素序列。
- **WHEN** 调用方使用 `struct asn1ber_oid_value.elements` 或 `beroid_type_t` 值初始化 OID。
- **THEN** 每个元素按照 `uint32_t` 存储，并可传入 OID 编码和解码接口。

Trace: `lib/asn1-ber.h:beroid_type_t`, `lib/spnego-wrapper.c:oid_gss_mech_spnego`

### Requirement: asn tag macros preserve BER tag constants
系统 MUST 暴露源码声明的 ASN.1 universal tag、class、constructed 和 private 宏常量，使调用方按 X.690/X.208 数值构造 BER type octet。

#### Scenario: emit declared ASN.1 tag value
- **GIVEN** 调用方包含 `lib/asn1-ber.h` 并使用任一 `asn*` tag 宏。
- **WHEN** 该宏参与 BER type octet 编码或比较。
- **THEN** 宏展开值与 `lib/asn1-ber.h` 中对应的十六进制声明值一致。

Trace: `lib/asn1-ber.h:asnUNIVERSAL`, `lib/asn1-ber.h:asnCONTEXT_SPECIFIC`, `lib/spnego-wrapper.c:smb2_spnego_create_negotiate_reply_blob`

### Requirement: ber_type_t expose BER and SNMP type codes
系统 MUST 暴露 `ber_type_t` 枚举及其声明的 BER/SNMP 类型码，使解码函数输出和编码函数输入共享稳定类型集合。

#### Scenario: compare decoded type code
- **GIVEN** 解码函数读取 BER type octet 并写入 `ber_type_t` 输出参数。
- **WHEN** 调用方或内部实现将该值与 `BER_INTEGER`、`BER_OBJECT_ID` 或 application 类型比较。
- **THEN** 比较值与头文件声明的枚举常量一致。

Trace: `lib/asn1-ber.h:ber_type_t`, `lib/asn1-ber.c:ber_typecode_from_ber`, `lib/asn1-ber.c:asn1ber_uint32_from_ber`

### Requirement: ASN1_SEQUENCE construct sequence tag
系统 MUST 将 `ASN1_SEQUENCE(n)` 展开为 `asnSTRUCT | (n)`，以便调用方构造源码定义的 sequence-like BER tag。

#### Scenario: encode sequence wrapper
- **GIVEN** SPNEGO 编码路径需要写入 sequence wrapper type octet。
- **WHEN** 调用方使用 `ASN1_SEQUENCE(0)` 并传给 `asn1ber_ber_from_typecode`。
- **THEN** 写出的 type octet 为 `asnSTRUCT | 0`。

Trace: `lib/asn1-ber.h:ASN1_SEQUENCE`, `lib/spnego-wrapper.c:smb2_spnego_wrap_gssapi`

### Requirement: ASN1_CONTEXT construct context tag
系统 MUST 将 `ASN1_CONTEXT(n)` 展开为 `asnCONTEXT_SPECIFIC | asnCONSTRUCTOR | (n)`，以便调用方构造 context-specific constructed BER tag。

#### Scenario: encode constructed context field
- **GIVEN** SPNEGO 编码路径需要写入 context-specific constructed 字段。
- **WHEN** 调用方使用 `ASN1_CONTEXT(0)` 或其他索引并传给 `asn1ber_ber_from_typecode`。
- **THEN** 写出的 type octet 同时包含 context-specific class、constructed 位和调用方提供的低位索引。

Trace: `lib/asn1-ber.h:ASN1_CONTEXT`, `lib/spnego-wrapper.c:smb2_spnego_wrap_ntlmssp_challenge`

### Requirement: ASN1_CONTEXT_SIMPLE construct simple context tag
系统 MUST 将 `ASN1_CONTEXT_SIMPLE(n)` 展开为 `asnCONTEXT_SPECIFIC | (n)`，以便调用方构造非 constructed context-specific BER tag。

#### Scenario: derive simple context type
- **GIVEN** 调用方需要 context-specific simple type octet。
- **WHEN** 调用方展开 `ASN1_CONTEXT_SIMPLE(n)`。
- **THEN** 结果只包含 context-specific class 位和调用方提供的低位索引，不包含 `asnCONSTRUCTOR` 位。

Trace: `lib/asn1-ber.h:ASN1_CONTEXT_SIMPLE`

### Requirement: ASN1_PRIVATE expose private class alias
系统 MUST 将 `ASN1_PRIVATE` 暴露为 `asnPRIVATE`，使调用方可通过公共别名引用 BER private class 位。

#### Scenario: read private class constant
- **GIVEN** 调用方包含 `lib/asn1-ber.h`。
- **WHEN** 调用方读取 `ASN1_PRIVATE`。
- **THEN** 该宏展开为源码声明的 `asnPRIVATE` 值 `0xC0`。

Trace: `lib/asn1-ber.h:ASN1_PRIVATE`, `lib/asn1-ber.h:asnPRIVATE`

### Requirement: struct asn1ber_context carry BER cursor state
系统 MUST 暴露 `struct asn1ber_context` 的输入缓冲区、输出缓冲区、游标和 `last_error` 字段，使所有 BER helper 通过同一结构读写状态。

#### Scenario: encode into caller-provided buffer
- **GIVEN** 调用方初始化 `dst`、`dst_size` 和 `dst_head` 字段。
- **WHEN** 调用方执行任一 `asn1ber_ber_from_*` 编码接口。
- **THEN** 编码接口从 `dst_head` 位置写入 `dst`，并按实际写入字节推进 `dst_head` 或在空间不足时返回错误。

Trace: `lib/asn1-ber.h:struct asn1ber_context`, `lib/asn1-ber.c:asn1ber_out_byte`, `lib/spnego-wrapper.c:smb2_spnego_wrap_gssapi`

#### Scenario: decode from caller-provided buffer
- **GIVEN** 调用方初始化 `src`、`src_count` 和 `src_tail` 字段。
- **WHEN** 调用方执行任一 `*_from_ber` 解码接口。
- **THEN** 解码接口从 `src_tail` 位置读取 `src`，并按实际读取字节推进 `src_tail` 或在输入不足时返回错误。

Trace: `lib/asn1-ber.h:struct asn1ber_context`, `lib/asn1-ber.c:asn1ber_next_byte`, `lib/spnego-wrapper.c:smb2_spnego_decode_negTokenInit`

### Requirement: struct asn1ber_oid_value carry bounded OID values
系统 MUST 暴露 `struct asn1ber_oid_value` 的 `length` 和固定 `elements` 数组，使 OID 编码按前 `length` 个元素读取并使 OID 解码写回实际元素数。

#### Scenario: encode static OID value
- **GIVEN** 调用方提供 `length` 和对应数量的 `elements`。
- **WHEN** 调用方调用 `asn1ber_ber_from_oid`。
- **THEN** 编码实现使用前 `length` 个元素生成 BER object identifier 内容，且 `length` 不得达到或超过 `BER_MAX_OID_ELEMENTS`。

Trace: `lib/asn1-ber.h:struct asn1ber_oid_value`, `lib/asn1-ber.c:asn1ber_ber_from_oid`, `lib/spnego-wrapper.c:oid_spnego_mech_ntlmssp`

### Requirement: asn1ber_save_out_state snapshot output position
系统 MUST 在 `actx`、`actx->dst` 和 `out_pos` 有效且当前输出位置未越过输出缓冲区时，将 `actx->dst_head` 写入 `*out_pos` 并返回 0。

#### Scenario: save length placeholder position
- **GIVEN** 调用方正在编码嵌套 BER 结构，且输出上下文有效。
- **WHEN** 调用方调用 `asn1ber_save_out_state(actx, &out_pos)`。
- **THEN** `out_pos` 接收当前 `dst_head`，后续可传给 `asn1ber_annotate_length` 回填该位置的长度。

Trace: `lib/asn1-ber.h:asn1ber_save_out_state`, `lib/asn1-ber.c:asn1ber_save_out_state`, `lib/spnego-wrapper.c:smb2_spnego_create_negotiate_reply_blob`

### Requirement: asn1ber_annotate_length backfill reserved length
系统 MUST 计算 `out_pos` 之后扣除 `reserved` 的 payload 字节数，将 BER length 写回 `out_pos`，并在预留长度大于实际 length 编码字节数时左移 payload。

#### Scenario: shrink reserved length field
- **GIVEN** 调用方先在 `out_pos` 预留了 length 字节，随后写入 payload。
- **WHEN** 调用方调用 `asn1ber_annotate_length(actx, out_pos, reserved)`。
- **THEN** 函数在 `out_pos` 位置写入实际 payload 长度，并让 `dst_head` 指向紧随 length 和 payload 后的新结尾。

Trace: `lib/asn1-ber.h:asn1ber_annotate_length`, `lib/asn1-ber.c:asn1ber_annotate_length`, `lib/spnego-wrapper.c:smb2_spnego_wrap_ntlmssp_challenge`

### Requirement: asn1ber_length_from_ber decode BER length
系统 MUST 从输入流读取 BER length octets，支持短格式和最多 4 个后续字节的长格式，并通过 `len` 输出解码后的长度。

#### Scenario: decode short-form length
- **GIVEN** 输入流下一个字节未设置高位。
- **WHEN** 调用方调用 `asn1ber_length_from_ber(actx, &len)`。
- **THEN** `len` 等于该字节值，函数返回 0，并消耗 1 个输入字节。

Trace: `lib/asn1-ber.h:asn1ber_length_from_ber`, `lib/asn1-ber.c:asn1ber_length_from_ber`

#### Scenario: reject oversized long-form length header
- **GIVEN** 输入流下一个 length 字节设置高位且低 7 位大于 4。
- **WHEN** 调用方调用 `asn1ber_length_from_ber(actx, &len)`。
- **THEN** 函数返回 `-1`，并将 `actx->last_error` 设置为 `-E2BIG`。

Trace: `lib/asn1-ber.h:asn1ber_length_from_ber`, `lib/asn1-ber.c:asn1ber_length_from_ber`

### Requirement: ber_typecode_from_ber decode BER type code
系统 MUST 从输入流读取 BER type octet；普通低 5 位非 `0x1F` 时直接输出该字节，implicit 形式时读取下一字节并按源码规则折算输出。

#### Scenario: decode direct type code
- **GIVEN** 输入流下一个 type octet 的低 5 位不是 `0x1F`。
- **WHEN** 调用方调用 `ber_typecode_from_ber(actx, &typecode)`。
- **THEN** `typecode` 等于该 type octet，函数返回 0。

Trace: `lib/asn1-ber.h:ber_typecode_from_ber`, `lib/asn1-ber.c:ber_typecode_from_ber`

### Requirement: ber_typelen_from_ber decode type and length
系统 MUST 先按 `ber_typecode_from_ber` 解码类型码，再按 `asn1ber_length_from_ber` 解码长度，并传播任一阶段的错误返回值。

#### Scenario: decode BER header pair
- **GIVEN** 输入流当前位置包含 BER type 后跟 BER length。
- **WHEN** 调用方调用 `ber_typelen_from_ber(actx, &typecode, &len)`。
- **THEN** `typecode` 和 `len` 分别接收解码结果，输入游标推进到 value 起始位置。

Trace: `lib/asn1-ber.h:ber_typelen_from_ber`, `lib/asn1-ber.c:ber_typelen_from_ber`

### Requirement: asn1ber_request_from_ber decode request header
系统 MUST 将 request 头解码委托给 `ber_typelen_from_ber`，通过 `opcode` 和 `len` 输出读取到的 type 和 length。

#### Scenario: decode request opcode and length
- **GIVEN** 输入流当前位置包含 ASN.1 request 的 type 和 length。
- **WHEN** 调用方调用 `asn1ber_request_from_ber(actx, &opcode, &len)`。
- **THEN** `opcode` 和 `len` 与 `ber_typelen_from_ber` 解码结果一致，错误返回值被原样传播。

Trace: `lib/asn1-ber.h:asn1ber_request_from_ber`, `lib/asn1-ber.c:asn1ber_request_from_ber`

### Requirement: asn1ber_struct_from_ber require struct tag
系统 MUST 解码 type 和 length，并在 typecode 不等于 `asnSTRUCT` 时返回 `-1` 且设置 `actx->last_error` 为 `-EINVAL`。

#### Scenario: accept struct header
- **GIVEN** 输入流当前位置的 typecode 为 `asnSTRUCT`，后面跟随 BER length。
- **WHEN** 调用方调用 `asn1ber_struct_from_ber(actx, &len)`。
- **THEN** 函数返回 0，`len` 接收结构 payload 长度。

Trace: `lib/asn1-ber.h:asn1ber_struct_from_ber`, `lib/asn1-ber.c:asn1ber_struct_from_ber`

#### Scenario: reject non-struct header
- **GIVEN** 输入流当前位置的 typecode 不是 `asnSTRUCT`。
- **WHEN** 调用方调用 `asn1ber_struct_from_ber(actx, &len)`。
- **THEN** 函数返回 `-1`，并将 `actx->last_error` 设置为 `-EINVAL`。

Trace: `lib/asn1-ber.h:asn1ber_struct_from_ber`, `lib/asn1-ber.c:asn1ber_struct_from_ber`

### Requirement: asn1ber_null_from_ber require null tag
系统 MUST 解码 type 和 length，并在 typecode 不等于 `asnNULL` 时返回 `-1` 且设置 `actx->last_error` 为 `-EINVAL`。

#### Scenario: accept null header
- **GIVEN** 输入流当前位置的 typecode 为 `asnNULL`，后面跟随 BER length。
- **WHEN** 调用方调用 `asn1ber_null_from_ber(actx, &len)`。
- **THEN** 函数返回 0，`len` 接收 NULL payload 长度。

Trace: `lib/asn1-ber.h:asn1ber_null_from_ber`, `lib/asn1-ber.c:asn1ber_null_from_ber`

### Requirement: asn1ber_int32_from_ber decode signed 32-bit integer
系统 MUST 只接受 `BER_INTEGER` 或 `BER_COUNTER` type，要求 value length 为 1 到 4 字节，并按最高有效 value 字节符号位执行符号扩展。

#### Scenario: decode signed integer value
- **GIVEN** 输入流包含 `BER_INTEGER` 或 `BER_COUNTER`，length 为 1 到 4，后跟 big-endian value 字节。
- **WHEN** 调用方调用 `asn1ber_int32_from_ber(actx, &val)`。
- **THEN** `val` 接收符号扩展后的 `int32_t` 值，函数返回 0。

Trace: `lib/asn1-ber.h:asn1ber_int32_from_ber`, `lib/asn1-ber.c:asn1ber_int32_from_ber`

#### Scenario: reject invalid signed integer length
- **GIVEN** 输入流的 integer value length 为 0 或大于 4。
- **WHEN** 调用方调用 `asn1ber_int32_from_ber(actx, &val)`。
- **THEN** 函数返回 `-1`，将 `val` 置 0，并将 `actx->last_error` 设置为 `-E2BIG`。

Trace: `lib/asn1-ber.h:asn1ber_int32_from_ber`, `lib/asn1-ber.c:asn1ber_int32_from_ber`

### Requirement: asn1ber_uint32_from_ber decode unsigned 32-bit value
系统 MUST 只接受源码白名单中的 32-bit BER/application type，要求 value length 为 1 到 4 字节，并按 big-endian 字节序输出 `uint32_t` 值。

#### Scenario: decode unsigned application value
- **GIVEN** 输入流包含 `BER_BOOLEAN`、`BER_IPADDRESS`、`BER_COUNTER`、`BER_UNSIGNED`、`BER_TIMETICKS`、`BER_NSAPADDRESS`、`BER_UNSIGNED32` 或 `BER_ENUMERATED` 类型，且 length 为 1 到 4。
- **WHEN** 调用方调用 `asn1ber_uint32_from_ber(actx, &val)`。
- **THEN** `val` 接收按 big-endian 组合的无符号 32-bit 值。

Trace: `lib/asn1-ber.h:asn1ber_uint32_from_ber`, `lib/asn1-ber.c:asn1ber_uint32_from_ber`

### Requirement: asn1ber_int64_from_ber decode signed 64-bit integer
系统 MUST 只接受 `BER_INTEGER64` type，要求 value length 为 1 到 8 字节，并按最高有效 value 字节符号位执行符号扩展。

#### Scenario: decode signed 64-bit value
- **GIVEN** 输入流包含 `BER_INTEGER64`，length 为 1 到 8，后跟 big-endian value 字节。
- **WHEN** 调用方调用 `asn1ber_int64_from_ber(actx, &val)`。
- **THEN** `val` 接收符号扩展后的 `int64_t` 值，函数返回 0。

Trace: `lib/asn1-ber.h:asn1ber_int64_from_ber`, `lib/asn1-ber.c:asn1ber_int64_from_ber`

### Requirement: asn1ber_uint64_from_ber decode unsigned 64-bit value
系统 MUST 只接受 `BER_UNSIGNED64` 或 `BER_COUNTER64` type，要求 value length 为 1 到 8 字节，并按 big-endian 字节序输出 `uint64_t` 值。

#### Scenario: decode unsigned 64-bit value
- **GIVEN** 输入流包含 `BER_UNSIGNED64` 或 `BER_COUNTER64`，length 为 1 到 8，后跟 big-endian value 字节。
- **WHEN** 调用方调用 `asn1ber_uint64_from_ber(actx, &val)`。
- **THEN** `val` 接收按 big-endian 组合的无符号 64-bit 值。

Trace: `lib/asn1-ber.h:asn1ber_uint64_from_ber`, `lib/asn1-ber.c:asn1ber_uint64_from_ber`

### Requirement: asn1ber_oid_from_ber decode object identifier
系统 MUST 只接受 `BER_OBJECT_ID` type，按 BER OID base-128 规则写入 `oid->elements`，并在成功时设置 `oid->length` 为实际元素数。

#### Scenario: decode valid OID
- **GIVEN** 输入流包含 `BER_OBJECT_ID`、有效 length 和 OID value 字节。
- **WHEN** 调用方调用 `asn1ber_oid_from_ber(actx, &oid)`。
- **THEN** `oid.elements[0]` 和 `oid.elements[1]` 由首个 OID value 字节拆分，后续元素按 base-128 continuation 字节解码，`oid.length` 为写入元素数。

Trace: `lib/asn1-ber.h:asn1ber_oid_from_ber`, `lib/asn1-ber.c:asn1ber_oid_from_ber`, `lib/spnego-wrapper.c:smb2_spnego_decode_negTokenInit`

### Requirement: asn1ber_bytes_from_ber decode octet string
系统 MUST 只接受 `asnOCTET_STRING` type，在 value length 不超过 `maxlen` 时复制 value 字节到调用方缓冲区，并通过 `lenout` 输出复制长度。

#### Scenario: decode non-empty bytes
- **GIVEN** 输入流包含 octet string type、BER length 和不超过 `maxlen` 的 value 字节。
- **WHEN** 调用方调用 `asn1ber_bytes_from_ber(actx, val, maxlen, &lenout)`。
- **THEN** 前 `lenout` 个字节复制到 `val`，函数返回 0，并在 `lenout < maxlen` 时写入一个额外的 0 终止字节。

Trace: `lib/asn1-ber.h:asn1ber_bytes_from_ber`, `lib/asn1-ber.c:asn1ber_bytes_from_ber`

### Requirement: asn1ber_string_from_ber decode string as bytes
系统 MUST 将 `asn1ber_string_from_ber` 的行为委托给 `asn1ber_bytes_from_ber`，使用同一 octet string 类型检查、长度限制和 `lenout` 输出语义。

#### Scenario: decode string payload
- **GIVEN** 输入流包含 BER octet string，调用方提供 `char *` 输出缓冲区。
- **WHEN** 调用方调用 `asn1ber_string_from_ber(actx, val, maxlen, &lenout)`。
- **THEN** 结果与以同一缓冲区调用 `asn1ber_bytes_from_ber` 一致。

Trace: `lib/asn1-ber.h:asn1ber_string_from_ber`, `lib/asn1-ber.c:asn1ber_string_from_ber`

### Requirement: asn1ber_ber_from_length encode BER length
系统 MUST 对小于 128 的长度写入短格式单字节 length，对 128 及以上的长度写入长格式 length，并通过 `lenout` 输出 length 字段字节数。

#### Scenario: encode short-form length
- **GIVEN** 调用方提供 `lenin < 128` 的长度和有效输出上下文。
- **WHEN** 调用方调用 `asn1ber_ber_from_length(actx, lenin, &lenout)`。
- **THEN** 输出缓冲区写入一个值为 `lenin` 的字节，`lenout` 为 1。

Trace: `lib/asn1-ber.h:asn1ber_ber_from_length`, `lib/asn1-ber.c:asn1ber_ber_from_length`

#### Scenario: encode long-form length
- **GIVEN** 调用方提供 `lenin >= 128` 的长度和有效输出上下文。
- **WHEN** 调用方调用 `asn1ber_ber_from_length(actx, lenin, &lenout)`。
- **THEN** 输出缓冲区先写入 `0x80 | lenbytesneeded`，随后按大端顺序写入 length 字节，`lenout` 为总 length 字段字节数。

Trace: `lib/asn1-ber.h:asn1ber_ber_from_length`, `lib/asn1-ber.c:asn1ber_ber_from_length`

### Requirement: asn1ber_ber_reserve_length reserve zero bytes
系统 MUST 向输出缓冲区写入调用方请求数量的零字节，用作后续 `asn1ber_annotate_length` 的 length 占位空间。

#### Scenario: reserve nested length bytes
- **GIVEN** 调用方准备编码嵌套 BER 结构并已保存输出位置。
- **WHEN** 调用方调用 `asn1ber_ber_reserve_length(actx, len)`。
- **THEN** 输出缓冲区追加 `len` 个零字节，任一写入失败时返回错误。

Trace: `lib/asn1-ber.h:asn1ber_ber_reserve_length`, `lib/asn1-ber.c:asn1ber_ber_reserve_length`, `lib/spnego-wrapper.c:smb2_spnego_wrap_gssapi`

### Requirement: asn1ber_ber_from_typecode encode type octet
系统 MUST 将调用方提供的 `ber_type_t` 值截断为 `uint8_t` 并写入输出缓冲区当前 `dst_head` 位置。

#### Scenario: write context-specific type
- **GIVEN** 调用方提供通过 `ASN1_CONTEXT(n)` 构造的 typecode。
- **WHEN** 调用方调用 `asn1ber_ber_from_typecode(actx, typecode)`。
- **THEN** 输出缓冲区追加该 typecode 的低 8 位，`dst_head` 前进 1。

Trace: `lib/asn1-ber.h:asn1ber_ber_from_typecode`, `lib/asn1-ber.c:asn1ber_ber_from_typecode`, `lib/spnego-wrapper.c:smb2_spnego_wrap_ntlmssp_challenge`

### Requirement: asn1ber_ber_from_typelen encode type and length
系统 MUST 先写入 type octet，再按 BER length 规则写入 `lenin`，并通过 `lenout` 输出 type 和 length 字段的总字节数。

#### Scenario: encode BER header
- **GIVEN** 调用方提供 typecode、payload 长度和有效输出上下文。
- **WHEN** 调用方调用 `asn1ber_ber_from_typelen(actx, typecode, lenin, &lenout)`。
- **THEN** 输出缓冲区依次追加 type 和 length，`lenout` 等于 length 编码字节数加 1。

Trace: `lib/asn1-ber.h:asn1ber_ber_from_typelen`, `lib/asn1-ber.c:asn1ber_ber_from_typelen`

### Requirement: asn1ber_ber_from_int32 encode signed 32-bit integer
系统 MUST 使用调用方提供的 typecode 和最短源码实现字节数编码 `int32_t` 值，并按 big-endian 顺序写入 value 字节。

#### Scenario: encode signed 32-bit value
- **GIVEN** 调用方提供 signed 32-bit 值和输出 typecode。
- **WHEN** 调用方调用 `asn1ber_ber_from_int32(actx, type, val)`。
- **THEN** 输出缓冲区包含 type、length 和按源码最短规则选择的 big-endian value 字节。

Trace: `lib/asn1-ber.h:asn1ber_ber_from_int32`, `lib/asn1-ber.c:asn1ber_ber_from_int32`

### Requirement: asn1ber_ber_from_uint32 encode unsigned 32-bit value
系统 MUST 使用调用方提供的 typecode 和源码实现计算的字节数编码 `uint32_t` 值，并按 big-endian 顺序写入 value 字节。

#### Scenario: encode unsigned 32-bit value
- **GIVEN** 调用方提供 unsigned 32-bit 值和输出 typecode。
- **WHEN** 调用方调用 `asn1ber_ber_from_uint32(actx, type, val)`。
- **THEN** 输出缓冲区包含 type、length 和按源码规则选择的 big-endian value 字节。

Trace: `lib/asn1-ber.h:asn1ber_ber_from_uint32`, `lib/asn1-ber.c:asn1ber_ber_from_uint32`

### Requirement: asn1ber_ber_from_int64 encode signed 64-bit integer
系统 MUST 使用调用方提供的 typecode 和最短源码实现字节数编码 `int64_t` 值，并按 big-endian 顺序写入 value 字节。

#### Scenario: encode signed 64-bit value
- **GIVEN** 调用方提供 signed 64-bit 值和输出 typecode。
- **WHEN** 调用方调用 `asn1ber_ber_from_int64(actx, type, val)`。
- **THEN** 输出缓冲区包含 type、length 和按源码最短规则选择的 big-endian value 字节。

Trace: `lib/asn1-ber.h:asn1ber_ber_from_int64`, `lib/asn1-ber.c:asn1ber_ber_from_int64`

### Requirement: asn1ber_ber_from_uint64 encode unsigned 64-bit value
系统 MUST 使用调用方提供的 typecode 和源码实现计算的字节数编码 `uint64_t` 值，并按 big-endian 顺序写入 value 字节。

#### Scenario: encode unsigned 64-bit value
- **GIVEN** 调用方提供 unsigned 64-bit 值和输出 typecode。
- **WHEN** 调用方调用 `asn1ber_ber_from_uint64(actx, type, val)`。
- **THEN** 输出缓冲区包含 type、length 和按源码规则选择的 big-endian value 字节。

Trace: `lib/asn1-ber.h:asn1ber_ber_from_uint64`, `lib/asn1-ber.c:asn1ber_ber_from_uint64`

### Requirement: asn1ber_ber_from_oid encode object identifier
系统 MUST 写入 `BER_OBJECT_ID` type，预留并回填 length，然后按 BER OID base-128 规则编码 `oid->elements` 中的元素。

#### Scenario: encode SPNEGO mechanism OID
- **GIVEN** 调用方提供有效 `struct asn1ber_oid_value`，且 `oid->length` 小于 `BER_MAX_OID_ELEMENTS`。
- **WHEN** 调用方调用 `asn1ber_ber_from_oid(actx, oid)`。
- **THEN** 输出缓冲区追加 object identifier 的 type、length 和 BER 编码内容，返回值来自最终 length 回填结果。

Trace: `lib/asn1-ber.h:asn1ber_ber_from_oid`, `lib/asn1-ber.c:asn1ber_ber_from_oid`, `lib/spnego-wrapper.c:smb2_spnego_create_negotiate_reply_blob`

### Requirement: asn1ber_ber_from_bytes encode bytes with caller type
系统 MUST 使用调用方提供的 typecode 和 `len` 写入 BER type+length，然后按原始顺序复制 `val[0..len)` 到输出缓冲区。

#### Scenario: encode octet string payload
- **GIVEN** 调用方提供 bytes 指针、长度和 `asnOCTET_STRING` typecode。
- **WHEN** 调用方调用 `asn1ber_ber_from_bytes(actx, type, val, len)`。
- **THEN** 输出缓冲区追加 type、length 和完全相同顺序的 payload 字节。

Trace: `lib/asn1-ber.h:asn1ber_ber_from_bytes`, `lib/asn1-ber.c:asn1ber_ber_from_bytes`, `lib/spnego-wrapper.c:smb2_spnego_wrap_ntlmssp_challenge`

### Requirement: asn1ber_ber_from_string encode string as octet string
系统 MUST 将 `asn1ber_ber_from_string` 的行为委托给 `asn1ber_ber_from_bytes`，并固定使用 `BER_OCTET_STRING` 作为输出 typecode。

#### Scenario: encode string payload
- **GIVEN** 调用方提供字符串指针和要编码的字节长度。
- **WHEN** 调用方调用 `asn1ber_ber_from_string(actx, val, len)`。
- **THEN** 输出结果与以同一字节范围调用 `asn1ber_ber_from_bytes(actx, BER_OCTET_STRING, (uint8_t *)val, len)` 一致。

Trace: `lib/asn1-ber.h:asn1ber_ber_from_string`, `lib/asn1-ber.c:asn1ber_ber_from_string`

## Open Questions

| ID | Question | Related Interface | Reason |
| --- | --- | --- | --- |
| Q-001 | `asn1ber_ber_from_uint64` 的源码循环从 `bytesneeded = 4` 开始，是否有意只为无符号 64-bit 输出最多 4 个字节，还是应按 8 字节范围处理？ | asn1ber_ber_from_uint64 | 头文件声明为 `uint64_t`，但实现中的最短长度计算初始值与 32-bit 路径一致，当前 spec 记录现有源码行为而不推断意图。 |
| Q-002 | `ber_typecode_from_ber` 对 implicit type 第二字节大于等于 `0x30` 时减去 `0x30` 的规则是否仅服务当前 SPNEGO 解码输入？ | ber_typecode_from_ber | 源码实现存在该折算规则，但头文件和注释未说明完整 ASN.1 high-tag-number 兼容范围。 |
| Q-003 | GitNexus 对头文件声明的直接调用者返回为空，对实现 UID 才能看到部分调用链；是否需要重新索引以补齐声明到实现和测试调用关系？ | file-level | `gitnexus context` on header declarations reported no incoming calls while source search and implementation context show `lib/spnego-wrapper.c` dependencies。 |
