# lib/dcerpc-lsa.c Specification

## Source Context

- Source: `lib/dcerpc-lsa.c`
- Related Headers: `include/smb2/libsmb2-dcerpc-lsa.h`, `include/smb2/libsmb2-dcerpc.h`, `include/smb2/libsmb2-raw.h`, `include/smb2/libsmb2.h`, `include/smb2/smb2.h`, `include/libsmb2-private.h`, `lib/compat.h`
- Related Tests: `none`
- Related Dependencies: GitNexus context for `lsa_interface`, `lsa_RPC_SID_coder`, `lsa_RPC_UNICODE_STRING_coder`, `lsa_Close_req_coder`, `lsa_OpenPolicy2_req_coder`, `lsa_LookupSids2_req_coder`, and `lsa_LookupSids2_rep_coder` shows dependencies on shared DCERPC coders including `dcerpc_ptr_coder`, `dcerpc_uint8_coder`, `dcerpc_uint16_coder`, `dcerpc_uint32_coder`, `dcerpc_uint3264_coder`, `dcerpc_context_handle_coder`, `dcerpc_utf16_coder`, `dcerpc_utf16z_coder`, `dcerpc_align_3264`, `dcerpc_pdu_direction`, `dcerpc_get_smb2_context`, `dcerpc_get_pdu_payload`, and `smb2_alloc_data`. Impact for `lsa_interface` is LOW with no indexed upstream callers; impact for `lsa_RPC_UNICODE_STRING_coder` is LOW with direct callers `lsa_TRANSLATED_NAME_EX_coder` and `lsa_TRUST_INFORMATION_coder`; same-name public declarations make several function impact queries ambiguous.
- Build/Compile Context: C implementation compiled with optional `HAVE_CONFIG_H`, `_GNU_SOURCE`, and platform header feature macros from project configure/CMake context; implementation defines the LSA transfer syntax object and NDR coder functions used by the DCERPC LSA public header and example `examples/smb2-lsa-lookupsids.c`.

## Interface Summary

| Interface | Kind | Signature | Decision | Reason |
| --- | --- | --- | --- | --- |
| LSA_UUID | macro | #define LSA_UUID    0x12345778, 0x1234, 0xabcd, {0xef, 0x00, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab} | Include | 文件级 LSA transfer syntax UUID，驱动 `lsa_interface` 的外部连接身份。 |
| lsa_interface | object | p_syntax_id_t lsa_interface = { {LSA_UUID}, 0, 0 }; | Include | DCERPC LSA endpoint connect 使用的公开语法标识对象。 |
| NT_SID_AUTHORITY | object | unsigned char NT_SID_AUTHORITY[6] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x05 }; | Include | 公开 NT SID authority 数组定义，与头文件 extern 声明配对。 |
| lsa_RPC_SID_coder | function | int lsa_RPC_SID_coder(struct dcerpc_context *dce, struct dcerpc_pdu *pdu, struct smb2_iovec *iov, int *offset, void *ptr) | Include | 公开 RPC SID NDR coder，并被内部 SID 数组和 trust information coder 复用。 |
| lsa_PRPC_SID_array_coder | function | static int lsa_PRPC_SID_array_coder(struct dcerpc_context *dce, struct dcerpc_pdu *pdu, struct smb2_iovec *iov, int *offset, void *ptr) | Skip | 纯内部数组 helper，通过 `lsa_SID_ENUM_BUFFER_coder` 归属，无独立外部契约。 |
| lsa_SID_ENUM_BUFFER_coder | function | static int lsa_SID_ENUM_BUFFER_coder(struct dcerpc_context *dce, struct dcerpc_pdu *pdu, struct smb2_iovec *iov, int *offset, void *ptr) | Skip | 纯内部 `LSAPR_SID_ENUM_BUFFER` helper，通过 `lsa_LookupSids2_req_coder` 归属。 |
| lsa_RPC_UNICODE_STRING_coder | function | int lsa_RPC_UNICODE_STRING_coder(struct dcerpc_context *dce, struct dcerpc_pdu *pdu, struct smb2_iovec *iov, int *offset, void *ptr) | Include | 非 static 字符串 coder，被多个 LSA 结构 coder 复用并影响名称编码/解码。 |
| lsa_TRANSLATED_NAME_EX_coder | function | static int lsa_TRANSLATED_NAME_EX_coder(struct dcerpc_context *dce, struct dcerpc_pdu *pdu, struct smb2_iovec *iov, int *offset, void *ptr) | Skip | 纯内部 translated-name helper，通过 `lsa_TRANSLATED_NAMES_EX_coder` 归属。 |
| TN_array_coder | function | static int TN_array_coder(struct dcerpc_context *dce, struct dcerpc_pdu *pdu, struct smb2_iovec *iov, int *offset, void *ptr) | Skip | 纯内部数组 helper，通过 `lsa_TRANSLATED_NAMES_EX_coder` 归属。 |
| lsa_TRANSLATED_NAMES_EX_coder | function | static int lsa_TRANSLATED_NAMES_EX_coder(struct dcerpc_context *dce, struct dcerpc_pdu *pdu, struct smb2_iovec *iov, int *offset, void *ptr) | Skip | 纯内部 translated-names helper，通过 LookupSids2 请求/响应 coder 归属。 |
| lsa_ObjectAttributes_coder | function | static int lsa_ObjectAttributes_coder(struct dcerpc_context *dce, struct dcerpc_pdu *pdu, struct smb2_iovec *iov, int *offset, void *ptr) | Skip | 纯内部 OpenPolicy2 object attributes helper，通过 `lsa_OpenPolicy2_req_coder` 归属。 |
| lsa_Close_req_coder | function | int lsa_Close_req_coder(struct dcerpc_context *dce, struct dcerpc_pdu *pdu, struct smb2_iovec *iov, int *offset, void *ptr) | Include | 公开 Close 请求 NDR coder。 |
| lsa_Close_rep_coder | function | int lsa_Close_rep_coder(struct dcerpc_context *dce, struct dcerpc_pdu *pdu, struct smb2_iovec *iov, int *offset, void *ptr) | Include | 公开 Close 响应 NDR coder。 |
| lsa_OpenPolicy2_req_coder | function | int lsa_OpenPolicy2_req_coder(struct dcerpc_context *dce, struct dcerpc_pdu *pdu, struct smb2_iovec *iov, int *offset, void *ptr) | Include | 公开 OpenPolicy2 请求 NDR coder。 |
| lsa_OpenPolicy2_rep_coder | function | int lsa_OpenPolicy2_rep_coder(struct dcerpc_context *dce, struct dcerpc_pdu *pdu, struct smb2_iovec *iov, int *offset, void *ptr) | Include | 公开 OpenPolicy2 响应 NDR coder。 |
| lsa_TRUST_INFORMATION_coder | function | static int lsa_TRUST_INFORMATION_coder(struct dcerpc_context *dce, struct dcerpc_pdu *pdu, struct smb2_iovec *iov, int *offset, void *ptr) | Skip | 纯内部 referenced-domain entry helper，通过 `lsa_REFERENCED_DOMAIN_LIST_coder` 归属。 |
| RDL_DOMAINS_array_coder | function | static int RDL_DOMAINS_array_coder(struct dcerpc_context *dce, struct dcerpc_pdu *pdu, struct smb2_iovec *iov, int *offset, void *ptr) | Skip | 纯内部 referenced-domain array helper，通过 `lsa_REFERENCED_DOMAIN_LIST_coder` 归属。 |
| lsa_REFERENCED_DOMAIN_LIST_coder | function | static int lsa_REFERENCED_DOMAIN_LIST_coder(struct dcerpc_context *dce, struct dcerpc_pdu *pdu, struct smb2_iovec *iov, int *offset, void *ptr) | Skip | 纯内部 referenced-domain list helper，通过 `lsa_LookupSids2_rep_coder` 归属。 |
| lsa_LookupSids2_req_coder | function | int lsa_LookupSids2_req_coder(struct dcerpc_context *dce, struct dcerpc_pdu *pdu, struct smb2_iovec *iov, int *offset, void *ptr) | Include | 公开 LookupSids2 请求 NDR coder，含固定 LookupOptions/ClientRevision 序列化语义。 |
| lsa_LookupSids2_rep_coder | function | int lsa_LookupSids2_rep_coder(struct dcerpc_context *dce, struct dcerpc_pdu *pdu, struct smb2_iovec *iov, int *offset, void *ptr) | Include | 公开 LookupSids2 响应 NDR coder，负责 referenced domains、translated names、mapped count 和 status。 |

## Data Model Summary

| Type/Macro | Kind | Definition | Notes |
| --- | --- | --- | --- |
| LSA_UUID | macro | lib/dcerpc-lsa.c:70 | LSA RPC interface UUID `12345778-1234-abcd-ef00-0123456789ab`。 |
| lsa_interface | object | lib/dcerpc-lsa.c:72 | `p_syntax_id_t` 使用 `LSA_UUID`，major/minor 版本字段为 `0, 0`。 |
| NT_SID_AUTHORITY | object | lib/dcerpc-lsa.c:76 | 六字节 NT authority `{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x05 }`。 |
| RPC_SID | struct | include/smb2/libsmb2-dcerpc-lsa.h:47 | `lsa_RPC_SID_coder` 处理 revision、sub-authority count、authority bytes 和动态 sub-authority 数组。 |
| LSAPR_SID_ENUM_BUFFER | struct | include/smb2/libsmb2-dcerpc-lsa.h:66 | `Entries` 控制 `SidInfo` 指针数组，decode 路径分配数组和每个 `RPC_SID`。 |
| LSAPR_TRANSLATED_NAME_EX | struct | include/smb2/libsmb2-dcerpc-lsa.h:54 | translated name 条目包含 `Use`、`Name`、`DomainIndex`、`Flags`。 |
| LSAPR_TRANSLATED_NAMES_EX | struct | include/smb2/libsmb2-dcerpc-lsa.h:61 | `Entries` 控制 `Names` 数组，decode 路径分配 translated-name 数组。 |
| LSAPR_OBJECT_ATTRIBUTES | struct | include/smb2/libsmb2-dcerpc-lsa.h:93 | OpenPolicy2 helper 不读取输入对象字段，而编码固定空对象属性。 |
| LSAPR_TRUST_INFORMATION | struct | include/smb2/libsmb2-dcerpc-lsa.h:81 | referenced-domain 条目包含名称和 SID。 |
| LSAPR_REFERENCED_DOMAIN_LIST | struct | include/smb2/libsmb2-dcerpc-lsa.h:86 | `Entries` 控制 `Domains` 数组，`MaxEntries` 被序列化但头文件注释要求忽略。 |
| lsa_close_req | struct | include/smb2/libsmb2-dcerpc-lsa.h:102 | Close 请求只包含 `PolicyHandle`。 |
| lsa_close_rep | struct | include/smb2/libsmb2-dcerpc-lsa.h:106 | Close 响应包含 `status` 和 `PolicyHandle`。 |
| lsa_openpolicy2_req | struct | include/smb2/libsmb2-dcerpc-lsa.h:112 | OpenPolicy2 请求包含 `SystemName`、`ObjectAttributes`、`DesiredAccess`。 |
| lsa_openpolicy2_rep | struct | include/smb2/libsmb2-dcerpc-lsa.h:118 | OpenPolicy2 响应包含 `status` 和 `PolicyHandle`。 |
| lsa_lookupsids2_req | struct | include/smb2/libsmb2-dcerpc-lsa.h:124 | LookupSids2 请求包含 policy handle、SID buffer、translated names 和 lookup level。 |
| lsa_lookupsids2_rep | struct | include/smb2/libsmb2-dcerpc-lsa.h:131 | LookupSids2 响应包含 referenced domains、translated names、mapped count 和 status。 |

## ADDED Requirements

### Requirement: LSA_UUID defines the LSA transfer syntax UUID
系统 MUST define `LSA_UUID` as `0x12345778, 0x1234, 0xabcd, {0xef, 0x00, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab}` so the implementation can initialize the LSA DCERPC syntax identifier.

#### Scenario: LSA UUID initializes syntax identifier
- **GIVEN** the LSA DCERPC implementation is compiled
- **WHEN** `lsa_interface` is initialized
- **THEN** the syntax identifier uses the byte sequence from `LSA_UUID`

Trace: `lib/dcerpc-lsa.c:LSA_UUID`, `lib/dcerpc-lsa.c:lsa_interface`

### Requirement: lsa_interface exposes the LSA syntax identifier
系统 MUST provide `lsa_interface` as a `p_syntax_id_t` initialized with `LSA_UUID` and version fields `0, 0` for callers that bind to the LSA DCERPC interface.

#### Scenario: caller binds to LSA interface
- **GIVEN** a caller needs to connect a DCERPC context to the LSA endpoint
- **WHEN** the caller passes `lsa_interface` to the DCERPC connect path
- **THEN** the object supplies the LSA UUID with both version fields set to zero

Trace: `lib/dcerpc-lsa.c:lsa_interface`, `examples/smb2-lsa-lookupsids.c:261`

### Requirement: NT_SID_AUTHORITY defines NT SID authority bytes
系统 MUST define `NT_SID_AUTHORITY` as a six-byte array containing `{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x05 }`.

#### Scenario: caller constructs NT authority SID
- **GIVEN** a caller prepares an `RPC_SID.IdentifierAuthority` buffer
- **WHEN** the caller copies `NT_SID_AUTHORITY`
- **THEN** the available byte sequence is exactly six bytes ending with authority byte `0x05`

Trace: `lib/dcerpc-lsa.c:NT_SID_AUTHORITY`, `include/smb2/libsmb2-dcerpc-lsa.h:NT_SID_AUTHORITY`, `examples/smb2-lsa-lookupsids.c:148`

### Requirement: lsa_RPC_SID_coder encodes and decodes RPC SID values
系统 MUST process an `RPC_SID` by coding the sub-authority count as a 32/64-bit conformant count, coding revision, coding `SubAuthorityCount`, coding six identifier-authority bytes, allocating `SubAuthority` storage during decode, and coding each 32-bit sub-authority.

#### Scenario: RPC SID coder succeeds
- **GIVEN** a valid `RPC_SID`, DCERPC context, PDU, iovec, and offset pointer
- **WHEN** `lsa_RPC_SID_coder` runs and all primitive coders plus decode allocation succeed
- **THEN** the function returns `0` after processing the count, fixed authority bytes, and `SubAuthorityCount` sub-authority values

Trace: `lib/dcerpc-lsa.c:lsa_RPC_SID_coder`

#### Scenario: RPC SID coder fails on primitive or allocation error
- **GIVEN** `lsa_RPC_SID_coder` is processing an `RPC_SID`
- **WHEN** any nested coder returns an error or decode allocation for `SubAuthority` returns `NULL`
- **THEN** the function returns `-1`

Trace: `lib/dcerpc-lsa.c:lsa_RPC_SID_coder`

### Requirement: lsa_RPC_UNICODE_STRING_coder encodes and decodes RPC unicode strings
系统 MUST align the offset with `dcerpc_align_3264`, encode `Length` and `MaximumLength` as 16-bit values, and process the string buffer as a unique pointer through `dcerpc_utf16_coder`.

#### Scenario: unicode string coder encodes string length
- **GIVEN** `dcerpc_pdu_direction(pdu)` is `DCERPC_ENCODE` and `ptr` addresses a `char *`
- **WHEN** `lsa_RPC_UNICODE_STRING_coder` processes the value
- **THEN** `Length` is derived from `strlen(*(char **)ptr) * 2`, `MaximumLength` is derived from that length, and the UTF-16 buffer is coded as a unique pointer

Trace: `lib/dcerpc-lsa.c:lsa_RPC_UNICODE_STRING_coder`

#### Scenario: unicode string coder fails on nested coder error
- **GIVEN** `lsa_RPC_UNICODE_STRING_coder` is processing a string value
- **WHEN** a 16-bit field coder or `dcerpc_ptr_coder` fails
- **THEN** the function returns `-1`

Trace: `lib/dcerpc-lsa.c:lsa_RPC_UNICODE_STRING_coder`

### Requirement: lsa_Close_req_coder encodes Close requests
系统 MUST encode `struct lsa_close_req.PolicyHandle` as a reference pointer to `dcerpc_context_handle_coder` and return `-1` if that nested pointer coding fails.

#### Scenario: Close request coder processes policy handle
- **GIVEN** a valid `struct lsa_close_req` pointer
- **WHEN** `lsa_Close_req_coder` is invoked
- **THEN** the function codes `PolicyHandle` with pointer kind `PTR_REF` and returns `0` when the nested coder succeeds

Trace: `lib/dcerpc-lsa.c:lsa_Close_req_coder`

### Requirement: lsa_Close_rep_coder encodes and decodes Close responses
系统 MUST process `struct lsa_close_rep.PolicyHandle` as a reference context handle followed by the 32-bit `status` field, returning `-1` on either nested coder failure.

#### Scenario: Close response coder processes handle and status
- **GIVEN** a valid `struct lsa_close_rep` pointer
- **WHEN** `lsa_Close_rep_coder` is invoked and nested coders succeed
- **THEN** the function returns `0` after coding `PolicyHandle` and `status` in that order

Trace: `lib/dcerpc-lsa.c:lsa_Close_rep_coder`

### Requirement: lsa_OpenPolicy2_req_coder encodes OpenPolicy2 requests
系统 MUST encode `SystemName` as a unique UTF-16 zero-terminated pointer, encode object attributes as a reference pointer to the implementation's empty-object helper, and encode `DesiredAccess` as a 32-bit value.

#### Scenario: OpenPolicy2 request coder processes request fields
- **GIVEN** a valid `struct lsa_openpolicy2_req` pointer
- **WHEN** `lsa_OpenPolicy2_req_coder` is invoked and nested coders succeed
- **THEN** the function returns `0` after coding `SystemName`, `ObjectAttributes`, and `DesiredAccess` in order

Trace: `lib/dcerpc-lsa.c:lsa_OpenPolicy2_req_coder`, `lib/dcerpc-lsa.c:lsa_ObjectAttributes_coder`

#### Scenario: OpenPolicy2 object attributes are encoded as empty attributes
- **GIVEN** `lsa_OpenPolicy2_req_coder` delegates to `lsa_ObjectAttributes_coder`
- **WHEN** object attributes are serialized
- **THEN** the helper emits length `24`, null pointer-sized fields, zero attributes, and no caller-provided object-name or security fields

Trace: `lib/dcerpc-lsa.c:lsa_ObjectAttributes_coder`

### Requirement: lsa_OpenPolicy2_rep_coder encodes and decodes OpenPolicy2 responses
系统 MUST process `struct lsa_openpolicy2_rep.PolicyHandle` as a reference context handle followed by the 32-bit `status` field, returning `-1` on either nested coder failure.

#### Scenario: OpenPolicy2 response coder processes handle and status
- **GIVEN** a valid `struct lsa_openpolicy2_rep` pointer
- **WHEN** `lsa_OpenPolicy2_rep_coder` is invoked and nested coders succeed
- **THEN** the function returns `0` after coding `PolicyHandle` and `status` in order

Trace: `lib/dcerpc-lsa.c:lsa_OpenPolicy2_rep_coder`

### Requirement: lsa_LookupSids2_req_coder encodes LookupSids2 requests
系统 MUST encode `PolicyHandle`, `SidEnumBuffer`, `TranslatedNames`, and `LookupLevel`, then write fixed 32-bit values `0`, `0`, and `2` for LookupOptions-related fields and client revision.

#### Scenario: LookupSids2 request coder processes request fields
- **GIVEN** a valid `struct lsa_lookupsids2_req` pointer
- **WHEN** `lsa_LookupSids2_req_coder` is invoked and nested coders succeed
- **THEN** the function returns `0` after coding the policy handle, SID enum buffer, translated names, lookup level, two zero values, and revision value `2`

Trace: `lib/dcerpc-lsa.c:lsa_LookupSids2_req_coder`, `lib/dcerpc-lsa.c:lsa_SID_ENUM_BUFFER_coder`, `lib/dcerpc-lsa.c:lsa_TRANSLATED_NAMES_EX_coder`

#### Scenario: LookupSids2 request coder fails on nested coder error
- **GIVEN** `lsa_LookupSids2_req_coder` is processing a request
- **WHEN** any pointer coder or 32-bit field coder fails
- **THEN** the function returns `-1`

Trace: `lib/dcerpc-lsa.c:lsa_LookupSids2_req_coder`

### Requirement: lsa_LookupSids2_rep_coder encodes and decodes LookupSids2 responses
系统 MUST process `ReferencedDomains` as a unique referenced-domain list pointer, `TranslatedNames` as a reference translated-names pointer, `MappedCount` as a 32-bit value, and `status` as a final 32-bit value.

#### Scenario: LookupSids2 response coder processes response fields
- **GIVEN** a valid `struct lsa_lookupsids2_rep` pointer
- **WHEN** `lsa_LookupSids2_rep_coder` is invoked and nested coders succeed
- **THEN** the function returns `0` after coding referenced domains, translated names, mapped count, and status in order

Trace: `lib/dcerpc-lsa.c:lsa_LookupSids2_rep_coder`, `lib/dcerpc-lsa.c:lsa_REFERENCED_DOMAIN_LIST_coder`, `lib/dcerpc-lsa.c:lsa_TRANSLATED_NAMES_EX_coder`

#### Scenario: LookupSids2 response decode allocates nested arrays
- **GIVEN** a LookupSids2 response is being decoded
- **WHEN** referenced domains, translated names, or SID arrays contain nonzero counts
- **THEN** the implementation allocates payload-owned arrays through `smb2_alloc_data` before coding each nested element

Trace: `lib/dcerpc-lsa.c:RDL_DOMAINS_array_coder`, `lib/dcerpc-lsa.c:TN_array_coder`, `lib/dcerpc-lsa.c:lsa_PRPC_SID_array_coder`

## Open Questions

| ID | Question | Related Interface | Reason |
| --- | --- | --- | --- |
| Q-001 | `lsa_RPC_UNICODE_STRING_coder` 在 decode 路径中本地变量 `len` 和 `maxlen` 传入 coder 前没有显式初始化，这是否依赖 `dcerpc_uint16_coder` 在 decode 时覆盖输入值？ | lsa_RPC_UNICODE_STRING_coder | 源码显示 encode 路径初始化长度，decode 路径未初始化；当前没有测试或 helper 契约证据确认该调用约定。 |
| Q-002 | `lsa_RPC_SID_coder` 和内部数组 coder 是否需要对 `SubAuthorityCount`、`Entries` 或 decode 分配大小执行 20480 等协议上限检查？ | lsa_RPC_SID_coder | 注释记录部分 IDL range，但实现按输入 count 分配，仓库内未发现边界测试。 |
| Q-003 | GitNexus impact 对 `lsa_RPC_SID_coder`、`lsa_LookupSids2_req_coder` 等符号因头文件声明和实现同名而返回 ambiguous，真实上游调用范围是否仅限当前文件和示例？ | file-level | `context` 可定位实现符号，但当前 CLI impact 选项无法按 UID 或文件消歧。 |
