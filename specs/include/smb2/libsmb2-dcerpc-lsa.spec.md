# include/smb2/libsmb2-dcerpc-lsa.h Specification

## Source Context

- Source: `include/smb2/libsmb2-dcerpc-lsa.h`
- Related Headers: `include/smb2/libsmb2-dcerpc.h`, `include/smb2/libsmb2-raw.h`, `include/smb2/libsmb2.h`, `include/smb2/smb2.h`
- Related Tests: `none`
- Related Dependencies: GitNexus context resolves the public declarations to header symbols with no indexed incoming callers; implementation symbols in `lib/dcerpc-lsa.c` call shared NDR helpers such as `dcerpc_ptr_coder`, `dcerpc_uint32_coder`, `dcerpc_uint3264_coder`, `dcerpc_uint8_coder`, `dcerpc_pdu_direction`, `smb2_alloc_data`, `dcerpc_get_smb2_context`, and `dcerpc_get_pdu_payload`. Impact for key implementation symbols `lsa_RPC_SID_coder`, `lsa_OpenPolicy2_req_coder`, and `lsa_LookupSids2_req_coder` is LOW with no indexed upstream callers.
- Build/Compile Context: Public C header guarded by `_LIBSMB2_DCERPC_LSA_H_` and wrapped in `extern "C"` for C++ consumers; included by `lib/dcerpc-lsa.c` and used by the example `examples/smb2-lsa-lookupsids.c`. The header depends on DCERPC/SMB2 declarations for `struct dcerpc_context`, `struct dcerpc_pdu`, `struct smb2_iovec`, and `struct ndr_context_handle` but does not include those headers itself.

## Interface Summary

| Interface | Kind | Signature | Decision | Reason |
| --- | --- | --- | --- | --- |
| LSA_CLOSE | macro | #define LSA_CLOSE          0x00 | Include | 公开 LSA Close 操作号，调用方用它构造 DCERPC 请求。 |
| LSA_OPENPOLICY2 | macro | #define LSA_OPENPOLICY2    0x2c | Include | 公开 LsarOpenPolicy2 操作号，调用方用它构造 DCERPC 请求。 |
| LSA_LOOKUPSIDS2 | macro | #define LSA_LOOKUPSIDS2    0x39 | Include | 公开 LsarLookupSids2 操作号，调用方用它构造 DCERPC 请求。 |
| POLICY_VIEW_LOCAL_INFORMATION | macro | #define POLICY_VIEW_LOCAL_INFORMATION    0x00000001 | Include | 公开 LSA policy access mask 位，供 `DesiredAccess` 组合使用。 |
| POLICY_VIEW_AUDIT_INFORMATION | macro | #define POLICY_VIEW_AUDIT_INFORMATION    0x00000002 | Include | 公开 LSA policy access mask 位，供 `DesiredAccess` 组合使用。 |
| POLICY_GET_PRIVATE_INFORMATION | macro | #define POLICY_GET_PRIVATE_INFORMATION   0x00000004 | Include | 公开 LSA policy access mask 位，供 `DesiredAccess` 组合使用。 |
| POLICY_TRUST_ADMIN | macro | #define POLICY_TRUST_ADMIN               0x00000008 | Include | 公开 LSA policy access mask 位，供 `DesiredAccess` 组合使用。 |
| POLICY_CREATE_ACCOUNT | macro | #define POLICY_CREATE_ACCOUNT            0x00000010 | Include | 公开 LSA policy access mask 位，供 `DesiredAccess` 组合使用。 |
| POLICY_CREATE_SECRET | macro | #define POLICY_CREATE_SECRET             0x00000020 | Include | 公开 LSA policy access mask 位，供 `DesiredAccess` 组合使用。 |
| POLICY_CREATE_PRIVILEGE | macro | #define POLICY_CREATE_PRIVILEGE          0x00000040 | Include | 公开 LSA policy access mask 位，供 `DesiredAccess` 组合使用。 |
| POLICY_SET_DEFAULT_QUOTA_LIMITS | macro | #define POLICY_SET_DEFAULT_QUOTA_LIMITS  0x00000080 | Include | 公开 LSA policy access mask 位，供 `DesiredAccess` 组合使用。 |
| POLICY_SET_AUDIT_REQUIREMENTS | macro | #define POLICY_SET_AUDIT_REQUIREMENTS    0x00000100 | Include | 公开 LSA policy access mask 位，供 `DesiredAccess` 组合使用。 |
| POLICY_AUDIT_LOG_ADMIN | macro | #define POLICY_AUDIT_LOG_ADMIN           0x00000200 | Include | 公开 LSA policy access mask 位，供 `DesiredAccess` 组合使用。 |
| POLICY_SERVER_ADMIN | macro | #define POLICY_SERVER_ADMIN              0x00000400 | Include | 公开 LSA policy access mask 位，供 `DesiredAccess` 组合使用。 |
| POLICY_LOOKUP_NAMES | macro | #define POLICY_LOOKUP_NAMES              0x00000800 | Include | 公开 LSA policy access mask 位，示例请求使用它作为 `DesiredAccess`。 |
| POLICY_NOTIFICATION | macro | #define POLICY_NOTIFICATION              0x00001000 | Include | 公开 LSA policy access mask 位，供 `DesiredAccess` 组合使用。 |
| NT_SID_AUTHORITY | object | extern unsigned char NT_SID_AUTHORITY[6]; | Include | 公开 NT SID authority 常量数组声明，调用方可复制到 `RPC_SID.IdentifierAuthority`。 |
| RPC_SID | type | typedef struct RPC_SID { uint8_t Revision; uint8_t SubAuthorityCount; uint8_t IdentifierAuthority[6]; uint32_t *SubAuthority; } RPC_SID, *PRPC_SID; | Include | 公开 SID 数据模型，被 `lsa_RPC_SID_coder` 和 LookupSids2 请求/响应结构使用。 |
| LSAPR_TRANSLATED_NAME_EX | type | typedef struct _LSAPR_TRANSLATED_NAME_EX { uint32_t Use; char *Name; uint32_t DomainIndex; uint32_t Flags; } LSAPR_TRANSLATED_NAME_EX, *PLSAPR_TRANSLATED_NAME_EX; | Include | 公开单个 SID 翻译结果模型，被翻译名称数组使用。 |
| LSAPR_TRANSLATED_NAMES_EX | type | typedef struct _LSAPR_TRANSLATED_NAMES_EX { uint32_t Entries; LSAPR_TRANSLATED_NAME_EX  *Names; } LSAPR_TRANSLATED_NAMES_EX, *PLSAPR_TRANSLATED_NAMES_EX; | Include | 公开翻译名称数组模型，被 LookupSids2 请求和响应复用。 |
| LSAPR_SID_ENUM_BUFFER | type | typedef struct _SID_ENUM_BUFFER { uint32_t Entries; PRPC_SID *SidInfo; } LSAPR_SID_ENUM_BUFFER, *PLSAPR_SID_ENUM_BUFFER; | Include | 公开 SID 输入数组模型，被 LookupSids2 请求使用。 |
| LSAP_LOOKUP_LEVEL | type | typedef enum _LSAP_LOOKUP_LEVEL { LsapLookupWksta = 1, LsapLookupPDC, LsapLookupTDL, LsapLookupGC, LsapLookupXForestReferral, LsapLookupXForestResolve, LsapLookupRODCReferralToFullDC } LSAP_LOOKUP_LEVEL, *PLSAP_LOOKUP_LEVEL; | Include | 公开 LookupSids2 查找级别枚举，影响请求编码值。 |
| LSAPR_TRUST_INFORMATION | type | typedef struct _LSAPR_TRUST_INFORMATION { char *Name; RPC_SID Sid; } LSAPR_TRUST_INFORMATION, *PLSAPR_TRUST_INFORMATION; | Include | 公开引用域条目模型，被响应域列表使用。 |
| LSAPR_REFERENCED_DOMAIN_LIST | type | typedef struct _LSAPR_REFERENCED_DOMAIN_LIST { uint32_t Entries; LSAPR_TRUST_INFORMATION *Domains; uint32_t MaxEntries; } LSAPR_REFERENCED_DOMAIN_LIST, *PLSAPR_REFERENCED_DOMAIN_LIST; | Include | 公开引用域列表模型，源码注释声明 `MaxEntries` must be ignored。 |
| LSAPR_OBJECT_ATTRIBUTES | type | typedef struct _LSAPR_OBJECT_ATTRIBUTES { uint32_t Length; unsigned char *RootDirectory; void *ObjectName; uint32_t Attributes; void *SecurityDescriptor; void *SecurityQualityOfService; } LSAPR_OBJECT_ATTRIBUTES, *PLSAPR_OBJECT_ATTRIBUTES; | Include | 公开 OpenPolicy2 对象属性模型，源码注释声明 `RootDirectory` MUST be zero and everything else is ignored。 |
| lsa_close_req | type | struct lsa_close_req { struct ndr_context_handle PolicyHandle; }; | Include | 公开 Close 请求载荷模型，被 Close 请求 coder 使用。 |
| lsa_close_rep | type | struct lsa_close_rep { uint32_t status; struct ndr_context_handle PolicyHandle; }; | Include | 公开 Close 响应载荷模型，被 Close 响应 coder 使用。 |
| lsa_openpolicy2_req | type | struct lsa_openpolicy2_req { char *SystemName; LSAPR_OBJECT_ATTRIBUTES ObjectAttributes; uint32_t DesiredAccess; }; | Include | 公开 OpenPolicy2 请求载荷模型，被 OpenPolicy2 请求 coder 使用。 |
| lsa_openpolicy2_rep | type | struct lsa_openpolicy2_rep { uint32_t status; struct ndr_context_handle PolicyHandle; }; | Include | 公开 OpenPolicy2 响应载荷模型，被 OpenPolicy2 响应 coder 使用。 |
| lsa_lookupsids2_req | type | struct lsa_lookupsids2_req { struct ndr_context_handle PolicyHandle; LSAPR_SID_ENUM_BUFFER SidEnumBuffer; LSAPR_TRANSLATED_NAMES_EX TranslatedNames; LSAP_LOOKUP_LEVEL LookupLevel; }; | Include | 公开 LookupSids2 请求载荷模型，被 LookupSids2 请求 coder 使用。 |
| lsa_lookupsids2_rep | type | struct lsa_lookupsids2_rep { uint32_t status; LSAPR_REFERENCED_DOMAIN_LIST ReferencedDomains; LSAPR_TRANSLATED_NAMES_EX TranslatedNames; uint32_t MappedCount; }; | Include | 公开 LookupSids2 响应载荷模型，被 LookupSids2 响应 coder 使用。 |
| lsa_Close_rep_coder | function | int lsa_Close_rep_coder(struct dcerpc_context *dce, struct dcerpc_pdu *pdu, struct smb2_iovec *iov, int *offset, void *ptr); | Include | 公开 Close 响应 NDR coder，声明与 `lib/dcerpc-lsa.c` 实现匹配。 |
| lsa_Close_req_coder | function | int lsa_Close_req_coder(struct dcerpc_context *dce, struct dcerpc_pdu *pdu, struct smb2_iovec *iov, int *offset, void *ptr); | Include | 公开 Close 请求 NDR coder，声明与 `lib/dcerpc-lsa.c` 实现匹配。 |
| lsa_LookupSids2_rep_coder | function | int lsa_LookupSids2_rep_coder(struct dcerpc_context *dce, struct dcerpc_pdu *pdu, struct smb2_iovec *iov, int *offset, void *ptr); | Include | 公开 LookupSids2 响应 NDR coder，声明与 `lib/dcerpc-lsa.c` 实现匹配。 |
| lsa_LookupSids2_req_coder | function | int lsa_LookupSids2_req_coder(struct dcerpc_context *dce, struct dcerpc_pdu *pdu, struct smb2_iovec *iov, int *offset, void *ptr); | Include | 公开 LookupSids2 请求 NDR coder，声明与 `lib/dcerpc-lsa.c` 实现匹配。 |
| lsa_OpenPolicy2_rep_coder | function | int lsa_OpenPolicy2_rep_coder(struct dcerpc_context *dce, struct dcerpc_pdu *pdu, struct smb2_iovec *iov, int *offset, void *ptr); | Include | 公开 OpenPolicy2 响应 NDR coder，声明与 `lib/dcerpc-lsa.c` 实现匹配。 |
| lsa_OpenPolicy2_req_coder | function | int lsa_OpenPolicy2_req_coder(struct dcerpc_context *dce, struct dcerpc_pdu *pdu, struct smb2_iovec *iov, int *offset, void *ptr); | Include | 公开 OpenPolicy2 请求 NDR coder，声明与 `lib/dcerpc-lsa.c` 实现匹配。 |
| lsa_RPC_SID_coder | function | int lsa_RPC_SID_coder(struct dcerpc_context *dce, struct dcerpc_pdu *pdu, struct smb2_iovec *iov, int *offset, void *ptr); | Include | 公开 RPC SID NDR coder，声明与 `lib/dcerpc-lsa.c` 实现匹配，并被内部数组/域信息 coder 复用。 |

## Data Model Summary

| Type/Macro | Kind | Definition | Notes |
| --- | --- | --- | --- |
| LSA_CLOSE | macro | include/smb2/libsmb2-dcerpc-lsa.h:26 | LSA Close 操作号 `0x00`。 |
| LSA_OPENPOLICY2 | macro | include/smb2/libsmb2-dcerpc-lsa.h:27 | LSA OpenPolicy2 操作号 `0x2c`。 |
| LSA_LOOKUPSIDS2 | macro | include/smb2/libsmb2-dcerpc-lsa.h:28 | LSA LookupSids2 操作号 `0x39`。 |
| POLICY_VIEW_LOCAL_INFORMATION | macro | include/smb2/libsmb2-dcerpc-lsa.h:31 | LSA policy access mask 位 `0x00000001`。 |
| POLICY_VIEW_AUDIT_INFORMATION | macro | include/smb2/libsmb2-dcerpc-lsa.h:32 | LSA policy access mask 位 `0x00000002`。 |
| POLICY_GET_PRIVATE_INFORMATION | macro | include/smb2/libsmb2-dcerpc-lsa.h:33 | LSA policy access mask 位 `0x00000004`。 |
| POLICY_TRUST_ADMIN | macro | include/smb2/libsmb2-dcerpc-lsa.h:34 | LSA policy access mask 位 `0x00000008`。 |
| POLICY_CREATE_ACCOUNT | macro | include/smb2/libsmb2-dcerpc-lsa.h:35 | LSA policy access mask 位 `0x00000010`。 |
| POLICY_CREATE_SECRET | macro | include/smb2/libsmb2-dcerpc-lsa.h:36 | LSA policy access mask 位 `0x00000020`。 |
| POLICY_CREATE_PRIVILEGE | macro | include/smb2/libsmb2-dcerpc-lsa.h:37 | LSA policy access mask 位 `0x00000040`。 |
| POLICY_SET_DEFAULT_QUOTA_LIMITS | macro | include/smb2/libsmb2-dcerpc-lsa.h:38 | LSA policy access mask 位 `0x00000080`。 |
| POLICY_SET_AUDIT_REQUIREMENTS | macro | include/smb2/libsmb2-dcerpc-lsa.h:39 | LSA policy access mask 位 `0x00000100`。 |
| POLICY_AUDIT_LOG_ADMIN | macro | include/smb2/libsmb2-dcerpc-lsa.h:40 | LSA policy access mask 位 `0x00000200`。 |
| POLICY_SERVER_ADMIN | macro | include/smb2/libsmb2-dcerpc-lsa.h:41 | LSA policy access mask 位 `0x00000400`。 |
| POLICY_LOOKUP_NAMES | macro | include/smb2/libsmb2-dcerpc-lsa.h:42 | LSA policy access mask 位 `0x00000800`。 |
| POLICY_NOTIFICATION | macro | include/smb2/libsmb2-dcerpc-lsa.h:43 | LSA policy access mask 位 `0x00001000`。 |
| NT_SID_AUTHORITY | macro | include/smb2/libsmb2-dcerpc-lsa.h:45 | 外部声明为 6 字节数组，`lib/dcerpc-lsa.c` 定义值为 `{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x05 }`。 |
| RPC_SID | struct | include/smb2/libsmb2-dcerpc-lsa.h:47 | SID revision、sub-authority count、6 字节 authority 和动态 sub-authority 数组。 |
| LSAPR_TRANSLATED_NAME_EX | struct | include/smb2/libsmb2-dcerpc-lsa.h:54 | 单个翻译名称记录，包含 use、name、domain index 和 flags。 |
| LSAPR_TRANSLATED_NAMES_EX | struct | include/smb2/libsmb2-dcerpc-lsa.h:61 | 翻译名称数组，`Entries` 控制 `Names` 数组。 |
| LSAPR_SID_ENUM_BUFFER | struct | include/smb2/libsmb2-dcerpc-lsa.h:66 | SID 指针数组，`Entries` 控制 `SidInfo` 数组。 |
| LSAP_LOOKUP_LEVEL | enum | include/smb2/libsmb2-dcerpc-lsa.h:71 | 查找级别枚举从 `LsapLookupWksta = 1` 顺序递增到 `LsapLookupRODCReferralToFullDC`。 |
| LSAPR_TRUST_INFORMATION | struct | include/smb2/libsmb2-dcerpc-lsa.h:81 | 引用域名称与 SID。 |
| LSAPR_REFERENCED_DOMAIN_LIST | struct | include/smb2/libsmb2-dcerpc-lsa.h:86 | 引用域数组，`MaxEntries` 注释为 must be ignored。 |
| LSAPR_OBJECT_ATTRIBUTES | struct | include/smb2/libsmb2-dcerpc-lsa.h:93 | OpenPolicy2 对象属性，注释声明 `RootDirectory` MUST be zero 且其他字段 ignored。 |
| lsa_close_req | struct | include/smb2/libsmb2-dcerpc-lsa.h:102 | Close 请求载荷。 |
| lsa_close_rep | struct | include/smb2/libsmb2-dcerpc-lsa.h:106 | Close 响应载荷。 |
| lsa_openpolicy2_req | struct | include/smb2/libsmb2-dcerpc-lsa.h:112 | OpenPolicy2 请求载荷。 |
| lsa_openpolicy2_rep | struct | include/smb2/libsmb2-dcerpc-lsa.h:118 | OpenPolicy2 响应载荷。 |
| lsa_lookupsids2_req | struct | include/smb2/libsmb2-dcerpc-lsa.h:124 | LookupSids2 请求载荷。 |
| lsa_lookupsids2_rep | struct | include/smb2/libsmb2-dcerpc-lsa.h:131 | LookupSids2 响应载荷。 |

## ADDED Requirements

### Requirement: LSA_CLOSE exposes the Close operation number
系统 MUST expose `LSA_CLOSE` as the numeric DCERPC operation value `0x00` for LSA Close calls.

#### Scenario: Close operation constant is available
- **GIVEN** a caller includes `include/smb2/libsmb2-dcerpc-lsa.h`
- **WHEN** the caller builds an LSA Close DCERPC request
- **THEN** `LSA_CLOSE` expands to `0x00`

Trace: `include/smb2/libsmb2-dcerpc-lsa.h:LSA_CLOSE`, `lib/dcerpc-lsa.c:lsa_Close_req_coder`

### Requirement: LSA_OPENPOLICY2 exposes the OpenPolicy2 operation number
系统 MUST expose `LSA_OPENPOLICY2` as the numeric DCERPC operation value `0x2c` for LsarOpenPolicy2 calls.

#### Scenario: OpenPolicy2 operation constant is available
- **GIVEN** a caller includes `include/smb2/libsmb2-dcerpc-lsa.h`
- **WHEN** the caller builds an LSA OpenPolicy2 DCERPC request
- **THEN** `LSA_OPENPOLICY2` expands to `0x2c`

Trace: `include/smb2/libsmb2-dcerpc-lsa.h:LSA_OPENPOLICY2`, `lib/dcerpc-lsa.c:lsa_OpenPolicy2_req_coder`

### Requirement: LSA_LOOKUPSIDS2 exposes the LookupSids2 operation number
系统 MUST expose `LSA_LOOKUPSIDS2` as the numeric DCERPC operation value `0x39` for LsarLookupSids2 calls.

#### Scenario: LookupSids2 operation constant is available
- **GIVEN** a caller includes `include/smb2/libsmb2-dcerpc-lsa.h`
- **WHEN** the caller builds an LSA LookupSids2 DCERPC request
- **THEN** `LSA_LOOKUPSIDS2` expands to `0x39`

Trace: `include/smb2/libsmb2-dcerpc-lsa.h:LSA_LOOKUPSIDS2`, `lib/dcerpc-lsa.c:lsa_LookupSids2_req_coder`

### Requirement: POLICY_VIEW_LOCAL_INFORMATION exposes its policy access bit
系统 MUST expose `POLICY_VIEW_LOCAL_INFORMATION` as the access mask value `0x00000001`.

#### Scenario: policy access bit is available
- **GIVEN** a caller includes `include/smb2/libsmb2-dcerpc-lsa.h`
- **WHEN** the caller composes an OpenPolicy2 `DesiredAccess` mask
- **THEN** `POLICY_VIEW_LOCAL_INFORMATION` expands to `0x00000001`

Trace: `include/smb2/libsmb2-dcerpc-lsa.h:POLICY_VIEW_LOCAL_INFORMATION`

### Requirement: POLICY_VIEW_AUDIT_INFORMATION exposes its policy access bit
系统 MUST expose `POLICY_VIEW_AUDIT_INFORMATION` as the access mask value `0x00000002`.

#### Scenario: policy access bit is available
- **GIVEN** a caller includes `include/smb2/libsmb2-dcerpc-lsa.h`
- **WHEN** the caller composes an OpenPolicy2 `DesiredAccess` mask
- **THEN** `POLICY_VIEW_AUDIT_INFORMATION` expands to `0x00000002`

Trace: `include/smb2/libsmb2-dcerpc-lsa.h:POLICY_VIEW_AUDIT_INFORMATION`

### Requirement: POLICY_GET_PRIVATE_INFORMATION exposes its policy access bit
系统 MUST expose `POLICY_GET_PRIVATE_INFORMATION` as the access mask value `0x00000004`.

#### Scenario: policy access bit is available
- **GIVEN** a caller includes `include/smb2/libsmb2-dcerpc-lsa.h`
- **WHEN** the caller composes an OpenPolicy2 `DesiredAccess` mask
- **THEN** `POLICY_GET_PRIVATE_INFORMATION` expands to `0x00000004`

Trace: `include/smb2/libsmb2-dcerpc-lsa.h:POLICY_GET_PRIVATE_INFORMATION`

### Requirement: POLICY_TRUST_ADMIN exposes its policy access bit
系统 MUST expose `POLICY_TRUST_ADMIN` as the access mask value `0x00000008`.

#### Scenario: policy access bit is available
- **GIVEN** a caller includes `include/smb2/libsmb2-dcerpc-lsa.h`
- **WHEN** the caller composes an OpenPolicy2 `DesiredAccess` mask
- **THEN** `POLICY_TRUST_ADMIN` expands to `0x00000008`

Trace: `include/smb2/libsmb2-dcerpc-lsa.h:POLICY_TRUST_ADMIN`

### Requirement: POLICY_CREATE_ACCOUNT exposes its policy access bit
系统 MUST expose `POLICY_CREATE_ACCOUNT` as the access mask value `0x00000010`.

#### Scenario: policy access bit is available
- **GIVEN** a caller includes `include/smb2/libsmb2-dcerpc-lsa.h`
- **WHEN** the caller composes an OpenPolicy2 `DesiredAccess` mask
- **THEN** `POLICY_CREATE_ACCOUNT` expands to `0x00000010`

Trace: `include/smb2/libsmb2-dcerpc-lsa.h:POLICY_CREATE_ACCOUNT`

### Requirement: POLICY_CREATE_SECRET exposes its policy access bit
系统 MUST expose `POLICY_CREATE_SECRET` as the access mask value `0x00000020`.

#### Scenario: policy access bit is available
- **GIVEN** a caller includes `include/smb2/libsmb2-dcerpc-lsa.h`
- **WHEN** the caller composes an OpenPolicy2 `DesiredAccess` mask
- **THEN** `POLICY_CREATE_SECRET` expands to `0x00000020`

Trace: `include/smb2/libsmb2-dcerpc-lsa.h:POLICY_CREATE_SECRET`

### Requirement: POLICY_CREATE_PRIVILEGE exposes its policy access bit
系统 MUST expose `POLICY_CREATE_PRIVILEGE` as the access mask value `0x00000040`.

#### Scenario: policy access bit is available
- **GIVEN** a caller includes `include/smb2/libsmb2-dcerpc-lsa.h`
- **WHEN** the caller composes an OpenPolicy2 `DesiredAccess` mask
- **THEN** `POLICY_CREATE_PRIVILEGE` expands to `0x00000040`

Trace: `include/smb2/libsmb2-dcerpc-lsa.h:POLICY_CREATE_PRIVILEGE`

### Requirement: POLICY_SET_DEFAULT_QUOTA_LIMITS exposes its policy access bit
系统 MUST expose `POLICY_SET_DEFAULT_QUOTA_LIMITS` as the access mask value `0x00000080`.

#### Scenario: policy access bit is available
- **GIVEN** a caller includes `include/smb2/libsmb2-dcerpc-lsa.h`
- **WHEN** the caller composes an OpenPolicy2 `DesiredAccess` mask
- **THEN** `POLICY_SET_DEFAULT_QUOTA_LIMITS` expands to `0x00000080`

Trace: `include/smb2/libsmb2-dcerpc-lsa.h:POLICY_SET_DEFAULT_QUOTA_LIMITS`

### Requirement: POLICY_SET_AUDIT_REQUIREMENTS exposes its policy access bit
系统 MUST expose `POLICY_SET_AUDIT_REQUIREMENTS` as the access mask value `0x00000100`.

#### Scenario: policy access bit is available
- **GIVEN** a caller includes `include/smb2/libsmb2-dcerpc-lsa.h`
- **WHEN** the caller composes an OpenPolicy2 `DesiredAccess` mask
- **THEN** `POLICY_SET_AUDIT_REQUIREMENTS` expands to `0x00000100`

Trace: `include/smb2/libsmb2-dcerpc-lsa.h:POLICY_SET_AUDIT_REQUIREMENTS`

### Requirement: POLICY_AUDIT_LOG_ADMIN exposes its policy access bit
系统 MUST expose `POLICY_AUDIT_LOG_ADMIN` as the access mask value `0x00000200`.

#### Scenario: policy access bit is available
- **GIVEN** a caller includes `include/smb2/libsmb2-dcerpc-lsa.h`
- **WHEN** the caller composes an OpenPolicy2 `DesiredAccess` mask
- **THEN** `POLICY_AUDIT_LOG_ADMIN` expands to `0x00000200`

Trace: `include/smb2/libsmb2-dcerpc-lsa.h:POLICY_AUDIT_LOG_ADMIN`

### Requirement: POLICY_SERVER_ADMIN exposes its policy access bit
系统 MUST expose `POLICY_SERVER_ADMIN` as the access mask value `0x00000400`.

#### Scenario: policy access bit is available
- **GIVEN** a caller includes `include/smb2/libsmb2-dcerpc-lsa.h`
- **WHEN** the caller composes an OpenPolicy2 `DesiredAccess` mask
- **THEN** `POLICY_SERVER_ADMIN` expands to `0x00000400`

Trace: `include/smb2/libsmb2-dcerpc-lsa.h:POLICY_SERVER_ADMIN`

### Requirement: POLICY_LOOKUP_NAMES exposes its policy access bit
系统 MUST expose `POLICY_LOOKUP_NAMES` as the access mask value `0x00000800`.

#### Scenario: policy access bit is available
- **GIVEN** a caller includes `include/smb2/libsmb2-dcerpc-lsa.h`
- **WHEN** the caller composes an OpenPolicy2 `DesiredAccess` mask
- **THEN** `POLICY_LOOKUP_NAMES` expands to `0x00000800`

Trace: `include/smb2/libsmb2-dcerpc-lsa.h:POLICY_LOOKUP_NAMES`, `examples/smb2-lsa-lookupsids.c:204`

### Requirement: POLICY_NOTIFICATION exposes its policy access bit
系统 MUST expose `POLICY_NOTIFICATION` as the access mask value `0x00001000`.

#### Scenario: policy access bit is available
- **GIVEN** a caller includes `include/smb2/libsmb2-dcerpc-lsa.h`
- **WHEN** the caller composes an OpenPolicy2 `DesiredAccess` mask
- **THEN** `POLICY_NOTIFICATION` expands to `0x00001000`

Trace: `include/smb2/libsmb2-dcerpc-lsa.h:POLICY_NOTIFICATION`

### Requirement: NT_SID_AUTHORITY exposes the NT authority bytes
系统 MUST declare `NT_SID_AUTHORITY` as a six-byte external array, and the library definition SHALL provide the NT authority byte sequence `{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x05 }`.

#### Scenario: caller copies NT SID authority
- **GIVEN** a caller constructs an `RPC_SID`
- **WHEN** the caller copies `NT_SID_AUTHORITY` into `RPC_SID.IdentifierAuthority`
- **THEN** the available authority source is exactly six bytes and the implementation definition contains the NT authority value ending in `0x05`

Trace: `include/smb2/libsmb2-dcerpc-lsa.h:NT_SID_AUTHORITY`, `lib/dcerpc-lsa.c:NT_SID_AUTHORITY`, `examples/smb2-lsa-lookupsids.c:148`

### Requirement: RPC_SID defines the public SID layout
系统 MUST define `RPC_SID` with `Revision`, `SubAuthorityCount`, six `IdentifierAuthority` bytes, and a `uint32_t *SubAuthority` array pointer used by the SID coder.

#### Scenario: SID structure carries variable sub-authorities
- **GIVEN** a caller prepares an `RPC_SID`
- **WHEN** the caller sets `SubAuthorityCount` and points `SubAuthority` at `uint32_t` values
- **THEN** the public layout provides the count and pointer fields consumed by `lsa_RPC_SID_coder`

Trace: `include/smb2/libsmb2-dcerpc-lsa.h:RPC_SID`, `lib/dcerpc-lsa.c:lsa_RPC_SID_coder`

### Requirement: LSAPR_TRANSLATED_NAME_EX defines one translated name record
系统 MUST define `LSAPR_TRANSLATED_NAME_EX` with `Use`, `Name`, `DomainIndex`, and `Flags` fields for one translated SID/name result.

#### Scenario: translated name record is addressable
- **GIVEN** LookupSids2 response decoding populates translated names
- **WHEN** an entry in `LSAPR_TRANSLATED_NAMES_EX.Names` is accessed
- **THEN** the entry exposes use, name, domain index, and flags fields

Trace: `include/smb2/libsmb2-dcerpc-lsa.h:LSAPR_TRANSLATED_NAME_EX`, `lib/dcerpc-lsa.c:lsa_TRANSLATED_NAME_EX_coder`

### Requirement: LSAPR_TRANSLATED_NAMES_EX defines the translated-name array
系统 MUST define `LSAPR_TRANSLATED_NAMES_EX` with an `Entries` count and `Names` pointer so LookupSids2 request and response coders can process translated-name arrays.

#### Scenario: translated names array is encoded or decoded
- **GIVEN** a LookupSids2 request or response contains translated-name state
- **WHEN** the coder processes `LSAPR_TRANSLATED_NAMES_EX`
- **THEN** `Entries` controls the number of `LSAPR_TRANSLATED_NAME_EX` elements referenced by `Names`

Trace: `include/smb2/libsmb2-dcerpc-lsa.h:LSAPR_TRANSLATED_NAMES_EX`, `lib/dcerpc-lsa.c:lsa_TRANSLATED_NAMES_EX_coder`

### Requirement: LSAPR_SID_ENUM_BUFFER defines the SID input array
系统 MUST define `LSAPR_SID_ENUM_BUFFER` with an `Entries` count and `PRPC_SID *SidInfo` pointer for LookupSids2 SID inputs.

#### Scenario: SID enum buffer carries multiple SIDs
- **GIVEN** a caller prepares a LookupSids2 request for one or more SIDs
- **WHEN** `lsa_LookupSids2_req_coder` processes the request
- **THEN** `Entries` controls how many `PRPC_SID` entries are read through `SidInfo`

Trace: `include/smb2/libsmb2-dcerpc-lsa.h:LSAPR_SID_ENUM_BUFFER`, `lib/dcerpc-lsa.c:lsa_SID_ENUM_BUFFER_coder`

### Requirement: LSAP_LOOKUP_LEVEL defines stable lookup-level values
系统 MUST define `LSAP_LOOKUP_LEVEL` values starting with `LsapLookupWksta = 1` and continuing in declaration order through `LsapLookupRODCReferralToFullDC`.

#### Scenario: lookup level enum is serialized as uint32
- **GIVEN** a caller sets `lsa_lookupsids2_req.LookupLevel`
- **WHEN** `lsa_LookupSids2_req_coder` serializes the request
- **THEN** the enum value is converted through a `uint32_t` transport value and written back to `LookupLevel`

Trace: `include/smb2/libsmb2-dcerpc-lsa.h:LSAP_LOOKUP_LEVEL`, `lib/dcerpc-lsa.c:lsa_LookupSids2_req_coder`

### Requirement: LSAPR_TRUST_INFORMATION defines referenced-domain entries
系统 MUST define `LSAPR_TRUST_INFORMATION` with a domain `Name` and `RPC_SID Sid` for entries in a referenced-domain list.

#### Scenario: referenced domain entry carries name and SID
- **GIVEN** a LookupSids2 response contains referenced domains
- **WHEN** a domain entry is decoded
- **THEN** the entry exposes a string name and an embedded `RPC_SID`

Trace: `include/smb2/libsmb2-dcerpc-lsa.h:LSAPR_TRUST_INFORMATION`, `lib/dcerpc-lsa.c:lsa_TRUST_INFORMATION_coder`

### Requirement: LSAPR_REFERENCED_DOMAIN_LIST defines referenced-domain arrays
系统 MUST define `LSAPR_REFERENCED_DOMAIN_LIST` with `Entries`, `Domains`, and `MaxEntries`, and callers SHALL treat `MaxEntries` as ignored according to the header comment.

#### Scenario: referenced-domain list is decoded
- **GIVEN** a LookupSids2 response contains a referenced-domain list
- **WHEN** `lsa_LookupSids2_rep_coder` processes `ReferencedDomains`
- **THEN** `Entries` controls the number of `LSAPR_TRUST_INFORMATION` records in `Domains`, and `MaxEntries` remains a serialized field without caller-visible sizing authority

Trace: `include/smb2/libsmb2-dcerpc-lsa.h:LSAPR_REFERENCED_DOMAIN_LIST`, `lib/dcerpc-lsa.c:lsa_REFERENCED_DOMAIN_LIST_coder`

### Requirement: LSAPR_OBJECT_ATTRIBUTES defines OpenPolicy2 object attributes
系统 MUST define `LSAPR_OBJECT_ATTRIBUTES` with the six declared fields, and OpenPolicy2 callers SHALL provide a zero `RootDirectory` because the header comment requires it while other fields are ignored.

#### Scenario: OpenPolicy2 object attributes are encoded as empty attributes
- **GIVEN** a caller prepares `lsa_openpolicy2_req.ObjectAttributes`
- **WHEN** `lsa_OpenPolicy2_req_coder` processes the request
- **THEN** the implementation encodes an empty object-attributes payload with null pointer-sized fields and zero attributes independent of most input field values

Trace: `include/smb2/libsmb2-dcerpc-lsa.h:LSAPR_OBJECT_ATTRIBUTES`, `lib/dcerpc-lsa.c:lsa_ObjectAttributes_coder`

### Requirement: lsa_close_req defines the Close request payload
系统 MUST define `struct lsa_close_req` with a `PolicyHandle` context handle for Close requests.

#### Scenario: Close request carries a policy handle
- **GIVEN** a caller prepares `struct lsa_close_req`
- **WHEN** `lsa_Close_req_coder` encodes the request
- **THEN** the coder serializes `PolicyHandle` as a reference pointer to a DCERPC context handle

Trace: `include/smb2/libsmb2-dcerpc-lsa.h:lsa_close_req`, `lib/dcerpc-lsa.c:lsa_Close_req_coder`

### Requirement: lsa_close_rep defines the Close response payload
系统 MUST define `struct lsa_close_rep` with `status` and `PolicyHandle` fields for Close responses.

#### Scenario: Close response carries handle and status
- **GIVEN** a caller decodes `struct lsa_close_rep`
- **WHEN** `lsa_Close_rep_coder` processes the response
- **THEN** the coder processes the context handle first and then the 32-bit status value

Trace: `include/smb2/libsmb2-dcerpc-lsa.h:lsa_close_rep`, `lib/dcerpc-lsa.c:lsa_Close_rep_coder`

### Requirement: lsa_openpolicy2_req defines the OpenPolicy2 request payload
系统 MUST define `struct lsa_openpolicy2_req` with `SystemName`, `ObjectAttributes`, and `DesiredAccess` fields.

#### Scenario: OpenPolicy2 request carries system name, attributes, and access mask
- **GIVEN** a caller prepares `struct lsa_openpolicy2_req`
- **WHEN** `lsa_OpenPolicy2_req_coder` encodes the request
- **THEN** the coder processes `SystemName` as a unique UTF-16 string pointer, `ObjectAttributes` as a reference object-attributes pointer, and `DesiredAccess` as a 32-bit value

Trace: `include/smb2/libsmb2-dcerpc-lsa.h:lsa_openpolicy2_req`, `lib/dcerpc-lsa.c:lsa_OpenPolicy2_req_coder`

### Requirement: lsa_openpolicy2_rep defines the OpenPolicy2 response payload
系统 MUST define `struct lsa_openpolicy2_rep` with `status` and `PolicyHandle` fields for OpenPolicy2 responses.

#### Scenario: OpenPolicy2 response carries handle and status
- **GIVEN** a caller decodes `struct lsa_openpolicy2_rep`
- **WHEN** `lsa_OpenPolicy2_rep_coder` processes the response
- **THEN** the coder processes `PolicyHandle` as a reference context handle and then processes `status` as a 32-bit value

Trace: `include/smb2/libsmb2-dcerpc-lsa.h:lsa_openpolicy2_rep`, `lib/dcerpc-lsa.c:lsa_OpenPolicy2_rep_coder`

### Requirement: lsa_lookupsids2_req defines the LookupSids2 request payload
系统 MUST define `struct lsa_lookupsids2_req` with `PolicyHandle`, `SidEnumBuffer`, `TranslatedNames`, and `LookupLevel` fields.

#### Scenario: LookupSids2 request carries SID and lookup state
- **GIVEN** a caller prepares `struct lsa_lookupsids2_req`
- **WHEN** `lsa_LookupSids2_req_coder` encodes the request
- **THEN** the coder processes the policy handle, SID enum buffer, translated names, lookup level, two zero 32-bit values, and client revision value `2`

Trace: `include/smb2/libsmb2-dcerpc-lsa.h:lsa_lookupsids2_req`, `lib/dcerpc-lsa.c:lsa_LookupSids2_req_coder`

### Requirement: lsa_lookupsids2_rep defines the LookupSids2 response payload
系统 MUST define `struct lsa_lookupsids2_rep` with `status`, `ReferencedDomains`, `TranslatedNames`, and `MappedCount` fields.

#### Scenario: LookupSids2 response carries domains, names, count, and status
- **GIVEN** a caller decodes `struct lsa_lookupsids2_rep`
- **WHEN** `lsa_LookupSids2_rep_coder` processes the response
- **THEN** the coder processes referenced domains, translated names, mapped count, and final status in that order

Trace: `include/smb2/libsmb2-dcerpc-lsa.h:lsa_lookupsids2_rep`, `lib/dcerpc-lsa.c:lsa_LookupSids2_rep_coder`

### Requirement: lsa_Close_rep_coder decodes or encodes Close responses
系统 MUST provide `lsa_Close_rep_coder` with the declared signature, and the implementation SHALL return `-1` if either the policy-handle coder or status coder fails; otherwise it returns `0`.

#### Scenario: Close response coder succeeds
- **GIVEN** a valid DCERPC context, PDU, iovec, offset pointer, and `struct lsa_close_rep` pointer
- **WHEN** `lsa_Close_rep_coder` is invoked and both field coders succeed
- **THEN** the function returns `0` after processing `PolicyHandle` and `status`

Trace: `include/smb2/libsmb2-dcerpc-lsa.h:lsa_Close_rep_coder`, `lib/dcerpc-lsa.c:lsa_Close_rep_coder`

### Requirement: lsa_Close_req_coder encodes Close requests
系统 MUST provide `lsa_Close_req_coder` with the declared signature, and the implementation SHALL return `-1` if policy-handle coding fails; otherwise it returns `0`.

#### Scenario: Close request coder succeeds
- **GIVEN** a valid DCERPC context, PDU, iovec, offset pointer, and `struct lsa_close_req` pointer
- **WHEN** `lsa_Close_req_coder` is invoked and context-handle coding succeeds
- **THEN** the function returns `0` after processing `PolicyHandle` as a reference pointer

Trace: `include/smb2/libsmb2-dcerpc-lsa.h:lsa_Close_req_coder`, `lib/dcerpc-lsa.c:lsa_Close_req_coder`

### Requirement: lsa_LookupSids2_rep_coder decodes or encodes LookupSids2 responses
系统 MUST provide `lsa_LookupSids2_rep_coder` with the declared signature, and the implementation SHALL return `-1` on any referenced-domain, translated-name, mapped-count, or status coding failure; otherwise it returns `0`.

#### Scenario: LookupSids2 response coder succeeds
- **GIVEN** a valid DCERPC context, PDU, iovec, offset pointer, and `struct lsa_lookupsids2_rep` pointer
- **WHEN** `lsa_LookupSids2_rep_coder` is invoked and all field coders succeed
- **THEN** the function returns `0` after processing referenced domains, translated names, mapped count, and status

Trace: `include/smb2/libsmb2-dcerpc-lsa.h:lsa_LookupSids2_rep_coder`, `lib/dcerpc-lsa.c:lsa_LookupSids2_rep_coder`

### Requirement: lsa_LookupSids2_req_coder encodes LookupSids2 requests
系统 MUST provide `lsa_LookupSids2_req_coder` with the declared signature, and the implementation SHALL return `-1` on any field-coding failure while writing fixed zero lookup option values and client revision `2` after `LookupLevel`.

#### Scenario: LookupSids2 request coder succeeds
- **GIVEN** a valid DCERPC context, PDU, iovec, offset pointer, and `struct lsa_lookupsids2_req` pointer
- **WHEN** `lsa_LookupSids2_req_coder` is invoked and all field coders succeed
- **THEN** the function returns `0` after processing the handle, SID buffer, translated names, lookup level, two zero 32-bit values, and revision `2`

Trace: `include/smb2/libsmb2-dcerpc-lsa.h:lsa_LookupSids2_req_coder`, `lib/dcerpc-lsa.c:lsa_LookupSids2_req_coder`

### Requirement: lsa_OpenPolicy2_rep_coder decodes or encodes OpenPolicy2 responses
系统 MUST provide `lsa_OpenPolicy2_rep_coder` with the declared signature, and the implementation SHALL return `-1` if policy-handle or status coding fails; otherwise it returns `0`.

#### Scenario: OpenPolicy2 response coder succeeds
- **GIVEN** a valid DCERPC context, PDU, iovec, offset pointer, and `struct lsa_openpolicy2_rep` pointer
- **WHEN** `lsa_OpenPolicy2_rep_coder` is invoked and both field coders succeed
- **THEN** the function returns `0` after processing `PolicyHandle` and `status`

Trace: `include/smb2/libsmb2-dcerpc-lsa.h:lsa_OpenPolicy2_rep_coder`, `lib/dcerpc-lsa.c:lsa_OpenPolicy2_rep_coder`

### Requirement: lsa_OpenPolicy2_req_coder encodes OpenPolicy2 requests
系统 MUST provide `lsa_OpenPolicy2_req_coder` with the declared signature, and the implementation SHALL return `-1` on `SystemName`, `ObjectAttributes`, or `DesiredAccess` coding failure; otherwise it returns `0`.

#### Scenario: OpenPolicy2 request coder succeeds
- **GIVEN** a valid DCERPC context, PDU, iovec, offset pointer, and `struct lsa_openpolicy2_req` pointer
- **WHEN** `lsa_OpenPolicy2_req_coder` is invoked and all field coders succeed
- **THEN** the function returns `0` after processing `SystemName`, object attributes, and desired access

Trace: `include/smb2/libsmb2-dcerpc-lsa.h:lsa_OpenPolicy2_req_coder`, `lib/dcerpc-lsa.c:lsa_OpenPolicy2_req_coder`

### Requirement: lsa_RPC_SID_coder encodes and decodes RPC SID values
系统 MUST provide `lsa_RPC_SID_coder` with the declared signature, and the implementation SHALL process the sub-authority count, revision, authority bytes, and each 32-bit sub-authority while allocating `SubAuthority` storage during decode.

#### Scenario: RPC SID coder processes variable sub-authorities
- **GIVEN** a valid DCERPC context, PDU, iovec, offset pointer, and `RPC_SID` pointer
- **WHEN** `lsa_RPC_SID_coder` is invoked and all primitive coders and decode allocation succeed
- **THEN** the function returns `0` after processing six identifier-authority bytes and `SubAuthorityCount` 32-bit sub-authority values

Trace: `include/smb2/libsmb2-dcerpc-lsa.h:lsa_RPC_SID_coder`, `lib/dcerpc-lsa.c:lsa_RPC_SID_coder`

## Open Questions

| ID | Question | Related Interface | Reason |
| --- | --- | --- | --- |
| Q-001 | `include/smb2/libsmb2-dcerpc-lsa.h` 是否有意不直接包含定义 `uint8_t`、`uint32_t`、`struct dcerpc_context`、`struct dcerpc_pdu`、`struct smb2_iovec` 和 `struct ndr_context_handle` 的头文件？ | file-level | 源码显示该头文件依赖外部 include 顺序，当前证据无法确认这是稳定公共契约还是内部包含约定。 |
| Q-002 | `lsa_LookupSids2_req_coder` 固定写入两个 `0` 和 client revision `2` 是否对所有服务器/协议变体都必须保持？ | lsa_LookupSids2_req_coder | 实现和注释显示 LookupOptions should be 0 与 revision 2，但仓库内未发现测试断言或协议配置分支。 |
