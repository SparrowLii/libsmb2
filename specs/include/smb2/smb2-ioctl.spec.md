# include/smb2/smb2-ioctl.h Specification

## Source Context

- Source: `include/smb2/smb2-ioctl.h`
- Related Headers: `include/smb2/smb2.h`
- Related Tests: `none`
- Related Dependencies: GitNexus `query` for `file:include/smb2/smb2-ioctl.h` did not rank this header as a public API candidate; GitNexus `context` found sampled macros `FSCTL_GET_REPARSE_POINT`, `FSCTL_PIPE_TRANSCEIVE`, and `FSCTL_SRV_ENUMERATE_SNAPSHOTS` in this header with no incoming callers, outgoing calls, or processes; source grep confirmed overlapping SMB2 ioctl constants are also declared with `SMB2_FSCTL_*` names in `include/smb2/smb2.h` and used by ioctl/DCERPC paths.
- Build/Compile Context: C header guarded by `_SMB2_IOCTL_H_`; no source-level compile conditions alter the exported macro set.

## Interface Summary

| Interface | Kind | Signature | Decision | Reason |
| --- | --- | --- | --- | --- |
| FSCTL_CREATE_OR_GET_OBJECT_ID | macro | #define FSCTL_CREATE_OR_GET_OBJECT_ID 0x000900C0 | Include | 公开 Windows/SMB ioctl control code 常量，调用方可直接用于 ioctl 编码。 |
| FSCTL_DELETE_OBJECT_ID | macro | #define FSCTL_DELETE_OBJECT_ID 0x000900A0 | Include | 公开 Windows/SMB ioctl control code 常量，调用方可直接用于 ioctl 编码。 |
| FSCTL_DELETE_REPARSE_POINT | macro | #define FSCTL_DELETE_REPARSE_POINT 0x000900AC | Include | 公开 reparse point 删除 control code 常量，调用方可直接用于 ioctl 编码。 |
| FSCTL_DUPLICATE_EXTENTS_TO_FILE | macro | #define FSCTL_DUPLICATE_EXTENTS_TO_FILE 0x00098344 | Include | 公开 duplicate extents control code 常量，调用方可直接用于 ioctl 编码。 |
| FSCTL_DUPLICATE_EXTENTS_TO_FILE_EX | macro | #define FSCTL_DUPLICATE_EXTENTS_TO_FILE_EX 0x000983E8 | Include | 公开 extended duplicate extents control code 常量，调用方可直接用于 ioctl 编码。 |
| FSCTL_FILESYSTEM_GET_STATISTICS | macro | #define FSCTL_FILESYSTEM_GET_STATISTICS 0x00090060 | Include | 公开 filesystem statistics control code 常量，调用方可直接用于 ioctl 编码。 |
| FSCTL_FILE_LEVEL_TRIM | macro | #define FSCTL_FILE_LEVEL_TRIM 0x00098208 | Include | 公开 file level trim control code 常量，并与 `SMB2_FSCTL_FILE_LEVEL_TRIM` 数值一致。 |
| FSCTL_FIND_FILES_BY_SID | macro | #define FSCTL_FIND_FILES_BY_SID 0x0009008F | Include | 公开 find-by-SID control code 常量，调用方可直接用于 ioctl 编码。 |
| FSCTL_GET_COMPRESSION | macro | #define FSCTL_GET_COMPRESSION 0x0009003C | Include | 公开 compression query control code 常量，调用方可直接用于 ioctl 编码。 |
| FSCTL_GET_INTEGRITY_INFORMATION | macro | #define FSCTL_GET_INTEGRITY_INFORMATION 0x0009027C | Include | 公开 integrity information query control code 常量，调用方可直接用于 ioctl 编码。 |
| FSCTL_GET_NTFS_VOLUME_DATA | macro | #define FSCTL_GET_NTFS_VOLUME_DATA 0x00090064 | Include | 公开 NTFS volume data control code 常量，调用方可直接用于 ioctl 编码。 |
| FSCTL_GET_REFS_VOLUME_DATA | macro | #define FSCTL_GET_REFS_VOLUME_DATA 0x000902D8 | Include | 公开 ReFS volume data control code 常量，调用方可直接用于 ioctl 编码。 |
| FSCTL_GET_OBJECT_ID | macro | #define FSCTL_GET_OBJECT_ID 0x0009009C | Include | 公开 object ID query control code 常量，调用方可直接用于 ioctl 编码。 |
| FSCTL_GET_REPARSE_POINT | macro | #define FSCTL_GET_REPARSE_POINT 0x000900A8 | Include | 公开 reparse point query control code 常量，并与 `SMB2_FSCTL_GET_REPARSE_POINT` 数值一致。 |
| FSCTL_GET_RETRIEVAL_POINTER_COUNT | macro | #define FSCTL_GET_RETRIEVAL_POINTER_COUNT 0x0009042B | Include | 公开 retrieval pointer count control code 常量，调用方可直接用于 ioctl 编码。 |
| FSCTL_GET_RETRIEVAL_POINTERS | macro | #define FSCTL_GET_RETRIEVAL_POINTERS 0x00090073 | Include | 公开 retrieval pointers control code 常量，调用方可直接用于 ioctl 编码。 |
| FSCTL_GET_RETRIEVAL_POINTERS_AND_REFCOUNT | macro | #define FSCTL_GET_RETRIEVAL_POINTERS_AND_REFCOUNT 0x000903D3 | Include | 公开 retrieval pointers and refcount control code 常量，调用方可直接用于 ioctl 编码。 |
| FSCTL_IS_PATHNAME_VALID | macro | #define FSCTL_IS_PATHNAME_VALID 0x0009002C | Include | 公开 pathname validation control code 常量，调用方可直接用于 ioctl 编码。 |
| FSCTL_LMR_SET_LINK_TRACKING_INFORMATION | macro | #define FSCTL_LMR_SET_LINK_TRACKING_INFORMATION 0x001400EC | Include | 公开 link tracking control code 常量，调用方可直接用于 ioctl 编码。 |
| FSCTL_MARK_HANDLE | macro | #define FSCTL_MARK_HANDLE 0x000900FC | Include | 公开 mark handle control code 常量，调用方可直接用于 ioctl 编码。 |
| FSCTL_OFFLOAD_READ | macro | #define FSCTL_OFFLOAD_READ 0x00094264 | Include | 公开 offload read control code 常量，调用方可直接用于 ioctl 编码。 |
| FSCTL_OFFLOAD_WRITE | macro | #define FSCTL_OFFLOAD_WRITE 0x00098268 | Include | 公开 offload write control code 常量，调用方可直接用于 ioctl 编码。 |
| FSCTL_PIPE_PEEK | macro | #define FSCTL_PIPE_PEEK 0x0011400C | Include | 公开 pipe peek control code 常量，并与 `SMB2_FSCTL_PIPE_PEEK` 数值一致。 |
| FSCTL_PIPE_TRANSCEIVE | macro | #define FSCTL_PIPE_TRANSCEIVE 0x0011C017 | Include | 公开 pipe transceive control code 常量，并与 `SMB2_FSCTL_PIPE_TRANSCEIVE` 数值一致。 |
| FSCTL_PIPE_WAIT | macro | #define FSCTL_PIPE_WAIT 0x00110018 | Include | 公开 pipe wait control code 常量，并与 `SMB2_FSCTL_PIPE_WAIT` 数值一致。 |
| FSCTL_QUERY_ALLOCATED_RANGES | macro | #define FSCTL_QUERY_ALLOCATED_RANGES 0x000940CF | Include | 公开 allocated ranges query control code 常量，调用方可直接用于 ioctl 编码。 |
| FSCTL_QUERY_FAT_BPB | macro | #define FSCTL_QUERY_FAT_BPB 0x00090058 | Include | 公开 FAT BPB query control code 常量，调用方可直接用于 ioctl 编码。 |
| FSCTL_QUERY_FILE_REGIONS | macro | #define FSCTL_QUERY_FILE_REGIONS 0x00090284 | Include | 公开 file regions query control code 常量，调用方可直接用于 ioctl 编码。 |
| FSCTL_QUERY_ON_DISK_VOLUME_INFO | macro | #define FSCTL_QUERY_ON_DISK_VOLUME_INFO 0x0009013C | Include | 公开 on-disk volume information query control code 常量，调用方可直接用于 ioctl 编码。 |
| FSCTL_QUERY_SPARING_INFO | macro | #define FSCTL_QUERY_SPARING_INFO 0x00090138 | Include | 公开 sparing information query control code 常量，调用方可直接用于 ioctl 编码。 |
| FSCTL_READ_FILE_USN_DATA | macro | #define FSCTL_READ_FILE_USN_DATA 0x000900EB | Include | 公开 USN data read control code 常量，调用方可直接用于 ioctl 编码。 |
| FSCTL_RECALL_FILE | macro | #define FSCTL_RECALL_FILE 0x00090117 | Include | 公开 recall file control code 常量，调用方可直接用于 ioctl 编码。 |
| FSCTL_REFS_STREAM_SNAPSHOT_MANAGEMENT | macro | #define FSCTL_REFS_STREAM_SNAPSHOT_MANAGEMENT 0x00090440 | Include | 公开 ReFS stream snapshot management control code 常量，调用方可直接用于 ioctl 编码。 |
| FSCTL_SET_COMPRESSION | macro | #define FSCTL_SET_COMPRESSION 0x0009C040 | Include | 公开 compression set control code 常量，调用方可直接用于 ioctl 编码。 |
| FSCTL_SET_DEFECT_MANAGEMENT | macro | #define FSCTL_SET_DEFECT_MANAGEMENT 0x00098134 | Include | 公开 defect management control code 常量，调用方可直接用于 ioctl 编码。 |
| FSCTL_SET_ENCRYPTION | macro | #define FSCTL_SET_ENCRYPTION 0x000900D7 | Include | 公开 encryption set control code 常量，调用方可直接用于 ioctl 编码。 |
| FSCTL_SET_INTEGRITY_INFORMATION | macro | #define FSCTL_SET_INTEGRITY_INFORMATION 0x0009C280 | Include | 公开 integrity information set control code 常量，调用方可直接用于 ioctl 编码。 |
| FSCTL_SET_INTEGRITY_INFORMATION_EX | macro | #define FSCTL_SET_INTEGRITY_INFORMATION_EX 0x00090380 | Include | 公开 extended integrity information set control code 常量，调用方可直接用于 ioctl 编码。 |
| FSCTL_SET_OBJECT_ID | macro | #define FSCTL_SET_OBJECT_ID 0x00090098 | Include | 公开 object ID set control code 常量，调用方可直接用于 ioctl 编码。 |
| FSCTL_SET_OBJECT_ID_EXTENDED | macro | #define FSCTL_SET_OBJECT_ID_EXTENDED 0x000900BC | Include | 公开 extended object ID set control code 常量，调用方可直接用于 ioctl 编码。 |
| FSCTL_SET_REPARSE_POINT | macro | #define FSCTL_SET_REPARSE_POINT 0x000900A4 | Include | 公开 reparse point set control code 常量，并与 `SMB2_FSCTL_SET_REPARSE_POINT` 数值一致。 |
| FSCTL_SET_SPARSE | macro | #define FSCTL_SET_SPARSE 0x000900C4 | Include | 公开 sparse file set control code 常量，调用方可直接用于 ioctl 编码。 |
| FSCTL_SET_ZERO_DATA | macro | #define FSCTL_SET_ZERO_DATA 0x000980C8 | Include | 公开 zero data set control code 常量，调用方可直接用于 ioctl 编码。 |
| FSCTL_SET_ZERO_ON_DEALLOCATION | macro | #define FSCTL_SET_ZERO_ON_DEALLOCATION 0x00090194 | Include | 公开 zero-on-deallocation set control code 常量，调用方可直接用于 ioctl 编码。 |
| FSCTL_SIS_COPYFILE | macro | #define FSCTL_SIS_COPYFILE 0x00090100 | Include | 公开 SIS copyfile control code 常量，调用方可直接用于 ioctl 编码。 |
| FSCTL_WRITE_USN_CLOSE_RECORD | macro | #define FSCTL_WRITE_USN_CLOSE_RECORD 0x000900EF | Include | 公开 USN close record write control code 常量，调用方可直接用于 ioctl 编码。 |
| FSCTL_SRV_ENUMERATE_SNAPSHOTS | macro | #define FSCTL_SRV_ENUMERATE_SNAPSHOTS 0x00144064 | Include | 公开 server snapshots enumeration control code 常量，并与 `SMB2_FSCTL_SRV_ENUMERATE_SNAPSHOTS` 数值一致。 |
| FSCTL_GET_SHADOW_COPY_DATA | macro | #define FSCTL_GET_SHADOW_COPY_DATA 0x00144064 | Include | 公开 shadow copy data control code 别名，数值与 `FSCTL_SRV_ENUMERATE_SNAPSHOTS` 相同。 |
| _SMB2_IOCTL_H_ | macro | #define _SMB2_IOCTL_H_ | Skip | include guard，无独立 ioctl control code 行为契约。 |

## Data Model Summary

| Type/Macro | Kind | Definition | Notes |
| --- | --- | --- | --- |
| FSCTL_CREATE_OR_GET_OBJECT_ID | macro | include/smb2/smb2-ioctl.h:32 | Defines ioctl control code `0x000900C0`. |
| FSCTL_DELETE_OBJECT_ID | macro | include/smb2/smb2-ioctl.h:33 | Defines ioctl control code `0x000900A0`. |
| FSCTL_DELETE_REPARSE_POINT | macro | include/smb2/smb2-ioctl.h:34 | Defines ioctl control code `0x000900AC`. |
| FSCTL_DUPLICATE_EXTENTS_TO_FILE | macro | include/smb2/smb2-ioctl.h:35 | Defines ioctl control code `0x00098344`. |
| FSCTL_DUPLICATE_EXTENTS_TO_FILE_EX | macro | include/smb2/smb2-ioctl.h:36 | Defines ioctl control code `0x000983E8`. |
| FSCTL_FILESYSTEM_GET_STATISTICS | macro | include/smb2/smb2-ioctl.h:37 | Defines ioctl control code `0x00090060`. |
| FSCTL_FILE_LEVEL_TRIM | macro | include/smb2/smb2-ioctl.h:38 | Defines ioctl control code `0x00098208`; same numeric value appears as `SMB2_FSCTL_FILE_LEVEL_TRIM` in `include/smb2/smb2.h:978`. |
| FSCTL_FIND_FILES_BY_SID | macro | include/smb2/smb2-ioctl.h:39 | Defines ioctl control code `0x0009008F`. |
| FSCTL_GET_COMPRESSION | macro | include/smb2/smb2-ioctl.h:40 | Defines ioctl control code `0x0009003C`. |
| FSCTL_GET_INTEGRITY_INFORMATION | macro | include/smb2/smb2-ioctl.h:41 | Defines ioctl control code `0x0009027C`. |
| FSCTL_GET_NTFS_VOLUME_DATA | macro | include/smb2/smb2-ioctl.h:42 | Defines ioctl control code `0x00090064`. |
| FSCTL_GET_REFS_VOLUME_DATA | macro | include/smb2/smb2-ioctl.h:43 | Defines ioctl control code `0x000902D8`. |
| FSCTL_GET_OBJECT_ID | macro | include/smb2/smb2-ioctl.h:44 | Defines ioctl control code `0x0009009C`. |
| FSCTL_GET_REPARSE_POINT | macro | include/smb2/smb2-ioctl.h:45 | Defines ioctl control code `0x000900A8`; same numeric value appears as `SMB2_FSCTL_GET_REPARSE_POINT` in `include/smb2/smb2.h:976`. |
| FSCTL_GET_RETRIEVAL_POINTER_COUNT | macro | include/smb2/smb2-ioctl.h:46 | Defines ioctl control code `0x0009042B`. |
| FSCTL_GET_RETRIEVAL_POINTERS | macro | include/smb2/smb2-ioctl.h:47 | Defines ioctl control code `0x00090073`. |
| FSCTL_GET_RETRIEVAL_POINTERS_AND_REFCOUNT | macro | include/smb2/smb2-ioctl.h:48 | Defines ioctl control code `0x000903D3`. |
| FSCTL_IS_PATHNAME_VALID | macro | include/smb2/smb2-ioctl.h:49 | Defines ioctl control code `0x0009002C`. |
| FSCTL_LMR_SET_LINK_TRACKING_INFORMATION | macro | include/smb2/smb2-ioctl.h:50 | Defines ioctl control code `0x001400EC`. |
| FSCTL_MARK_HANDLE | macro | include/smb2/smb2-ioctl.h:51 | Defines ioctl control code `0x000900FC`. |
| FSCTL_OFFLOAD_READ | macro | include/smb2/smb2-ioctl.h:52 | Defines ioctl control code `0x00094264`. |
| FSCTL_OFFLOAD_WRITE | macro | include/smb2/smb2-ioctl.h:53 | Defines ioctl control code `0x00098268`. |
| FSCTL_PIPE_PEEK | macro | include/smb2/smb2-ioctl.h:54 | Defines ioctl control code `0x0011400C`; same numeric value appears as `SMB2_FSCTL_PIPE_PEEK` in `include/smb2/smb2.h:965`. |
| FSCTL_PIPE_TRANSCEIVE | macro | include/smb2/smb2-ioctl.h:55 | Defines ioctl control code `0x0011C017`; same numeric value appears as `SMB2_FSCTL_PIPE_TRANSCEIVE` in `include/smb2/smb2.h:967`. |
| FSCTL_PIPE_WAIT | macro | include/smb2/smb2-ioctl.h:56 | Defines ioctl control code `0x00110018`; same numeric value appears as `SMB2_FSCTL_PIPE_WAIT` in `include/smb2/smb2.h:966`. |
| FSCTL_QUERY_ALLOCATED_RANGES | macro | include/smb2/smb2-ioctl.h:57 | Defines ioctl control code `0x000940CF`. |
| FSCTL_QUERY_FAT_BPB | macro | include/smb2/smb2-ioctl.h:58 | Defines ioctl control code `0x00090058`. |
| FSCTL_QUERY_FILE_REGIONS | macro | include/smb2/smb2-ioctl.h:59 | Defines ioctl control code `0x00090284`. |
| FSCTL_QUERY_ON_DISK_VOLUME_INFO | macro | include/smb2/smb2-ioctl.h:60 | Defines ioctl control code `0x0009013C`. |
| FSCTL_QUERY_SPARING_INFO | macro | include/smb2/smb2-ioctl.h:61 | Defines ioctl control code `0x00090138`. |
| FSCTL_READ_FILE_USN_DATA | macro | include/smb2/smb2-ioctl.h:62 | Defines ioctl control code `0x000900EB`. |
| FSCTL_RECALL_FILE | macro | include/smb2/smb2-ioctl.h:63 | Defines ioctl control code `0x00090117`. |
| FSCTL_REFS_STREAM_SNAPSHOT_MANAGEMENT | macro | include/smb2/smb2-ioctl.h:64 | Defines ioctl control code `0x00090440`. |
| FSCTL_SET_COMPRESSION | macro | include/smb2/smb2-ioctl.h:65 | Defines ioctl control code `0x0009C040`. |
| FSCTL_SET_DEFECT_MANAGEMENT | macro | include/smb2/smb2-ioctl.h:66 | Defines ioctl control code `0x00098134`. |
| FSCTL_SET_ENCRYPTION | macro | include/smb2/smb2-ioctl.h:67 | Defines ioctl control code `0x000900D7`. |
| FSCTL_SET_INTEGRITY_INFORMATION | macro | include/smb2/smb2-ioctl.h:68 | Defines ioctl control code `0x0009C280`. |
| FSCTL_SET_INTEGRITY_INFORMATION_EX | macro | include/smb2/smb2-ioctl.h:69 | Defines ioctl control code `0x00090380`. |
| FSCTL_SET_OBJECT_ID | macro | include/smb2/smb2-ioctl.h:70 | Defines ioctl control code `0x00090098`. |
| FSCTL_SET_OBJECT_ID_EXTENDED | macro | include/smb2/smb2-ioctl.h:71 | Defines ioctl control code `0x000900BC`. |
| FSCTL_SET_REPARSE_POINT | macro | include/smb2/smb2-ioctl.h:72 | Defines ioctl control code `0x000900A4`; same numeric value appears as `SMB2_FSCTL_SET_REPARSE_POINT` in `include/smb2/smb2.h:975`. |
| FSCTL_SET_SPARSE | macro | include/smb2/smb2-ioctl.h:73 | Defines ioctl control code `0x000900C4`. |
| FSCTL_SET_ZERO_DATA | macro | include/smb2/smb2-ioctl.h:74 | Defines ioctl control code `0x000980C8`. |
| FSCTL_SET_ZERO_ON_DEALLOCATION | macro | include/smb2/smb2-ioctl.h:75 | Defines ioctl control code `0x00090194`. |
| FSCTL_SIS_COPYFILE | macro | include/smb2/smb2-ioctl.h:76 | Defines ioctl control code `0x00090100`. |
| FSCTL_WRITE_USN_CLOSE_RECORD | macro | include/smb2/smb2-ioctl.h:77 | Defines ioctl control code `0x000900EF`. |
| FSCTL_SRV_ENUMERATE_SNAPSHOTS | macro | include/smb2/smb2-ioctl.h:79 | Defines ioctl control code `0x00144064`; same numeric value appears as `SMB2_FSCTL_SRV_ENUMERATE_SNAPSHOTS` in `include/smb2/smb2.h:969`. |
| FSCTL_GET_SHADOW_COPY_DATA | macro | include/smb2/smb2-ioctl.h:80 | Defines alias ioctl control code `0x00144064`, matching `FSCTL_SRV_ENUMERATE_SNAPSHOTS`. |
| _SMB2_IOCTL_H_ | macro | include/smb2/smb2-ioctl.h:29 | Include guard for the header. |

## ADDED Requirements

### Requirement: FSCTL_CREATE_OR_GET_OBJECT_ID exposes stable ioctl code
系统 MUST expose `FSCTL_CREATE_OR_GET_OBJECT_ID` as the literal control code `0x000900C0` when `include/smb2/smb2-ioctl.h` is included.

#### Scenario: object ID create-or-get code is available
- **GIVEN** C code includes `include/smb2/smb2-ioctl.h`
- **WHEN** the caller references `FSCTL_CREATE_OR_GET_OBJECT_ID`
- **THEN** the macro expands to `0x000900C0`

Trace: `include/smb2/smb2-ioctl.h:32`

### Requirement: FSCTL_DELETE_OBJECT_ID exposes stable ioctl code
系统 MUST expose `FSCTL_DELETE_OBJECT_ID` as the literal control code `0x000900A0` when `include/smb2/smb2-ioctl.h` is included.

#### Scenario: object ID delete code is available
- **GIVEN** C code includes `include/smb2/smb2-ioctl.h`
- **WHEN** the caller references `FSCTL_DELETE_OBJECT_ID`
- **THEN** the macro expands to `0x000900A0`

Trace: `include/smb2/smb2-ioctl.h:33`

### Requirement: FSCTL_DELETE_REPARSE_POINT exposes stable ioctl code
系统 MUST expose `FSCTL_DELETE_REPARSE_POINT` as the literal control code `0x000900AC` when `include/smb2/smb2-ioctl.h` is included.

#### Scenario: reparse point delete code is available
- **GIVEN** C code includes `include/smb2/smb2-ioctl.h`
- **WHEN** the caller references `FSCTL_DELETE_REPARSE_POINT`
- **THEN** the macro expands to `0x000900AC`

Trace: `include/smb2/smb2-ioctl.h:34`

### Requirement: FSCTL_DUPLICATE_EXTENTS_TO_FILE exposes stable ioctl code
系统 MUST expose `FSCTL_DUPLICATE_EXTENTS_TO_FILE` as the literal control code `0x00098344` when `include/smb2/smb2-ioctl.h` is included.

#### Scenario: duplicate extents code is available
- **GIVEN** C code includes `include/smb2/smb2-ioctl.h`
- **WHEN** the caller references `FSCTL_DUPLICATE_EXTENTS_TO_FILE`
- **THEN** the macro expands to `0x00098344`

Trace: `include/smb2/smb2-ioctl.h:35`

### Requirement: FSCTL_DUPLICATE_EXTENTS_TO_FILE_EX exposes stable ioctl code
系统 MUST expose `FSCTL_DUPLICATE_EXTENTS_TO_FILE_EX` as the literal control code `0x000983E8` when `include/smb2/smb2-ioctl.h` is included.

#### Scenario: extended duplicate extents code is available
- **GIVEN** C code includes `include/smb2/smb2-ioctl.h`
- **WHEN** the caller references `FSCTL_DUPLICATE_EXTENTS_TO_FILE_EX`
- **THEN** the macro expands to `0x000983E8`

Trace: `include/smb2/smb2-ioctl.h:36`

### Requirement: FSCTL_FILESYSTEM_GET_STATISTICS exposes stable ioctl code
系统 MUST expose `FSCTL_FILESYSTEM_GET_STATISTICS` as the literal control code `0x00090060` when `include/smb2/smb2-ioctl.h` is included.

#### Scenario: filesystem statistics code is available
- **GIVEN** C code includes `include/smb2/smb2-ioctl.h`
- **WHEN** the caller references `FSCTL_FILESYSTEM_GET_STATISTICS`
- **THEN** the macro expands to `0x00090060`

Trace: `include/smb2/smb2-ioctl.h:37`

### Requirement: FSCTL_FILE_LEVEL_TRIM exposes stable ioctl code
系统 MUST expose `FSCTL_FILE_LEVEL_TRIM` as the literal control code `0x00098208` when `include/smb2/smb2-ioctl.h` is included.

#### Scenario: file level trim code is available
- **GIVEN** C code includes `include/smb2/smb2-ioctl.h`
- **WHEN** the caller references `FSCTL_FILE_LEVEL_TRIM`
- **THEN** the macro expands to `0x00098208` and matches `SMB2_FSCTL_FILE_LEVEL_TRIM`

Trace: `include/smb2/smb2-ioctl.h:38`, `include/smb2/smb2.h:978`

### Requirement: FSCTL_FIND_FILES_BY_SID exposes stable ioctl code
系统 MUST expose `FSCTL_FIND_FILES_BY_SID` as the literal control code `0x0009008F` when `include/smb2/smb2-ioctl.h` is included.

#### Scenario: find files by SID code is available
- **GIVEN** C code includes `include/smb2/smb2-ioctl.h`
- **WHEN** the caller references `FSCTL_FIND_FILES_BY_SID`
- **THEN** the macro expands to `0x0009008F`

Trace: `include/smb2/smb2-ioctl.h:39`

### Requirement: FSCTL_GET_COMPRESSION exposes stable ioctl code
系统 MUST expose `FSCTL_GET_COMPRESSION` as the literal control code `0x0009003C` when `include/smb2/smb2-ioctl.h` is included.

#### Scenario: get compression code is available
- **GIVEN** C code includes `include/smb2/smb2-ioctl.h`
- **WHEN** the caller references `FSCTL_GET_COMPRESSION`
- **THEN** the macro expands to `0x0009003C`

Trace: `include/smb2/smb2-ioctl.h:40`

### Requirement: FSCTL_GET_INTEGRITY_INFORMATION exposes stable ioctl code
系统 MUST expose `FSCTL_GET_INTEGRITY_INFORMATION` as the literal control code `0x0009027C` when `include/smb2/smb2-ioctl.h` is included.

#### Scenario: get integrity information code is available
- **GIVEN** C code includes `include/smb2/smb2-ioctl.h`
- **WHEN** the caller references `FSCTL_GET_INTEGRITY_INFORMATION`
- **THEN** the macro expands to `0x0009027C`

Trace: `include/smb2/smb2-ioctl.h:41`

### Requirement: FSCTL_GET_NTFS_VOLUME_DATA exposes stable ioctl code
系统 MUST expose `FSCTL_GET_NTFS_VOLUME_DATA` as the literal control code `0x00090064` when `include/smb2/smb2-ioctl.h` is included.

#### Scenario: NTFS volume data code is available
- **GIVEN** C code includes `include/smb2/smb2-ioctl.h`
- **WHEN** the caller references `FSCTL_GET_NTFS_VOLUME_DATA`
- **THEN** the macro expands to `0x00090064`

Trace: `include/smb2/smb2-ioctl.h:42`

### Requirement: FSCTL_GET_REFS_VOLUME_DATA exposes stable ioctl code
系统 MUST expose `FSCTL_GET_REFS_VOLUME_DATA` as the literal control code `0x000902D8` when `include/smb2/smb2-ioctl.h` is included.

#### Scenario: ReFS volume data code is available
- **GIVEN** C code includes `include/smb2/smb2-ioctl.h`
- **WHEN** the caller references `FSCTL_GET_REFS_VOLUME_DATA`
- **THEN** the macro expands to `0x000902D8`

Trace: `include/smb2/smb2-ioctl.h:43`

### Requirement: FSCTL_GET_OBJECT_ID exposes stable ioctl code
系统 MUST expose `FSCTL_GET_OBJECT_ID` as the literal control code `0x0009009C` when `include/smb2/smb2-ioctl.h` is included.

#### Scenario: get object ID code is available
- **GIVEN** C code includes `include/smb2/smb2-ioctl.h`
- **WHEN** the caller references `FSCTL_GET_OBJECT_ID`
- **THEN** the macro expands to `0x0009009C`

Trace: `include/smb2/smb2-ioctl.h:44`

### Requirement: FSCTL_GET_REPARSE_POINT exposes stable ioctl code
系统 MUST expose `FSCTL_GET_REPARSE_POINT` as the literal control code `0x000900A8` when `include/smb2/smb2-ioctl.h` is included.

#### Scenario: get reparse point code is available
- **GIVEN** C code includes `include/smb2/smb2-ioctl.h`
- **WHEN** the caller references `FSCTL_GET_REPARSE_POINT`
- **THEN** the macro expands to `0x000900A8` and matches `SMB2_FSCTL_GET_REPARSE_POINT`

Trace: `include/smb2/smb2-ioctl.h:45`, `include/smb2/smb2.h:976`

### Requirement: FSCTL_GET_RETRIEVAL_POINTER_COUNT exposes stable ioctl code
系统 MUST expose `FSCTL_GET_RETRIEVAL_POINTER_COUNT` as the literal control code `0x0009042B` when `include/smb2/smb2-ioctl.h` is included.

#### Scenario: retrieval pointer count code is available
- **GIVEN** C code includes `include/smb2/smb2-ioctl.h`
- **WHEN** the caller references `FSCTL_GET_RETRIEVAL_POINTER_COUNT`
- **THEN** the macro expands to `0x0009042B`

Trace: `include/smb2/smb2-ioctl.h:46`

### Requirement: FSCTL_GET_RETRIEVAL_POINTERS exposes stable ioctl code
系统 MUST expose `FSCTL_GET_RETRIEVAL_POINTERS` as the literal control code `0x00090073` when `include/smb2/smb2-ioctl.h` is included.

#### Scenario: retrieval pointers code is available
- **GIVEN** C code includes `include/smb2/smb2-ioctl.h`
- **WHEN** the caller references `FSCTL_GET_RETRIEVAL_POINTERS`
- **THEN** the macro expands to `0x00090073`

Trace: `include/smb2/smb2-ioctl.h:47`

### Requirement: FSCTL_GET_RETRIEVAL_POINTERS_AND_REFCOUNT exposes stable ioctl code
系统 MUST expose `FSCTL_GET_RETRIEVAL_POINTERS_AND_REFCOUNT` as the literal control code `0x000903D3` when `include/smb2/smb2-ioctl.h` is included.

#### Scenario: retrieval pointers and refcount code is available
- **GIVEN** C code includes `include/smb2/smb2-ioctl.h`
- **WHEN** the caller references `FSCTL_GET_RETRIEVAL_POINTERS_AND_REFCOUNT`
- **THEN** the macro expands to `0x000903D3`

Trace: `include/smb2/smb2-ioctl.h:48`

### Requirement: FSCTL_IS_PATHNAME_VALID exposes stable ioctl code
系统 MUST expose `FSCTL_IS_PATHNAME_VALID` as the literal control code `0x0009002C` when `include/smb2/smb2-ioctl.h` is included.

#### Scenario: pathname validation code is available
- **GIVEN** C code includes `include/smb2/smb2-ioctl.h`
- **WHEN** the caller references `FSCTL_IS_PATHNAME_VALID`
- **THEN** the macro expands to `0x0009002C`

Trace: `include/smb2/smb2-ioctl.h:49`

### Requirement: FSCTL_LMR_SET_LINK_TRACKING_INFORMATION exposes stable ioctl code
系统 MUST expose `FSCTL_LMR_SET_LINK_TRACKING_INFORMATION` as the literal control code `0x001400EC` when `include/smb2/smb2-ioctl.h` is included.

#### Scenario: link tracking information code is available
- **GIVEN** C code includes `include/smb2/smb2-ioctl.h`
- **WHEN** the caller references `FSCTL_LMR_SET_LINK_TRACKING_INFORMATION`
- **THEN** the macro expands to `0x001400EC`

Trace: `include/smb2/smb2-ioctl.h:50`

### Requirement: FSCTL_MARK_HANDLE exposes stable ioctl code
系统 MUST expose `FSCTL_MARK_HANDLE` as the literal control code `0x000900FC` when `include/smb2/smb2-ioctl.h` is included.

#### Scenario: mark handle code is available
- **GIVEN** C code includes `include/smb2/smb2-ioctl.h`
- **WHEN** the caller references `FSCTL_MARK_HANDLE`
- **THEN** the macro expands to `0x000900FC`

Trace: `include/smb2/smb2-ioctl.h:51`

### Requirement: FSCTL_OFFLOAD_READ exposes stable ioctl code
系统 MUST expose `FSCTL_OFFLOAD_READ` as the literal control code `0x00094264` when `include/smb2/smb2-ioctl.h` is included.

#### Scenario: offload read code is available
- **GIVEN** C code includes `include/smb2/smb2-ioctl.h`
- **WHEN** the caller references `FSCTL_OFFLOAD_READ`
- **THEN** the macro expands to `0x00094264`

Trace: `include/smb2/smb2-ioctl.h:52`

### Requirement: FSCTL_OFFLOAD_WRITE exposes stable ioctl code
系统 MUST expose `FSCTL_OFFLOAD_WRITE` as the literal control code `0x00098268` when `include/smb2/smb2-ioctl.h` is included.

#### Scenario: offload write code is available
- **GIVEN** C code includes `include/smb2/smb2-ioctl.h`
- **WHEN** the caller references `FSCTL_OFFLOAD_WRITE`
- **THEN** the macro expands to `0x00098268`

Trace: `include/smb2/smb2-ioctl.h:53`

### Requirement: FSCTL_PIPE_PEEK exposes stable ioctl code
系统 MUST expose `FSCTL_PIPE_PEEK` as the literal control code `0x0011400C` when `include/smb2/smb2-ioctl.h` is included.

#### Scenario: pipe peek code is available
- **GIVEN** C code includes `include/smb2/smb2-ioctl.h`
- **WHEN** the caller references `FSCTL_PIPE_PEEK`
- **THEN** the macro expands to `0x0011400C` and matches `SMB2_FSCTL_PIPE_PEEK`

Trace: `include/smb2/smb2-ioctl.h:54`, `include/smb2/smb2.h:965`

### Requirement: FSCTL_PIPE_TRANSCEIVE exposes stable ioctl code
系统 MUST expose `FSCTL_PIPE_TRANSCEIVE` as the literal control code `0x0011C017` when `include/smb2/smb2-ioctl.h` is included.

#### Scenario: pipe transceive code is available
- **GIVEN** C code includes `include/smb2/smb2-ioctl.h`
- **WHEN** the caller references `FSCTL_PIPE_TRANSCEIVE`
- **THEN** the macro expands to `0x0011C017` and matches `SMB2_FSCTL_PIPE_TRANSCEIVE`

Trace: `include/smb2/smb2-ioctl.h:55`, `include/smb2/smb2.h:967`

### Requirement: FSCTL_PIPE_WAIT exposes stable ioctl code
系统 MUST expose `FSCTL_PIPE_WAIT` as the literal control code `0x00110018` when `include/smb2/smb2-ioctl.h` is included.

#### Scenario: pipe wait code is available
- **GIVEN** C code includes `include/smb2/smb2-ioctl.h`
- **WHEN** the caller references `FSCTL_PIPE_WAIT`
- **THEN** the macro expands to `0x00110018` and matches `SMB2_FSCTL_PIPE_WAIT`

Trace: `include/smb2/smb2-ioctl.h:56`, `include/smb2/smb2.h:966`

### Requirement: FSCTL_QUERY_ALLOCATED_RANGES exposes stable ioctl code
系统 MUST expose `FSCTL_QUERY_ALLOCATED_RANGES` as the literal control code `0x000940CF` when `include/smb2/smb2-ioctl.h` is included.

#### Scenario: allocated ranges query code is available
- **GIVEN** C code includes `include/smb2/smb2-ioctl.h`
- **WHEN** the caller references `FSCTL_QUERY_ALLOCATED_RANGES`
- **THEN** the macro expands to `0x000940CF`

Trace: `include/smb2/smb2-ioctl.h:57`

### Requirement: FSCTL_QUERY_FAT_BPB exposes stable ioctl code
系统 MUST expose `FSCTL_QUERY_FAT_BPB` as the literal control code `0x00090058` when `include/smb2/smb2-ioctl.h` is included.

#### Scenario: FAT BPB query code is available
- **GIVEN** C code includes `include/smb2/smb2-ioctl.h`
- **WHEN** the caller references `FSCTL_QUERY_FAT_BPB`
- **THEN** the macro expands to `0x00090058`

Trace: `include/smb2/smb2-ioctl.h:58`

### Requirement: FSCTL_QUERY_FILE_REGIONS exposes stable ioctl code
系统 MUST expose `FSCTL_QUERY_FILE_REGIONS` as the literal control code `0x00090284` when `include/smb2/smb2-ioctl.h` is included.

#### Scenario: file regions query code is available
- **GIVEN** C code includes `include/smb2/smb2-ioctl.h`
- **WHEN** the caller references `FSCTL_QUERY_FILE_REGIONS`
- **THEN** the macro expands to `0x00090284`

Trace: `include/smb2/smb2-ioctl.h:59`

### Requirement: FSCTL_QUERY_ON_DISK_VOLUME_INFO exposes stable ioctl code
系统 MUST expose `FSCTL_QUERY_ON_DISK_VOLUME_INFO` as the literal control code `0x0009013C` when `include/smb2/smb2-ioctl.h` is included.

#### Scenario: on-disk volume information query code is available
- **GIVEN** C code includes `include/smb2/smb2-ioctl.h`
- **WHEN** the caller references `FSCTL_QUERY_ON_DISK_VOLUME_INFO`
- **THEN** the macro expands to `0x0009013C`

Trace: `include/smb2/smb2-ioctl.h:60`

### Requirement: FSCTL_QUERY_SPARING_INFO exposes stable ioctl code
系统 MUST expose `FSCTL_QUERY_SPARING_INFO` as the literal control code `0x00090138` when `include/smb2/smb2-ioctl.h` is included.

#### Scenario: sparing information query code is available
- **GIVEN** C code includes `include/smb2/smb2-ioctl.h`
- **WHEN** the caller references `FSCTL_QUERY_SPARING_INFO`
- **THEN** the macro expands to `0x00090138`

Trace: `include/smb2/smb2-ioctl.h:61`

### Requirement: FSCTL_READ_FILE_USN_DATA exposes stable ioctl code
系统 MUST expose `FSCTL_READ_FILE_USN_DATA` as the literal control code `0x000900EB` when `include/smb2/smb2-ioctl.h` is included.

#### Scenario: read file USN data code is available
- **GIVEN** C code includes `include/smb2/smb2-ioctl.h`
- **WHEN** the caller references `FSCTL_READ_FILE_USN_DATA`
- **THEN** the macro expands to `0x000900EB`

Trace: `include/smb2/smb2-ioctl.h:62`

### Requirement: FSCTL_RECALL_FILE exposes stable ioctl code
系统 MUST expose `FSCTL_RECALL_FILE` as the literal control code `0x00090117` when `include/smb2/smb2-ioctl.h` is included.

#### Scenario: recall file code is available
- **GIVEN** C code includes `include/smb2/smb2-ioctl.h`
- **WHEN** the caller references `FSCTL_RECALL_FILE`
- **THEN** the macro expands to `0x00090117`

Trace: `include/smb2/smb2-ioctl.h:63`

### Requirement: FSCTL_REFS_STREAM_SNAPSHOT_MANAGEMENT exposes stable ioctl code
系统 MUST expose `FSCTL_REFS_STREAM_SNAPSHOT_MANAGEMENT` as the literal control code `0x00090440` when `include/smb2/smb2-ioctl.h` is included.

#### Scenario: ReFS stream snapshot management code is available
- **GIVEN** C code includes `include/smb2/smb2-ioctl.h`
- **WHEN** the caller references `FSCTL_REFS_STREAM_SNAPSHOT_MANAGEMENT`
- **THEN** the macro expands to `0x00090440`

Trace: `include/smb2/smb2-ioctl.h:64`

### Requirement: FSCTL_SET_COMPRESSION exposes stable ioctl code
系统 MUST expose `FSCTL_SET_COMPRESSION` as the literal control code `0x0009C040` when `include/smb2/smb2-ioctl.h` is included.

#### Scenario: set compression code is available
- **GIVEN** C code includes `include/smb2/smb2-ioctl.h`
- **WHEN** the caller references `FSCTL_SET_COMPRESSION`
- **THEN** the macro expands to `0x0009C040`

Trace: `include/smb2/smb2-ioctl.h:65`

### Requirement: FSCTL_SET_DEFECT_MANAGEMENT exposes stable ioctl code
系统 MUST expose `FSCTL_SET_DEFECT_MANAGEMENT` as the literal control code `0x00098134` when `include/smb2/smb2-ioctl.h` is included.

#### Scenario: set defect management code is available
- **GIVEN** C code includes `include/smb2/smb2-ioctl.h`
- **WHEN** the caller references `FSCTL_SET_DEFECT_MANAGEMENT`
- **THEN** the macro expands to `0x00098134`

Trace: `include/smb2/smb2-ioctl.h:66`

### Requirement: FSCTL_SET_ENCRYPTION exposes stable ioctl code
系统 MUST expose `FSCTL_SET_ENCRYPTION` as the literal control code `0x000900D7` when `include/smb2/smb2-ioctl.h` is included.

#### Scenario: set encryption code is available
- **GIVEN** C code includes `include/smb2/smb2-ioctl.h`
- **WHEN** the caller references `FSCTL_SET_ENCRYPTION`
- **THEN** the macro expands to `0x000900D7`

Trace: `include/smb2/smb2-ioctl.h:67`

### Requirement: FSCTL_SET_INTEGRITY_INFORMATION exposes stable ioctl code
系统 MUST expose `FSCTL_SET_INTEGRITY_INFORMATION` as the literal control code `0x0009C280` when `include/smb2/smb2-ioctl.h` is included.

#### Scenario: set integrity information code is available
- **GIVEN** C code includes `include/smb2/smb2-ioctl.h`
- **WHEN** the caller references `FSCTL_SET_INTEGRITY_INFORMATION`
- **THEN** the macro expands to `0x0009C280`

Trace: `include/smb2/smb2-ioctl.h:68`

### Requirement: FSCTL_SET_INTEGRITY_INFORMATION_EX exposes stable ioctl code
系统 MUST expose `FSCTL_SET_INTEGRITY_INFORMATION_EX` as the literal control code `0x00090380` when `include/smb2/smb2-ioctl.h` is included.

#### Scenario: extended set integrity information code is available
- **GIVEN** C code includes `include/smb2/smb2-ioctl.h`
- **WHEN** the caller references `FSCTL_SET_INTEGRITY_INFORMATION_EX`
- **THEN** the macro expands to `0x00090380`

Trace: `include/smb2/smb2-ioctl.h:69`

### Requirement: FSCTL_SET_OBJECT_ID exposes stable ioctl code
系统 MUST expose `FSCTL_SET_OBJECT_ID` as the literal control code `0x00090098` when `include/smb2/smb2-ioctl.h` is included.

#### Scenario: set object ID code is available
- **GIVEN** C code includes `include/smb2/smb2-ioctl.h`
- **WHEN** the caller references `FSCTL_SET_OBJECT_ID`
- **THEN** the macro expands to `0x00090098`

Trace: `include/smb2/smb2-ioctl.h:70`

### Requirement: FSCTL_SET_OBJECT_ID_EXTENDED exposes stable ioctl code
系统 MUST expose `FSCTL_SET_OBJECT_ID_EXTENDED` as the literal control code `0x000900BC` when `include/smb2/smb2-ioctl.h` is included.

#### Scenario: extended set object ID code is available
- **GIVEN** C code includes `include/smb2/smb2-ioctl.h`
- **WHEN** the caller references `FSCTL_SET_OBJECT_ID_EXTENDED`
- **THEN** the macro expands to `0x000900BC`

Trace: `include/smb2/smb2-ioctl.h:71`

### Requirement: FSCTL_SET_REPARSE_POINT exposes stable ioctl code
系统 MUST expose `FSCTL_SET_REPARSE_POINT` as the literal control code `0x000900A4` when `include/smb2/smb2-ioctl.h` is included.

#### Scenario: set reparse point code is available
- **GIVEN** C code includes `include/smb2/smb2-ioctl.h`
- **WHEN** the caller references `FSCTL_SET_REPARSE_POINT`
- **THEN** the macro expands to `0x000900A4` and matches `SMB2_FSCTL_SET_REPARSE_POINT`

Trace: `include/smb2/smb2-ioctl.h:72`, `include/smb2/smb2.h:975`

### Requirement: FSCTL_SET_SPARSE exposes stable ioctl code
系统 MUST expose `FSCTL_SET_SPARSE` as the literal control code `0x000900C4` when `include/smb2/smb2-ioctl.h` is included.

#### Scenario: set sparse code is available
- **GIVEN** C code includes `include/smb2/smb2-ioctl.h`
- **WHEN** the caller references `FSCTL_SET_SPARSE`
- **THEN** the macro expands to `0x000900C4`

Trace: `include/smb2/smb2-ioctl.h:73`

### Requirement: FSCTL_SET_ZERO_DATA exposes stable ioctl code
系统 MUST expose `FSCTL_SET_ZERO_DATA` as the literal control code `0x000980C8` when `include/smb2/smb2-ioctl.h` is included.

#### Scenario: set zero data code is available
- **GIVEN** C code includes `include/smb2/smb2-ioctl.h`
- **WHEN** the caller references `FSCTL_SET_ZERO_DATA`
- **THEN** the macro expands to `0x000980C8`

Trace: `include/smb2/smb2-ioctl.h:74`

### Requirement: FSCTL_SET_ZERO_ON_DEALLOCATION exposes stable ioctl code
系统 MUST expose `FSCTL_SET_ZERO_ON_DEALLOCATION` as the literal control code `0x00090194` when `include/smb2/smb2-ioctl.h` is included.

#### Scenario: set zero on deallocation code is available
- **GIVEN** C code includes `include/smb2/smb2-ioctl.h`
- **WHEN** the caller references `FSCTL_SET_ZERO_ON_DEALLOCATION`
- **THEN** the macro expands to `0x00090194`

Trace: `include/smb2/smb2-ioctl.h:75`

### Requirement: FSCTL_SIS_COPYFILE exposes stable ioctl code
系统 MUST expose `FSCTL_SIS_COPYFILE` as the literal control code `0x00090100` when `include/smb2/smb2-ioctl.h` is included.

#### Scenario: SIS copyfile code is available
- **GIVEN** C code includes `include/smb2/smb2-ioctl.h`
- **WHEN** the caller references `FSCTL_SIS_COPYFILE`
- **THEN** the macro expands to `0x00090100`

Trace: `include/smb2/smb2-ioctl.h:76`

### Requirement: FSCTL_WRITE_USN_CLOSE_RECORD exposes stable ioctl code
系统 MUST expose `FSCTL_WRITE_USN_CLOSE_RECORD` as the literal control code `0x000900EF` when `include/smb2/smb2-ioctl.h` is included.

#### Scenario: write USN close record code is available
- **GIVEN** C code includes `include/smb2/smb2-ioctl.h`
- **WHEN** the caller references `FSCTL_WRITE_USN_CLOSE_RECORD`
- **THEN** the macro expands to `0x000900EF`

Trace: `include/smb2/smb2-ioctl.h:77`

### Requirement: FSCTL_SRV_ENUMERATE_SNAPSHOTS exposes stable ioctl code
系统 MUST expose `FSCTL_SRV_ENUMERATE_SNAPSHOTS` as the literal control code `0x00144064` when `include/smb2/smb2-ioctl.h` is included.

#### Scenario: server snapshot enumeration code is available
- **GIVEN** C code includes `include/smb2/smb2-ioctl.h`
- **WHEN** the caller references `FSCTL_SRV_ENUMERATE_SNAPSHOTS`
- **THEN** the macro expands to `0x00144064` and matches `SMB2_FSCTL_SRV_ENUMERATE_SNAPSHOTS`

Trace: `include/smb2/smb2-ioctl.h:79`, `include/smb2/smb2.h:969`

### Requirement: FSCTL_GET_SHADOW_COPY_DATA aliases snapshot enumeration code
系统 MUST expose `FSCTL_GET_SHADOW_COPY_DATA` as the literal control code `0x00144064` when `include/smb2/smb2-ioctl.h` is included.

#### Scenario: shadow copy data alias is available
- **GIVEN** C code includes `include/smb2/smb2-ioctl.h`
- **WHEN** the caller references `FSCTL_GET_SHADOW_COPY_DATA`
- **THEN** the macro expands to `0x00144064` and is numerically identical to `FSCTL_SRV_ENUMERATE_SNAPSHOTS`

Trace: `include/smb2/smb2-ioctl.h:79`, `include/smb2/smb2-ioctl.h:80`

## Open Questions

| ID | Question | Related Interface | Reason |
| --- | --- | --- | --- |
| Q-001 | `include/smb2/smb2-ioctl.h` 与 `include/smb2/smb2.h` 中部分 `SMB2_FSCTL_*` 常量存在重叠，但命名集不完全一致；需要确认该头是否计划作为外部调用方的完整 Windows FSCTL 常量入口。 | file-level | GitNexus 未显示本头调用者或流程，源码仅确认部分数值在 `include/smb2/smb2.h` 和 ioctl/DCERPC 实现中以 `SMB2_FSCTL_*` 名称使用。 |
| Q-002 | `FSCTL_GET_REPARSE_POINT` 在本头使用 `0x000900A8`，而 `include/smb2/smb2.h` 中同值宏写作 `0X000900A8`；需要确认大小写差异是否仅为文本风格。 | FSCTL_GET_REPARSE_POINT | C 数值常量语义等价，但源码文本不完全一致。 |
