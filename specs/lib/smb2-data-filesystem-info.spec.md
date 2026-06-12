# lib/smb2-data-filesystem-info.c Specification

## Source Context

- Source: `lib/smb2-data-filesystem-info.c`
- Related Headers: `include/libsmb2-private.h`, `include/smb2/smb2.h`
- Related Tests: `none`
- Related Dependencies: `lib/smb2-cmd-query-info.c:smb2_process_query_info_variable`, `lib/smb2-cmd-query-info.c:smb2_encode_query_info_reply`, `lib/pdu.c`, `lib/alloc.c`, `lib/timestamps.c`, `lib/unicode.c`
- Build/Compile Context: `CMakeLists.txt`/`lib/CMakeLists.txt` build the core C library; compile-time includes are guarded by `HAVE_CONFIG_H`, `HAVE_STDINT_H`, `HAVE_STDLIB_H`, `HAVE_STRING_H`, `STDC_HEADERS`, `HAVE_TIME_H`, and `HAVE_SYS_TIME_H`.

## Interface Summary

| Interface | Kind | Signature | Decision | Reason |
| --- | --- | --- | --- | --- |
| smb2_decode_file_fs_volume_info | function | `int smb2_decode_file_fs_volume_info(struct smb2_context *smb2, void *memctx, struct smb2_file_fs_volume_info *fs, struct smb2_iovec *vec);` | Include | 查询信息解码路径调用该接口填充卷信息结构，包含时间转换、UTF-16 名称转换和内存分配错误语义。 |
| smb2_encode_file_fs_volume_info | function | `int smb2_encode_file_fs_volume_info(struct smb2_context *smb2, struct smb2_file_fs_volume_info *fs, struct smb2_iovec *vec);` | Include | 查询信息回复编码路径调用该接口写入卷信息结构，包含时间转换、UTF-8 名称转换和返回长度语义。 |
| smb2_decode_file_fs_size_info | function | `int smb2_decode_file_fs_size_info(struct smb2_context *smb2, void *memctx, struct smb2_file_fs_size_info *fs, struct smb2_iovec *vec);` | Include | 查询信息解码路径调用该接口填充分配单元和扇区大小字段，包含固定长度校验。 |
| smb2_encode_file_fs_size_info | function | `int smb2_encode_file_fs_size_info(struct smb2_context *smb2, struct smb2_file_fs_size_info *fs, struct smb2_iovec *vec);` | Include | 查询信息回复编码路径调用该接口写入固定 24 字节大小信息，包含固定长度校验和返回长度语义。 |
| smb2_decode_file_fs_device_info | function | `int smb2_decode_file_fs_device_info(struct smb2_context *smb2, void *memctx, struct smb2_file_fs_device_info *fs, struct smb2_iovec *vec);` | Include | 查询信息解码路径调用该接口填充设备类型和特征字段，包含固定长度校验。 |
| smb2_encode_file_fs_device_info | function | `int smb2_encode_file_fs_device_info(struct smb2_context *smb2, struct smb2_file_fs_device_info *fs, struct smb2_iovec *vec);` | Include | 查询信息回复编码路径调用该接口写入设备类型和特征字段，包含固定长度校验和返回长度语义。 |
| smb2_decode_file_fs_attribute_info | function | `int smb2_decode_file_fs_attribute_info(struct smb2_context *smb2, void *memctx, struct smb2_file_fs_attribute_info *fs, struct smb2_iovec *vec);` | Include | 查询信息解码路径调用该接口填充文件系统属性和可选 UTF-16 名称，包含转换与分配失败语义。 |
| smb2_encode_file_fs_attribute_info | function | `int smb2_encode_file_fs_attribute_info(struct smb2_context *smb2, struct smb2_file_fs_attribute_info *fs, struct smb2_iovec *vec);` | Include | 查询信息回复编码路径调用该接口写入文件系统属性和 UTF-16 名称，包含固定头长度校验和返回长度语义。 |
| smb2_decode_file_fs_control_info | function | `int smb2_decode_file_fs_control_info(struct smb2_context *smb2, void *memctx, struct smb2_file_fs_control_info *fs, struct smb2_iovec *vec);` | Include | 查询信息解码路径调用该接口填充配额和控制标志，包含固定长度校验和 44 字节成功返回。 |
| smb2_encode_file_fs_control_info | function | `int smb2_encode_file_fs_control_info(struct smb2_context *smb2, struct smb2_file_fs_control_info *fs, struct smb2_iovec *vec);` | Include | 查询信息回复编码路径调用该接口写入配额和控制标志，包含实现中的 48 字节输入校验与 44 字节返回。 |
| smb2_decode_file_fs_full_size_info | function | `int smb2_decode_file_fs_full_size_info(struct smb2_context *smb2, void *memctx, struct smb2_file_fs_full_size_info *fs, struct smb2_iovec *vec);` | Include | 查询信息解码路径调用该接口填充完整容量信息，包含固定长度校验。 |
| smb2_encode_file_fs_full_size_info | function | `int smb2_encode_file_fs_full_size_info(struct smb2_context *smb2, struct smb2_file_fs_full_size_info *fs, struct smb2_iovec *vec);` | Include | 查询信息回复编码路径调用该接口写入完整容量信息，包含固定长度校验和返回长度语义。 |
| smb2_decode_file_fs_object_id_info | function | `int smb2_decode_file_fs_object_id_info(struct smb2_context *smb2, void *memctx, struct smb2_file_fs_object_id_info *fs, struct smb2_iovec *vec);` | Include | 查询信息解码路径调用该接口复制对象 GUID 和扩展信息，包含固定长度校验。 |
| smb2_encode_file_fs_object_id_info | function | `int smb2_encode_file_fs_object_id_info(struct smb2_context *smb2, struct smb2_file_fs_object_id_info *fs, struct smb2_iovec *vec);` | Include | 查询信息回复编码路径调用该接口复制对象 GUID 和扩展信息，包含固定长度校验和返回长度语义。 |
| smb2_decode_file_fs_sector_size_info | function | `int smb2_decode_file_fs_sector_size_info(struct smb2_context *smb2, void *memctx, struct smb2_file_fs_sector_size_info *fs, struct smb2_iovec *vec);` | Include | 查询信息解码路径调用该接口填充扇区大小和对齐字段，包含固定长度校验。 |
| smb2_encode_file_fs_sector_size_info | function | `int smb2_encode_file_fs_sector_size_info(struct smb2_context *smb2, struct smb2_file_fs_sector_size_info *fs, struct smb2_iovec *vec);` | Include | 查询信息回复编码路径调用该接口写入扇区大小和对齐字段，包含固定长度校验和返回长度语义。 |

## Data Model Summary

| Type/Macro | Kind | Definition | Notes |
| --- | --- | --- | --- |
| smb2_file_fs_volume_info | struct | `include/smb2/smb2.h:858` | 卷创建时间、序列号、标签长度、对象支持标志、保留字节和卷标签指针的数据模型。 |
| smb2_file_fs_size_info | struct | `include/smb2/smb2.h:867` | 总/可用分配单元和扇区几何的数据模型。 |
| smb2_file_fs_attribute_info | struct | `include/smb2/smb2.h:874` | 文件系统属性、最大组件名称长度、名称长度和名称指针的数据模型。 |
| smb2_file_fs_device_info | struct | `include/smb2/smb2.h:899` | 设备类型和设备特征的数据模型。 |
| smb2_file_fs_control_info | struct | `include/smb2/smb2.h:915` | 空间过滤、默认配额阈值/限制和控制标志的数据模型。 |
| smb2_file_fs_full_size_info | struct | `include/smb2/smb2.h:924` | 完整容量、调用者可用容量、实际可用容量和扇区几何的数据模型。 |
| smb2_file_fs_object_id_info | struct | `include/smb2/smb2.h:932` | 对象 GUID 和 48 字节扩展信息的数据模型。 |
| smb2_file_fs_sector_size_info | struct | `include/smb2/smb2.h:943` | 逻辑/物理扇区大小、有效物理扇区大小、标志和对齐偏移的数据模型。 |
| FILE_DEVICE_CD_ROM | macro | `include/smb2/smb2.h:882` | 设备类型常量。 |
| FILE_DEVICE_DISK | macro | `include/smb2/smb2.h:883` | 设备类型常量。 |
| FILE_REMOVABLE_MEDIA | macro | `include/smb2/smb2.h:886` | 设备特征标志。 |
| FILE_READ_ONLY_DEVICE | macro | `include/smb2/smb2.h:887` | 设备特征标志。 |
| FILE_FLOPPY_DISKETTE | macro | `include/smb2/smb2.h:888` | 设备特征标志。 |
| FILE_WRITE_ONCE_MEDIA | macro | `include/smb2/smb2.h:889` | 设备特征标志。 |
| FILE_REMOTE_DEVICE | macro | `include/smb2/smb2.h:890` | 设备特征标志。 |
| FILE_DEVICE_IS_MOUNTED | macro | `include/smb2/smb2.h:891` | 设备特征标志。 |
| FILE_VIRTUAL_VOLUME | macro | `include/smb2/smb2.h:892` | 设备特征标志。 |
| FILE_DEVICE_SECURE_OPEN | macro | `include/smb2/smb2.h:893` | 设备特征标志。 |
| FILE_CHARACTERISTIC_TS_DEVICE | macro | `include/smb2/smb2.h:894` | 设备特征标志。 |
| FILE_CHARACTERISTIC_WEBDAV_DEVICE | macro | `include/smb2/smb2.h:895` | 设备特征标志。 |
| FILE_DEVICE_ALLOW_APPCONTAINER_TRAVERSAL | macro | `include/smb2/smb2.h:896` | 设备特征标志。 |
| FILE_PORTABLE_DEVICE | macro | `include/smb2/smb2.h:897` | 设备特征标志。 |
| FILE_VC_QUOTA_TRACK | macro | `include/smb2/smb2.h:905` | 文件系统控制标志。 |
| FILE_VC_QUOTA_ENFORCE | macro | `include/smb2/smb2.h:906` | 文件系统控制标志。 |
| FILE_VC_CONTENT_INDEX_DISABLED | macro | `include/smb2/smb2.h:907` | 文件系统控制标志。 |
| FILE_VC_LOG_QUOTA_THRESHOLD | macro | `include/smb2/smb2.h:908` | 文件系统控制标志。 |
| FILE_VC_LOG_QUOTA_LIMIT | macro | `include/smb2/smb2.h:909` | 文件系统控制标志。 |
| FILE_VC_LOG_VOLUME_THRESHOLD | macro | `include/smb2/smb2.h:910` | 文件系统控制标志。 |
| FILE_VC_LOG_VOLUME_LIMIT | macro | `include/smb2/smb2.h:911` | 文件系统控制标志。 |
| FILE_VC_QUOTAS_INCOMPLETE | macro | `include/smb2/smb2.h:912` | 文件系统控制标志。 |
| FILE_VC_QUOTAS_REBUILDING | macro | `include/smb2/smb2.h:913` | 文件系统控制标志。 |
| SSINFO_FLAGS_ALIGNED_DEVICE | macro | `include/smb2/smb2.h:938` | 扇区大小信息标志。 |
| SSINFO_FLAGS_PARTITION_ALIGNED_ON_DEVICE | macro | `include/smb2/smb2.h:939` | 扇区大小信息标志。 |
| SSINFO_FLAGS_NO_SEEK_PENALTY | macro | `include/smb2/smb2.h:940` | 扇区大小信息标志。 |
| SSINFO_FLAGS_TRIM_ENABLED | macro | `include/smb2/smb2.h:941` | 扇区大小信息标志。 |

## ADDED Requirements

### Requirement: smb2_decode_file_fs_volume_info decodes volume information
系统 MUST 从输入向量固定偏移解码卷信息字段，并在卷标签分配失败时返回 `-1`。

#### Scenario: decode volume fields and label
- **GIVEN** 调用方提供包含 SMB2 文件系统卷信息布局的 `vec`、可写 `fs` 和数据分配上下文
- **WHEN** 调用 `smb2_decode_file_fs_volume_info(smb2, memctx, fs, vec)`
- **THEN** 实现从偏移 0 读取 Windows 时间并转换为 `fs->creation_time`，从偏移 8、12、16、17 分别读取序列号、标签字节长度、对象支持标志和保留字节，将偏移 18 的 UTF-16 标签转换为 UTF-8 并通过 `smb2_alloc_data` 保存到 `fs->volume_label`，成功时返回 `0`

Trace: `lib/smb2-data-filesystem-info.c:smb2_decode_file_fs_volume_info`

#### Scenario: fail when volume label allocation fails
- **GIVEN** 卷标签 UTF-16 转换已返回名称，但 `smb2_alloc_data` 无法分配 `strlen(name) + 1` 字节
- **WHEN** 调用 `smb2_decode_file_fs_volume_info(smb2, memctx, fs, vec)`
- **THEN** 实现释放临时名称并返回 `-1`

Trace: `lib/smb2-data-filesystem-info.c:smb2_decode_file_fs_volume_info`

### Requirement: smb2_encode_file_fs_volume_info encodes volume information
系统 MUST 将卷信息结构编码到固定 SMB2 布局，并返回写入的卷信息字节长度。

#### Scenario: encode volume fields and label
- **GIVEN** 调用方提供包含创建时间、序列号、对象支持标志、保留字节和 UTF-8 卷标签的 `fs`
- **WHEN** 调用 `smb2_encode_file_fs_volume_info(smb2, fs, vec)`
- **THEN** 实现将创建时间转换为 Windows 时间并写入偏移 0，将序列号写入偏移 8，将对象支持标志和保留字节写入偏移 16 和 17，将 UTF-8 标签转换为 UTF-16 后把字节长度写入偏移 12、内容写入偏移 18，释放临时 UTF-16 缓冲并返回 `18 + name_len`

Trace: `lib/smb2-data-filesystem-info.c:smb2_encode_file_fs_volume_info`

### Requirement: smb2_decode_file_fs_size_info decodes size information
系统 MUST 只在输入向量至少 24 字节时解码文件系统大小信息。

#### Scenario: reject short size buffer
- **GIVEN** `vec->len` 小于 24
- **WHEN** 调用 `smb2_decode_file_fs_size_info(smb2, memctx, fs, vec)`
- **THEN** 实现返回 `-1` 且不继续读取固定字段

Trace: `lib/smb2-data-filesystem-info.c:smb2_decode_file_fs_size_info`

#### Scenario: decode size fields
- **GIVEN** `vec->len` 至少为 24
- **WHEN** 调用 `smb2_decode_file_fs_size_info(smb2, memctx, fs, vec)`
- **THEN** 实现从偏移 0、8、16、20 分别读取总分配单元、可用分配单元、每分配单元扇区数和每扇区字节数，并返回 `0`

Trace: `lib/smb2-data-filesystem-info.c:smb2_decode_file_fs_size_info`

### Requirement: smb2_encode_file_fs_size_info encodes size information
系统 MUST 只在输出向量至少 24 字节时编码文件系统大小信息并报告固定长度。

#### Scenario: reject short size output buffer
- **GIVEN** `vec->len` 小于 24
- **WHEN** 调用 `smb2_encode_file_fs_size_info(smb2, fs, vec)`
- **THEN** 实现返回 `-1` 且不写入固定字段

Trace: `lib/smb2-data-filesystem-info.c:smb2_encode_file_fs_size_info`

#### Scenario: encode size fields
- **GIVEN** `vec->len` 至少为 24 且 `fs` 包含大小信息字段
- **WHEN** 调用 `smb2_encode_file_fs_size_info(smb2, fs, vec)`
- **THEN** 实现向偏移 0、8、16、20 分别写入总分配单元、可用分配单元、每分配单元扇区数和每扇区字节数，并返回 `24`

Trace: `lib/smb2-data-filesystem-info.c:smb2_encode_file_fs_size_info`

### Requirement: smb2_decode_file_fs_device_info decodes device information
系统 MUST 只在输入向量至少 8 字节时解码设备类型和设备特征。

#### Scenario: reject short device buffer
- **GIVEN** `vec->len` 小于 8
- **WHEN** 调用 `smb2_decode_file_fs_device_info(smb2, memctx, fs, vec)`
- **THEN** 实现返回 `-1` 且不继续读取固定字段

Trace: `lib/smb2-data-filesystem-info.c:smb2_decode_file_fs_device_info`

#### Scenario: decode device fields
- **GIVEN** `vec->len` 至少为 8
- **WHEN** 调用 `smb2_decode_file_fs_device_info(smb2, memctx, fs, vec)`
- **THEN** 实现从偏移 0 和 4 分别读取 `device_type` 和 `characteristics`，并返回 `0`

Trace: `lib/smb2-data-filesystem-info.c:smb2_decode_file_fs_device_info`

### Requirement: smb2_encode_file_fs_device_info encodes device information
系统 MUST 只在输出向量至少 8 字节时编码设备类型和设备特征。

#### Scenario: reject short device output buffer
- **GIVEN** `vec->len` 小于 8
- **WHEN** 调用 `smb2_encode_file_fs_device_info(smb2, fs, vec)`
- **THEN** 实现返回 `-1` 且不写入固定字段

Trace: `lib/smb2-data-filesystem-info.c:smb2_encode_file_fs_device_info`

#### Scenario: encode device fields
- **GIVEN** `vec->len` 至少为 8 且 `fs` 包含设备类型和特征字段
- **WHEN** 调用 `smb2_encode_file_fs_device_info(smb2, fs, vec)`
- **THEN** 实现向偏移 0 和 4 分别写入 `device_type` 和 `characteristics`，并返回 `8`

Trace: `lib/smb2-data-filesystem-info.c:smb2_encode_file_fs_device_info`

### Requirement: smb2_decode_file_fs_attribute_info decodes attribute information
系统 MUST 只在输入向量至少 20 字节时解码文件系统属性信息，并在名称转换或分配失败时返回 `-1`。

#### Scenario: reject short attribute buffer
- **GIVEN** `vec->len` 小于 20
- **WHEN** 调用 `smb2_decode_file_fs_attribute_info(smb2, memctx, fs, vec)`
- **THEN** 实现返回 `-1` 且不继续读取固定字段

Trace: `lib/smb2-data-filesystem-info.c:smb2_decode_file_fs_attribute_info`

#### Scenario: decode attributes with name
- **GIVEN** `vec->len` 至少为 20 且偏移 8 的名称字节长度大于 0
- **WHEN** 调用 `smb2_decode_file_fs_attribute_info(smb2, memctx, fs, vec)`
- **THEN** 实现从偏移 0、4、8 读取文件系统属性、最大组件名称长度和名称字节长度，将偏移 12 的 UTF-16 名称转换为 UTF-8 后通过 `smb2_alloc_data` 保存到 `fs->filesystem_name`，并返回 `0`

Trace: `lib/smb2-data-filesystem-info.c:smb2_decode_file_fs_attribute_info`

#### Scenario: fail when attribute name cannot be converted or allocated
- **GIVEN** 名称字节长度大于 0 且 UTF-16 转换返回空指针，或名称转换成功但 `smb2_alloc_data` 分配失败
- **WHEN** 调用 `smb2_decode_file_fs_attribute_info(smb2, memctx, fs, vec)`
- **THEN** 实现返回 `-1`，并在分配失败路径释放临时名称

Trace: `lib/smb2-data-filesystem-info.c:smb2_decode_file_fs_attribute_info`

### Requirement: smb2_encode_file_fs_attribute_info encodes attribute information
系统 MUST 只在输出向量至少 12 字节时编码文件系统属性和名称信息。

#### Scenario: reject short attribute output buffer
- **GIVEN** `vec->len` 小于 12
- **WHEN** 调用 `smb2_encode_file_fs_attribute_info(smb2, fs, vec)`
- **THEN** 实现返回 `-1` 且不写入固定字段

Trace: `lib/smb2-data-filesystem-info.c:smb2_encode_file_fs_attribute_info`

#### Scenario: encode attributes with name
- **GIVEN** `vec->len` 至少为 12 且 `fs` 包含属性、最大组件名称长度和 UTF-8 文件系统名称
- **WHEN** 调用 `smb2_encode_file_fs_attribute_info(smb2, fs, vec)`
- **THEN** 实现向偏移 0 和 4 写入属性字段，将名称转换为 UTF-16 后把字节长度写入偏移 8、内容写入偏移 12，释放临时 UTF-16 缓冲并返回 `12 + name_len`

Trace: `lib/smb2-data-filesystem-info.c:smb2_encode_file_fs_attribute_info`

### Requirement: smb2_decode_file_fs_control_info decodes control information
系统 MUST 只在输入向量至少 44 字节时解码文件系统控制信息。

#### Scenario: reject short control buffer
- **GIVEN** `vec->len` 小于 44
- **WHEN** 调用 `smb2_decode_file_fs_control_info(smb2, memctx, fs, vec)`
- **THEN** 实现返回 `-1` 且不继续读取固定字段

Trace: `lib/smb2-data-filesystem-info.c:smb2_decode_file_fs_control_info`

#### Scenario: decode control fields
- **GIVEN** `vec->len` 至少为 44
- **WHEN** 调用 `smb2_decode_file_fs_control_info(smb2, memctx, fs, vec)`
- **THEN** 实现从偏移 0、8、16、24、32、40 读取空间过滤、配额阈值/限制和控制标志字段，并返回 `44`

Trace: `lib/smb2-data-filesystem-info.c:smb2_decode_file_fs_control_info`

### Requirement: smb2_encode_file_fs_control_info encodes control information
系统 MUST 按实现约束要求输出向量至少 48 字节后编码 44 字节文件系统控制信息。

#### Scenario: reject control output buffer below implementation threshold
- **GIVEN** `vec->len` 小于 48
- **WHEN** 调用 `smb2_encode_file_fs_control_info(smb2, fs, vec)`
- **THEN** 实现返回 `-1` 且不写入固定字段

Trace: `lib/smb2-data-filesystem-info.c:smb2_encode_file_fs_control_info`

#### Scenario: encode control fields
- **GIVEN** `vec->len` 至少为 48 且 `fs` 包含控制信息字段
- **WHEN** 调用 `smb2_encode_file_fs_control_info(smb2, fs, vec)`
- **THEN** 实现向偏移 0、8、16、24、32、40 写入空间过滤、配额阈值/限制和控制标志字段，并返回 `44`

Trace: `lib/smb2-data-filesystem-info.c:smb2_encode_file_fs_control_info`

### Requirement: smb2_decode_file_fs_full_size_info decodes full size information
系统 MUST 只在输入向量至少 32 字节时解码完整文件系统大小信息。

#### Scenario: reject short full-size buffer
- **GIVEN** `vec->len` 小于 32
- **WHEN** 调用 `smb2_decode_file_fs_full_size_info(smb2, memctx, fs, vec)`
- **THEN** 实现返回 `-1` 且不继续读取固定字段

Trace: `lib/smb2-data-filesystem-info.c:smb2_decode_file_fs_full_size_info`

#### Scenario: decode full-size fields
- **GIVEN** `vec->len` 至少为 32
- **WHEN** 调用 `smb2_decode_file_fs_full_size_info(smb2, memctx, fs, vec)`
- **THEN** 实现从偏移 0、8、16、24、28 读取总分配单元、调用者可用分配单元、实际可用分配单元、每分配单元扇区数和每扇区字节数，并返回 `0`

Trace: `lib/smb2-data-filesystem-info.c:smb2_decode_file_fs_full_size_info`

### Requirement: smb2_encode_file_fs_full_size_info encodes full size information
系统 MUST 只在输出向量至少 32 字节时编码完整文件系统大小信息。

#### Scenario: reject short full-size output buffer
- **GIVEN** `vec->len` 小于 32
- **WHEN** 调用 `smb2_encode_file_fs_full_size_info(smb2, fs, vec)`
- **THEN** 实现返回 `-1` 且不写入固定字段

Trace: `lib/smb2-data-filesystem-info.c:smb2_encode_file_fs_full_size_info`

#### Scenario: encode full-size fields
- **GIVEN** `vec->len` 至少为 32 且 `fs` 包含完整大小信息字段
- **WHEN** 调用 `smb2_encode_file_fs_full_size_info(smb2, fs, vec)`
- **THEN** 实现向偏移 0、8、16、24、28 写入总分配单元、调用者可用分配单元、实际可用分配单元、每分配单元扇区数和每扇区字节数，并返回 `32`

Trace: `lib/smb2-data-filesystem-info.c:smb2_encode_file_fs_full_size_info`

### Requirement: smb2_decode_file_fs_object_id_info decodes object id information
系统 MUST 只在输入向量至少 64 字节时复制对象标识信息。

#### Scenario: reject short object-id buffer
- **GIVEN** `vec->len` 小于 64
- **WHEN** 调用 `smb2_decode_file_fs_object_id_info(smb2, memctx, fs, vec)`
- **THEN** 实现返回 `-1` 且不复制对象字段

Trace: `lib/smb2-data-filesystem-info.c:smb2_decode_file_fs_object_id_info`

#### Scenario: decode object id fields
- **GIVEN** `vec->len` 至少为 64
- **WHEN** 调用 `smb2_decode_file_fs_object_id_info(smb2, memctx, fs, vec)`
- **THEN** 实现从偏移 0 复制 `SMB2_GUID_SIZE` 字节到 `fs->object_id`，从偏移 `SMB2_GUID_SIZE` 复制 `sizeof(fs->extended_info)` 字节到 `fs->extended_info`，并返回 `0`

Trace: `lib/smb2-data-filesystem-info.c:smb2_decode_file_fs_object_id_info`

### Requirement: smb2_encode_file_fs_object_id_info encodes object id information
系统 MUST 只在输出向量至少 64 字节时复制对象标识信息。

#### Scenario: reject short object-id output buffer
- **GIVEN** `vec->len` 小于 64
- **WHEN** 调用 `smb2_encode_file_fs_object_id_info(smb2, fs, vec)`
- **THEN** 实现返回 `-1` 且不写入对象字段

Trace: `lib/smb2-data-filesystem-info.c:smb2_encode_file_fs_object_id_info`

#### Scenario: encode object id fields
- **GIVEN** `vec->len` 至少为 64 且 `fs` 包含对象 GUID 和扩展信息
- **WHEN** 调用 `smb2_encode_file_fs_object_id_info(smb2, fs, vec)`
- **THEN** 实现将 `fs->object_id` 复制到偏移 0，将 `fs->extended_info` 复制到偏移 `SMB2_GUID_SIZE`，并返回 `SMB2_GUID_SIZE + sizeof(fs->extended_info)`

Trace: `lib/smb2-data-filesystem-info.c:smb2_encode_file_fs_object_id_info`

### Requirement: smb2_decode_file_fs_sector_size_info decodes sector size information
系统 MUST 只在输入向量至少 28 字节时解码扇区大小和对齐信息。

#### Scenario: reject short sector-size buffer
- **GIVEN** `vec->len` 小于 28
- **WHEN** 调用 `smb2_decode_file_fs_sector_size_info(smb2, memctx, fs, vec)`
- **THEN** 实现返回 `-1` 且不继续读取固定字段

Trace: `lib/smb2-data-filesystem-info.c:smb2_decode_file_fs_sector_size_info`

#### Scenario: decode sector-size fields
- **GIVEN** `vec->len` 至少为 28
- **WHEN** 调用 `smb2_decode_file_fs_sector_size_info(smb2, memctx, fs, vec)`
- **THEN** 实现从偏移 0、4、8、12、16、20、24 读取逻辑扇区大小、物理扇区大小、有效物理扇区大小、标志和对齐偏移，并返回 `0`

Trace: `lib/smb2-data-filesystem-info.c:smb2_decode_file_fs_sector_size_info`

### Requirement: smb2_encode_file_fs_sector_size_info encodes sector size information
系统 MUST 只在输出向量至少 28 字节时编码扇区大小和对齐信息。

#### Scenario: reject short sector-size output buffer
- **GIVEN** `vec->len` 小于 28
- **WHEN** 调用 `smb2_encode_file_fs_sector_size_info(smb2, fs, vec)`
- **THEN** 实现返回 `-1` 且不写入固定字段

Trace: `lib/smb2-data-filesystem-info.c:smb2_encode_file_fs_sector_size_info`

#### Scenario: encode sector-size fields
- **GIVEN** `vec->len` 至少为 28 且 `fs` 包含扇区大小和对齐字段
- **WHEN** 调用 `smb2_encode_file_fs_sector_size_info(smb2, fs, vec)`
- **THEN** 实现向偏移 0、4、8、12、16、20、24 写入逻辑扇区大小、物理扇区大小、有效物理扇区大小、标志和对齐偏移，并返回 `28`

Trace: `lib/smb2-data-filesystem-info.c:smb2_encode_file_fs_sector_size_info`

## Open Questions

| ID | Question | Related Interface | Reason |
| --- | --- | --- | --- |
| Q-001 | `smb2_decode_file_fs_volume_info` 是否应像其他解码器一样在读取 18 字节头部和可变标签前检查 `vec->len`？ | smb2_decode_file_fs_volume_info | 源码未检查长度，调用方是否保证完整缓冲未在当前文件确认。 |
| Q-002 | 卷信息和属性信息编码器是否需要在写入可变 UTF-16 名称前检查 `vec->len` 是否覆盖 `18 + name_len` 或 `12 + name_len`？ | smb2_encode_file_fs_volume_info, smb2_encode_file_fs_attribute_info | 源码只对属性编码器检查 12 字节头部，卷编码器无长度检查；调用方缓冲容量约束未在当前文件确认。 |
| Q-003 | `smb2_encode_file_fs_control_info` 使用 `vec->len < 48` 作为失败条件但成功返回和写入长度为 44 字节是否为协议兼容要求？ | smb2_encode_file_fs_control_info | 源码显示 48 字节门槛与 44 字节写入/返回不一致，未发现本文件内解释。 |
| Q-004 | UTF-8 到 UTF-16 转换失败时编码器是否应返回 `-1`？ | smb2_encode_file_fs_volume_info, smb2_encode_file_fs_attribute_info | 源码直接解引用 `name->len`，未在当前文件确认转换函数是否保证非空。 |
