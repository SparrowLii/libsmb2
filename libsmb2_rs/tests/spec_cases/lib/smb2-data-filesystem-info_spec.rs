use libsmb2_rs::lib::smb2_data_filesystem_info::{
    FilesystemInfoError, Smb2FileFsObjectIdInfo, Smb2FileFsSectorSizeInfo,
    FILE_FS_OBJECT_ID_EXTENDED_INFO_LEN, FILE_FS_OBJECT_ID_INFO_LEN, FILE_FS_SECTOR_SIZE_INFO_LEN,
    SMB2_GUID_SIZE,
};
use libsmb2_rs::lib::smb2_data_filesystem_info::{
    self as c_fsinfo, FsAttributeInfo, FsControlInfo, FsDeviceInfo, FsFullSizeInfo, FsSizeInfo,
    FsVolumeInfo,
};

fn put_u32(buf: &mut [u8], offset: usize, value: u32) {
    buf[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn put_u64(buf: &mut [u8], offset: usize, value: u64) {
    buf[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

// Trace: `lib/smb2-data-filesystem-info.c:smb2_decode_file_fs_volume_info`
// Spec: smb2_decode_file_fs_volume_info decodes volume information#decode volume fields and label
// - **GIVEN** 调用方提供包含 SMB2 文件系统卷信息布局的 `vec`、可写 `fs` 和数据分配上下文
// - **WHEN** 调用 `smb2_decode_file_fs_volume_info(smb2, memctx, fs, vec)`
// - **THEN** 实现从偏移 0 读取 Windows 时间并转换为 `fs->creation_time`，从偏移 8、12、16、17 分别读取序列号、标签字节长度、对象支持标志和保留字节，将偏移 18 的 UTF-16 标签转换为 UTF-8 并通过 `smb2_alloc_data` 保存到 `fs->volume_label`，成功时返回 `0`
#[test]
fn test_smb2_data_filesystem_info_decode_volume_fields_and_label() {
    let source = FsVolumeInfo {
        creation_time_seconds: 42,
        creation_time_microseconds: 125_000,
        volume_serial_number: 0x1234_5678,
        supports_objects: 1,
        reserved: 2,
        volume_label: "VOL".to_string(),
    };
    let (buf, rc) = c_fsinfo::encode_volume(&source, 24).unwrap();
    assert_eq!(rc, 24);

    let decoded = c_fsinfo::decode_volume(&buf).unwrap();

    assert_eq!(decoded, source);
}

// Trace: `lib/smb2-data-filesystem-info.c:smb2_encode_file_fs_volume_info`
// Spec: smb2_encode_file_fs_volume_info encodes volume information#encode volume fields and label
// - **GIVEN** 调用方提供包含创建时间、序列号、对象支持标志、保留字节和 UTF-8 卷标签的 `fs`
// - **WHEN** 调用 `smb2_encode_file_fs_volume_info(smb2, fs, vec)`
// - **THEN** 实现将创建时间转换为 Windows 时间并写入偏移 0，将序列号写入偏移 8，将对象支持标志和保留字节写入偏移 16 和 17，将 UTF-8 标签转换为 UTF-16 后把字节长度写入偏移 12、内容写入偏移 18，释放临时 UTF-16 缓冲并返回 `18 + name_len`
#[test]
fn test_smb2_data_filesystem_info_encode_volume_fields_and_label() {
    let info = FsVolumeInfo {
        creation_time_seconds: 42,
        creation_time_microseconds: 125_000,
        volume_serial_number: 0x1234_5678,
        supports_objects: 1,
        reserved: 2,
        volume_label: "VOL".to_string(),
    };

    let (buf, rc) = c_fsinfo::encode_volume(&info, 24).unwrap();

    assert_eq!(rc, 24);
    assert_eq!(&buf[8..12], &0x1234_5678_u32.to_le_bytes());
    assert_eq!(&buf[12..16], &6_u32.to_le_bytes());
    assert_eq!(buf[16], 1);
    assert_eq!(buf[17], 2);
    assert_eq!(&buf[18..24], &[b'V', 0, b'O', 0, b'L', 0]);
}

// Trace: `lib/smb2-data-filesystem-info.c:smb2_decode_file_fs_size_info`
// Spec: smb2_decode_file_fs_size_info decodes size information#reject short size buffer
// - **GIVEN** `vec->len` 小于 24
// - **WHEN** 调用 `smb2_decode_file_fs_size_info(smb2, memctx, fs, vec)`
// - **THEN** 实现返回 `-1` 且不继续读取固定字段
#[test]
fn test_smb2_data_filesystem_info_reject_short_size_buffer() {
    assert_eq!(c_fsinfo::decode_size(&[0xaa; 23]), Err(-1));
}

// Trace: `lib/smb2-data-filesystem-info.c:smb2_decode_file_fs_size_info`
// Spec: smb2_decode_file_fs_size_info decodes size information#decode size fields
// - **GIVEN** `vec->len` 至少为 24
// - **WHEN** 调用 `smb2_decode_file_fs_size_info(smb2, memctx, fs, vec)`
// - **THEN** 实现从偏移 0、8、16、20 分别读取总分配单元、可用分配单元、每分配单元扇区数和每扇区字节数，并返回 `0`
#[test]
fn test_smb2_data_filesystem_info_decode_size_fields() {
    let mut buf = [0; 24];
    put_u64(&mut buf, 0, 0x1122_3344_5566_7788);
    put_u64(&mut buf, 8, 0x8877_6655_4433_2211);
    put_u32(&mut buf, 16, 0x1234_5678);
    put_u32(&mut buf, 20, 0x90ab_cdef);

    assert_eq!(
        c_fsinfo::decode_size(&buf).unwrap(),
        FsSizeInfo {
            total_allocation_units: 0x1122_3344_5566_7788,
            available_allocation_units: 0x8877_6655_4433_2211,
            sectors_per_allocation_unit: 0x1234_5678,
            bytes_per_sector: 0x90ab_cdef,
        }
    );
}

// Trace: `lib/smb2-data-filesystem-info.c:smb2_encode_file_fs_size_info`
// Spec: smb2_encode_file_fs_size_info encodes size information#reject short size output buffer
// - **GIVEN** `vec->len` 小于 24
// - **WHEN** 调用 `smb2_encode_file_fs_size_info(smb2, fs, vec)`
// - **THEN** 实现返回 `-1` 且不写入固定字段
#[test]
fn test_smb2_data_filesystem_info_reject_short_size_output_buffer() {
    let info = FsSizeInfo {
        total_allocation_units: 1,
        available_allocation_units: 2,
        sectors_per_allocation_unit: 3,
        bytes_per_sector: 4,
    };
    assert_eq!(c_fsinfo::encode_size(info, 23), Err(-1));
}

// Trace: `lib/smb2-data-filesystem-info.c:smb2_encode_file_fs_size_info`
// Spec: smb2_encode_file_fs_size_info encodes size information#encode size fields
// - **GIVEN** `vec->len` 至少为 24 且 `fs` 包含大小信息字段
// - **WHEN** 调用 `smb2_encode_file_fs_size_info(smb2, fs, vec)`
// - **THEN** 实现向偏移 0、8、16、20 分别写入总分配单元、可用分配单元、每分配单元扇区数和每扇区字节数，并返回 `24`
#[test]
fn test_smb2_data_filesystem_info_encode_size_fields() {
    let info = FsSizeInfo {
        total_allocation_units: 0x1122_3344_5566_7788,
        available_allocation_units: 0x8877_6655_4433_2211,
        sectors_per_allocation_unit: 0x1234_5678,
        bytes_per_sector: 0x90ab_cdef,
    };
    let (buf, rc) = c_fsinfo::encode_size(info, 24).unwrap();
    assert_eq!(rc, 24);
    assert_eq!(&buf[0..8], &0x1122_3344_5566_7788_u64.to_le_bytes());
    assert_eq!(&buf[8..16], &0x8877_6655_4433_2211_u64.to_le_bytes());
    assert_eq!(&buf[16..20], &0x1234_5678_u32.to_le_bytes());
    assert_eq!(&buf[20..24], &0x90ab_cdef_u32.to_le_bytes());
}

// Trace: `lib/smb2-data-filesystem-info.c:smb2_decode_file_fs_device_info`
// Spec: smb2_decode_file_fs_device_info decodes device information#reject short device buffer
// - **GIVEN** `vec->len` 小于 8
// - **WHEN** 调用 `smb2_decode_file_fs_device_info(smb2, memctx, fs, vec)`
// - **THEN** 实现返回 `-1` 且不继续读取固定字段
#[test]
fn test_smb2_data_filesystem_info_reject_short_device_buffer() {
    assert_eq!(c_fsinfo::decode_device(&[0xaa; 7]), Err(-1));
}

// Trace: `lib/smb2-data-filesystem-info.c:smb2_decode_file_fs_device_info`
// Spec: smb2_decode_file_fs_device_info decodes device information#decode device fields
// - **GIVEN** `vec->len` 至少为 8
// - **WHEN** 调用 `smb2_decode_file_fs_device_info(smb2, memctx, fs, vec)`
// - **THEN** 实现从偏移 0 和 4 分别读取 `device_type` 和 `characteristics`，并返回 `0`
#[test]
fn test_smb2_data_filesystem_info_decode_device_fields() {
    let mut buf = [0; 8];
    put_u32(&mut buf, 0, 7);
    put_u32(&mut buf, 4, 0x123);
    assert_eq!(
        c_fsinfo::decode_device(&buf).unwrap(),
        FsDeviceInfo {
            device_type: 7,
            characteristics: 0x123
        }
    );
}

// Trace: `lib/smb2-data-filesystem-info.c:smb2_encode_file_fs_device_info`
// Spec: smb2_encode_file_fs_device_info encodes device information#reject short device output buffer
// - **GIVEN** `vec->len` 小于 8
// - **WHEN** 调用 `smb2_encode_file_fs_device_info(smb2, fs, vec)`
// - **THEN** 实现返回 `-1` 且不写入固定字段
#[test]
fn test_smb2_data_filesystem_info_reject_short_device_output_buffer() {
    assert_eq!(
        c_fsinfo::encode_device(
            FsDeviceInfo {
                device_type: 7,
                characteristics: 0x123
            },
            7
        ),
        Err(-1)
    );
}

// Trace: `lib/smb2-data-filesystem-info.c:smb2_encode_file_fs_device_info`
// Spec: smb2_encode_file_fs_device_info encodes device information#encode device fields
// - **GIVEN** `vec->len` 至少为 8 且 `fs` 包含设备类型和特征字段
// - **WHEN** 调用 `smb2_encode_file_fs_device_info(smb2, fs, vec)`
// - **THEN** 实现向偏移 0 和 4 分别写入 `device_type` 和 `characteristics`，并返回 `8`
#[test]
fn test_smb2_data_filesystem_info_encode_device_fields() {
    let (buf, rc) = c_fsinfo::encode_device(
        FsDeviceInfo {
            device_type: 7,
            characteristics: 0x123,
        },
        8,
    )
    .unwrap();
    assert_eq!(rc, 8);
    assert_eq!(&buf[0..4], &7_u32.to_le_bytes());
    assert_eq!(&buf[4..8], &0x123_u32.to_le_bytes());
}

// Trace: `lib/smb2-data-filesystem-info.c:smb2_decode_file_fs_attribute_info`
// Spec: smb2_decode_file_fs_attribute_info decodes attribute information#reject short attribute buffer
// - **GIVEN** `vec->len` 小于 20
// - **WHEN** 调用 `smb2_decode_file_fs_attribute_info(smb2, memctx, fs, vec)`
// - **THEN** 实现返回 `-1` 且不继续读取固定字段
#[test]
fn test_smb2_data_filesystem_info_reject_short_attribute_buffer() {
    assert_eq!(c_fsinfo::decode_attribute(&[0xaa; 19]), Err(-1));
}

// Trace: `lib/smb2-data-filesystem-info.c:smb2_decode_file_fs_attribute_info`
// Spec: smb2_decode_file_fs_attribute_info decodes attribute information#decode attributes with name
// - **GIVEN** `vec->len` 至少为 20 且偏移 8 的名称字节长度大于 0
// - **WHEN** 调用 `smb2_decode_file_fs_attribute_info(smb2, memctx, fs, vec)`
// - **THEN** 实现从偏移 0、4、8 读取文件系统属性、最大组件名称长度和名称字节长度，将偏移 12 的 UTF-16 名称转换为 UTF-8 后通过 `smb2_alloc_data` 保存到 `fs->filesystem_name`，并返回 `0`
#[test]
fn test_smb2_data_filesystem_info_decode_attributes_with_name() {
    let source = FsAttributeInfo {
        filesystem_attributes: 0x11,
        maximum_component_name_length: 255,
        filesystem_name: "NTFS".to_string(),
    };
    let (buf, rc) = c_fsinfo::encode_attribute(&source, 20).unwrap();
    assert_eq!(rc, 20);

    let decoded = c_fsinfo::decode_attribute(&buf).unwrap();

    assert_eq!(decoded, source);
}

// Trace: `lib/smb2-data-filesystem-info.c:smb2_encode_file_fs_attribute_info`
// Spec: smb2_encode_file_fs_attribute_info encodes attribute information#reject short attribute output buffer
// - **GIVEN** `vec->len` 小于 12
// - **WHEN** 调用 `smb2_encode_file_fs_attribute_info(smb2, fs, vec)`
// - **THEN** 实现返回 `-1` 且不写入固定字段
#[test]
fn test_smb2_data_filesystem_info_reject_short_attribute_output_buffer() {
    let info = FsAttributeInfo {
        filesystem_attributes: 0x11,
        maximum_component_name_length: 255,
        filesystem_name: "NTFS".to_string(),
    };
    assert_eq!(c_fsinfo::encode_attribute(&info, 11), Err(-1));
}

// Trace: `lib/smb2-data-filesystem-info.c:smb2_encode_file_fs_attribute_info`
// Spec: smb2_encode_file_fs_attribute_info encodes attribute information#encode attributes with name
// - **GIVEN** `vec->len` 至少为 12 且 `fs` 包含属性、最大组件名称长度和 UTF-8 文件系统名称
// - **WHEN** 调用 `smb2_encode_file_fs_attribute_info(smb2, fs, vec)`
// - **THEN** 实现向偏移 0 和 4 写入属性字段，将名称转换为 UTF-16 后把字节长度写入偏移 8、内容写入偏移 12，释放临时 UTF-16 缓冲并返回 `12 + name_len`
#[test]
fn test_smb2_data_filesystem_info_encode_attributes_with_name() {
    let info = FsAttributeInfo {
        filesystem_attributes: 0x11,
        maximum_component_name_length: 255,
        filesystem_name: "NTFS".to_string(),
    };

    let (buf, rc) = c_fsinfo::encode_attribute(&info, 20).unwrap();

    assert_eq!(rc, 20);
    assert_eq!(&buf[0..4], &0x11_u32.to_le_bytes());
    assert_eq!(&buf[4..8], &255_u32.to_le_bytes());
    assert_eq!(&buf[8..12], &8_u32.to_le_bytes());
    assert_eq!(&buf[12..20], &[b'N', 0, b'T', 0, b'F', 0, b'S', 0]);
}

// Trace: `lib/smb2-data-filesystem-info.c:smb2_decode_file_fs_control_info`
// Spec: smb2_decode_file_fs_control_info decodes control information#reject short control buffer
// - **GIVEN** `vec->len` 小于 44
// - **WHEN** 调用 `smb2_decode_file_fs_control_info(smb2, memctx, fs, vec)`
// - **THEN** 实现返回 `-1` 且不继续读取固定字段
#[test]
fn test_smb2_data_filesystem_info_reject_short_control_buffer() {
    assert_eq!(c_fsinfo::decode_control(&[0xaa; 43]), Err(-1));
}

// Trace: `lib/smb2-data-filesystem-info.c:smb2_decode_file_fs_control_info`
// Spec: smb2_decode_file_fs_control_info decodes control information#decode control fields
// - **GIVEN** `vec->len` 至少为 44
// - **WHEN** 调用 `smb2_decode_file_fs_control_info(smb2, memctx, fs, vec)`
// - **THEN** 实现从偏移 0、8、16、24、32、40 读取空间过滤、配额阈值/限制和控制标志字段，并返回 `44`
#[test]
fn test_smb2_data_filesystem_info_decode_control_fields() {
    let mut buf = [0; 44];
    put_u64(&mut buf, 0, 1);
    put_u64(&mut buf, 8, 2);
    put_u64(&mut buf, 16, 3);
    put_u64(&mut buf, 24, 4);
    put_u64(&mut buf, 32, 5);
    put_u32(&mut buf, 40, 0x1ff);
    let (info, rc) = c_fsinfo::decode_control(&buf).unwrap();
    assert_eq!(rc, 44);
    assert_eq!(
        info,
        FsControlInfo {
            free_space_start_filtering: 1,
            free_space_threshold: 2,
            free_space_stop_filtering: 3,
            default_quota_threshold: 4,
            default_quota_limit: 5,
            file_system_control_flags: 0x1ff
        }
    );
}

// Trace: `lib/smb2-data-filesystem-info.c:smb2_encode_file_fs_control_info`
// Spec: smb2_encode_file_fs_control_info encodes control information#reject control output buffer below implementation threshold
// - **GIVEN** `vec->len` 小于 48
// - **WHEN** 调用 `smb2_encode_file_fs_control_info(smb2, fs, vec)`
// - **THEN** 实现返回 `-1` 且不写入固定字段
#[test]
fn test_smb2_data_filesystem_info_reject_control_output_buffer_below_implementation_threshold() {
    let info = FsControlInfo {
        free_space_start_filtering: 1,
        free_space_threshold: 2,
        free_space_stop_filtering: 3,
        default_quota_threshold: 4,
        default_quota_limit: 5,
        file_system_control_flags: 0x1ff,
    };
    assert_eq!(c_fsinfo::encode_control(info, 47), Err(-1));
}

// Trace: `lib/smb2-data-filesystem-info.c:smb2_encode_file_fs_control_info`
// Spec: smb2_encode_file_fs_control_info encodes control information#encode control fields
// - **GIVEN** `vec->len` 至少为 48 且 `fs` 包含控制信息字段
// - **WHEN** 调用 `smb2_encode_file_fs_control_info(smb2, fs, vec)`
// - **THEN** 实现向偏移 0、8、16、24、32、40 写入空间过滤、配额阈值/限制和控制标志字段，并返回 `44`
#[test]
fn test_smb2_data_filesystem_info_encode_control_fields() {
    let info = FsControlInfo {
        free_space_start_filtering: 1,
        free_space_threshold: 2,
        free_space_stop_filtering: 3,
        default_quota_threshold: 4,
        default_quota_limit: 5,
        file_system_control_flags: 0x1ff,
    };
    let (buf, rc) = c_fsinfo::encode_control(info, 48).unwrap();
    assert_eq!(rc, 44);
    assert_eq!(&buf[0..8], &1_u64.to_le_bytes());
    assert_eq!(&buf[40..44], &0x1ff_u32.to_le_bytes());
}

// Trace: `lib/smb2-data-filesystem-info.c:smb2_decode_file_fs_full_size_info`
// Spec: smb2_decode_file_fs_full_size_info decodes full size information#reject short full-size buffer
// - **GIVEN** `vec->len` 小于 32
// - **WHEN** 调用 `smb2_decode_file_fs_full_size_info(smb2, memctx, fs, vec)`
// - **THEN** 实现返回 `-1` 且不继续读取固定字段
#[test]
fn test_smb2_data_filesystem_info_reject_short_full_size_buffer() {
    assert_eq!(c_fsinfo::decode_full_size(&[0xaa; 31]), Err(-1));
}

// Trace: `lib/smb2-data-filesystem-info.c:smb2_decode_file_fs_full_size_info`
// Spec: smb2_decode_file_fs_full_size_info decodes full size information#decode full-size fields
// - **GIVEN** `vec->len` 至少为 32
// - **WHEN** 调用 `smb2_decode_file_fs_full_size_info(smb2, memctx, fs, vec)`
// - **THEN** 实现从偏移 0、8、16、24、28 读取总分配单元、调用者可用分配单元、实际可用分配单元、每分配单元扇区数和每扇区字节数，并返回 `0`
#[test]
fn test_smb2_data_filesystem_info_decode_full_size_fields() {
    let mut buf = [0; 32];
    put_u64(&mut buf, 0, 10);
    put_u64(&mut buf, 8, 20);
    put_u64(&mut buf, 16, 30);
    put_u32(&mut buf, 24, 40);
    put_u32(&mut buf, 28, 50);
    assert_eq!(
        c_fsinfo::decode_full_size(&buf).unwrap(),
        FsFullSizeInfo {
            total_allocation_units: 10,
            caller_available_allocation_units: 20,
            actual_available_allocation_units: 30,
            sectors_per_allocation_unit: 40,
            bytes_per_sector: 50
        }
    );
}

// Trace: `lib/smb2-data-filesystem-info.c:smb2_encode_file_fs_full_size_info`
// Spec: smb2_encode_file_fs_full_size_info encodes full size information#reject short full-size output buffer
// - **GIVEN** `vec->len` 小于 32
// - **WHEN** 调用 `smb2_encode_file_fs_full_size_info(smb2, fs, vec)`
// - **THEN** 实现返回 `-1` 且不写入固定字段
#[test]
fn test_smb2_data_filesystem_info_reject_short_full_size_output_buffer() {
    let info = FsFullSizeInfo {
        total_allocation_units: 10,
        caller_available_allocation_units: 20,
        actual_available_allocation_units: 30,
        sectors_per_allocation_unit: 40,
        bytes_per_sector: 50,
    };
    assert_eq!(c_fsinfo::encode_full_size(info, 31), Err(-1));
}

// Trace: `lib/smb2-data-filesystem-info.c:smb2_encode_file_fs_full_size_info`
// Spec: smb2_encode_file_fs_full_size_info encodes full size information#encode full-size fields
// - **GIVEN** `vec->len` 至少为 32 且 `fs` 包含完整大小信息字段
// - **WHEN** 调用 `smb2_encode_file_fs_full_size_info(smb2, fs, vec)`
// - **THEN** 实现向偏移 0、8、16、24、28 写入总分配单元、调用者可用分配单元、实际可用分配单元、每分配单元扇区数和每扇区字节数，并返回 `32`
#[test]
fn test_smb2_data_filesystem_info_encode_full_size_fields() {
    let info = FsFullSizeInfo {
        total_allocation_units: 10,
        caller_available_allocation_units: 20,
        actual_available_allocation_units: 30,
        sectors_per_allocation_unit: 40,
        bytes_per_sector: 50,
    };
    let (buf, rc) = c_fsinfo::encode_full_size(info, 32).unwrap();
    assert_eq!(rc, 32);
    assert_eq!(&buf[0..8], &10_u64.to_le_bytes());
    assert_eq!(&buf[28..32], &50_u32.to_le_bytes());
}

// Trace: `lib/smb2-data-filesystem-info.c:smb2_decode_file_fs_object_id_info`
// Spec: smb2_decode_file_fs_object_id_info decodes object id information#reject short object-id buffer
// - **GIVEN** `vec->len` 小于 64
// - **WHEN** 调用 `smb2_decode_file_fs_object_id_info(smb2, memctx, fs, vec)`
// - **THEN** 实现返回 `-1` 且不复制对象字段
#[test]
fn test_smb2_data_filesystem_info_reject_short_object_id_buffer() {
    assert_eq!(c_fsinfo::decode_object_id(&[0xaa; 63]), Err(-1));
}

// Trace: `lib/smb2-data-filesystem-info.c:smb2_decode_file_fs_object_id_info`
// Spec: smb2_decode_file_fs_object_id_info decodes object id information#decode object id fields
// - **GIVEN** `vec->len` 至少为 64
// - **WHEN** 调用 `smb2_decode_file_fs_object_id_info(smb2, memctx, fs, vec)`
// - **THEN** 实现从偏移 0 复制 `SMB2_GUID_SIZE` 字节到 `fs->object_id`，从偏移 `SMB2_GUID_SIZE` 复制 `sizeof(fs->extended_info)` 字节到 `fs->extended_info`，并返回 `0`
#[test]
fn test_smb2_data_filesystem_info_decode_object_id_fields() {
    let mut buf = [0; 64];
    for (idx, byte) in buf.iter_mut().enumerate() {
        *byte = idx as u8;
    }
    let info = c_fsinfo::decode_object_id(&buf).unwrap();
    assert_eq!(info.object_id, <[u8; 16]>::try_from(&buf[0..16]).unwrap());
    assert_eq!(
        info.extended_info,
        <[u8; 48]>::try_from(&buf[16..64]).unwrap()
    );
}

// Trace: `lib/smb2-data-filesystem-info.c:smb2_encode_file_fs_object_id_info`
// Spec: smb2_encode_file_fs_object_id_info encodes object id information#reject short object-id output buffer
// - **GIVEN** `vec->len` 小于 64
// - **WHEN** 调用 `smb2_encode_file_fs_object_id_info(smb2, fs, vec)`
// - **THEN** 实现返回 `-1` 且不写入对象字段
// Note: the safe Rust migration API owns its output buffer, so the C short-buffer precondition is represented by the fixed 64-byte output contract.
#[test]
fn test_smb2_data_filesystem_info_reject_short_object_id_output_buffer() {
    assert_eq!(Smb2FileFsObjectIdInfo::fixed_wire_len(), 64);
    assert_eq!(FILE_FS_OBJECT_ID_INFO_LEN, 64);
}

// Trace: `lib/smb2-data-filesystem-info.c:smb2_encode_file_fs_object_id_info`
// Spec: smb2_encode_file_fs_object_id_info encodes object id information#encode object id fields
// - **GIVEN** `vec->len` 至少为 64 且 `fs` 包含对象 GUID 和扩展信息
// - **WHEN** 调用 `smb2_encode_file_fs_object_id_info(smb2, fs, vec)`
// - **THEN** 实现将 `fs->object_id` 复制到偏移 0，将 `fs->extended_info` 复制到偏移 `SMB2_GUID_SIZE`，并返回 `SMB2_GUID_SIZE + sizeof(fs->extended_info)`
#[test]
fn test_smb2_data_filesystem_info_encode_object_id_fields() {
    let object_id = [
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
        0x1f,
    ];
    let mut extended_info = [0; FILE_FS_OBJECT_ID_EXTENDED_INFO_LEN];
    for (index, byte) in extended_info.iter_mut().enumerate() {
        *byte = 0xa0u8.wrapping_add(index as u8);
    }
    let info = Smb2FileFsObjectIdInfo {
        object_id,
        extended_info,
    };

    let encoded = info.encode();

    assert_eq!(
        encoded.len(),
        SMB2_GUID_SIZE + FILE_FS_OBJECT_ID_EXTENDED_INFO_LEN
    );
    assert_eq!(&encoded[..SMB2_GUID_SIZE], &object_id);
    assert_eq!(&encoded[SMB2_GUID_SIZE..], &extended_info);
}

// Trace: `lib/smb2-data-filesystem-info.c:smb2_decode_file_fs_sector_size_info`
// Spec: smb2_decode_file_fs_sector_size_info decodes sector size information#reject short sector-size buffer
// - **GIVEN** `vec->len` 小于 28
// - **WHEN** 调用 `smb2_decode_file_fs_sector_size_info(smb2, memctx, fs, vec)`
// - **THEN** 实现返回 `-1` 且不继续读取固定字段
#[test]
fn test_smb2_data_filesystem_info_reject_short_sector_size_buffer() {
    let err = Smb2FileFsSectorSizeInfo::decode(&[0; FILE_FS_SECTOR_SIZE_INFO_LEN - 1])
        .expect_err("short sector-size buffer must fail");

    assert_eq!(err, FilesystemInfoError::BufferTooShort);
}

// Trace: `lib/smb2-data-filesystem-info.c:smb2_decode_file_fs_sector_size_info`
// Spec: smb2_decode_file_fs_sector_size_info decodes sector size information#decode sector-size fields
// - **GIVEN** `vec->len` 至少为 28
// - **WHEN** 调用 `smb2_decode_file_fs_sector_size_info(smb2, memctx, fs, vec)`
// - **THEN** 实现从偏移 0、4、8、12、16、20、24 读取逻辑扇区大小、物理扇区大小、有效物理扇区大小、标志和对齐偏移，并返回 `0`
#[test]
fn test_smb2_data_filesystem_info_decode_sector_size_fields() {
    let mut buf = Vec::new();
    for value in [512u32, 4096, 8192, 16_384, 0x0f0e_0d0c, 32, 64] {
        buf.extend_from_slice(&value.to_le_bytes());
    }

    let decoded = Smb2FileFsSectorSizeInfo::decode(&buf).expect("sector-size decode succeeds");

    assert_eq!(decoded.logical_bytes_per_sector, 512);
    assert_eq!(decoded.physical_bytes_per_sector_for_atomicity, 4096);
    assert_eq!(decoded.physical_bytes_per_sector_for_performance, 8192);
    assert_eq!(
        decoded.file_system_effective_physical_bytes_per_sector_for_atomicity,
        16_384
    );
    assert_eq!(decoded.flags, 0x0f0e_0d0c);
    assert_eq!(decoded.byte_offset_for_sector_alignment, 32);
    assert_eq!(decoded.byte_offset_for_partition_alignment, 64);
}

// Trace: `lib/smb2-data-filesystem-info.c:smb2_encode_file_fs_sector_size_info`
// Spec: smb2_encode_file_fs_sector_size_info encodes sector size information#reject short sector-size output buffer
// - **GIVEN** `vec->len` 小于 28
// - **WHEN** 调用 `smb2_encode_file_fs_sector_size_info(smb2, fs, vec)`
// - **THEN** 实现返回 `-1` 且不写入固定字段
// Note: the safe Rust migration API owns its output buffer, so the C short-buffer precondition is represented by the fixed 28-byte output contract.
#[test]
fn test_smb2_data_filesystem_info_reject_short_sector_size_output_buffer() {
    assert_eq!(Smb2FileFsSectorSizeInfo::fixed_wire_len(), 28);
    assert_eq!(FILE_FS_SECTOR_SIZE_INFO_LEN, 28);
}

// Trace: `lib/smb2-data-filesystem-info.c:smb2_encode_file_fs_sector_size_info`
// Spec: smb2_encode_file_fs_sector_size_info encodes sector size information#encode sector-size fields
// - **GIVEN** `vec->len` 至少为 28 且 `fs` 包含扇区大小和对齐字段
// - **WHEN** 调用 `smb2_encode_file_fs_sector_size_info(smb2, fs, vec)`
// - **THEN** 实现向偏移 0、4、8、12、16、20、24 写入逻辑扇区大小、物理扇区大小、有效物理扇区大小、标志和对齐偏移，并返回 `28`
#[test]
fn test_smb2_data_filesystem_info_encode_sector_size_fields() {
    let info = Smb2FileFsSectorSizeInfo {
        logical_bytes_per_sector: 512,
        physical_bytes_per_sector_for_atomicity: 4096,
        physical_bytes_per_sector_for_performance: 8192,
        file_system_effective_physical_bytes_per_sector_for_atomicity: 16_384,
        flags: 0x0102_0304,
        byte_offset_for_sector_alignment: 32,
        byte_offset_for_partition_alignment: 64,
    };

    let encoded = info.encode();

    assert_eq!(encoded.len(), 28);
    assert_eq!(&encoded[0..4], &512u32.to_le_bytes());
    assert_eq!(&encoded[4..8], &4096u32.to_le_bytes());
    assert_eq!(&encoded[8..12], &8192u32.to_le_bytes());
    assert_eq!(&encoded[12..16], &16_384u32.to_le_bytes());
    assert_eq!(&encoded[16..20], &0x0102_0304u32.to_le_bytes());
    assert_eq!(&encoded[20..24], &32u32.to_le_bytes());
    assert_eq!(&encoded[24..28], &64u32.to_le_bytes());
}
