use libsmb2_rs::lib::smb2_data_file_info::{
    self as file_info, FileInfoError, Smb2FileAllInfo, Smb2FileBasicInfo, Smb2FileNameInfo,
    Smb2FileNetworkOpenInfo, Smb2FilePositionInfo, Smb2FileStandardInfo, Smb2FileStreamInfo,
    FILE_ALL_INFO_PREFIX_SIZE, FILE_BASIC_INFO_SIZE, FILE_NETWORK_OPEN_INFO_SIZE,
    FILE_POSITION_INFO_SIZE, FILE_STANDARD_INFO_SIZE,
};
use libsmb2_rs::lib::timestamps::Smb2Timeval;

fn put_u32(buf: &mut [u8], offset: usize, value: u32) {
    buf[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn put_u64(buf: &mut [u8], offset: usize, value: u64) {
    buf[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

// Trace: `lib/smb2-data-file-info.c:smb2_decode_file_basic_info`
// Spec: smb2_decode_file_basic_info fixed layout decode#解码 basic info 固定字段
// - **GIVEN** `vec` 指向至少包含 basic info 固定字段的 SMB2 字节序载荷，`fs` 指向可写 `struct smb2_file_basic_info`
// - **WHEN** 调用 `smb2_decode_file_basic_info(smb2, memctx, fs, vec)`
// - **THEN** implementation MUST 读取偏移 0、8、16、24 的 64-bit 时间戳并写入 creation/access/write/change time，读取偏移 32 的 attributes，并返回 `0`
#[test]
fn test_smb2_data_file_info_decode_basic_fixed_fields() {
    let mut buf = [0; FILE_BASIC_INFO_SIZE];
    put_u64(&mut buf, 0, 116_444_736_010_000_000);
    put_u64(&mut buf, 8, 116_444_736_020_000_000);
    put_u64(&mut buf, 16, 116_444_736_030_000_000);
    put_u64(&mut buf, 24, 116_444_736_040_000_000);
    put_u32(&mut buf, 32, 0x20);

    let decoded = file_info::smb2_decode_file_basic_info(&buf).unwrap();

    assert_eq!(decoded.creation_time.tv_sec, 1);
    assert_eq!(decoded.last_access_time.tv_sec, 2);
    assert_eq!(decoded.last_write_time.tv_sec, 3);
    assert_eq!(decoded.change_time.tv_sec, 4);
    assert_eq!(decoded.file_attributes, 0x20);
}

// Trace: `lib/smb2-data-file-info.c:smb2_encode_file_basic_info`
// Spec: smb2_encode_file_basic_info fixed layout encode#编码 basic info 固定字段
// - **GIVEN** `fs` 包含 basic info 时间戳和属性，`vec` 指向可写输出缓冲区
// - **WHEN** 调用 `smb2_encode_file_basic_info(smb2, fs, vec)`
// - **THEN** implementation MUST 写入偏移 0、8、16、24 的 64-bit SMB 时间戳、偏移 32 的 attributes、偏移 36 的零值保留字段，并返回 `40`
#[test]
fn test_smb2_data_file_info_encode_basic_fixed_fields() {
    let info = Smb2FileBasicInfo {
        creation_time: Smb2Timeval {
            tv_sec: 1,
            tv_usec: 0,
        },
        file_attributes: 0x80,
        ..Smb2FileBasicInfo::default()
    };
    let mut buf = [0xff; FILE_BASIC_INFO_SIZE];

    let written = file_info::smb2_encode_file_basic_info(&info, &mut buf).unwrap();

    assert_eq!(written, FILE_BASIC_INFO_SIZE);
    assert_eq!(
        u64::from_le_bytes(buf[0..8].try_into().unwrap()),
        116_444_736_010_000_000
    );
    assert_eq!(u32::from_le_bytes(buf[32..36].try_into().unwrap()), 0x80);
    assert_eq!(u32::from_le_bytes(buf[36..40].try_into().unwrap()), 0);
}

// Trace: `lib/smb2-data-file-info.c:smb2_encode_file_basic_info`
// Spec: smb2_encode_file_basic_info fixed layout encode#编码 timeval 哨兵值
// - **GIVEN** 任一输入 `struct smb2_timeval` 为 `{0, 0}` 或 `{0xffffffff, 0xffffffff}`
// - **WHEN** 调用 `smb2_encode_file_basic_info(smb2, fs, vec)`
// - **THEN** implementation MUST 分别编码为 `0` 或 `0xffffffffffffffffULL`，其他 timeval MUST 通过 `smb2_timeval_to_win` 转换
#[test]
fn test_smb2_data_file_info_encode_basic_timeval_sentinel() {
    let info = Smb2FileBasicInfo {
        creation_time: Smb2Timeval::default(),
        last_access_time: Smb2Timeval {
            tv_sec: 0xffff_ffff,
            tv_usec: 0xffff_ffff,
        },
        ..Smb2FileBasicInfo::default()
    };
    let mut buf = [0; FILE_BASIC_INFO_SIZE];

    file_info::smb2_encode_file_basic_info(&info, &mut buf).unwrap();

    assert_eq!(u64::from_le_bytes(buf[0..8].try_into().unwrap()), 0);
    assert_eq!(u64::from_le_bytes(buf[8..16].try_into().unwrap()), u64::MAX);
}

// Trace: `lib/smb2-data-file-info.c:smb2_decode_file_standard_info`
// Spec: smb2_decode_file_standard_info fixed layout decode#解码 standard info 固定字段
// - **GIVEN** `vec` 指向 standard info 固定字段载荷，`fs` 指向可写 `struct smb2_file_standard_info`
// - **WHEN** 调用 `smb2_decode_file_standard_info(smb2, memctx, fs, vec)`
// - **THEN** implementation MUST 读取偏移 0、8 的 64-bit 字段、偏移 16 的 32-bit link count、偏移 20 和 21 的 8-bit flags，并返回 `0`
#[test]
fn test_smb2_data_file_info_decode_standard_fixed_fields() {
    let mut buf = [0; FILE_STANDARD_INFO_SIZE];
    put_u64(&mut buf, 0, 11);
    put_u64(&mut buf, 8, 22);
    put_u32(&mut buf, 16, 3);
    buf[20] = 1;
    buf[21] = 0;

    let decoded = file_info::smb2_decode_file_standard_info(&buf).unwrap();

    assert_eq!(decoded.allocation_size, 11);
    assert_eq!(decoded.end_of_file, 22);
    assert_eq!(decoded.number_of_links, 3);
    assert_eq!(decoded.delete_pending, 1);
    assert_eq!(decoded.directory, 0);
}

// Trace: `lib/smb2-data-file-info.c:smb2_encode_file_standard_info`
// Spec: smb2_encode_file_standard_info fixed layout encode#编码 standard info 固定字段
// - **GIVEN** `fs` 包含 standard info 字段，`vec` 指向可写输出缓冲区
// - **WHEN** 调用 `smb2_encode_file_standard_info(smb2, fs, vec)`
// - **THEN** implementation MUST 写入 allocation size、EOF、link count、delete pending、directory 和偏移 22 的 16-bit 零值保留字段，并返回 `24`
#[test]
fn test_smb2_data_file_info_encode_standard_fixed_fields() {
    let info = Smb2FileStandardInfo {
        allocation_size: 11,
        end_of_file: 22,
        number_of_links: 3,
        delete_pending: 1,
        directory: 0,
    };
    let mut buf = [0xff; FILE_STANDARD_INFO_SIZE];

    let written = file_info::smb2_encode_file_standard_info(&info, &mut buf).unwrap();

    assert_eq!(written, FILE_STANDARD_INFO_SIZE);
    assert_eq!(u64::from_le_bytes(buf[0..8].try_into().unwrap()), 11);
    assert_eq!(u16::from_le_bytes(buf[22..24].try_into().unwrap()), 0);
}

// Trace: `lib/smb2-data-file-info.c:smb2_decode_file_stream_info`
// Spec: smb2_decode_file_stream_info chained stream decode#解码 stream info 链表
// - **GIVEN** `vec` 包含一个或多个 stream info 条目，`fs` 指向足够容纳结果条目的数组
// - **WHEN** 调用 `smb2_decode_file_stream_info(smb2, memctx, fs, vec)`
// - **THEN** implementation MUST 读取每个条目的 next offset、name length、stream size 和 allocation size，成功转换名称时 MUST 设置 UTF-8 `stream_name` 和按 UTF-8 字节数更新 `stream_name_length`
#[test]
fn test_smb2_data_file_info_decode_stream_chain() {
    let entries = vec![
        Smb2FileStreamInfo {
            stream_size: 7,
            stream_allocation_size: 8,
            stream_name: Some(":one:$DATA".to_string()),
            ..Smb2FileStreamInfo::default()
        },
        Smb2FileStreamInfo {
            stream_size: 9,
            stream_allocation_size: 10,
            stream_name: Some(":two:$DATA".to_string()),
            ..Smb2FileStreamInfo::default()
        },
    ];
    let mut buf = vec![0; 128];
    let len = file_info::smb2_encode_file_stream_info(&entries, &mut buf).unwrap();

    let decoded = file_info::smb2_decode_file_stream_info(&buf[..len]).unwrap();

    assert_eq!(decoded.len(), 2);
    assert_eq!(decoded[0].stream_name.as_deref(), Some(":one:$DATA"));
    assert_eq!(decoded[1].stream_size, 9);
}

// Trace: `lib/smb2-data-file-info.c:smb2_decode_file_stream_info`
// Spec: smb2_decode_file_stream_info chained stream decode#解码 stream info 截断或失败
// - **GIVEN** stream name length 超出剩余 `vec->len`，或 UTF-16 转换/内存分配失败
// - **WHEN** 调用 `smb2_decode_file_stream_info(smb2, memctx, fs, vec)`
// - **THEN** implementation MUST 将名称读取长度截断到剩余载荷；转换或分配失败时 MUST 返回 `-1`
#[test]
fn test_smb2_data_file_info_decode_stream_truncate_failure() {
    let mut buf = vec![0; 24];
    put_u32(&mut buf, 4, 4);

    assert!(matches!(
        file_info::smb2_decode_file_stream_info(&buf),
        Err(FileInfoError::BufferTooShort { .. })
    ));
}

// Trace: `lib/smb2-data-file-info.c:smb2_encode_file_stream_info`
// Spec: smb2_encode_file_stream_info chained stream encode#编码 stream info 链表
// - **GIVEN** `fs` 指向 stream info 链表，`vec` 指向可写输出缓冲区
// - **WHEN** 调用 `smb2_encode_file_stream_info(smb2, fs, vec)`
// - **THEN** implementation MUST 将 UTF-8 stream name 转换为 UTF-16，写入名称长度、大小字段和 next offset，非末尾条目 MUST 用零字节填充到 64-bit 对齐并返回写入总字节数
#[test]
fn test_smb2_data_file_info_encode_stream_chain() {
    let entries = [Smb2FileStreamInfo {
        stream_size: 7,
        stream_allocation_size: 8,
        stream_name: Some(":alt:$DATA".to_string()),
        ..Smb2FileStreamInfo::default()
    }];
    let mut buf = vec![0; 64];

    let written = file_info::smb2_encode_file_stream_info(&entries, &mut buf).unwrap();

    assert_eq!(u32::from_le_bytes(buf[0..4].try_into().unwrap()), 0);
    assert_eq!(u64::from_le_bytes(buf[8..16].try_into().unwrap()), 7);
    assert_eq!(written, 24 + ":alt:$DATA".encode_utf16().count() * 2);
}

// Trace: `lib/smb2-data-file-info.c:smb2_decode_file_position_info`
// Spec: smb2_decode_file_position_info fixed layout decode#解码 position info
// - **GIVEN** `vec` 指向包含 64-bit current byte offset 的载荷，`fs` 指向可写 position info
// - **WHEN** 调用 `smb2_decode_file_position_info(smb2, memctx, fs, vec)`
// - **THEN** implementation MUST 从偏移 0 读取 current byte offset 并返回 `0`
#[test]
fn test_smb2_data_file_info_decode_position_info() {
    let mut buf = [0; FILE_POSITION_INFO_SIZE];
    put_u64(&mut buf, 0, 0x1122_3344_5566_7788);

    let decoded = file_info::smb2_decode_file_position_info(&buf).unwrap();

    assert_eq!(decoded.current_byte_offset, 0x1122_3344_5566_7788);
}

// Trace: `lib/smb2-data-file-info.c:smb2_encode_file_position_info`
// Spec: smb2_encode_file_position_info fixed layout encode#编码 position info
// - **GIVEN** `fs` 包含 current byte offset，`vec` 指向可写输出缓冲区
// - **WHEN** 调用 `smb2_encode_file_position_info(smb2, fs, vec)`
// - **THEN** implementation MUST 在偏移 0 写入 current byte offset 并返回 `8`
#[test]
fn test_smb2_data_file_info_encode_position_info() {
    let info = Smb2FilePositionInfo {
        current_byte_offset: 0x1122,
    };
    let mut buf = [0; FILE_POSITION_INFO_SIZE];

    let written = file_info::smb2_encode_file_position_info(&info, &mut buf).unwrap();

    assert_eq!(written, FILE_POSITION_INFO_SIZE);
    assert_eq!(u64::from_le_bytes(buf.try_into().unwrap()), 0x1122);
}

// Trace: `lib/smb2-data-file-info.c:smb2_decode_file_all_info`
// Spec: smb2_decode_file_all_info aggregate decode#解码 all info 聚合字段
// - **GIVEN** `vec->len` 至少包含 100 字节 fixed/name-length 区域，`fs` 指向可写 all info
// - **WHEN** 调用 `smb2_decode_file_all_info(smb2, memctx, fs, vec)`
// - **THEN** implementation MUST 先解码 basic 和 standard 子结构，再读取 index、EA size、access flags、position、mode、alignment、name length 和可选 UTF-8 name，并在成功时返回 `0`
#[test]
fn test_smb2_data_file_info_decode_all_info_aggregate() {
    let info = Smb2FileAllInfo {
        standard: Smb2FileStandardInfo {
            allocation_size: 11,
            ..Smb2FileStandardInfo::default()
        },
        index_number: 99,
        name: Some("name".to_string()),
        ..Smb2FileAllInfo::default()
    };
    let mut buf = vec![0; FILE_ALL_INFO_PREFIX_SIZE + 16];
    let len = file_info::smb2_encode_file_all_info(&info, &mut buf).unwrap();

    let decoded = file_info::smb2_decode_file_all_info(&buf[..len]).unwrap();

    assert_eq!(decoded.standard.allocation_size, 11);
    assert_eq!(decoded.index_number, 99);
    assert_eq!(decoded.name.as_deref(), Some("name"));
}

// Trace: `lib/smb2-data-file-info.c:smb2_decode_file_all_info`
// Spec: smb2_decode_file_all_info aggregate decode#解码 all info 长度和名称失败
// - **GIVEN** `vec->len` 小于 40 或 64，或名称转换/分配失败
// - **WHEN** 调用 `smb2_decode_file_all_info(smb2, memctx, fs, vec)`
// - **THEN** implementation MUST 返回 `-1`; 当名称长度超过剩余载荷时 MUST 将名称读取长度截断到 `vec->len - 100`
#[test]
fn test_smb2_data_file_info_decode_all_info_length_name_failure() {
    let mut buf = vec![0; FILE_ALL_INFO_PREFIX_SIZE + 2];
    put_u32(&mut buf, 96, 4);

    assert!(matches!(
        file_info::smb2_decode_file_all_info(&buf),
        Err(FileInfoError::BufferTooShort { .. })
    ));
}

// Trace: `lib/smb2-data-file-info.c:smb2_encode_file_all_info`
// Spec: smb2_encode_file_all_info aggregate encode#编码 all info 聚合字段
// - **GIVEN** `vec->len` 至少为 64，`fs` 包含 all info 字段
// - **WHEN** 调用 `smb2_encode_file_all_info(smb2, fs, vec)`
// - **THEN** implementation MUST 编码 basic 和 standard 子结构，写入 index、EA size、access flags、position、mode、alignment；名称存在时 MUST 写入 UTF-16 名称长度和字节并返回 `100 + name_len`，名称为空时 MUST 写入名称长度 `0` 并返回 `100`
#[test]
fn test_smb2_data_file_info_encode_all_info_aggregate() {
    let info = Smb2FileAllInfo {
        index_number: 99,
        name: Some("xy".to_string()),
        ..Smb2FileAllInfo::default()
    };
    let mut buf = vec![0; FILE_ALL_INFO_PREFIX_SIZE + 4];

    let written = file_info::smb2_encode_file_all_info(&info, &mut buf).unwrap();

    assert_eq!(written, FILE_ALL_INFO_PREFIX_SIZE + 4);
    assert_eq!(u64::from_le_bytes(buf[64..72].try_into().unwrap()), 99);
    assert_eq!(u32::from_le_bytes(buf[96..100].try_into().unwrap()), 4);
}

// Trace: `lib/smb2-data-file-info.c:smb2_encode_file_all_info`
// Spec: smb2_encode_file_all_info aggregate encode#编码 all info 长度或转换失败
// - **GIVEN** `vec->len` 小于 40 或 64，或名称 UTF-8 到 UTF-16 转换失败
// - **WHEN** 调用 `smb2_encode_file_all_info(smb2, fs, vec)`
// - **THEN** implementation MUST 返回 `-1`
#[test]
fn test_smb2_data_file_info_encode_all_info_length_conversion_failure() {
    let info = Smb2FileAllInfo::default();
    let mut buf = vec![0; FILE_ALL_INFO_PREFIX_SIZE - 1];

    assert!(matches!(
        file_info::smb2_encode_file_all_info(&info, &mut buf),
        Err(FileInfoError::BufferTooShort { .. })
    ));
}

// Trace: `lib/smb2-data-file-info.c:smb2_decode_file_network_open_info`
// Spec: smb2_decode_file_network_open_info fixed layout decode#解码 network open info
// - **GIVEN** `vec->len` 至少为 56，`fs` 指向可写 network open info
// - **WHEN** 调用 `smb2_decode_file_network_open_info(smb2, memctx, fs, vec)`
// - **THEN** implementation MUST 解码四个 64-bit SMB 时间戳、allocation size、EOF 和 attributes，并返回 `0`
#[test]
fn test_smb2_data_file_info_decode_network_open_info() {
    let mut buf = [0; FILE_NETWORK_OPEN_INFO_SIZE];
    put_u64(&mut buf, 32, 100);
    put_u64(&mut buf, 40, 200);
    put_u32(&mut buf, 48, 0x20);

    let decoded = file_info::smb2_decode_file_network_open_info(&buf).unwrap();

    assert_eq!(decoded.allocation_size, 100);
    assert_eq!(decoded.end_of_file, 200);
    assert_eq!(decoded.file_attributes, 0x20);
}

// Trace: `lib/smb2-data-file-info.c:smb2_decode_file_network_open_info`
// Spec: smb2_decode_file_network_open_info fixed layout decode#拒绝过短 network open info
// - **GIVEN** `vec->len` 小于 56
// - **WHEN** 调用 `smb2_decode_file_network_open_info(smb2, memctx, fs, vec)`
// - **THEN** implementation MUST 返回 `-1`
#[test]
fn test_smb2_data_file_info_reject_short_network_open_info() {
    assert!(matches!(
        file_info::smb2_decode_file_network_open_info(&[0; FILE_NETWORK_OPEN_INFO_SIZE - 1]),
        Err(FileInfoError::BufferTooShort { .. })
    ));
}

// Trace: `lib/smb2-data-file-info.c:smb2_encode_file_network_open_info`
// Spec: smb2_encode_file_network_open_info fixed layout encode#编码 network open info
// - **GIVEN** `vec->len` 至少为 56，`fs` 包含 network open info 字段
// - **WHEN** 调用 `smb2_encode_file_network_open_info(smb2, fs, vec)`
// - **THEN** implementation MUST 编码四个 SMB 时间戳、allocation size、EOF、attributes 和偏移 52 的 32-bit 零值保留字段，并返回 `56`
#[test]
fn test_smb2_data_file_info_encode_network_open_info() {
    let info = Smb2FileNetworkOpenInfo {
        allocation_size: 100,
        end_of_file: 200,
        file_attributes: 0x20,
        ..Smb2FileNetworkOpenInfo::default()
    };
    let mut buf = [0xff; FILE_NETWORK_OPEN_INFO_SIZE];

    let written = file_info::smb2_encode_file_network_open_info(&info, &mut buf).unwrap();

    assert_eq!(written, FILE_NETWORK_OPEN_INFO_SIZE);
    assert_eq!(u64::from_le_bytes(buf[32..40].try_into().unwrap()), 100);
    assert_eq!(u32::from_le_bytes(buf[52..56].try_into().unwrap()), 0);
}

// Trace: `lib/smb2-data-file-info.c:smb2_encode_file_network_open_info`
// Spec: smb2_encode_file_network_open_info fixed layout encode#拒绝过短 network open encode buffer
// - **GIVEN** `vec->len` 小于 56
// - **WHEN** 调用 `smb2_encode_file_network_open_info(smb2, fs, vec)`
// - **THEN** implementation MUST 返回 `-1`
#[test]
fn test_smb2_data_file_info_reject_short_network_open_encode() {
    let mut buf = [0; FILE_NETWORK_OPEN_INFO_SIZE - 1];

    assert!(matches!(
        file_info::smb2_encode_file_network_open_info(
            &Smb2FileNetworkOpenInfo::default(),
            &mut buf
        ),
        Err(FileInfoError::BufferTooShort { .. })
    ));
}

// Trace: `lib/smb2-data-file-info.c:smb2_decode_file_normalized_name_info`
// Spec: smb2_decode_file_normalized_name_info name decode#解码 normalized name
// - **GIVEN** `vec->len` 至少为 4，且 name length 指示存在名称载荷
// - **WHEN** 调用 `smb2_decode_file_normalized_name_info(smb2, memctx, fs, vec)`
// - **THEN** implementation MUST 读取 name length，将 UTF-16 名称转换为 UTF-8，使用 `smb2_alloc_data` 分配输出名称，并在成功时返回 `0`
#[test]
fn test_smb2_data_file_info_decode_normalized_name() {
    let info = Smb2FileNameInfo {
        file_name_length: 0,
        name: Some("abc".to_string()),
    };
    let mut buf = vec![0; 16];
    let len = file_info::smb2_encode_file_normalized_name_info(&info, &mut buf).unwrap();

    let decoded = file_info::smb2_decode_file_normalized_name_info(&buf[..len]).unwrap();

    assert_eq!(decoded.file_name_length, 6);
    assert_eq!(decoded.name.as_deref(), Some("abc"));
}

// Trace: `lib/smb2-data-file-info.c:smb2_decode_file_normalized_name_info`
// Spec: smb2_decode_file_normalized_name_info name decode#解码 normalized name 边界和失败
// - **GIVEN** `vec->len` 小于 4，或 UTF-16 转换/名称分配失败
// - **WHEN** 调用 `smb2_decode_file_normalized_name_info(smb2, memctx, fs, vec)`
// - **THEN** implementation MUST 返回 `-1`; 当声明名称长度超过剩余载荷时 MUST 截断读取长度，名称长度为 0 或截断后无名称时 MUST 设置 `fs->name` 为 `NULL`
#[test]
fn test_smb2_data_file_info_decode_normalized_name_boundary_failure() {
    let mut buf = vec![0; 6];
    put_u32(&mut buf, 0, 4);

    assert!(matches!(
        file_info::smb2_decode_file_normalized_name_info(&buf),
        Err(FileInfoError::BufferTooShort { .. })
    ));
}

// Trace: `lib/smb2-data-file-info.c:smb2_encode_file_normalized_name_info`
// Spec: smb2_encode_file_normalized_name_info name encode#编码 normalized name
// - **GIVEN** `fs->name` 非空，`vec` 可容纳 4 字节长度字段和 UTF-16 名称
// - **WHEN** 调用 `smb2_encode_file_normalized_name_info(smb2, fs, vec)`
// - **THEN** implementation MUST 将 UTF-8 名称转换为 UTF-16，必要时更新 `fs->file_name_length`，写入名称字节，对声明长度剩余部分写零，并返回 `4 + fs->file_name_length`
#[test]
fn test_smb2_data_file_info_encode_normalized_name() {
    let info = Smb2FileNameInfo {
        file_name_length: 64,
        name: Some("xy".to_string()),
    };
    let mut buf = vec![0; 8];

    let written = file_info::smb2_encode_file_normalized_name_info(&info, &mut buf).unwrap();

    assert_eq!(written, 8);
    assert_eq!(u32::from_le_bytes(buf[0..4].try_into().unwrap()), 4);
    assert_eq!(&buf[4..8], &[b'x', 0, b'y', 0]);
}

// Trace: `lib/smb2-data-file-info.c:smb2_encode_file_normalized_name_info`
// Spec: smb2_encode_file_normalized_name_info name encode#编码 normalized name 空名称或失败
// - **GIVEN** `fs->name` 为空、输出缓冲区不足或 UTF-8 到 UTF-16 转换失败
// - **WHEN** 调用 `smb2_encode_file_normalized_name_info(smb2, fs, vec)`
// - **THEN** implementation MUST 对空名称设置 `fs->file_name_length` 为 `0` 并返回 `4`; 对缓冲区不足或转换失败 MUST 返回 `-1`
#[test]
fn test_smb2_data_file_info_encode_normalized_name_empty_failure() {
    let info = Smb2FileNameInfo::default();
    let mut buf = vec![0xff; 4];

    let written = file_info::smb2_encode_file_normalized_name_info(&info, &mut buf).unwrap();

    assert_eq!(written, 4);
    assert_eq!(u32::from_le_bytes(buf.try_into().unwrap()), 0);
}
