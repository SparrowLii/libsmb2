use libsmb2_rs::lib::smb2_cmd_notify_change;
use libsmb2_rs::lib::smb2_cmd_query_directory;
use libsmb2_sys::smb2::smb2 as protocol;

// Trace: `include/smb2/smb2.h:114`, `specs/include/smb2/smb2.spec.md:25`
// Spec: include/smb2/smb2.h data model summary#SMB2 GUID uses sixteen bytes
// - **GIVEN** 调用方读取 `SMB2_GUID_SIZE`。
// - **WHEN** Rust safe model exposes `Smb2Guid`.
// - **THEN** the GUID model contains exactly 16 bytes.
#[test]
fn test_smb2_guid_uses_sixteen_bytes() {
    let guid: protocol::Smb2Guid = [0; protocol::SMB2_GUID_SIZE];

    assert_eq!(protocol::SMB2_GUID_SIZE, 16);
    assert_eq!(guid.len(), 16);
}

// Trace: `include/smb2/smb2.h:344`, `specs/include/smb2/smb2.spec.md:26`
// Spec: include/smb2/smb2.h data model summary#file id uses sixteen bytes
// - **GIVEN** 调用方读取 `SMB2_FD_SIZE`。
// - **WHEN** Rust safe model exposes `Smb2FileId`.
// - **THEN** the file id model contains exactly 16 bytes.
#[test]
fn test_smb2_file_id_uses_sixteen_bytes() {
    let file_id: protocol::Smb2FileId = [0; protocol::SMB2_FD_SIZE];

    assert_eq!(protocol::SMB2_FD_SIZE, 16);
    assert_eq!(file_id.len(), 16);
}

// Trace: `include/smb2/smb2.h:347`, `specs/include/smb2/smb2.spec.md:27`
// Spec: include/smb2/smb2.h data model summary#lease key uses sixteen bytes
// - **GIVEN** 调用方读取 `SMB2_LEASE_KEY_SIZE`。
// - **WHEN** Rust safe model exposes `Smb2LeaseKey`.
// - **THEN** the lease key model contains exactly 16 bytes.
#[test]
fn test_smb2_lease_key_uses_sixteen_bytes() {
    let lease_key: protocol::Smb2LeaseKey = [0; protocol::SMB2_LEASE_KEY_SIZE];

    assert_eq!(protocol::SMB2_LEASE_KEY_SIZE, 16);
    assert_eq!(lease_key.len(), 16);
}

// Trace: `include/smb2/smb2.h:57-78`, `specs/include/smb2/smb2.spec.md:28`
// Spec: include/smb2/smb2.h data model summary#command enum exposes SMB2 command ids
// - **GIVEN** 调用方读取 `enum smb2_command` command ids.
// - **WHEN** Rust safe model exposes `Smb2Command`.
// - **THEN** NEGOTIATE, READ, WRITE, and SMB1_NEGOTIATE preserve their header values.
#[test]
fn test_smb2_command_enum_preserves_command_ids() {
    assert_eq!(protocol::Smb2Command::Negotiate as u16, 0);
    assert_eq!(protocol::Smb2Command::Read as u16, 8);
    assert_eq!(protocol::Smb2Command::Write as u16, 9);
    assert_eq!(protocol::Smb2Command::Smb1Negotiate as u16, 114);
}

// Trace: `include/smb2/smb2.h:57-78`, `specs/include/smb2/smb2.spec.md:28`
// Spec: include/smb2/smb2.h data model summary#command enum rejects unknown command id
// - **GIVEN** 调用方持有一个未分配 command id.
// - **WHEN** Rust safe model maps the numeric value.
// - **THEN** the value is not mapped to a known `Smb2Command`.
#[test]
fn test_smb2_command_enum_rejects_unknown_command_id() {
    assert_eq!(protocol::Smb2Command::from_u16(19), None);
    assert_eq!(protocol::Smb2Command::from_u16(113), None);
}

// Trace: `include/smb2/smb2.h:49-55`, `specs/include/smb2/smb2.spec.md:29`
// Spec: include/smb2/smb2.h data model summary#header flags expose bit values
// - **GIVEN** 调用方读取 `SMB2_FLAGS_*` constants.
// - **WHEN** Rust safe model exposes the header flag constants.
// - **THEN** signed, DFS, and replay bits preserve their header values.
#[test]
fn test_smb2_header_flags_expose_bit_values() {
    assert_eq!(protocol::SMB2_FLAGS_SIGNED, 0x0000_0008);
    assert_eq!(protocol::SMB2_FLAGS_DFS_OPERATIONS, 0x1000_0000);
    assert_eq!(protocol::SMB2_FLAGS_REPLAY_OPERATION, 0x2000_0000);
}

// Trace: `include/smb2/smb2.h:112`, `specs/include/smb2/smb2.spec.md:30`
// Spec: include/smb2/smb2.h data model summary#negotiate request size is available
// - **GIVEN** 调用方读取 `SMB2_NEGOTIATE_REQUEST_SIZE`.
// - **WHEN** Rust safe model exposes the negotiate request size constant.
// - **THEN** it equals the fixed header value 36.
#[test]
fn test_smb2_negotiate_request_size_is_available() {
    assert_eq!(protocol::SMB2_NEGOTIATE_REQUEST_SIZE, 36);
}

// Trace: `include/smb2/smb2.h:127`, `specs/include/smb2/smb2.spec.md:30`
// Spec: include/smb2/smb2.h data model summary#negotiate reply size is available
// - **GIVEN** 调用方读取 `SMB2_NEGOTIATE_REPLY_SIZE`.
// - **WHEN** Rust safe model exposes the negotiate reply size constant.
// - **THEN** it equals the fixed header value 65.
#[test]
fn test_smb2_negotiate_reply_size_is_available() {
    assert_eq!(protocol::SMB2_NEGOTIATE_REPLY_SIZE, 65);
}

// Trace: `include/smb2/smb2.h:156`, `specs/include/smb2/smb2.spec.md:30`
// Spec: include/smb2/smb2.h data model summary#session setup sizes are available
// - **GIVEN** 调用方读取 session setup request and reply sizes.
// - **WHEN** Rust safe model exposes both size constants.
// - **THEN** they equal the fixed header values 25 and 9.
#[test]
fn test_smb2_session_setup_sizes_are_available() {
    assert_eq!(protocol::SMB2_SESSION_SETUP_REQUEST_SIZE, 25);
    assert_eq!(protocol::SMB2_SESSION_SETUP_REPLY_SIZE, 9);
}

// Trace: `include/smb2/smb2.h:181`, `specs/include/smb2/smb2.spec.md:30`
// Spec: include/smb2/smb2.h data model summary#tree connect sizes are available
// - **GIVEN** 调用方读取 tree connect request and reply sizes.
// - **WHEN** Rust safe model exposes both size constants.
// - **THEN** they equal the fixed header values 9 and 16.
#[test]
fn test_smb2_tree_connect_sizes_are_available() {
    assert_eq!(protocol::SMB2_TREE_CONNECT_REQUEST_SIZE, 9);
    assert_eq!(protocol::SMB2_TREE_CONNECT_REPLY_SIZE, 16);
}

// Trace: `include/smb2/smb2.h:226`, `specs/include/smb2/smb2.spec.md:30`
// Spec: include/smb2/smb2.h data model summary#create sizes are available
// - **GIVEN** 调用方读取 create request and reply sizes.
// - **WHEN** Rust safe model exposes both size constants.
// - **THEN** they equal the fixed header values 57 and 89.
#[test]
fn test_smb2_create_sizes_are_available() {
    assert_eq!(protocol::SMB2_CREATE_REQUEST_SIZE, 57);
    assert_eq!(protocol::SMB2_CREATE_REPLY_SIZE, 89);
}

// Trace: `include/smb2/smb2.h:390`, `specs/include/smb2/smb2.spec.md:30`
// Spec: include/smb2/smb2.h data model summary#close sizes are available
// - **GIVEN** 调用方读取 close request and reply sizes.
// - **WHEN** Rust safe model exposes both size constants.
// - **THEN** they equal the fixed header values 24 and 60.
#[test]
fn test_smb2_close_sizes_are_available() {
    assert_eq!(protocol::SMB2_CLOSE_REQUEST_SIZE, 24);
    assert_eq!(protocol::SMB2_CLOSE_REPLY_SIZE, 60);
}

// Trace: `include/smb2/smb2.h:499`, `specs/include/smb2/smb2.spec.md:36`
// Spec: include/smb2/smb2.h data model summary#directory information size is available
// - **GIVEN** 调用方读取 file-id full directory information size.
// - **WHEN** Rust safe model exposes the size constant.
// - **THEN** it equals the fixed header value 80.
#[test]
fn test_smb2_directory_information_size_is_available() {
    assert_eq!(protocol::SMB2_FILEID_FULL_DIRECTORY_INFORMATION_SIZE, 80);
}

// Trace: `include/smb2/smb2.h:564`, `specs/include/smb2/smb2.spec.md:37`
// Spec: include/smb2/smb2.h data model summary#read sizes are available
// - **GIVEN** 调用方读取 read request and reply sizes.
// - **WHEN** Rust safe model exposes both size constants.
// - **THEN** they equal the fixed header values 49 and 17.
#[test]
fn test_smb2_read_sizes_are_available() {
    assert_eq!(protocol::SMB2_READ_REQUEST_SIZE, 49);
    assert_eq!(protocol::SMB2_READ_REPLY_SIZE, 17);
}

// Trace: `include/smb2/smb2.h:693`, `specs/include/smb2/smb2.spec.md:38`
// Spec: include/smb2/smb2.h data model summary#query info sizes are available
// - **GIVEN** 调用方读取 query info request and reply sizes.
// - **WHEN** Rust safe model exposes both size constants.
// - **THEN** they equal the fixed header values 41 and 9.
#[test]
fn test_smb2_query_info_sizes_are_available() {
    assert_eq!(protocol::SMB2_QUERY_INFO_REQUEST_SIZE, 41);
    assert_eq!(protocol::SMB2_QUERY_INFO_REPLY_SIZE, 9);
}

// Trace: `include/smb2/smb2.h:1016`, `specs/include/smb2/smb2.spec.md:42`
// Spec: include/smb2/smb2.h data model summary#ioctl sizes are available
// - **GIVEN** 调用方读取 ioctl request and reply sizes.
// - **WHEN** Rust safe model exposes both size constants.
// - **THEN** they equal the fixed header values 57 and 49.
#[test]
fn test_smb2_ioctl_sizes_are_available() {
    assert_eq!(protocol::SMB2_IOCTL_REQUEST_SIZE, 57);
    assert_eq!(protocol::SMB2_IOCTL_REPLY_SIZE, 49);
}

// Trace: `include/smb2/smb2.h:1072`, `specs/include/smb2/smb2.spec.md:44`
// Spec: include/smb2/smb2.h data model summary#change notify sizes are available
// - **GIVEN** 调用方读取 change notify request and reply sizes.
// - **WHEN** Rust safe model exposes both size constants.
// - **THEN** they equal the fixed header values 32 and 9.
#[test]
fn test_smb2_change_notify_sizes_are_available() {
    assert_eq!(protocol::SMB2_CHANGE_NOTIFY_REQUEST_SIZE, 32);
    assert_eq!(protocol::SMB2_CHANGE_NOTIFY_REPLY_SIZE, 9);
}

// Trace: `include/smb2/smb2.h:1191`, `specs/include/smb2/smb2.spec.md:46`
// Spec: include/smb2/smb2.h data model summary#write sizes are available
// - **GIVEN** 调用方读取 write request and reply sizes.
// - **WHEN** Rust safe model exposes both size constants.
// - **THEN** they equal the fixed header values 49 and 17.
#[test]
fn test_smb2_write_sizes_are_available() {
    assert_eq!(protocol::SMB2_WRITE_REQUEST_SIZE, 49);
    assert_eq!(protocol::SMB2_WRITE_REPLY_SIZE, 17);
}

// Trace: `include/smb2/smb2.h:1214`, `specs/include/smb2/smb2.spec.md:47`
// Spec: include/smb2/smb2.h data model summary#lock sizes are available
// - **GIVEN** 调用方读取 lock element and request sizes.
// - **WHEN** Rust safe model exposes both size constants.
// - **THEN** they equal the fixed header values 24 and 48.
#[test]
fn test_smb2_lock_sizes_are_available() {
    assert_eq!(protocol::SMB2_LOCK_ELEMENT_SIZE, 24);
    assert_eq!(protocol::SMB2_LOCK_REQUEST_SIZE, 48);
}

// Trace: `include/smb2/smb2.h:117-125`, `specs/include/smb2/smb2.spec.md:31`
// Spec: include/smb2/smb2.h data model summary#negotiate request default preserves fixed dialect capacity
// - **GIVEN** 调用方 constructs a default negotiate request model.
// - **WHEN** Rust safe model initializes `Smb2NegotiateRequest`.
// - **THEN** the dialect array has the fixed `SMB2_NEGOTIATE_MAX_DIALECTS` capacity.
#[test]
fn test_smb2_negotiate_request_default_preserves_fixed_dialect_capacity() {
    let request = protocol::Smb2NegotiateRequest::default();

    assert_eq!(protocol::SMB2_NEGOTIATE_MAX_DIALECTS, 10);
    assert_eq!(
        request.dialects.len(),
        protocol::SMB2_NEGOTIATE_MAX_DIALECTS
    );
}

// Trace: `include/smb2/smb2.h:219-224`, `specs/include/smb2/smb2.spec.md:33`
// Spec: include/smb2/smb2.h data model summary#tree connect reply default exposes share fields
// - **GIVEN** 调用方 constructs a default tree connect reply model.
// - **WHEN** Rust safe model initializes `Smb2TreeConnectReply`.
// - **THEN** share type, share flags, capabilities, and maximal access are zero-initialized fields.
#[test]
fn test_smb2_tree_connect_reply_default_exposes_share_fields() {
    let reply = protocol::Smb2TreeConnectReply::default();

    assert_eq!(reply.share_type, 0);
    assert_eq!(reply.share_flags, 0);
    assert_eq!(reply.capabilities, 0);
    assert_eq!(reply.maximal_access, 0);
}

// Trace: `include/smb2/smb2.h:324-342`, `specs/include/smb2/smb2.spec.md:34`
// Spec: include/smb2/smb2.h data model summary#create request model exposes open parameters
// - **GIVEN** 调用方 constructs a create request model.
// - **WHEN** Rust safe model stores access, attributes, disposition, options, and name.
// - **THEN** those public data-model fields remain observable without raw FFI.
#[test]
fn test_smb2_create_request_model_exposes_open_parameters() {
    let request = protocol::Smb2CreateRequest {
        desired_access: protocol::SMB2_FILE_READ_DATA,
        file_attributes: protocol::SMB2_FILE_ATTRIBUTE_NORMAL,
        create_disposition: 1,
        create_options: 0,
        name: "file.txt".to_owned(),
        ..Default::default()
    };

    assert_eq!(request.desired_access, protocol::SMB2_FILE_READ_DATA);
    assert_eq!(
        request.file_attributes,
        protocol::SMB2_FILE_ATTRIBUTE_NORMAL
    );
    assert_eq!(request.create_disposition, 1);
    assert_eq!(request.name, "file.txt");
}

// Trace: `include/smb2/smb2.h:382-389`, `specs/include/smb2/smb2.spec.md:35`
// Spec: include/smb2/smb2.h data model summary#close request model stores file id
// - **GIVEN** 调用方 constructs a close request model with a file id.
// - **WHEN** Rust safe model stores `file_id`.
// - **THEN** the 16 byte file id remains observable.
#[test]
fn test_smb2_close_request_model_stores_file_id() {
    let request = protocol::Smb2CloseRequest {
        file_id: [0xAB; protocol::SMB2_FD_SIZE],
        ..Default::default()
    };

    assert_eq!(request.file_id, [0xAB; protocol::SMB2_FD_SIZE]);
}

// Trace: `include/smb2/smb2.h:511-525`, `specs/include/smb2/smb2.spec.md:37`
// Spec: include/smb2/smb2.h data model summary#read request model stores offset length and file id
// - **GIVEN** 调用方 constructs a read request model.
// - **WHEN** Rust safe model stores length, offset, and file id.
// - **THEN** those fields remain observable without raw FFI.
#[test]
fn test_smb2_read_request_model_stores_offset_length_and_file_id() {
    let request = protocol::Smb2ReadRequest {
        length: 4096,
        offset: 8192,
        file_id: [1; protocol::SMB2_FD_SIZE],
        ..Default::default()
    };

    assert_eq!(request.length, 4096);
    assert_eq!(request.offset, 8192);
    assert_eq!(request.file_id, [1; protocol::SMB2_FD_SIZE]);
}

// Trace: `include/smb2/smb2.h:672-681`, `specs/include/smb2/smb2.spec.md:38`
// Spec: include/smb2/smb2.h data model summary#query info request model stores info selectors
// - **GIVEN** 调用方 constructs a query info request model.
// - **WHEN** Rust safe model stores info type and file information class.
// - **THEN** those selector fields remain observable without raw FFI.
#[test]
fn test_smb2_query_info_request_model_stores_info_selectors() {
    let request = protocol::Smb2QueryInfoRequest {
        info_type: protocol::SMB2_0_INFO_FILE,
        file_info_class: protocol::SMB2_FILE_ID_FULL_DIRECTORY_INFORMATION,
        output_buffer_length: 1024,
        ..Default::default()
    };

    assert_eq!(request.info_type, protocol::SMB2_0_INFO_FILE);
    assert_eq!(
        request.file_info_class,
        protocol::SMB2_FILE_ID_FULL_DIRECTORY_INFORMATION
    );
    assert_eq!(request.output_buffer_length, 1024);
}

// Trace: `include/smb2/smb2.h:1003-1015`, `specs/include/smb2/smb2.spec.md:42`
// Spec: include/smb2/smb2.h data model summary#ioctl request model stores counts and payload
// - **GIVEN** 调用方 constructs an ioctl request model.
// - **WHEN** Rust safe model stores input count, output count, and input payload.
// - **THEN** those fields remain observable without raw FFI.
#[test]
fn test_smb2_ioctl_request_model_stores_counts_and_payload() {
    let request = protocol::Smb2IoctlRequest {
        input_count: 3,
        output_count: 8,
        input: vec![1, 2, 3],
        ..Default::default()
    };

    assert_eq!(request.input_count, 3);
    assert_eq!(request.output_count, 8);
    assert_eq!(request.input, vec![1, 2, 3]);
}

// Trace: `include/smb2/smb2.h:1064-1071`, `specs/include/smb2/smb2.spec.md:44`
// Spec: include/smb2/smb2.h data model summary#change notify request model stores completion filter
// - **GIVEN** 调用方 constructs a change notify request model.
// - **WHEN** Rust safe model stores output buffer length and completion filter.
// - **THEN** those fields remain observable without raw FFI.
#[test]
fn test_smb2_change_notify_request_model_stores_completion_filter() {
    let request = protocol::Smb2ChangeNotifyRequest {
        output_buffer_length: 512,
        completion_filter: 0x0000_0010,
        ..Default::default()
    };

    assert_eq!(request.output_buffer_length, 512);
    assert_eq!(request.completion_filter, 0x0000_0010);
}

// Trace: `include/smb2/smb2.h:1191-1203`, `specs/include/smb2/smb2.spec.md:46`
// Spec: include/smb2/smb2.h data model summary#write request model stores buffer offset and length
// - **GIVEN** 调用方 constructs a write request model.
// - **WHEN** Rust safe model stores length, offset, and buffer bytes.
// - **THEN** those fields remain observable without raw FFI.
#[test]
fn test_smb2_write_request_model_stores_buffer_offset_and_length() {
    let request = protocol::Smb2WriteRequest {
        length: 4,
        offset: 16,
        buf: vec![1, 2, 3, 4],
        ..Default::default()
    };

    assert_eq!(request.length, 4);
    assert_eq!(request.offset, 16);
    assert_eq!(request.buf, vec![1, 2, 3, 4]);
}

// Trace: `include/smb2/smb2.h:1214-1218`, `specs/include/smb2/smb2.spec.md:47`
// Spec: include/smb2/smb2.h data model summary#lock element model stores range and flags
// - **GIVEN** 调用方 constructs a lock element model.
// - **WHEN** Rust safe model stores offset, length, and flags.
// - **THEN** those fields remain observable without raw FFI.
#[test]
fn test_smb2_lock_element_model_stores_range_and_flags() {
    let element = protocol::Smb2LockElement {
        offset: 64,
        length: 128,
        flags: 1,
    };

    assert_eq!(element.offset, 64);
    assert_eq!(element.length, 128);
    assert_eq!(element.flags, 1);
}

// Trace: `include/smb2/smb2.h:smb2_get_file_id`, `lib/libsmb2.c:smb2_get_file_id`
// Spec: smb2_get_file_id expose handle file identifier#返回句柄内部 file id 指针
#[test]
fn test_smb2_get_file_id_model_exposes_internal_identifier() {
    let handle = libsmb2_rs::lib::libsmb2::Smb2FileHandle::new([0x5a; 16]);

    assert_eq!(handle.file_id, [0x5a; 16]);
}

// Trace: `include/smb2/smb2.h:smb2_fh_from_file_id`, `lib/libsmb2.c:smb2_fh_from_file_id`
// Spec: smb2_fh_from_file_id allocate handle from identifier#成功复制 file id
#[test]
fn test_smb2_fh_from_file_id_model_copies_identifier() {
    let mut source = [0x21_u8; 16];
    source[0] = 0x7f;
    let handle = libsmb2_rs::lib::libsmb2::Smb2FileHandle::new(source);
    source.fill(0);

    assert_eq!(handle.file_id[0], 0x7f);
    assert_eq!(handle.file_id[1..], [0x21; 15]);
}

// Trace: `include/smb2/smb2.h:smb2_decode_fileidfulldirectoryinformation`, `lib/smb2-cmd-query-directory.c:smb2_decode_fileidfulldirectoryinformation`
// Spec: smb2_decode_fileidfulldirectoryinformation decode directory entry#解码有效目录项
#[test]
fn test_smb2_decode_fileid_full_directory_valid_entry() {
    let buffer = fileid_full_directory_entry("ab");
    let decoded = smb2_cmd_query_directory::smb2_decode_fileidfulldirectoryinformation(&buffer)
        .unwrap();

    assert_eq!(decoded.file_index, 7);
    assert_eq!(decoded.end_of_file, 0x0102_0304_0506_0708);
    assert_eq!(decoded.allocation_size, 0x1112_1314_1516_1718);
    assert_eq!(decoded.file_attributes, 0x20);
    assert_eq!(decoded.ea_size, 3);
    assert_eq!(decoded.file_id, 0xa1a2_a3a4_a5a6_a7a8);
    assert_eq!(decoded.name, "ab");
}

// Trace: `include/smb2/smb2.h:smb2_decode_fileidfulldirectoryinformation`, `lib/smb2-cmd-query-directory.c:smb2_decode_fileidfulldirectoryinformation`
// Spec: smb2_decode_fileidfulldirectoryinformation decode directory entry#拒绝越界名称
#[test]
fn test_smb2_decode_fileid_full_directory_rejects_oob_name() {
    let mut buffer = fileid_full_directory_entry("ab");
    write_u32(&mut buffer, 60, 100);

    let result = smb2_cmd_query_directory::smb2_decode_fileidfulldirectoryinformation(&buffer);

    assert_eq!(result, Err(smb2_cmd_query_directory::QueryDirectoryError::MalformedName));
}

// Trace: `include/smb2/smb2.h:smb2_decode_filenotifychangeinformation`, `lib/libsmb2.c:smb2_decode_filenotifychangeinformation`
// Spec: smb2_decode_filenotifychangeinformation decode notify chain#解码单个通知记录
#[test]
fn test_smb2_decode_filenotify_single_record() {
    let buffer = notify_record(1, "a");
    let records = smb2_cmd_notify_change::smb2_decode_file_notify_information_records(&buffer)
        .unwrap();

    assert_eq!(records.len(), 1);
    assert_eq!(records[0].action, 1);
    assert_eq!(records[0].file_name, "a");
}

// Trace: `include/smb2/smb2.h:smb2_decode_filenotifychangeinformation`, `lib/libsmb2.c:smb2_decode_filenotifychangeinformation`
// Spec: smb2_decode_filenotifychangeinformation decode notify chain#解码链式通知记录
#[test]
fn test_smb2_decode_filenotify_chain_records() {
    let buffer = notify_chain();
    let records = smb2_cmd_notify_change::smb2_decode_file_notify_information_records(&buffer)
        .unwrap();

    assert_eq!(records.len(), 2);
    assert_eq!(records[0].file_name, "a");
    assert_eq!(records[1].action, 3);
    assert_eq!(records[1].file_name, "b");
}

// Trace: `include/smb2/smb2.h:smb2_decode_filenotifychangeinformation`, `lib/libsmb2.c:smb2_decode_filenotifychangeinformation`
// Spec: smb2_decode_filenotifychangeinformation decode notify chain#短缓冲区返回成功且不解码
#[test]
fn test_smb2_decode_filenotify_short_buffer_is_rejected_by_safe_decoder() {
    let result = smb2_cmd_notify_change::smb2_decode_file_notify_information_records(&[0_u8; 4]);

    assert_eq!(result, Err(smb2_cmd_notify_change::ChangeNotifyError::BufferTooShort));
}

fn fileid_full_directory_entry(name: &str) -> Vec<u8> {
    let name_bytes = utf16le(name);
    let mut buffer = vec![0_u8; 80 + name_bytes.len()];
    write_u32(&mut buffer, 4, 7);
    write_u64(&mut buffer, 40, 0x0102_0304_0506_0708);
    write_u64(&mut buffer, 48, 0x1112_1314_1516_1718);
    write_u32(&mut buffer, 56, 0x20);
    write_u32(&mut buffer, 60, name_bytes.len() as u32);
    write_u32(&mut buffer, 64, 3);
    write_u64(&mut buffer, 72, 0xa1a2_a3a4_a5a6_a7a8);
    buffer[80..].copy_from_slice(&name_bytes);
    buffer
}

fn notify_record(action: u32, name: &str) -> Vec<u8> {
    let name_bytes = utf16le(name);
    let mut buffer = vec![0_u8; 12 + name_bytes.len()];
    write_u32(&mut buffer, 4, action);
    write_u32(&mut buffer, 8, name_bytes.len() as u32);
    buffer[12..].copy_from_slice(&name_bytes);
    buffer
}

fn notify_chain() -> Vec<u8> {
    let first_name = utf16le("a");
    let second_name = utf16le("b");
    let first_len = 12 + first_name.len();
    let first_padded = (first_len + 3) & !3;
    let mut buffer = vec![0_u8; first_padded + 12 + second_name.len()];
    write_u32(&mut buffer, 0, first_padded as u32);
    write_u32(&mut buffer, 4, 1);
    write_u32(&mut buffer, 8, first_name.len() as u32);
    buffer[12..12 + first_name.len()].copy_from_slice(&first_name);
    write_u32(&mut buffer, first_padded + 4, 3);
    write_u32(&mut buffer, first_padded + 8, second_name.len() as u32);
    buffer[first_padded + 12..].copy_from_slice(&second_name);
    buffer
}

fn utf16le(value: &str) -> Vec<u8> {
    value
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect::<Vec<_>>()
}

fn write_u32(buffer: &mut [u8], offset: usize, value: u32) {
    buffer[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn write_u64(buffer: &mut [u8], offset: usize, value: u64) {
    buffer[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}
