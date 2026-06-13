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
