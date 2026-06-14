use libsmb2_rs::lib::smb2_cmd_query_info::{
    self as query_info, QueryInfoError, QueryInfoPayload, QueryInfoReply, QueryInfoRequest,
};
use libsmb2_rs::lib::smb2_data_file_info::{
    Smb2FileBasicInfo, Smb2FilePositionInfo, FILE_BASIC_INFO_SIZE, FILE_POSITION_INFO_SIZE,
};
use libsmb2_rs::lib::smb2_data_filesystem_info::Smb2FileFsSizeInfo;
use libsmb2_rs::lib::smb2_data_security_descriptor::Smb2SecurityDescriptor;

// Trace: `lib/smb2-cmd-query-info.c:smb2_cmd_query_info_async`, `lib/smb2-cmd-query-info.c:smb2_encode_query_info_request`, `include/smb2/libsmb2-raw.h:smb2_cmd_query_info_async`
// Spec: smb2_cmd_query_info_async build Query Info request PDU#encode request without input buffer
// - **GIVEN** a `struct smb2_query_info_request` with `input_buffer_length` equal to zero and valid info type, file info class, output length, additional information, flags, and file id
// - **WHEN** `smb2_cmd_query_info_async` is called with a context, request, callback, and callback data
// - **THEN** the returned PDU MUST use command `SMB2_QUERY_INFO`, encode `SMB2_QUERY_INFO_REQUEST_SIZE`, copy the fixed request fields and `SMB2_FD_SIZE` bytes of file id, set `input_buffer_offset` to the fixed request end, and store `req->info_type` and `req->file_info_class` in the PDU for reply unmarshalling
#[test]
fn test_smb2_cmd_query_info_encode_request_without_input_buffer() {
    let req = QueryInfoRequest::new(
        query_info::SMB2_0_INFO_FILE,
        query_info::SMB2_FILE_BASIC_INFORMATION,
        [0x55; 16],
        128,
    );
    let pdu = query_info::smb2_cmd_query_info_async(&req).unwrap();
    assert_eq!(pdu.command, query_info::SMB2_QUERY_INFO);
    assert_eq!(pdu.info_type, query_info::SMB2_0_INFO_FILE);
    assert_eq!(pdu.file_info_class, query_info::SMB2_FILE_BASIC_INFORMATION);
    assert_eq!(
        &pdu.payload[0..2],
        &(query_info::SMB2_QUERY_INFO_REQUEST_SIZE as u16).to_le_bytes()
    );
    assert_eq!(&pdu.payload[24..40], &[0x55; 16]);
}

// Trace: `lib/smb2-cmd-query-info.c:smb2_cmd_query_info_async`, `lib/smb2-cmd-query-info.c:smb2_encode_query_info_request`
// Spec: smb2_cmd_query_info_async build Query Info request PDU#reject unsupported request input buffer
// - **GIVEN** a Query Info request whose `input_buffer_length` is greater than zero
// - **WHEN** `smb2_cmd_query_info_async` attempts to encode the request
// - **THEN** it MUST set an error for unsupported input buffers, free the allocated PDU through the caller path, and return `NULL`
#[test]
fn test_smb2_cmd_query_info_reject_unsupported_request_input_buffer() {
    let mut req = QueryInfoRequest::new(
        query_info::SMB2_0_INFO_FILE,
        query_info::SMB2_FILE_BASIC_INFORMATION,
        [0x55; 16],
        128,
    );
    req.input_buffer_length = 1;

    assert_eq!(
        query_info::smb2_cmd_query_info_async(&req),
        Err(QueryInfoError::UnsupportedInputBuffer)
    );
}

// Trace: `lib/smb2-cmd-query-info.c:smb2_cmd_query_info_async`, `include/smb2/libsmb2-raw.h:smb2_cmd_query_info_async`
// Spec: smb2_cmd_query_info_async build Query Info request PDU#request construction failure
// - **GIVEN** PDU allocation, fixed request allocation, iovector append, or final padding fails
// - **WHEN** `smb2_cmd_query_info_async` constructs the request PDU
// - **THEN** the function MUST return `NULL`, free an allocated PDU on encode or padding failure, and preserve the header contract that the callback is not invoked on local setup error
#[test]
fn test_smb2_cmd_query_info_request_construction_failure() {
    let mut req = QueryInfoRequest::new(
        query_info::SMB2_0_INFO_FILE,
        query_info::SMB2_FILE_BASIC_INFORMATION,
        [0x11; 16],
        128,
    );
    req.input_buffer_length = 8;

    assert_eq!(
        query_info::smb2_cmd_query_info_async(&req),
        Err(QueryInfoError::UnsupportedInputBuffer)
    );
}

// Trace: `lib/smb2-cmd-query-info.c:smb2_cmd_query_info_reply_async`, `lib/smb2-cmd-query-info.c:smb2_encode_query_info_reply`, `lib/libsmb2.c:smb2_query_info_request_cb`
// Spec: smb2_cmd_query_info_reply_async build Query Info reply PDU#encode supported file and filesystem output
// - **GIVEN** a reply with nonzero `output_buffer_length`, a non-null `output_buffer`, and request info type/class matching a supported file or filesystem encoder
// - **WHEN** `smb2_cmd_query_info_reply_async` builds the reply PDU
// - **THEN** the output payload MUST be encoded using the matching file, filesystem, or name/stream encoder, the fixed reply MUST report the resulting output length, and the variable iovector length MUST be padded to an 8-byte boundary
#[test]
fn test_smb2_cmd_query_info_reply_encode_supported_output() {
    let file_req = QueryInfoRequest::new(
        query_info::SMB2_0_INFO_FILE,
        query_info::SMB2_FILE_POSITION_INFORMATION,
        [0; 16],
        64,
    );
    let file_reply = QueryInfoReply {
        output_buffer: QueryInfoPayload::FilePositionInformation(Smb2FilePositionInfo {
            current_byte_offset: 0x1122_3344,
        }),
        ..QueryInfoReply::new()
    };

    let file_pdu =
        query_info::smb2_cmd_query_info_reply_async(&file_req, &file_reply, false).unwrap();

    assert_eq!(file_pdu.command, query_info::SMB2_QUERY_INFO);
    assert_eq!(
        u32::from_le_bytes([
            file_pdu.payload[4],
            file_pdu.payload[5],
            file_pdu.payload[6],
            file_pdu.payload[7]
        ]),
        FILE_POSITION_INFO_SIZE as u32
    );
    assert_eq!(file_pdu.payload.len() % 8, 0);

    let fs_req = QueryInfoRequest::new(
        query_info::SMB2_0_INFO_FILESYSTEM,
        query_info::SMB2_FILE_FS_SIZE_INFORMATION,
        [0; 16],
        64,
    );
    let fs_reply = QueryInfoReply {
        output_buffer: QueryInfoPayload::FileFsSizeInformation(Smb2FileFsSizeInfo {
            total_allocation_units: 5,
            available_allocation_units: 3,
            sectors_per_allocation_unit: 2,
            bytes_per_sector: 512,
        }),
        ..QueryInfoReply::new()
    };

    let fs_pdu = query_info::smb2_cmd_query_info_reply_async(&fs_req, &fs_reply, false).unwrap();

    assert_eq!(fs_pdu.payload.len() % 8, 0);
    assert_eq!(fs_pdu.status, None);
}

// Trace: `lib/smb2-cmd-query-info.c:smb2_cmd_query_info_reply_async`, `lib/smb2-cmd-query-info.c:smb2_encode_query_info_reply`
// Spec: smb2_cmd_query_info_reply_async build Query Info reply PDU#truncate oversized encoded output
// - **GIVEN** a supported encoder produces more bytes than `req->output_buffer_length`
// - **WHEN** `smb2_cmd_query_info_reply_async` finalizes the encoded reply
// - **THEN** it MUST limit `rep->output_buffer_length` to the requested output length, set the PDU status to `SMB2_STATUS_BUFFER_OVERFLOW`, and keep the variable iovector padded to the truncated length
#[test]
fn test_smb2_cmd_query_info_reply_truncate_oversized_output() {
    let req = QueryInfoRequest::new(
        query_info::SMB2_0_INFO_FILE,
        query_info::SMB2_FILE_BASIC_INFORMATION,
        [0; 16],
        8,
    );
    let rep = QueryInfoReply {
        output_buffer: QueryInfoPayload::FileBasicInformation(Smb2FileBasicInfo::default()),
        ..QueryInfoReply::new()
    };

    let pdu = query_info::smb2_cmd_query_info_reply_async(&req, &rep, false).unwrap();

    assert_eq!(pdu.status, Some(query_info::SMB2_STATUS_BUFFER_OVERFLOW));
    assert_eq!(
        u32::from_le_bytes([
            pdu.payload[4],
            pdu.payload[5],
            pdu.payload[6],
            pdu.payload[7]
        ]),
        8
    );
    assert_eq!(
        pdu.payload.len(),
        QueryInfoReply::fixed_wire_len() + query_info::pad_to_64bit(8)
    );
}

// Trace: `lib/smb2-cmd-query-info.c:smb2_cmd_query_info_reply_async`, `lib/smb2-cmd-query-info.c:smb2_encode_query_info_reply`
// Spec: smb2_cmd_query_info_reply_async build Query Info reply PDU#passthrough reply output
// - **GIVEN** a reply with nonzero output length for an unhandled info type/class and `smb2->passthrough` enabled
// - **WHEN** `smb2_cmd_query_info_reply_async` builds the reply PDU
// - **THEN** it MUST copy the output buffer bytes into the reply, zero the padding up to 8-byte alignment, and report the original output buffer length in the fixed reply
#[test]
fn test_smb2_cmd_query_info_reply_passthrough_output() {
    let req = QueryInfoRequest::new(
        query_info::SMB2_0_INFO_FILE,
        query_info::SMB2_FILE_ACCESS_INFORMATION,
        [0; 16],
        16,
    );
    let rep = QueryInfoReply::new()
        .with_raw_output(vec![1, 2, 3])
        .unwrap();

    let pdu = query_info::smb2_cmd_query_info_reply_async(&req, &rep, true).unwrap();

    assert_eq!(
        u32::from_le_bytes([
            pdu.payload[4],
            pdu.payload[5],
            pdu.payload[6],
            pdu.payload[7]
        ]),
        3
    );
    assert_eq!(
        &pdu.payload[QueryInfoReply::fixed_wire_len()..QueryInfoReply::fixed_wire_len() + 3],
        &[1, 2, 3]
    );
    assert!(pdu.payload[QueryInfoReply::fixed_wire_len() + 3..]
        .iter()
        .all(|byte| *byte == 0));
}

// Trace: `lib/smb2-cmd-query-info.c:smb2_cmd_query_info_reply_async`, `lib/smb2-cmd-query-info.c:smb2_encode_query_info_reply`
// Spec: smb2_cmd_query_info_reply_async build Query Info reply PDU#unsupported non-passthrough reply output
// - **GIVEN** a reply with nonzero output length for an unhandled info type/class and `smb2->passthrough` disabled
// - **WHEN** `smb2_cmd_query_info_reply_async` attempts to encode the output payload
// - **THEN** it MUST set an error for the unhandled info type/class and return `NULL` through the caller path
#[test]
fn test_smb2_cmd_query_info_reply_unsupported_non_passthrough_output() {
    let req = QueryInfoRequest::new(
        query_info::SMB2_0_INFO_FILE,
        query_info::SMB2_FILE_ACCESS_INFORMATION,
        [0; 16],
        16,
    );
    let rep = QueryInfoReply::new()
        .with_raw_output(vec![1, 2, 3])
        .unwrap();

    assert_eq!(
        query_info::smb2_cmd_query_info_reply_async(&req, &rep, false),
        Err(QueryInfoError::UnsupportedOutputClass {
            info_type: query_info::SMB2_0_INFO_FILE,
            info_class: query_info::SMB2_FILE_ACCESS_INFORMATION
        })
    );
}

// Trace: `lib/smb2-cmd-query-info.c:smb2_process_query_info_fixed`, `lib/pdu.c:smb2_process_reply_payload_fixed`
// Spec: smb2_process_query_info_fixed parse Query Info reply fixed body#fixed reply without output
// - **GIVEN** an incoming Query Info reply fixed body with structure size `SMB2_QUERY_INFO_REPLY_SIZE`, matching even wire length, and `output_buffer_length` equal to zero
// - **WHEN** `smb2_process_query_info_fixed` parses the fixed payload
// - **THEN** it MUST allocate the reply payload, assign it to `pdu->payload`, set `rep->output_buffer` to `NULL`, and return `0`
#[test]
fn test_smb2_cmd_query_info_fixed_reply_without_output() {
    let fixed = query_info::smb2_encode_query_info_reply(
        &QueryInfoRequest::new(
            query_info::SMB2_0_INFO_FILE,
            query_info::SMB2_FILE_BASIC_INFORMATION,
            [0; 16],
            0,
        ),
        &QueryInfoReply::new(),
        false,
    )
    .unwrap()
    .0;

    let (reply, needed) =
        query_info::smb2_process_query_info_fixed(&fixed, fixed.len(), None).unwrap();

    assert_eq!(needed, 0);
    assert_eq!(reply.output_buffer, QueryInfoPayload::None);
}

// Trace: `lib/smb2-cmd-query-info.c:smb2_process_query_info_fixed`, `lib/pdu.c:smb2_process_reply_payload_fixed`
// Spec: smb2_process_query_info_fixed parse Query Info reply fixed body#fixed reply with output buffer
// - **GIVEN** an incoming Query Info reply fixed body with nonzero output length, non-wrapping offset plus length, and an output offset at or after the end of the fixed reply body
// - **WHEN** `smb2_process_query_info_fixed` parses the fixed payload
// - **THEN** it MUST verify the output does not extend past the current PDU or into the next chained PDU, then return `IOV_OFFSET_QUERY + rep->output_buffer_length` so the caller reads the variable payload
#[test]
fn test_smb2_cmd_query_info_fixed_reply_with_output_buffer() {
    let mut fixed = vec![0_u8; QueryInfoReply::fixed_wire_len()];
    fixed[0..2].copy_from_slice(&(query_info::SMB2_QUERY_INFO_REPLY_SIZE as u16).to_le_bytes());
    fixed[2..4].copy_from_slice(&(query_info::reply_payload_offset() as u16).to_le_bytes());
    fixed[4..8].copy_from_slice(&3_u32.to_le_bytes());

    let (_reply, needed) = query_info::smb2_process_query_info_fixed(
        &fixed,
        query_info::reply_payload_offset() + 3,
        None,
    )
    .unwrap();

    assert_eq!(needed, 3);
}

// Trace: `lib/smb2-cmd-query-info.c:smb2_process_query_info_fixed`, `lib/pdu.c:smb2_process_reply_payload_fixed`
// Spec: smb2_process_query_info_fixed parse Query Info reply fixed body#malformed fixed reply
// - **GIVEN** an incoming fixed reply with unexpected structure size, mismatched fixed length, allocation failure, wrapped output range, output beyond the current PDU, output into the next chained PDU, or output offset overlapping the fixed header
// - **WHEN** `smb2_process_query_info_fixed` validates the fixed payload
// - **THEN** it MUST return `-1`, set an error where implemented, and clear/free `pdu->payload` for failures detected after allocation
#[test]
fn test_smb2_cmd_query_info_malformed_fixed_reply() {
    let fixed = [0_u8; 2];

    assert_eq!(
        query_info::smb2_process_query_info_fixed(&fixed, fixed.len(), None),
        Err(QueryInfoError::BufferTooShort)
    );
}

// Trace: `lib/smb2-cmd-query-info.c:smb2_process_query_info_variable`, `lib/smb2-data-file-info.c:smb2_decode_file_basic_info`, `lib/pdu.c:smb2_process_reply_payload_variable`
// Spec: smb2_process_query_info_variable parse Query Info reply variable body#decode supported file information output
// - **GIVEN** `pdu->payload` is a Query Info reply and `pdu->info_type` is `SMB2_0_INFO_FILE` with a supported file information class
// - **WHEN** `smb2_process_query_info_variable` parses the variable payload
// - **THEN** it MUST allocate an appropriate SMB2-owned structure, decode the output using the matching file-info decoder, assign the decoded pointer to `rep->output_buffer`, and return `0` when decoding succeeds
#[test]
fn test_smb2_cmd_query_info_variable_decode_file_information_output() {
    let mut bytes = vec![0_u8; FILE_BASIC_INFO_SIZE];
    Smb2FileBasicInfo::default().encode(&mut bytes).unwrap();
    let mut rep = QueryInfoReply {
        output_buffer_offset: query_info::reply_payload_offset() as u16,
        output_buffer_length: FILE_BASIC_INFO_SIZE as u32,
        output_buffer: QueryInfoPayload::None,
    };

    query_info::smb2_process_query_info_variable(
        &mut rep,
        query_info::SMB2_0_INFO_FILE,
        query_info::SMB2_FILE_BASIC_INFORMATION,
        &bytes,
        false,
    )
    .unwrap();

    assert!(matches!(
        rep.output_buffer,
        QueryInfoPayload::FileBasicInformation(_)
    ));
}

// Trace: `lib/smb2-cmd-query-info.c:smb2_process_query_info_variable`, `lib/smb2-data-filesystem-info.c:smb2_decode_file_fs_volume_info`, `lib/pdu.c:smb2_process_reply_payload_variable`
// Spec: smb2_process_query_info_variable parse Query Info reply variable body#decode supported filesystem information output
// - **GIVEN** `pdu->payload` is a Query Info reply and `pdu->info_type` is `SMB2_0_INFO_FILESYSTEM` with a supported filesystem information class
// - **WHEN** `smb2_process_query_info_variable` parses the variable payload
// - **THEN** it MUST allocate an appropriate SMB2-owned filesystem structure, decode the output using the matching filesystem decoder, assign the decoded pointer to `rep->output_buffer`, and return `0` when decoding succeeds
#[test]
fn test_smb2_cmd_query_info_variable_decode_filesystem_information_output() {
    let bytes = Smb2FileFsSizeInfo {
        total_allocation_units: 9,
        available_allocation_units: 4,
        sectors_per_allocation_unit: 8,
        bytes_per_sector: 512,
    }
    .encode();
    let mut rep = QueryInfoReply {
        output_buffer_offset: query_info::reply_payload_offset() as u16,
        output_buffer_length: bytes.len() as u32,
        output_buffer: QueryInfoPayload::None,
    };

    query_info::smb2_process_query_info_variable(
        &mut rep,
        query_info::SMB2_0_INFO_FILESYSTEM,
        query_info::SMB2_FILE_FS_SIZE_INFORMATION,
        &bytes,
        false,
    )
    .unwrap();

    assert!(matches!(
        rep.output_buffer,
        QueryInfoPayload::FileFsSizeInformation(_)
    ));
}

// Trace: `lib/smb2-cmd-query-info.c:smb2_process_query_info_variable`, `lib/smb2-data-security-descriptor.c:smb2_decode_security_descriptor`, `lib/pdu.c:smb2_process_reply_payload_variable`
// Spec: smb2_process_query_info_variable parse Query Info reply variable body#decode security descriptor output
// - **GIVEN** `pdu->payload` is a Query Info reply, `pdu->info_type` is `SMB2_0_INFO_SECURITY`, and `smb2->passthrough` is disabled
// - **WHEN** `smb2_process_query_info_variable` parses the variable payload
// - **THEN** it MUST allocate `struct smb2_security_descriptor`, decode the security descriptor, assign it to `rep->output_buffer`, and return `0` when decoding succeeds
#[test]
fn test_smb2_cmd_query_info_variable_decode_security_descriptor_output() {
    let bytes = Smb2SecurityDescriptor::from_header(1, 0).encode().unwrap();
    let mut rep = QueryInfoReply {
        output_buffer_offset: query_info::reply_payload_offset() as u16,
        output_buffer_length: bytes.len() as u32,
        output_buffer: QueryInfoPayload::None,
    };

    query_info::smb2_process_query_info_variable(
        &mut rep,
        query_info::SMB2_0_INFO_SECURITY,
        0,
        &bytes,
        false,
    )
    .unwrap();

    assert!(matches!(
        rep.output_buffer,
        QueryInfoPayload::SecurityDescriptor(_)
    ));
}

// Trace: `lib/smb2-cmd-query-info.c:smb2_process_query_info_variable`, `lib/pdu.c:smb2_process_reply_payload_variable`
// Spec: smb2_process_query_info_variable parse Query Info reply variable body#unsupported output class handling
// - **GIVEN** the reply info type/class does not produce a decoder result
// - **WHEN** `smb2_process_query_info_variable` reaches the fallback path
// - **THEN** it MUST copy the raw output bytes into SMB2-owned memory when `smb2->passthrough` is enabled, and MUST return `-1` with an error when passthrough is disabled
#[test]
fn test_smb2_cmd_query_info_variable_unsupported_output_class_handling() {
    let mut passthrough_rep = QueryInfoReply {
        output_buffer_offset: query_info::reply_payload_offset() as u16,
        output_buffer_length: 3,
        output_buffer: QueryInfoPayload::None,
    };
    query_info::smb2_process_query_info_variable(
        &mut passthrough_rep,
        query_info::SMB2_0_INFO_FILE,
        query_info::SMB2_FILE_ACCESS_INFORMATION,
        &[7, 8, 9],
        true,
    )
    .unwrap();

    assert_eq!(passthrough_rep.output_buffer.as_bytes(), &[7, 8, 9]);

    let mut strict_rep = QueryInfoReply {
        output_buffer_offset: query_info::reply_payload_offset() as u16,
        output_buffer_length: 3,
        output_buffer: QueryInfoPayload::None,
    };

    assert_eq!(
        query_info::smb2_process_query_info_variable(
            &mut strict_rep,
            query_info::SMB2_0_INFO_FILE,
            query_info::SMB2_FILE_ACCESS_INFORMATION,
            &[7, 8, 9],
            false,
        ),
        Err(QueryInfoError::UnsupportedOutputClass {
            info_type: query_info::SMB2_0_INFO_FILE,
            info_class: query_info::SMB2_FILE_ACCESS_INFORMATION
        })
    );
}

// Trace: `lib/smb2-cmd-query-info.c:smb2_process_query_info_request_fixed`, `lib/pdu.c:smb2_process_request_payload_fixed`
// Spec: smb2_process_query_info_request_fixed parse Query Info request fixed body#fixed request without input
// - **GIVEN** an incoming Query Info request fixed body with structure size `SMB2_QUERY_INFO_REQUEST_SIZE`, matching even wire length, and `input_buffer_length` equal to zero
// - **WHEN** `smb2_process_query_info_request_fixed` parses the fixed payload
// - **THEN** it MUST allocate the request payload, populate info type, file info class, output length, input offset and length, additional information, flags, and file id, store it in `pdu->payload`, and return `0`
#[test]
fn test_smb2_cmd_query_info_request_fixed_without_input() {
    let req = QueryInfoRequest::new(
        query_info::SMB2_0_INFO_FILE,
        query_info::SMB2_FILE_BASIC_INFORMATION,
        [3; 16],
        32,
    );
    let fixed = query_info::smb2_encode_query_info_request(&req).unwrap();

    let (parsed, needed) =
        query_info::smb2_process_query_info_request_fixed(&fixed, fixed.len()).unwrap();

    assert_eq!(needed, 0);
    assert_eq!(parsed.info_type, query_info::SMB2_0_INFO_FILE);
    assert_eq!(parsed.file_id, [3; 16]);
}

// Trace: `lib/smb2-cmd-query-info.c:smb2_process_query_info_request_fixed`, `lib/pdu.c:smb2_process_request_payload_fixed`
// Spec: smb2_process_query_info_request_fixed parse Query Info request fixed body#fixed request with input buffer
// - **GIVEN** an incoming Query Info request fixed body with nonzero input length and an input offset at or after the end of the fixed request body
// - **WHEN** `smb2_process_query_info_request_fixed` parses the fixed payload
// - **THEN** it MUST return `IOVREQ_OFFSET_QUERY + req->input_buffer_length` so the caller reads the complete input variable payload
#[test]
fn test_smb2_cmd_query_info_request_fixed_with_input_buffer() {
    let mut fixed = vec![0_u8; QueryInfoRequest::fixed_wire_len()];
    fixed[0..2].copy_from_slice(&(query_info::SMB2_QUERY_INFO_REQUEST_SIZE as u16).to_le_bytes());
    fixed[8..10].copy_from_slice(&(query_info::request_payload_offset() as u16).to_le_bytes());
    fixed[12..16].copy_from_slice(&4_u32.to_le_bytes());

    let (_parsed, needed) = query_info::smb2_process_query_info_request_fixed(
        &fixed,
        query_info::request_payload_offset() + 4,
    )
    .unwrap();

    assert_eq!(needed, 4);
}

// Trace: `lib/smb2-cmd-query-info.c:smb2_process_query_info_request_fixed`, `lib/pdu.c:smb2_process_request_payload_fixed`
// Spec: smb2_process_query_info_request_fixed parse Query Info request fixed body#malformed fixed request
// - **GIVEN** an incoming fixed request with unexpected structure size, mismatched fixed length, allocation failure, or input offset overlapping the fixed header
// - **WHEN** `smb2_process_query_info_request_fixed` validates the fixed payload
// - **THEN** it MUST return `-1`, set an error where implemented, and clear/free `pdu->payload` when overlap is detected after allocation
#[test]
fn test_smb2_cmd_query_info_malformed_fixed_request() {
    let mut fixed = vec![0_u8; QueryInfoRequest::fixed_wire_len()];
    fixed[0..2].copy_from_slice(&(query_info::SMB2_QUERY_INFO_REQUEST_SIZE as u16).to_le_bytes());
    fixed[8..10].copy_from_slice(&1_u16.to_le_bytes());
    fixed[12..16].copy_from_slice(&1_u32.to_le_bytes());

    assert_eq!(
        query_info::smb2_process_query_info_request_fixed(
            &fixed,
            query_info::request_payload_offset() + 1
        ),
        Err(QueryInfoError::BufferOverlap)
    );
}

// Trace: `lib/smb2-cmd-query-info.c:smb2_process_query_info_request_variable`, `lib/pdu.c:smb2_process_request_payload_variable`
// Spec: smb2_process_query_info_request_variable expose Query Info request input#bind request input pointer
// - **GIVEN** `pdu->payload` is a parsed `struct smb2_query_info_request` with nonzero input length and the variable payload iovector contains the requested bytes
// - **WHEN** `smb2_process_query_info_request_variable` parses the variable payload
// - **THEN** it MUST compute `IOVREQ_OFFSET_QUERY`, assign `req->input` to that location in the current incoming iovector, and return `0` without copying the input bytes
#[test]
fn test_smb2_cmd_query_info_request_variable_bind_request_input_pointer() {
    let mut req = QueryInfoRequest::new(
        query_info::SMB2_0_INFO_FILE,
        query_info::SMB2_FILE_BASIC_INFORMATION,
        [0; 16],
        16,
    );
    req.input_buffer_offset = (query_info::request_payload_offset() + 2) as u16;
    req.input_buffer_length = 3;

    query_info::smb2_process_query_info_request_variable(&mut req, &[0, 0, 5, 6, 7]).unwrap();

    assert_eq!(req.input, vec![5, 6, 7]);
}
