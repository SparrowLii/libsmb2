use libsmb2_rs::lib::smb2_cmd_lock::{
    self as lock, Smb2LockElement, Smb2LockError, Smb2LockRequest,
};

fn file_id() -> [u8; 16] {
    [0x11; 16]
}

fn lock_element(offset: u64, length: u64, flags: u32) -> Smb2LockElement {
    Smb2LockElement {
        offset,
        length,
        flags,
    }
}

fn valid_fixed_lock_request(count: u16) -> Vec<u8> {
    let request =
        Smb2LockRequest::new(file_id(), vec![lock_element(10, 20, 1); usize::from(count)]);
    lock::smb2_cmd_lock_async(request).unwrap().out[0]
        .as_slice()
        .to_vec()
}

// Trace: `lib/smb2-cmd-lock.c:smb2_cmd_lock_async`, `lib/smb2-cmd-lock.c:smb2_encode_lock_request`, `include/smb2/libsmb2-raw.h:smb2_cmd_lock_async`
// Spec: smb2_cmd_lock_async build lock request PDU#construct single-lock request
// - **GIVEN** a context, callback, callback data, and a lock request with `lock_count` set to one and `locks` pointing to at least one element
// - **WHEN** `smb2_cmd_lock_async` is called
// - **THEN** the returned PDU contains an SMB2_LOCK command with a 48-byte fixed body, the first lock encoded in the fixed body, and output padding aligned to 64 bits
#[test]
fn test_smb2_cmd_lock_construct_single_lock_request() {
    let request = Smb2LockRequest::new(file_id(), vec![lock_element(10, 20, 1)]);
    let pdu = lock::smb2_cmd_lock_async(request).expect("lock request pdu");

    assert_eq!(pdu.out.len(), 1);
    assert_eq!(pdu.out[0].len(), usize::from(lock::SMB2_LOCK_REQUEST_SIZE));
    assert_eq!(
        &pdu.out[0].as_slice()[0..2],
        &lock::SMB2_LOCK_REQUEST_SIZE.to_le_bytes()
    );
    assert_eq!(&pdu.out[0].as_slice()[8..24], &file_id());
    assert_eq!(&pdu.out[0].as_slice()[24..32], &10_u64.to_le_bytes());
}

// Trace: `lib/smb2-cmd-lock.c:smb2_cmd_lock_async`, `lib/smb2-cmd-lock.c:smb2_encode_lock_request`, `include/smb2/smb2.h:SMB2_LOCK_ELEMENT_SIZE`
// Spec: smb2_cmd_lock_async build lock request PDU#construct multi-lock request
// - **GIVEN** a lock request with `lock_count` greater than one and `locks` pointing to an array with all requested elements
// - **WHEN** `smb2_cmd_lock_async` is called
// - **THEN** the first lock is encoded in the fixed body and each additional lock is encoded in a padded variable iovector using 24-byte element slots
#[test]
fn test_smb2_cmd_lock_construct_multi_lock_request() {
    let request = Smb2LockRequest::new(
        file_id(),
        vec![lock_element(10, 20, 1), lock_element(30, 40, 2)],
    );
    let pdu = lock::smb2_cmd_lock_async(request).expect("multi lock request pdu");

    assert_eq!(pdu.out.len(), 2);
    assert_eq!(pdu.out[1].len(), lock::SMB2_LOCK_ELEMENT_SIZE);
    assert_eq!(&pdu.out[1].as_slice()[0..8], &30_u64.to_le_bytes());
    assert_eq!(&pdu.out[1].as_slice()[8..16], &40_u64.to_le_bytes());
}

// Trace: `lib/smb2-cmd-lock.c:smb2_cmd_lock_reply_async`, `lib/smb2-cmd-lock.c:smb2_encode_lock_reply`, `lib/libsmb2.c:smb2_lock_request_cb`
// Spec: smb2_cmd_lock_reply_async build lock reply PDU#construct successful lock reply
// - **GIVEN** a context, callback, and callback data for a successful server-side lock command
// - **WHEN** `smb2_cmd_lock_reply_async` is called
// - **THEN** the returned PDU uses command SMB2_LOCK, contains a 4-byte lock reply structure, and has its output padded to a 64-bit boundary
#[test]
fn test_smb2_cmd_lock_construct_successful_lock_reply() {
    let pdu = lock::smb2_cmd_lock_reply_async().expect("lock reply pdu");

    assert_eq!(pdu.out.len(), 1);
    // The fixed lock reply body is SMB2_LOCK_REPLY_SIZE (4) bytes with the
    // structure size in the first 2 bytes.
    let mut expected = vec![0u8; usize::from(lock::SMB2_LOCK_REPLY_SIZE & 0xfffe)];
    expected[0..2].copy_from_slice(&lock::SMB2_LOCK_REPLY_SIZE.to_le_bytes());
    assert_eq!(pdu.out[0].as_slice(), expected.as_slice());
}

// Trace: `lib/smb2-cmd-lock.c:smb2_process_lock_fixed`, `lib/pdu.c:smb2_process_reply_payload_fixed`
// Spec: smb2_process_lock_fixed validate lock reply fixed body#accept valid lock reply size
// - **GIVEN** the current input iovector contains a lock reply with structure size `SMB2_LOCK_REPLY_SIZE` and matching received length
// - **WHEN** `smb2_process_lock_fixed` parses the fixed reply payload
// - **THEN** the function returns `0` without allocating command data
#[test]
fn test_smb2_cmd_lock_accept_valid_lock_reply_size() {
    // The fixed reply body is SMB2_LOCK_REPLY_SIZE (4) bytes wide.
    let mut fixed = vec![0u8; usize::from(lock::SMB2_LOCK_REPLY_SIZE & 0xfffe)];
    fixed[0..2].copy_from_slice(&lock::SMB2_LOCK_REPLY_SIZE.to_le_bytes());
    assert!(lock::smb2_process_lock_fixed(&fixed).is_ok());
}

// Trace: `lib/smb2-cmd-lock.c:smb2_process_lock_fixed`, `include/smb2/smb2.h:SMB2_LOCK_REPLY_SIZE`
// Spec: smb2_process_lock_fixed validate lock reply fixed body#reject invalid lock reply size
// - **GIVEN** the current input iovector contains a lock reply whose structure size is not `SMB2_LOCK_REPLY_SIZE` or whose masked size does not match the iovector length
// - **WHEN** `smb2_process_lock_fixed` parses the fixed reply payload
// - **THEN** the function records an unexpected-size error and returns `-1`
#[test]
fn test_smb2_cmd_lock_reject_invalid_lock_reply_size() {
    // A 4-byte body whose declared structure size is wrong must be rejected.
    let mut fixed = vec![0u8; usize::from(lock::SMB2_LOCK_REPLY_SIZE & 0xfffe)];
    fixed[0..2].copy_from_slice(&(lock::SMB2_LOCK_REPLY_SIZE + 2).to_le_bytes());
    assert!(matches!(
        lock::smb2_process_lock_fixed(&fixed),
        Err(Smb2LockError::InvalidStructureSize { .. })
    ));
}

// Trace: `lib/smb2-cmd-lock.c:smb2_process_lock_request_fixed`, `lib/pdu.c:smb2_process_request_payload_fixed`, `include/smb2/smb2.h:smb2_lock_request`
// Spec: smb2_process_lock_request_fixed parse lock request fixed body#parse valid lock request fixed body
// - **GIVEN** the current input iovector contains a lock request with structure size `SMB2_LOCK_REQUEST_SIZE`, matching received length, and `lock_count` of at least one
// - **WHEN** `smb2_process_lock_request_fixed` parses the fixed request payload
// - **THEN** the function stores a newly allocated `smb2_lock_request` in `pdu->payload`, decodes the sequence number from the high 4 bits, decodes the sequence index from the low 28 bits, copies the file id, parses the first lock element, and returns `SMB2_LOCK_ELEMENT_SIZE * (lock_count - 1)`
#[test]
fn test_smb2_cmd_lock_parse_valid_lock_request_fixed_body() {
    let (request, remaining) =
        lock::smb2_process_lock_request_fixed(&valid_fixed_lock_request(2)).unwrap();

    assert_eq!(request.file_id, file_id());
    assert_eq!(request.locks[0], lock_element(10, 20, 1));
    assert_eq!(remaining, lock::SMB2_LOCK_ELEMENT_SIZE);
}

// Trace: `lib/smb2-cmd-lock.c:smb2_process_lock_request_fixed`, `include/smb2/smb2.h:SMB2_LOCK_REQUEST_SIZE`
// Spec: smb2_process_lock_request_fixed parse lock request fixed body#reject malformed or empty lock request
// - **GIVEN** the fixed request iovector has an unexpected structure size, mismatched masked length, or a decoded `lock_count` less than one
// - **WHEN** `smb2_process_lock_request_fixed` parses the fixed request payload
// - **THEN** the function records an error, returns `-1`, and clears/frees the partially allocated payload when rejection happens after payload allocation
#[test]
fn test_smb2_cmd_lock_reject_malformed_or_empty_lock_request() {
    let result = lock::smb2_process_lock_request_fixed(&[0; 46]);
    assert_eq!(result, Err(Smb2LockError::BufferTooSmall));

    let mut fixed = vec![0; 48];
    fixed[0..2].copy_from_slice(&48_u16.to_le_bytes());
    assert_eq!(
        lock::smb2_process_lock_request_fixed(&fixed),
        Err(Smb2LockError::MissingLockElement)
    );
}

// Trace: `lib/smb2-cmd-lock.c:smb2_process_lock_request_variable`, `lib/smb2-cmd-lock.c:smb2_parse_locks`, `lib/pdu.c:smb2_process_request_payload_variable`
// Spec: smb2_process_lock_request_variable parse remaining lock elements#parse additional lock elements
// - **GIVEN** `pdu->payload` is a lock request previously populated by `smb2_process_lock_request_fixed` with `lock_count` greater than one
// - **WHEN** `smb2_process_lock_request_variable` is called for the variable payload
// - **THEN** the function parses `lock_count - 1` additional lock elements from offset zero into `req->locks + 1` and returns `0` on success
#[test]
fn test_smb2_cmd_lock_parse_additional_lock_elements() {
    let request = Smb2LockRequest::new(
        file_id(),
        vec![lock_element(1, 2, 3), lock_element(4, 5, 6)],
    );
    let fixed = lock::smb2_encode_lock_request(&request).unwrap()[0]
        .as_slice()
        .to_vec();
    let variable = lock::smb2_encode_lock_request(&request).unwrap()[1]
        .as_slice()
        .to_vec();
    let (mut parsed, remaining) = lock::smb2_process_lock_request_fixed(&fixed).unwrap();

    lock::smb2_process_lock_request_variable(&mut parsed, &variable, 2).unwrap();

    assert_eq!(remaining, 24);
    assert_eq!(parsed.locks, request.locks);
}

// Trace: `lib/smb2-cmd-lock.c:smb2_process_lock_request_variable`, `lib/smb2-cmd-lock.c:smb2_parse_locks`
// Spec: smb2_process_lock_request_variable parse remaining lock elements#reject missing variable parse targets
// - **GIVEN** the variable parse helper receives a missing iovector or missing lock output pointer
// - **WHEN** lock element parsing is requested
// - **THEN** the helper returns `-1` and `smb2_process_lock_request_variable` propagates that failure
#[test]
fn test_smb2_cmd_lock_reject_missing_variable_parse_targets() {
    let mut request = Smb2LockRequest::new(file_id(), vec![lock_element(1, 2, 3)]);

    let result = lock::smb2_process_lock_request_variable(&mut request, &[], 2);

    assert_eq!(result, Err(Smb2LockError::BufferTooSmall));
}
