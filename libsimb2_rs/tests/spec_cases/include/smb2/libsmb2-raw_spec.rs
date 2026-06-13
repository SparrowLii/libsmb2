use libsmb2_sys::smb2::libsmb2_raw::{COMPOUND_FILE_ID, SMB2_FD_SIZE};

// Trace: `include/smb2/libsmb2-raw.h:compound_file_id`, `lib/libsmb2.c:compound_file_id`
// Spec: compound_file_id expose compound sentinel#复合请求复用特殊 file id
// - **GIVEN** 调用方或库内部构造 compound create/query/close 请求链
// - **WHEN** 后续请求需要引用 compound 链中前序创建的文件句柄
// - **THEN** 请求构造代码 MUST 使用 `compound_file_id` 作为特殊 `smb2_file_id` 哨兵
#[test]
fn test_libsmb2_raw_compound_request_reuses_special_file_id() {
    assert_eq!(COMPOUND_FILE_ID.len(), SMB2_FD_SIZE);
    assert!(COMPOUND_FILE_ID.iter().all(|byte| *byte == 0xff));
}
