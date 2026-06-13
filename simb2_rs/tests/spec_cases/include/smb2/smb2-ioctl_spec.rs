use libsmb2_sys::smb2::smb2_ioctl as ioctl;

macro_rules! assert_ioctl_code {
    ($actual:expr, $expected:expr) => {
        assert_eq!($actual, $expected);
    };
}

// Trace: `include/smb2/smb2-ioctl.h:32`
// Spec: FSCTL_CREATE_OR_GET_OBJECT_ID exposes stable ioctl code#object ID create-or-get code is available
// - **GIVEN** C code includes `include/smb2/smb2-ioctl.h`
// - **WHEN** the caller references `FSCTL_CREATE_OR_GET_OBJECT_ID`
// - **THEN** the macro expands to `0x000900C0`
#[test]
fn test_smb2_ioctl_object_id_create_or_get_code_is_available() {
    assert_ioctl_code!(ioctl::FSCTL_CREATE_OR_GET_OBJECT_ID, 0x0009_00C0);
}

// Trace: `include/smb2/smb2-ioctl.h:33`
// Spec: FSCTL_DELETE_OBJECT_ID exposes stable ioctl code#object ID delete code is available
// - **GIVEN** C code includes `include/smb2/smb2-ioctl.h`
// - **WHEN** the caller references `FSCTL_DELETE_OBJECT_ID`
// - **THEN** the macro expands to `0x000900A0`
#[test]
fn test_smb2_ioctl_object_id_delete_code_is_available() {
    assert_ioctl_code!(ioctl::FSCTL_DELETE_OBJECT_ID, 0x0009_00A0);
}

// Trace: `include/smb2/smb2-ioctl.h:34`
// Spec: FSCTL_DELETE_REPARSE_POINT exposes stable ioctl code#reparse point delete code is available
// - **GIVEN** C code includes `include/smb2/smb2-ioctl.h`
// - **WHEN** the caller references `FSCTL_DELETE_REPARSE_POINT`
// - **THEN** the macro expands to `0x000900AC`
#[test]
fn test_smb2_ioctl_reparse_point_delete_code_is_available() {
    assert_ioctl_code!(ioctl::FSCTL_DELETE_REPARSE_POINT, 0x0009_00AC);
}

// Trace: `include/smb2/smb2-ioctl.h:35`
// Spec: FSCTL_DUPLICATE_EXTENTS_TO_FILE exposes stable ioctl code#duplicate extents code is available
// - **GIVEN** C code includes `include/smb2/smb2-ioctl.h`
// - **WHEN** the caller references `FSCTL_DUPLICATE_EXTENTS_TO_FILE`
// - **THEN** the macro expands to `0x00098344`
#[test]
fn test_smb2_ioctl_duplicate_extents_code_is_available() {
    assert_ioctl_code!(ioctl::FSCTL_DUPLICATE_EXTENTS_TO_FILE, 0x0009_8344);
}

// Trace: `include/smb2/smb2-ioctl.h:36`
// Spec: FSCTL_DUPLICATE_EXTENTS_TO_FILE_EX exposes stable ioctl code#extended duplicate extents code is available
// - **GIVEN** C code includes `include/smb2/smb2-ioctl.h`
// - **WHEN** the caller references `FSCTL_DUPLICATE_EXTENTS_TO_FILE_EX`
// - **THEN** the macro expands to `0x000983E8`
#[test]
fn test_smb2_ioctl_extended_duplicate_extents_code_is_available() {
    assert_ioctl_code!(ioctl::FSCTL_DUPLICATE_EXTENTS_TO_FILE_EX, 0x0009_83E8);
}

// Trace: `include/smb2/smb2-ioctl.h:37`
// Spec: FSCTL_FILESYSTEM_GET_STATISTICS exposes stable ioctl code#filesystem statistics code is available
// - **GIVEN** C code includes `include/smb2/smb2-ioctl.h`
// - **WHEN** the caller references `FSCTL_FILESYSTEM_GET_STATISTICS`
// - **THEN** the macro expands to `0x00090060`
#[test]
fn test_smb2_ioctl_filesystem_statistics_code_is_available() {
    assert_ioctl_code!(ioctl::FSCTL_FILESYSTEM_GET_STATISTICS, 0x0009_0060);
}

// Trace: `include/smb2/smb2-ioctl.h:38`, `include/smb2/smb2.h:978`
// Spec: FSCTL_FILE_LEVEL_TRIM exposes stable ioctl code#file level trim code is available
// - **GIVEN** C code includes `include/smb2/smb2-ioctl.h`
// - **WHEN** the caller references `FSCTL_FILE_LEVEL_TRIM`
// - **THEN** the macro expands to `0x00098208` and matches `SMB2_FSCTL_FILE_LEVEL_TRIM`
#[test]
fn test_smb2_ioctl_file_level_trim_code_is_available() {
    assert_ioctl_code!(ioctl::FSCTL_FILE_LEVEL_TRIM, 0x0009_8208);
}

// Trace: `include/smb2/smb2-ioctl.h:39`
// Spec: FSCTL_FIND_FILES_BY_SID exposes stable ioctl code#find files by SID code is available
// - **GIVEN** C code includes `include/smb2/smb2-ioctl.h`
// - **WHEN** the caller references `FSCTL_FIND_FILES_BY_SID`
// - **THEN** the macro expands to `0x0009008F`
#[test]
fn test_smb2_ioctl_find_files_by_sid_code_is_available() {
    assert_ioctl_code!(ioctl::FSCTL_FIND_FILES_BY_SID, 0x0009_008F);
}

// Trace: `include/smb2/smb2-ioctl.h:40`
// Spec: FSCTL_GET_COMPRESSION exposes stable ioctl code#get compression code is available
// - **GIVEN** C code includes `include/smb2/smb2-ioctl.h`
// - **WHEN** the caller references `FSCTL_GET_COMPRESSION`
// - **THEN** the macro expands to `0x0009003C`
#[test]
fn test_smb2_ioctl_get_compression_code_is_available() {
    assert_ioctl_code!(ioctl::FSCTL_GET_COMPRESSION, 0x0009_003C);
}

// Trace: `include/smb2/smb2-ioctl.h:41`
// Spec: FSCTL_GET_INTEGRITY_INFORMATION exposes stable ioctl code#get integrity information code is available
// - **GIVEN** C code includes `include/smb2/smb2-ioctl.h`
// - **WHEN** the caller references `FSCTL_GET_INTEGRITY_INFORMATION`
// - **THEN** the macro expands to `0x0009027C`
#[test]
fn test_smb2_ioctl_get_integrity_information_code_is_available() {
    assert_ioctl_code!(ioctl::FSCTL_GET_INTEGRITY_INFORMATION, 0x0009_027C);
}

// Trace: `include/smb2/smb2-ioctl.h:42`
// Spec: FSCTL_GET_NTFS_VOLUME_DATA exposes stable ioctl code#NTFS volume data code is available
// - **GIVEN** C code includes `include/smb2/smb2-ioctl.h`
// - **WHEN** the caller references `FSCTL_GET_NTFS_VOLUME_DATA`
// - **THEN** the macro expands to `0x00090064`
#[test]
fn test_smb2_ioctl_ntfs_volume_data_code_is_available() {
    assert_ioctl_code!(ioctl::FSCTL_GET_NTFS_VOLUME_DATA, 0x0009_0064);
}

// Trace: `include/smb2/smb2-ioctl.h:43`
// Spec: FSCTL_GET_REFS_VOLUME_DATA exposes stable ioctl code#ReFS volume data code is available
// - **GIVEN** C code includes `include/smb2/smb2-ioctl.h`
// - **WHEN** the caller references `FSCTL_GET_REFS_VOLUME_DATA`
// - **THEN** the macro expands to `0x000902D8`
#[test]
fn test_smb2_ioctl_refs_volume_data_code_is_available() {
    assert_ioctl_code!(ioctl::FSCTL_GET_REFS_VOLUME_DATA, 0x0009_02D8);
}

// Trace: `include/smb2/smb2-ioctl.h:44`
// Spec: FSCTL_GET_OBJECT_ID exposes stable ioctl code#get object ID code is available
// - **GIVEN** C code includes `include/smb2/smb2-ioctl.h`
// - **WHEN** the caller references `FSCTL_GET_OBJECT_ID`
// - **THEN** the macro expands to `0x0009009C`
#[test]
fn test_smb2_ioctl_get_object_id_code_is_available() {
    assert_ioctl_code!(ioctl::FSCTL_GET_OBJECT_ID, 0x0009_009C);
}

// Trace: `include/smb2/smb2-ioctl.h:45`, `include/smb2/smb2.h:976`
// Spec: FSCTL_GET_REPARSE_POINT exposes stable ioctl code#get reparse point code is available
// - **GIVEN** C code includes `include/smb2/smb2-ioctl.h`
// - **WHEN** the caller references `FSCTL_GET_REPARSE_POINT`
// - **THEN** the macro expands to `0x000900A8` and matches `SMB2_FSCTL_GET_REPARSE_POINT`
#[test]
fn test_smb2_ioctl_get_reparse_point_code_is_available() {
    assert_ioctl_code!(ioctl::FSCTL_GET_REPARSE_POINT, 0x0009_00A8);
}

// Trace: `include/smb2/smb2-ioctl.h:46`
// Spec: FSCTL_GET_RETRIEVAL_POINTER_COUNT exposes stable ioctl code#retrieval pointer count code is available
// - **GIVEN** C code includes `include/smb2/smb2-ioctl.h`
// - **WHEN** the caller references `FSCTL_GET_RETRIEVAL_POINTER_COUNT`
// - **THEN** the macro expands to `0x0009042B`
#[test]
fn test_smb2_ioctl_retrieval_pointer_count_code_is_available() {
    assert_ioctl_code!(ioctl::FSCTL_GET_RETRIEVAL_POINTER_COUNT, 0x0009_042B);
}

// Trace: `include/smb2/smb2-ioctl.h:47`
// Spec: FSCTL_GET_RETRIEVAL_POINTERS exposes stable ioctl code#retrieval pointers code is available
// - **GIVEN** C code includes `include/smb2/smb2-ioctl.h`
// - **WHEN** the caller references `FSCTL_GET_RETRIEVAL_POINTERS`
// - **THEN** the macro expands to `0x00090073`
#[test]
fn test_smb2_ioctl_retrieval_pointers_code_is_available() {
    assert_ioctl_code!(ioctl::FSCTL_GET_RETRIEVAL_POINTERS, 0x0009_0073);
}

// Trace: `include/smb2/smb2-ioctl.h:48`
// Spec: FSCTL_GET_RETRIEVAL_POINTERS_AND_REFCOUNT exposes stable ioctl code#retrieval pointers and refcount code is available
// - **GIVEN** C code includes `include/smb2/smb2-ioctl.h`
// - **WHEN** the caller references `FSCTL_GET_RETRIEVAL_POINTERS_AND_REFCOUNT`
// - **THEN** the macro expands to `0x000903D3`
#[test]
fn test_smb2_ioctl_retrieval_pointers_and_refcount_code_is_available() {
    assert_ioctl_code!(
        ioctl::FSCTL_GET_RETRIEVAL_POINTERS_AND_REFCOUNT,
        0x0009_03D3
    );
}

// Trace: `include/smb2/smb2-ioctl.h:49`
// Spec: FSCTL_IS_PATHNAME_VALID exposes stable ioctl code#pathname validation code is available
// - **GIVEN** C code includes `include/smb2/smb2-ioctl.h`
// - **WHEN** the caller references `FSCTL_IS_PATHNAME_VALID`
// - **THEN** the macro expands to `0x0009002C`
#[test]
fn test_smb2_ioctl_pathname_validation_code_is_available() {
    assert_ioctl_code!(ioctl::FSCTL_IS_PATHNAME_VALID, 0x0009_002C);
}

// Trace: `include/smb2/smb2-ioctl.h:50`
// Spec: FSCTL_LMR_SET_LINK_TRACKING_INFORMATION exposes stable ioctl code#link tracking information code is available
// - **GIVEN** C code includes `include/smb2/smb2-ioctl.h`
// - **WHEN** the caller references `FSCTL_LMR_SET_LINK_TRACKING_INFORMATION`
// - **THEN** the macro expands to `0x001400EC`
#[test]
fn test_smb2_ioctl_link_tracking_information_code_is_available() {
    assert_ioctl_code!(ioctl::FSCTL_LMR_SET_LINK_TRACKING_INFORMATION, 0x0014_00EC);
}

// Trace: `include/smb2/smb2-ioctl.h:51`
// Spec: FSCTL_MARK_HANDLE exposes stable ioctl code#mark handle code is available
// - **GIVEN** C code includes `include/smb2/smb2-ioctl.h`
// - **WHEN** the caller references `FSCTL_MARK_HANDLE`
// - **THEN** the macro expands to `0x000900FC`
#[test]
fn test_smb2_ioctl_mark_handle_code_is_available() {
    assert_ioctl_code!(ioctl::FSCTL_MARK_HANDLE, 0x0009_00FC);
}

// Trace: `include/smb2/smb2-ioctl.h:52`
// Spec: FSCTL_OFFLOAD_READ exposes stable ioctl code#offload read code is available
// - **GIVEN** C code includes `include/smb2/smb2-ioctl.h`
// - **WHEN** the caller references `FSCTL_OFFLOAD_READ`
// - **THEN** the macro expands to `0x00094264`
#[test]
fn test_smb2_ioctl_offload_read_code_is_available() {
    assert_ioctl_code!(ioctl::FSCTL_OFFLOAD_READ, 0x0009_4264);
}

// Trace: `include/smb2/smb2-ioctl.h:53`
// Spec: FSCTL_OFFLOAD_WRITE exposes stable ioctl code#offload write code is available
// - **GIVEN** C code includes `include/smb2/smb2-ioctl.h`
// - **WHEN** the caller references `FSCTL_OFFLOAD_WRITE`
// - **THEN** the macro expands to `0x00098268`
#[test]
fn test_smb2_ioctl_offload_write_code_is_available() {
    assert_ioctl_code!(ioctl::FSCTL_OFFLOAD_WRITE, 0x0009_8268);
}

// Trace: `include/smb2/smb2-ioctl.h:54`, `include/smb2/smb2.h:965`
// Spec: FSCTL_PIPE_PEEK exposes stable ioctl code#pipe peek code is available
// - **GIVEN** C code includes `include/smb2/smb2-ioctl.h`
// - **WHEN** the caller references `FSCTL_PIPE_PEEK`
// - **THEN** the macro expands to `0x0011400C` and matches `SMB2_FSCTL_PIPE_PEEK`
#[test]
fn test_smb2_ioctl_pipe_peek_code_is_available() {
    assert_ioctl_code!(ioctl::FSCTL_PIPE_PEEK, 0x0011_400C);
}

// Trace: `include/smb2/smb2-ioctl.h:55`, `include/smb2/smb2.h:967`
// Spec: FSCTL_PIPE_TRANSCEIVE exposes stable ioctl code#pipe transceive code is available
// - **GIVEN** C code includes `include/smb2/smb2-ioctl.h`
// - **WHEN** the caller references `FSCTL_PIPE_TRANSCEIVE`
// - **THEN** the macro expands to `0x0011C017` and matches `SMB2_FSCTL_PIPE_TRANSCEIVE`
#[test]
fn test_smb2_ioctl_pipe_transceive_code_is_available() {
    assert_ioctl_code!(ioctl::FSCTL_PIPE_TRANSCEIVE, 0x0011_C017);
}

// Trace: `include/smb2/smb2-ioctl.h:56`, `include/smb2/smb2.h:966`
// Spec: FSCTL_PIPE_WAIT exposes stable ioctl code#pipe wait code is available
// - **GIVEN** C code includes `include/smb2/smb2-ioctl.h`
// - **WHEN** the caller references `FSCTL_PIPE_WAIT`
// - **THEN** the macro expands to `0x00110018` and matches `SMB2_FSCTL_PIPE_WAIT`
#[test]
fn test_smb2_ioctl_pipe_wait_code_is_available() {
    assert_ioctl_code!(ioctl::FSCTL_PIPE_WAIT, 0x0011_0018);
}

// Trace: `include/smb2/smb2-ioctl.h:57`
// Spec: FSCTL_QUERY_ALLOCATED_RANGES exposes stable ioctl code#allocated ranges query code is available
// - **GIVEN** C code includes `include/smb2/smb2-ioctl.h`
// - **WHEN** the caller references `FSCTL_QUERY_ALLOCATED_RANGES`
// - **THEN** the macro expands to `0x000940CF`
#[test]
fn test_smb2_ioctl_allocated_ranges_query_code_is_available() {
    assert_ioctl_code!(ioctl::FSCTL_QUERY_ALLOCATED_RANGES, 0x0009_40CF);
}

// Trace: `include/smb2/smb2-ioctl.h:58`
// Spec: FSCTL_QUERY_FAT_BPB exposes stable ioctl code#FAT BPB query code is available
// - **GIVEN** C code includes `include/smb2/smb2-ioctl.h`
// - **WHEN** the caller references `FSCTL_QUERY_FAT_BPB`
// - **THEN** the macro expands to `0x00090058`
#[test]
fn test_smb2_ioctl_fat_bpb_query_code_is_available() {
    assert_ioctl_code!(ioctl::FSCTL_QUERY_FAT_BPB, 0x0009_0058);
}

// Trace: `include/smb2/smb2-ioctl.h:59`
// Spec: FSCTL_QUERY_FILE_REGIONS exposes stable ioctl code#file regions query code is available
// - **GIVEN** C code includes `include/smb2/smb2-ioctl.h`
// - **WHEN** the caller references `FSCTL_QUERY_FILE_REGIONS`
// - **THEN** the macro expands to `0x00090284`
#[test]
fn test_smb2_ioctl_file_regions_query_code_is_available() {
    assert_ioctl_code!(ioctl::FSCTL_QUERY_FILE_REGIONS, 0x0009_0284);
}

// Trace: `include/smb2/smb2-ioctl.h:60`
// Spec: FSCTL_QUERY_ON_DISK_VOLUME_INFO exposes stable ioctl code#on-disk volume information query code is available
// - **GIVEN** C code includes `include/smb2/smb2-ioctl.h`
// - **WHEN** the caller references `FSCTL_QUERY_ON_DISK_VOLUME_INFO`
// - **THEN** the macro expands to `0x0009013C`
#[test]
fn test_smb2_ioctl_on_disk_volume_information_query_code_is_available() {
    assert_ioctl_code!(ioctl::FSCTL_QUERY_ON_DISK_VOLUME_INFO, 0x0009_013C);
}

// Trace: `include/smb2/smb2-ioctl.h:61`
// Spec: FSCTL_QUERY_SPARING_INFO exposes stable ioctl code#sparing information query code is available
// - **GIVEN** C code includes `include/smb2/smb2-ioctl.h`
// - **WHEN** the caller references `FSCTL_QUERY_SPARING_INFO`
// - **THEN** the macro expands to `0x00090138`
#[test]
fn test_smb2_ioctl_sparing_information_query_code_is_available() {
    assert_ioctl_code!(ioctl::FSCTL_QUERY_SPARING_INFO, 0x0009_0138);
}

// Trace: `include/smb2/smb2-ioctl.h:62`
// Spec: FSCTL_READ_FILE_USN_DATA exposes stable ioctl code#read file USN data code is available
// - **GIVEN** C code includes `include/smb2/smb2-ioctl.h`
// - **WHEN** the caller references `FSCTL_READ_FILE_USN_DATA`
// - **THEN** the macro expands to `0x000900EB`
#[test]
fn test_smb2_ioctl_read_file_usn_data_code_is_available() {
    assert_ioctl_code!(ioctl::FSCTL_READ_FILE_USN_DATA, 0x0009_00EB);
}

// Trace: `include/smb2/smb2-ioctl.h:63`
// Spec: FSCTL_RECALL_FILE exposes stable ioctl code#recall file code is available
// - **GIVEN** C code includes `include/smb2/smb2-ioctl.h`
// - **WHEN** the caller references `FSCTL_RECALL_FILE`
// - **THEN** the macro expands to `0x00090117`
#[test]
fn test_smb2_ioctl_recall_file_code_is_available() {
    assert_ioctl_code!(ioctl::FSCTL_RECALL_FILE, 0x0009_0117);
}

// Trace: `include/smb2/smb2-ioctl.h:64`
// Spec: FSCTL_REFS_STREAM_SNAPSHOT_MANAGEMENT exposes stable ioctl code#ReFS stream snapshot management code is available
// - **GIVEN** C code includes `include/smb2/smb2-ioctl.h`
// - **WHEN** the caller references `FSCTL_REFS_STREAM_SNAPSHOT_MANAGEMENT`
// - **THEN** the macro expands to `0x00090440`
#[test]
fn test_smb2_ioctl_refs_stream_snapshot_management_code_is_available() {
    assert_ioctl_code!(ioctl::FSCTL_REFS_STREAM_SNAPSHOT_MANAGEMENT, 0x0009_0440);
}

// Trace: `include/smb2/smb2-ioctl.h:65`
// Spec: FSCTL_SET_COMPRESSION exposes stable ioctl code#set compression code is available
// - **GIVEN** C code includes `include/smb2/smb2-ioctl.h`
// - **WHEN** the caller references `FSCTL_SET_COMPRESSION`
// - **THEN** the macro expands to `0x0009C040`
#[test]
fn test_smb2_ioctl_set_compression_code_is_available() {
    assert_ioctl_code!(ioctl::FSCTL_SET_COMPRESSION, 0x0009_C040);
}

// Trace: `include/smb2/smb2-ioctl.h:66`
// Spec: FSCTL_SET_DEFECT_MANAGEMENT exposes stable ioctl code#set defect management code is available
// - **GIVEN** C code includes `include/smb2/smb2-ioctl.h`
// - **WHEN** the caller references `FSCTL_SET_DEFECT_MANAGEMENT`
// - **THEN** the macro expands to `0x00098134`
#[test]
fn test_smb2_ioctl_set_defect_management_code_is_available() {
    assert_ioctl_code!(ioctl::FSCTL_SET_DEFECT_MANAGEMENT, 0x0009_8134);
}

// Trace: `include/smb2/smb2-ioctl.h:67`
// Spec: FSCTL_SET_ENCRYPTION exposes stable ioctl code#set encryption code is available
// - **GIVEN** C code includes `include/smb2/smb2-ioctl.h`
// - **WHEN** the caller references `FSCTL_SET_ENCRYPTION`
// - **THEN** the macro expands to `0x000900D7`
#[test]
fn test_smb2_ioctl_set_encryption_code_is_available() {
    assert_ioctl_code!(ioctl::FSCTL_SET_ENCRYPTION, 0x0009_00D7);
}

// Trace: `include/smb2/smb2-ioctl.h:68`
// Spec: FSCTL_SET_INTEGRITY_INFORMATION exposes stable ioctl code#set integrity information code is available
// - **GIVEN** C code includes `include/smb2/smb2-ioctl.h`
// - **WHEN** the caller references `FSCTL_SET_INTEGRITY_INFORMATION`
// - **THEN** the macro expands to `0x0009C280`
#[test]
fn test_smb2_ioctl_set_integrity_information_code_is_available() {
    assert_ioctl_code!(ioctl::FSCTL_SET_INTEGRITY_INFORMATION, 0x0009_C280);
}

// Trace: `include/smb2/smb2-ioctl.h:69`
// Spec: FSCTL_SET_INTEGRITY_INFORMATION_EX exposes stable ioctl code#extended set integrity information code is available
// - **GIVEN** C code includes `include/smb2/smb2-ioctl.h`
// - **WHEN** the caller references `FSCTL_SET_INTEGRITY_INFORMATION_EX`
// - **THEN** the macro expands to `0x00090380`
#[test]
fn test_smb2_ioctl_extended_set_integrity_information_code_is_available() {
    assert_ioctl_code!(ioctl::FSCTL_SET_INTEGRITY_INFORMATION_EX, 0x0009_0380);
}

// Trace: `include/smb2/smb2-ioctl.h:70`
// Spec: FSCTL_SET_OBJECT_ID exposes stable ioctl code#set object ID code is available
// - **GIVEN** C code includes `include/smb2/smb2-ioctl.h`
// - **WHEN** the caller references `FSCTL_SET_OBJECT_ID`
// - **THEN** the macro expands to `0x00090098`
#[test]
fn test_smb2_ioctl_set_object_id_code_is_available() {
    assert_ioctl_code!(ioctl::FSCTL_SET_OBJECT_ID, 0x0009_0098);
}

// Trace: `include/smb2/smb2-ioctl.h:71`
// Spec: FSCTL_SET_OBJECT_ID_EXTENDED exposes stable ioctl code#extended set object ID code is available
// - **GIVEN** C code includes `include/smb2/smb2-ioctl.h`
// - **WHEN** the caller references `FSCTL_SET_OBJECT_ID_EXTENDED`
// - **THEN** the macro expands to `0x000900BC`
#[test]
fn test_smb2_ioctl_extended_set_object_id_code_is_available() {
    assert_ioctl_code!(ioctl::FSCTL_SET_OBJECT_ID_EXTENDED, 0x0009_00BC);
}

// Trace: `include/smb2/smb2-ioctl.h:72`, `include/smb2/smb2.h:975`
// Spec: FSCTL_SET_REPARSE_POINT exposes stable ioctl code#set reparse point code is available
// - **GIVEN** C code includes `include/smb2/smb2-ioctl.h`
// - **WHEN** the caller references `FSCTL_SET_REPARSE_POINT`
// - **THEN** the macro expands to `0x000900A4` and matches `SMB2_FSCTL_SET_REPARSE_POINT`
#[test]
fn test_smb2_ioctl_set_reparse_point_code_is_available() {
    assert_ioctl_code!(ioctl::FSCTL_SET_REPARSE_POINT, 0x0009_00A4);
}

// Trace: `include/smb2/smb2-ioctl.h:73`
// Spec: FSCTL_SET_SPARSE exposes stable ioctl code#set sparse code is available
// - **GIVEN** C code includes `include/smb2/smb2-ioctl.h`
// - **WHEN** the caller references `FSCTL_SET_SPARSE`
// - **THEN** the macro expands to `0x000900C4`
#[test]
fn test_smb2_ioctl_set_sparse_code_is_available() {
    assert_ioctl_code!(ioctl::FSCTL_SET_SPARSE, 0x0009_00C4);
}

// Trace: `include/smb2/smb2-ioctl.h:74`
// Spec: FSCTL_SET_ZERO_DATA exposes stable ioctl code#set zero data code is available
// - **GIVEN** C code includes `include/smb2/smb2-ioctl.h`
// - **WHEN** the caller references `FSCTL_SET_ZERO_DATA`
// - **THEN** the macro expands to `0x000980C8`
#[test]
fn test_smb2_ioctl_set_zero_data_code_is_available() {
    assert_ioctl_code!(ioctl::FSCTL_SET_ZERO_DATA, 0x0009_80C8);
}

// Trace: `include/smb2/smb2-ioctl.h:75`
// Spec: FSCTL_SET_ZERO_ON_DEALLOCATION exposes stable ioctl code#set zero on deallocation code is available
// - **GIVEN** C code includes `include/smb2/smb2-ioctl.h`
// - **WHEN** the caller references `FSCTL_SET_ZERO_ON_DEALLOCATION`
// - **THEN** the macro expands to `0x00090194`
#[test]
fn test_smb2_ioctl_set_zero_on_deallocation_code_is_available() {
    assert_ioctl_code!(ioctl::FSCTL_SET_ZERO_ON_DEALLOCATION, 0x0009_0194);
}

// Trace: `include/smb2/smb2-ioctl.h:76`
// Spec: FSCTL_SIS_COPYFILE exposes stable ioctl code#SIS copyfile code is available
// - **GIVEN** C code includes `include/smb2/smb2-ioctl.h`
// - **WHEN** the caller references `FSCTL_SIS_COPYFILE`
// - **THEN** the macro expands to `0x00090100`
#[test]
fn test_smb2_ioctl_sis_copyfile_code_is_available() {
    assert_ioctl_code!(ioctl::FSCTL_SIS_COPYFILE, 0x0009_0100);
}

// Trace: `include/smb2/smb2-ioctl.h:77`
// Spec: FSCTL_WRITE_USN_CLOSE_RECORD exposes stable ioctl code#write USN close record code is available
// - **GIVEN** C code includes `include/smb2/smb2-ioctl.h`
// - **WHEN** the caller references `FSCTL_WRITE_USN_CLOSE_RECORD`
// - **THEN** the macro expands to `0x000900EF`
#[test]
fn test_smb2_ioctl_write_usn_close_record_code_is_available() {
    assert_ioctl_code!(ioctl::FSCTL_WRITE_USN_CLOSE_RECORD, 0x0009_00EF);
}

// Trace: `include/smb2/smb2-ioctl.h:79`, `include/smb2/smb2.h:969`
// Spec: FSCTL_SRV_ENUMERATE_SNAPSHOTS exposes stable ioctl code#server snapshot enumeration code is available
// - **GIVEN** C code includes `include/smb2/smb2-ioctl.h`
// - **WHEN** the caller references `FSCTL_SRV_ENUMERATE_SNAPSHOTS`
// - **THEN** the macro expands to `0x00144064` and matches `SMB2_FSCTL_SRV_ENUMERATE_SNAPSHOTS`
#[test]
fn test_smb2_ioctl_server_snapshot_enumeration_code_is_available() {
    assert_ioctl_code!(ioctl::FSCTL_SRV_ENUMERATE_SNAPSHOTS, 0x0014_4064);
}

// Trace: `include/smb2/smb2-ioctl.h:79`, `include/smb2/smb2-ioctl.h:80`
// Spec: FSCTL_GET_SHADOW_COPY_DATA aliases snapshot enumeration code#shadow copy data alias is available
// - **GIVEN** C code includes `include/smb2/smb2-ioctl.h`
// - **WHEN** the caller references `FSCTL_GET_SHADOW_COPY_DATA`
// - **THEN** the macro expands to `0x00144064` and is numerically identical to `FSCTL_SRV_ENUMERATE_SNAPSHOTS`
#[test]
fn test_smb2_ioctl_shadow_copy_data_alias_is_available() {
    assert_ioctl_code!(ioctl::FSCTL_GET_SHADOW_COPY_DATA, 0x0014_4064);
    assert_eq!(
        ioctl::FSCTL_GET_SHADOW_COPY_DATA,
        ioctl::FSCTL_SRV_ENUMERATE_SNAPSHOTS
    );
}
