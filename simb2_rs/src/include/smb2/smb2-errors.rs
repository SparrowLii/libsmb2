//! NTSTATUS constants and light-weight helpers from `include/smb2/smb2-errors.h`.
//!
//! This module mirrors the header-level responsibilities only: named status
//! values, NTSTATUS bit-field helpers, and small lookup primitives. It does not
//! implement SMB2 protocol handling or a complete errno translation table.

macro_rules! smb2_status_const {
    ($name:ident, $value:expr, $description:expr) => {
        #[doc = $description]
        pub const $name: u32 = $value;
    };
}

smb2_status_const!(
    SMB2_STATUS_SEVERITY_MASK,
    0xC000_0000,
    "NTSTATUS field constant `SMB2_STATUS_SEVERITY_MASK`."
);
smb2_status_const!(
    SMB2_STATUS_SEVERITY_SUCCESS,
    0x0000_0000,
    "NTSTATUS field constant `SMB2_STATUS_SEVERITY_SUCCESS`."
);
smb2_status_const!(
    SMB2_STATUS_SEVERITY_INFO,
    0x4000_0000,
    "NTSTATUS field constant `SMB2_STATUS_SEVERITY_INFO`."
);
smb2_status_const!(
    SMB2_STATUS_SEVERITY_WARNING,
    0x8000_0000,
    "NTSTATUS field constant `SMB2_STATUS_SEVERITY_WARNING`."
);
smb2_status_const!(
    SMB2_STATUS_SEVERITY_ERROR,
    0xC000_0000,
    "NTSTATUS field constant `SMB2_STATUS_SEVERITY_ERROR`."
);
smb2_status_const!(
    SMB2_STATUS_CUSTOMER_MASK,
    0x2000_0000,
    "NTSTATUS field constant `SMB2_STATUS_CUSTOMER_MASK`."
);
smb2_status_const!(
    SMB2_STATUS_FACILITY_MASK,
    0x0FFF_0000,
    "NTSTATUS field constant `SMB2_STATUS_FACILITY_MASK`."
);
smb2_status_const!(
    SMB2_STATUS_CODE_MASK,
    0x0000_FFFF,
    "NTSTATUS field constant `SMB2_STATUS_CODE_MASK`."
);
smb2_status_const!(
    SMB2_STATUS_SUCCESS,
    0x0000_0000,
    "SMB2 error status constant `SMB2_STATUS_SUCCESS`."
);
smb2_status_const!(
    SMB2_STATUS_SHUTDOWN,
    0xFFFF_FFFF,
    "SMB2 error status constant `SMB2_STATUS_SHUTDOWN`."
);
smb2_status_const!(
    SMB2_STATUS_PENDING,
    0x0000_0103,
    "SMB2 error status constant `SMB2_STATUS_PENDING`."
);
smb2_status_const!(
    SMB2_STATUS_SMB_BAD_FID,
    0x0006_0001,
    "SMB2 error status constant `SMB2_STATUS_SMB_BAD_FID`."
);
smb2_status_const!(
    SMB2_STATUS_NO_MORE_FILES,
    0x8000_0006,
    "SMB2 error status constant `SMB2_STATUS_NO_MORE_FILES`."
);
smb2_status_const!(
    SMB2_STATUS_UNSUCCESSFUL,
    0xC000_0001,
    "SMB2 error status constant `SMB2_STATUS_UNSUCCESSFUL`."
);
smb2_status_const!(
    SMB2_STATUS_NOT_IMPLEMENTED,
    0xC000_0002,
    "SMB2 error status constant `SMB2_STATUS_NOT_IMPLEMENTED`."
);
smb2_status_const!(
    SMB2_STATUS_INVALID_INFO_CLASS,
    0xC000_0003,
    "SMB2 error status constant `SMB2_STATUS_INVALID_INFO_CLASS`."
);
smb2_status_const!(
    SMB2_STATUS_INFO_LENGTH_MISMATCH,
    0xC000_0004,
    "SMB2 error status constant `SMB2_STATUS_INFO_LENGTH_MISMATCH`."
);
smb2_status_const!(
    SMB2_STATUS_ACCESS_VIOLATION,
    0xC000_0005,
    "SMB2 error status constant `SMB2_STATUS_ACCESS_VIOLATION`."
);
smb2_status_const!(
    SMB2_STATUS_IN_PAGE_ERROR,
    0xC000_0006,
    "SMB2 error status constant `SMB2_STATUS_IN_PAGE_ERROR`."
);
smb2_status_const!(
    SMB2_STATUS_PAGEFILE_QUOTA,
    0xC000_0007,
    "SMB2 error status constant `SMB2_STATUS_PAGEFILE_QUOTA`."
);
smb2_status_const!(
    SMB2_STATUS_INVALID_HANDLE,
    0xC000_0008,
    "SMB2 error status constant `SMB2_STATUS_INVALID_HANDLE`."
);
smb2_status_const!(
    SMB2_STATUS_BAD_INITIAL_STACK,
    0xC000_0009,
    "SMB2 error status constant `SMB2_STATUS_BAD_INITIAL_STACK`."
);
smb2_status_const!(
    SMB2_STATUS_BAD_INITIAL_PC,
    0xC000_000A,
    "SMB2 error status constant `SMB2_STATUS_BAD_INITIAL_PC`."
);
smb2_status_const!(
    SMB2_STATUS_INVALID_CID,
    0xC000_000B,
    "SMB2 error status constant `SMB2_STATUS_INVALID_CID`."
);
smb2_status_const!(
    SMB2_STATUS_TIMER_NOT_CANCELED,
    0xC000_000C,
    "SMB2 error status constant `SMB2_STATUS_TIMER_NOT_CANCELED`."
);
smb2_status_const!(
    SMB2_STATUS_INVALID_PARAMETER,
    0xC000_000D,
    "SMB2 error status constant `SMB2_STATUS_INVALID_PARAMETER`."
);
smb2_status_const!(
    SMB2_STATUS_NO_SUCH_DEVICE,
    0xC000_000E,
    "SMB2 error status constant `SMB2_STATUS_NO_SUCH_DEVICE`."
);
smb2_status_const!(
    SMB2_STATUS_NO_SUCH_FILE,
    0xC000_000F,
    "SMB2 error status constant `SMB2_STATUS_NO_SUCH_FILE`."
);
smb2_status_const!(
    SMB2_STATUS_INVALID_DEVICE_REQUEST,
    0xC000_0010,
    "SMB2 error status constant `SMB2_STATUS_INVALID_DEVICE_REQUEST`."
);
smb2_status_const!(
    SMB2_STATUS_END_OF_FILE,
    0xC000_0011,
    "SMB2 error status constant `SMB2_STATUS_END_OF_FILE`."
);
smb2_status_const!(
    SMB2_STATUS_WRONG_VOLUME,
    0xC000_0012,
    "SMB2 error status constant `SMB2_STATUS_WRONG_VOLUME`."
);
smb2_status_const!(
    SMB2_STATUS_NO_MEDIA_IN_DEVICE,
    0xC000_0013,
    "SMB2 error status constant `SMB2_STATUS_NO_MEDIA_IN_DEVICE`."
);
smb2_status_const!(
    SMB2_STATUS_UNRECOGNIZED_MEDIA,
    0xC000_0014,
    "SMB2 error status constant `SMB2_STATUS_UNRECOGNIZED_MEDIA`."
);
smb2_status_const!(
    SMB2_STATUS_NONEXISTENT_SECTOR,
    0xC000_0015,
    "SMB2 error status constant `SMB2_STATUS_NONEXISTENT_SECTOR`."
);
smb2_status_const!(
    SMB2_STATUS_MORE_PROCESSING_REQUIRED,
    0xC000_0016,
    "SMB2 error status constant `SMB2_STATUS_MORE_PROCESSING_REQUIRED`."
);
smb2_status_const!(
    SMB2_STATUS_NO_MEMORY,
    0xC000_0017,
    "SMB2 error status constant `SMB2_STATUS_NO_MEMORY`."
);
smb2_status_const!(
    SMB2_STATUS_CONFLICTING_ADDRESSES,
    0xC000_0018,
    "SMB2 error status constant `SMB2_STATUS_CONFLICTING_ADDRESSES`."
);
smb2_status_const!(
    SMB2_STATUS_NOT_MAPPED_VIEW,
    0xC000_0019,
    "SMB2 error status constant `SMB2_STATUS_NOT_MAPPED_VIEW`."
);
smb2_status_const!(
    SMB2_STATUS_UNABLE_TO_FREE_VM,
    0xC000_001A,
    "SMB2 error status constant `SMB2_STATUS_UNABLE_TO_FREE_VM`."
);
smb2_status_const!(
    SMB2_STATUS_UNABLE_TO_DELETE_SECTION,
    0xC000_001B,
    "SMB2 error status constant `SMB2_STATUS_UNABLE_TO_DELETE_SECTION`."
);
smb2_status_const!(
    SMB2_STATUS_INVALID_SYSTEM_SERVICE,
    0xC000_001C,
    "SMB2 error status constant `SMB2_STATUS_INVALID_SYSTEM_SERVICE`."
);
smb2_status_const!(
    SMB2_STATUS_ILLEGAL_INSTRUCTION,
    0xC000_001D,
    "SMB2 error status constant `SMB2_STATUS_ILLEGAL_INSTRUCTION`."
);
smb2_status_const!(
    SMB2_STATUS_INVALID_LOCK_SEQUENCE,
    0xC000_001E,
    "SMB2 error status constant `SMB2_STATUS_INVALID_LOCK_SEQUENCE`."
);
smb2_status_const!(
    SMB2_STATUS_INVALID_VIEW_SIZE,
    0xC000_001F,
    "SMB2 error status constant `SMB2_STATUS_INVALID_VIEW_SIZE`."
);
smb2_status_const!(
    SMB2_STATUS_INVALID_FILE_FOR_SECTION,
    0xC000_0020,
    "SMB2 error status constant `SMB2_STATUS_INVALID_FILE_FOR_SECTION`."
);
smb2_status_const!(
    SMB2_STATUS_ALREADY_COMMITTED,
    0xC000_0021,
    "SMB2 error status constant `SMB2_STATUS_ALREADY_COMMITTED`."
);
smb2_status_const!(
    SMB2_STATUS_ACCESS_DENIED,
    0xC000_0022,
    "SMB2 error status constant `SMB2_STATUS_ACCESS_DENIED`."
);
smb2_status_const!(
    SMB2_STATUS_BUFFER_TOO_SMALL,
    0xC000_0023,
    "SMB2 error status constant `SMB2_STATUS_BUFFER_TOO_SMALL`."
);
smb2_status_const!(
    SMB2_STATUS_OBJECT_TYPE_MISMATCH,
    0xC000_0024,
    "SMB2 error status constant `SMB2_STATUS_OBJECT_TYPE_MISMATCH`."
);
smb2_status_const!(
    SMB2_STATUS_NONCONTINUABLE_EXCEPTION,
    0xC000_0025,
    "SMB2 error status constant `SMB2_STATUS_NONCONTINUABLE_EXCEPTION`."
);
smb2_status_const!(
    SMB2_STATUS_INVALID_DISPOSITION,
    0xC000_0026,
    "SMB2 error status constant `SMB2_STATUS_INVALID_DISPOSITION`."
);
smb2_status_const!(
    SMB2_STATUS_UNWIND,
    0xC000_0027,
    "SMB2 error status constant `SMB2_STATUS_UNWIND`."
);
smb2_status_const!(
    SMB2_STATUS_BAD_STACK,
    0xC000_0028,
    "SMB2 error status constant `SMB2_STATUS_BAD_STACK`."
);
smb2_status_const!(
    SMB2_STATUS_INVALID_UNWIND_TARGET,
    0xC000_0029,
    "SMB2 error status constant `SMB2_STATUS_INVALID_UNWIND_TARGET`."
);
smb2_status_const!(
    SMB2_STATUS_NOT_LOCKED,
    0xC000_002A,
    "SMB2 error status constant `SMB2_STATUS_NOT_LOCKED`."
);
smb2_status_const!(
    SMB2_STATUS_PARITY_ERROR,
    0xC000_002B,
    "SMB2 error status constant `SMB2_STATUS_PARITY_ERROR`."
);
smb2_status_const!(
    SMB2_STATUS_UNABLE_TO_DECOMMIT_VM,
    0xC000_002C,
    "SMB2 error status constant `SMB2_STATUS_UNABLE_TO_DECOMMIT_VM`."
);
smb2_status_const!(
    SMB2_STATUS_NOT_COMMITTED,
    0xC000_002D,
    "SMB2 error status constant `SMB2_STATUS_NOT_COMMITTED`."
);
smb2_status_const!(
    SMB2_STATUS_INVALID_PORT_ATTRIBUTES,
    0xC000_002E,
    "SMB2 error status constant `SMB2_STATUS_INVALID_PORT_ATTRIBUTES`."
);
smb2_status_const!(
    SMB2_STATUS_PORT_MESSAGE_TOO_LONG,
    0xC000_002F,
    "SMB2 error status constant `SMB2_STATUS_PORT_MESSAGE_TOO_LONG`."
);
smb2_status_const!(
    SMB2_STATUS_INVALID_PARAMETER_MIX,
    0xC000_0030,
    "SMB2 error status constant `SMB2_STATUS_INVALID_PARAMETER_MIX`."
);
smb2_status_const!(
    SMB2_STATUS_INVALID_QUOTA_LOWER,
    0xC000_0031,
    "SMB2 error status constant `SMB2_STATUS_INVALID_QUOTA_LOWER`."
);
smb2_status_const!(
    SMB2_STATUS_DISK_CORRUPT_ERROR,
    0xC000_0032,
    "SMB2 error status constant `SMB2_STATUS_DISK_CORRUPT_ERROR`."
);
smb2_status_const!(
    SMB2_STATUS_OBJECT_NAME_INVALID,
    0xC000_0033,
    "SMB2 error status constant `SMB2_STATUS_OBJECT_NAME_INVALID`."
);
smb2_status_const!(
    SMB2_STATUS_OBJECT_NAME_NOT_FOUND,
    0xC000_0034,
    "SMB2 error status constant `SMB2_STATUS_OBJECT_NAME_NOT_FOUND`."
);
smb2_status_const!(
    SMB2_STATUS_OBJECT_NAME_COLLISION,
    0xC000_0035,
    "SMB2 error status constant `SMB2_STATUS_OBJECT_NAME_COLLISION`."
);
smb2_status_const!(
    SMB2_STATUS_HANDLE_NOT_WAITABLE,
    0xC000_0036,
    "SMB2 error status constant `SMB2_STATUS_HANDLE_NOT_WAITABLE`."
);
smb2_status_const!(
    SMB2_STATUS_PORT_DISCONNECTED,
    0xC000_0037,
    "SMB2 error status constant `SMB2_STATUS_PORT_DISCONNECTED`."
);
smb2_status_const!(
    SMB2_STATUS_DEVICE_ALREADY_ATTACHED,
    0xC000_0038,
    "SMB2 error status constant `SMB2_STATUS_DEVICE_ALREADY_ATTACHED`."
);
smb2_status_const!(
    SMB2_STATUS_OBJECT_PATH_INVALID,
    0xC000_0039,
    "SMB2 error status constant `SMB2_STATUS_OBJECT_PATH_INVALID`."
);
smb2_status_const!(
    SMB2_STATUS_OBJECT_PATH_NOT_FOUND,
    0xC000_003A,
    "SMB2 error status constant `SMB2_STATUS_OBJECT_PATH_NOT_FOUND`."
);
smb2_status_const!(
    SMB2_STATUS_OBJECT_PATH_SYNTAX_BAD,
    0xC000_003B,
    "SMB2 error status constant `SMB2_STATUS_OBJECT_PATH_SYNTAX_BAD`."
);
smb2_status_const!(
    SMB2_STATUS_DATA_OVERRUN,
    0xC000_003C,
    "SMB2 error status constant `SMB2_STATUS_DATA_OVERRUN`."
);
smb2_status_const!(
    SMB2_STATUS_DATA_LATE_ERROR,
    0xC000_003D,
    "SMB2 error status constant `SMB2_STATUS_DATA_LATE_ERROR`."
);
smb2_status_const!(
    SMB2_STATUS_DATA_ERROR,
    0xC000_003E,
    "SMB2 error status constant `SMB2_STATUS_DATA_ERROR`."
);
smb2_status_const!(
    SMB2_STATUS_CRC_ERROR,
    0xC000_003F,
    "SMB2 error status constant `SMB2_STATUS_CRC_ERROR`."
);
smb2_status_const!(
    SMB2_STATUS_SECTION_TOO_BIG,
    0xC000_0040,
    "SMB2 error status constant `SMB2_STATUS_SECTION_TOO_BIG`."
);
smb2_status_const!(
    SMB2_STATUS_PORT_CONNECTION_REFUSED,
    0xC000_0041,
    "SMB2 error status constant `SMB2_STATUS_PORT_CONNECTION_REFUSED`."
);
smb2_status_const!(
    SMB2_STATUS_INVALID_PORT_HANDLE,
    0xC000_0042,
    "SMB2 error status constant `SMB2_STATUS_INVALID_PORT_HANDLE`."
);
smb2_status_const!(
    SMB2_STATUS_SHARING_VIOLATION,
    0xC000_0043,
    "SMB2 error status constant `SMB2_STATUS_SHARING_VIOLATION`."
);
smb2_status_const!(
    SMB2_STATUS_QUOTA_EXCEEDED,
    0xC000_0044,
    "SMB2 error status constant `SMB2_STATUS_QUOTA_EXCEEDED`."
);
smb2_status_const!(
    SMB2_STATUS_INVALID_PAGE_PROTECTION,
    0xC000_0045,
    "SMB2 error status constant `SMB2_STATUS_INVALID_PAGE_PROTECTION`."
);
smb2_status_const!(
    SMB2_STATUS_MUTANT_NOT_OWNED,
    0xC000_0046,
    "SMB2 error status constant `SMB2_STATUS_MUTANT_NOT_OWNED`."
);
smb2_status_const!(
    SMB2_STATUS_SEMAPHORE_LIMIT_EXCEEDED,
    0xC000_0047,
    "SMB2 error status constant `SMB2_STATUS_SEMAPHORE_LIMIT_EXCEEDED`."
);
smb2_status_const!(
    SMB2_STATUS_PORT_ALREADY_SET,
    0xC000_0048,
    "SMB2 error status constant `SMB2_STATUS_PORT_ALREADY_SET`."
);
smb2_status_const!(
    SMB2_STATUS_SECTION_NOT_IMAGE,
    0xC000_0049,
    "SMB2 error status constant `SMB2_STATUS_SECTION_NOT_IMAGE`."
);
smb2_status_const!(
    SMB2_STATUS_SUSPEND_COUNT_EXCEEDED,
    0xC000_004A,
    "SMB2 error status constant `SMB2_STATUS_SUSPEND_COUNT_EXCEEDED`."
);
smb2_status_const!(
    SMB2_STATUS_THREAD_IS_TERMINATING,
    0xC000_004B,
    "SMB2 error status constant `SMB2_STATUS_THREAD_IS_TERMINATING`."
);
smb2_status_const!(
    SMB2_STATUS_BAD_WORKING_SET_LIMIT,
    0xC000_004C,
    "SMB2 error status constant `SMB2_STATUS_BAD_WORKING_SET_LIMIT`."
);
smb2_status_const!(
    SMB2_STATUS_INCOMPATIBLE_FILE_MAP,
    0xC000_004D,
    "SMB2 error status constant `SMB2_STATUS_INCOMPATIBLE_FILE_MAP`."
);
smb2_status_const!(
    SMB2_STATUS_SECTION_PROTECTION,
    0xC000_004E,
    "SMB2 error status constant `SMB2_STATUS_SECTION_PROTECTION`."
);
smb2_status_const!(
    SMB2_STATUS_EAS_NOT_SUPPORTED,
    0xC000_004F,
    "SMB2 error status constant `SMB2_STATUS_EAS_NOT_SUPPORTED`."
);
smb2_status_const!(
    SMB2_STATUS_EA_TOO_LARGE,
    0xC000_0050,
    "SMB2 error status constant `SMB2_STATUS_EA_TOO_LARGE`."
);
smb2_status_const!(
    SMB2_STATUS_NONEXISTENT_EA_ENTRY,
    0xC000_0051,
    "SMB2 error status constant `SMB2_STATUS_NONEXISTENT_EA_ENTRY`."
);
smb2_status_const!(
    SMB2_STATUS_NO_EAS_ON_FILE,
    0xC000_0052,
    "SMB2 error status constant `SMB2_STATUS_NO_EAS_ON_FILE`."
);
smb2_status_const!(
    SMB2_STATUS_EA_CORRUPT_ERROR,
    0xC000_0053,
    "SMB2 error status constant `SMB2_STATUS_EA_CORRUPT_ERROR`."
);
smb2_status_const!(
    SMB2_STATUS_FILE_LOCK_CONFLICT,
    0xC000_0054,
    "SMB2 error status constant `SMB2_STATUS_FILE_LOCK_CONFLICT`."
);
smb2_status_const!(
    SMB2_STATUS_LOCK_NOT_GRANTED,
    0xC000_0055,
    "SMB2 error status constant `SMB2_STATUS_LOCK_NOT_GRANTED`."
);
smb2_status_const!(
    SMB2_STATUS_DELETE_PENDING,
    0xC000_0056,
    "SMB2 error status constant `SMB2_STATUS_DELETE_PENDING`."
);
smb2_status_const!(
    SMB2_STATUS_CTL_FILE_NOT_SUPPORTED,
    0xC000_0057,
    "SMB2 error status constant `SMB2_STATUS_CTL_FILE_NOT_SUPPORTED`."
);
smb2_status_const!(
    SMB2_STATUS_UNKNOWN_REVISION,
    0xC000_0058,
    "SMB2 error status constant `SMB2_STATUS_UNKNOWN_REVISION`."
);
smb2_status_const!(
    SMB2_STATUS_REVISION_MISMATCH,
    0xC000_0059,
    "SMB2 error status constant `SMB2_STATUS_REVISION_MISMATCH`."
);
smb2_status_const!(
    SMB2_STATUS_INVALID_OWNER,
    0xC000_005A,
    "SMB2 error status constant `SMB2_STATUS_INVALID_OWNER`."
);
smb2_status_const!(
    SMB2_STATUS_INVALID_PRIMARY_GROUP,
    0xC000_005B,
    "SMB2 error status constant `SMB2_STATUS_INVALID_PRIMARY_GROUP`."
);
smb2_status_const!(
    SMB2_STATUS_NO_IMPERSONATION_TOKEN,
    0xC000_005C,
    "SMB2 error status constant `SMB2_STATUS_NO_IMPERSONATION_TOKEN`."
);
smb2_status_const!(
    SMB2_STATUS_CANT_DISABLE_MANDATORY,
    0xC000_005D,
    "SMB2 error status constant `SMB2_STATUS_CANT_DISABLE_MANDATORY`."
);
smb2_status_const!(
    SMB2_STATUS_NO_LOGON_SERVERS,
    0xC000_005E,
    "SMB2 error status constant `SMB2_STATUS_NO_LOGON_SERVERS`."
);
smb2_status_const!(
    SMB2_STATUS_NO_SUCH_LOGON_SESSION,
    0xC000_005F,
    "SMB2 error status constant `SMB2_STATUS_NO_SUCH_LOGON_SESSION`."
);
smb2_status_const!(
    SMB2_STATUS_NO_SUCH_PRIVILEGE,
    0xC000_0060,
    "SMB2 error status constant `SMB2_STATUS_NO_SUCH_PRIVILEGE`."
);
smb2_status_const!(
    SMB2_STATUS_PRIVILEGE_NOT_HELD,
    0xC000_0061,
    "SMB2 error status constant `SMB2_STATUS_PRIVILEGE_NOT_HELD`."
);
smb2_status_const!(
    SMB2_STATUS_INVALID_ACCOUNT_NAME,
    0xC000_0062,
    "SMB2 error status constant `SMB2_STATUS_INVALID_ACCOUNT_NAME`."
);
smb2_status_const!(
    SMB2_STATUS_USER_EXISTS,
    0xC000_0063,
    "SMB2 error status constant `SMB2_STATUS_USER_EXISTS`."
);
smb2_status_const!(
    SMB2_STATUS_NO_SUCH_USER,
    0xC000_0064,
    "SMB2 error status constant `SMB2_STATUS_NO_SUCH_USER`."
);
smb2_status_const!(
    SMB2_STATUS_GROUP_EXISTS,
    0xC000_0065,
    "SMB2 error status constant `SMB2_STATUS_GROUP_EXISTS`."
);
smb2_status_const!(
    SMB2_STATUS_NO_SUCH_GROUP,
    0xC000_0066,
    "SMB2 error status constant `SMB2_STATUS_NO_SUCH_GROUP`."
);
smb2_status_const!(
    SMB2_STATUS_MEMBER_IN_GROUP,
    0xC000_0067,
    "SMB2 error status constant `SMB2_STATUS_MEMBER_IN_GROUP`."
);
smb2_status_const!(
    SMB2_STATUS_MEMBER_NOT_IN_GROUP,
    0xC000_0068,
    "SMB2 error status constant `SMB2_STATUS_MEMBER_NOT_IN_GROUP`."
);
smb2_status_const!(
    SMB2_STATUS_LAST_ADMIN,
    0xC000_0069,
    "SMB2 error status constant `SMB2_STATUS_LAST_ADMIN`."
);
smb2_status_const!(
    SMB2_STATUS_WRONG_PASSWORD,
    0xC000_006A,
    "SMB2 error status constant `SMB2_STATUS_WRONG_PASSWORD`."
);
smb2_status_const!(
    SMB2_STATUS_ILL_FORMED_PASSWORD,
    0xC000_006B,
    "SMB2 error status constant `SMB2_STATUS_ILL_FORMED_PASSWORD`."
);
smb2_status_const!(
    SMB2_STATUS_PASSWORD_RESTRICTION,
    0xC000_006C,
    "SMB2 error status constant `SMB2_STATUS_PASSWORD_RESTRICTION`."
);
smb2_status_const!(
    SMB2_STATUS_LOGON_FAILURE,
    0xC000_006D,
    "SMB2 error status constant `SMB2_STATUS_LOGON_FAILURE`."
);
smb2_status_const!(
    SMB2_STATUS_ACCOUNT_RESTRICTION,
    0xC000_006E,
    "SMB2 error status constant `SMB2_STATUS_ACCOUNT_RESTRICTION`."
);
smb2_status_const!(
    SMB2_STATUS_INVALID_LOGON_HOURS,
    0xC000_006F,
    "SMB2 error status constant `SMB2_STATUS_INVALID_LOGON_HOURS`."
);
smb2_status_const!(
    SMB2_STATUS_INVALID_WORKSTATION,
    0xC000_0070,
    "SMB2 error status constant `SMB2_STATUS_INVALID_WORKSTATION`."
);
smb2_status_const!(
    SMB2_STATUS_PASSWORD_EXPIRED,
    0xC000_0071,
    "SMB2 error status constant `SMB2_STATUS_PASSWORD_EXPIRED`."
);
smb2_status_const!(
    SMB2_STATUS_ACCOUNT_DISABLED,
    0xC000_0072,
    "SMB2 error status constant `SMB2_STATUS_ACCOUNT_DISABLED`."
);
smb2_status_const!(
    SMB2_STATUS_NONE_MAPPED,
    0xC000_0073,
    "SMB2 error status constant `SMB2_STATUS_NONE_MAPPED`."
);
smb2_status_const!(
    SMB2_STATUS_TOO_MANY_LUIDS_REQUESTED,
    0xC000_0074,
    "SMB2 error status constant `SMB2_STATUS_TOO_MANY_LUIDS_REQUESTED`."
);
smb2_status_const!(
    SMB2_STATUS_LUIDS_EXHAUSTED,
    0xC000_0075,
    "SMB2 error status constant `SMB2_STATUS_LUIDS_EXHAUSTED`."
);
smb2_status_const!(
    SMB2_STATUS_INVALID_SUB_AUTHORITY,
    0xC000_0076,
    "SMB2 error status constant `SMB2_STATUS_INVALID_SUB_AUTHORITY`."
);
smb2_status_const!(
    SMB2_STATUS_INVALID_ACL,
    0xC000_0077,
    "SMB2 error status constant `SMB2_STATUS_INVALID_ACL`."
);
smb2_status_const!(
    SMB2_STATUS_INVALID_SID,
    0xC000_0078,
    "SMB2 error status constant `SMB2_STATUS_INVALID_SID`."
);
smb2_status_const!(
    SMB2_STATUS_INVALID_SECURITY_DESCR,
    0xC000_0079,
    "SMB2 error status constant `SMB2_STATUS_INVALID_SECURITY_DESCR`."
);
smb2_status_const!(
    SMB2_STATUS_PROCEDURE_NOT_FOUND,
    0xC000_007A,
    "SMB2 error status constant `SMB2_STATUS_PROCEDURE_NOT_FOUND`."
);
smb2_status_const!(
    SMB2_STATUS_INVALID_IMAGE_FORMAT,
    0xC000_007B,
    "SMB2 error status constant `SMB2_STATUS_INVALID_IMAGE_FORMAT`."
);
smb2_status_const!(
    SMB2_STATUS_NO_TOKEN,
    0xC000_007C,
    "SMB2 error status constant `SMB2_STATUS_NO_TOKEN`."
);
smb2_status_const!(
    SMB2_STATUS_BAD_INHERITANCE_ACL,
    0xC000_007D,
    "SMB2 error status constant `SMB2_STATUS_BAD_INHERITANCE_ACL`."
);
smb2_status_const!(
    SMB2_STATUS_RANGE_NOT_LOCKED,
    0xC000_007E,
    "SMB2 error status constant `SMB2_STATUS_RANGE_NOT_LOCKED`."
);
smb2_status_const!(
    SMB2_STATUS_DISK_FULL,
    0xC000_007F,
    "SMB2 error status constant `SMB2_STATUS_DISK_FULL`."
);
smb2_status_const!(
    SMB2_STATUS_SERVER_DISABLED,
    0xC000_0080,
    "SMB2 error status constant `SMB2_STATUS_SERVER_DISABLED`."
);
smb2_status_const!(
    SMB2_STATUS_SERVER_NOT_DISABLED,
    0xC000_0081,
    "SMB2 error status constant `SMB2_STATUS_SERVER_NOT_DISABLED`."
);
smb2_status_const!(
    SMB2_STATUS_TOO_MANY_GUIDS_REQUESTED,
    0xC000_0082,
    "SMB2 error status constant `SMB2_STATUS_TOO_MANY_GUIDS_REQUESTED`."
);
smb2_status_const!(
    SMB2_STATUS_GUIDS_EXHAUSTED,
    0xC000_0083,
    "SMB2 error status constant `SMB2_STATUS_GUIDS_EXHAUSTED`."
);
smb2_status_const!(
    SMB2_STATUS_INVALID_ID_AUTHORITY,
    0xC000_0084,
    "SMB2 error status constant `SMB2_STATUS_INVALID_ID_AUTHORITY`."
);
smb2_status_const!(
    SMB2_STATUS_AGENTS_EXHAUSTED,
    0xC000_0085,
    "SMB2 error status constant `SMB2_STATUS_AGENTS_EXHAUSTED`."
);
smb2_status_const!(
    SMB2_STATUS_INVALID_VOLUME_LABEL,
    0xC000_0086,
    "SMB2 error status constant `SMB2_STATUS_INVALID_VOLUME_LABEL`."
);
smb2_status_const!(
    SMB2_STATUS_SECTION_NOT_EXTENDED,
    0xC000_0087,
    "SMB2 error status constant `SMB2_STATUS_SECTION_NOT_EXTENDED`."
);
smb2_status_const!(
    SMB2_STATUS_NOT_MAPPED_DATA,
    0xC000_0088,
    "SMB2 error status constant `SMB2_STATUS_NOT_MAPPED_DATA`."
);
smb2_status_const!(
    SMB2_STATUS_RESOURCE_DATA_NOT_FOUND,
    0xC000_0089,
    "SMB2 error status constant `SMB2_STATUS_RESOURCE_DATA_NOT_FOUND`."
);
smb2_status_const!(
    SMB2_STATUS_RESOURCE_TYPE_NOT_FOUND,
    0xC000_008A,
    "SMB2 error status constant `SMB2_STATUS_RESOURCE_TYPE_NOT_FOUND`."
);
smb2_status_const!(
    SMB2_STATUS_RESOURCE_NAME_NOT_FOUND,
    0xC000_008B,
    "SMB2 error status constant `SMB2_STATUS_RESOURCE_NAME_NOT_FOUND`."
);
smb2_status_const!(
    SMB2_STATUS_ARRAY_BOUNDS_EXCEEDED,
    0xC000_008C,
    "SMB2 error status constant `SMB2_STATUS_ARRAY_BOUNDS_EXCEEDED`."
);
smb2_status_const!(
    SMB2_STATUS_FLOAT_DENORMAL_OPERAND,
    0xC000_008D,
    "SMB2 error status constant `SMB2_STATUS_FLOAT_DENORMAL_OPERAND`."
);
smb2_status_const!(
    SMB2_STATUS_FLOAT_DIVIDE_BY_ZERO,
    0xC000_008E,
    "SMB2 error status constant `SMB2_STATUS_FLOAT_DIVIDE_BY_ZERO`."
);
smb2_status_const!(
    SMB2_STATUS_FLOAT_INEXACT_RESULT,
    0xC000_008F,
    "SMB2 error status constant `SMB2_STATUS_FLOAT_INEXACT_RESULT`."
);
smb2_status_const!(
    SMB2_STATUS_FLOAT_INVALID_OPERATION,
    0xC000_0090,
    "SMB2 error status constant `SMB2_STATUS_FLOAT_INVALID_OPERATION`."
);
smb2_status_const!(
    SMB2_STATUS_FLOAT_OVERFLOW,
    0xC000_0091,
    "SMB2 error status constant `SMB2_STATUS_FLOAT_OVERFLOW`."
);
smb2_status_const!(
    SMB2_STATUS_FLOAT_STACK_CHECK,
    0xC000_0092,
    "SMB2 error status constant `SMB2_STATUS_FLOAT_STACK_CHECK`."
);
smb2_status_const!(
    SMB2_STATUS_FLOAT_UNDERFLOW,
    0xC000_0093,
    "SMB2 error status constant `SMB2_STATUS_FLOAT_UNDERFLOW`."
);
smb2_status_const!(
    SMB2_STATUS_INTEGER_DIVIDE_BY_ZERO,
    0xC000_0094,
    "SMB2 error status constant `SMB2_STATUS_INTEGER_DIVIDE_BY_ZERO`."
);
smb2_status_const!(
    SMB2_STATUS_INTEGER_OVERFLOW,
    0xC000_0095,
    "SMB2 error status constant `SMB2_STATUS_INTEGER_OVERFLOW`."
);
smb2_status_const!(
    SMB2_STATUS_PRIVILEGED_INSTRUCTION,
    0xC000_0096,
    "SMB2 error status constant `SMB2_STATUS_PRIVILEGED_INSTRUCTION`."
);
smb2_status_const!(
    SMB2_STATUS_TOO_MANY_PAGING_FILES,
    0xC000_0097,
    "SMB2 error status constant `SMB2_STATUS_TOO_MANY_PAGING_FILES`."
);
smb2_status_const!(
    SMB2_STATUS_FILE_INVALID,
    0xC000_0098,
    "SMB2 error status constant `SMB2_STATUS_FILE_INVALID`."
);
smb2_status_const!(
    SMB2_STATUS_ALLOTTED_SPACE_EXCEEDED,
    0xC000_0099,
    "SMB2 error status constant `SMB2_STATUS_ALLOTTED_SPACE_EXCEEDED`."
);
smb2_status_const!(
    SMB2_STATUS_INSUFFICIENT_RESOURCES,
    0xC000_009A,
    "SMB2 error status constant `SMB2_STATUS_INSUFFICIENT_RESOURCES`."
);
smb2_status_const!(
    SMB2_STATUS_DFS_EXIT_PATH_FOUND,
    0xC000_009B,
    "SMB2 error status constant `SMB2_STATUS_DFS_EXIT_PATH_FOUND`."
);
smb2_status_const!(
    SMB2_STATUS_DEVICE_DATA_ERROR,
    0xC000_009C,
    "SMB2 error status constant `SMB2_STATUS_DEVICE_DATA_ERROR`."
);
smb2_status_const!(
    SMB2_STATUS_DEVICE_NOT_CONNECTED,
    0xC000_009D,
    "SMB2 error status constant `SMB2_STATUS_DEVICE_NOT_CONNECTED`."
);
smb2_status_const!(
    SMB2_STATUS_DEVICE_POWER_FAILURE,
    0xC000_009E,
    "SMB2 error status constant `SMB2_STATUS_DEVICE_POWER_FAILURE`."
);
smb2_status_const!(
    SMB2_STATUS_FREE_VM_NOT_AT_BASE,
    0xC000_009F,
    "SMB2 error status constant `SMB2_STATUS_FREE_VM_NOT_AT_BASE`."
);
smb2_status_const!(
    SMB2_STATUS_MEMORY_NOT_ALLOCATED,
    0xC000_00A0,
    "SMB2 error status constant `SMB2_STATUS_MEMORY_NOT_ALLOCATED`."
);
smb2_status_const!(
    SMB2_STATUS_WORKING_SET_QUOTA,
    0xC000_00A1,
    "SMB2 error status constant `SMB2_STATUS_WORKING_SET_QUOTA`."
);
smb2_status_const!(
    SMB2_STATUS_MEDIA_WRITE_PROTECTED,
    0xC000_00A2,
    "SMB2 error status constant `SMB2_STATUS_MEDIA_WRITE_PROTECTED`."
);
smb2_status_const!(
    SMB2_STATUS_DEVICE_NOT_READY,
    0xC000_00A3,
    "SMB2 error status constant `SMB2_STATUS_DEVICE_NOT_READY`."
);
smb2_status_const!(
    SMB2_STATUS_INVALID_GROUP_ATTRIBUTES,
    0xC000_00A4,
    "SMB2 error status constant `SMB2_STATUS_INVALID_GROUP_ATTRIBUTES`."
);
smb2_status_const!(
    SMB2_STATUS_BAD_IMPERSONATION_LEVEL,
    0xC000_00A5,
    "SMB2 error status constant `SMB2_STATUS_BAD_IMPERSONATION_LEVEL`."
);
smb2_status_const!(
    SMB2_STATUS_CANT_OPEN_ANONYMOUS,
    0xC000_00A6,
    "SMB2 error status constant `SMB2_STATUS_CANT_OPEN_ANONYMOUS`."
);
smb2_status_const!(
    SMB2_STATUS_BAD_VALIDATION_CLASS,
    0xC000_00A7,
    "SMB2 error status constant `SMB2_STATUS_BAD_VALIDATION_CLASS`."
);
smb2_status_const!(
    SMB2_STATUS_BAD_TOKEN_TYPE,
    0xC000_00A8,
    "SMB2 error status constant `SMB2_STATUS_BAD_TOKEN_TYPE`."
);
smb2_status_const!(
    SMB2_STATUS_BAD_MASTER_BOOT_RECORD,
    0xC000_00A9,
    "SMB2 error status constant `SMB2_STATUS_BAD_MASTER_BOOT_RECORD`."
);
smb2_status_const!(
    SMB2_STATUS_INSTRUCTION_MISALIGNMENT,
    0xC000_00AA,
    "SMB2 error status constant `SMB2_STATUS_INSTRUCTION_MISALIGNMENT`."
);
smb2_status_const!(
    SMB2_STATUS_INSTANCE_NOT_AVAILABLE,
    0xC000_00AB,
    "SMB2 error status constant `SMB2_STATUS_INSTANCE_NOT_AVAILABLE`."
);
smb2_status_const!(
    SMB2_STATUS_PIPE_NOT_AVAILABLE,
    0xC000_00AC,
    "SMB2 error status constant `SMB2_STATUS_PIPE_NOT_AVAILABLE`."
);
smb2_status_const!(
    SMB2_STATUS_INVALID_PIPE_STATE,
    0xC000_00AD,
    "SMB2 error status constant `SMB2_STATUS_INVALID_PIPE_STATE`."
);
smb2_status_const!(
    SMB2_STATUS_PIPE_BUSY,
    0xC000_00AE,
    "SMB2 error status constant `SMB2_STATUS_PIPE_BUSY`."
);
smb2_status_const!(
    SMB2_STATUS_ILLEGAL_FUNCTION,
    0xC000_00AF,
    "SMB2 error status constant `SMB2_STATUS_ILLEGAL_FUNCTION`."
);
smb2_status_const!(
    SMB2_STATUS_PIPE_DISCONNECTED,
    0xC000_00B0,
    "SMB2 error status constant `SMB2_STATUS_PIPE_DISCONNECTED`."
);
smb2_status_const!(
    SMB2_STATUS_PIPE_CLOSING,
    0xC000_00B1,
    "SMB2 error status constant `SMB2_STATUS_PIPE_CLOSING`."
);
smb2_status_const!(
    SMB2_STATUS_PIPE_CONNECTED,
    0xC000_00B2,
    "SMB2 error status constant `SMB2_STATUS_PIPE_CONNECTED`."
);
smb2_status_const!(
    SMB2_STATUS_PIPE_LISTENING,
    0xC000_00B3,
    "SMB2 error status constant `SMB2_STATUS_PIPE_LISTENING`."
);
smb2_status_const!(
    SMB2_STATUS_INVALID_READ_MODE,
    0xC000_00B4,
    "SMB2 error status constant `SMB2_STATUS_INVALID_READ_MODE`."
);
smb2_status_const!(
    SMB2_STATUS_IO_TIMEOUT,
    0xC000_00B5,
    "SMB2 error status constant `SMB2_STATUS_IO_TIMEOUT`."
);
smb2_status_const!(
    SMB2_STATUS_FILE_FORCED_CLOSED,
    0xC000_00B6,
    "SMB2 error status constant `SMB2_STATUS_FILE_FORCED_CLOSED`."
);
smb2_status_const!(
    SMB2_STATUS_PROFILING_NOT_STARTED,
    0xC000_00B7,
    "SMB2 error status constant `SMB2_STATUS_PROFILING_NOT_STARTED`."
);
smb2_status_const!(
    SMB2_STATUS_PROFILING_NOT_STOPPED,
    0xC000_00B8,
    "SMB2 error status constant `SMB2_STATUS_PROFILING_NOT_STOPPED`."
);
smb2_status_const!(
    SMB2_STATUS_COULD_NOT_INTERPRET,
    0xC000_00B9,
    "SMB2 error status constant `SMB2_STATUS_COULD_NOT_INTERPRET`."
);
smb2_status_const!(
    SMB2_STATUS_FILE_IS_A_DIRECTORY,
    0xC000_00BA,
    "SMB2 error status constant `SMB2_STATUS_FILE_IS_A_DIRECTORY`."
);
smb2_status_const!(
    SMB2_STATUS_NOT_SUPPORTED,
    0xC000_00BB,
    "SMB2 error status constant `SMB2_STATUS_NOT_SUPPORTED`."
);
smb2_status_const!(
    SMB2_STATUS_REMOTE_NOT_LISTENING,
    0xC000_00BC,
    "SMB2 error status constant `SMB2_STATUS_REMOTE_NOT_LISTENING`."
);
smb2_status_const!(
    SMB2_STATUS_DUPLICATE_NAME,
    0xC000_00BD,
    "SMB2 error status constant `SMB2_STATUS_DUPLICATE_NAME`."
);
smb2_status_const!(
    SMB2_STATUS_BAD_NETWORK_PATH,
    0xC000_00BE,
    "SMB2 error status constant `SMB2_STATUS_BAD_NETWORK_PATH`."
);
smb2_status_const!(
    SMB2_STATUS_NETWORK_BUSY,
    0xC000_00BF,
    "SMB2 error status constant `SMB2_STATUS_NETWORK_BUSY`."
);
smb2_status_const!(
    SMB2_STATUS_DEVICE_DOES_NOT_EXIST,
    0xC000_00C0,
    "SMB2 error status constant `SMB2_STATUS_DEVICE_DOES_NOT_EXIST`."
);
smb2_status_const!(
    SMB2_STATUS_TOO_MANY_COMMANDS,
    0xC000_00C1,
    "SMB2 error status constant `SMB2_STATUS_TOO_MANY_COMMANDS`."
);
smb2_status_const!(
    SMB2_STATUS_ADAPTER_HARDWARE_ERROR,
    0xC000_00C2,
    "SMB2 error status constant `SMB2_STATUS_ADAPTER_HARDWARE_ERROR`."
);
smb2_status_const!(
    SMB2_STATUS_INVALID_NETWORK_RESPONSE,
    0xC000_00C3,
    "SMB2 error status constant `SMB2_STATUS_INVALID_NETWORK_RESPONSE`."
);
smb2_status_const!(
    SMB2_STATUS_UNEXPECTED_NETWORK_ERROR,
    0xC000_00C4,
    "SMB2 error status constant `SMB2_STATUS_UNEXPECTED_NETWORK_ERROR`."
);
smb2_status_const!(
    SMB2_STATUS_BAD_REMOTE_ADAPTER,
    0xC000_00C5,
    "SMB2 error status constant `SMB2_STATUS_BAD_REMOTE_ADAPTER`."
);
smb2_status_const!(
    SMB2_STATUS_PRINT_QUEUE_FULL,
    0xC000_00C6,
    "SMB2 error status constant `SMB2_STATUS_PRINT_QUEUE_FULL`."
);
smb2_status_const!(
    SMB2_STATUS_NO_SPOOL_SPACE,
    0xC000_00C7,
    "SMB2 error status constant `SMB2_STATUS_NO_SPOOL_SPACE`."
);
smb2_status_const!(
    SMB2_STATUS_PRINT_CANCELLED,
    0xC000_00C8,
    "SMB2 error status constant `SMB2_STATUS_PRINT_CANCELLED`."
);
smb2_status_const!(
    SMB2_STATUS_NETWORK_NAME_DELETED,
    0xC000_00C9,
    "SMB2 error status constant `SMB2_STATUS_NETWORK_NAME_DELETED`."
);
smb2_status_const!(
    SMB2_STATUS_NETWORK_ACCESS_DENIED,
    0xC000_00CA,
    "SMB2 error status constant `SMB2_STATUS_NETWORK_ACCESS_DENIED`."
);
smb2_status_const!(
    SMB2_STATUS_BAD_DEVICE_TYPE,
    0xC000_00CB,
    "SMB2 error status constant `SMB2_STATUS_BAD_DEVICE_TYPE`."
);
smb2_status_const!(
    SMB2_STATUS_BAD_NETWORK_NAME,
    0xC000_00CC,
    "SMB2 error status constant `SMB2_STATUS_BAD_NETWORK_NAME`."
);
smb2_status_const!(
    SMB2_STATUS_TOO_MANY_NAMES,
    0xC000_00CD,
    "SMB2 error status constant `SMB2_STATUS_TOO_MANY_NAMES`."
);
smb2_status_const!(
    SMB2_STATUS_TOO_MANY_SESSIONS,
    0xC000_00CE,
    "SMB2 error status constant `SMB2_STATUS_TOO_MANY_SESSIONS`."
);
smb2_status_const!(
    SMB2_STATUS_SHARING_PAUSED,
    0xC000_00CF,
    "SMB2 error status constant `SMB2_STATUS_SHARING_PAUSED`."
);
smb2_status_const!(
    SMB2_STATUS_REQUEST_NOT_ACCEPTED,
    0xC000_00D0,
    "SMB2 error status constant `SMB2_STATUS_REQUEST_NOT_ACCEPTED`."
);
smb2_status_const!(
    SMB2_STATUS_REDIRECTOR_PAUSED,
    0xC000_00D1,
    "SMB2 error status constant `SMB2_STATUS_REDIRECTOR_PAUSED`."
);
smb2_status_const!(
    SMB2_STATUS_NET_WRITE_FAULT,
    0xC000_00D2,
    "SMB2 error status constant `SMB2_STATUS_NET_WRITE_FAULT`."
);
smb2_status_const!(
    SMB2_STATUS_PROFILING_AT_LIMIT,
    0xC000_00D3,
    "SMB2 error status constant `SMB2_STATUS_PROFILING_AT_LIMIT`."
);
smb2_status_const!(
    SMB2_STATUS_NOT_SAME_DEVICE,
    0xC000_00D4,
    "SMB2 error status constant `SMB2_STATUS_NOT_SAME_DEVICE`."
);
smb2_status_const!(
    SMB2_STATUS_FILE_RENAMED,
    0xC000_00D5,
    "SMB2 error status constant `SMB2_STATUS_FILE_RENAMED`."
);
smb2_status_const!(
    SMB2_STATUS_VIRTUAL_CIRCUIT_CLOSED,
    0xC000_00D6,
    "SMB2 error status constant `SMB2_STATUS_VIRTUAL_CIRCUIT_CLOSED`."
);
smb2_status_const!(
    SMB2_STATUS_NO_SECURITY_ON_OBJECT,
    0xC000_00D7,
    "SMB2 error status constant `SMB2_STATUS_NO_SECURITY_ON_OBJECT`."
);
smb2_status_const!(
    SMB2_STATUS_CANT_WAIT,
    0xC000_00D8,
    "SMB2 error status constant `SMB2_STATUS_CANT_WAIT`."
);
smb2_status_const!(
    SMB2_STATUS_PIPE_EMPTY,
    0xC000_00D9,
    "SMB2 error status constant `SMB2_STATUS_PIPE_EMPTY`."
);
smb2_status_const!(
    SMB2_STATUS_CANT_ACCESS_DOMAIN_INFO,
    0xC000_00DA,
    "SMB2 error status constant `SMB2_STATUS_CANT_ACCESS_DOMAIN_INFO`."
);
smb2_status_const!(
    SMB2_STATUS_CANT_TERMINATE_SELF,
    0xC000_00DB,
    "SMB2 error status constant `SMB2_STATUS_CANT_TERMINATE_SELF`."
);
smb2_status_const!(
    SMB2_STATUS_INVALID_SERVER_STATE,
    0xC000_00DC,
    "SMB2 error status constant `SMB2_STATUS_INVALID_SERVER_STATE`."
);
smb2_status_const!(
    SMB2_STATUS_INVALID_DOMAIN_STATE,
    0xC000_00DD,
    "SMB2 error status constant `SMB2_STATUS_INVALID_DOMAIN_STATE`."
);
smb2_status_const!(
    SMB2_STATUS_INVALID_DOMAIN_ROLE,
    0xC000_00DE,
    "SMB2 error status constant `SMB2_STATUS_INVALID_DOMAIN_ROLE`."
);
smb2_status_const!(
    SMB2_STATUS_NO_SUCH_DOMAIN,
    0xC000_00DF,
    "SMB2 error status constant `SMB2_STATUS_NO_SUCH_DOMAIN`."
);
smb2_status_const!(
    SMB2_STATUS_DOMAIN_EXISTS,
    0xC000_00E0,
    "SMB2 error status constant `SMB2_STATUS_DOMAIN_EXISTS`."
);
smb2_status_const!(
    SMB2_STATUS_DOMAIN_LIMIT_EXCEEDED,
    0xC000_00E1,
    "SMB2 error status constant `SMB2_STATUS_DOMAIN_LIMIT_EXCEEDED`."
);
smb2_status_const!(
    SMB2_STATUS_OPLOCK_NOT_GRANTED,
    0xC000_00E2,
    "SMB2 error status constant `SMB2_STATUS_OPLOCK_NOT_GRANTED`."
);
smb2_status_const!(
    SMB2_STATUS_INVALID_OPLOCK_PROTOCOL,
    0xC000_00E3,
    "SMB2 error status constant `SMB2_STATUS_INVALID_OPLOCK_PROTOCOL`."
);
smb2_status_const!(
    SMB2_STATUS_INTERNAL_DB_CORRUPTION,
    0xC000_00E4,
    "SMB2 error status constant `SMB2_STATUS_INTERNAL_DB_CORRUPTION`."
);
smb2_status_const!(
    SMB2_STATUS_INTERNAL_ERROR,
    0xC000_00E5,
    "SMB2 error status constant `SMB2_STATUS_INTERNAL_ERROR`."
);
smb2_status_const!(
    SMB2_STATUS_GENERIC_NOT_MAPPED,
    0xC000_00E6,
    "SMB2 error status constant `SMB2_STATUS_GENERIC_NOT_MAPPED`."
);
smb2_status_const!(
    SMB2_STATUS_BAD_DESCRIPTOR_FORMAT,
    0xC000_00E7,
    "SMB2 error status constant `SMB2_STATUS_BAD_DESCRIPTOR_FORMAT`."
);
smb2_status_const!(
    SMB2_STATUS_INVALID_USER_BUFFER,
    0xC000_00E8,
    "SMB2 error status constant `SMB2_STATUS_INVALID_USER_BUFFER`."
);
smb2_status_const!(
    SMB2_STATUS_UNEXPECTED_IO_ERROR,
    0xC000_00E9,
    "SMB2 error status constant `SMB2_STATUS_UNEXPECTED_IO_ERROR`."
);
smb2_status_const!(
    SMB2_STATUS_UNEXPECTED_MM_CREATE_ERR,
    0xC000_00EA,
    "SMB2 error status constant `SMB2_STATUS_UNEXPECTED_MM_CREATE_ERR`."
);
smb2_status_const!(
    SMB2_STATUS_UNEXPECTED_MM_MAP_ERROR,
    0xC000_00EB,
    "SMB2 error status constant `SMB2_STATUS_UNEXPECTED_MM_MAP_ERROR`."
);
smb2_status_const!(
    SMB2_STATUS_UNEXPECTED_MM_EXTEND_ERR,
    0xC000_00EC,
    "SMB2 error status constant `SMB2_STATUS_UNEXPECTED_MM_EXTEND_ERR`."
);
smb2_status_const!(
    SMB2_STATUS_NOT_LOGON_PROCESS,
    0xC000_00ED,
    "SMB2 error status constant `SMB2_STATUS_NOT_LOGON_PROCESS`."
);
smb2_status_const!(
    SMB2_STATUS_LOGON_SESSION_EXISTS,
    0xC000_00EE,
    "SMB2 error status constant `SMB2_STATUS_LOGON_SESSION_EXISTS`."
);
smb2_status_const!(
    SMB2_STATUS_INVALID_PARAMETER_1,
    0xC000_00EF,
    "SMB2 error status constant `SMB2_STATUS_INVALID_PARAMETER_1`."
);
smb2_status_const!(
    SMB2_STATUS_INVALID_PARAMETER_2,
    0xC000_00F0,
    "SMB2 error status constant `SMB2_STATUS_INVALID_PARAMETER_2`."
);
smb2_status_const!(
    SMB2_STATUS_INVALID_PARAMETER_3,
    0xC000_00F1,
    "SMB2 error status constant `SMB2_STATUS_INVALID_PARAMETER_3`."
);
smb2_status_const!(
    SMB2_STATUS_INVALID_PARAMETER_4,
    0xC000_00F2,
    "SMB2 error status constant `SMB2_STATUS_INVALID_PARAMETER_4`."
);
smb2_status_const!(
    SMB2_STATUS_INVALID_PARAMETER_5,
    0xC000_00F3,
    "SMB2 error status constant `SMB2_STATUS_INVALID_PARAMETER_5`."
);
smb2_status_const!(
    SMB2_STATUS_INVALID_PARAMETER_6,
    0xC000_00F4,
    "SMB2 error status constant `SMB2_STATUS_INVALID_PARAMETER_6`."
);
smb2_status_const!(
    SMB2_STATUS_INVALID_PARAMETER_7,
    0xC000_00F5,
    "SMB2 error status constant `SMB2_STATUS_INVALID_PARAMETER_7`."
);
smb2_status_const!(
    SMB2_STATUS_INVALID_PARAMETER_8,
    0xC000_00F6,
    "SMB2 error status constant `SMB2_STATUS_INVALID_PARAMETER_8`."
);
smb2_status_const!(
    SMB2_STATUS_INVALID_PARAMETER_9,
    0xC000_00F7,
    "SMB2 error status constant `SMB2_STATUS_INVALID_PARAMETER_9`."
);
smb2_status_const!(
    SMB2_STATUS_INVALID_PARAMETER_10,
    0xC000_00F8,
    "SMB2 error status constant `SMB2_STATUS_INVALID_PARAMETER_10`."
);
smb2_status_const!(
    SMB2_STATUS_INVALID_PARAMETER_11,
    0xC000_00F9,
    "SMB2 error status constant `SMB2_STATUS_INVALID_PARAMETER_11`."
);
smb2_status_const!(
    SMB2_STATUS_INVALID_PARAMETER_12,
    0xC000_00FA,
    "SMB2 error status constant `SMB2_STATUS_INVALID_PARAMETER_12`."
);
smb2_status_const!(
    SMB2_STATUS_REDIRECTOR_NOT_STARTED,
    0xC000_00FB,
    "SMB2 error status constant `SMB2_STATUS_REDIRECTOR_NOT_STARTED`."
);
smb2_status_const!(
    SMB2_STATUS_REDIRECTOR_STARTED,
    0xC000_00FC,
    "SMB2 error status constant `SMB2_STATUS_REDIRECTOR_STARTED`."
);
smb2_status_const!(
    SMB2_STATUS_STACK_OVERFLOW,
    0xC000_00FD,
    "SMB2 error status constant `SMB2_STATUS_STACK_OVERFLOW`."
);
smb2_status_const!(
    SMB2_STATUS_NO_SUCH_PACKAGE,
    0xC000_00FE,
    "SMB2 error status constant `SMB2_STATUS_NO_SUCH_PACKAGE`."
);
smb2_status_const!(
    SMB2_STATUS_BAD_FUNCTION_TABLE,
    0xC000_00FF,
    "SMB2 error status constant `SMB2_STATUS_BAD_FUNCTION_TABLE`."
);
smb2_status_const!(
    SMB2_STATUS_DIRECTORY_NOT_EMPTY,
    0xC000_0101,
    "SMB2 error status constant `SMB2_STATUS_DIRECTORY_NOT_EMPTY`."
);
smb2_status_const!(
    SMB2_STATUS_FILE_CORRUPT_ERROR,
    0xC000_0102,
    "SMB2 error status constant `SMB2_STATUS_FILE_CORRUPT_ERROR`."
);
smb2_status_const!(
    SMB2_STATUS_NOT_A_DIRECTORY,
    0xC000_0103,
    "SMB2 error status constant `SMB2_STATUS_NOT_A_DIRECTORY`."
);
smb2_status_const!(
    SMB2_STATUS_BAD_LOGON_SESSION_STATE,
    0xC000_0104,
    "SMB2 error status constant `SMB2_STATUS_BAD_LOGON_SESSION_STATE`."
);
smb2_status_const!(
    SMB2_STATUS_LOGON_SESSION_COLLISION,
    0xC000_0105,
    "SMB2 error status constant `SMB2_STATUS_LOGON_SESSION_COLLISION`."
);
smb2_status_const!(
    SMB2_STATUS_NAME_TOO_LONG,
    0xC000_0106,
    "SMB2 error status constant `SMB2_STATUS_NAME_TOO_LONG`."
);
smb2_status_const!(
    SMB2_STATUS_FILES_OPEN,
    0xC000_0107,
    "SMB2 error status constant `SMB2_STATUS_FILES_OPEN`."
);
smb2_status_const!(
    SMB2_STATUS_CONNECTION_IN_USE,
    0xC000_0108,
    "SMB2 error status constant `SMB2_STATUS_CONNECTION_IN_USE`."
);
smb2_status_const!(
    SMB2_STATUS_MESSAGE_NOT_FOUND,
    0xC000_0109,
    "SMB2 error status constant `SMB2_STATUS_MESSAGE_NOT_FOUND`."
);
smb2_status_const!(
    SMB2_STATUS_PROCESS_IS_TERMINATING,
    0xC000_010A,
    "SMB2 error status constant `SMB2_STATUS_PROCESS_IS_TERMINATING`."
);
smb2_status_const!(
    SMB2_STATUS_INVALID_LOGON_TYPE,
    0xC000_010B,
    "SMB2 error status constant `SMB2_STATUS_INVALID_LOGON_TYPE`."
);
smb2_status_const!(
    SMB2_STATUS_NO_GUID_TRANSLATION,
    0xC000_010C,
    "SMB2 error status constant `SMB2_STATUS_NO_GUID_TRANSLATION`."
);
smb2_status_const!(
    SMB2_STATUS_CANNOT_IMPERSONATE,
    0xC000_010D,
    "SMB2 error status constant `SMB2_STATUS_CANNOT_IMPERSONATE`."
);
smb2_status_const!(
    SMB2_STATUS_IMAGE_ALREADY_LOADED,
    0xC000_010E,
    "SMB2 error status constant `SMB2_STATUS_IMAGE_ALREADY_LOADED`."
);
smb2_status_const!(
    SMB2_STATUS_ABIOS_NOT_PRESENT,
    0xC000_010F,
    "SMB2 error status constant `SMB2_STATUS_ABIOS_NOT_PRESENT`."
);
smb2_status_const!(
    SMB2_STATUS_ABIOS_LID_NOT_EXIST,
    0xC000_0110,
    "SMB2 error status constant `SMB2_STATUS_ABIOS_LID_NOT_EXIST`."
);
smb2_status_const!(
    SMB2_STATUS_ABIOS_LID_ALREADY_OWNED,
    0xC000_0111,
    "SMB2 error status constant `SMB2_STATUS_ABIOS_LID_ALREADY_OWNED`."
);
smb2_status_const!(
    SMB2_STATUS_ABIOS_NOT_LID_OWNER,
    0xC000_0112,
    "SMB2 error status constant `SMB2_STATUS_ABIOS_NOT_LID_OWNER`."
);
smb2_status_const!(
    SMB2_STATUS_ABIOS_INVALID_COMMAND,
    0xC000_0113,
    "SMB2 error status constant `SMB2_STATUS_ABIOS_INVALID_COMMAND`."
);
smb2_status_const!(
    SMB2_STATUS_ABIOS_INVALID_LID,
    0xC000_0114,
    "SMB2 error status constant `SMB2_STATUS_ABIOS_INVALID_LID`."
);
smb2_status_const!(
    SMB2_STATUS_ABIOS_SELECTOR_NOT_AVAILABLE,
    0xC000_0115,
    "SMB2 error status constant `SMB2_STATUS_ABIOS_SELECTOR_NOT_AVAILABLE`."
);
smb2_status_const!(
    SMB2_STATUS_ABIOS_INVALID_SELECTOR,
    0xC000_0116,
    "SMB2 error status constant `SMB2_STATUS_ABIOS_INVALID_SELECTOR`."
);
smb2_status_const!(
    SMB2_STATUS_NO_LDT,
    0xC000_0117,
    "SMB2 error status constant `SMB2_STATUS_NO_LDT`."
);
smb2_status_const!(
    SMB2_STATUS_INVALID_LDT_SIZE,
    0xC000_0118,
    "SMB2 error status constant `SMB2_STATUS_INVALID_LDT_SIZE`."
);
smb2_status_const!(
    SMB2_STATUS_INVALID_LDT_OFFSET,
    0xC000_0119,
    "SMB2 error status constant `SMB2_STATUS_INVALID_LDT_OFFSET`."
);
smb2_status_const!(
    SMB2_STATUS_INVALID_LDT_DESCRIPTOR,
    0xC000_011A,
    "SMB2 error status constant `SMB2_STATUS_INVALID_LDT_DESCRIPTOR`."
);
smb2_status_const!(
    SMB2_STATUS_INVALID_IMAGE_NE_FORMAT,
    0xC000_011B,
    "SMB2 error status constant `SMB2_STATUS_INVALID_IMAGE_NE_FORMAT`."
);
smb2_status_const!(
    SMB2_STATUS_RXACT_INVALID_STATE,
    0xC000_011C,
    "SMB2 error status constant `SMB2_STATUS_RXACT_INVALID_STATE`."
);
smb2_status_const!(
    SMB2_STATUS_RXACT_COMMIT_FAILURE,
    0xC000_011D,
    "SMB2 error status constant `SMB2_STATUS_RXACT_COMMIT_FAILURE`."
);
smb2_status_const!(
    SMB2_STATUS_MAPPED_FILE_SIZE_ZERO,
    0xC000_011E,
    "SMB2 error status constant `SMB2_STATUS_MAPPED_FILE_SIZE_ZERO`."
);
smb2_status_const!(
    SMB2_STATUS_TOO_MANY_OPENED_FILES,
    0xC000_011F,
    "SMB2 error status constant `SMB2_STATUS_TOO_MANY_OPENED_FILES`."
);
smb2_status_const!(
    SMB2_STATUS_CANCELLED,
    0xC000_0120,
    "SMB2 error status constant `SMB2_STATUS_CANCELLED`."
);
smb2_status_const!(
    SMB2_STATUS_CANNOT_DELETE,
    0xC000_0121,
    "SMB2 error status constant `SMB2_STATUS_CANNOT_DELETE`."
);
smb2_status_const!(
    SMB2_STATUS_INVALID_COMPUTER_NAME,
    0xC000_0122,
    "SMB2 error status constant `SMB2_STATUS_INVALID_COMPUTER_NAME`."
);
smb2_status_const!(
    SMB2_STATUS_FILE_DELETED,
    0xC000_0123,
    "SMB2 error status constant `SMB2_STATUS_FILE_DELETED`."
);
smb2_status_const!(
    SMB2_STATUS_SPECIAL_ACCOUNT,
    0xC000_0124,
    "SMB2 error status constant `SMB2_STATUS_SPECIAL_ACCOUNT`."
);
smb2_status_const!(
    SMB2_STATUS_SPECIAL_GROUP,
    0xC000_0125,
    "SMB2 error status constant `SMB2_STATUS_SPECIAL_GROUP`."
);
smb2_status_const!(
    SMB2_STATUS_SPECIAL_USER,
    0xC000_0126,
    "SMB2 error status constant `SMB2_STATUS_SPECIAL_USER`."
);
smb2_status_const!(
    SMB2_STATUS_MEMBERS_PRIMARY_GROUP,
    0xC000_0127,
    "SMB2 error status constant `SMB2_STATUS_MEMBERS_PRIMARY_GROUP`."
);
smb2_status_const!(
    SMB2_STATUS_FILE_CLOSED,
    0xC000_0128,
    "SMB2 error status constant `SMB2_STATUS_FILE_CLOSED`."
);
smb2_status_const!(
    SMB2_STATUS_TOO_MANY_THREADS,
    0xC000_0129,
    "SMB2 error status constant `SMB2_STATUS_TOO_MANY_THREADS`."
);
smb2_status_const!(
    SMB2_STATUS_THREAD_NOT_IN_PROCESS,
    0xC000_012A,
    "SMB2 error status constant `SMB2_STATUS_THREAD_NOT_IN_PROCESS`."
);
smb2_status_const!(
    SMB2_STATUS_TOKEN_ALREADY_IN_USE,
    0xC000_012B,
    "SMB2 error status constant `SMB2_STATUS_TOKEN_ALREADY_IN_USE`."
);
smb2_status_const!(
    SMB2_STATUS_PAGEFILE_QUOTA_EXCEEDED,
    0xC000_012C,
    "SMB2 error status constant `SMB2_STATUS_PAGEFILE_QUOTA_EXCEEDED`."
);
smb2_status_const!(
    SMB2_STATUS_COMMITMENT_LIMIT,
    0xC000_012D,
    "SMB2 error status constant `SMB2_STATUS_COMMITMENT_LIMIT`."
);
smb2_status_const!(
    SMB2_STATUS_INVALID_IMAGE_LE_FORMAT,
    0xC000_012E,
    "SMB2 error status constant `SMB2_STATUS_INVALID_IMAGE_LE_FORMAT`."
);
smb2_status_const!(
    SMB2_STATUS_INVALID_IMAGE_NOT_MZ,
    0xC000_012F,
    "SMB2 error status constant `SMB2_STATUS_INVALID_IMAGE_NOT_MZ`."
);
smb2_status_const!(
    SMB2_STATUS_INVALID_IMAGE_PROTECT,
    0xC000_0130,
    "SMB2 error status constant `SMB2_STATUS_INVALID_IMAGE_PROTECT`."
);
smb2_status_const!(
    SMB2_STATUS_INVALID_IMAGE_WIN_16,
    0xC000_0131,
    "SMB2 error status constant `SMB2_STATUS_INVALID_IMAGE_WIN_16`."
);
smb2_status_const!(
    SMB2_STATUS_LOGON_SERVER_CONFLICT,
    0xC000_0132,
    "SMB2 error status constant `SMB2_STATUS_LOGON_SERVER_CONFLICT`."
);
smb2_status_const!(
    SMB2_STATUS_TIME_DIFFERENCE_AT_DC,
    0xC000_0133,
    "SMB2 error status constant `SMB2_STATUS_TIME_DIFFERENCE_AT_DC`."
);
smb2_status_const!(
    SMB2_STATUS_SYNCHRONIZATION_REQUIRED,
    0xC000_0134,
    "SMB2 error status constant `SMB2_STATUS_SYNCHRONIZATION_REQUIRED`."
);
smb2_status_const!(
    SMB2_STATUS_DLL_NOT_FOUND,
    0xC000_0135,
    "SMB2 error status constant `SMB2_STATUS_DLL_NOT_FOUND`."
);
smb2_status_const!(
    SMB2_STATUS_OPEN_FAILED,
    0xC000_0136,
    "SMB2 error status constant `SMB2_STATUS_OPEN_FAILED`."
);
smb2_status_const!(
    SMB2_STATUS_IO_PRIVILEGE_FAILED,
    0xC000_0137,
    "SMB2 error status constant `SMB2_STATUS_IO_PRIVILEGE_FAILED`."
);
smb2_status_const!(
    SMB2_STATUS_ORDINAL_NOT_FOUND,
    0xC000_0138,
    "SMB2 error status constant `SMB2_STATUS_ORDINAL_NOT_FOUND`."
);
smb2_status_const!(
    SMB2_STATUS_ENTRYPOINT_NOT_FOUND,
    0xC000_0139,
    "SMB2 error status constant `SMB2_STATUS_ENTRYPOINT_NOT_FOUND`."
);
smb2_status_const!(
    SMB2_STATUS_CONTROL_C_EXIT,
    0xC000_013A,
    "SMB2 error status constant `SMB2_STATUS_CONTROL_C_EXIT`."
);
smb2_status_const!(
    SMB2_STATUS_LOCAL_DISCONNECT,
    0xC000_013B,
    "SMB2 error status constant `SMB2_STATUS_LOCAL_DISCONNECT`."
);
smb2_status_const!(
    SMB2_STATUS_REMOTE_DISCONNECT,
    0xC000_013C,
    "SMB2 error status constant `SMB2_STATUS_REMOTE_DISCONNECT`."
);
smb2_status_const!(
    SMB2_STATUS_REMOTE_RESOURCES,
    0xC000_013D,
    "SMB2 error status constant `SMB2_STATUS_REMOTE_RESOURCES`."
);
smb2_status_const!(
    SMB2_STATUS_LINK_FAILED,
    0xC000_013E,
    "SMB2 error status constant `SMB2_STATUS_LINK_FAILED`."
);
smb2_status_const!(
    SMB2_STATUS_LINK_TIMEOUT,
    0xC000_013F,
    "SMB2 error status constant `SMB2_STATUS_LINK_TIMEOUT`."
);
smb2_status_const!(
    SMB2_STATUS_INVALID_CONNECTION,
    0xC000_0140,
    "SMB2 error status constant `SMB2_STATUS_INVALID_CONNECTION`."
);
smb2_status_const!(
    SMB2_STATUS_INVALID_ADDRESS,
    0xC000_0141,
    "SMB2 error status constant `SMB2_STATUS_INVALID_ADDRESS`."
);
smb2_status_const!(
    SMB2_STATUS_DLL_INIT_FAILED,
    0xC000_0142,
    "SMB2 error status constant `SMB2_STATUS_DLL_INIT_FAILED`."
);
smb2_status_const!(
    SMB2_STATUS_MISSING_SYSTEMFILE,
    0xC000_0143,
    "SMB2 error status constant `SMB2_STATUS_MISSING_SYSTEMFILE`."
);
smb2_status_const!(
    SMB2_STATUS_UNHANDLED_EXCEPTION,
    0xC000_0144,
    "SMB2 error status constant `SMB2_STATUS_UNHANDLED_EXCEPTION`."
);
smb2_status_const!(
    SMB2_STATUS_APP_INIT_FAILURE,
    0xC000_0145,
    "SMB2 error status constant `SMB2_STATUS_APP_INIT_FAILURE`."
);
smb2_status_const!(
    SMB2_STATUS_PAGEFILE_CREATE_FAILED,
    0xC000_0146,
    "SMB2 error status constant `SMB2_STATUS_PAGEFILE_CREATE_FAILED`."
);
smb2_status_const!(
    SMB2_STATUS_NO_PAGEFILE,
    0xC000_0147,
    "SMB2 error status constant `SMB2_STATUS_NO_PAGEFILE`."
);
smb2_status_const!(
    SMB2_STATUS_INVALID_LEVEL,
    0xC000_0148,
    "SMB2 error status constant `SMB2_STATUS_INVALID_LEVEL`."
);
smb2_status_const!(
    SMB2_STATUS_WRONG_PASSWORD_CORE,
    0xC000_0149,
    "SMB2 error status constant `SMB2_STATUS_WRONG_PASSWORD_CORE`."
);
smb2_status_const!(
    SMB2_STATUS_ILLEGAL_FLOAT_CONTEXT,
    0xC000_014A,
    "SMB2 error status constant `SMB2_STATUS_ILLEGAL_FLOAT_CONTEXT`."
);
smb2_status_const!(
    SMB2_STATUS_PIPE_BROKEN,
    0xC000_014B,
    "SMB2 error status constant `SMB2_STATUS_PIPE_BROKEN`."
);
smb2_status_const!(
    SMB2_STATUS_REGISTRY_CORRUPT,
    0xC000_014C,
    "SMB2 error status constant `SMB2_STATUS_REGISTRY_CORRUPT`."
);
smb2_status_const!(
    SMB2_STATUS_REGISTRY_IO_FAILED,
    0xC000_014D,
    "SMB2 error status constant `SMB2_STATUS_REGISTRY_IO_FAILED`."
);
smb2_status_const!(
    SMB2_STATUS_NO_EVENT_PAIR,
    0xC000_014E,
    "SMB2 error status constant `SMB2_STATUS_NO_EVENT_PAIR`."
);
smb2_status_const!(
    SMB2_STATUS_UNRECOGNIZED_VOLUME,
    0xC000_014F,
    "SMB2 error status constant `SMB2_STATUS_UNRECOGNIZED_VOLUME`."
);
smb2_status_const!(
    SMB2_STATUS_SERIAL_NO_DEVICE_INITED,
    0xC000_0150,
    "SMB2 error status constant `SMB2_STATUS_SERIAL_NO_DEVICE_INITED`."
);
smb2_status_const!(
    SMB2_STATUS_NO_SUCH_ALIAS,
    0xC000_0151,
    "SMB2 error status constant `SMB2_STATUS_NO_SUCH_ALIAS`."
);
smb2_status_const!(
    SMB2_STATUS_MEMBER_NOT_IN_ALIAS,
    0xC000_0152,
    "SMB2 error status constant `SMB2_STATUS_MEMBER_NOT_IN_ALIAS`."
);
smb2_status_const!(
    SMB2_STATUS_MEMBER_IN_ALIAS,
    0xC000_0153,
    "SMB2 error status constant `SMB2_STATUS_MEMBER_IN_ALIAS`."
);
smb2_status_const!(
    SMB2_STATUS_ALIAS_EXISTS,
    0xC000_0154,
    "SMB2 error status constant `SMB2_STATUS_ALIAS_EXISTS`."
);
smb2_status_const!(
    SMB2_STATUS_LOGON_NOT_GRANTED,
    0xC000_0155,
    "SMB2 error status constant `SMB2_STATUS_LOGON_NOT_GRANTED`."
);
smb2_status_const!(
    SMB2_STATUS_TOO_MANY_SECRETS,
    0xC000_0156,
    "SMB2 error status constant `SMB2_STATUS_TOO_MANY_SECRETS`."
);
smb2_status_const!(
    SMB2_STATUS_SECRET_TOO_LONG,
    0xC000_0157,
    "SMB2 error status constant `SMB2_STATUS_SECRET_TOO_LONG`."
);
smb2_status_const!(
    SMB2_STATUS_INTERNAL_DB_ERROR,
    0xC000_0158,
    "SMB2 error status constant `SMB2_STATUS_INTERNAL_DB_ERROR`."
);
smb2_status_const!(
    SMB2_STATUS_FULLSCREEN_MODE,
    0xC000_0159,
    "SMB2 error status constant `SMB2_STATUS_FULLSCREEN_MODE`."
);
smb2_status_const!(
    SMB2_STATUS_TOO_MANY_CONTEXT_IDS,
    0xC000_015A,
    "SMB2 error status constant `SMB2_STATUS_TOO_MANY_CONTEXT_IDS`."
);
smb2_status_const!(
    SMB2_STATUS_LOGON_TYPE_NOT_GRANTED,
    0xC000_015B,
    "SMB2 error status constant `SMB2_STATUS_LOGON_TYPE_NOT_GRANTED`."
);
smb2_status_const!(
    SMB2_STATUS_NOT_REGISTRY_FILE,
    0xC000_015C,
    "SMB2 error status constant `SMB2_STATUS_NOT_REGISTRY_FILE`."
);
smb2_status_const!(
    SMB2_STATUS_NT_CROSS_ENCRYPTION_REQUIRED,
    0xC000_015D,
    "SMB2 error status constant `SMB2_STATUS_NT_CROSS_ENCRYPTION_REQUIRED`."
);
smb2_status_const!(
    SMB2_STATUS_DOMAIN_CTRLR_CONFIG_ERROR,
    0xC000_015E,
    "SMB2 error status constant `SMB2_STATUS_DOMAIN_CTRLR_CONFIG_ERROR`."
);
smb2_status_const!(
    SMB2_STATUS_FT_MISSING_MEMBER,
    0xC000_015F,
    "SMB2 error status constant `SMB2_STATUS_FT_MISSING_MEMBER`."
);
smb2_status_const!(
    SMB2_STATUS_ILL_FORMED_SERVICE_ENTRY,
    0xC000_0160,
    "SMB2 error status constant `SMB2_STATUS_ILL_FORMED_SERVICE_ENTRY`."
);
smb2_status_const!(
    SMB2_STATUS_ILLEGAL_CHARACTER,
    0xC000_0161,
    "SMB2 error status constant `SMB2_STATUS_ILLEGAL_CHARACTER`."
);
smb2_status_const!(
    SMB2_STATUS_UNMAPPABLE_CHARACTER,
    0xC000_0162,
    "SMB2 error status constant `SMB2_STATUS_UNMAPPABLE_CHARACTER`."
);
smb2_status_const!(
    SMB2_STATUS_UNDEFINED_CHARACTER,
    0xC000_0163,
    "SMB2 error status constant `SMB2_STATUS_UNDEFINED_CHARACTER`."
);
smb2_status_const!(
    SMB2_STATUS_FLOPPY_VOLUME,
    0xC000_0164,
    "SMB2 error status constant `SMB2_STATUS_FLOPPY_VOLUME`."
);
smb2_status_const!(
    SMB2_STATUS_FLOPPY_ID_MARK_NOT_FOUND,
    0xC000_0165,
    "SMB2 error status constant `SMB2_STATUS_FLOPPY_ID_MARK_NOT_FOUND`."
);
smb2_status_const!(
    SMB2_STATUS_FLOPPY_WRONG_CYLINDER,
    0xC000_0166,
    "SMB2 error status constant `SMB2_STATUS_FLOPPY_WRONG_CYLINDER`."
);
smb2_status_const!(
    SMB2_STATUS_FLOPPY_UNKNOWN_ERROR,
    0xC000_0167,
    "SMB2 error status constant `SMB2_STATUS_FLOPPY_UNKNOWN_ERROR`."
);
smb2_status_const!(
    SMB2_STATUS_FLOPPY_BAD_REGISTERS,
    0xC000_0168,
    "SMB2 error status constant `SMB2_STATUS_FLOPPY_BAD_REGISTERS`."
);
smb2_status_const!(
    SMB2_STATUS_DISK_RECALIBRATE_FAILED,
    0xC000_0169,
    "SMB2 error status constant `SMB2_STATUS_DISK_RECALIBRATE_FAILED`."
);
smb2_status_const!(
    SMB2_STATUS_DISK_OPERATION_FAILED,
    0xC000_016A,
    "SMB2 error status constant `SMB2_STATUS_DISK_OPERATION_FAILED`."
);
smb2_status_const!(
    SMB2_STATUS_DISK_RESET_FAILED,
    0xC000_016B,
    "SMB2 error status constant `SMB2_STATUS_DISK_RESET_FAILED`."
);
smb2_status_const!(
    SMB2_STATUS_SHARED_IRQ_BUSY,
    0xC000_016C,
    "SMB2 error status constant `SMB2_STATUS_SHARED_IRQ_BUSY`."
);
smb2_status_const!(
    SMB2_STATUS_FT_ORPHANING,
    0xC000_016D,
    "SMB2 error status constant `SMB2_STATUS_FT_ORPHANING`."
);
smb2_status_const!(
    SMB2_STATUS_PARTITION_FAILURE,
    0xC000_0172,
    "SMB2 error status constant `SMB2_STATUS_PARTITION_FAILURE`."
);
smb2_status_const!(
    SMB2_STATUS_INVALID_BLOCK_LENGTH,
    0xC000_0173,
    "SMB2 error status constant `SMB2_STATUS_INVALID_BLOCK_LENGTH`."
);
smb2_status_const!(
    SMB2_STATUS_DEVICE_NOT_PARTITIONED,
    0xC000_0174,
    "SMB2 error status constant `SMB2_STATUS_DEVICE_NOT_PARTITIONED`."
);
smb2_status_const!(
    SMB2_STATUS_UNABLE_TO_LOCK_MEDIA,
    0xC000_0175,
    "SMB2 error status constant `SMB2_STATUS_UNABLE_TO_LOCK_MEDIA`."
);
smb2_status_const!(
    SMB2_STATUS_UNABLE_TO_UNLOAD_MEDIA,
    0xC000_0176,
    "SMB2 error status constant `SMB2_STATUS_UNABLE_TO_UNLOAD_MEDIA`."
);
smb2_status_const!(
    SMB2_STATUS_EOM_OVERFLOW,
    0xC000_0177,
    "SMB2 error status constant `SMB2_STATUS_EOM_OVERFLOW`."
);
smb2_status_const!(
    SMB2_STATUS_NO_MEDIA,
    0xC000_0178,
    "SMB2 error status constant `SMB2_STATUS_NO_MEDIA`."
);
smb2_status_const!(
    SMB2_STATUS_NO_SUCH_MEMBER,
    0xC000_017A,
    "SMB2 error status constant `SMB2_STATUS_NO_SUCH_MEMBER`."
);
smb2_status_const!(
    SMB2_STATUS_INVALID_MEMBER,
    0xC000_017B,
    "SMB2 error status constant `SMB2_STATUS_INVALID_MEMBER`."
);
smb2_status_const!(
    SMB2_STATUS_KEY_DELETED,
    0xC000_017C,
    "SMB2 error status constant `SMB2_STATUS_KEY_DELETED`."
);
smb2_status_const!(
    SMB2_STATUS_NO_LOG_SPACE,
    0xC000_017D,
    "SMB2 error status constant `SMB2_STATUS_NO_LOG_SPACE`."
);
smb2_status_const!(
    SMB2_STATUS_TOO_MANY_SIDS,
    0xC000_017E,
    "SMB2 error status constant `SMB2_STATUS_TOO_MANY_SIDS`."
);
smb2_status_const!(
    SMB2_STATUS_LM_CROSS_ENCRYPTION_REQUIRED,
    0xC000_017F,
    "SMB2 error status constant `SMB2_STATUS_LM_CROSS_ENCRYPTION_REQUIRED`."
);
smb2_status_const!(
    SMB2_STATUS_KEY_HAS_CHILDREN,
    0xC000_0180,
    "SMB2 error status constant `SMB2_STATUS_KEY_HAS_CHILDREN`."
);
smb2_status_const!(
    SMB2_STATUS_CHILD_MUST_BE_VOLATILE,
    0xC000_0181,
    "SMB2 error status constant `SMB2_STATUS_CHILD_MUST_BE_VOLATILE`."
);
smb2_status_const!(
    SMB2_STATUS_DEVICE_CONFIGURATION_ERROR,
    0xC000_0182,
    "SMB2 error status constant `SMB2_STATUS_DEVICE_CONFIGURATION_ERROR`."
);
smb2_status_const!(
    SMB2_STATUS_DRIVER_INTERNAL_ERROR,
    0xC000_0183,
    "SMB2 error status constant `SMB2_STATUS_DRIVER_INTERNAL_ERROR`."
);
smb2_status_const!(
    SMB2_STATUS_INVALID_DEVICE_STATE,
    0xC000_0184,
    "SMB2 error status constant `SMB2_STATUS_INVALID_DEVICE_STATE`."
);
smb2_status_const!(
    SMB2_STATUS_IO_DEVICE_ERROR,
    0xC000_0185,
    "SMB2 error status constant `SMB2_STATUS_IO_DEVICE_ERROR`."
);
smb2_status_const!(
    SMB2_STATUS_DEVICE_PROTOCOL_ERROR,
    0xC000_0186,
    "SMB2 error status constant `SMB2_STATUS_DEVICE_PROTOCOL_ERROR`."
);
smb2_status_const!(
    SMB2_STATUS_BACKUP_CONTROLLER,
    0xC000_0187,
    "SMB2 error status constant `SMB2_STATUS_BACKUP_CONTROLLER`."
);
smb2_status_const!(
    SMB2_STATUS_LOG_FILE_FULL,
    0xC000_0188,
    "SMB2 error status constant `SMB2_STATUS_LOG_FILE_FULL`."
);
smb2_status_const!(
    SMB2_STATUS_TOO_LATE,
    0xC000_0189,
    "SMB2 error status constant `SMB2_STATUS_TOO_LATE`."
);
smb2_status_const!(
    SMB2_STATUS_NO_TRUST_LSA_SECRET,
    0xC000_018A,
    "SMB2 error status constant `SMB2_STATUS_NO_TRUST_LSA_SECRET`."
);
smb2_status_const!(
    SMB2_STATUS_NO_TRUST_SAM_ACCOUNT,
    0xC000_018B,
    "SMB2 error status constant `SMB2_STATUS_NO_TRUST_SAM_ACCOUNT`."
);
smb2_status_const!(
    SMB2_STATUS_TRUSTED_DOMAIN_FAILURE,
    0xC000_018C,
    "SMB2 error status constant `SMB2_STATUS_TRUSTED_DOMAIN_FAILURE`."
);
smb2_status_const!(
    SMB2_STATUS_TRUSTED_RELATIONSHIP_FAILURE,
    0xC000_018D,
    "SMB2 error status constant `SMB2_STATUS_TRUSTED_RELATIONSHIP_FAILURE`."
);
smb2_status_const!(
    SMB2_STATUS_EVENTLOG_FILE_CORRUPT,
    0xC000_018E,
    "SMB2 error status constant `SMB2_STATUS_EVENTLOG_FILE_CORRUPT`."
);
smb2_status_const!(
    SMB2_STATUS_EVENTLOG_CANT_START,
    0xC000_018F,
    "SMB2 error status constant `SMB2_STATUS_EVENTLOG_CANT_START`."
);
smb2_status_const!(
    SMB2_STATUS_TRUST_FAILURE,
    0xC000_0190,
    "SMB2 error status constant `SMB2_STATUS_TRUST_FAILURE`."
);
smb2_status_const!(
    SMB2_STATUS_MUTANT_LIMIT_EXCEEDED,
    0xC000_0191,
    "SMB2 error status constant `SMB2_STATUS_MUTANT_LIMIT_EXCEEDED`."
);
smb2_status_const!(
    SMB2_STATUS_NETLOGON_NOT_STARTED,
    0xC000_0192,
    "SMB2 error status constant `SMB2_STATUS_NETLOGON_NOT_STARTED`."
);
smb2_status_const!(
    SMB2_STATUS_ACCOUNT_EXPIRED,
    0xC000_0193,
    "SMB2 error status constant `SMB2_STATUS_ACCOUNT_EXPIRED`."
);
smb2_status_const!(
    SMB2_STATUS_POSSIBLE_DEADLOCK,
    0xC000_0194,
    "SMB2 error status constant `SMB2_STATUS_POSSIBLE_DEADLOCK`."
);
smb2_status_const!(
    SMB2_STATUS_NETWORK_CREDENTIAL_CONFLICT,
    0xC000_0195,
    "SMB2 error status constant `SMB2_STATUS_NETWORK_CREDENTIAL_CONFLICT`."
);
smb2_status_const!(
    SMB2_STATUS_REMOTE_SESSION_LIMIT,
    0xC000_0196,
    "SMB2 error status constant `SMB2_STATUS_REMOTE_SESSION_LIMIT`."
);
smb2_status_const!(
    SMB2_STATUS_EVENTLOG_FILE_CHANGED,
    0xC000_0197,
    "SMB2 error status constant `SMB2_STATUS_EVENTLOG_FILE_CHANGED`."
);
smb2_status_const!(
    SMB2_STATUS_NOLOGON_INTERDOMAIN_TRUST_ACCOUNT,
    0xC000_0198,
    "SMB2 error status constant `SMB2_STATUS_NOLOGON_INTERDOMAIN_TRUST_ACCOUNT`."
);
smb2_status_const!(
    SMB2_STATUS_NOLOGON_WORKSTATION_TRUST_ACCOUNT,
    0xC000_0199,
    "SMB2 error status constant `SMB2_STATUS_NOLOGON_WORKSTATION_TRUST_ACCOUNT`."
);
smb2_status_const!(
    SMB2_STATUS_NOLOGON_SERVER_TRUST_ACCOUNT,
    0xC000_019A,
    "SMB2 error status constant `SMB2_STATUS_NOLOGON_SERVER_TRUST_ACCOUNT`."
);
smb2_status_const!(
    SMB2_STATUS_DOMAIN_TRUST_INCONSISTENT,
    0xC000_019B,
    "SMB2 error status constant `SMB2_STATUS_DOMAIN_TRUST_INCONSISTENT`."
);
smb2_status_const!(
    SMB2_STATUS_FS_DRIVER_REQUIRED,
    0xC000_019C,
    "SMB2 error status constant `SMB2_STATUS_FS_DRIVER_REQUIRED`."
);
smb2_status_const!(
    SMB2_STATUS_NO_USER_SESSION_KEY,
    0xC000_0202,
    "SMB2 error status constant `SMB2_STATUS_NO_USER_SESSION_KEY`."
);
smb2_status_const!(
    SMB2_STATUS_USER_SESSION_DELETED,
    0xC000_0203,
    "SMB2 error status constant `SMB2_STATUS_USER_SESSION_DELETED`."
);
smb2_status_const!(
    SMB2_STATUS_RESOURCE_LANG_NOT_FOUND,
    0xC000_0204,
    "SMB2 error status constant `SMB2_STATUS_RESOURCE_LANG_NOT_FOUND`."
);
smb2_status_const!(
    SMB2_STATUS_INSUFF_SERVER_RESOURCES,
    0xC000_0205,
    "SMB2 error status constant `SMB2_STATUS_INSUFF_SERVER_RESOURCES`."
);
smb2_status_const!(
    SMB2_STATUS_INVALID_BUFFER_SIZE,
    0xC000_0206,
    "SMB2 error status constant `SMB2_STATUS_INVALID_BUFFER_SIZE`."
);
smb2_status_const!(
    SMB2_STATUS_INVALID_ADDRESS_COMPONENT,
    0xC000_0207,
    "SMB2 error status constant `SMB2_STATUS_INVALID_ADDRESS_COMPONENT`."
);
smb2_status_const!(
    SMB2_STATUS_INVALID_ADDRESS_WILDCARD,
    0xC000_0208,
    "SMB2 error status constant `SMB2_STATUS_INVALID_ADDRESS_WILDCARD`."
);
smb2_status_const!(
    SMB2_STATUS_TOO_MANY_ADDRESSES,
    0xC000_0209,
    "SMB2 error status constant `SMB2_STATUS_TOO_MANY_ADDRESSES`."
);
smb2_status_const!(
    SMB2_STATUS_ADDRESS_ALREADY_EXISTS,
    0xC000_020A,
    "SMB2 error status constant `SMB2_STATUS_ADDRESS_ALREADY_EXISTS`."
);
smb2_status_const!(
    SMB2_STATUS_ADDRESS_CLOSED,
    0xC000_020B,
    "SMB2 error status constant `SMB2_STATUS_ADDRESS_CLOSED`."
);
smb2_status_const!(
    SMB2_STATUS_CONNECTION_DISCONNECTED,
    0xC000_020C,
    "SMB2 error status constant `SMB2_STATUS_CONNECTION_DISCONNECTED`."
);
smb2_status_const!(
    SMB2_STATUS_CONNECTION_RESET,
    0xC000_020D,
    "SMB2 error status constant `SMB2_STATUS_CONNECTION_RESET`."
);
smb2_status_const!(
    SMB2_STATUS_TOO_MANY_NODES,
    0xC000_020E,
    "SMB2 error status constant `SMB2_STATUS_TOO_MANY_NODES`."
);
smb2_status_const!(
    SMB2_STATUS_TRANSACTION_ABORTED,
    0xC000_020F,
    "SMB2 error status constant `SMB2_STATUS_TRANSACTION_ABORTED`."
);
smb2_status_const!(
    SMB2_STATUS_TRANSACTION_TIMED_OUT,
    0xC000_0210,
    "SMB2 error status constant `SMB2_STATUS_TRANSACTION_TIMED_OUT`."
);
smb2_status_const!(
    SMB2_STATUS_TRANSACTION_NO_RELEASE,
    0xC000_0211,
    "SMB2 error status constant `SMB2_STATUS_TRANSACTION_NO_RELEASE`."
);
smb2_status_const!(
    SMB2_STATUS_TRANSACTION_NO_MATCH,
    0xC000_0212,
    "SMB2 error status constant `SMB2_STATUS_TRANSACTION_NO_MATCH`."
);
smb2_status_const!(
    SMB2_STATUS_TRANSACTION_RESPONDED,
    0xC000_0213,
    "SMB2 error status constant `SMB2_STATUS_TRANSACTION_RESPONDED`."
);
smb2_status_const!(
    SMB2_STATUS_TRANSACTION_INVALID_ID,
    0xC000_0214,
    "SMB2 error status constant `SMB2_STATUS_TRANSACTION_INVALID_ID`."
);
smb2_status_const!(
    SMB2_STATUS_TRANSACTION_INVALID_TYPE,
    0xC000_0215,
    "SMB2 error status constant `SMB2_STATUS_TRANSACTION_INVALID_TYPE`."
);
smb2_status_const!(
    SMB2_STATUS_NOT_SERVER_SESSION,
    0xC000_0216,
    "SMB2 error status constant `SMB2_STATUS_NOT_SERVER_SESSION`."
);
smb2_status_const!(
    SMB2_STATUS_NOT_CLIENT_SESSION,
    0xC000_0217,
    "SMB2 error status constant `SMB2_STATUS_NOT_CLIENT_SESSION`."
);
smb2_status_const!(
    SMB2_STATUS_CANNOT_LOAD_REGISTRY_FILE,
    0xC000_0218,
    "SMB2 error status constant `SMB2_STATUS_CANNOT_LOAD_REGISTRY_FILE`."
);
smb2_status_const!(
    SMB2_STATUS_DEBUG_ATTACH_FAILED,
    0xC000_0219,
    "SMB2 error status constant `SMB2_STATUS_DEBUG_ATTACH_FAILED`."
);
smb2_status_const!(
    SMB2_STATUS_SYSTEM_PROCESS_TERMINATED,
    0xC000_021A,
    "SMB2 error status constant `SMB2_STATUS_SYSTEM_PROCESS_TERMINATED`."
);
smb2_status_const!(
    SMB2_STATUS_DATA_NOT_ACCEPTED,
    0xC000_021B,
    "SMB2 error status constant `SMB2_STATUS_DATA_NOT_ACCEPTED`."
);
smb2_status_const!(
    SMB2_STATUS_NO_BROWSER_SERVERS_FOUND,
    0xC000_021C,
    "SMB2 error status constant `SMB2_STATUS_NO_BROWSER_SERVERS_FOUND`."
);
smb2_status_const!(
    SMB2_STATUS_VDM_HARD_ERROR,
    0xC000_021D,
    "SMB2 error status constant `SMB2_STATUS_VDM_HARD_ERROR`."
);
smb2_status_const!(
    SMB2_STATUS_DRIVER_CANCEL_TIMEOUT,
    0xC000_021E,
    "SMB2 error status constant `SMB2_STATUS_DRIVER_CANCEL_TIMEOUT`."
);
smb2_status_const!(
    SMB2_STATUS_REPLY_MESSAGE_MISMATCH,
    0xC000_021F,
    "SMB2 error status constant `SMB2_STATUS_REPLY_MESSAGE_MISMATCH`."
);
smb2_status_const!(
    SMB2_STATUS_MAPPED_ALIGNMENT,
    0xC000_0220,
    "SMB2 error status constant `SMB2_STATUS_MAPPED_ALIGNMENT`."
);
smb2_status_const!(
    SMB2_STATUS_IMAGE_CHECKSUM_MISMATCH,
    0xC000_0221,
    "SMB2 error status constant `SMB2_STATUS_IMAGE_CHECKSUM_MISMATCH`."
);
smb2_status_const!(
    SMB2_STATUS_LOST_WRITEBEHIND_DATA,
    0xC000_0222,
    "SMB2 error status constant `SMB2_STATUS_LOST_WRITEBEHIND_DATA`."
);
smb2_status_const!(
    SMB2_STATUS_CLIENT_SERVER_PARAMETERS_INVALID,
    0xC000_0223,
    "SMB2 error status constant `SMB2_STATUS_CLIENT_SERVER_PARAMETERS_INVALID`."
);
smb2_status_const!(
    SMB2_STATUS_PASSWORD_MUST_CHANGE,
    0xC000_0224,
    "SMB2 error status constant `SMB2_STATUS_PASSWORD_MUST_CHANGE`."
);
smb2_status_const!(
    SMB2_STATUS_NOT_FOUND,
    0xC000_0225,
    "SMB2 error status constant `SMB2_STATUS_NOT_FOUND`."
);
smb2_status_const!(
    SMB2_STATUS_NOT_TINY_STREAM,
    0xC000_0226,
    "SMB2 error status constant `SMB2_STATUS_NOT_TINY_STREAM`."
);
smb2_status_const!(
    SMB2_STATUS_RECOVERY_FAILURE,
    0xC000_0227,
    "SMB2 error status constant `SMB2_STATUS_RECOVERY_FAILURE`."
);
smb2_status_const!(
    SMB2_STATUS_STACK_OVERFLOW_READ,
    0xC000_0228,
    "SMB2 error status constant `SMB2_STATUS_STACK_OVERFLOW_READ`."
);
smb2_status_const!(
    SMB2_STATUS_FAIL_CHECK,
    0xC000_0229,
    "SMB2 error status constant `SMB2_STATUS_FAIL_CHECK`."
);
smb2_status_const!(
    SMB2_STATUS_DUPLICATE_OBJECTID,
    0xC000_022A,
    "SMB2 error status constant `SMB2_STATUS_DUPLICATE_OBJECTID`."
);
smb2_status_const!(
    SMB2_STATUS_OBJECTID_EXISTS,
    0xC000_022B,
    "SMB2 error status constant `SMB2_STATUS_OBJECTID_EXISTS`."
);
smb2_status_const!(
    SMB2_STATUS_CONVERT_TO_LARGE,
    0xC000_022C,
    "SMB2 error status constant `SMB2_STATUS_CONVERT_TO_LARGE`."
);
smb2_status_const!(
    SMB2_STATUS_RETRY,
    0xC000_022D,
    "SMB2 error status constant `SMB2_STATUS_RETRY`."
);
smb2_status_const!(
    SMB2_STATUS_FOUND_OUT_OF_SCOPE,
    0xC000_022E,
    "SMB2 error status constant `SMB2_STATUS_FOUND_OUT_OF_SCOPE`."
);
smb2_status_const!(
    SMB2_STATUS_ALLOCATE_BUCKET,
    0xC000_022F,
    "SMB2 error status constant `SMB2_STATUS_ALLOCATE_BUCKET`."
);
smb2_status_const!(
    SMB2_STATUS_PROPSET_NOT_FOUND,
    0xC000_0230,
    "SMB2 error status constant `SMB2_STATUS_PROPSET_NOT_FOUND`."
);
smb2_status_const!(
    SMB2_STATUS_MARSHALL_OVERFLOW,
    0xC000_0231,
    "SMB2 error status constant `SMB2_STATUS_MARSHALL_OVERFLOW`."
);
smb2_status_const!(
    SMB2_STATUS_INVALID_VARIANT,
    0xC000_0232,
    "SMB2 error status constant `SMB2_STATUS_INVALID_VARIANT`."
);
smb2_status_const!(
    SMB2_STATUS_DOMAIN_CONTROLLER_NOT_FOUND,
    0xC000_0233,
    "SMB2 error status constant `SMB2_STATUS_DOMAIN_CONTROLLER_NOT_FOUND`."
);
smb2_status_const!(
    SMB2_STATUS_ACCOUNT_LOCKED_OUT,
    0xC000_0234,
    "SMB2 error status constant `SMB2_STATUS_ACCOUNT_LOCKED_OUT`."
);
smb2_status_const!(
    SMB2_STATUS_HANDLE_NOT_CLOSABLE,
    0xC000_0235,
    "SMB2 error status constant `SMB2_STATUS_HANDLE_NOT_CLOSABLE`."
);
smb2_status_const!(
    SMB2_STATUS_CONNECTION_REFUSED,
    0xC000_0236,
    "SMB2 error status constant `SMB2_STATUS_CONNECTION_REFUSED`."
);
smb2_status_const!(
    SMB2_STATUS_GRACEFUL_DISCONNECT,
    0xC000_0237,
    "SMB2 error status constant `SMB2_STATUS_GRACEFUL_DISCONNECT`."
);
smb2_status_const!(
    SMB2_STATUS_ADDRESS_ALREADY_ASSOCIATED,
    0xC000_0238,
    "SMB2 error status constant `SMB2_STATUS_ADDRESS_ALREADY_ASSOCIATED`."
);
smb2_status_const!(
    SMB2_STATUS_ADDRESS_NOT_ASSOCIATED,
    0xC000_0239,
    "SMB2 error status constant `SMB2_STATUS_ADDRESS_NOT_ASSOCIATED`."
);
smb2_status_const!(
    SMB2_STATUS_CONNECTION_INVALID,
    0xC000_023A,
    "SMB2 error status constant `SMB2_STATUS_CONNECTION_INVALID`."
);
smb2_status_const!(
    SMB2_STATUS_CONNECTION_ACTIVE,
    0xC000_023B,
    "SMB2 error status constant `SMB2_STATUS_CONNECTION_ACTIVE`."
);
smb2_status_const!(
    SMB2_STATUS_NETWORK_UNREACHABLE,
    0xC000_023C,
    "SMB2 error status constant `SMB2_STATUS_NETWORK_UNREACHABLE`."
);
smb2_status_const!(
    SMB2_STATUS_HOST_UNREACHABLE,
    0xC000_023D,
    "SMB2 error status constant `SMB2_STATUS_HOST_UNREACHABLE`."
);
smb2_status_const!(
    SMB2_STATUS_PROTOCOL_UNREACHABLE,
    0xC000_023E,
    "SMB2 error status constant `SMB2_STATUS_PROTOCOL_UNREACHABLE`."
);
smb2_status_const!(
    SMB2_STATUS_PORT_UNREACHABLE,
    0xC000_023F,
    "SMB2 error status constant `SMB2_STATUS_PORT_UNREACHABLE`."
);
smb2_status_const!(
    SMB2_STATUS_REQUEST_ABORTED,
    0xC000_0240,
    "SMB2 error status constant `SMB2_STATUS_REQUEST_ABORTED`."
);
smb2_status_const!(
    SMB2_STATUS_CONNECTION_ABORTED,
    0xC000_0241,
    "SMB2 error status constant `SMB2_STATUS_CONNECTION_ABORTED`."
);
smb2_status_const!(
    SMB2_STATUS_BAD_COMPRESSION_BUFFER,
    0xC000_0242,
    "SMB2 error status constant `SMB2_STATUS_BAD_COMPRESSION_BUFFER`."
);
smb2_status_const!(
    SMB2_STATUS_USER_MAPPED_FILE,
    0xC000_0243,
    "SMB2 error status constant `SMB2_STATUS_USER_MAPPED_FILE`."
);
smb2_status_const!(
    SMB2_STATUS_AUDIT_FAILED,
    0xC000_0244,
    "SMB2 error status constant `SMB2_STATUS_AUDIT_FAILED`."
);
smb2_status_const!(
    SMB2_STATUS_TIMER_RESOLUTION_NOT_SET,
    0xC000_0245,
    "SMB2 error status constant `SMB2_STATUS_TIMER_RESOLUTION_NOT_SET`."
);
smb2_status_const!(
    SMB2_STATUS_CONNECTION_COUNT_LIMIT,
    0xC000_0246,
    "SMB2 error status constant `SMB2_STATUS_CONNECTION_COUNT_LIMIT`."
);
smb2_status_const!(
    SMB2_STATUS_LOGIN_TIME_RESTRICTION,
    0xC000_0247,
    "SMB2 error status constant `SMB2_STATUS_LOGIN_TIME_RESTRICTION`."
);
smb2_status_const!(
    SMB2_STATUS_LOGIN_WKSTA_RESTRICTION,
    0xC000_0248,
    "SMB2 error status constant `SMB2_STATUS_LOGIN_WKSTA_RESTRICTION`."
);
smb2_status_const!(
    SMB2_STATUS_IMAGE_MP_UP_MISMATCH,
    0xC000_0249,
    "SMB2 error status constant `SMB2_STATUS_IMAGE_MP_UP_MISMATCH`."
);
smb2_status_const!(
    SMB2_STATUS_INSUFFICIENT_LOGON_INFO,
    0xC000_0250,
    "SMB2 error status constant `SMB2_STATUS_INSUFFICIENT_LOGON_INFO`."
);
smb2_status_const!(
    SMB2_STATUS_BAD_DLL_ENTRYPOINT,
    0xC000_0251,
    "SMB2 error status constant `SMB2_STATUS_BAD_DLL_ENTRYPOINT`."
);
smb2_status_const!(
    SMB2_STATUS_BAD_SERVICE_ENTRYPOINT,
    0xC000_0252,
    "SMB2 error status constant `SMB2_STATUS_BAD_SERVICE_ENTRYPOINT`."
);
smb2_status_const!(
    SMB2_STATUS_LPC_REPLY_LOST,
    0xC000_0253,
    "SMB2 error status constant `SMB2_STATUS_LPC_REPLY_LOST`."
);
smb2_status_const!(
    SMB2_STATUS_IP_ADDRESS_CONFLICT1,
    0xC000_0254,
    "SMB2 error status constant `SMB2_STATUS_IP_ADDRESS_CONFLICT1`."
);
smb2_status_const!(
    SMB2_STATUS_IP_ADDRESS_CONFLICT2,
    0xC000_0255,
    "SMB2 error status constant `SMB2_STATUS_IP_ADDRESS_CONFLICT2`."
);
smb2_status_const!(
    SMB2_STATUS_REGISTRY_QUOTA_LIMIT,
    0xC000_0256,
    "SMB2 error status constant `SMB2_STATUS_REGISTRY_QUOTA_LIMIT`."
);
smb2_status_const!(
    SMB2_STATUS_PATH_NOT_COVERED,
    0xC000_0257,
    "SMB2 error status constant `SMB2_STATUS_PATH_NOT_COVERED`."
);
smb2_status_const!(
    SMB2_STATUS_NO_CALLBACK_ACTIVE,
    0xC000_0258,
    "SMB2 error status constant `SMB2_STATUS_NO_CALLBACK_ACTIVE`."
);
smb2_status_const!(
    SMB2_STATUS_LICENSE_QUOTA_EXCEEDED,
    0xC000_0259,
    "SMB2 error status constant `SMB2_STATUS_LICENSE_QUOTA_EXCEEDED`."
);
smb2_status_const!(
    SMB2_STATUS_PWD_TOO_SHORT,
    0xC000_025A,
    "SMB2 error status constant `SMB2_STATUS_PWD_TOO_SHORT`."
);
smb2_status_const!(
    SMB2_STATUS_PWD_TOO_RECENT,
    0xC000_025B,
    "SMB2 error status constant `SMB2_STATUS_PWD_TOO_RECENT`."
);
smb2_status_const!(
    SMB2_STATUS_PWD_HISTORY_CONFLICT,
    0xC000_025C,
    "SMB2 error status constant `SMB2_STATUS_PWD_HISTORY_CONFLICT`."
);
smb2_status_const!(
    SMB2_STATUS_PLUGPLAY_NO_DEVICE,
    0xC000_025E,
    "SMB2 error status constant `SMB2_STATUS_PLUGPLAY_NO_DEVICE`."
);
smb2_status_const!(
    SMB2_STATUS_UNSUPPORTED_COMPRESSION,
    0xC000_025F,
    "SMB2 error status constant `SMB2_STATUS_UNSUPPORTED_COMPRESSION`."
);
smb2_status_const!(
    SMB2_STATUS_INVALID_HW_PROFILE,
    0xC000_0260,
    "SMB2 error status constant `SMB2_STATUS_INVALID_HW_PROFILE`."
);
smb2_status_const!(
    SMB2_STATUS_INVALID_PLUGPLAY_DEVICE_PATH,
    0xC000_0261,
    "SMB2 error status constant `SMB2_STATUS_INVALID_PLUGPLAY_DEVICE_PATH`."
);
smb2_status_const!(
    SMB2_STATUS_DRIVER_ORDINAL_NOT_FOUND,
    0xC000_0262,
    "SMB2 error status constant `SMB2_STATUS_DRIVER_ORDINAL_NOT_FOUND`."
);
smb2_status_const!(
    SMB2_STATUS_DRIVER_ENTRYPOINT_NOT_FOUND,
    0xC000_0263,
    "SMB2 error status constant `SMB2_STATUS_DRIVER_ENTRYPOINT_NOT_FOUND`."
);
smb2_status_const!(
    SMB2_STATUS_RESOURCE_NOT_OWNED,
    0xC000_0264,
    "SMB2 error status constant `SMB2_STATUS_RESOURCE_NOT_OWNED`."
);
smb2_status_const!(
    SMB2_STATUS_TOO_MANY_LINKS,
    0xC000_0265,
    "SMB2 error status constant `SMB2_STATUS_TOO_MANY_LINKS`."
);
smb2_status_const!(
    SMB2_STATUS_QUOTA_LIST_INCONSISTENT,
    0xC000_0266,
    "SMB2 error status constant `SMB2_STATUS_QUOTA_LIST_INCONSISTENT`."
);
smb2_status_const!(
    SMB2_STATUS_FILE_IS_OFFLINE,
    0xC000_0267,
    "SMB2 error status constant `SMB2_STATUS_FILE_IS_OFFLINE`."
);
smb2_status_const!(
    SMB2_STATUS_VOLUME_DISMOUNTED,
    0xC000_026E,
    "SMB2 error status constant `SMB2_STATUS_VOLUME_DISMOUNTED`."
);
smb2_status_const!(
    SMB2_STATUS_NOT_A_REPARSE_POINT,
    0xC000_0275,
    "SMB2 error status constant `SMB2_STATUS_NOT_A_REPARSE_POINT`."
);
smb2_status_const!(
    SMB2_STATUS_SERVER_UNAVAILABLE,
    0xC000_0466,
    "SMB2 error status constant `SMB2_STATUS_SERVER_UNAVAILABLE`."
);
smb2_status_const!(
    SMB2_STATUS_BUFFER_OVERFLOW,
    0x8000_0005,
    "SMB2 warning status constant `SMB2_STATUS_BUFFER_OVERFLOW`."
);
smb2_status_const!(
    SMB2_STATUS_STOPPED_ON_SYMLINK,
    0x8000_002D,
    "SMB2 warning status constant `SMB2_STATUS_STOPPED_ON_SYMLINK`."
);

/// Backwards-compatible shorthand alias for `SMB2_STATUS_SUCCESS`.
pub const STATUS_SUCCESS: u32 = SMB2_STATUS_SUCCESS;
/// Backwards-compatible shorthand alias for `SMB2_STATUS_UNSUCCESSFUL`.
pub const STATUS_UNSUCCESSFUL: u32 = SMB2_STATUS_UNSUCCESSFUL;

/// Severity bits extracted from an NTSTATUS value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NtStatusSeverity {
    /// Successful completion severity.
    Success,
    /// Informational severity.
    Informational,
    /// Warning severity.
    Warning,
    /// Error severity.
    Error,
    /// Reserved or otherwise unknown severity bit pattern.
    Unknown(u32),
}

/// Wrapper for a raw SMB2 NTSTATUS value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct NtStatus(u32);

impl NtStatus {
    /// Creates a wrapper from the raw 32-bit NTSTATUS value.
    #[must_use]
    pub const fn new(raw: u32) -> Self {
        Self(raw)
    }

    /// Returns the raw 32-bit NTSTATUS value.
    #[must_use]
    pub const fn raw(self) -> u32 {
        self.0
    }

    /// Returns the severity field for this NTSTATUS value.
    #[must_use]
    pub const fn severity(self) -> NtStatusSeverity {
        ntstatus_severity(self.0)
    }

    /// Returns `true` when the customer-defined bit is set.
    #[must_use]
    pub const fn is_customer_defined(self) -> bool {
        ntstatus_customer(self.0)
    }

    /// Returns the facility field for this NTSTATUS value.
    #[must_use]
    pub const fn facility(self) -> u32 {
        ntstatus_facility(self.0)
    }

    /// Returns the code field for this NTSTATUS value.
    #[must_use]
    pub const fn code(self) -> u32 {
        ntstatus_code(self.0)
    }

    /// Returns `true` when this value is `SMB2_STATUS_SUCCESS`.
    #[must_use]
    pub const fn is_success(self) -> bool {
        self.0 == SMB2_STATUS_SUCCESS
    }
}

impl From<u32> for NtStatus {
    fn from(value: u32) -> Self {
        Self::new(value)
    }
}

/// Returns the severity field for a raw NTSTATUS value.
#[must_use]
pub const fn ntstatus_severity(status: u32) -> NtStatusSeverity {
    match status & SMB2_STATUS_SEVERITY_MASK {
        SMB2_STATUS_SEVERITY_SUCCESS => NtStatusSeverity::Success,
        SMB2_STATUS_SEVERITY_INFO => NtStatusSeverity::Informational,
        SMB2_STATUS_SEVERITY_WARNING => NtStatusSeverity::Warning,
        SMB2_STATUS_SEVERITY_ERROR => NtStatusSeverity::Error,
        other => NtStatusSeverity::Unknown(other),
    }
}

/// Returns `true` when the customer-defined bit is set in a raw NTSTATUS value.
#[must_use]
pub const fn ntstatus_customer(status: u32) -> bool {
    (status & SMB2_STATUS_CUSTOMER_MASK) != 0
}

/// Returns the facility field from a raw NTSTATUS value.
#[must_use]
pub const fn ntstatus_facility(status: u32) -> u32 {
    status & SMB2_STATUS_FACILITY_MASK
}

/// Returns the code field from a raw NTSTATUS value.
#[must_use]
pub const fn ntstatus_code(status: u32) -> u32 {
    status & SMB2_STATUS_CODE_MASK
}

/// Named NTSTATUS entry for header-derived lookup skeletons.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NtStatusEntry {
    /// Numeric NTSTATUS value.
    pub status: NtStatus,
    /// Header constant name without interpretation.
    pub name: &'static str,
}

impl NtStatusEntry {
    /// Creates a status-name entry.
    #[must_use]
    pub const fn new(status: u32, name: &'static str) -> Self {
        Self {
            status: NtStatus::new(status),
            name,
        }
    }

    /// Returns `true` when this entry matches the supplied raw status value.
    #[must_use]
    pub const fn matches(self, status: u32) -> bool {
        self.status.raw() == status
    }
}

/// Header-derived NTSTATUS constants as name/value entries.
pub const SMB2_STATUS_TABLE: &[NtStatusEntry] = &[
    NtStatusEntry::new(SMB2_STATUS_SEVERITY_MASK, "SMB2_STATUS_SEVERITY_MASK"),
    NtStatusEntry::new(SMB2_STATUS_SEVERITY_SUCCESS, "SMB2_STATUS_SEVERITY_SUCCESS"),
    NtStatusEntry::new(SMB2_STATUS_SEVERITY_INFO, "SMB2_STATUS_SEVERITY_INFO"),
    NtStatusEntry::new(SMB2_STATUS_SEVERITY_WARNING, "SMB2_STATUS_SEVERITY_WARNING"),
    NtStatusEntry::new(SMB2_STATUS_SEVERITY_ERROR, "SMB2_STATUS_SEVERITY_ERROR"),
    NtStatusEntry::new(SMB2_STATUS_CUSTOMER_MASK, "SMB2_STATUS_CUSTOMER_MASK"),
    NtStatusEntry::new(SMB2_STATUS_FACILITY_MASK, "SMB2_STATUS_FACILITY_MASK"),
    NtStatusEntry::new(SMB2_STATUS_CODE_MASK, "SMB2_STATUS_CODE_MASK"),
    NtStatusEntry::new(SMB2_STATUS_SUCCESS, "SMB2_STATUS_SUCCESS"),
    NtStatusEntry::new(SMB2_STATUS_SHUTDOWN, "SMB2_STATUS_SHUTDOWN"),
    NtStatusEntry::new(SMB2_STATUS_PENDING, "SMB2_STATUS_PENDING"),
    NtStatusEntry::new(SMB2_STATUS_SMB_BAD_FID, "SMB2_STATUS_SMB_BAD_FID"),
    NtStatusEntry::new(SMB2_STATUS_NO_MORE_FILES, "SMB2_STATUS_NO_MORE_FILES"),
    NtStatusEntry::new(SMB2_STATUS_UNSUCCESSFUL, "SMB2_STATUS_UNSUCCESSFUL"),
    NtStatusEntry::new(SMB2_STATUS_NOT_IMPLEMENTED, "SMB2_STATUS_NOT_IMPLEMENTED"),
    NtStatusEntry::new(
        SMB2_STATUS_INVALID_INFO_CLASS,
        "SMB2_STATUS_INVALID_INFO_CLASS",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_INFO_LENGTH_MISMATCH,
        "SMB2_STATUS_INFO_LENGTH_MISMATCH",
    ),
    NtStatusEntry::new(SMB2_STATUS_ACCESS_VIOLATION, "SMB2_STATUS_ACCESS_VIOLATION"),
    NtStatusEntry::new(SMB2_STATUS_IN_PAGE_ERROR, "SMB2_STATUS_IN_PAGE_ERROR"),
    NtStatusEntry::new(SMB2_STATUS_PAGEFILE_QUOTA, "SMB2_STATUS_PAGEFILE_QUOTA"),
    NtStatusEntry::new(SMB2_STATUS_INVALID_HANDLE, "SMB2_STATUS_INVALID_HANDLE"),
    NtStatusEntry::new(
        SMB2_STATUS_BAD_INITIAL_STACK,
        "SMB2_STATUS_BAD_INITIAL_STACK",
    ),
    NtStatusEntry::new(SMB2_STATUS_BAD_INITIAL_PC, "SMB2_STATUS_BAD_INITIAL_PC"),
    NtStatusEntry::new(SMB2_STATUS_INVALID_CID, "SMB2_STATUS_INVALID_CID"),
    NtStatusEntry::new(
        SMB2_STATUS_TIMER_NOT_CANCELED,
        "SMB2_STATUS_TIMER_NOT_CANCELED",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_INVALID_PARAMETER,
        "SMB2_STATUS_INVALID_PARAMETER",
    ),
    NtStatusEntry::new(SMB2_STATUS_NO_SUCH_DEVICE, "SMB2_STATUS_NO_SUCH_DEVICE"),
    NtStatusEntry::new(SMB2_STATUS_NO_SUCH_FILE, "SMB2_STATUS_NO_SUCH_FILE"),
    NtStatusEntry::new(
        SMB2_STATUS_INVALID_DEVICE_REQUEST,
        "SMB2_STATUS_INVALID_DEVICE_REQUEST",
    ),
    NtStatusEntry::new(SMB2_STATUS_END_OF_FILE, "SMB2_STATUS_END_OF_FILE"),
    NtStatusEntry::new(SMB2_STATUS_WRONG_VOLUME, "SMB2_STATUS_WRONG_VOLUME"),
    NtStatusEntry::new(
        SMB2_STATUS_NO_MEDIA_IN_DEVICE,
        "SMB2_STATUS_NO_MEDIA_IN_DEVICE",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_UNRECOGNIZED_MEDIA,
        "SMB2_STATUS_UNRECOGNIZED_MEDIA",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_NONEXISTENT_SECTOR,
        "SMB2_STATUS_NONEXISTENT_SECTOR",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_MORE_PROCESSING_REQUIRED,
        "SMB2_STATUS_MORE_PROCESSING_REQUIRED",
    ),
    NtStatusEntry::new(SMB2_STATUS_NO_MEMORY, "SMB2_STATUS_NO_MEMORY"),
    NtStatusEntry::new(
        SMB2_STATUS_CONFLICTING_ADDRESSES,
        "SMB2_STATUS_CONFLICTING_ADDRESSES",
    ),
    NtStatusEntry::new(SMB2_STATUS_NOT_MAPPED_VIEW, "SMB2_STATUS_NOT_MAPPED_VIEW"),
    NtStatusEntry::new(
        SMB2_STATUS_UNABLE_TO_FREE_VM,
        "SMB2_STATUS_UNABLE_TO_FREE_VM",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_UNABLE_TO_DELETE_SECTION,
        "SMB2_STATUS_UNABLE_TO_DELETE_SECTION",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_INVALID_SYSTEM_SERVICE,
        "SMB2_STATUS_INVALID_SYSTEM_SERVICE",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_ILLEGAL_INSTRUCTION,
        "SMB2_STATUS_ILLEGAL_INSTRUCTION",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_INVALID_LOCK_SEQUENCE,
        "SMB2_STATUS_INVALID_LOCK_SEQUENCE",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_INVALID_VIEW_SIZE,
        "SMB2_STATUS_INVALID_VIEW_SIZE",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_INVALID_FILE_FOR_SECTION,
        "SMB2_STATUS_INVALID_FILE_FOR_SECTION",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_ALREADY_COMMITTED,
        "SMB2_STATUS_ALREADY_COMMITTED",
    ),
    NtStatusEntry::new(SMB2_STATUS_ACCESS_DENIED, "SMB2_STATUS_ACCESS_DENIED"),
    NtStatusEntry::new(SMB2_STATUS_BUFFER_TOO_SMALL, "SMB2_STATUS_BUFFER_TOO_SMALL"),
    NtStatusEntry::new(
        SMB2_STATUS_OBJECT_TYPE_MISMATCH,
        "SMB2_STATUS_OBJECT_TYPE_MISMATCH",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_NONCONTINUABLE_EXCEPTION,
        "SMB2_STATUS_NONCONTINUABLE_EXCEPTION",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_INVALID_DISPOSITION,
        "SMB2_STATUS_INVALID_DISPOSITION",
    ),
    NtStatusEntry::new(SMB2_STATUS_UNWIND, "SMB2_STATUS_UNWIND"),
    NtStatusEntry::new(SMB2_STATUS_BAD_STACK, "SMB2_STATUS_BAD_STACK"),
    NtStatusEntry::new(
        SMB2_STATUS_INVALID_UNWIND_TARGET,
        "SMB2_STATUS_INVALID_UNWIND_TARGET",
    ),
    NtStatusEntry::new(SMB2_STATUS_NOT_LOCKED, "SMB2_STATUS_NOT_LOCKED"),
    NtStatusEntry::new(SMB2_STATUS_PARITY_ERROR, "SMB2_STATUS_PARITY_ERROR"),
    NtStatusEntry::new(
        SMB2_STATUS_UNABLE_TO_DECOMMIT_VM,
        "SMB2_STATUS_UNABLE_TO_DECOMMIT_VM",
    ),
    NtStatusEntry::new(SMB2_STATUS_NOT_COMMITTED, "SMB2_STATUS_NOT_COMMITTED"),
    NtStatusEntry::new(
        SMB2_STATUS_INVALID_PORT_ATTRIBUTES,
        "SMB2_STATUS_INVALID_PORT_ATTRIBUTES",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_PORT_MESSAGE_TOO_LONG,
        "SMB2_STATUS_PORT_MESSAGE_TOO_LONG",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_INVALID_PARAMETER_MIX,
        "SMB2_STATUS_INVALID_PARAMETER_MIX",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_INVALID_QUOTA_LOWER,
        "SMB2_STATUS_INVALID_QUOTA_LOWER",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_DISK_CORRUPT_ERROR,
        "SMB2_STATUS_DISK_CORRUPT_ERROR",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_OBJECT_NAME_INVALID,
        "SMB2_STATUS_OBJECT_NAME_INVALID",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_OBJECT_NAME_NOT_FOUND,
        "SMB2_STATUS_OBJECT_NAME_NOT_FOUND",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_OBJECT_NAME_COLLISION,
        "SMB2_STATUS_OBJECT_NAME_COLLISION",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_HANDLE_NOT_WAITABLE,
        "SMB2_STATUS_HANDLE_NOT_WAITABLE",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_PORT_DISCONNECTED,
        "SMB2_STATUS_PORT_DISCONNECTED",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_DEVICE_ALREADY_ATTACHED,
        "SMB2_STATUS_DEVICE_ALREADY_ATTACHED",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_OBJECT_PATH_INVALID,
        "SMB2_STATUS_OBJECT_PATH_INVALID",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_OBJECT_PATH_NOT_FOUND,
        "SMB2_STATUS_OBJECT_PATH_NOT_FOUND",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_OBJECT_PATH_SYNTAX_BAD,
        "SMB2_STATUS_OBJECT_PATH_SYNTAX_BAD",
    ),
    NtStatusEntry::new(SMB2_STATUS_DATA_OVERRUN, "SMB2_STATUS_DATA_OVERRUN"),
    NtStatusEntry::new(SMB2_STATUS_DATA_LATE_ERROR, "SMB2_STATUS_DATA_LATE_ERROR"),
    NtStatusEntry::new(SMB2_STATUS_DATA_ERROR, "SMB2_STATUS_DATA_ERROR"),
    NtStatusEntry::new(SMB2_STATUS_CRC_ERROR, "SMB2_STATUS_CRC_ERROR"),
    NtStatusEntry::new(SMB2_STATUS_SECTION_TOO_BIG, "SMB2_STATUS_SECTION_TOO_BIG"),
    NtStatusEntry::new(
        SMB2_STATUS_PORT_CONNECTION_REFUSED,
        "SMB2_STATUS_PORT_CONNECTION_REFUSED",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_INVALID_PORT_HANDLE,
        "SMB2_STATUS_INVALID_PORT_HANDLE",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_SHARING_VIOLATION,
        "SMB2_STATUS_SHARING_VIOLATION",
    ),
    NtStatusEntry::new(SMB2_STATUS_QUOTA_EXCEEDED, "SMB2_STATUS_QUOTA_EXCEEDED"),
    NtStatusEntry::new(
        SMB2_STATUS_INVALID_PAGE_PROTECTION,
        "SMB2_STATUS_INVALID_PAGE_PROTECTION",
    ),
    NtStatusEntry::new(SMB2_STATUS_MUTANT_NOT_OWNED, "SMB2_STATUS_MUTANT_NOT_OWNED"),
    NtStatusEntry::new(
        SMB2_STATUS_SEMAPHORE_LIMIT_EXCEEDED,
        "SMB2_STATUS_SEMAPHORE_LIMIT_EXCEEDED",
    ),
    NtStatusEntry::new(SMB2_STATUS_PORT_ALREADY_SET, "SMB2_STATUS_PORT_ALREADY_SET"),
    NtStatusEntry::new(
        SMB2_STATUS_SECTION_NOT_IMAGE,
        "SMB2_STATUS_SECTION_NOT_IMAGE",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_SUSPEND_COUNT_EXCEEDED,
        "SMB2_STATUS_SUSPEND_COUNT_EXCEEDED",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_THREAD_IS_TERMINATING,
        "SMB2_STATUS_THREAD_IS_TERMINATING",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_BAD_WORKING_SET_LIMIT,
        "SMB2_STATUS_BAD_WORKING_SET_LIMIT",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_INCOMPATIBLE_FILE_MAP,
        "SMB2_STATUS_INCOMPATIBLE_FILE_MAP",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_SECTION_PROTECTION,
        "SMB2_STATUS_SECTION_PROTECTION",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_EAS_NOT_SUPPORTED,
        "SMB2_STATUS_EAS_NOT_SUPPORTED",
    ),
    NtStatusEntry::new(SMB2_STATUS_EA_TOO_LARGE, "SMB2_STATUS_EA_TOO_LARGE"),
    NtStatusEntry::new(
        SMB2_STATUS_NONEXISTENT_EA_ENTRY,
        "SMB2_STATUS_NONEXISTENT_EA_ENTRY",
    ),
    NtStatusEntry::new(SMB2_STATUS_NO_EAS_ON_FILE, "SMB2_STATUS_NO_EAS_ON_FILE"),
    NtStatusEntry::new(SMB2_STATUS_EA_CORRUPT_ERROR, "SMB2_STATUS_EA_CORRUPT_ERROR"),
    NtStatusEntry::new(
        SMB2_STATUS_FILE_LOCK_CONFLICT,
        "SMB2_STATUS_FILE_LOCK_CONFLICT",
    ),
    NtStatusEntry::new(SMB2_STATUS_LOCK_NOT_GRANTED, "SMB2_STATUS_LOCK_NOT_GRANTED"),
    NtStatusEntry::new(SMB2_STATUS_DELETE_PENDING, "SMB2_STATUS_DELETE_PENDING"),
    NtStatusEntry::new(
        SMB2_STATUS_CTL_FILE_NOT_SUPPORTED,
        "SMB2_STATUS_CTL_FILE_NOT_SUPPORTED",
    ),
    NtStatusEntry::new(SMB2_STATUS_UNKNOWN_REVISION, "SMB2_STATUS_UNKNOWN_REVISION"),
    NtStatusEntry::new(
        SMB2_STATUS_REVISION_MISMATCH,
        "SMB2_STATUS_REVISION_MISMATCH",
    ),
    NtStatusEntry::new(SMB2_STATUS_INVALID_OWNER, "SMB2_STATUS_INVALID_OWNER"),
    NtStatusEntry::new(
        SMB2_STATUS_INVALID_PRIMARY_GROUP,
        "SMB2_STATUS_INVALID_PRIMARY_GROUP",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_NO_IMPERSONATION_TOKEN,
        "SMB2_STATUS_NO_IMPERSONATION_TOKEN",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_CANT_DISABLE_MANDATORY,
        "SMB2_STATUS_CANT_DISABLE_MANDATORY",
    ),
    NtStatusEntry::new(SMB2_STATUS_NO_LOGON_SERVERS, "SMB2_STATUS_NO_LOGON_SERVERS"),
    NtStatusEntry::new(
        SMB2_STATUS_NO_SUCH_LOGON_SESSION,
        "SMB2_STATUS_NO_SUCH_LOGON_SESSION",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_NO_SUCH_PRIVILEGE,
        "SMB2_STATUS_NO_SUCH_PRIVILEGE",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_PRIVILEGE_NOT_HELD,
        "SMB2_STATUS_PRIVILEGE_NOT_HELD",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_INVALID_ACCOUNT_NAME,
        "SMB2_STATUS_INVALID_ACCOUNT_NAME",
    ),
    NtStatusEntry::new(SMB2_STATUS_USER_EXISTS, "SMB2_STATUS_USER_EXISTS"),
    NtStatusEntry::new(SMB2_STATUS_NO_SUCH_USER, "SMB2_STATUS_NO_SUCH_USER"),
    NtStatusEntry::new(SMB2_STATUS_GROUP_EXISTS, "SMB2_STATUS_GROUP_EXISTS"),
    NtStatusEntry::new(SMB2_STATUS_NO_SUCH_GROUP, "SMB2_STATUS_NO_SUCH_GROUP"),
    NtStatusEntry::new(SMB2_STATUS_MEMBER_IN_GROUP, "SMB2_STATUS_MEMBER_IN_GROUP"),
    NtStatusEntry::new(
        SMB2_STATUS_MEMBER_NOT_IN_GROUP,
        "SMB2_STATUS_MEMBER_NOT_IN_GROUP",
    ),
    NtStatusEntry::new(SMB2_STATUS_LAST_ADMIN, "SMB2_STATUS_LAST_ADMIN"),
    NtStatusEntry::new(SMB2_STATUS_WRONG_PASSWORD, "SMB2_STATUS_WRONG_PASSWORD"),
    NtStatusEntry::new(
        SMB2_STATUS_ILL_FORMED_PASSWORD,
        "SMB2_STATUS_ILL_FORMED_PASSWORD",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_PASSWORD_RESTRICTION,
        "SMB2_STATUS_PASSWORD_RESTRICTION",
    ),
    NtStatusEntry::new(SMB2_STATUS_LOGON_FAILURE, "SMB2_STATUS_LOGON_FAILURE"),
    NtStatusEntry::new(
        SMB2_STATUS_ACCOUNT_RESTRICTION,
        "SMB2_STATUS_ACCOUNT_RESTRICTION",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_INVALID_LOGON_HOURS,
        "SMB2_STATUS_INVALID_LOGON_HOURS",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_INVALID_WORKSTATION,
        "SMB2_STATUS_INVALID_WORKSTATION",
    ),
    NtStatusEntry::new(SMB2_STATUS_PASSWORD_EXPIRED, "SMB2_STATUS_PASSWORD_EXPIRED"),
    NtStatusEntry::new(SMB2_STATUS_ACCOUNT_DISABLED, "SMB2_STATUS_ACCOUNT_DISABLED"),
    NtStatusEntry::new(SMB2_STATUS_NONE_MAPPED, "SMB2_STATUS_NONE_MAPPED"),
    NtStatusEntry::new(
        SMB2_STATUS_TOO_MANY_LUIDS_REQUESTED,
        "SMB2_STATUS_TOO_MANY_LUIDS_REQUESTED",
    ),
    NtStatusEntry::new(SMB2_STATUS_LUIDS_EXHAUSTED, "SMB2_STATUS_LUIDS_EXHAUSTED"),
    NtStatusEntry::new(
        SMB2_STATUS_INVALID_SUB_AUTHORITY,
        "SMB2_STATUS_INVALID_SUB_AUTHORITY",
    ),
    NtStatusEntry::new(SMB2_STATUS_INVALID_ACL, "SMB2_STATUS_INVALID_ACL"),
    NtStatusEntry::new(SMB2_STATUS_INVALID_SID, "SMB2_STATUS_INVALID_SID"),
    NtStatusEntry::new(
        SMB2_STATUS_INVALID_SECURITY_DESCR,
        "SMB2_STATUS_INVALID_SECURITY_DESCR",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_PROCEDURE_NOT_FOUND,
        "SMB2_STATUS_PROCEDURE_NOT_FOUND",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_INVALID_IMAGE_FORMAT,
        "SMB2_STATUS_INVALID_IMAGE_FORMAT",
    ),
    NtStatusEntry::new(SMB2_STATUS_NO_TOKEN, "SMB2_STATUS_NO_TOKEN"),
    NtStatusEntry::new(
        SMB2_STATUS_BAD_INHERITANCE_ACL,
        "SMB2_STATUS_BAD_INHERITANCE_ACL",
    ),
    NtStatusEntry::new(SMB2_STATUS_RANGE_NOT_LOCKED, "SMB2_STATUS_RANGE_NOT_LOCKED"),
    NtStatusEntry::new(SMB2_STATUS_DISK_FULL, "SMB2_STATUS_DISK_FULL"),
    NtStatusEntry::new(SMB2_STATUS_SERVER_DISABLED, "SMB2_STATUS_SERVER_DISABLED"),
    NtStatusEntry::new(
        SMB2_STATUS_SERVER_NOT_DISABLED,
        "SMB2_STATUS_SERVER_NOT_DISABLED",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_TOO_MANY_GUIDS_REQUESTED,
        "SMB2_STATUS_TOO_MANY_GUIDS_REQUESTED",
    ),
    NtStatusEntry::new(SMB2_STATUS_GUIDS_EXHAUSTED, "SMB2_STATUS_GUIDS_EXHAUSTED"),
    NtStatusEntry::new(
        SMB2_STATUS_INVALID_ID_AUTHORITY,
        "SMB2_STATUS_INVALID_ID_AUTHORITY",
    ),
    NtStatusEntry::new(SMB2_STATUS_AGENTS_EXHAUSTED, "SMB2_STATUS_AGENTS_EXHAUSTED"),
    NtStatusEntry::new(
        SMB2_STATUS_INVALID_VOLUME_LABEL,
        "SMB2_STATUS_INVALID_VOLUME_LABEL",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_SECTION_NOT_EXTENDED,
        "SMB2_STATUS_SECTION_NOT_EXTENDED",
    ),
    NtStatusEntry::new(SMB2_STATUS_NOT_MAPPED_DATA, "SMB2_STATUS_NOT_MAPPED_DATA"),
    NtStatusEntry::new(
        SMB2_STATUS_RESOURCE_DATA_NOT_FOUND,
        "SMB2_STATUS_RESOURCE_DATA_NOT_FOUND",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_RESOURCE_TYPE_NOT_FOUND,
        "SMB2_STATUS_RESOURCE_TYPE_NOT_FOUND",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_RESOURCE_NAME_NOT_FOUND,
        "SMB2_STATUS_RESOURCE_NAME_NOT_FOUND",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_ARRAY_BOUNDS_EXCEEDED,
        "SMB2_STATUS_ARRAY_BOUNDS_EXCEEDED",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_FLOAT_DENORMAL_OPERAND,
        "SMB2_STATUS_FLOAT_DENORMAL_OPERAND",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_FLOAT_DIVIDE_BY_ZERO,
        "SMB2_STATUS_FLOAT_DIVIDE_BY_ZERO",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_FLOAT_INEXACT_RESULT,
        "SMB2_STATUS_FLOAT_INEXACT_RESULT",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_FLOAT_INVALID_OPERATION,
        "SMB2_STATUS_FLOAT_INVALID_OPERATION",
    ),
    NtStatusEntry::new(SMB2_STATUS_FLOAT_OVERFLOW, "SMB2_STATUS_FLOAT_OVERFLOW"),
    NtStatusEntry::new(
        SMB2_STATUS_FLOAT_STACK_CHECK,
        "SMB2_STATUS_FLOAT_STACK_CHECK",
    ),
    NtStatusEntry::new(SMB2_STATUS_FLOAT_UNDERFLOW, "SMB2_STATUS_FLOAT_UNDERFLOW"),
    NtStatusEntry::new(
        SMB2_STATUS_INTEGER_DIVIDE_BY_ZERO,
        "SMB2_STATUS_INTEGER_DIVIDE_BY_ZERO",
    ),
    NtStatusEntry::new(SMB2_STATUS_INTEGER_OVERFLOW, "SMB2_STATUS_INTEGER_OVERFLOW"),
    NtStatusEntry::new(
        SMB2_STATUS_PRIVILEGED_INSTRUCTION,
        "SMB2_STATUS_PRIVILEGED_INSTRUCTION",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_TOO_MANY_PAGING_FILES,
        "SMB2_STATUS_TOO_MANY_PAGING_FILES",
    ),
    NtStatusEntry::new(SMB2_STATUS_FILE_INVALID, "SMB2_STATUS_FILE_INVALID"),
    NtStatusEntry::new(
        SMB2_STATUS_ALLOTTED_SPACE_EXCEEDED,
        "SMB2_STATUS_ALLOTTED_SPACE_EXCEEDED",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_INSUFFICIENT_RESOURCES,
        "SMB2_STATUS_INSUFFICIENT_RESOURCES",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_DFS_EXIT_PATH_FOUND,
        "SMB2_STATUS_DFS_EXIT_PATH_FOUND",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_DEVICE_DATA_ERROR,
        "SMB2_STATUS_DEVICE_DATA_ERROR",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_DEVICE_NOT_CONNECTED,
        "SMB2_STATUS_DEVICE_NOT_CONNECTED",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_DEVICE_POWER_FAILURE,
        "SMB2_STATUS_DEVICE_POWER_FAILURE",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_FREE_VM_NOT_AT_BASE,
        "SMB2_STATUS_FREE_VM_NOT_AT_BASE",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_MEMORY_NOT_ALLOCATED,
        "SMB2_STATUS_MEMORY_NOT_ALLOCATED",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_WORKING_SET_QUOTA,
        "SMB2_STATUS_WORKING_SET_QUOTA",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_MEDIA_WRITE_PROTECTED,
        "SMB2_STATUS_MEDIA_WRITE_PROTECTED",
    ),
    NtStatusEntry::new(SMB2_STATUS_DEVICE_NOT_READY, "SMB2_STATUS_DEVICE_NOT_READY"),
    NtStatusEntry::new(
        SMB2_STATUS_INVALID_GROUP_ATTRIBUTES,
        "SMB2_STATUS_INVALID_GROUP_ATTRIBUTES",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_BAD_IMPERSONATION_LEVEL,
        "SMB2_STATUS_BAD_IMPERSONATION_LEVEL",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_CANT_OPEN_ANONYMOUS,
        "SMB2_STATUS_CANT_OPEN_ANONYMOUS",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_BAD_VALIDATION_CLASS,
        "SMB2_STATUS_BAD_VALIDATION_CLASS",
    ),
    NtStatusEntry::new(SMB2_STATUS_BAD_TOKEN_TYPE, "SMB2_STATUS_BAD_TOKEN_TYPE"),
    NtStatusEntry::new(
        SMB2_STATUS_BAD_MASTER_BOOT_RECORD,
        "SMB2_STATUS_BAD_MASTER_BOOT_RECORD",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_INSTRUCTION_MISALIGNMENT,
        "SMB2_STATUS_INSTRUCTION_MISALIGNMENT",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_INSTANCE_NOT_AVAILABLE,
        "SMB2_STATUS_INSTANCE_NOT_AVAILABLE",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_PIPE_NOT_AVAILABLE,
        "SMB2_STATUS_PIPE_NOT_AVAILABLE",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_INVALID_PIPE_STATE,
        "SMB2_STATUS_INVALID_PIPE_STATE",
    ),
    NtStatusEntry::new(SMB2_STATUS_PIPE_BUSY, "SMB2_STATUS_PIPE_BUSY"),
    NtStatusEntry::new(SMB2_STATUS_ILLEGAL_FUNCTION, "SMB2_STATUS_ILLEGAL_FUNCTION"),
    NtStatusEntry::new(
        SMB2_STATUS_PIPE_DISCONNECTED,
        "SMB2_STATUS_PIPE_DISCONNECTED",
    ),
    NtStatusEntry::new(SMB2_STATUS_PIPE_CLOSING, "SMB2_STATUS_PIPE_CLOSING"),
    NtStatusEntry::new(SMB2_STATUS_PIPE_CONNECTED, "SMB2_STATUS_PIPE_CONNECTED"),
    NtStatusEntry::new(SMB2_STATUS_PIPE_LISTENING, "SMB2_STATUS_PIPE_LISTENING"),
    NtStatusEntry::new(
        SMB2_STATUS_INVALID_READ_MODE,
        "SMB2_STATUS_INVALID_READ_MODE",
    ),
    NtStatusEntry::new(SMB2_STATUS_IO_TIMEOUT, "SMB2_STATUS_IO_TIMEOUT"),
    NtStatusEntry::new(
        SMB2_STATUS_FILE_FORCED_CLOSED,
        "SMB2_STATUS_FILE_FORCED_CLOSED",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_PROFILING_NOT_STARTED,
        "SMB2_STATUS_PROFILING_NOT_STARTED",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_PROFILING_NOT_STOPPED,
        "SMB2_STATUS_PROFILING_NOT_STOPPED",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_COULD_NOT_INTERPRET,
        "SMB2_STATUS_COULD_NOT_INTERPRET",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_FILE_IS_A_DIRECTORY,
        "SMB2_STATUS_FILE_IS_A_DIRECTORY",
    ),
    NtStatusEntry::new(SMB2_STATUS_NOT_SUPPORTED, "SMB2_STATUS_NOT_SUPPORTED"),
    NtStatusEntry::new(
        SMB2_STATUS_REMOTE_NOT_LISTENING,
        "SMB2_STATUS_REMOTE_NOT_LISTENING",
    ),
    NtStatusEntry::new(SMB2_STATUS_DUPLICATE_NAME, "SMB2_STATUS_DUPLICATE_NAME"),
    NtStatusEntry::new(SMB2_STATUS_BAD_NETWORK_PATH, "SMB2_STATUS_BAD_NETWORK_PATH"),
    NtStatusEntry::new(SMB2_STATUS_NETWORK_BUSY, "SMB2_STATUS_NETWORK_BUSY"),
    NtStatusEntry::new(
        SMB2_STATUS_DEVICE_DOES_NOT_EXIST,
        "SMB2_STATUS_DEVICE_DOES_NOT_EXIST",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_TOO_MANY_COMMANDS,
        "SMB2_STATUS_TOO_MANY_COMMANDS",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_ADAPTER_HARDWARE_ERROR,
        "SMB2_STATUS_ADAPTER_HARDWARE_ERROR",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_INVALID_NETWORK_RESPONSE,
        "SMB2_STATUS_INVALID_NETWORK_RESPONSE",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_UNEXPECTED_NETWORK_ERROR,
        "SMB2_STATUS_UNEXPECTED_NETWORK_ERROR",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_BAD_REMOTE_ADAPTER,
        "SMB2_STATUS_BAD_REMOTE_ADAPTER",
    ),
    NtStatusEntry::new(SMB2_STATUS_PRINT_QUEUE_FULL, "SMB2_STATUS_PRINT_QUEUE_FULL"),
    NtStatusEntry::new(SMB2_STATUS_NO_SPOOL_SPACE, "SMB2_STATUS_NO_SPOOL_SPACE"),
    NtStatusEntry::new(SMB2_STATUS_PRINT_CANCELLED, "SMB2_STATUS_PRINT_CANCELLED"),
    NtStatusEntry::new(
        SMB2_STATUS_NETWORK_NAME_DELETED,
        "SMB2_STATUS_NETWORK_NAME_DELETED",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_NETWORK_ACCESS_DENIED,
        "SMB2_STATUS_NETWORK_ACCESS_DENIED",
    ),
    NtStatusEntry::new(SMB2_STATUS_BAD_DEVICE_TYPE, "SMB2_STATUS_BAD_DEVICE_TYPE"),
    NtStatusEntry::new(SMB2_STATUS_BAD_NETWORK_NAME, "SMB2_STATUS_BAD_NETWORK_NAME"),
    NtStatusEntry::new(SMB2_STATUS_TOO_MANY_NAMES, "SMB2_STATUS_TOO_MANY_NAMES"),
    NtStatusEntry::new(
        SMB2_STATUS_TOO_MANY_SESSIONS,
        "SMB2_STATUS_TOO_MANY_SESSIONS",
    ),
    NtStatusEntry::new(SMB2_STATUS_SHARING_PAUSED, "SMB2_STATUS_SHARING_PAUSED"),
    NtStatusEntry::new(
        SMB2_STATUS_REQUEST_NOT_ACCEPTED,
        "SMB2_STATUS_REQUEST_NOT_ACCEPTED",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_REDIRECTOR_PAUSED,
        "SMB2_STATUS_REDIRECTOR_PAUSED",
    ),
    NtStatusEntry::new(SMB2_STATUS_NET_WRITE_FAULT, "SMB2_STATUS_NET_WRITE_FAULT"),
    NtStatusEntry::new(
        SMB2_STATUS_PROFILING_AT_LIMIT,
        "SMB2_STATUS_PROFILING_AT_LIMIT",
    ),
    NtStatusEntry::new(SMB2_STATUS_NOT_SAME_DEVICE, "SMB2_STATUS_NOT_SAME_DEVICE"),
    NtStatusEntry::new(SMB2_STATUS_FILE_RENAMED, "SMB2_STATUS_FILE_RENAMED"),
    NtStatusEntry::new(
        SMB2_STATUS_VIRTUAL_CIRCUIT_CLOSED,
        "SMB2_STATUS_VIRTUAL_CIRCUIT_CLOSED",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_NO_SECURITY_ON_OBJECT,
        "SMB2_STATUS_NO_SECURITY_ON_OBJECT",
    ),
    NtStatusEntry::new(SMB2_STATUS_CANT_WAIT, "SMB2_STATUS_CANT_WAIT"),
    NtStatusEntry::new(SMB2_STATUS_PIPE_EMPTY, "SMB2_STATUS_PIPE_EMPTY"),
    NtStatusEntry::new(
        SMB2_STATUS_CANT_ACCESS_DOMAIN_INFO,
        "SMB2_STATUS_CANT_ACCESS_DOMAIN_INFO",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_CANT_TERMINATE_SELF,
        "SMB2_STATUS_CANT_TERMINATE_SELF",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_INVALID_SERVER_STATE,
        "SMB2_STATUS_INVALID_SERVER_STATE",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_INVALID_DOMAIN_STATE,
        "SMB2_STATUS_INVALID_DOMAIN_STATE",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_INVALID_DOMAIN_ROLE,
        "SMB2_STATUS_INVALID_DOMAIN_ROLE",
    ),
    NtStatusEntry::new(SMB2_STATUS_NO_SUCH_DOMAIN, "SMB2_STATUS_NO_SUCH_DOMAIN"),
    NtStatusEntry::new(SMB2_STATUS_DOMAIN_EXISTS, "SMB2_STATUS_DOMAIN_EXISTS"),
    NtStatusEntry::new(
        SMB2_STATUS_DOMAIN_LIMIT_EXCEEDED,
        "SMB2_STATUS_DOMAIN_LIMIT_EXCEEDED",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_OPLOCK_NOT_GRANTED,
        "SMB2_STATUS_OPLOCK_NOT_GRANTED",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_INVALID_OPLOCK_PROTOCOL,
        "SMB2_STATUS_INVALID_OPLOCK_PROTOCOL",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_INTERNAL_DB_CORRUPTION,
        "SMB2_STATUS_INTERNAL_DB_CORRUPTION",
    ),
    NtStatusEntry::new(SMB2_STATUS_INTERNAL_ERROR, "SMB2_STATUS_INTERNAL_ERROR"),
    NtStatusEntry::new(
        SMB2_STATUS_GENERIC_NOT_MAPPED,
        "SMB2_STATUS_GENERIC_NOT_MAPPED",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_BAD_DESCRIPTOR_FORMAT,
        "SMB2_STATUS_BAD_DESCRIPTOR_FORMAT",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_INVALID_USER_BUFFER,
        "SMB2_STATUS_INVALID_USER_BUFFER",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_UNEXPECTED_IO_ERROR,
        "SMB2_STATUS_UNEXPECTED_IO_ERROR",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_UNEXPECTED_MM_CREATE_ERR,
        "SMB2_STATUS_UNEXPECTED_MM_CREATE_ERR",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_UNEXPECTED_MM_MAP_ERROR,
        "SMB2_STATUS_UNEXPECTED_MM_MAP_ERROR",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_UNEXPECTED_MM_EXTEND_ERR,
        "SMB2_STATUS_UNEXPECTED_MM_EXTEND_ERR",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_NOT_LOGON_PROCESS,
        "SMB2_STATUS_NOT_LOGON_PROCESS",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_LOGON_SESSION_EXISTS,
        "SMB2_STATUS_LOGON_SESSION_EXISTS",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_INVALID_PARAMETER_1,
        "SMB2_STATUS_INVALID_PARAMETER_1",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_INVALID_PARAMETER_2,
        "SMB2_STATUS_INVALID_PARAMETER_2",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_INVALID_PARAMETER_3,
        "SMB2_STATUS_INVALID_PARAMETER_3",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_INVALID_PARAMETER_4,
        "SMB2_STATUS_INVALID_PARAMETER_4",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_INVALID_PARAMETER_5,
        "SMB2_STATUS_INVALID_PARAMETER_5",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_INVALID_PARAMETER_6,
        "SMB2_STATUS_INVALID_PARAMETER_6",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_INVALID_PARAMETER_7,
        "SMB2_STATUS_INVALID_PARAMETER_7",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_INVALID_PARAMETER_8,
        "SMB2_STATUS_INVALID_PARAMETER_8",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_INVALID_PARAMETER_9,
        "SMB2_STATUS_INVALID_PARAMETER_9",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_INVALID_PARAMETER_10,
        "SMB2_STATUS_INVALID_PARAMETER_10",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_INVALID_PARAMETER_11,
        "SMB2_STATUS_INVALID_PARAMETER_11",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_INVALID_PARAMETER_12,
        "SMB2_STATUS_INVALID_PARAMETER_12",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_REDIRECTOR_NOT_STARTED,
        "SMB2_STATUS_REDIRECTOR_NOT_STARTED",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_REDIRECTOR_STARTED,
        "SMB2_STATUS_REDIRECTOR_STARTED",
    ),
    NtStatusEntry::new(SMB2_STATUS_STACK_OVERFLOW, "SMB2_STATUS_STACK_OVERFLOW"),
    NtStatusEntry::new(SMB2_STATUS_NO_SUCH_PACKAGE, "SMB2_STATUS_NO_SUCH_PACKAGE"),
    NtStatusEntry::new(
        SMB2_STATUS_BAD_FUNCTION_TABLE,
        "SMB2_STATUS_BAD_FUNCTION_TABLE",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_DIRECTORY_NOT_EMPTY,
        "SMB2_STATUS_DIRECTORY_NOT_EMPTY",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_FILE_CORRUPT_ERROR,
        "SMB2_STATUS_FILE_CORRUPT_ERROR",
    ),
    NtStatusEntry::new(SMB2_STATUS_NOT_A_DIRECTORY, "SMB2_STATUS_NOT_A_DIRECTORY"),
    NtStatusEntry::new(
        SMB2_STATUS_BAD_LOGON_SESSION_STATE,
        "SMB2_STATUS_BAD_LOGON_SESSION_STATE",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_LOGON_SESSION_COLLISION,
        "SMB2_STATUS_LOGON_SESSION_COLLISION",
    ),
    NtStatusEntry::new(SMB2_STATUS_NAME_TOO_LONG, "SMB2_STATUS_NAME_TOO_LONG"),
    NtStatusEntry::new(SMB2_STATUS_FILES_OPEN, "SMB2_STATUS_FILES_OPEN"),
    NtStatusEntry::new(
        SMB2_STATUS_CONNECTION_IN_USE,
        "SMB2_STATUS_CONNECTION_IN_USE",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_MESSAGE_NOT_FOUND,
        "SMB2_STATUS_MESSAGE_NOT_FOUND",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_PROCESS_IS_TERMINATING,
        "SMB2_STATUS_PROCESS_IS_TERMINATING",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_INVALID_LOGON_TYPE,
        "SMB2_STATUS_INVALID_LOGON_TYPE",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_NO_GUID_TRANSLATION,
        "SMB2_STATUS_NO_GUID_TRANSLATION",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_CANNOT_IMPERSONATE,
        "SMB2_STATUS_CANNOT_IMPERSONATE",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_IMAGE_ALREADY_LOADED,
        "SMB2_STATUS_IMAGE_ALREADY_LOADED",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_ABIOS_NOT_PRESENT,
        "SMB2_STATUS_ABIOS_NOT_PRESENT",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_ABIOS_LID_NOT_EXIST,
        "SMB2_STATUS_ABIOS_LID_NOT_EXIST",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_ABIOS_LID_ALREADY_OWNED,
        "SMB2_STATUS_ABIOS_LID_ALREADY_OWNED",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_ABIOS_NOT_LID_OWNER,
        "SMB2_STATUS_ABIOS_NOT_LID_OWNER",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_ABIOS_INVALID_COMMAND,
        "SMB2_STATUS_ABIOS_INVALID_COMMAND",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_ABIOS_INVALID_LID,
        "SMB2_STATUS_ABIOS_INVALID_LID",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_ABIOS_SELECTOR_NOT_AVAILABLE,
        "SMB2_STATUS_ABIOS_SELECTOR_NOT_AVAILABLE",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_ABIOS_INVALID_SELECTOR,
        "SMB2_STATUS_ABIOS_INVALID_SELECTOR",
    ),
    NtStatusEntry::new(SMB2_STATUS_NO_LDT, "SMB2_STATUS_NO_LDT"),
    NtStatusEntry::new(SMB2_STATUS_INVALID_LDT_SIZE, "SMB2_STATUS_INVALID_LDT_SIZE"),
    NtStatusEntry::new(
        SMB2_STATUS_INVALID_LDT_OFFSET,
        "SMB2_STATUS_INVALID_LDT_OFFSET",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_INVALID_LDT_DESCRIPTOR,
        "SMB2_STATUS_INVALID_LDT_DESCRIPTOR",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_INVALID_IMAGE_NE_FORMAT,
        "SMB2_STATUS_INVALID_IMAGE_NE_FORMAT",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_RXACT_INVALID_STATE,
        "SMB2_STATUS_RXACT_INVALID_STATE",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_RXACT_COMMIT_FAILURE,
        "SMB2_STATUS_RXACT_COMMIT_FAILURE",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_MAPPED_FILE_SIZE_ZERO,
        "SMB2_STATUS_MAPPED_FILE_SIZE_ZERO",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_TOO_MANY_OPENED_FILES,
        "SMB2_STATUS_TOO_MANY_OPENED_FILES",
    ),
    NtStatusEntry::new(SMB2_STATUS_CANCELLED, "SMB2_STATUS_CANCELLED"),
    NtStatusEntry::new(SMB2_STATUS_CANNOT_DELETE, "SMB2_STATUS_CANNOT_DELETE"),
    NtStatusEntry::new(
        SMB2_STATUS_INVALID_COMPUTER_NAME,
        "SMB2_STATUS_INVALID_COMPUTER_NAME",
    ),
    NtStatusEntry::new(SMB2_STATUS_FILE_DELETED, "SMB2_STATUS_FILE_DELETED"),
    NtStatusEntry::new(SMB2_STATUS_SPECIAL_ACCOUNT, "SMB2_STATUS_SPECIAL_ACCOUNT"),
    NtStatusEntry::new(SMB2_STATUS_SPECIAL_GROUP, "SMB2_STATUS_SPECIAL_GROUP"),
    NtStatusEntry::new(SMB2_STATUS_SPECIAL_USER, "SMB2_STATUS_SPECIAL_USER"),
    NtStatusEntry::new(
        SMB2_STATUS_MEMBERS_PRIMARY_GROUP,
        "SMB2_STATUS_MEMBERS_PRIMARY_GROUP",
    ),
    NtStatusEntry::new(SMB2_STATUS_FILE_CLOSED, "SMB2_STATUS_FILE_CLOSED"),
    NtStatusEntry::new(SMB2_STATUS_TOO_MANY_THREADS, "SMB2_STATUS_TOO_MANY_THREADS"),
    NtStatusEntry::new(
        SMB2_STATUS_THREAD_NOT_IN_PROCESS,
        "SMB2_STATUS_THREAD_NOT_IN_PROCESS",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_TOKEN_ALREADY_IN_USE,
        "SMB2_STATUS_TOKEN_ALREADY_IN_USE",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_PAGEFILE_QUOTA_EXCEEDED,
        "SMB2_STATUS_PAGEFILE_QUOTA_EXCEEDED",
    ),
    NtStatusEntry::new(SMB2_STATUS_COMMITMENT_LIMIT, "SMB2_STATUS_COMMITMENT_LIMIT"),
    NtStatusEntry::new(
        SMB2_STATUS_INVALID_IMAGE_LE_FORMAT,
        "SMB2_STATUS_INVALID_IMAGE_LE_FORMAT",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_INVALID_IMAGE_NOT_MZ,
        "SMB2_STATUS_INVALID_IMAGE_NOT_MZ",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_INVALID_IMAGE_PROTECT,
        "SMB2_STATUS_INVALID_IMAGE_PROTECT",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_INVALID_IMAGE_WIN_16,
        "SMB2_STATUS_INVALID_IMAGE_WIN_16",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_LOGON_SERVER_CONFLICT,
        "SMB2_STATUS_LOGON_SERVER_CONFLICT",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_TIME_DIFFERENCE_AT_DC,
        "SMB2_STATUS_TIME_DIFFERENCE_AT_DC",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_SYNCHRONIZATION_REQUIRED,
        "SMB2_STATUS_SYNCHRONIZATION_REQUIRED",
    ),
    NtStatusEntry::new(SMB2_STATUS_DLL_NOT_FOUND, "SMB2_STATUS_DLL_NOT_FOUND"),
    NtStatusEntry::new(SMB2_STATUS_OPEN_FAILED, "SMB2_STATUS_OPEN_FAILED"),
    NtStatusEntry::new(
        SMB2_STATUS_IO_PRIVILEGE_FAILED,
        "SMB2_STATUS_IO_PRIVILEGE_FAILED",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_ORDINAL_NOT_FOUND,
        "SMB2_STATUS_ORDINAL_NOT_FOUND",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_ENTRYPOINT_NOT_FOUND,
        "SMB2_STATUS_ENTRYPOINT_NOT_FOUND",
    ),
    NtStatusEntry::new(SMB2_STATUS_CONTROL_C_EXIT, "SMB2_STATUS_CONTROL_C_EXIT"),
    NtStatusEntry::new(SMB2_STATUS_LOCAL_DISCONNECT, "SMB2_STATUS_LOCAL_DISCONNECT"),
    NtStatusEntry::new(
        SMB2_STATUS_REMOTE_DISCONNECT,
        "SMB2_STATUS_REMOTE_DISCONNECT",
    ),
    NtStatusEntry::new(SMB2_STATUS_REMOTE_RESOURCES, "SMB2_STATUS_REMOTE_RESOURCES"),
    NtStatusEntry::new(SMB2_STATUS_LINK_FAILED, "SMB2_STATUS_LINK_FAILED"),
    NtStatusEntry::new(SMB2_STATUS_LINK_TIMEOUT, "SMB2_STATUS_LINK_TIMEOUT"),
    NtStatusEntry::new(
        SMB2_STATUS_INVALID_CONNECTION,
        "SMB2_STATUS_INVALID_CONNECTION",
    ),
    NtStatusEntry::new(SMB2_STATUS_INVALID_ADDRESS, "SMB2_STATUS_INVALID_ADDRESS"),
    NtStatusEntry::new(SMB2_STATUS_DLL_INIT_FAILED, "SMB2_STATUS_DLL_INIT_FAILED"),
    NtStatusEntry::new(
        SMB2_STATUS_MISSING_SYSTEMFILE,
        "SMB2_STATUS_MISSING_SYSTEMFILE",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_UNHANDLED_EXCEPTION,
        "SMB2_STATUS_UNHANDLED_EXCEPTION",
    ),
    NtStatusEntry::new(SMB2_STATUS_APP_INIT_FAILURE, "SMB2_STATUS_APP_INIT_FAILURE"),
    NtStatusEntry::new(
        SMB2_STATUS_PAGEFILE_CREATE_FAILED,
        "SMB2_STATUS_PAGEFILE_CREATE_FAILED",
    ),
    NtStatusEntry::new(SMB2_STATUS_NO_PAGEFILE, "SMB2_STATUS_NO_PAGEFILE"),
    NtStatusEntry::new(SMB2_STATUS_INVALID_LEVEL, "SMB2_STATUS_INVALID_LEVEL"),
    NtStatusEntry::new(
        SMB2_STATUS_WRONG_PASSWORD_CORE,
        "SMB2_STATUS_WRONG_PASSWORD_CORE",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_ILLEGAL_FLOAT_CONTEXT,
        "SMB2_STATUS_ILLEGAL_FLOAT_CONTEXT",
    ),
    NtStatusEntry::new(SMB2_STATUS_PIPE_BROKEN, "SMB2_STATUS_PIPE_BROKEN"),
    NtStatusEntry::new(SMB2_STATUS_REGISTRY_CORRUPT, "SMB2_STATUS_REGISTRY_CORRUPT"),
    NtStatusEntry::new(
        SMB2_STATUS_REGISTRY_IO_FAILED,
        "SMB2_STATUS_REGISTRY_IO_FAILED",
    ),
    NtStatusEntry::new(SMB2_STATUS_NO_EVENT_PAIR, "SMB2_STATUS_NO_EVENT_PAIR"),
    NtStatusEntry::new(
        SMB2_STATUS_UNRECOGNIZED_VOLUME,
        "SMB2_STATUS_UNRECOGNIZED_VOLUME",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_SERIAL_NO_DEVICE_INITED,
        "SMB2_STATUS_SERIAL_NO_DEVICE_INITED",
    ),
    NtStatusEntry::new(SMB2_STATUS_NO_SUCH_ALIAS, "SMB2_STATUS_NO_SUCH_ALIAS"),
    NtStatusEntry::new(
        SMB2_STATUS_MEMBER_NOT_IN_ALIAS,
        "SMB2_STATUS_MEMBER_NOT_IN_ALIAS",
    ),
    NtStatusEntry::new(SMB2_STATUS_MEMBER_IN_ALIAS, "SMB2_STATUS_MEMBER_IN_ALIAS"),
    NtStatusEntry::new(SMB2_STATUS_ALIAS_EXISTS, "SMB2_STATUS_ALIAS_EXISTS"),
    NtStatusEntry::new(
        SMB2_STATUS_LOGON_NOT_GRANTED,
        "SMB2_STATUS_LOGON_NOT_GRANTED",
    ),
    NtStatusEntry::new(SMB2_STATUS_TOO_MANY_SECRETS, "SMB2_STATUS_TOO_MANY_SECRETS"),
    NtStatusEntry::new(SMB2_STATUS_SECRET_TOO_LONG, "SMB2_STATUS_SECRET_TOO_LONG"),
    NtStatusEntry::new(
        SMB2_STATUS_INTERNAL_DB_ERROR,
        "SMB2_STATUS_INTERNAL_DB_ERROR",
    ),
    NtStatusEntry::new(SMB2_STATUS_FULLSCREEN_MODE, "SMB2_STATUS_FULLSCREEN_MODE"),
    NtStatusEntry::new(
        SMB2_STATUS_TOO_MANY_CONTEXT_IDS,
        "SMB2_STATUS_TOO_MANY_CONTEXT_IDS",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_LOGON_TYPE_NOT_GRANTED,
        "SMB2_STATUS_LOGON_TYPE_NOT_GRANTED",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_NOT_REGISTRY_FILE,
        "SMB2_STATUS_NOT_REGISTRY_FILE",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_NT_CROSS_ENCRYPTION_REQUIRED,
        "SMB2_STATUS_NT_CROSS_ENCRYPTION_REQUIRED",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_DOMAIN_CTRLR_CONFIG_ERROR,
        "SMB2_STATUS_DOMAIN_CTRLR_CONFIG_ERROR",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_FT_MISSING_MEMBER,
        "SMB2_STATUS_FT_MISSING_MEMBER",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_ILL_FORMED_SERVICE_ENTRY,
        "SMB2_STATUS_ILL_FORMED_SERVICE_ENTRY",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_ILLEGAL_CHARACTER,
        "SMB2_STATUS_ILLEGAL_CHARACTER",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_UNMAPPABLE_CHARACTER,
        "SMB2_STATUS_UNMAPPABLE_CHARACTER",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_UNDEFINED_CHARACTER,
        "SMB2_STATUS_UNDEFINED_CHARACTER",
    ),
    NtStatusEntry::new(SMB2_STATUS_FLOPPY_VOLUME, "SMB2_STATUS_FLOPPY_VOLUME"),
    NtStatusEntry::new(
        SMB2_STATUS_FLOPPY_ID_MARK_NOT_FOUND,
        "SMB2_STATUS_FLOPPY_ID_MARK_NOT_FOUND",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_FLOPPY_WRONG_CYLINDER,
        "SMB2_STATUS_FLOPPY_WRONG_CYLINDER",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_FLOPPY_UNKNOWN_ERROR,
        "SMB2_STATUS_FLOPPY_UNKNOWN_ERROR",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_FLOPPY_BAD_REGISTERS,
        "SMB2_STATUS_FLOPPY_BAD_REGISTERS",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_DISK_RECALIBRATE_FAILED,
        "SMB2_STATUS_DISK_RECALIBRATE_FAILED",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_DISK_OPERATION_FAILED,
        "SMB2_STATUS_DISK_OPERATION_FAILED",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_DISK_RESET_FAILED,
        "SMB2_STATUS_DISK_RESET_FAILED",
    ),
    NtStatusEntry::new(SMB2_STATUS_SHARED_IRQ_BUSY, "SMB2_STATUS_SHARED_IRQ_BUSY"),
    NtStatusEntry::new(SMB2_STATUS_FT_ORPHANING, "SMB2_STATUS_FT_ORPHANING"),
    NtStatusEntry::new(
        SMB2_STATUS_PARTITION_FAILURE,
        "SMB2_STATUS_PARTITION_FAILURE",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_INVALID_BLOCK_LENGTH,
        "SMB2_STATUS_INVALID_BLOCK_LENGTH",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_DEVICE_NOT_PARTITIONED,
        "SMB2_STATUS_DEVICE_NOT_PARTITIONED",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_UNABLE_TO_LOCK_MEDIA,
        "SMB2_STATUS_UNABLE_TO_LOCK_MEDIA",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_UNABLE_TO_UNLOAD_MEDIA,
        "SMB2_STATUS_UNABLE_TO_UNLOAD_MEDIA",
    ),
    NtStatusEntry::new(SMB2_STATUS_EOM_OVERFLOW, "SMB2_STATUS_EOM_OVERFLOW"),
    NtStatusEntry::new(SMB2_STATUS_NO_MEDIA, "SMB2_STATUS_NO_MEDIA"),
    NtStatusEntry::new(SMB2_STATUS_NO_SUCH_MEMBER, "SMB2_STATUS_NO_SUCH_MEMBER"),
    NtStatusEntry::new(SMB2_STATUS_INVALID_MEMBER, "SMB2_STATUS_INVALID_MEMBER"),
    NtStatusEntry::new(SMB2_STATUS_KEY_DELETED, "SMB2_STATUS_KEY_DELETED"),
    NtStatusEntry::new(SMB2_STATUS_NO_LOG_SPACE, "SMB2_STATUS_NO_LOG_SPACE"),
    NtStatusEntry::new(SMB2_STATUS_TOO_MANY_SIDS, "SMB2_STATUS_TOO_MANY_SIDS"),
    NtStatusEntry::new(
        SMB2_STATUS_LM_CROSS_ENCRYPTION_REQUIRED,
        "SMB2_STATUS_LM_CROSS_ENCRYPTION_REQUIRED",
    ),
    NtStatusEntry::new(SMB2_STATUS_KEY_HAS_CHILDREN, "SMB2_STATUS_KEY_HAS_CHILDREN"),
    NtStatusEntry::new(
        SMB2_STATUS_CHILD_MUST_BE_VOLATILE,
        "SMB2_STATUS_CHILD_MUST_BE_VOLATILE",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_DEVICE_CONFIGURATION_ERROR,
        "SMB2_STATUS_DEVICE_CONFIGURATION_ERROR",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_DRIVER_INTERNAL_ERROR,
        "SMB2_STATUS_DRIVER_INTERNAL_ERROR",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_INVALID_DEVICE_STATE,
        "SMB2_STATUS_INVALID_DEVICE_STATE",
    ),
    NtStatusEntry::new(SMB2_STATUS_IO_DEVICE_ERROR, "SMB2_STATUS_IO_DEVICE_ERROR"),
    NtStatusEntry::new(
        SMB2_STATUS_DEVICE_PROTOCOL_ERROR,
        "SMB2_STATUS_DEVICE_PROTOCOL_ERROR",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_BACKUP_CONTROLLER,
        "SMB2_STATUS_BACKUP_CONTROLLER",
    ),
    NtStatusEntry::new(SMB2_STATUS_LOG_FILE_FULL, "SMB2_STATUS_LOG_FILE_FULL"),
    NtStatusEntry::new(SMB2_STATUS_TOO_LATE, "SMB2_STATUS_TOO_LATE"),
    NtStatusEntry::new(
        SMB2_STATUS_NO_TRUST_LSA_SECRET,
        "SMB2_STATUS_NO_TRUST_LSA_SECRET",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_NO_TRUST_SAM_ACCOUNT,
        "SMB2_STATUS_NO_TRUST_SAM_ACCOUNT",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_TRUSTED_DOMAIN_FAILURE,
        "SMB2_STATUS_TRUSTED_DOMAIN_FAILURE",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_TRUSTED_RELATIONSHIP_FAILURE,
        "SMB2_STATUS_TRUSTED_RELATIONSHIP_FAILURE",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_EVENTLOG_FILE_CORRUPT,
        "SMB2_STATUS_EVENTLOG_FILE_CORRUPT",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_EVENTLOG_CANT_START,
        "SMB2_STATUS_EVENTLOG_CANT_START",
    ),
    NtStatusEntry::new(SMB2_STATUS_TRUST_FAILURE, "SMB2_STATUS_TRUST_FAILURE"),
    NtStatusEntry::new(
        SMB2_STATUS_MUTANT_LIMIT_EXCEEDED,
        "SMB2_STATUS_MUTANT_LIMIT_EXCEEDED",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_NETLOGON_NOT_STARTED,
        "SMB2_STATUS_NETLOGON_NOT_STARTED",
    ),
    NtStatusEntry::new(SMB2_STATUS_ACCOUNT_EXPIRED, "SMB2_STATUS_ACCOUNT_EXPIRED"),
    NtStatusEntry::new(
        SMB2_STATUS_POSSIBLE_DEADLOCK,
        "SMB2_STATUS_POSSIBLE_DEADLOCK",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_NETWORK_CREDENTIAL_CONFLICT,
        "SMB2_STATUS_NETWORK_CREDENTIAL_CONFLICT",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_REMOTE_SESSION_LIMIT,
        "SMB2_STATUS_REMOTE_SESSION_LIMIT",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_EVENTLOG_FILE_CHANGED,
        "SMB2_STATUS_EVENTLOG_FILE_CHANGED",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_NOLOGON_INTERDOMAIN_TRUST_ACCOUNT,
        "SMB2_STATUS_NOLOGON_INTERDOMAIN_TRUST_ACCOUNT",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_NOLOGON_WORKSTATION_TRUST_ACCOUNT,
        "SMB2_STATUS_NOLOGON_WORKSTATION_TRUST_ACCOUNT",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_NOLOGON_SERVER_TRUST_ACCOUNT,
        "SMB2_STATUS_NOLOGON_SERVER_TRUST_ACCOUNT",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_DOMAIN_TRUST_INCONSISTENT,
        "SMB2_STATUS_DOMAIN_TRUST_INCONSISTENT",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_FS_DRIVER_REQUIRED,
        "SMB2_STATUS_FS_DRIVER_REQUIRED",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_NO_USER_SESSION_KEY,
        "SMB2_STATUS_NO_USER_SESSION_KEY",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_USER_SESSION_DELETED,
        "SMB2_STATUS_USER_SESSION_DELETED",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_RESOURCE_LANG_NOT_FOUND,
        "SMB2_STATUS_RESOURCE_LANG_NOT_FOUND",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_INSUFF_SERVER_RESOURCES,
        "SMB2_STATUS_INSUFF_SERVER_RESOURCES",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_INVALID_BUFFER_SIZE,
        "SMB2_STATUS_INVALID_BUFFER_SIZE",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_INVALID_ADDRESS_COMPONENT,
        "SMB2_STATUS_INVALID_ADDRESS_COMPONENT",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_INVALID_ADDRESS_WILDCARD,
        "SMB2_STATUS_INVALID_ADDRESS_WILDCARD",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_TOO_MANY_ADDRESSES,
        "SMB2_STATUS_TOO_MANY_ADDRESSES",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_ADDRESS_ALREADY_EXISTS,
        "SMB2_STATUS_ADDRESS_ALREADY_EXISTS",
    ),
    NtStatusEntry::new(SMB2_STATUS_ADDRESS_CLOSED, "SMB2_STATUS_ADDRESS_CLOSED"),
    NtStatusEntry::new(
        SMB2_STATUS_CONNECTION_DISCONNECTED,
        "SMB2_STATUS_CONNECTION_DISCONNECTED",
    ),
    NtStatusEntry::new(SMB2_STATUS_CONNECTION_RESET, "SMB2_STATUS_CONNECTION_RESET"),
    NtStatusEntry::new(SMB2_STATUS_TOO_MANY_NODES, "SMB2_STATUS_TOO_MANY_NODES"),
    NtStatusEntry::new(
        SMB2_STATUS_TRANSACTION_ABORTED,
        "SMB2_STATUS_TRANSACTION_ABORTED",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_TRANSACTION_TIMED_OUT,
        "SMB2_STATUS_TRANSACTION_TIMED_OUT",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_TRANSACTION_NO_RELEASE,
        "SMB2_STATUS_TRANSACTION_NO_RELEASE",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_TRANSACTION_NO_MATCH,
        "SMB2_STATUS_TRANSACTION_NO_MATCH",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_TRANSACTION_RESPONDED,
        "SMB2_STATUS_TRANSACTION_RESPONDED",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_TRANSACTION_INVALID_ID,
        "SMB2_STATUS_TRANSACTION_INVALID_ID",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_TRANSACTION_INVALID_TYPE,
        "SMB2_STATUS_TRANSACTION_INVALID_TYPE",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_NOT_SERVER_SESSION,
        "SMB2_STATUS_NOT_SERVER_SESSION",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_NOT_CLIENT_SESSION,
        "SMB2_STATUS_NOT_CLIENT_SESSION",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_CANNOT_LOAD_REGISTRY_FILE,
        "SMB2_STATUS_CANNOT_LOAD_REGISTRY_FILE",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_DEBUG_ATTACH_FAILED,
        "SMB2_STATUS_DEBUG_ATTACH_FAILED",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_SYSTEM_PROCESS_TERMINATED,
        "SMB2_STATUS_SYSTEM_PROCESS_TERMINATED",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_DATA_NOT_ACCEPTED,
        "SMB2_STATUS_DATA_NOT_ACCEPTED",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_NO_BROWSER_SERVERS_FOUND,
        "SMB2_STATUS_NO_BROWSER_SERVERS_FOUND",
    ),
    NtStatusEntry::new(SMB2_STATUS_VDM_HARD_ERROR, "SMB2_STATUS_VDM_HARD_ERROR"),
    NtStatusEntry::new(
        SMB2_STATUS_DRIVER_CANCEL_TIMEOUT,
        "SMB2_STATUS_DRIVER_CANCEL_TIMEOUT",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_REPLY_MESSAGE_MISMATCH,
        "SMB2_STATUS_REPLY_MESSAGE_MISMATCH",
    ),
    NtStatusEntry::new(SMB2_STATUS_MAPPED_ALIGNMENT, "SMB2_STATUS_MAPPED_ALIGNMENT"),
    NtStatusEntry::new(
        SMB2_STATUS_IMAGE_CHECKSUM_MISMATCH,
        "SMB2_STATUS_IMAGE_CHECKSUM_MISMATCH",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_LOST_WRITEBEHIND_DATA,
        "SMB2_STATUS_LOST_WRITEBEHIND_DATA",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_CLIENT_SERVER_PARAMETERS_INVALID,
        "SMB2_STATUS_CLIENT_SERVER_PARAMETERS_INVALID",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_PASSWORD_MUST_CHANGE,
        "SMB2_STATUS_PASSWORD_MUST_CHANGE",
    ),
    NtStatusEntry::new(SMB2_STATUS_NOT_FOUND, "SMB2_STATUS_NOT_FOUND"),
    NtStatusEntry::new(SMB2_STATUS_NOT_TINY_STREAM, "SMB2_STATUS_NOT_TINY_STREAM"),
    NtStatusEntry::new(SMB2_STATUS_RECOVERY_FAILURE, "SMB2_STATUS_RECOVERY_FAILURE"),
    NtStatusEntry::new(
        SMB2_STATUS_STACK_OVERFLOW_READ,
        "SMB2_STATUS_STACK_OVERFLOW_READ",
    ),
    NtStatusEntry::new(SMB2_STATUS_FAIL_CHECK, "SMB2_STATUS_FAIL_CHECK"),
    NtStatusEntry::new(
        SMB2_STATUS_DUPLICATE_OBJECTID,
        "SMB2_STATUS_DUPLICATE_OBJECTID",
    ),
    NtStatusEntry::new(SMB2_STATUS_OBJECTID_EXISTS, "SMB2_STATUS_OBJECTID_EXISTS"),
    NtStatusEntry::new(SMB2_STATUS_CONVERT_TO_LARGE, "SMB2_STATUS_CONVERT_TO_LARGE"),
    NtStatusEntry::new(SMB2_STATUS_RETRY, "SMB2_STATUS_RETRY"),
    NtStatusEntry::new(
        SMB2_STATUS_FOUND_OUT_OF_SCOPE,
        "SMB2_STATUS_FOUND_OUT_OF_SCOPE",
    ),
    NtStatusEntry::new(SMB2_STATUS_ALLOCATE_BUCKET, "SMB2_STATUS_ALLOCATE_BUCKET"),
    NtStatusEntry::new(
        SMB2_STATUS_PROPSET_NOT_FOUND,
        "SMB2_STATUS_PROPSET_NOT_FOUND",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_MARSHALL_OVERFLOW,
        "SMB2_STATUS_MARSHALL_OVERFLOW",
    ),
    NtStatusEntry::new(SMB2_STATUS_INVALID_VARIANT, "SMB2_STATUS_INVALID_VARIANT"),
    NtStatusEntry::new(
        SMB2_STATUS_DOMAIN_CONTROLLER_NOT_FOUND,
        "SMB2_STATUS_DOMAIN_CONTROLLER_NOT_FOUND",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_ACCOUNT_LOCKED_OUT,
        "SMB2_STATUS_ACCOUNT_LOCKED_OUT",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_HANDLE_NOT_CLOSABLE,
        "SMB2_STATUS_HANDLE_NOT_CLOSABLE",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_CONNECTION_REFUSED,
        "SMB2_STATUS_CONNECTION_REFUSED",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_GRACEFUL_DISCONNECT,
        "SMB2_STATUS_GRACEFUL_DISCONNECT",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_ADDRESS_ALREADY_ASSOCIATED,
        "SMB2_STATUS_ADDRESS_ALREADY_ASSOCIATED",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_ADDRESS_NOT_ASSOCIATED,
        "SMB2_STATUS_ADDRESS_NOT_ASSOCIATED",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_CONNECTION_INVALID,
        "SMB2_STATUS_CONNECTION_INVALID",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_CONNECTION_ACTIVE,
        "SMB2_STATUS_CONNECTION_ACTIVE",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_NETWORK_UNREACHABLE,
        "SMB2_STATUS_NETWORK_UNREACHABLE",
    ),
    NtStatusEntry::new(SMB2_STATUS_HOST_UNREACHABLE, "SMB2_STATUS_HOST_UNREACHABLE"),
    NtStatusEntry::new(
        SMB2_STATUS_PROTOCOL_UNREACHABLE,
        "SMB2_STATUS_PROTOCOL_UNREACHABLE",
    ),
    NtStatusEntry::new(SMB2_STATUS_PORT_UNREACHABLE, "SMB2_STATUS_PORT_UNREACHABLE"),
    NtStatusEntry::new(SMB2_STATUS_REQUEST_ABORTED, "SMB2_STATUS_REQUEST_ABORTED"),
    NtStatusEntry::new(
        SMB2_STATUS_CONNECTION_ABORTED,
        "SMB2_STATUS_CONNECTION_ABORTED",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_BAD_COMPRESSION_BUFFER,
        "SMB2_STATUS_BAD_COMPRESSION_BUFFER",
    ),
    NtStatusEntry::new(SMB2_STATUS_USER_MAPPED_FILE, "SMB2_STATUS_USER_MAPPED_FILE"),
    NtStatusEntry::new(SMB2_STATUS_AUDIT_FAILED, "SMB2_STATUS_AUDIT_FAILED"),
    NtStatusEntry::new(
        SMB2_STATUS_TIMER_RESOLUTION_NOT_SET,
        "SMB2_STATUS_TIMER_RESOLUTION_NOT_SET",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_CONNECTION_COUNT_LIMIT,
        "SMB2_STATUS_CONNECTION_COUNT_LIMIT",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_LOGIN_TIME_RESTRICTION,
        "SMB2_STATUS_LOGIN_TIME_RESTRICTION",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_LOGIN_WKSTA_RESTRICTION,
        "SMB2_STATUS_LOGIN_WKSTA_RESTRICTION",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_IMAGE_MP_UP_MISMATCH,
        "SMB2_STATUS_IMAGE_MP_UP_MISMATCH",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_INSUFFICIENT_LOGON_INFO,
        "SMB2_STATUS_INSUFFICIENT_LOGON_INFO",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_BAD_DLL_ENTRYPOINT,
        "SMB2_STATUS_BAD_DLL_ENTRYPOINT",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_BAD_SERVICE_ENTRYPOINT,
        "SMB2_STATUS_BAD_SERVICE_ENTRYPOINT",
    ),
    NtStatusEntry::new(SMB2_STATUS_LPC_REPLY_LOST, "SMB2_STATUS_LPC_REPLY_LOST"),
    NtStatusEntry::new(
        SMB2_STATUS_IP_ADDRESS_CONFLICT1,
        "SMB2_STATUS_IP_ADDRESS_CONFLICT1",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_IP_ADDRESS_CONFLICT2,
        "SMB2_STATUS_IP_ADDRESS_CONFLICT2",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_REGISTRY_QUOTA_LIMIT,
        "SMB2_STATUS_REGISTRY_QUOTA_LIMIT",
    ),
    NtStatusEntry::new(SMB2_STATUS_PATH_NOT_COVERED, "SMB2_STATUS_PATH_NOT_COVERED"),
    NtStatusEntry::new(
        SMB2_STATUS_NO_CALLBACK_ACTIVE,
        "SMB2_STATUS_NO_CALLBACK_ACTIVE",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_LICENSE_QUOTA_EXCEEDED,
        "SMB2_STATUS_LICENSE_QUOTA_EXCEEDED",
    ),
    NtStatusEntry::new(SMB2_STATUS_PWD_TOO_SHORT, "SMB2_STATUS_PWD_TOO_SHORT"),
    NtStatusEntry::new(SMB2_STATUS_PWD_TOO_RECENT, "SMB2_STATUS_PWD_TOO_RECENT"),
    NtStatusEntry::new(
        SMB2_STATUS_PWD_HISTORY_CONFLICT,
        "SMB2_STATUS_PWD_HISTORY_CONFLICT",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_PLUGPLAY_NO_DEVICE,
        "SMB2_STATUS_PLUGPLAY_NO_DEVICE",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_UNSUPPORTED_COMPRESSION,
        "SMB2_STATUS_UNSUPPORTED_COMPRESSION",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_INVALID_HW_PROFILE,
        "SMB2_STATUS_INVALID_HW_PROFILE",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_INVALID_PLUGPLAY_DEVICE_PATH,
        "SMB2_STATUS_INVALID_PLUGPLAY_DEVICE_PATH",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_DRIVER_ORDINAL_NOT_FOUND,
        "SMB2_STATUS_DRIVER_ORDINAL_NOT_FOUND",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_DRIVER_ENTRYPOINT_NOT_FOUND,
        "SMB2_STATUS_DRIVER_ENTRYPOINT_NOT_FOUND",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_RESOURCE_NOT_OWNED,
        "SMB2_STATUS_RESOURCE_NOT_OWNED",
    ),
    NtStatusEntry::new(SMB2_STATUS_TOO_MANY_LINKS, "SMB2_STATUS_TOO_MANY_LINKS"),
    NtStatusEntry::new(
        SMB2_STATUS_QUOTA_LIST_INCONSISTENT,
        "SMB2_STATUS_QUOTA_LIST_INCONSISTENT",
    ),
    NtStatusEntry::new(SMB2_STATUS_FILE_IS_OFFLINE, "SMB2_STATUS_FILE_IS_OFFLINE"),
    NtStatusEntry::new(
        SMB2_STATUS_VOLUME_DISMOUNTED,
        "SMB2_STATUS_VOLUME_DISMOUNTED",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_NOT_A_REPARSE_POINT,
        "SMB2_STATUS_NOT_A_REPARSE_POINT",
    ),
    NtStatusEntry::new(
        SMB2_STATUS_SERVER_UNAVAILABLE,
        "SMB2_STATUS_SERVER_UNAVAILABLE",
    ),
    NtStatusEntry::new(SMB2_STATUS_BUFFER_OVERFLOW, "SMB2_STATUS_BUFFER_OVERFLOW"),
    NtStatusEntry::new(
        SMB2_STATUS_STOPPED_ON_SYMLINK,
        "SMB2_STATUS_STOPPED_ON_SYMLINK",
    ),
];

/// Returns the header constant name for a raw NTSTATUS value when it is known.
#[must_use]
pub fn ntstatus_name(status: u32) -> Option<&'static str> {
    SMB2_STATUS_TABLE
        .iter()
        .find(|entry| entry.matches(status))
        .map(|entry| entry.name)
}

/// Maps an NTSTATUS to a negative errno-style value.
///
/// This is intentionally only a skeleton: success maps to `0`, pending maps to
/// `-11`, and all other statuses keep the existing generic `-1` placeholder.
/// Full protocol-specific errno translation belongs in the dedicated errors
/// module rather than this header mirror.
#[must_use]
pub const fn nterror_to_errno(status: u32) -> i32 {
    match status {
        SMB2_STATUS_SUCCESS => 0,
        SMB2_STATUS_PENDING => -11,
        _ => -1,
    }
}
