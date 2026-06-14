mod ffi {
    #![allow(
        dead_code,
        non_camel_case_types,
        non_snake_case,
        non_upper_case_globals
    )]
    include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncOperation {
    ConnectShare,
    DisconnectShare,
    Opendir,
    Open,
    Close,
    Fsync,
    Pread,
    Pwrite,
    Read,
    Write,
    Unlink,
    Rmdir,
    Mkdir,
    Fstat,
    Stat,
    Rename,
    Statvfs,
    Truncate,
    Ftruncate,
    Readlink,
    Echo,
    NotifyChange,
    ShareEnum,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncHarnessResult {
    pub rc: i32,
    pub returned_pointer: bool,
    pub callback_status: i32,
    pub async_called: i32,
    pub wait_service_called: i32,
    pub error: String,
}

pub type StatusResult = SyncHarnessResult;

pub type PointerResult = SyncHarnessResult;

pub fn run_status(operation: SyncOperation, callback_status: i32) -> SyncHarnessResult {
    convert(unsafe { ffi::sync_ffi_run_status(operation.raw(), 0, callback_status) })
}

pub fn run_status_start_failure(operation: SyncOperation, async_rc: i32) -> SyncHarnessResult {
    convert(unsafe { ffi::sync_ffi_run_status(operation.raw(), async_rc, 0) })
}

pub fn run_pointer(operation: SyncOperation) -> SyncHarnessResult {
    convert(unsafe { ffi::sync_ffi_run_pointer(operation.raw(), 0, 0) })
}

pub fn run_pointer_start_failure(operation: SyncOperation, async_rc: i32) -> SyncHarnessResult {
    convert(unsafe { ffi::sync_ffi_run_pointer(operation.raw(), async_rc, 0) })
}

pub fn run_disconnected(operation: SyncOperation) -> SyncHarnessResult {
    convert(unsafe { ffi::sync_ffi_run_disconnected(operation.raw()) })
}

impl SyncOperation {
    fn raw(self) -> ffi::sync_ffi_operation {
        match self {
            Self::ConnectShare => ffi::sync_ffi_operation_SYNC_FFI_CONNECT_SHARE,
            Self::DisconnectShare => ffi::sync_ffi_operation_SYNC_FFI_DISCONNECT_SHARE,
            Self::Opendir => ffi::sync_ffi_operation_SYNC_FFI_OPENDIR,
            Self::Open => ffi::sync_ffi_operation_SYNC_FFI_OPEN,
            Self::Close => ffi::sync_ffi_operation_SYNC_FFI_CLOSE,
            Self::Fsync => ffi::sync_ffi_operation_SYNC_FFI_FSYNC,
            Self::Pread => ffi::sync_ffi_operation_SYNC_FFI_PREAD,
            Self::Pwrite => ffi::sync_ffi_operation_SYNC_FFI_PWRITE,
            Self::Read => ffi::sync_ffi_operation_SYNC_FFI_READ,
            Self::Write => ffi::sync_ffi_operation_SYNC_FFI_WRITE,
            Self::Unlink => ffi::sync_ffi_operation_SYNC_FFI_UNLINK,
            Self::Rmdir => ffi::sync_ffi_operation_SYNC_FFI_RMDIR,
            Self::Mkdir => ffi::sync_ffi_operation_SYNC_FFI_MKDIR,
            Self::Fstat => ffi::sync_ffi_operation_SYNC_FFI_FSTAT,
            Self::Stat => ffi::sync_ffi_operation_SYNC_FFI_STAT,
            Self::Rename => ffi::sync_ffi_operation_SYNC_FFI_RENAME,
            Self::Statvfs => ffi::sync_ffi_operation_SYNC_FFI_STATVFS,
            Self::Truncate => ffi::sync_ffi_operation_SYNC_FFI_TRUNCATE,
            Self::Ftruncate => ffi::sync_ffi_operation_SYNC_FFI_FTRUNCATE,
            Self::Readlink => ffi::sync_ffi_operation_SYNC_FFI_READLINK,
            Self::Echo => ffi::sync_ffi_operation_SYNC_FFI_ECHO,
            Self::NotifyChange => ffi::sync_ffi_operation_SYNC_FFI_NOTIFY_CHANGE,
            Self::ShareEnum => ffi::sync_ffi_operation_SYNC_FFI_SHARE_ENUM,
        }
    }
}

fn convert(raw: ffi::sync_ffi_result) -> SyncHarnessResult {
    SyncHarnessResult {
        rc: raw.rc,
        returned_pointer: raw.returned_pointer != 0,
        callback_status: raw.callback_status,
        async_called: raw.async_called,
        wait_service_called: raw.wait_service_called,
        error: c_buffer_to_string(&raw.error),
    }
}

fn c_buffer_to_string(buf: &[i8]) -> String {
    let end = buf.iter().position(|byte| *byte == 0).unwrap_or(buf.len());
    let bytes = buf[..end]
        .iter()
        .map(|byte| *byte as u8)
        .collect::<Vec<_>>();
    String::from_utf8_lossy(&bytes).into_owned()
}
