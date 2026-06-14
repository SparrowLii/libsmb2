//! C ABI adapter for the Rust libsmb2 implementation.

use libsmb2_rs::include::smb2::libsmb2::{DirectoryEntry, PduHandle, Smb2OperationResult};
use libsmb2_rs::lib::smb2_cmd_notify_change;
use libsmb2_rs::lib::smb2_cmd_query_directory;
use libsmb2_rs::lib::sync::{self, SyncPayload};
use libsmb2_rs::lib::{errors, timestamps, unicode};
use libsmb2_rs::{FileHandle, Smb2Client, Smb2Url, Stat, StatVfs};
use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_void};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::ptr;

const PTR_REF: i32 = 0;

unsafe extern "C" {
    fn malloc(size: usize) -> *mut c_void;
    fn free(ptr: *mut c_void);
    fn pipe(fds: *mut i32) -> i32;
    fn read(fd: i32, buf: *mut c_void, count: usize) -> isize;
    fn write(fd: i32, buf: *const c_void, count: usize) -> isize;
    fn close(fd: i32) -> i32;
}

const WAKE_BYTE: u8 = 1;

type Smb2CommandCallback = Option<
    unsafe extern "C" fn(
        smb2: *mut Smb2RustContext,
        status: i32,
        command_data: *mut c_void,
        cb_data: *mut c_void,
    ),
>;

type Smb2ErrorCallback =
    Option<unsafe extern "C" fn(smb2: *mut Smb2RustContext, error: *const c_char)>;
type Smb2ChangeFdCallback =
    Option<unsafe extern "C" fn(smb2: *mut Smb2RustContext, fd: i32, cmd: i32)>;
type Smb2ChangeEventsCallback =
    Option<unsafe extern "C" fn(smb2: *mut Smb2RustContext, fd: i32, events: i32)>;
type Smb2AcceptedCallback = Option<unsafe extern "C" fn(fd: i32, cb_data: *mut c_void) -> i32>;
type Smb2ClientConnectionCallback =
    Option<unsafe extern "C" fn(smb2: *mut Smb2RustContext, cb_data: *mut c_void)>;
type Smb2OplockOrLeaseBreakCallback = Option<
    unsafe extern "C" fn(
        smb2: *mut Smb2RustContext,
        status: i32,
        rep: *mut c_void,
        new_oplock_level: *mut u8,
        new_lease_state: *mut u32,
    ),
>;

type DceRpcCallback = Option<
    unsafe extern "C" fn(
        dce: *mut DceRpcRustContext,
        status: i32,
        command_data: *mut c_void,
        cb_data: *mut c_void,
    ),
>;
type DceRpcCoder = Option<
    unsafe extern "C" fn(
        dce: *mut DceRpcRustContext,
        pdu: *mut DceRpcRustPdu,
        iov: *mut Smb2Iovec,
        offset: *mut i32,
        ptr: *mut c_void,
    ) -> i32,
>;

const ENOSYS: i32 = -38;

fn empty_c_string() -> CString {
    CString::new("").expect("empty string cannot contain an interior NUL")
}

fn ffi_error_string(message: &str) -> CString {
    let sanitized = message.replace('\0', " ");
    CString::new(sanitized).unwrap_or_else(|_| empty_c_string())
}

fn invalid_argument_code() -> i32 {
    -22
}

fn not_implemented_code() -> i32 {
    ENOSYS
}

/// Opaque Rust-backed SMB2 context handle used by the C ABI layer.
pub struct Smb2RustContext {
    inner: Smb2Client,
    error_string: CString,
    pending_callbacks: Vec<PendingCallback>,
    user_string: Option<CString>,
    domain_string: Option<CString>,
    workstation_string: Option<CString>,
    client_guid: Option<[u8; 16]>,
    error_callback: Smb2ErrorCallback,
    oplock_or_lease_break_callback: Smb2OplockOrLeaseBreakCallback,
    change_fd_callback: Smb2ChangeFdCallback,
    change_events_callback: Smb2ChangeEventsCallback,
    fd_storage: [i32; 1],
    wake_read_fd: i32,
    wake_write_fd: i32,
    wake_pending: bool,
}

impl Smb2RustContext {
    fn new() -> Self {
        Self {
            inner: Smb2Client::new(),
            error_string: empty_c_string(),
            pending_callbacks: Vec::new(),
            user_string: None,
            domain_string: None,
            workstation_string: None,
            client_guid: None,
            error_callback: None,
            oplock_or_lease_break_callback: None,
            change_fd_callback: None,
            change_events_callback: None,
            fd_storage: [-1],
            wake_read_fd: -1,
            wake_write_fd: -1,
            wake_pending: false,
        }
    }

    fn ensure_wake_fd(&mut self) -> i32 {
        if self.wake_read_fd >= 0 {
            return self.wake_read_fd;
        }
        let mut fds = [-1; 2];
        if unsafe { pipe(fds.as_mut_ptr()) } != 0 {
            self.set_error("failed to create local event wake pipe");
            return -1;
        }
        self.wake_read_fd = fds[0];
        self.wake_write_fd = fds[1];
        self.inner.set_fd(self.wake_read_fd);
        self.wake_read_fd
    }

    fn wake_local_service(&mut self) {
        if self.ensure_wake_fd() < 0 || self.wake_pending {
            return;
        }
        let byte = WAKE_BYTE;
        let wrote = unsafe { write(self.wake_write_fd, (&byte as *const u8).cast::<c_void>(), 1) };
        if wrote == 1 {
            self.wake_pending = true;
        }
    }

    fn drain_local_wake(&mut self) {
        if self.wake_read_fd < 0 || !self.wake_pending {
            return;
        }
        let mut byte = 0_u8;
        let read_count = unsafe {
            read(
                self.wake_read_fd,
                (&mut byte as *mut u8).cast::<c_void>(),
                1,
            )
        };
        if read_count >= 0 {
            self.wake_pending = false;
        }
    }

    fn close_wake_fd(&mut self) {
        if self.wake_read_fd >= 0 {
            unsafe { close(self.wake_read_fd) };
            self.wake_read_fd = -1;
        }
        if self.wake_write_fd >= 0 {
            unsafe { close(self.wake_write_fd) };
            self.wake_write_fd = -1;
        }
        self.wake_pending = false;
    }

    fn set_error(&mut self, message: &str) {
        self.inner.set_error(message);
        self.error_string = ffi_error_string(message);
        if let Some(callback) = self.error_callback {
            // SAFETY: The callback was registered by the C caller. A null context
            // is used because this helper may be called before a stable self
            // pointer is available; callers that need the context can query later.
            unsafe { callback(ptr::null_mut(), self.error_string.as_ptr()) };
        }
    }

    fn clear_error(&mut self) {
        self.inner.set_error("");
        self.error_string = empty_c_string();
    }

    fn sync_error_from_client(&mut self) {
        let error = self.inner.error().unwrap_or_default().to_owned();
        self.error_string = ffi_error_string(&error);
    }

    fn finish_status(&mut self, result: libsmb2_rs::Result<impl Sized>) -> i32 {
        match result {
            Ok(_) => {
                self.clear_error();
                0
            }
            Err(error) => {
                self.sync_error_from_client();
                if self.error_string.as_bytes().is_empty() {
                    self.set_error("SMB2 operation failed");
                }
                error.code()
            }
        }
    }

    fn push_callback(
        &mut self,
        message_id: u64,
        kind: PendingCallbackKind,
        callback: Smb2CommandCallback,
        cb_data: *mut c_void,
        free_cb: Option<unsafe extern "C" fn(*mut c_void)>,
    ) {
        self.pending_callbacks.push(PendingCallback {
            message_id,
            kind,
            callback,
            cb_data,
            free_cb,
            cancelled: false,
        });
        self.wake_local_service();
    }

    fn cancel_callback(&mut self, message_id: u64) {
        if let Some(callback) = self
            .pending_callbacks
            .iter_mut()
            .find(|callback| callback.message_id == message_id)
        {
            callback.cancelled = true;
        }
    }

    fn dispatch_completed_callbacks(&mut self, context_ptr: *mut Smb2RustContext) {
        let completions = self.inner.take_completed_results();
        for completion in completions {
            let Some(index) = self
                .pending_callbacks
                .iter()
                .position(|callback| callback.message_id == completion.message_id)
            else {
                continue;
            };
            let callback = self.pending_callbacks.remove(index);
            if callback.cancelled {
                if let Some(free_cb) = callback.free_cb {
                    // SAFETY: The callback data and free callback are supplied by
                    // the C caller for this queued operation.
                    unsafe { free_cb(callback.cb_data) };
                }
                continue;
            }
            let (status, command_data, temporary) = callback_payload_for_completion(
                callback.kind,
                completion.status,
                completion.result,
            );
            if let Some(cb) = callback.callback {
                // SAFETY: The callback pointer uses the legacy C ABI. The command
                // data pointer, when non-null, is allocated by this facade and
                // follows the same ownership convention as the corresponding C API.
                unsafe { cb(context_ptr, status, command_data, callback.cb_data) };
            }
            if temporary && !command_data.is_null() {
                free_temporary_command_data(callback.kind, command_data);
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PendingCallbackKind {
    StatusOnly,
    Open,
    OpenDir,
    Read {
        buf: *mut u8,
        count: u32,
        offset: u64,
    },
    Write {
        count: u32,
        offset: u64,
    },
    Stat {
        out: *mut Smb2Stat64,
    },
    StatVfs {
        out: *mut Smb2StatVfs,
    },
    Readlink,
}

struct PendingCallback {
    message_id: u64,
    kind: PendingCallbackKind,
    callback: Smb2CommandCallback,
    cb_data: *mut c_void,
    free_cb: Option<unsafe extern "C" fn(*mut c_void)>,
    cancelled: bool,
}

/// C-compatible `struct smb2_stat_64`.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Smb2Stat64 {
    pub smb2_type: u32,
    pub smb2_nlink: u32,
    pub smb2_ino: u64,
    pub smb2_size: u64,
    pub smb2_atime: u64,
    pub smb2_atime_nsec: u64,
    pub smb2_mtime: u64,
    pub smb2_mtime_nsec: u64,
    pub smb2_ctime: u64,
    pub smb2_ctime_nsec: u64,
    pub smb2_btime: u64,
    pub smb2_btime_nsec: u64,
}

impl From<Stat> for Smb2Stat64 {
    fn from(stat: Stat) -> Self {
        Self {
            smb2_type: stat.file_type.as_raw(),
            smb2_nlink: stat.nlink,
            smb2_ino: stat.ino,
            smb2_size: stat.size,
            smb2_atime: stat.atime,
            smb2_atime_nsec: stat.atime_nsec,
            smb2_mtime: stat.mtime,
            smb2_mtime_nsec: stat.mtime_nsec,
            smb2_ctime: stat.ctime,
            smb2_ctime_nsec: stat.ctime_nsec,
            smb2_btime: stat.btime,
            smb2_btime_nsec: stat.btime_nsec,
        }
    }
}

/// C-compatible `struct smb2_statvfs`.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Smb2StatVfs {
    pub f_bsize: u32,
    pub f_frsize: u32,
    pub f_blocks: u64,
    pub f_bfree: u64,
    pub f_bavail: u64,
    pub f_files: u32,
    pub f_ffree: u32,
    pub f_favail: u32,
    pub f_fsid: u32,
    pub f_flag: u32,
    pub f_namemax: u32,
}

impl From<StatVfs> for Smb2StatVfs {
    fn from(statvfs: StatVfs) -> Self {
        Self {
            f_bsize: statvfs.block_size,
            f_frsize: statvfs.fragment_size,
            f_blocks: statvfs.blocks,
            f_bfree: statvfs.blocks_free,
            f_bavail: statvfs.blocks_available,
            f_files: statvfs.files,
            f_ffree: statvfs.files_free,
            f_favail: statvfs.files_available,
            f_fsid: statvfs.filesystem_id,
            f_flag: statvfs.flags,
            f_namemax: statvfs.name_max,
        }
    }
}

/// C-compatible `struct smb2dirent`.
#[repr(C)]
pub struct Smb2Dirent {
    pub name: *const c_char,
    pub st: Smb2Stat64,
}

struct OwnedDirent {
    entry: Smb2Dirent,
    _name: CString,
}

/// Opaque Rust-backed `struct smb2dir`.
pub struct Smb2RustDir {
    entries: Vec<OwnedDirent>,
    index: usize,
}

/// Opaque Rust-backed `struct smb2fh`.
pub struct Smb2RustFileHandle {
    inner: FileHandle,
    file_id: [u8; 16],
}

/// Opaque Rust-backed `struct smb2_pdu`.
pub struct Smb2RustPdu {
    message_id: u64,
    tree_id: Option<u32>,
    status: i32,
    is_compound: bool,
    compound: *mut Smb2RustPdu,
}

/// C-compatible `struct smb2_read_cb_data`.
#[repr(C)]
pub struct Smb2ReadCbData {
    pub fh: *mut Smb2RustFileHandle,
    pub buf: *mut u8,
    pub count: u32,
    pub offset: u64,
}

/// C-compatible `struct smb2_write_cb_data`.
#[repr(C)]
pub struct Smb2WriteCbData {
    pub fh: *mut Smb2RustFileHandle,
    pub buf: *const u8,
    pub count: u32,
    pub offset: u64,
}

/// C-compatible `struct smb2_iovec`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Smb2Iovec {
    pub buf: *mut u8,
    pub len: usize,
    pub free: Option<unsafe extern "C" fn(*mut c_void)>,
}

/// C-compatible `struct smb2_timeval`.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct Smb2Timeval {
    pub tv_sec: i64,
    pub tv_usec: i64,
}

/// C-compatible `struct smb2_fileidfulldirectoryinformation`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Smb2FileIdFullDirectoryInformationC {
    pub next_entry_offset: u32,
    pub file_index: u32,
    pub creation_time: Smb2Timeval,
    pub last_access_time: Smb2Timeval,
    pub last_write_time: Smb2Timeval,
    pub change_time: Smb2Timeval,
    pub end_of_file: u64,
    pub allocation_size: u64,
    pub file_attributes: u32,
    pub file_name_length: u32,
    pub ea_size: u32,
    pub file_id: u64,
    pub name: *const c_char,
}

impl Default for Smb2FileIdFullDirectoryInformationC {
    fn default() -> Self {
        Self {
            next_entry_offset: 0,
            file_index: 0,
            creation_time: Smb2Timeval::default(),
            last_access_time: Smb2Timeval::default(),
            last_write_time: Smb2Timeval::default(),
            change_time: Smb2Timeval::default(),
            end_of_file: 0,
            allocation_size: 0,
            file_attributes: 0,
            file_name_length: 0,
            ea_size: 0,
            file_id: 0,
            name: ptr::null(),
        }
    }
}

/// C-compatible `struct smb2_file_notify_change_information`.
#[repr(C)]
#[derive(Debug)]
pub struct Smb2FileNotifyChangeInformationC {
    pub action: u32,
    pub name: *const c_char,
    pub next: *mut Smb2FileNotifyChangeInformationC,
}

impl Default for Smb2FileNotifyChangeInformationC {
    fn default() -> Self {
        Self {
            action: 0,
            name: ptr::null(),
            next: ptr::null_mut(),
        }
    }
}

/// C-compatible `struct smb2_libversion`.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct Smb2LibVersion {
    pub major_version: u8,
    pub minor_version: u8,
    pub patch_version: u8,
}

/// C-compatible `struct smb2_utf16` header with flexible trailing units.
#[repr(C)]
pub struct Smb2Utf16 {
    pub len: i32,
    pub val: [u16; 1],
}

/// C-compatible presentation syntax UUID.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct DceRpcUuid {
    pub v1: u32,
    pub v2: u16,
    pub v3: u16,
    pub v4: [u8; 8],
}

/// C-compatible presentation syntax id.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct PSyntaxId {
    pub uuid: DceRpcUuid,
    pub vers: u16,
    pub vers_minor: u16,
}

/// C-compatible NDR context handle.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct NdrContextHandle {
    pub context_handle_attributes: u32,
    pub context_handle_uuid: DceRpcUuid,
}

/// C-compatible `struct dcerpc_utf16`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct DceRpcUtf16C {
    pub max_count: u32,
    pub offset: u32,
    pub actual_count: u32,
    pub utf16: *mut Smb2Utf16,
    pub utf8: *const c_char,
}

/// Opaque Rust-backed DCERPC context.
pub struct DceRpcRustContext {
    smb2: *mut Smb2RustContext,
    error_string: CString,
    tctx: i32,
}

/// Opaque Rust-backed DCERPC PDU.
pub struct DceRpcRustPdu {
    pub direction: i32,
    payload: Vec<u8>,
    allocations: Vec<*mut c_char>,
    deferred_pointers: Vec<DeferredPointer>,
    size_is: i32,
    little_endian: bool,
    top_level: bool,
    conformance_run: bool,
    suppress_conformance_io: bool,
    max_alignment: usize,
}

struct DeferredPointer {
    coder: DceRpcCoder,
    ptr: *mut c_void,
}

/// C-compatible `struct srvsvc_SHARE_INFO_1`.
#[repr(C)]
pub struct SrvsvcShareInfo1C {
    pub netname: DceRpcUtf16C,
    pub type_: u32,
    pub remark: DceRpcUtf16C,
}

/// C-compatible `struct srvsvc_SHARE_INFO_1_CONTAINER`.
#[repr(C)]
pub struct SrvsvcShareInfo1ContainerC {
    pub entries_read: u32,
    pub share_info_1: *mut SrvsvcShareInfo1C,
}

#[no_mangle]
pub static mut compound_file_id: [u8; 16] = [0xff; 16];

#[no_mangle]
pub static mut NT_SID_AUTHORITY: [u8; 6] = [0, 0, 0, 0, 0, 5];

#[no_mangle]
pub static mut lsa_interface: PSyntaxId = PSyntaxId {
    uuid: DceRpcUuid {
        v1: 0x1234_5778,
        v2: 0x1234,
        v3: 0xabcd,
        v4: [0xef, 0x00, 0x01, 0x23, 0x45, 0x67, 0xcf, 0xfb],
    },
    vers: 0,
    vers_minor: 0,
};

#[no_mangle]
pub static mut srvsvc_interface: PSyntaxId = PSyntaxId {
    uuid: DceRpcUuid {
        v1: 0x4b32_4fc8,
        v2: 0x1670,
        v3: 0x01d3,
        v4: [0x12, 0x78, 0x5a, 0x47, 0xbf, 0x6e, 0xe1, 0x88],
    },
    vers: 3,
    vers_minor: 0,
};

fn boxed_void<T>(value: T) -> *mut c_void {
    Box::into_raw(Box::new(value)).cast::<c_void>()
}

fn command_data_for_result(
    kind: PendingCallbackKind,
    result: libsmb2_rs::Result<Smb2OperationResult>,
) -> (*mut c_void, bool) {
    match (kind, result) {
        (PendingCallbackKind::Open, Ok(Smb2OperationResult::Open { handle, .. })) => (
            boxed_void(Smb2RustFileHandle {
                file_id: handle.id(),
                inner: handle,
            }),
            false,
        ),
        (PendingCallbackKind::OpenDir, Ok(Smb2OperationResult::Directory { entries, .. })) => {
            (boxed_void(dir_from_entries(entries)), false)
        }
        (
            PendingCallbackKind::Read { buf, offset, .. },
            Ok(Smb2OperationResult::Read { data, .. }),
        ) => {
            if !buf.is_null() && !data.is_empty() {
                // SAFETY: The buffer pointer and requested size came from the C caller.
                unsafe { ptr::copy_nonoverlapping(data.as_ptr(), buf, data.len()) };
            }
            (
                boxed_void(Smb2ReadCbData {
                    fh: ptr::null_mut(),
                    buf,
                    count: data.len().try_into().unwrap_or(u32::MAX),
                    offset,
                }),
                true,
            )
        }
        (PendingCallbackKind::Write { count, offset }, Ok(Smb2OperationResult::Write { .. })) => (
            boxed_void(Smb2WriteCbData {
                fh: ptr::null_mut(),
                buf: ptr::null(),
                count,
                offset,
            }),
            true,
        ),
        (PendingCallbackKind::Stat { out }, Ok(Smb2OperationResult::Stat { stat })) => {
            if !out.is_null() {
                // SAFETY: The output pointer was supplied by the C caller.
                unsafe { *out = Smb2Stat64::from(stat) };
            }
            (out.cast::<c_void>(), false)
        }
        (PendingCallbackKind::StatVfs { out }, Ok(Smb2OperationResult::StatVfs { statvfs })) => {
            if !out.is_null() {
                // SAFETY: The output pointer was supplied by the C caller.
                unsafe { *out = Smb2StatVfs::from(statvfs) };
            }
            (out.cast::<c_void>(), false)
        }
        (PendingCallbackKind::Readlink, Ok(Smb2OperationResult::Readlink { target, .. })) => {
            match CString::new(target) {
                Ok(target) => (target.into_raw().cast::<c_void>(), true),
                Err(_) => (ptr::null_mut(), false),
            }
        }
        _ => (ptr::null_mut(), false),
    }
}

fn callback_payload_for_completion(
    kind: PendingCallbackKind,
    status: i32,
    result: libsmb2_rs::Result<Smb2OperationResult>,
) -> (i32, *mut c_void, bool) {
    if status != 0 {
        return (status, ptr::null_mut(), false);
    }

    let (command_data, temporary) = command_data_for_result(kind, result);
    let status = match kind {
        PendingCallbackKind::Read { .. } | PendingCallbackKind::Write { .. } => {
            if command_data.is_null() {
                0
            } else if matches!(kind, PendingCallbackKind::Read { .. }) {
                // SAFETY: command_data is a temporary Smb2ReadCbData allocated above.
                unsafe { (*(command_data.cast::<Smb2ReadCbData>())).count as i32 }
            } else {
                // SAFETY: command_data is a temporary Smb2WriteCbData allocated above.
                unsafe { (*(command_data.cast::<Smb2WriteCbData>())).count as i32 }
            }
        }
        _ => 0,
    };
    (status, command_data, temporary)
}

fn free_temporary_command_data(kind: PendingCallbackKind, command_data: *mut c_void) {
    match kind {
        PendingCallbackKind::Read { .. } => {
            // SAFETY: The pointer was allocated as Smb2ReadCbData in command_data_for_result.
            unsafe { drop(Box::from_raw(command_data.cast::<Smb2ReadCbData>())) };
        }
        PendingCallbackKind::Write { .. } => {
            // SAFETY: The pointer was allocated as Smb2WriteCbData in command_data_for_result.
            unsafe { drop(Box::from_raw(command_data.cast::<Smb2WriteCbData>())) };
        }
        PendingCallbackKind::Readlink => {
            // SAFETY: The pointer was allocated with CString::into_raw in command_data_for_result.
            unsafe { drop(CString::from_raw(command_data.cast::<c_char>())) };
        }
        _ => {}
    }
}

fn dir_from_entries(entries: Vec<DirectoryEntry>) -> Smb2RustDir {
    let entries = entries
        .into_iter()
        .filter_map(|entry| {
            let name = ffi_error_string(&entry.name);
            let dirent = Smb2Dirent {
                name: name.as_ptr(),
                st: Smb2Stat64::from(entry.stat),
            };
            Some(OwnedDirent {
                entry: dirent,
                _name: name,
            })
        })
        .collect();
    Smb2RustDir { entries, index: 0 }
}

fn sync_payload_file(payload: SyncPayload) -> Option<FileHandle> {
    match payload {
        SyncPayload::File(handle) => Some(handle),
        _ => None,
    }
}

fn sync_payload_dir(payload: SyncPayload) -> Option<Smb2RustDir> {
    match payload {
        SyncPayload::Directory(_) => Some(dir_from_entries(Vec::new())),
        _ => None,
    }
}

fn last_directory_result(context: &Smb2RustContext) -> Option<Smb2RustDir> {
    let completion = context.inner.last_completed_result()?;
    match &completion.result {
        Ok(Smb2OperationResult::Directory { entries, .. }) => {
            Some(dir_from_entries(entries.clone()))
        }
        _ => None,
    }
}

fn queue_pdu_callback(
    context: &mut Smb2RustContext,
    before_message_id: u64,
    kind: PendingCallbackKind,
    cb: Smb2CommandCallback,
    cb_data: *mut c_void,
    free_cb: Option<unsafe extern "C" fn(*mut c_void)>,
) -> *mut Smb2RustPdu {
    let message_id = context.inner.last_request_message_id();
    if message_id == before_message_id {
        context.sync_error_from_client();
        if context.error_string.as_bytes().is_empty() {
            context.set_error("failed to queue SMB2 operation");
        }
        return ptr::null_mut();
    }
    context.push_callback(message_id, kind, cb, cb_data, free_cb);
    Box::into_raw(Box::new(Smb2RustPdu {
        message_id,
        tree_id: None,
        status: 0,
        is_compound: false,
        compound: ptr::null_mut(),
    }))
}

fn result_code<T>(context: &mut Smb2RustContext, result: libsmb2_rs::Result<T>) -> i32 {
    match result {
        Ok(_) => {
            context.clear_error();
            0
        }
        Err(error) => {
            context.sync_error_from_client();
            if context.error_string.as_bytes().is_empty() {
                context.set_error("SMB2 operation failed");
            }
            error.code()
        }
    }
}

fn write_stat(out: *mut Smb2Stat64, stat: Stat) -> i32 {
    if out.is_null() {
        return invalid_argument_code();
    }
    // SAFETY: The caller supplied a non-null output pointer.
    unsafe { *out = Smb2Stat64::from(stat) };
    0
}

fn write_statvfs(out: *mut Smb2StatVfs, statvfs: StatVfs) -> i32 {
    if out.is_null() {
        return invalid_argument_code();
    }
    // SAFETY: The caller supplied a non-null output pointer.
    unsafe { *out = Smb2StatVfs::from(statvfs) };
    0
}

fn copy_readlink_target(buf: *mut c_char, bufsiz: u32, target: &[u8]) -> i32 {
    if buf.is_null() || bufsiz == 0 {
        return invalid_argument_code();
    }
    let capacity = bufsiz as usize;
    let copy_len = target.len().min(capacity.saturating_sub(1));
    if copy_len > 0 {
        // SAFETY: The caller supplied a buffer of bufsiz bytes.
        unsafe { ptr::copy_nonoverlapping(target.as_ptr().cast::<c_char>(), buf, copy_len) };
    }
    // SAFETY: The buffer is non-null and bufsiz is at least one.
    unsafe { *buf.add(copy_len) = 0 };
    0
}

fn dcerpc_is_decode(pdu: *const DceRpcRustPdu) -> bool {
    !pdu.is_null() && unsafe { (*pdu).direction == 0 }
}

fn dcerpc_count_size(ctx: *const DceRpcRustContext) -> usize {
    if !ctx.is_null() && unsafe { (*ctx).tctx } != 0 {
        8
    } else {
        4
    }
}

fn dcerpc_note_alignment(pdu: *mut DceRpcRustPdu, alignment: usize) {
    if !pdu.is_null() && unsafe { (*pdu).conformance_run } {
        unsafe { (*pdu).max_alignment = (*pdu).max_alignment.max(alignment) };
    }
}

fn dcerpc_should_write_conformance(pdu: *const DceRpcRustPdu) -> bool {
    pdu.is_null() || unsafe { (*pdu).conformance_run && !(*pdu).suppress_conformance_io }
}

fn dcerpc_align_offset(offset: *mut i32, alignment: usize) -> Option<()> {
    if offset.is_null() || alignment == 0 {
        return None;
    }
    let current = unsafe { *offset };
    if current < 0 {
        return None;
    }
    let aligned = ((current as usize).saturating_add(alignment - 1)) & !(alignment - 1);
    let aligned = i32::try_from(aligned).ok()?;
    unsafe { *offset = aligned };
    Some(())
}

fn dcerpc_write_count(
    pdu: *const DceRpcRustPdu,
    iov: *mut Smb2Iovec,
    offset: *mut i32,
    value: u32,
    count_size: usize,
) -> i32 {
    if offset.is_null() || count_size == 0 {
        return invalid_argument_code();
    }
    if count_size == 8 {
        let mut bytes = [0_u8; 8];
        let raw = u64::from(value);
        if !pdu.is_null() && unsafe { !(*pdu).little_endian } {
            bytes.copy_from_slice(&raw.to_be_bytes());
        } else {
            bytes.copy_from_slice(&raw.to_le_bytes());
        }
        dcerpc_code_bytes(iov, offset, bytes.as_ptr(), bytes.len(), false)
    } else {
        let bytes = if !pdu.is_null() && unsafe { !(*pdu).little_endian } {
            value.to_be_bytes()
        } else {
            value.to_le_bytes()
        };
        dcerpc_code_bytes(iov, offset, bytes.as_ptr(), bytes.len(), false)
    }
}

fn dcerpc_read_or_write_count(
    pdu: *const DceRpcRustPdu,
    iov: *mut Smb2Iovec,
    offset: *mut i32,
    value: u32,
    count_size: usize,
) -> Option<u32> {
    if dcerpc_is_decode(pdu) {
        dcerpc_read_count(pdu, iov, offset, count_size)
    } else if dcerpc_write_count(pdu, iov, offset, value, count_size) == 0 {
        Some(value)
    } else {
        None
    }
}

fn dcerpc_code_pointer_referent(
    ctx: *const DceRpcRustContext,
    pdu: *const DceRpcRustPdu,
    iov: *mut Smb2Iovec,
    offset: *mut i32,
    present: bool,
) -> Option<bool> {
    let count_size = dcerpc_count_size(ctx);
    dcerpc_note_alignment(pdu.cast_mut(), count_size);
    if !pdu.is_null() && unsafe { (*pdu).conformance_run } {
        return Some(present);
    }
    if dcerpc_is_decode(pdu) {
        dcerpc_read_count(pdu, iov, offset, count_size).map(|value| value != 0)
    } else if count_size == 8 && present {
        let marker = *b"UptrrtpU";
        if dcerpc_code_bytes(iov, offset, marker.as_ptr(), marker.len(), false) == 0 {
            Some(true)
        } else {
            None
        }
    } else {
        let value = if present { 0x7274_7055 } else { 0 };
        dcerpc_read_or_write_count(pdu, iov, offset, value, count_size).map(|_| present)
    }
}

fn dcerpc_read_count(
    pdu: *const DceRpcRustPdu,
    iov: *mut Smb2Iovec,
    offset: *mut i32,
    count_size: usize,
) -> Option<u32> {
    if iov.is_null() || offset.is_null() {
        return None;
    }
    let start = unsafe { *offset };
    if start < 0 {
        return None;
    }
    let start = start as usize;
    let iov_ref = unsafe { &*iov };
    if iov_ref.buf.is_null() || start.saturating_add(count_size) > iov_ref.len {
        return None;
    }
    let little_endian = pdu.is_null() || unsafe { (*pdu).little_endian };
    let value = unsafe {
        if count_size == 8 {
            let mut bytes = [0_u8; 8];
            ptr::copy_nonoverlapping(iov_ref.buf.add(start), bytes.as_mut_ptr(), bytes.len());
            if little_endian {
                u64::from_le_bytes(bytes)
            } else {
                u64::from_be_bytes(bytes)
            }
        } else {
            let mut bytes = [0_u8; 4];
            ptr::copy_nonoverlapping(iov_ref.buf.add(start), bytes.as_mut_ptr(), bytes.len());
            if little_endian {
                u64::from(u32::from_le_bytes(bytes))
            } else {
                u64::from(u32::from_be_bytes(bytes))
            }
        }
    };
    unsafe {
        *offset = offset
            .read()
            .saturating_add(i32::try_from(count_size).ok()?)
    };
    u32::try_from(value).ok()
}

fn dcerpc_code_bytes(
    iov: *mut Smb2Iovec,
    offset: *mut i32,
    src: *const u8,
    len: usize,
    decode: bool,
) -> i32 {
    if iov.is_null() || offset.is_null() || (src.is_null() && len != 0) {
        return invalid_argument_code();
    }
    if dcerpc_align_offset(offset, len).is_none() {
        return invalid_argument_code();
    }
    let start = unsafe { *offset };
    if start < 0 {
        return invalid_argument_code();
    }
    let start = start as usize;
    let iov_ref = unsafe { &mut *iov };
    if !iov_ref.buf.is_null() && start.saturating_add(len) <= iov_ref.len && len != 0 {
        if decode {
            unsafe { ptr::copy_nonoverlapping(iov_ref.buf.add(start), src.cast_mut(), len) };
        } else {
            unsafe { ptr::copy_nonoverlapping(src, iov_ref.buf.add(start), len) };
        }
    }
    unsafe {
        *offset = offset
            .read()
            .saturating_add(i32::try_from(len).unwrap_or(i32::MAX))
    };
    0
}

fn dcerpc_utf16_string(ptr_: *const DceRpcUtf16C) -> Option<String> {
    if ptr_.is_null() {
        return None;
    }
    let utf8 = unsafe { (*ptr_).utf8 };
    if utf8.is_null() {
        return Some(String::new());
    }
    unsafe { CStr::from_ptr(utf8).to_str().ok().map(str::to_owned) }
}

fn dcerpc_store_decoded_utf8(
    pdu: *mut DceRpcRustPdu,
    out: *mut DceRpcUtf16C,
    value: String,
) -> i32 {
    if out.is_null() {
        return invalid_argument_code();
    }
    let c_string = ffi_error_string(&value);
    let ptr = c_string.into_raw();
    unsafe {
        (*out).utf8 = ptr;
        if !pdu.is_null() {
            (*pdu).allocations.push(ptr);
        }
    }
    0
}

fn dcerpc_code_utf16_string(
    ctx: *const DceRpcRustContext,
    pdu: *mut DceRpcRustPdu,
    iov: *mut Smb2Iovec,
    offset: *mut i32,
    value: *mut DceRpcUtf16C,
    nul_terminated: bool,
) -> i32 {
    if value.is_null() {
        return invalid_argument_code();
    }
    dcerpc_note_alignment(pdu, 2);
    if !pdu.is_null() && unsafe { (*pdu).conformance_run } {
        if unsafe { (*pdu).suppress_conformance_io } {
            return 0;
        }
        if dcerpc_is_decode(pdu) {
            unsafe {
                let _ = dcerpc_conformance_coder(
                    ctx.cast_mut(),
                    pdu,
                    iov,
                    offset,
                    (&mut (*value).max_count as *mut u32).cast::<c_void>(),
                );
                let _ = dcerpc_conformance_coder(
                    ctx.cast_mut(),
                    pdu,
                    iov,
                    offset,
                    (&mut (*value).offset as *mut u32).cast::<c_void>(),
                );
                return dcerpc_conformance_coder(
                    ctx.cast_mut(),
                    pdu,
                    iov,
                    offset,
                    (&mut (*value).actual_count as *mut u32).cast::<c_void>(),
                );
            }
        }

        let text = dcerpc_utf16_string(value).unwrap_or_default();
        let actual_count = text
            .encode_utf16()
            .count()
            .saturating_add(usize::from(nul_terminated));
        let max_count = if !nul_terminated && actual_count % 2 != 0 {
            actual_count.saturating_add(1)
        } else {
            actual_count
        };
        let Ok(max_count) = u32::try_from(max_count) else {
            return invalid_argument_code();
        };
        let Ok(actual_count) = u32::try_from(actual_count) else {
            return invalid_argument_code();
        };
        unsafe {
            (*value).max_count = max_count;
            (*value).offset = 0;
            (*value).actual_count = actual_count;
            let _ = dcerpc_conformance_coder(
                ctx.cast_mut(),
                pdu,
                iov,
                offset,
                (&mut (*value).max_count as *mut u32).cast::<c_void>(),
            );
            let _ = dcerpc_conformance_coder(
                ctx.cast_mut(),
                pdu,
                iov,
                offset,
                (&mut (*value).offset as *mut u32).cast::<c_void>(),
            );
            return dcerpc_conformance_coder(
                ctx.cast_mut(),
                pdu,
                iov,
                offset,
                (&mut (*value).actual_count as *mut u32).cast::<c_void>(),
            );
        }
    }
    let count_size = dcerpc_count_size(ctx);
    if dcerpc_is_decode(pdu) {
        let Some(_max_count) = dcerpc_read_count(pdu, iov, offset, count_size) else {
            return invalid_argument_code();
        };
        let Some(value_offset) = dcerpc_read_count(pdu, iov, offset, count_size) else {
            return invalid_argument_code();
        };
        let Some(actual_count) = dcerpc_read_count(pdu, iov, offset, count_size) else {
            return invalid_argument_code();
        };
        let mut units = Vec::with_capacity(actual_count as usize);
        for _ in 0..actual_count {
            let mut unit = 0_u16;
            let rc = dcerpc_scalar_coder(
                pdu,
                iov,
                offset,
                (&mut unit as *mut u16).cast::<c_void>(),
                2,
            );
            if rc != 0 {
                return rc;
            }
            units.push(unit);
        }
        let slice_len = if nul_terminated && units.last().copied() == Some(0) {
            units.len().saturating_sub(1)
        } else {
            units.len()
        };
        let Ok(decoded) = String::from_utf16(&units[..slice_len]) else {
            return invalid_argument_code();
        };
        unsafe {
            (*value).max_count = actual_count;
            (*value).offset = value_offset;
            (*value).actual_count = actual_count;
        }
        return dcerpc_store_decoded_utf8(pdu, value, decoded);
    }

    let text = dcerpc_utf16_string(value).unwrap_or_default();
    let units: Vec<u16> = text.encode_utf16().collect();
    let actual_count = units.len().saturating_add(usize::from(nul_terminated));
    let max_count = if nul_terminated || actual_count % 2 == 0 {
        actual_count
    } else {
        actual_count.saturating_add(1)
    };
    let Ok(actual_count) = u32::try_from(actual_count) else {
        return invalid_argument_code();
    };
    let Ok(max_count) = u32::try_from(max_count) else {
        return invalid_argument_code();
    };
    for count in [max_count, 0, actual_count] {
        let rc = dcerpc_write_count(pdu, iov, offset, count, count_size);
        if rc != 0 {
            return rc;
        }
    }
    for unit in units {
        let mut unit = unit;
        let rc = dcerpc_scalar_coder(
            pdu,
            iov,
            offset,
            (&mut unit as *mut u16).cast::<c_void>(),
            2,
        );
        if rc != 0 {
            return rc;
        }
    }
    if nul_terminated {
        let mut zero = 0_u16;
        dcerpc_scalar_coder(
            pdu,
            iov,
            offset,
            (&mut zero as *mut u16).cast::<c_void>(),
            2,
        )
    } else {
        0
    }
}

fn set_context_error(context: *mut Smb2RustContext, message: &str) {
    if !context.is_null() {
        // SAFETY: The caller supplied a live context pointer when non-null.
        unsafe { (*context).set_error(message) };
    }
}

fn malloc_c_string(value: &str) -> *const c_char {
    ffi_error_string(value).into_raw()
}

unsafe fn free_nullable_c_string(ptr: *const c_char) {
    if !ptr.is_null() {
        // SAFETY: Strings assigned by this facade are allocated with CString::into_raw.
        unsafe { drop(CString::from_raw(ptr.cast_mut())) };
    }
}

fn timeval_from_query_directory(value: smb2_cmd_query_directory::Smb2Timeval) -> Smb2Timeval {
    Smb2Timeval {
        tv_sec: value.tv_sec,
        tv_usec: value.tv_usec,
    }
}

unsafe fn clear_fileid_full_directory_output(fs: *mut Smb2FileIdFullDirectoryInformationC) {
    if !fs.is_null() {
        // SAFETY: The output pointer is valid by caller contract; name may have been set by this facade.
        unsafe {
            free_nullable_c_string((*fs).name);
            *fs = Smb2FileIdFullDirectoryInformationC::default();
        }
    }
}

unsafe fn free_notify_chain_tail(mut node: *mut Smb2FileNotifyChangeInformationC) {
    while !node.is_null() {
        // SAFETY: Tail nodes are allocated by this facade with malloc.
        let next = unsafe { (*node).next };
        unsafe {
            free_nullable_c_string((*node).name);
            free(node.cast::<c_void>());
        }
        node = next;
    }
}

unsafe fn clear_notify_output(fnc: *mut Smb2FileNotifyChangeInformationC) {
    if !fnc.is_null() {
        // SAFETY: The head pointer is valid by caller contract; tail nodes, if any, are facade-owned.
        unsafe {
            free_nullable_c_string((*fnc).name);
            free_notify_chain_tail((*fnc).next);
            *fnc = Smb2FileNotifyChangeInformationC::default();
        }
    }
}

fn alloc_notify_node() -> *mut Smb2FileNotifyChangeInformationC {
    let ptr = unsafe { malloc(core::mem::size_of::<Smb2FileNotifyChangeInformationC>()) }
        .cast::<Smb2FileNotifyChangeInformationC>();
    if !ptr.is_null() {
        // SAFETY: `ptr` points to writable storage for one notify node.
        unsafe { *ptr = Smb2FileNotifyChangeInformationC::default() };
    }
    ptr
}

/// C-compatible parsed URL returned by `smb2_parse_url`.
#[repr(C)]
pub struct Smb2RustUrl {
    pub domain: *const c_char,
    pub user: *const c_char,
    pub server: *const c_char,
    pub share: *const c_char,
    pub path: *const c_char,
    domain_storage: Option<CString>,
    user_storage: Option<CString>,
    server_storage: CString,
    share_storage: CString,
    path_storage: Option<CString>,
}

impl Smb2RustUrl {
    fn new(url: Smb2Url) -> Result<Self, ()> {
        let domain_storage = optional_c_string(url.domain)?;
        let user_storage = optional_c_string(url.user)?;
        let server_storage = CString::new(url.server).map_err(|_| ())?;
        let share_storage = CString::new(url.share).map_err(|_| ())?;
        let path_storage = optional_c_string(url.path)?;

        Ok(Self {
            domain: optional_ptr(&domain_storage),
            user: optional_ptr(&user_storage),
            server: server_storage.as_ptr(),
            share: share_storage.as_ptr(),
            path: optional_ptr(&path_storage),
            domain_storage,
            user_storage,
            server_storage,
            share_storage,
            path_storage,
        })
    }
}

fn optional_c_string(value: Option<String>) -> Result<Option<CString>, ()> {
    value.map(CString::new).transpose().map_err(|_| ())
}

fn optional_ptr(value: &Option<CString>) -> *const c_char {
    value.as_ref().map_or(ptr::null(), |value| value.as_ptr())
}

unsafe fn c_string_arg<'a>(value: *const c_char) -> Option<&'a str> {
    if value.is_null() {
        return None;
    }

    // SAFETY: The caller provides a pointer to a NUL-terminated C string.
    unsafe { CStr::from_ptr(value) }.to_str().ok()
}

unsafe fn required_c_string_arg<'a>(
    context: &mut Smb2RustContext,
    name: &str,
    value: *const c_char,
) -> Result<&'a str, i32> {
    let Some(value) = (unsafe { c_string_arg(value) }) else {
        context.set_error(&format!("{name} is not valid UTF-8 or is NULL"));
        return Err(invalid_argument_code());
    };
    Ok(value)
}

unsafe fn optional_c_string_arg<'a>(value: *const c_char) -> Option<&'a str> {
    unsafe { c_string_arg(value) }
}

/// Creates a new Rust-backed SMB2 context.
///
/// Returns a null pointer if Rust context construction panics. The returned
/// pointer must be released with [`smb2_destroy_context`].
#[no_mangle]
pub extern "C" fn smb2_init_context() -> *mut Smb2RustContext {
    match catch_unwind(Smb2RustContext::new) {
        Ok(context) => Box::into_raw(Box::new(context)),
        Err(_) => std::ptr::null_mut(),
    }
}

/// Destroys a context previously returned by [`smb2_init_context`].
///
/// Passing a null pointer is allowed and has no effect.
///
/// # Safety
///
/// `context` must be either null or a pointer returned by [`smb2_init_context`]
/// that has not already been passed to [`smb2_destroy_context`].
#[no_mangle]
pub unsafe extern "C" fn smb2_destroy_context(context: *mut Smb2RustContext) {
    if context.is_null() {
        return;
    }

    let result = catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: The caller contract requires a unique pointer returned by
        // smb2_init_context that has not already been destroyed.
        let mut context = unsafe { Box::from_raw(context) };
        context.close_wake_fd();
    }));

    if result.is_err() {
        std::process::abort();
    }
}

/// Closes a context while keeping the allocation valid.
///
/// # Safety
///
/// `context` must be null or a valid live pointer returned by [`smb2_init_context`].
#[no_mangle]
pub unsafe extern "C" fn smb2_close_context(context: *mut Smb2RustContext) {
    if context.is_null() {
        return;
    }
    let result = catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: The caller contract requires a valid live context pointer.
        unsafe { (*context).inner.close_context() };
    }));
    if result.is_err() {
        std::process::abort();
    }
}

/// Returns the active context list head.
#[no_mangle]
pub extern "C" fn smb2_active_contexts() -> *mut Smb2RustContext {
    ptr::null_mut()
}

/// Returns whether the context is active.
///
/// # Safety
///
/// `context` must be null or a valid live pointer returned by [`smb2_init_context`].
#[no_mangle]
pub unsafe extern "C" fn smb2_context_active(context: *mut Smb2RustContext) -> i32 {
    if context.is_null() {
        return 0;
    }
    // SAFETY: The caller contract requires a valid live context pointer.
    i32::from(unsafe { (*context).inner.is_active() })
}

/// Releases a URL previously returned by [`smb2_parse_url`].
///
/// Passing a null pointer is allowed and has no effect.
///
/// # Safety
///
/// `url` must be either null or a pointer returned by [`smb2_parse_url`] that
/// has not already been passed to [`smb2_destroy_url`].
#[no_mangle]
pub unsafe extern "C" fn smb2_destroy_url(url: *mut Smb2RustUrl) {
    if url.is_null() {
        return;
    }

    let result = catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: The caller contract requires a unique URL pointer returned by
        // smb2_parse_url that has not already been destroyed.
        unsafe { drop(Box::from_raw(url)) };
    }));

    if result.is_err() {
        std::process::abort();
    }
}

/// Parses an SMB URL into a C-compatible `smb2_url` structure.
///
/// Returns null and records an error on invalid input.
///
/// # Safety
///
/// `context` must be null or a valid live pointer returned by
/// [`smb2_init_context`]. `url` must be a valid NUL-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn smb2_parse_url(
    context: *mut Smb2RustContext,
    url: *const c_char,
) -> *mut Smb2RustUrl {
    let result = catch_unwind(AssertUnwindSafe(|| {
        if context.is_null() {
            return ptr::null_mut();
        }

        // SAFETY: The caller contract requires a valid live context pointer.
        let context = unsafe { &mut *context };
        let Some(url) = (unsafe { c_string_arg(url) }) else {
            context.set_error("URL is not valid UTF-8 or is NULL");
            return ptr::null_mut();
        };

        match context.inner.parse_url(url).and_then(|parsed| {
            Smb2RustUrl::new(parsed).map_err(|()| libsmb2_rs::ErrorCode::from_errno(22))
        }) {
            Ok(parsed) => {
                context.clear_error();
                Box::into_raw(Box::new(parsed))
            }
            Err(_) => {
                context.sync_error_from_client();
                if context.error_string.as_bytes().is_empty() {
                    context.set_error("Failed to parse SMB URL");
                }
                ptr::null_mut()
            }
        }
    }));

    result.unwrap_or(ptr::null_mut())
}

/// Returns the last error string recorded on the context.
///
/// # Safety
///
/// `context` must be null or a valid live pointer returned by
/// [`smb2_init_context`].
#[no_mangle]
pub unsafe extern "C" fn smb2_get_error(context: *const Smb2RustContext) -> *const c_char {
    if context.is_null() {
        return c"".as_ptr();
    }

    // SAFETY: The caller contract requires a valid live context pointer.
    unsafe { (*context).error_string.as_ptr() }
}

/// Sets the SMB2 security mode on the Rust-backed context.
///
/// # Safety
///
/// `context` must be null or a valid live pointer returned by
/// [`smb2_init_context`].
#[no_mangle]
pub unsafe extern "C" fn smb2_set_security_mode(context: *mut Smb2RustContext, security_mode: u16) {
    if context.is_null() {
        return;
    }

    let result = catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: The caller contract requires a valid live context pointer.
        let context = unsafe { &mut *context };
        context.inner.set_security_mode(security_mode);
    }));

    if result.is_err() {
        std::process::abort();
    }
}

/// Sets the context timeout in seconds.
///
/// # Safety
///
/// `context` must be null or a valid live pointer returned by
/// [`smb2_init_context`].
#[no_mangle]
pub unsafe extern "C" fn smb2_set_timeout(context: *mut Smb2RustContext, seconds: i32) {
    if context.is_null() {
        return;
    }
    let result = catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: The caller contract requires a valid live context pointer.
        unsafe { (*context).inner.set_timeout(seconds) };
    }));
    if result.is_err() {
        std::process::abort();
    }
}

/// Sets passthrough mode on the context.
///
/// # Safety
///
/// `context` must be null or a valid live pointer returned by
/// [`smb2_init_context`].
#[no_mangle]
pub unsafe extern "C" fn smb2_set_passthrough(context: *mut Smb2RustContext, passthrough: i32) {
    if context.is_null() {
        return;
    }
    let result = catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: The caller contract requires a valid live context pointer.
        unsafe { (*context).inner.set_passthrough(passthrough != 0) };
    }));
    if result.is_err() {
        std::process::abort();
    }
}

/// Reads passthrough mode into the caller-provided output pointer.
///
/// # Safety
///
/// `context` and `passthrough` must be null or valid pointers for their roles.
#[no_mangle]
pub unsafe extern "C" fn smb2_get_passthrough(
    context: *mut Smb2RustContext,
    passthrough: *mut i32,
) {
    if context.is_null() || passthrough.is_null() {
        return;
    }
    let result = catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: Both pointers are checked above and must be valid by caller contract.
        unsafe { *passthrough = i32::from((*context).inner.passthrough()) };
    }));
    if result.is_err() {
        std::process::abort();
    }
}

/// Sets the SMB dialect negotiation selector.
///
/// # Safety
///
/// `context` must be null or a valid live pointer returned by
/// [`smb2_init_context`].
#[no_mangle]
pub unsafe extern "C" fn smb2_set_version(context: *mut Smb2RustContext, version: u16) {
    if context.is_null() {
        return;
    }
    let result = catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: The caller contract requires a valid live context pointer.
        unsafe {
            (*context).inner.set_version(
                libsmb2_rs::include::smb2::libsmb2::NegotiateVersion::from_raw(version),
            );
        }
    }));
    if result.is_err() {
        std::process::abort();
    }
}

/// Returns the currently recorded negotiated dialect.
///
/// # Safety
///
/// `context` must be null or a valid live pointer returned by
/// [`smb2_init_context`].
#[no_mangle]
pub unsafe extern "C" fn smb2_get_dialect(context: *const Smb2RustContext) -> u16 {
    if context.is_null() {
        return 0;
    }
    // SAFETY: The caller contract requires a valid live context pointer.
    unsafe { (*context).inner.dialect() }
}

/// Sets whether SMB3 sealing is requested.
///
/// # Safety
///
/// `context` must be null or a valid live pointer returned by
/// [`smb2_init_context`].
#[no_mangle]
pub unsafe extern "C" fn smb2_set_seal(context: *mut Smb2RustContext, val: i32) {
    if !context.is_null() {
        // SAFETY: The pointer is checked above and must be live by caller contract.
        unsafe { (*context).inner.set_seal(val != 0) };
    }
}

/// Sets whether SMB2 signing is required.
///
/// # Safety
///
/// `context` must be null or a valid live pointer returned by
/// [`smb2_init_context`].
#[no_mangle]
pub unsafe extern "C" fn smb2_set_sign(context: *mut Smb2RustContext, val: i32) {
    if !context.is_null() {
        // SAFETY: The pointer is checked above and must be live by caller contract.
        unsafe { (*context).inner.set_sign(val != 0) };
    }
}

/// Sets the authentication method selector.
///
/// # Safety
///
/// `context` must be null or a valid live pointer returned by
/// [`smb2_init_context`].
#[no_mangle]
pub unsafe extern "C" fn smb2_set_authentication(context: *mut Smb2RustContext, val: i32) {
    if context.is_null() {
        return;
    }
    let auth = match val {
        1 => libsmb2_rs::include::smb2::libsmb2::AuthenticationMethod::NtlmSsp,
        2 => libsmb2_rs::include::smb2::libsmb2::AuthenticationMethod::Krb5,
        _ => libsmb2_rs::include::smb2::libsmb2::AuthenticationMethod::Undefined,
    };
    // SAFETY: The pointer is checked above and must be live by caller contract.
    unsafe { (*context).inner.set_authentication(auth) };
}

/// Sets the username.
///
/// # Safety
///
/// `context` must be null or valid. `user` must be null or a valid C string.
#[no_mangle]
pub unsafe extern "C" fn smb2_set_user(context: *mut Smb2RustContext, user: *const c_char) {
    if context.is_null() {
        return;
    }
    let result = catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: The caller contract requires a valid live context pointer.
        let context = unsafe { &mut *context };
        if let Some(user) = unsafe { optional_c_string_arg(user) } {
            context.inner.set_user(user);
            context.user_string = Some(ffi_error_string(user));
        } else {
            context.user_string = None;
        }
    }));
    if result.is_err() {
        std::process::abort();
    }
}

/// Returns the configured username or null.
///
/// # Safety
///
/// `context` must be null or valid.
#[no_mangle]
pub unsafe extern "C" fn smb2_get_user(context: *const Smb2RustContext) -> *const c_char {
    if context.is_null() {
        return ptr::null();
    }
    // SAFETY: The caller contract requires a valid live context pointer.
    unsafe {
        (*context)
            .user_string
            .as_ref()
            .map_or(ptr::null(), |value| value.as_ptr())
    }
}

/// Sets the authentication password.
///
/// # Safety
///
/// `context` must be null or valid. `password` must be null or a valid C string.
#[no_mangle]
pub unsafe extern "C" fn smb2_set_password(context: *mut Smb2RustContext, password: *const c_char) {
    if context.is_null() {
        return;
    }
    let result = catch_unwind(AssertUnwindSafe(|| {
        let context = unsafe { &mut *context };
        if let Some(password) = unsafe { optional_c_string_arg(password) } {
            if context.inner.set_password(password).is_err() {
                context.set_error("password contains an interior NUL byte");
            }
        }
    }));
    if result.is_err() {
        std::process::abort();
    }
}

/// Sets the domain.
///
/// # Safety
///
/// `context` must be null or valid. `domain` must be null or a valid C string.
#[no_mangle]
pub unsafe extern "C" fn smb2_set_domain(context: *mut Smb2RustContext, domain: *const c_char) {
    if context.is_null() {
        return;
    }
    let context = unsafe { &mut *context };
    if let Some(domain) = unsafe { optional_c_string_arg(domain) } {
        context.inner.set_domain(domain);
        context.domain_string = Some(ffi_error_string(domain));
    } else {
        context.domain_string = None;
    }
}

/// Returns the configured domain or null.
///
/// # Safety
///
/// `context` must be null or valid.
#[no_mangle]
pub unsafe extern "C" fn smb2_get_domain(context: *const Smb2RustContext) -> *const c_char {
    if context.is_null() {
        return ptr::null();
    }
    unsafe {
        (*context)
            .domain_string
            .as_ref()
            .map_or(ptr::null(), |value| value.as_ptr())
    }
}

/// Sets the workstation.
///
/// # Safety
///
/// `context` must be null or valid. `workstation` must be null or a valid C string.
#[no_mangle]
pub unsafe extern "C" fn smb2_set_workstation(
    context: *mut Smb2RustContext,
    workstation: *const c_char,
) {
    if context.is_null() {
        return;
    }
    let context = unsafe { &mut *context };
    if let Some(workstation) = unsafe { optional_c_string_arg(workstation) } {
        context.inner.set_workstation(workstation);
        context.workstation_string = Some(ffi_error_string(workstation));
    } else {
        context.workstation_string = None;
    }
}

/// Returns the configured workstation or null.
///
/// # Safety
///
/// `context` must be null or valid.
#[no_mangle]
pub unsafe extern "C" fn smb2_get_workstation(context: *const Smb2RustContext) -> *const c_char {
    if context.is_null() {
        return ptr::null();
    }
    unsafe {
        (*context)
            .workstation_string
            .as_ref()
            .map_or(ptr::null(), |value| value.as_ptr())
    }
}

/// Sets user opaque data.
///
/// # Safety
///
/// `context` must be null or valid. `opaque` is stored but not dereferenced.
#[no_mangle]
pub unsafe extern "C" fn smb2_set_opaque(context: *mut Smb2RustContext, opaque: *mut c_void) {
    if !context.is_null() {
        unsafe { (*context).inner.set_opaque(Some(opaque as usize)) };
    }
}

/// Returns user opaque data.
///
/// # Safety
///
/// `context` must be null or valid.
#[no_mangle]
pub unsafe extern "C" fn smb2_get_opaque(context: *mut Smb2RustContext) -> *mut c_void {
    if context.is_null() {
        return ptr::null_mut();
    }
    unsafe {
        (*context)
            .inner
            .opaque()
            .map_or(ptr::null_mut(), |value| value as *mut c_void)
    }
}

/// Sets the client GUID bytes.
///
/// # Safety
///
/// `context` must be null or valid. `guid` must point to 16 bytes when non-null.
#[no_mangle]
pub unsafe extern "C" fn smb2_set_client_guid(context: *mut Smb2RustContext, guid: *const u8) {
    if context.is_null() || guid.is_null() {
        return;
    }
    let mut bytes = [0; 16];
    unsafe { ptr::copy_nonoverlapping(guid, bytes.as_mut_ptr(), bytes.len()) };
    unsafe {
        (*context).inner.set_client_guid(bytes);
        (*context).client_guid = Some(bytes);
    }
}

/// Writes the linked libsmb2-compatible version into `version`.
///
/// # Safety
///
/// `version` must be null or a valid output pointer.
#[no_mangle]
pub unsafe extern "C" fn smb2_get_libsmb2Version(version: *mut Smb2LibVersion) {
    if version.is_null() {
        return;
    }
    // SAFETY: The pointer is checked above and must be valid by caller contract.
    unsafe {
        *version = Smb2LibVersion {
            major_version: 4,
            minor_version: 0,
            patch_version: 0,
        };
    }
}

/// Registers an error callback.
///
/// # Safety
///
/// `context` must be null or valid.
#[no_mangle]
pub unsafe extern "C" fn smb2_register_error_callback(
    context: *mut Smb2RustContext,
    error_cb: Smb2ErrorCallback,
) {
    if !context.is_null() {
        unsafe { (*context).error_callback = error_cb };
    }
}

/// Registers an oplock or lease-break callback.
///
/// # Safety
///
/// `context` must be null or valid.
#[no_mangle]
pub unsafe extern "C" fn smb2_set_oplock_or_lease_break_callback(
    context: *mut Smb2RustContext,
    cb: Smb2OplockOrLeaseBreakCallback,
) {
    if !context.is_null() {
        unsafe { (*context).oplock_or_lease_break_callback = cb };
    }
}

/// Marks password-from-file resolution for the context.
///
/// # Safety
///
/// `context` must be null or valid.
#[no_mangle]
pub unsafe extern "C" fn smb2_set_password_from_file(context: *mut Smb2RustContext) {
    if !context.is_null() {
        unsafe { (*context).inner.set_password_from_file() };
    }
}

/// Delegates credentials from one context to another.
///
/// # Safety
///
/// `input` and `output` must be null or valid context pointers.
#[no_mangle]
pub unsafe extern "C" fn smb2_delegate_credentials(
    input: *mut Smb2RustContext,
    output: *mut Smb2RustContext,
) -> i32 {
    if input.is_null() || output.is_null() {
        return -1;
    }
    let input_ref = unsafe { &mut *input };
    let output_ref = unsafe { &mut *output };
    match input_ref.inner.delegate_credentials(&mut output_ref.inner) {
        Ok(()) => 0,
        Err(_) => -1,
    }
}

/// Returns a pointer to the configured 16-byte client GUID or null.
///
/// # Safety
///
/// `context` must be null or valid.
#[no_mangle]
pub unsafe extern "C" fn smb2_get_client_guid(context: *const Smb2RustContext) -> *const c_char {
    if context.is_null() {
        return ptr::null();
    }
    unsafe {
        (*context)
            .client_guid
            .as_ref()
            .map_or(ptr::null(), |guid| guid.as_ptr().cast::<c_char>())
    }
}

/// Connects the Rust-backed context to a share through the local sync skeleton.
///
/// Returns `0` on success or a negative errno-compatible code on failure.
///
/// # Safety
///
/// `context` must be null or a valid live pointer returned by
/// [`smb2_init_context`]. String pointers must be null or valid
/// NUL-terminated C strings as required by the legacy API.
#[no_mangle]
pub unsafe extern "C" fn smb2_connect_share(
    context: *mut Smb2RustContext,
    server: *const c_char,
    share: *const c_char,
    user: *const c_char,
) -> i32 {
    let result = catch_unwind(AssertUnwindSafe(|| {
        if context.is_null() {
            return invalid_argument_code();
        }

        // SAFETY: The caller contract requires a valid live context pointer.
        let context = unsafe { &mut *context };
        let server = match unsafe { required_c_string_arg(context, "server", server) } {
            Ok(server) => server,
            Err(code) => return code,
        };
        let share = match unsafe { required_c_string_arg(context, "share", share) } {
            Ok(share) => share,
            Err(code) => return code,
        };
        let user = unsafe { optional_c_string_arg(user) };
        let result = sync::smb2_connect_share(&mut context.inner, server, share, user);
        context.finish_status(result)
    }));

    result.unwrap_or_else(|_| invalid_argument_code())
}

/// Queues an asynchronous share connection.
///
/// # Safety
///
/// `context` must be valid. String pointers must be valid C strings when non-null.
#[no_mangle]
pub unsafe extern "C" fn smb2_connect_share_async(
    context: *mut Smb2RustContext,
    server: *const c_char,
    share: *const c_char,
    user: *const c_char,
    cb: Smb2CommandCallback,
    cb_data: *mut c_void,
) -> i32 {
    let result = catch_unwind(AssertUnwindSafe(|| {
        if context.is_null() {
            return invalid_argument_code();
        }
        let context_ref = unsafe { &mut *context };
        let server = match unsafe { required_c_string_arg(context_ref, "server", server) } {
            Ok(server) => server,
            Err(code) => return code,
        };
        let share = match unsafe { required_c_string_arg(context_ref, "share", share) } {
            Ok(share) => share,
            Err(code) => return code,
        };
        let user = unsafe { optional_c_string_arg(user) };
        context_ref.inner.connect_share_async(server, share, user);
        let message_id = context_ref.inner.last_request_message_id();
        context_ref.push_callback(
            message_id,
            PendingCallbackKind::StatusOnly,
            cb,
            cb_data,
            None,
        );
        0
    }));
    result.unwrap_or_else(|_| invalid_argument_code())
}

/// Queues an asynchronous TCP connect placeholder.
///
/// # Safety
///
/// `context` must be valid. `server` must be a valid C string.
#[no_mangle]
pub unsafe extern "C" fn smb2_connect_async(
    context: *mut Smb2RustContext,
    server: *const c_char,
    cb: Smb2CommandCallback,
    cb_data: *mut c_void,
) -> i32 {
    let result = catch_unwind(AssertUnwindSafe(|| {
        if context.is_null() {
            return invalid_argument_code();
        }
        let context_ref = unsafe { &mut *context };
        let server = match unsafe { required_c_string_arg(context_ref, "server", server) } {
            Ok(server) => server,
            Err(code) => return code,
        };
        context_ref.inner.connect_async(server);
        let message_id = context_ref.inner.last_request_message_id();
        context_ref.push_callback(
            message_id,
            PendingCallbackKind::StatusOnly,
            cb,
            cb_data,
            None,
        );
        0
    }));
    result.unwrap_or_else(|_| invalid_argument_code())
}

/// Disconnects the Rust-backed context from the current share.
///
/// Returns `0` on success or a negative errno-compatible code on failure.
///
/// # Safety
///
/// `context` must be null or a valid live pointer returned by
/// [`smb2_init_context`].
#[no_mangle]
pub unsafe extern "C" fn smb2_disconnect_share(context: *mut Smb2RustContext) -> i32 {
    let result = catch_unwind(AssertUnwindSafe(|| {
        if context.is_null() {
            return invalid_argument_code();
        }

        // SAFETY: The caller contract requires a valid live context pointer.
        let context = unsafe { &mut *context };
        let result = sync::smb2_disconnect_share(&mut context.inner);
        context.finish_status(result)
    }));

    result.unwrap_or_else(|_| invalid_argument_code())
}

/// Queues an asynchronous share disconnect.
///
/// # Safety
///
/// `context` must be valid when non-null.
#[no_mangle]
pub unsafe extern "C" fn smb2_disconnect_share_async(
    context: *mut Smb2RustContext,
    cb: Smb2CommandCallback,
    cb_data: *mut c_void,
) -> i32 {
    let result = catch_unwind(AssertUnwindSafe(|| {
        if context.is_null() {
            return invalid_argument_code();
        }
        let context_ref = unsafe { &mut *context };
        match context_ref.inner.disconnect_share() {
            Ok(()) => {
                let message_id = context_ref.inner.last_request_message_id();
                context_ref.push_callback(
                    message_id,
                    PendingCallbackKind::StatusOnly,
                    cb,
                    cb_data,
                    None,
                );
                0
            }
            Err(error) => result_code::<()>(context_ref, Err(error)),
        }
    }));
    result.unwrap_or_else(|_| invalid_argument_code())
}

/// Returns the primary file descriptor used by the context.
///
/// # Safety
///
/// `context` must be valid when non-null.
#[no_mangle]
pub unsafe extern "C" fn smb2_get_fd(context: *const Smb2RustContext) -> i32 {
    if context.is_null() {
        return -1;
    }
    let context = context.cast_mut();
    if !unsafe { (*context).inner.is_active() } {
        return -1;
    }
    unsafe { (*context).ensure_wake_fd() }
}

/// Returns the event mask requested by the context.
///
/// # Safety
///
/// `context` must be valid when non-null.
#[no_mangle]
pub unsafe extern "C" fn smb2_which_events(context: *const Smb2RustContext) -> i32 {
    if context.is_null() {
        return 0;
    }
    let context = unsafe { &*context };
    if !context.pending_callbacks.is_empty() || context.wake_pending {
        0x0001
    } else {
        context.inner.which_events()
    }
}

/// Services queued asynchronous work and dispatches completed callbacks.
///
/// # Safety
///
/// `context` must be valid when non-null.
#[no_mangle]
pub unsafe extern "C" fn smb2_service(context: *mut Smb2RustContext, revents: i32) -> i32 {
    let result = catch_unwind(AssertUnwindSafe(|| {
        if context.is_null() {
            return invalid_argument_code();
        }
        let context_ref = unsafe { &mut *context };
        if context_ref.wake_read_fd >= 0 && revents & 0x0001 != 0 {
            context_ref.drain_local_wake();
        }
        match context_ref.inner.service_local_ready() {
            Ok(()) => {
                context_ref.dispatch_completed_callbacks(context);
                if !context_ref.pending_callbacks.is_empty() {
                    context_ref.wake_local_service();
                }
                0
            }
            Err(error) => result_code::<()>(context_ref, Err(error)),
        }
    }));
    result.unwrap_or_else(|_| invalid_argument_code())
}

/// Services queued asynchronous work for a specific descriptor.
///
/// # Safety
///
/// `context` must be valid when non-null.
#[no_mangle]
pub unsafe extern "C" fn smb2_service_fd(
    context: *mut Smb2RustContext,
    fd: i32,
    revents: i32,
) -> i32 {
    let result = catch_unwind(AssertUnwindSafe(|| {
        if context.is_null() {
            return invalid_argument_code();
        }
        let context_ref = unsafe { &mut *context };
        if fd != -1 && fd != context_ref.wake_read_fd && fd != context_ref.inner.fd() {
            context_ref.set_error("unknown file descriptor");
            return invalid_argument_code();
        }
        if context_ref.wake_read_fd >= 0 && revents & 0x0001 != 0 {
            context_ref.drain_local_wake();
        }
        match context_ref.inner.service_local_ready() {
            Ok(()) => {
                context_ref.dispatch_completed_callbacks(context);
                if !context_ref.pending_callbacks.is_empty() {
                    context_ref.wake_local_service();
                }
                0
            }
            Err(error) => result_code::<()>(context_ref, Err(error)),
        }
    }));
    result.unwrap_or_else(|_| invalid_argument_code())
}

/// Returns all known fds and timeout.
///
/// # Safety
///
/// `context`, `fd_count`, and `timeout` must be null or valid for their roles.
#[no_mangle]
pub unsafe extern "C" fn smb2_get_fds(
    context: *mut Smb2RustContext,
    fd_count: *mut usize,
    timeout: *mut i32,
) -> *const i32 {
    if context.is_null() {
        if !fd_count.is_null() {
            unsafe { *fd_count = 0 };
        }
        if !timeout.is_null() {
            unsafe { *timeout = -1 };
        }
        return ptr::null();
    }
    let context_ref = unsafe { &mut *context };
    context_ref.fd_storage[0] = context_ref.ensure_wake_fd();
    let count = usize::from(context_ref.fd_storage[0] >= 0);
    if !fd_count.is_null() {
        unsafe { *fd_count = count };
    }
    if !timeout.is_null() {
        unsafe { *timeout = -1 };
    }
    if count == 0 {
        ptr::null()
    } else {
        context_ref.fd_storage.as_ptr()
    }
}

/// Registers fd event callbacks.
///
/// # Safety
///
/// `context` must be null or valid.
#[no_mangle]
pub unsafe extern "C" fn smb2_fd_event_callbacks(
    context: *mut Smb2RustContext,
    change_fd: Smb2ChangeFdCallback,
    change_events: Smb2ChangeEventsCallback,
) {
    if !context.is_null() {
        unsafe {
            (*context).change_fd_callback = change_fd;
            (*context).change_events_callback = change_events;
        }
    }
}

/// Creates a directory through the Rust-backed local sync skeleton.
///
/// Returns `0` on success or a negative errno-compatible code on failure.
///
/// # Safety
///
/// `context` must be null or a valid live pointer returned by
/// [`smb2_init_context`]. `path` must be a valid NUL-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn smb2_mkdir(context: *mut Smb2RustContext, path: *const c_char) -> i32 {
    let result = catch_unwind(AssertUnwindSafe(|| {
        if context.is_null() {
            return invalid_argument_code();
        }

        // SAFETY: The caller contract requires a valid live context pointer.
        let context = unsafe { &mut *context };
        let path = match unsafe { required_c_string_arg(context, "path", path) } {
            Ok(path) => path,
            Err(code) => return code,
        };
        let result = sync::smb2_mkdir(&mut context.inner, path);
        context.finish_status(result)
    }));

    result.unwrap_or_else(|_| invalid_argument_code())
}

/// Removes a directory through the Rust-backed local sync skeleton.
///
/// Returns `0` on success or a negative errno-compatible code on failure.
///
/// # Safety
///
/// `context` must be null or a valid live pointer returned by
/// [`smb2_init_context`]. `path` must be a valid NUL-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn smb2_rmdir(context: *mut Smb2RustContext, path: *const c_char) -> i32 {
    let result = catch_unwind(AssertUnwindSafe(|| {
        if context.is_null() {
            return invalid_argument_code();
        }

        // SAFETY: The caller contract requires a valid live context pointer.
        let context = unsafe { &mut *context };
        let path = match unsafe { required_c_string_arg(context, "path", path) } {
            Ok(path) => path,
            Err(code) => return code,
        };
        let result = sync::smb2_rmdir(&mut context.inner, path);
        context.finish_status(result)
    }));

    result.unwrap_or_else(|_| invalid_argument_code())
}

/// Opens a directory synchronously.
///
/// # Safety
///
/// `context` must be valid and `path` must be a valid C string.
#[no_mangle]
pub unsafe extern "C" fn smb2_opendir(
    context: *mut Smb2RustContext,
    path: *const c_char,
) -> *mut Smb2RustDir {
    let result = catch_unwind(AssertUnwindSafe(|| {
        if context.is_null() {
            return ptr::null_mut();
        }
        let context_ref = unsafe { &mut *context };
        let path = match unsafe { required_c_string_arg(context_ref, "path", path) } {
            Ok(path) => path,
            Err(_) => return ptr::null_mut(),
        };
        match sync::smb2_opendir(&mut context_ref.inner, path) {
            Ok(request) => match sync_payload_dir(request.payload().clone()) {
                Some(dir) => Box::into_raw(Box::new(dir)),
                None => last_directory_result(context_ref)
                    .map_or(ptr::null_mut(), |dir| Box::into_raw(Box::new(dir))),
            },
            Err(error) => {
                result_code::<()>(context_ref, Err(error));
                ptr::null_mut()
            }
        }
    }));
    result.unwrap_or(ptr::null_mut())
}

/// Queues an asynchronous opendir operation and returns its cancel handle.
///
/// # Safety
///
/// `context` must be valid and `path` must be a valid C string.
#[no_mangle]
pub unsafe extern "C" fn smb2_opendir_async_pdu(
    context: *mut Smb2RustContext,
    path: *const c_char,
    cb: Smb2CommandCallback,
    cb_data: *mut c_void,
    free_cb: Option<unsafe extern "C" fn(*mut c_void)>,
) -> *mut Smb2RustPdu {
    let result = catch_unwind(AssertUnwindSafe(|| {
        if context.is_null() {
            return ptr::null_mut();
        }
        let context_ref = unsafe { &mut *context };
        let path = match unsafe { required_c_string_arg(context_ref, "path", path) } {
            Ok(path) => path,
            Err(_) => return ptr::null_mut(),
        };
        let before = context_ref.inner.last_request_message_id();
        context_ref.inner.opendir_async(path);
        queue_pdu_callback(
            context_ref,
            before,
            PendingCallbackKind::OpenDir,
            cb,
            cb_data,
            free_cb,
        )
    }));
    result.unwrap_or(ptr::null_mut())
}

/// Queues an asynchronous opendir operation.
///
/// # Safety
///
/// `context` must be valid and `path` must be a valid C string.
#[no_mangle]
pub unsafe extern "C" fn smb2_opendir_async(
    context: *mut Smb2RustContext,
    path: *const c_char,
    cb: Smb2CommandCallback,
    cb_data: *mut c_void,
) -> i32 {
    let pdu = unsafe { smb2_opendir_async_pdu(context, path, cb, cb_data, None) };
    if pdu.is_null() {
        invalid_argument_code()
    } else {
        0
    }
}

/// Closes a directory handle.
///
/// # Safety
///
/// `dir` must be null or a pointer returned by this facade.
#[no_mangle]
pub unsafe extern "C" fn smb2_closedir(_context: *mut Smb2RustContext, dir: *mut Smb2RustDir) {
    if !dir.is_null() {
        unsafe { drop(Box::from_raw(dir)) };
    }
}

/// Reads the next directory entry.
///
/// # Safety
///
/// `dir` must be null or a valid directory pointer returned by this facade.
#[no_mangle]
pub unsafe extern "C" fn smb2_readdir(
    _context: *mut Smb2RustContext,
    dir: *mut Smb2RustDir,
) -> *mut Smb2Dirent {
    if dir.is_null() {
        return ptr::null_mut();
    }
    let dir = unsafe { &mut *dir };
    let Some(entry) = dir.entries.get_mut(dir.index) else {
        return ptr::null_mut();
    };
    dir.index += 1;
    (&mut entry.entry) as *mut Smb2Dirent
}

/// Rewinds a directory cursor.
///
/// # Safety
///
/// `dir` must be null or a valid directory pointer returned by this facade.
#[no_mangle]
pub unsafe extern "C" fn smb2_rewinddir(_context: *mut Smb2RustContext, dir: *mut Smb2RustDir) {
    if !dir.is_null() {
        unsafe { (*dir).index = 0 };
    }
}

/// Returns the current directory cursor position.
///
/// # Safety
///
/// `dir` must be null or a valid directory pointer returned by this facade.
#[no_mangle]
pub unsafe extern "C" fn smb2_telldir(
    _context: *mut Smb2RustContext,
    dir: *mut Smb2RustDir,
) -> isize {
    if dir.is_null() {
        return 0;
    }
    unsafe { (*dir).index as isize }
}

/// Sets the directory cursor position.
///
/// # Safety
///
/// `dir` must be null or a valid directory pointer returned by this facade.
#[no_mangle]
pub unsafe extern "C" fn smb2_seekdir(
    _context: *mut Smb2RustContext,
    dir: *mut Smb2RustDir,
    loc: isize,
) {
    if !dir.is_null() {
        let loc = usize::try_from(loc).unwrap_or(0);
        unsafe { (*dir).index = loc.min((*dir).entries.len()) };
    }
}

/// Opens a file synchronously.
///
/// # Safety
///
/// `context` must be valid and `path` must be a valid C string.
#[no_mangle]
pub unsafe extern "C" fn smb2_open(
    context: *mut Smb2RustContext,
    path: *const c_char,
    flags: i32,
) -> *mut Smb2RustFileHandle {
    let result = catch_unwind(AssertUnwindSafe(|| {
        if context.is_null() {
            return ptr::null_mut();
        }
        let context_ref = unsafe { &mut *context };
        let path = match unsafe { required_c_string_arg(context_ref, "path", path) } {
            Ok(path) => path,
            Err(_) => return ptr::null_mut(),
        };
        match sync::smb2_open(&mut context_ref.inner, path, flags) {
            Ok(request) => {
                sync_payload_file(request.payload().clone()).map_or(ptr::null_mut(), |handle| {
                    Box::into_raw(Box::new(Smb2RustFileHandle {
                        file_id: handle.id(),
                        inner: handle,
                    }))
                })
            }
            Err(error) => {
                result_code::<()>(context_ref, Err(error));
                ptr::null_mut()
            }
        }
    }));
    result.unwrap_or(ptr::null_mut())
}

/// Queues an async open operation and returns its cancel handle.
///
/// # Safety
///
/// `context` must be valid and `path` must be a valid C string.
#[no_mangle]
pub unsafe extern "C" fn smb2_open_async_pdu(
    context: *mut Smb2RustContext,
    path: *const c_char,
    flags: i32,
    cb: Smb2CommandCallback,
    cb_data: *mut c_void,
    free_cb: Option<unsafe extern "C" fn(*mut c_void)>,
) -> *mut Smb2RustPdu {
    let result = catch_unwind(AssertUnwindSafe(|| {
        if context.is_null() {
            return ptr::null_mut();
        }
        let context_ref = unsafe { &mut *context };
        let path = match unsafe { required_c_string_arg(context_ref, "path", path) } {
            Ok(path) => path,
            Err(_) => return ptr::null_mut(),
        };
        let before = context_ref.inner.last_request_message_id();
        context_ref.inner.open_async(path, flags);
        queue_pdu_callback(
            context_ref,
            before,
            PendingCallbackKind::Open,
            cb,
            cb_data,
            free_cb,
        )
    }));
    result.unwrap_or(ptr::null_mut())
}

/// Queues an async open operation.
///
/// # Safety
///
/// `context` must be valid and `path` must be a valid C string.
#[no_mangle]
pub unsafe extern "C" fn smb2_open_async(
    context: *mut Smb2RustContext,
    path: *const c_char,
    flags: i32,
    cb: Smb2CommandCallback,
    cb_data: *mut c_void,
) -> i32 {
    let pdu = unsafe { smb2_open_async_pdu(context, path, flags, cb, cb_data, None) };
    if pdu.is_null() {
        invalid_argument_code()
    } else {
        0
    }
}

/// Closes a file handle synchronously.
///
/// # Safety
///
/// `fh` must be null or a pointer returned by this facade.
#[no_mangle]
pub unsafe extern "C" fn smb2_close(
    context: *mut Smb2RustContext,
    fh: *mut Smb2RustFileHandle,
) -> i32 {
    let result = catch_unwind(AssertUnwindSafe(|| {
        if context.is_null() || fh.is_null() {
            return invalid_argument_code();
        }
        let context_ref = unsafe { &mut *context };
        let handle = unsafe { Box::from_raw(fh) };
        let close_result = sync::smb2_close(&mut context_ref.inner, &handle.inner);
        result_code(context_ref, close_result)
    }));
    result.unwrap_or_else(|_| invalid_argument_code())
}

/// Queues an async close operation.
///
/// # Safety
///
/// `fh` must be a live file handle pointer.
#[no_mangle]
pub unsafe extern "C" fn smb2_close_async(
    context: *mut Smb2RustContext,
    fh: *mut Smb2RustFileHandle,
    cb: Smb2CommandCallback,
    cb_data: *mut c_void,
) -> i32 {
    let result = catch_unwind(AssertUnwindSafe(|| {
        if context.is_null() || fh.is_null() {
            return invalid_argument_code();
        }
        let context_ref = unsafe { &mut *context };
        let handle = unsafe { &*fh };
        context_ref.inner.close_async(&handle.inner);
        let message_id = context_ref.inner.last_request_message_id();
        context_ref.push_callback(
            message_id,
            PendingCallbackKind::StatusOnly,
            cb,
            cb_data,
            None,
        );
        0
    }));
    result.unwrap_or_else(|_| invalid_argument_code())
}

/// Reads from a file handle at an explicit offset.
///
/// # Safety
///
/// `fh` and `buf` must be valid for the requested operation.
#[no_mangle]
pub unsafe extern "C" fn smb2_pread(
    context: *mut Smb2RustContext,
    fh: *mut Smb2RustFileHandle,
    buf: *mut u8,
    count: u32,
    offset: u64,
) -> i32 {
    let result = catch_unwind(AssertUnwindSafe(|| {
        if context.is_null() || fh.is_null() || (buf.is_null() && count != 0) {
            return invalid_argument_code();
        }
        let context_ref = unsafe { &mut *context };
        let handle = unsafe { &*fh };
        match context_ref.inner.pread(&handle.inner, count, offset) {
            Ok(data) => {
                if !buf.is_null() && !data.is_empty() {
                    unsafe { ptr::copy_nonoverlapping(data.as_ptr(), buf, data.len()) };
                }
                data.len().try_into().unwrap_or(i32::MAX)
            }
            Err(error) => result_code::<()>(context_ref, Err(error)),
        }
    }));
    result.unwrap_or_else(|_| invalid_argument_code())
}

/// Queues an async positioned read.
///
/// # Safety
///
/// `fh` and `buf` must be valid for the requested operation.
#[no_mangle]
pub unsafe extern "C" fn smb2_pread_async(
    context: *mut Smb2RustContext,
    fh: *mut Smb2RustFileHandle,
    buf: *mut u8,
    count: u32,
    offset: u64,
    cb: Smb2CommandCallback,
    cb_data: *mut c_void,
) -> i32 {
    let result = catch_unwind(AssertUnwindSafe(|| {
        if context.is_null() || fh.is_null() || (buf.is_null() && count != 0) {
            return invalid_argument_code();
        }
        let context_ref = unsafe { &mut *context };
        let handle = unsafe { &*fh };
        context_ref.inner.pread_async(&handle.inner, count, offset);
        let message_id = context_ref.inner.last_request_message_id();
        context_ref.push_callback(
            message_id,
            PendingCallbackKind::Read { buf, count, offset },
            cb,
            cb_data,
            None,
        );
        0
    }));
    result.unwrap_or_else(|_| invalid_argument_code())
}

/// Reads from the current file offset.
///
/// # Safety
///
/// `fh` and `buf` must be valid for the requested operation.
#[no_mangle]
pub unsafe extern "C" fn smb2_read(
    context: *mut Smb2RustContext,
    fh: *mut Smb2RustFileHandle,
    buf: *mut u8,
    count: u32,
) -> i32 {
    unsafe { smb2_pread(context, fh, buf, count, 0) }
}

/// Queues an async sequential read.
///
/// # Safety
///
/// `fh` and `buf` must be valid for the requested operation.
#[no_mangle]
pub unsafe extern "C" fn smb2_read_async(
    context: *mut Smb2RustContext,
    fh: *mut Smb2RustFileHandle,
    buf: *mut u8,
    count: u32,
    cb: Smb2CommandCallback,
    cb_data: *mut c_void,
) -> i32 {
    unsafe { smb2_pread_async(context, fh, buf, count, 0, cb, cb_data) }
}

/// Writes bytes at an explicit offset.
///
/// # Safety
///
/// `fh` and `buf` must be valid for the requested operation.
#[no_mangle]
pub unsafe extern "C" fn smb2_pwrite(
    context: *mut Smb2RustContext,
    fh: *mut Smb2RustFileHandle,
    buf: *const u8,
    count: u32,
    offset: u64,
) -> i32 {
    let _ = buf;
    let result = catch_unwind(AssertUnwindSafe(|| {
        if context.is_null() || fh.is_null() {
            return invalid_argument_code();
        }
        let context_ref = unsafe { &mut *context };
        let handle = unsafe { &*fh };
        match context_ref.inner.pwrite(&handle.inner, count, offset) {
            Ok(written) => i32::try_from(written).unwrap_or(i32::MAX),
            Err(error) => result_code::<()>(context_ref, Err(error)),
        }
    }));
    result.unwrap_or_else(|_| invalid_argument_code())
}

/// Queues an async positioned write.
///
/// # Safety
///
/// `fh` and `buf` must be valid for the requested operation.
#[no_mangle]
pub unsafe extern "C" fn smb2_pwrite_async(
    context: *mut Smb2RustContext,
    fh: *mut Smb2RustFileHandle,
    buf: *const u8,
    count: u32,
    offset: u64,
    cb: Smb2CommandCallback,
    cb_data: *mut c_void,
) -> i32 {
    let _ = buf;
    let result = catch_unwind(AssertUnwindSafe(|| {
        if context.is_null() || fh.is_null() {
            return invalid_argument_code();
        }
        let context_ref = unsafe { &mut *context };
        let handle = unsafe { &*fh };
        context_ref.inner.pwrite_async(&handle.inner, count, offset);
        let message_id = context_ref.inner.last_request_message_id();
        context_ref.push_callback(
            message_id,
            PendingCallbackKind::Write { count, offset },
            cb,
            cb_data,
            None,
        );
        0
    }));
    result.unwrap_or_else(|_| invalid_argument_code())
}

/// Writes bytes at the current file offset.
///
/// # Safety
///
/// `fh` and `buf` must be valid for the requested operation.
#[no_mangle]
pub unsafe extern "C" fn smb2_write(
    context: *mut Smb2RustContext,
    fh: *mut Smb2RustFileHandle,
    buf: *const u8,
    count: u32,
) -> i32 {
    unsafe { smb2_pwrite(context, fh, buf, count, 0) }
}

/// Queues an async sequential write.
///
/// # Safety
///
/// `fh` and `buf` must be valid for the requested operation.
#[no_mangle]
pub unsafe extern "C" fn smb2_write_async(
    context: *mut Smb2RustContext,
    fh: *mut Smb2RustFileHandle,
    buf: *const u8,
    count: u32,
    cb: Smb2CommandCallback,
    cb_data: *mut c_void,
) -> i32 {
    unsafe { smb2_pwrite_async(context, fh, buf, count, 0, cb, cb_data) }
}

/// Cancels and releases a PDU handle.
///
/// # Safety
///
/// `pdu` must be null or a pointer returned by this facade.
#[no_mangle]
pub unsafe extern "C" fn smb2_free_pdu(context: *mut Smb2RustContext, pdu: *mut Smb2RustPdu) {
    if pdu.is_null() {
        return;
    }
    let pdu_box = unsafe { Box::from_raw(pdu) };
    if !context.is_null() {
        unsafe { (*context).cancel_callback(pdu_box.message_id) };
    }
}

/// Removes a file path synchronously.
///
/// # Safety
///
/// `context` must be valid and `path` must be a valid C string.
#[no_mangle]
pub unsafe extern "C" fn smb2_unlink(context: *mut Smb2RustContext, path: *const c_char) -> i32 {
    let result = catch_unwind(AssertUnwindSafe(|| {
        if context.is_null() {
            return invalid_argument_code();
        }
        let context_ref = unsafe { &mut *context };
        let path = match unsafe { required_c_string_arg(context_ref, "path", path) } {
            Ok(path) => path,
            Err(code) => return code,
        };
        let unlink_result = sync::smb2_unlink(&mut context_ref.inner, path);
        result_code(context_ref, unlink_result)
    }));
    result.unwrap_or_else(|_| invalid_argument_code())
}

/// Queues an async unlink operation.
///
/// # Safety
///
/// `context` must be valid and `path` must be a valid C string.
#[no_mangle]
pub unsafe extern "C" fn smb2_unlink_async(
    context: *mut Smb2RustContext,
    path: *const c_char,
    cb: Smb2CommandCallback,
    cb_data: *mut c_void,
) -> i32 {
    let result = catch_unwind(AssertUnwindSafe(|| {
        if context.is_null() {
            return invalid_argument_code();
        }
        let context_ref = unsafe { &mut *context };
        let path = match unsafe { required_c_string_arg(context_ref, "path", path) } {
            Ok(path) => path,
            Err(code) => return code,
        };
        context_ref.inner.unlink_async(path);
        let message_id = context_ref.inner.last_request_message_id();
        context_ref.push_callback(
            message_id,
            PendingCallbackKind::StatusOnly,
            cb,
            cb_data,
            None,
        );
        0
    }));
    result.unwrap_or_else(|_| invalid_argument_code())
}

/// Queues an async rmdir operation.
///
/// # Safety
///
/// `context` must be valid and `path` must be a valid C string.
#[no_mangle]
pub unsafe extern "C" fn smb2_rmdir_async(
    context: *mut Smb2RustContext,
    path: *const c_char,
    cb: Smb2CommandCallback,
    cb_data: *mut c_void,
) -> i32 {
    let result = catch_unwind(AssertUnwindSafe(|| {
        if context.is_null() {
            return invalid_argument_code();
        }
        let context_ref = unsafe { &mut *context };
        let path = match unsafe { required_c_string_arg(context_ref, "path", path) } {
            Ok(path) => path,
            Err(code) => return code,
        };
        context_ref.inner.rmdir_async(path);
        let message_id = context_ref.inner.last_request_message_id();
        context_ref.push_callback(
            message_id,
            PendingCallbackKind::StatusOnly,
            cb,
            cb_data,
            None,
        );
        0
    }));
    result.unwrap_or_else(|_| invalid_argument_code())
}

/// Queues an async mkdir operation.
///
/// # Safety
///
/// `context` must be valid and `path` must be a valid C string.
#[no_mangle]
pub unsafe extern "C" fn smb2_mkdir_async(
    context: *mut Smb2RustContext,
    path: *const c_char,
    cb: Smb2CommandCallback,
    cb_data: *mut c_void,
) -> i32 {
    let result = catch_unwind(AssertUnwindSafe(|| {
        if context.is_null() {
            return invalid_argument_code();
        }
        let context_ref = unsafe { &mut *context };
        let path = match unsafe { required_c_string_arg(context_ref, "path", path) } {
            Ok(path) => path,
            Err(code) => return code,
        };
        context_ref.inner.mkdir_async(path);
        let message_id = context_ref.inner.last_request_message_id();
        context_ref.push_callback(
            message_id,
            PendingCallbackKind::StatusOnly,
            cb,
            cb_data,
            None,
        );
        0
    }));
    result.unwrap_or_else(|_| invalid_argument_code())
}

/// Gets file metadata synchronously.
///
/// # Safety
///
/// `context`, `path`, and `st` must be valid for their roles.
#[no_mangle]
pub unsafe extern "C" fn smb2_stat(
    context: *mut Smb2RustContext,
    path: *const c_char,
    st: *mut Smb2Stat64,
) -> i32 {
    let result = catch_unwind(AssertUnwindSafe(|| {
        if context.is_null() || st.is_null() {
            return invalid_argument_code();
        }
        let context_ref = unsafe { &mut *context };
        let path = match unsafe { required_c_string_arg(context_ref, "path", path) } {
            Ok(path) => path,
            Err(code) => return code,
        };
        match context_ref.inner.stat(path) {
            Ok(stat) => write_stat(st, stat),
            Err(error) => result_code::<()>(context_ref, Err(error)),
        }
    }));
    result.unwrap_or_else(|_| invalid_argument_code())
}

/// Queues an async stat operation.
///
/// # Safety
///
/// `context`, `path`, and `st` must be valid for their roles.
#[no_mangle]
pub unsafe extern "C" fn smb2_stat_async(
    context: *mut Smb2RustContext,
    path: *const c_char,
    st: *mut Smb2Stat64,
    cb: Smb2CommandCallback,
    cb_data: *mut c_void,
) -> i32 {
    let result = catch_unwind(AssertUnwindSafe(|| {
        if context.is_null() || st.is_null() {
            return invalid_argument_code();
        }
        let context_ref = unsafe { &mut *context };
        let path = match unsafe { required_c_string_arg(context_ref, "path", path) } {
            Ok(path) => path,
            Err(code) => return code,
        };
        context_ref.inner.stat_async(path);
        let message_id = context_ref.inner.last_request_message_id();
        context_ref.push_callback(
            message_id,
            PendingCallbackKind::Stat { out: st },
            cb,
            cb_data,
            None,
        );
        0
    }));
    result.unwrap_or_else(|_| invalid_argument_code())
}

/// Gets filesystem metadata synchronously.
///
/// # Safety
///
/// `context`, `path`, and `statvfs` must be valid for their roles.
#[no_mangle]
pub unsafe extern "C" fn smb2_statvfs(
    context: *mut Smb2RustContext,
    path: *const c_char,
    statvfs: *mut Smb2StatVfs,
) -> i32 {
    let result = catch_unwind(AssertUnwindSafe(|| {
        if context.is_null() || statvfs.is_null() {
            return invalid_argument_code();
        }
        let context_ref = unsafe { &mut *context };
        let path = match unsafe { required_c_string_arg(context_ref, "path", path) } {
            Ok(path) => path,
            Err(code) => return code,
        };
        match context_ref.inner.statvfs(path) {
            Ok(stat) => write_statvfs(statvfs, stat),
            Err(error) => result_code::<()>(context_ref, Err(error)),
        }
    }));
    result.unwrap_or_else(|_| invalid_argument_code())
}

/// Queues an async statvfs operation.
///
/// # Safety
///
/// `context`, `path`, and `statvfs` must be valid for their roles.
#[no_mangle]
pub unsafe extern "C" fn smb2_statvfs_async(
    context: *mut Smb2RustContext,
    path: *const c_char,
    statvfs: *mut Smb2StatVfs,
    cb: Smb2CommandCallback,
    cb_data: *mut c_void,
) -> i32 {
    let result = catch_unwind(AssertUnwindSafe(|| {
        if context.is_null() || statvfs.is_null() {
            return invalid_argument_code();
        }
        let context_ref = unsafe { &mut *context };
        let path = match unsafe { required_c_string_arg(context_ref, "path", path) } {
            Ok(path) => path,
            Err(code) => return code,
        };
        context_ref.inner.statvfs_async(path);
        let message_id = context_ref.inner.last_request_message_id();
        context_ref.push_callback(
            message_id,
            PendingCallbackKind::StatVfs { out: statvfs },
            cb,
            cb_data,
            None,
        );
        0
    }));
    result.unwrap_or_else(|_| invalid_argument_code())
}

/// Reads a symbolic link target synchronously.
///
/// # Safety
///
/// `context`, `path`, and `buf` must be valid for their roles.
#[no_mangle]
pub unsafe extern "C" fn smb2_readlink(
    context: *mut Smb2RustContext,
    path: *const c_char,
    buf: *mut c_char,
    bufsiz: u32,
) -> i32 {
    let result = catch_unwind(AssertUnwindSafe(|| {
        if context.is_null() {
            return invalid_argument_code();
        }
        let context_ref = unsafe { &mut *context };
        let path = match unsafe { required_c_string_arg(context_ref, "path", path) } {
            Ok(path) => path,
            Err(code) => return code,
        };
        match sync::smb2_readlink(&mut context_ref.inner, path, bufsiz as usize) {
            Ok(request) => match request.payload() {
                SyncPayload::Readlink(target) => copy_readlink_target(buf, bufsiz, target),
                _ => invalid_argument_code(),
            },
            Err(error) => result_code::<()>(context_ref, Err(error)),
        }
    }));
    result.unwrap_or_else(|_| invalid_argument_code())
}

/// Queues an async readlink operation.
///
/// # Safety
///
/// `context` and `path` must be valid for their roles.
#[no_mangle]
pub unsafe extern "C" fn smb2_readlink_async(
    context: *mut Smb2RustContext,
    path: *const c_char,
    cb: Smb2CommandCallback,
    cb_data: *mut c_void,
) -> i32 {
    let result = catch_unwind(AssertUnwindSafe(|| {
        if context.is_null() {
            return invalid_argument_code();
        }
        let context_ref = unsafe { &mut *context };
        let path = match unsafe { required_c_string_arg(context_ref, "path", path) } {
            Ok(path) => path,
            Err(code) => return code,
        };
        context_ref.inner.readlink_async(path, u32::MAX);
        let message_id = context_ref.inner.last_request_message_id();
        context_ref.push_callback(message_id, PendingCallbackKind::Readlink, cb, cb_data, None);
        0
    }));
    result.unwrap_or_else(|_| invalid_argument_code())
}

/// Sets a formatted error string. Extra C varargs are ignored by this facade.
///
/// # Safety
///
/// `context` must be null or valid. `error_string` must be null or a valid C string.
#[no_mangle]
pub unsafe extern "C" fn smb2_set_error(
    context: *mut Smb2RustContext,
    error_string: *const c_char,
) {
    if context.is_null() {
        return;
    }
    let context_ref = unsafe { &mut *context };
    if let Some(error) = unsafe { optional_c_string_arg(error_string) } {
        context_ref.set_error(error);
    }
}

/// Returns the last NTSTATUS value recorded by the context.
///
/// # Safety
///
/// `context` must be null or valid.
#[no_mangle]
pub unsafe extern "C" fn smb2_get_nterror(context: *mut Smb2RustContext) -> i32 {
    if context.is_null() {
        return 0;
    }
    unsafe { (*context).inner.nterror() }
}

/// Selects a tree id for subsequent operations.
///
/// # Safety
///
/// `context` must be null or valid.
#[no_mangle]
pub unsafe extern "C" fn smb2_select_tree_id(context: *mut Smb2RustContext, tree_id: u32) -> i32 {
    if context.is_null() {
        return invalid_argument_code();
    }
    unsafe { (*context).inner.select_tree_id(tree_id) };
    0
}

/// Returns the current session id.
///
/// # Safety
///
/// `context` and `session_id` must be null or valid for their roles.
#[no_mangle]
pub unsafe extern "C" fn smb2_get_session_id(
    context: *mut Smb2RustContext,
    session_id: *mut u64,
) -> i32 {
    if context.is_null() || session_id.is_null() {
        return invalid_argument_code();
    }
    match unsafe { (*context).inner.session_id() } {
        Some(value) => {
            unsafe { *session_id = value };
            0
        }
        None => invalid_argument_code(),
    }
}

/// Gets the tree id stored on a PDU.
///
/// # Safety
///
/// `pdu` and `tree_id` must be null or valid for their roles.
#[no_mangle]
pub unsafe extern "C" fn smb2_get_tree_id_for_pdu(
    _context: *mut Smb2RustContext,
    pdu: *mut Smb2RustPdu,
    tree_id: *mut u32,
) -> i32 {
    if pdu.is_null() || tree_id.is_null() {
        return invalid_argument_code();
    }
    match unsafe { (*pdu).tree_id } {
        Some(value) => {
            unsafe { *tree_id = value };
            0
        }
        None => invalid_argument_code(),
    }
}

/// Sets the tree id stored on a PDU.
///
/// # Safety
///
/// `pdu` must be null or valid.
#[no_mangle]
pub unsafe extern "C" fn smb2_set_tree_id_for_pdu(
    _context: *mut Smb2RustContext,
    pdu: *mut Smb2RustPdu,
    tree_id: u32,
) -> i32 {
    if pdu.is_null() {
        return invalid_argument_code();
    }
    unsafe { (*pdu).tree_id = Some(tree_id) };
    0
}

/// Marks a PDU chain as compound.
///
/// # Safety
///
/// `pdu` and `next_pdu` must be null or valid.
#[no_mangle]
pub unsafe extern "C" fn smb2_add_compound_pdu(
    _context: *mut Smb2RustContext,
    pdu: *mut Smb2RustPdu,
    next_pdu: *mut Smb2RustPdu,
) {
    if !pdu.is_null() && !next_pdu.is_null() {
        unsafe {
            (*pdu).is_compound = true;
            (*next_pdu).is_compound = true;
            (*pdu).compound = next_pdu;
        }
    }
}

/// Queues a PDU by assigning a message id when needed.
///
/// # Safety
///
/// `context` and `pdu` must be null or valid.
#[no_mangle]
pub unsafe extern "C" fn smb2_queue_pdu(context: *mut Smb2RustContext, pdu: *mut Smb2RustPdu) {
    if context.is_null() || pdu.is_null() {
        return;
    }
    let context_ref = unsafe { &mut *context };
    if unsafe { (*pdu).message_id } == 0 {
        let mut handle = PduHandle::default();
        context_ref.inner.queue_pdu(&mut handle);
        unsafe { (*pdu).message_id = context_ref.inner.last_request_message_id() };
    }
}

/// Returns the next compound PDU in the chain.
///
/// # Safety
///
/// `pdu` must be null or valid.
#[no_mangle]
pub unsafe extern "C" fn smb2_get_compound_pdu(
    _context: *mut Smb2RustContext,
    pdu: *mut Smb2RustPdu,
) -> *mut Smb2RustPdu {
    if pdu.is_null() {
        return ptr::null_mut();
    }
    unsafe { (*pdu).compound }
}

/// Sets the PDU completion status.
///
/// # Safety
///
/// `pdu` must be null or valid.
#[no_mangle]
pub unsafe extern "C" fn smb2_set_pdu_status(
    _context: *mut Smb2RustContext,
    pdu: *mut Smb2RustPdu,
    status: i32,
) {
    if !pdu.is_null() {
        unsafe { (*pdu).status = status };
    }
}

/// Sets the PDU message id.
///
/// # Safety
///
/// `pdu` must be null or valid.
#[no_mangle]
pub unsafe extern "C" fn smb2_set_pdu_message_id(
    _context: *mut Smb2RustContext,
    pdu: *mut Smb2RustPdu,
    message_id: u64,
) {
    if !pdu.is_null() {
        unsafe { (*pdu).message_id = message_id };
    }
}

/// Returns the PDU message id.
///
/// # Safety
///
/// `pdu` must be null or valid.
#[no_mangle]
pub unsafe extern "C" fn smb2_get_pdu_message_id(
    _context: *mut Smb2RustContext,
    pdu: *mut Smb2RustPdu,
) -> u64 {
    if pdu.is_null() {
        return 0;
    }
    unsafe { (*pdu).message_id }
}

/// Returns the last request message id.
///
/// # Safety
///
/// `context` must be null or valid.
#[no_mangle]
pub unsafe extern "C" fn smb2_get_last_request_message_id(context: *mut Smb2RustContext) -> u64 {
    if context.is_null() {
        return 0;
    }
    unsafe { (*context).inner.last_request_message_id() }
}

/// Returns the last reply message id.
///
/// # Safety
///
/// `context` must be null or valid.
#[no_mangle]
pub unsafe extern "C" fn smb2_get_last_reply_message_id(context: *mut Smb2RustContext) -> u64 {
    if context.is_null() {
        return 0;
    }
    unsafe { (*context).inner.last_reply_message_id() }
}

/// Returns whether the context currently has compound PDU state.
#[no_mangle]
pub extern "C" fn smb2_pdu_is_compound(_context: *mut Smb2RustContext) -> i32 {
    0
}

/// Returns a borrowed pointer to a file handle's 16-byte file id.
///
/// # Safety
///
/// `fh` must be null or a valid file handle pointer returned by this facade.
#[no_mangle]
pub unsafe extern "C" fn smb2_get_file_id(fh: *mut Smb2RustFileHandle) -> *mut [u8; 16] {
    if fh.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: The pointer is checked above and must be valid by caller contract.
    unsafe { &mut (*fh).file_id as *mut [u8; 16] }
}

/// Creates a file handle wrapper from a raw file id.
///
/// # Safety
///
/// `file_id` must be null or point to 16 bytes.
#[no_mangle]
pub unsafe extern "C" fn smb2_fh_from_file_id(
    _context: *mut Smb2RustContext,
    file_id: *mut [u8; 16],
) -> *mut Smb2RustFileHandle {
    if file_id.is_null() {
        return ptr::null_mut();
    }
    let id = unsafe { *file_id };
    Box::into_raw(Box::new(Smb2RustFileHandle {
        inner: FileHandle::new(id),
        file_id: id,
    }))
}

/// Flushes a file handle synchronously.
///
/// # Safety
///
/// `context` and `fh` must be null or valid for their roles.
#[no_mangle]
pub unsafe extern "C" fn smb2_fsync(
    context: *mut Smb2RustContext,
    fh: *mut Smb2RustFileHandle,
) -> i32 {
    let result = catch_unwind(AssertUnwindSafe(|| {
        if context.is_null() || fh.is_null() {
            return invalid_argument_code();
        }
        let context_ref = unsafe { &mut *context };
        let handle = unsafe { &*fh };
        let fsync_result = sync::smb2_fsync(&mut context_ref.inner, &handle.inner);
        result_code(context_ref, fsync_result)
    }));
    result.unwrap_or_else(|_| invalid_argument_code())
}

/// Queues an async fsync operation.
///
/// # Safety
///
/// `context` and `fh` must be null or valid for their roles.
#[no_mangle]
pub unsafe extern "C" fn smb2_fsync_async(
    context: *mut Smb2RustContext,
    fh: *mut Smb2RustFileHandle,
    cb: Smb2CommandCallback,
    cb_data: *mut c_void,
) -> i32 {
    let result = catch_unwind(AssertUnwindSafe(|| {
        if context.is_null() || fh.is_null() {
            return invalid_argument_code();
        }
        let context_ref = unsafe { &mut *context };
        let handle = unsafe { &*fh };
        context_ref.inner.fsync_async(&handle.inner);
        let message_id = context_ref.inner.last_request_message_id();
        context_ref.push_callback(
            message_id,
            PendingCallbackKind::StatusOnly,
            cb,
            cb_data,
            None,
        );
        0
    }));
    result.unwrap_or_else(|_| invalid_argument_code())
}

/// Returns the negotiated maximum read size.
///
/// # Safety
///
/// `context` must be null or valid.
#[no_mangle]
pub unsafe extern "C" fn smb2_get_max_read_size(context: *mut Smb2RustContext) -> u32 {
    if context.is_null() {
        return 0;
    }
    unsafe { (*context).inner.max_read_size() }
}

/// Returns the negotiated maximum write size.
///
/// # Safety
///
/// `context` must be null or valid.
#[no_mangle]
pub unsafe extern "C" fn smb2_get_max_write_size(context: *mut Smb2RustContext) -> u32 {
    if context.is_null() {
        return 0;
    }
    unsafe { (*context).inner.max_write_size() }
}

/// Seeks a local file handle offset.
///
/// # Safety
///
/// `context`, `fh`, and `current_offset` must be null or valid for their roles.
#[no_mangle]
pub unsafe extern "C" fn smb2_lseek(
    context: *mut Smb2RustContext,
    fh: *mut Smb2RustFileHandle,
    offset: i64,
    whence: i32,
    current_offset: *mut u64,
) -> i64 {
    if context.is_null() || fh.is_null() || current_offset.is_null() {
        return i64::from(invalid_argument_code());
    }
    let context_ref = unsafe { &mut *context };
    let handle = unsafe { &mut *fh };
    match context_ref.inner.lseek(&handle.inner, offset, whence) {
        Some(resolved) => {
            handle.inner.set_offset(resolved);
            unsafe { *current_offset = resolved };
            0
        }
        None => i64::from(invalid_argument_code()),
    }
}

/// Queues an async open-with-oplock-or-lease operation.
///
/// # Safety
///
/// `context` and `path` must be valid for their roles.
#[no_mangle]
pub unsafe extern "C" fn smb2_open_async_with_oplock_or_lease(
    context: *mut Smb2RustContext,
    path: *const c_char,
    flags: i32,
    oplock_level: u8,
    lease_state: u32,
    lease_key: *const u8,
    cb: Smb2CommandCallback,
    cb_data: *mut c_void,
) -> i32 {
    let result = catch_unwind(AssertUnwindSafe(|| {
        if context.is_null() {
            return invalid_argument_code();
        }
        let context_ref = unsafe { &mut *context };
        let path = match unsafe { required_c_string_arg(context_ref, "path", path) } {
            Ok(path) => path,
            Err(code) => return code,
        };
        let mut key = [0; 16];
        if !lease_key.is_null() {
            unsafe { ptr::copy_nonoverlapping(lease_key, key.as_mut_ptr(), key.len()) };
        }
        context_ref.inner.open_async_with_oplock_or_lease(
            path,
            flags,
            oplock_level,
            lease_state,
            libsmb2_rs::include::smb2::libsmb2::LeaseKey(key),
        );
        let message_id = context_ref.inner.last_request_message_id();
        context_ref.push_callback(message_id, PendingCallbackKind::Open, cb, cb_data, None);
        0
    }));
    result.unwrap_or_else(|_| invalid_argument_code())
}

/// Gets metadata for a file handle.
///
/// # Safety
///
/// `context`, `fh`, and `st` must be valid for their roles.
#[no_mangle]
pub unsafe extern "C" fn smb2_fstat(
    context: *mut Smb2RustContext,
    fh: *mut Smb2RustFileHandle,
    st: *mut Smb2Stat64,
) -> i32 {
    let result = catch_unwind(AssertUnwindSafe(|| {
        if context.is_null() || fh.is_null() || st.is_null() {
            return invalid_argument_code();
        }
        let context_ref = unsafe { &mut *context };
        let handle = unsafe { &*fh };
        match context_ref.inner.fstat(&handle.inner) {
            Ok(stat) => write_stat(st, stat),
            Err(error) => result_code::<()>(context_ref, Err(error)),
        }
    }));
    result.unwrap_or_else(|_| invalid_argument_code())
}

/// Queues an async fstat operation.
///
/// # Safety
///
/// `context`, `fh`, and `st` must be valid for their roles.
#[no_mangle]
pub unsafe extern "C" fn smb2_fstat_async(
    context: *mut Smb2RustContext,
    fh: *mut Smb2RustFileHandle,
    st: *mut Smb2Stat64,
    cb: Smb2CommandCallback,
    cb_data: *mut c_void,
) -> i32 {
    let result = catch_unwind(AssertUnwindSafe(|| {
        if context.is_null() || fh.is_null() || st.is_null() {
            return invalid_argument_code();
        }
        let context_ref = unsafe { &mut *context };
        let handle = unsafe { &*fh };
        context_ref.inner.fstat_async(&handle.inner);
        let message_id = context_ref.inner.last_request_message_id();
        context_ref.push_callback(
            message_id,
            PendingCallbackKind::Stat { out: st },
            cb,
            cb_data,
            None,
        );
        0
    }));
    result.unwrap_or_else(|_| invalid_argument_code())
}

/// Renames a path synchronously.
///
/// # Safety
///
/// `context`, `oldpath`, and `newpath` must be valid for their roles.
#[no_mangle]
pub unsafe extern "C" fn smb2_rename(
    context: *mut Smb2RustContext,
    oldpath: *const c_char,
    newpath: *const c_char,
) -> i32 {
    let result = catch_unwind(AssertUnwindSafe(|| {
        if context.is_null() {
            return invalid_argument_code();
        }
        let context_ref = unsafe { &mut *context };
        let oldpath = match unsafe { required_c_string_arg(context_ref, "oldpath", oldpath) } {
            Ok(path) => path,
            Err(code) => return code,
        };
        let newpath = match unsafe { required_c_string_arg(context_ref, "newpath", newpath) } {
            Ok(path) => path,
            Err(code) => return code,
        };
        let rename_result = context_ref.inner.rename(oldpath, newpath);
        result_code(context_ref, rename_result)
    }));
    result.unwrap_or_else(|_| invalid_argument_code())
}

/// Queues an async rename operation.
///
/// # Safety
///
/// `context`, `oldpath`, and `newpath` must be valid for their roles.
#[no_mangle]
pub unsafe extern "C" fn smb2_rename_async(
    context: *mut Smb2RustContext,
    oldpath: *const c_char,
    newpath: *const c_char,
    cb: Smb2CommandCallback,
    cb_data: *mut c_void,
) -> i32 {
    let result = catch_unwind(AssertUnwindSafe(|| {
        if context.is_null() {
            return invalid_argument_code();
        }
        let context_ref = unsafe { &mut *context };
        let oldpath = match unsafe { required_c_string_arg(context_ref, "oldpath", oldpath) } {
            Ok(path) => path,
            Err(code) => return code,
        };
        let newpath = match unsafe { required_c_string_arg(context_ref, "newpath", newpath) } {
            Ok(path) => path,
            Err(code) => return code,
        };
        context_ref.inner.rename_async(oldpath, newpath);
        let message_id = context_ref.inner.last_request_message_id();
        context_ref.push_callback(
            message_id,
            PendingCallbackKind::StatusOnly,
            cb,
            cb_data,
            None,
        );
        0
    }));
    result.unwrap_or_else(|_| invalid_argument_code())
}

/// Truncates a path synchronously.
///
/// # Safety
///
/// `context` and `path` must be valid for their roles.
#[no_mangle]
pub unsafe extern "C" fn smb2_truncate(
    context: *mut Smb2RustContext,
    path: *const c_char,
    length: u64,
) -> i32 {
    let result = catch_unwind(AssertUnwindSafe(|| {
        if context.is_null() {
            return invalid_argument_code();
        }
        let context_ref = unsafe { &mut *context };
        let path = match unsafe { required_c_string_arg(context_ref, "path", path) } {
            Ok(path) => path,
            Err(code) => return code,
        };
        let truncate_result = context_ref.inner.truncate(path, length);
        result_code(context_ref, truncate_result)
    }));
    result.unwrap_or_else(|_| invalid_argument_code())
}

/// Queues an async truncate operation.
///
/// # Safety
///
/// `context` and `path` must be valid for their roles.
#[no_mangle]
pub unsafe extern "C" fn smb2_truncate_async(
    context: *mut Smb2RustContext,
    path: *const c_char,
    length: u64,
    cb: Smb2CommandCallback,
    cb_data: *mut c_void,
) -> i32 {
    let result = catch_unwind(AssertUnwindSafe(|| {
        if context.is_null() {
            return invalid_argument_code();
        }
        let context_ref = unsafe { &mut *context };
        let path = match unsafe { required_c_string_arg(context_ref, "path", path) } {
            Ok(path) => path,
            Err(code) => return code,
        };
        context_ref.inner.truncate_async(path, length);
        let message_id = context_ref.inner.last_request_message_id();
        context_ref.push_callback(
            message_id,
            PendingCallbackKind::StatusOnly,
            cb,
            cb_data,
            None,
        );
        0
    }));
    result.unwrap_or_else(|_| invalid_argument_code())
}

/// Truncates a file handle synchronously.
///
/// # Safety
///
/// `context` and `fh` must be valid for their roles.
#[no_mangle]
pub unsafe extern "C" fn smb2_ftruncate(
    context: *mut Smb2RustContext,
    fh: *mut Smb2RustFileHandle,
    length: u64,
) -> i32 {
    let result = catch_unwind(AssertUnwindSafe(|| {
        if context.is_null() || fh.is_null() {
            return invalid_argument_code();
        }
        let context_ref = unsafe { &mut *context };
        let handle = unsafe { &*fh };
        let ftruncate_result = context_ref.inner.ftruncate(&handle.inner, length);
        result_code(context_ref, ftruncate_result)
    }));
    result.unwrap_or_else(|_| invalid_argument_code())
}

/// Queues an async ftruncate operation.
///
/// # Safety
///
/// `context` and `fh` must be valid for their roles.
#[no_mangle]
pub unsafe extern "C" fn smb2_ftruncate_async(
    context: *mut Smb2RustContext,
    fh: *mut Smb2RustFileHandle,
    length: u64,
    cb: Smb2CommandCallback,
    cb_data: *mut c_void,
) -> i32 {
    let result = catch_unwind(AssertUnwindSafe(|| {
        if context.is_null() || fh.is_null() {
            return invalid_argument_code();
        }
        let context_ref = unsafe { &mut *context };
        let handle = unsafe { &*fh };
        context_ref.inner.ftruncate_async(&handle.inner, length);
        let message_id = context_ref.inner.last_request_message_id();
        context_ref.push_callback(
            message_id,
            PendingCallbackKind::StatusOnly,
            cb,
            cb_data,
            None,
        );
        0
    }));
    result.unwrap_or_else(|_| invalid_argument_code())
}

/// Returns the current SMB2 message id stored in the Rust-backed context.
///
/// Returns `0` for a null context. This small accessor gives C smoke tests a
/// stable way to verify that an opaque Rust context is usable.
///
/// # Safety
///
/// `context` must be null or a valid pointer returned by [`smb2_init_context`]
/// that has not been destroyed.
#[no_mangle]
pub unsafe extern "C" fn smb2_context_message_id(context: *const Smb2RustContext) -> u64 {
    if context.is_null() {
        return 0;
    }

    // SAFETY: The caller contract requires a valid live context pointer.
    unsafe { (*context).inner.last_request_message_id() }
}

/// Returns a stable NTSTATUS name.
#[no_mangle]
pub extern "C" fn nterror_to_str(status: u32) -> *const c_char {
    ffi_error_string(errors::nterror_to_str(status)).into_raw()
}

/// Converts an NTSTATUS value to errno.
#[no_mangle]
pub extern "C" fn nterror_to_errno(status: u32) -> i32 {
    errors::nterror_to_errno(status)
}

/// Converts Windows FILETIME ticks to a Unix timeval.
///
/// # Safety
///
/// `tv` must be null or a valid output pointer.
#[no_mangle]
pub unsafe extern "C" fn smb2_win_to_timeval(smb2_time: u64, tv: *mut Smb2Timeval) {
    if tv.is_null() {
        return;
    }
    let converted = timestamps::smb2_win_to_timeval(smb2_time);
    unsafe {
        *tv = Smb2Timeval {
            tv_sec: converted.tv_sec,
            tv_usec: converted.tv_usec,
        };
    }
}

/// Converts a Unix timeval to Windows FILETIME ticks.
///
/// # Safety
///
/// `tv` must be null or a valid input pointer.
#[no_mangle]
pub unsafe extern "C" fn smb2_timeval_to_win(tv: *mut Smb2Timeval) -> u64 {
    if tv.is_null() {
        return 0;
    }
    let tv = unsafe { *tv };
    timestamps::smb2_timeval_to_win(&timestamps::Smb2Timeval::new(tv.tv_sec, tv.tv_usec))
}

/// Converts UTF-8 to the C-compatible SMB2 UTF-16 allocation.
///
/// # Safety
///
/// `utf8` must be null or a valid C string. The returned allocation is freed by `free`.
#[no_mangle]
pub unsafe extern "C" fn smb2_utf8_to_utf16(utf8: *const c_char) -> *mut Smb2Utf16 {
    let Some(input) = (unsafe { optional_c_string_arg(utf8) }) else {
        return ptr::null_mut();
    };
    let Ok(encoded) = unicode::smb2_utf8_to_utf16(input.as_bytes()) else {
        return ptr::null_mut();
    };
    let units = encoded.units;
    let total = core::mem::size_of::<i32>() + units.len().max(1) * core::mem::size_of::<u16>();
    let raw = unsafe { malloc(total) }.cast::<Smb2Utf16>();
    if raw.is_null() {
        return ptr::null_mut();
    }
    unsafe {
        (*raw).len = i32::try_from(units.len()).unwrap_or(i32::MAX);
        let dst = (*raw).val.as_mut_ptr();
        if units.is_empty() {
            *dst = 0;
        } else {
            ptr::copy_nonoverlapping(units.as_ptr(), dst, units.len());
        }
    }
    raw
}

/// Converts SMB2 UTF-16 code units to UTF-8.
///
/// # Safety
///
/// `str_` must be null or point to `len` UTF-16 units. The returned allocation is freed by `free`.
#[no_mangle]
pub unsafe extern "C" fn smb2_utf16_to_utf8(str_: *const u16, len: usize) -> *const c_char {
    if str_.is_null() {
        return ptr::null();
    }
    let units = unsafe { core::slice::from_raw_parts(str_, len) };
    let text = unicode::smb2_utf16_to_utf8(units);
    ffi_error_string(&text).into_raw()
}

/// Frees data returned by APIs that use C allocations.
///
/// # Safety
///
/// `ptr` must be null or a pointer allocated by a compatible C allocator.
#[no_mangle]
pub unsafe extern "C" fn smb2_free_data(_context: *mut Smb2RustContext, ptr: *mut c_void) {
    if !ptr.is_null() {
        unsafe { free(ptr) };
    }
}

/// Decodes one FILE_ID_FULL_DIRECTORY_INFORMATION entry.
#[no_mangle]
pub unsafe extern "C" fn smb2_decode_fileidfulldirectoryinformation(
    context: *mut Smb2RustContext,
    fs: *mut Smb2FileIdFullDirectoryInformationC,
    vec: *mut Smb2Iovec,
) -> i32 {
    let result = catch_unwind(AssertUnwindSafe(|| {
        if fs.is_null() || vec.is_null() {
            set_context_error(
                context,
                "invalid FILE_ID_FULL_DIRECTORY_INFORMATION decode arguments",
            );
            return invalid_argument_code();
        }

        // SAFETY: Pointers are checked above and the iovec buffer is borrowed for this call only.
        let vec_ref = unsafe { &*vec };
        if vec_ref.buf.is_null() && vec_ref.len != 0 {
            set_context_error(context, "invalid FILE_ID_FULL_DIRECTORY_INFORMATION buffer");
            return invalid_argument_code();
        }
        let data = if vec_ref.len == 0 {
            &[]
        } else {
            // SAFETY: The iovec contract provides a buffer of `len` bytes.
            unsafe { core::slice::from_raw_parts(vec_ref.buf.cast_const(), vec_ref.len) }
        };

        match smb2_cmd_query_directory::smb2_decode_fileidfulldirectoryinformation(data) {
            Ok(decoded) => {
                // SAFETY: Output pointer is valid by caller contract.
                unsafe { clear_fileid_full_directory_output(fs) };
                let name = malloc_c_string(&decoded.name);
                // SAFETY: Output pointer is valid by caller contract.
                unsafe {
                    *fs = Smb2FileIdFullDirectoryInformationC {
                        next_entry_offset: decoded.next_entry_offset,
                        file_index: decoded.file_index,
                        creation_time: timeval_from_query_directory(decoded.creation_time),
                        last_access_time: timeval_from_query_directory(decoded.last_access_time),
                        last_write_time: timeval_from_query_directory(decoded.last_write_time),
                        change_time: timeval_from_query_directory(decoded.change_time),
                        end_of_file: decoded.end_of_file,
                        allocation_size: decoded.allocation_size,
                        file_attributes: decoded.file_attributes,
                        file_name_length: decoded.file_name_length,
                        ea_size: decoded.ea_size,
                        file_id: decoded.file_id,
                        name,
                    };
                }
                if !context.is_null() {
                    // SAFETY: Context pointer is valid by caller contract.
                    unsafe { (*context).clear_error() };
                }
                0
            }
            Err(_) => {
                unsafe { clear_fileid_full_directory_output(fs) };
                set_context_error(context, "Malformed name in query.\n");
                -1
            }
        }
    }));
    result.unwrap_or_else(|_| invalid_argument_code())
}

/// Decodes a FILE_NOTIFY_INFORMATION chain.
#[no_mangle]
pub unsafe extern "C" fn smb2_decode_filenotifychangeinformation(
    context: *mut Smb2RustContext,
    fnc: *mut Smb2FileNotifyChangeInformationC,
    vec: *mut Smb2Iovec,
    next_entry_offset: u32,
) -> i32 {
    let result = catch_unwind(AssertUnwindSafe(|| {
        if fnc.is_null() || vec.is_null() {
            set_context_error(context, "invalid FILE_NOTIFY_INFORMATION decode arguments");
            return invalid_argument_code();
        }

        // SAFETY: Pointers are checked above and borrowed for this call only.
        let vec_ref = unsafe { &*vec };
        if vec_ref.buf.is_null() && vec_ref.len != 0 {
            set_context_error(context, "invalid FILE_NOTIFY_INFORMATION buffer");
            return invalid_argument_code();
        }
        let start = match usize::try_from(next_entry_offset) {
            Ok(value) => value,
            Err(_) => return invalid_argument_code(),
        };

        unsafe { clear_notify_output(fnc) };
        if start.saturating_add(12) > vec_ref.len {
            if !context.is_null() {
                unsafe { (*context).clear_error() };
            }
            return 0;
        }

        let data = if vec_ref.len == 0 {
            &[]
        } else {
            // SAFETY: The iovec contract provides a buffer of `len` bytes.
            unsafe { core::slice::from_raw_parts(vec_ref.buf.cast_const(), vec_ref.len) }
        };
        let Some(data) = data.get(start..) else {
            return 0;
        };

        match smb2_cmd_notify_change::smb2_decode_file_notify_information_records(data) {
            Ok(records) => {
                for (index, record) in records.into_iter().enumerate() {
                    let node = if index == 0 {
                        fnc
                    } else {
                        let node = alloc_notify_node();
                        if node.is_null() {
                            unsafe { clear_notify_output(fnc) };
                            set_context_error(context, "Failed to allocate file notify record");
                            return invalid_argument_code();
                        }
                        // SAFETY: `fnc` and all created tail nodes are valid mutable nodes.
                        unsafe {
                            let mut tail = fnc;
                            while !(*tail).next.is_null() {
                                tail = (*tail).next;
                            }
                            (*tail).next = node;
                        }
                        node
                    };
                    // SAFETY: The node is either caller-provided head or allocated above.
                    unsafe {
                        (*node).action = record.action;
                        (*node).name = malloc_c_string(&record.file_name);
                    }
                }
                if !context.is_null() {
                    unsafe { (*context).clear_error() };
                }
                0
            }
            Err(_) => {
                unsafe { clear_notify_output(fnc) };
                set_context_error(context, "Malformed file notify change information");
                -1
            }
        }
    }));
    result.unwrap_or_else(|_| invalid_argument_code())
}

macro_rules! raw_pdu_fn {
    ($name:ident ( $($arg:ident : $ty:ty),* $(,)? )) => {
        #[no_mangle]
        pub extern "C" fn $name($($arg: $ty),*) -> *mut Smb2RustPdu {
            let _ = ($($arg,)*);
            Box::into_raw(Box::new(Smb2RustPdu {
                message_id: 0,
                tree_id: None,
                status: 0,
                is_compound: false,
                compound: ptr::null_mut(),
            }))
        }
    };
}

raw_pdu_fn!(smb2_cmd_negotiate_async(ctx: *mut Smb2RustContext, req: *mut c_void, cb: Smb2CommandCallback, cb_data: *mut c_void));
raw_pdu_fn!(smb2_cmd_negotiate_reply_async(ctx: *mut Smb2RustContext, rep: *mut c_void, cb: Smb2CommandCallback, cb_data: *mut c_void));
raw_pdu_fn!(smb2_cmd_session_setup_async(ctx: *mut Smb2RustContext, req: *mut c_void, cb: Smb2CommandCallback, cb_data: *mut c_void));
raw_pdu_fn!(smb2_cmd_session_setup_reply_async(ctx: *mut Smb2RustContext, rep: *mut c_void, cb: Smb2CommandCallback, cb_data: *mut c_void));
raw_pdu_fn!(smb2_cmd_tree_connect_async(ctx: *mut Smb2RustContext, req: *mut c_void, cb: Smb2CommandCallback, cb_data: *mut c_void));
raw_pdu_fn!(smb2_cmd_tree_connect_reply_async(ctx: *mut Smb2RustContext, rep: *mut c_void, tree_id: u32, cb: Smb2CommandCallback, cb_data: *mut c_void));
raw_pdu_fn!(smb2_cmd_tree_disconnect_async(ctx: *mut Smb2RustContext, cb: Smb2CommandCallback, cb_data: *mut c_void));
raw_pdu_fn!(smb2_cmd_tree_disconnect_reply_async(ctx: *mut Smb2RustContext, cb: Smb2CommandCallback, cb_data: *mut c_void));
raw_pdu_fn!(smb2_cmd_create_async(ctx: *mut Smb2RustContext, req: *mut c_void, cb: Smb2CommandCallback, cb_data: *mut c_void));
raw_pdu_fn!(smb2_cmd_create_reply_async(ctx: *mut Smb2RustContext, rep: *mut c_void, cb: Smb2CommandCallback, cb_data: *mut c_void));
raw_pdu_fn!(smb2_cmd_close_async(ctx: *mut Smb2RustContext, req: *mut c_void, cb: Smb2CommandCallback, cb_data: *mut c_void));
raw_pdu_fn!(smb2_cmd_close_reply_async(ctx: *mut Smb2RustContext, rep: *mut c_void, cb: Smb2CommandCallback, cb_data: *mut c_void));
raw_pdu_fn!(smb2_cmd_read_async(ctx: *mut Smb2RustContext, req: *mut c_void, cb: Smb2CommandCallback, cb_data: *mut c_void));
raw_pdu_fn!(smb2_cmd_read_reply_async(ctx: *mut Smb2RustContext, rep: *mut c_void, cb: Smb2CommandCallback, cb_data: *mut c_void));
raw_pdu_fn!(smb2_cmd_write_async(ctx: *mut Smb2RustContext, req: *mut c_void, pass_buf_ownership: i32, cb: Smb2CommandCallback, cb_data: *mut c_void));
raw_pdu_fn!(smb2_cmd_write_reply_async(ctx: *mut Smb2RustContext, rep: *mut c_void, cb: Smb2CommandCallback, cb_data: *mut c_void));
raw_pdu_fn!(smb2_cmd_query_directory_async(ctx: *mut Smb2RustContext, req: *mut c_void, cb: Smb2CommandCallback, cb_data: *mut c_void));
raw_pdu_fn!(smb2_cmd_query_directory_reply_async(ctx: *mut Smb2RustContext, req: *mut c_void, rep: *mut c_void, cb: Smb2CommandCallback, cb_data: *mut c_void));
raw_pdu_fn!(smb2_cmd_change_notify_async(ctx: *mut Smb2RustContext, req: *mut c_void, cb: Smb2CommandCallback, cb_data: *mut c_void));
raw_pdu_fn!(smb2_cmd_change_notify_reply_async(ctx: *mut Smb2RustContext, rep: *mut c_void, cb: Smb2CommandCallback, cb_data: *mut c_void));
raw_pdu_fn!(smb2_cmd_query_info_async(ctx: *mut Smb2RustContext, req: *mut c_void, cb: Smb2CommandCallback, cb_data: *mut c_void));
raw_pdu_fn!(smb2_cmd_query_info_reply_async(ctx: *mut Smb2RustContext, req: *mut c_void, rep: *mut c_void, cb: Smb2CommandCallback, cb_data: *mut c_void));
raw_pdu_fn!(smb2_cmd_set_info_async(ctx: *mut Smb2RustContext, req: *mut c_void, cb: Smb2CommandCallback, cb_data: *mut c_void));
raw_pdu_fn!(smb2_cmd_set_info_reply_async(ctx: *mut Smb2RustContext, req: *mut c_void, cb: Smb2CommandCallback, cb_data: *mut c_void));
raw_pdu_fn!(smb2_cmd_ioctl_async(ctx: *mut Smb2RustContext, req: *mut c_void, cb: Smb2CommandCallback, cb_data: *mut c_void));
raw_pdu_fn!(smb2_cmd_ioctl_reply_async(ctx: *mut Smb2RustContext, rep: *mut c_void, cb: Smb2CommandCallback, cb_data: *mut c_void));
raw_pdu_fn!(smb2_cmd_echo_async(ctx: *mut Smb2RustContext, cb: Smb2CommandCallback, cb_data: *mut c_void));
raw_pdu_fn!(smb2_cmd_echo_reply_async(ctx: *mut Smb2RustContext, cb: Smb2CommandCallback, cb_data: *mut c_void));
raw_pdu_fn!(smb2_cmd_lock_async(ctx: *mut Smb2RustContext, req: *mut c_void, cb: Smb2CommandCallback, cb_data: *mut c_void));
raw_pdu_fn!(smb2_cmd_lock_reply_async(ctx: *mut Smb2RustContext, cb: Smb2CommandCallback, cb_data: *mut c_void));
raw_pdu_fn!(smb2_cmd_logoff_async(ctx: *mut Smb2RustContext, cb: Smb2CommandCallback, cb_data: *mut c_void));
raw_pdu_fn!(smb2_cmd_logoff_reply_async(ctx: *mut Smb2RustContext, cb: Smb2CommandCallback, cb_data: *mut c_void));
raw_pdu_fn!(smb2_cmd_flush_async(ctx: *mut Smb2RustContext, req: *mut c_void, cb: Smb2CommandCallback, cb_data: *mut c_void));
raw_pdu_fn!(smb2_cmd_flush_reply_async(ctx: *mut Smb2RustContext, cb: Smb2CommandCallback, cb_data: *mut c_void));
raw_pdu_fn!(smb2_cmd_oplock_break_async(ctx: *mut Smb2RustContext, req: *mut c_void, cb: Smb2CommandCallback, cb_data: *mut c_void));
raw_pdu_fn!(smb2_cmd_oplock_break_reply_async(ctx: *mut Smb2RustContext, rep: *mut c_void, cb: Smb2CommandCallback, cb_data: *mut c_void));
raw_pdu_fn!(smb2_cmd_oplock_break_notification_async(ctx: *mut Smb2RustContext, rep: *mut c_void, cb: Smb2CommandCallback, cb_data: *mut c_void));
raw_pdu_fn!(smb2_cmd_lease_break_async(ctx: *mut Smb2RustContext, req: *mut c_void, cb: Smb2CommandCallback, cb_data: *mut c_void));
raw_pdu_fn!(smb2_cmd_lease_break_reply_async(ctx: *mut Smb2RustContext, rep: *mut c_void, cb: Smb2CommandCallback, cb_data: *mut c_void));
raw_pdu_fn!(smb2_cmd_lease_break_notification_async(ctx: *mut Smb2RustContext, req: *mut c_void, cb: Smb2CommandCallback, cb_data: *mut c_void));
raw_pdu_fn!(smb2_cmd_error_reply_async(ctx: *mut Smb2RustContext, rep: *mut c_void, causing_command: u8, status: i32, cb: Smb2CommandCallback, cb_data: *mut c_void));

#[no_mangle]
pub extern "C" fn smb2_echo(_context: *mut Smb2RustContext) -> i32 {
    0
}

#[no_mangle]
pub extern "C" fn smb2_echo_async(
    ctx: *mut Smb2RustContext,
    cb: Smb2CommandCallback,
    cb_data: *mut c_void,
) -> i32 {
    unsafe { smb2_connect_async(ctx, c"echo".as_ptr(), cb, cb_data) }
}

#[no_mangle]
pub extern "C" fn free_smb2_file_notify_change_information(
    _context: *mut Smb2RustContext,
    ptr: *mut Smb2FileNotifyChangeInformationC,
) {
    if !ptr.is_null() {
        unsafe {
            free_nullable_c_string((*ptr).name);
            free_notify_chain_tail((*ptr).next);
            free(ptr.cast::<c_void>());
        }
    }
}

#[no_mangle]
pub extern "C" fn smb2_notify_change_async(
    _context: *mut Smb2RustContext,
    _path: *const c_char,
    _flags: u16,
    _filter: u32,
    _loop_: i32,
    _cb: Smb2CommandCallback,
    _cb_data: *mut c_void,
) -> i32 {
    not_implemented_code()
}

#[no_mangle]
pub extern "C" fn smb2_notify_change_filehandle_async(
    _context: *mut Smb2RustContext,
    _fh: *mut Smb2RustFileHandle,
    _flags: u16,
    _filter: u32,
    _loop_: i32,
    _cb: Smb2CommandCallback,
    _cb_data: *mut c_void,
) -> i32 {
    not_implemented_code()
}

#[no_mangle]
pub extern "C" fn smb2_notify_change(
    _context: *mut Smb2RustContext,
    _path: *const c_char,
    _flags: u16,
    _filter: u32,
) -> *mut c_void {
    ptr::null_mut()
}

#[no_mangle]
pub extern "C" fn smb2_bind_and_listen(_port: u16, _max_connections: i32, out_fd: *mut i32) -> i32 {
    if !out_fd.is_null() {
        unsafe { *out_fd = -1 };
    }
    not_implemented_code()
}

#[no_mangle]
pub extern "C" fn smb2_accept_connection_async(
    _fd: i32,
    _to_msecs: i32,
    _cb: Smb2AcceptedCallback,
    _cb_data: *mut c_void,
) -> i32 {
    not_implemented_code()
}

#[no_mangle]
pub extern "C" fn smb2_serve_port_async(
    _fd: i32,
    _to_msecs: i32,
    out_smb2: *mut *mut Smb2RustContext,
) -> i32 {
    if !out_smb2.is_null() {
        unsafe { *out_smb2 = ptr::null_mut() };
    }
    not_implemented_code()
}

#[no_mangle]
pub extern "C" fn smb2_serve_port(
    _server: *mut c_void,
    _max_connections: i32,
    _cb: Smb2ClientConnectionCallback,
    _cb_data: *mut c_void,
) -> i32 {
    not_implemented_code()
}

/// Creates a DCERPC context bound to an SMB2 context.
#[no_mangle]
pub extern "C" fn dcerpc_create_context(smb2: *mut Smb2RustContext) -> *mut DceRpcRustContext {
    Box::into_raw(Box::new(DceRpcRustContext {
        smb2,
        error_string: empty_c_string(),
        tctx: 0,
    }))
}

/// Frees DCERPC-owned data.
///
/// # Safety
///
/// `data` must be null or allocated by a compatible C allocator.
#[no_mangle]
pub unsafe extern "C" fn dcerpc_free_data(_dce: *mut DceRpcRustContext, data: *mut c_void) {
    if !data.is_null() {
        unsafe { free(data) };
    }
}

/// Returns the last DCERPC error string.
///
/// # Safety
///
/// `dce` must be null or valid.
#[no_mangle]
pub unsafe extern "C" fn dcerpc_get_error(dce: *mut DceRpcRustContext) -> *const c_char {
    if dce.is_null() {
        return c"".as_ptr();
    }
    unsafe { (*dce).error_string.as_ptr() }
}

/// Starts connecting a DCERPC context.
#[no_mangle]
pub extern "C" fn dcerpc_connect_context_async(
    _dce: *mut DceRpcRustContext,
    _path: *const c_char,
    _syntax: *mut PSyntaxId,
    _cb: DceRpcCallback,
    _cb_data: *mut c_void,
) -> i32 {
    not_implemented_code()
}

/// Destroys a DCERPC context.
///
/// # Safety
///
/// `dce` must be null or a pointer returned by `dcerpc_create_context`.
#[no_mangle]
pub unsafe extern "C" fn dcerpc_destroy_context(dce: *mut DceRpcRustContext) {
    if !dce.is_null() {
        unsafe { drop(Box::from_raw(dce)) };
    }
}

/// Returns the SMB2 context owned by a DCERPC context.
///
/// # Safety
///
/// `dce` must be null or valid.
#[no_mangle]
pub unsafe extern "C" fn dcerpc_get_smb2_context(
    dce: *mut DceRpcRustContext,
) -> *mut Smb2RustContext {
    if dce.is_null() {
        return ptr::null_mut();
    }
    unsafe { (*dce).smb2 }
}

/// Returns a pointer to the PDU payload.
///
/// # Safety
///
/// `pdu` must be null or valid.
#[no_mangle]
pub unsafe extern "C" fn dcerpc_get_pdu_payload(pdu: *mut DceRpcRustPdu) -> *mut c_void {
    if pdu.is_null() {
        return ptr::null_mut();
    }
    unsafe { (*pdu).payload.as_mut_ptr().cast::<c_void>() }
}

#[no_mangle]
pub extern "C" fn dcerpc_open_async(
    _dce: *mut DceRpcRustContext,
    _cb: DceRpcCallback,
    _cb_data: *mut c_void,
) -> i32 {
    not_implemented_code()
}

#[no_mangle]
pub extern "C" fn dcerpc_call_async(
    _dce: *mut DceRpcRustContext,
    _opnum: i32,
    _req_coder: DceRpcCoder,
    _req: *mut c_void,
    _rep_coder: DceRpcCoder,
    _decode_size: i32,
    _cb: DceRpcCallback,
    _cb_data: *mut c_void,
) -> i32 {
    not_implemented_code()
}

/// Invokes a DCERPC coder callback.
///
/// # Safety
///
/// All pointers must satisfy the legacy coder contract.
#[no_mangle]
pub unsafe extern "C" fn dcerpc_do_coder(
    dce: *mut DceRpcRustContext,
    pdu: *mut DceRpcRustPdu,
    iov: *mut Smb2Iovec,
    offset: *mut i32,
    ptr_: *mut c_void,
    coder: DceRpcCoder,
) -> i32 {
    let Some(coder) = coder else {
        return invalid_argument_code();
    };
    if pdu.is_null() {
        return unsafe { coder(dce, pdu, iov, offset, ptr_) };
    }

    let outer_conformance_run = unsafe { (*pdu).conformance_run };
    let outer_suppress_conformance_io = unsafe { (*pdu).suppress_conformance_io };
    if !outer_conformance_run {
        unsafe {
            (*pdu).max_alignment = 1;
            (*pdu).conformance_run = true;
            (*pdu).suppress_conformance_io = false;
        }
    }
    let rc = unsafe { coder(dce, pdu, iov, offset, ptr_) };
    if rc != 0 {
        return rc;
    }
    if !outer_conformance_run {
        let alignment = unsafe { (*pdu).max_alignment };
        if dcerpc_align_offset(offset, alignment).is_none() {
            return invalid_argument_code();
        }
    }
    unsafe {
        (*pdu).conformance_run = outer_conformance_run;
        (*pdu).suppress_conformance_io = outer_suppress_conformance_io;
    }
    if outer_conformance_run {
        return 0;
    }
    unsafe { coder(dce, pdu, iov, offset, ptr_) }
}

fn dcerpc_process_deferred_pointers(
    dce: *mut DceRpcRustContext,
    pdu: *mut DceRpcRustPdu,
    iov: *mut Smb2Iovec,
    offset: *mut i32,
) -> i32 {
    if pdu.is_null() {
        return 0;
    }
    loop {
        let next = unsafe {
            if (*pdu).deferred_pointers.is_empty() {
                None
            } else {
                Some((*pdu).deferred_pointers.remove(0))
            }
        };
        let Some(next) = next else {
            return 0;
        };
        let rc = unsafe { dcerpc_do_coder(dce, pdu, iov, offset, next.ptr, next.coder) };
        if rc != 0 {
            return rc;
        }
    }
}

/// Invokes a pointer coder callback.
///
/// # Safety
///
/// All pointers must satisfy the legacy coder contract.
#[no_mangle]
pub unsafe extern "C" fn dcerpc_ptr_coder(
    dce: *mut DceRpcRustContext,
    pdu: *mut DceRpcRustPdu,
    iov: *mut Smb2Iovec,
    offset: *mut i32,
    ptr_: *mut c_void,
    type_: i32,
    coder: DceRpcCoder,
) -> i32 {
    if pdu.is_null() {
        return unsafe { dcerpc_do_coder(dce, pdu, iov, offset, ptr_, coder) };
    }
    if unsafe { (*pdu).conformance_run } {
        if type_ != PTR_REF || unsafe { !(*pdu).top_level } {
            dcerpc_note_alignment(pdu, dcerpc_count_size(dce));
        }
        let suppress_conformance_io = unsafe { (*pdu).suppress_conformance_io };
        if type_ == PTR_REF && unsafe { (*pdu).top_level } {
            unsafe { (*pdu).suppress_conformance_io = true };
            let rc = unsafe { dcerpc_do_coder(dce, pdu, iov, offset, ptr_, coder) };
            unsafe { (*pdu).suppress_conformance_io = suppress_conformance_io };
            return rc;
        }
        unsafe { (*pdu).suppress_conformance_io = true };
        let rc = unsafe { dcerpc_do_coder(dce, pdu, iov, offset, ptr_, coder) };
        unsafe { (*pdu).suppress_conformance_io = suppress_conformance_io };
        if rc != 0 {
            return rc;
        }
        if unsafe { (*pdu).top_level } {
            return dcerpc_process_deferred_pointers(dce, pdu, iov, offset);
        }
        return 0;
    }

    let top_level = unsafe { (*pdu).top_level };
    if type_ == PTR_REF && top_level {
        unsafe { (*pdu).top_level = false };
        let rc = unsafe { dcerpc_do_coder(dce, pdu, iov, offset, ptr_, coder) };
        unsafe { (*pdu).top_level = top_level };
        if rc != 0 {
            return rc;
        }
    } else if type_ != PTR_REF {
        let Some(present) = dcerpc_code_pointer_referent(dce, pdu, iov, offset, !ptr_.is_null())
        else {
            return invalid_argument_code();
        };
        if !present {
            return 0;
        }
        if top_level {
            unsafe { (*pdu).top_level = false };
            let rc = unsafe { dcerpc_do_coder(dce, pdu, iov, offset, ptr_, coder) };
            unsafe { (*pdu).top_level = top_level };
            if rc != 0 {
                return rc;
            }
        } else {
            unsafe {
                (*pdu)
                    .deferred_pointers
                    .push(DeferredPointer { coder, ptr: ptr_ });
            }
        }
    } else {
        let Some(present) = dcerpc_code_pointer_referent(dce, pdu, iov, offset, !ptr_.is_null())
        else {
            return invalid_argument_code();
        };
        if present {
            unsafe {
                (*pdu)
                    .deferred_pointers
                    .push(DeferredPointer { coder, ptr: ptr_ });
            }
        }
    }

    if top_level {
        unsafe { (*pdu).top_level = false };
        let rc = dcerpc_process_deferred_pointers(dce, pdu, iov, offset);
        unsafe { (*pdu).top_level = top_level };
        return rc;
    }
    0
}

/// Invokes a coder over a C array.
///
/// # Safety
///
/// All pointers must satisfy the legacy coder contract.
#[no_mangle]
pub unsafe extern "C" fn dcerpc_carray_coder(
    dce: *mut DceRpcRustContext,
    pdu: *mut DceRpcRustPdu,
    iov: *mut Smb2Iovec,
    offset: *mut i32,
    num: i32,
    ptr_: *mut c_void,
    elem_size: i32,
    coder: DceRpcCoder,
) -> i32 {
    if num < 0 || elem_size < 0 {
        return invalid_argument_code();
    }
    for index in 0..num as usize {
        let elem = unsafe {
            ptr_.cast::<u8>()
                .add(index * elem_size as usize)
                .cast::<c_void>()
        };
        let rc = unsafe { dcerpc_do_coder(dce, pdu, iov, offset, elem, coder) };
        if rc != 0 {
            return rc;
        }
    }
    0
}

fn dcerpc_scalar_coder(
    pdu: *const DceRpcRustPdu,
    iov: *mut Smb2Iovec,
    offset: *mut i32,
    ptr_: *mut c_void,
    size: usize,
) -> i32 {
    if iov.is_null() || offset.is_null() || ptr_.is_null() {
        return invalid_argument_code();
    }
    let alignment = if size > 4 { 4 } else { size };
    dcerpc_note_alignment(pdu.cast_mut(), alignment);
    if !pdu.is_null() && unsafe { (*pdu).conformance_run } {
        return 0;
    }
    if dcerpc_align_offset(offset, alignment).is_none() {
        return invalid_argument_code();
    }
    let start = unsafe { *offset };
    if start < 0 {
        return invalid_argument_code();
    }
    let start = start as usize;
    let iov_ref = unsafe { &mut *iov };
    if !iov_ref.buf.is_null() && start.saturating_add(size) <= iov_ref.len {
        let little_endian = pdu.is_null() || unsafe { (*pdu).little_endian };
        if dcerpc_is_decode(pdu) {
            if little_endian || size == 1 {
                unsafe {
                    ptr::copy_nonoverlapping(iov_ref.buf.add(start), ptr_.cast::<u8>(), size)
                };
            } else {
                for index in 0..size {
                    unsafe {
                        *ptr_.cast::<u8>().add(index) = *iov_ref.buf.add(start + size - 1 - index)
                    };
                }
            }
        } else {
            if little_endian || size == 1 {
                unsafe {
                    ptr::copy_nonoverlapping(ptr_.cast::<u8>(), iov_ref.buf.add(start), size)
                };
            } else {
                for index in 0..size {
                    unsafe {
                        *iov_ref.buf.add(start + index) = *ptr_.cast::<u8>().add(size - 1 - index)
                    };
                }
            }
        }
    }
    unsafe {
        *offset = offset
            .read()
            .saturating_add(i32::try_from(size).unwrap_or(i32::MAX))
    };
    0
}

#[no_mangle]
pub extern "C" fn dcerpc_uint8_coder(
    _ctx: *mut DceRpcRustContext,
    pdu: *mut DceRpcRustPdu,
    iov: *mut Smb2Iovec,
    offset: *mut i32,
    ptr_: *mut c_void,
) -> i32 {
    dcerpc_scalar_coder(pdu, iov, offset, ptr_, 1)
}

#[no_mangle]
pub extern "C" fn dcerpc_uint16_coder(
    _ctx: *mut DceRpcRustContext,
    pdu: *mut DceRpcRustPdu,
    iov: *mut Smb2Iovec,
    offset: *mut i32,
    ptr_: *mut c_void,
) -> i32 {
    dcerpc_scalar_coder(pdu, iov, offset, ptr_, 2)
}

#[no_mangle]
pub extern "C" fn dcerpc_uint32_coder(
    _ctx: *mut DceRpcRustContext,
    pdu: *mut DceRpcRustPdu,
    iov: *mut Smb2Iovec,
    offset: *mut i32,
    ptr_: *mut c_void,
) -> i32 {
    dcerpc_scalar_coder(pdu, iov, offset, ptr_, 4)
}

#[no_mangle]
pub extern "C" fn dcerpc_uint3264_coder(
    ctx: *mut DceRpcRustContext,
    pdu: *mut DceRpcRustPdu,
    iov: *mut Smb2Iovec,
    offset: *mut i32,
    ptr_: *mut c_void,
) -> i32 {
    if dcerpc_count_size(ctx) == 8 {
        dcerpc_scalar_coder(pdu, iov, offset, ptr_, 8)
    } else {
        dcerpc_uint32_coder(ctx, pdu, iov, offset, ptr_)
    }
}

#[no_mangle]
pub extern "C" fn dcerpc_conformance_coder(
    ctx: *mut DceRpcRustContext,
    pdu: *mut DceRpcRustPdu,
    iov: *mut Smb2Iovec,
    offset: *mut i32,
    ptr_: *mut c_void,
) -> i32 {
    if !dcerpc_should_write_conformance(pdu) {
        return 0;
    }
    if dcerpc_count_size(ctx) == 8 {
        dcerpc_scalar_coder(pdu, iov, offset, ptr_, 8)
    } else {
        dcerpc_uint32_coder(ctx, pdu, iov, offset, ptr_)
    }
}

#[no_mangle]
pub extern "C" fn dcerpc_utf16_coder(
    ctx: *mut DceRpcRustContext,
    pdu: *mut DceRpcRustPdu,
    iov: *mut Smb2Iovec,
    offset: *mut i32,
    ptr_: *mut c_void,
) -> i32 {
    dcerpc_code_utf16_string(ctx, pdu, iov, offset, ptr_.cast::<DceRpcUtf16C>(), false)
}

#[no_mangle]
pub extern "C" fn dcerpc_utf16z_coder(
    ctx: *mut DceRpcRustContext,
    pdu: *mut DceRpcRustPdu,
    iov: *mut Smb2Iovec,
    offset: *mut i32,
    ptr_: *mut c_void,
) -> i32 {
    dcerpc_code_utf16_string(ctx, pdu, iov, offset, ptr_.cast::<DceRpcUtf16C>(), true)
}

#[no_mangle]
pub extern "C" fn srvsvc_SHARE_INFO_1_coder(
    ctx: *mut DceRpcRustContext,
    pdu: *mut DceRpcRustPdu,
    iov: *mut Smb2Iovec,
    offset: *mut i32,
    ptr_: *mut c_void,
) -> i32 {
    if ptr_.is_null() {
        return invalid_argument_code();
    }
    let share = ptr_.cast::<SrvsvcShareInfo1C>();
    let netname_present = unsafe { !(*share).netname.utf8.is_null() };
    let Some(netname_present) =
        dcerpc_code_pointer_referent(ctx, pdu, iov, offset, netname_present)
    else {
        return invalid_argument_code();
    };
    let rc = unsafe {
        dcerpc_uint32_coder(
            ctx,
            pdu,
            iov,
            offset,
            (&mut (*share).type_ as *mut u32).cast::<c_void>(),
        )
    };
    if rc != 0 {
        return rc;
    }
    let remark_present = unsafe { !(*share).remark.utf8.is_null() };
    let Some(remark_present) = dcerpc_code_pointer_referent(ctx, pdu, iov, offset, remark_present)
    else {
        return invalid_argument_code();
    };
    if netname_present {
        let rc = unsafe {
            dcerpc_utf16z_coder(
                ctx,
                pdu,
                iov,
                offset,
                (&mut (*share).netname as *mut DceRpcUtf16C).cast::<c_void>(),
            )
        };
        if rc != 0 {
            return rc;
        }
    }
    if remark_present {
        unsafe {
            dcerpc_utf16z_coder(
                ctx,
                pdu,
                iov,
                offset,
                (&mut (*share).remark as *mut DceRpcUtf16C).cast::<c_void>(),
            )
        }
    } else {
        0
    }
}

#[no_mangle]
pub extern "C" fn srvsvc_SHARE_INFO_1_CONTAINER_coder(
    ctx: *mut DceRpcRustContext,
    pdu: *mut DceRpcRustPdu,
    iov: *mut Smb2Iovec,
    offset: *mut i32,
    ptr_: *mut c_void,
) -> i32 {
    if ptr_.is_null() {
        return invalid_argument_code();
    }
    let container = ptr_.cast::<SrvsvcShareInfo1ContainerC>();
    let mut entries_read = unsafe { (*container).entries_read };
    let rc = dcerpc_uint3264_coder(
        ctx,
        pdu,
        iov,
        offset,
        (&mut entries_read as *mut u32).cast::<c_void>(),
    );
    if rc != 0 {
        return rc;
    }
    unsafe { (*container).entries_read = entries_read };

    let present = if dcerpc_is_decode(pdu) {
        let Some(value) = dcerpc_read_count(pdu, iov, offset, dcerpc_count_size(ctx)) else {
            return invalid_argument_code();
        };
        value != 0
    } else {
        let referent = if entries_read == 0 { 0 } else { 0x7274_7055 };
        let rc = dcerpc_write_count(pdu, iov, offset, referent, dcerpc_count_size(ctx));
        if rc != 0 {
            return rc;
        }
        entries_read != 0
    };
    if !present {
        return 0;
    }
    if dcerpc_is_decode(pdu) {
        // Phase 2 public-surface tests pass caller-owned backing storage.
        if unsafe { (*container).share_info_1.is_null() } {
            return invalid_argument_code();
        }
    }
    let Some(array_count) =
        dcerpc_read_or_write_count(pdu, iov, offset, entries_read, dcerpc_count_size(ctx))
    else {
        return invalid_argument_code();
    };
    unsafe { (*container).entries_read = array_count };
    for index in 0..array_count as usize {
        let item = unsafe { (*container).share_info_1.add(index) };
        let rc = srvsvc_SHARE_INFO_1_coder(ctx, pdu, iov, offset, item.cast::<c_void>());
        if rc != 0 {
            return rc;
        }
    }
    0
}

#[no_mangle]
pub extern "C" fn dcerpc_context_handle_coder(
    _dce: *mut DceRpcRustContext,
    pdu: *mut DceRpcRustPdu,
    iov: *mut Smb2Iovec,
    offset: *mut i32,
    ptr_: *mut c_void,
) -> i32 {
    dcerpc_scalar_coder(
        pdu,
        iov,
        offset,
        ptr_,
        core::mem::size_of::<NdrContextHandle>(),
    )
}

#[no_mangle]
pub extern "C" fn dcerpc_uuid_coder(
    _dce: *mut DceRpcRustContext,
    pdu: *mut DceRpcRustPdu,
    iov: *mut Smb2Iovec,
    offset: *mut i32,
    uuid: *mut DceRpcUuid,
) -> i32 {
    dcerpc_scalar_coder(
        pdu,
        iov,
        offset,
        uuid.cast::<c_void>(),
        core::mem::size_of::<DceRpcUuid>(),
    )
}

#[no_mangle]
pub extern "C" fn dcerpc_allocate_pdu(
    _dce: *mut DceRpcRustContext,
    direction: i32,
    payload_size: i32,
) -> *mut DceRpcRustPdu {
    let payload_size = usize::try_from(payload_size).unwrap_or(0);
    Box::into_raw(Box::new(DceRpcRustPdu {
        direction,
        payload: vec![0; payload_size],
        allocations: Vec::new(),
        deferred_pointers: Vec::new(),
        size_is: 0,
        little_endian: true,
        top_level: true,
        conformance_run: false,
        suppress_conformance_io: false,
        max_alignment: 1,
    }))
}

/// Frees a DCERPC PDU.
///
/// # Safety
///
/// `pdu` must be null or a pointer returned by `dcerpc_allocate_pdu`.
#[no_mangle]
pub unsafe extern "C" fn dcerpc_free_pdu(_dce: *mut DceRpcRustContext, pdu: *mut DceRpcRustPdu) {
    if !pdu.is_null() {
        let mut pdu = unsafe { Box::from_raw(pdu) };
        for allocation in pdu.allocations.drain(..) {
            unsafe { drop(CString::from_raw(allocation)) };
        }
    }
}

#[no_mangle]
pub extern "C" fn dcerpc_set_size_is(pdu: *mut DceRpcRustPdu, size_is: i32) {
    if !pdu.is_null() {
        unsafe { (*pdu).size_is = size_is };
    }
}

#[no_mangle]
pub extern "C" fn dcerpc_get_size_is(pdu: *mut DceRpcRustPdu) -> i32 {
    if pdu.is_null() {
        0
    } else {
        unsafe { (*pdu).size_is }
    }
}

#[no_mangle]
pub extern "C" fn dcerpc_set_tctx(ctx: *mut DceRpcRustContext, tctx: i32) {
    if !ctx.is_null() {
        unsafe { (*ctx).tctx = tctx };
    }
}

#[no_mangle]
pub extern "C" fn dcerpc_set_endian(pdu: *mut DceRpcRustPdu, little_endian: i32) {
    if !pdu.is_null() {
        unsafe { (*pdu).little_endian = little_endian != 0 };
    }
}

macro_rules! dcerpc_stub_coder {
    ($($name:ident),+ $(,)?) => {$(
        #[no_mangle]
        pub extern "C" fn $name(
            _dce: *mut DceRpcRustContext,
            _pdu: *mut DceRpcRustPdu,
            _iov: *mut Smb2Iovec,
            _offset: *mut i32,
            _ptr: *mut c_void,
        ) -> i32 { 0 }
    )+};
}

dcerpc_stub_coder!(
    lsa_Close_rep_coder,
    lsa_Close_req_coder,
    lsa_LookupSids2_rep_coder,
    lsa_LookupSids2_req_coder,
    lsa_OpenPolicy2_rep_coder,
    lsa_OpenPolicy2_req_coder,
    lsa_RPC_SID_coder,
    srvsvc_SHARE_INFO_0_coder,
    srvsvc_NetrShareEnum_rep_coder,
    srvsvc_NetrShareEnum_req_coder,
    srvsvc_NetrShareGetInfo_rep_coder,
    srvsvc_NetrShareGetInfo_req_coder,
);

#[no_mangle]
pub extern "C" fn smb2_share_enum_async(
    _context: *mut Smb2RustContext,
    _level: i32,
    _cb: Smb2CommandCallback,
    _cb_data: *mut c_void,
) -> i32 {
    not_implemented_code()
}

#[no_mangle]
pub extern "C" fn smb2_share_enum_sync(_context: *mut Smb2RustContext, _level: i32) -> *mut c_void {
    ptr::null_mut()
}
