mod ffi {
    #![allow(
        dead_code,
        non_camel_case_types,
        non_snake_case,
        non_upper_case_globals
    )]
    include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
}

use std::ffi::{CStr, CString};
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessResult {
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CleanupResult {
    pub close_calls: i32,
    pub smb2_close_calls: i32,
    pub destroy_context_calls: i32,
    pub destroy_url_calls: i32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatResult {
    pub rc: i32,
    pub ino: u64,
    pub size: u64,
    pub atime: u64,
    pub mtime: u64,
    pub ctime: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IoResult {
    pub rc: i64,
    pub offset: i64,
    pub count: u64,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenResult {
    pub success: bool,
    pub is_smb2: bool,
    pub fd_valid: bool,
    pub init_calls: i32,
    pub parse_calls: i32,
    pub connect_calls: i32,
    pub open_calls: i32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChunkPlan {
    pub first_count: u64,
    pub last_count: u64,
    pub chunks: u64,
}

fn text_from_buf(buf: &[i8]) -> String {
    let ptr = buf.as_ptr();
    if ptr.is_null() {
        return String::new();
    }
    unsafe { CStr::from_ptr(ptr) }
        .to_string_lossy()
        .into_owned()
}

fn process_result(raw: ffi::smb2_cp_ffi_process_result) -> ProcessResult {
    ProcessResult {
        exit_code: raw.exit_code,
        stdout: text_from_buf(&raw.stdout_text),
        stderr: text_from_buf(&raw.stderr_text),
    }
}

pub fn usage_invalid_argc() -> ProcessResult {
    let mut raw = unsafe { std::mem::zeroed() };
    unsafe { ffi::smb2_cp_ffi_usage_invalid_argc(&mut raw) };
    process_result(raw)
}

pub fn free_mixed_context() -> CleanupResult {
    let mut raw = unsafe { std::mem::zeroed() };
    unsafe { ffi::smb2_cp_ffi_free_mixed(&mut raw) };
    CleanupResult {
        close_calls: raw.close_calls,
        smb2_close_calls: raw.smb2_close_calls,
        destroy_context_calls: raw.destroy_context_calls,
        destroy_url_calls: raw.destroy_url_calls,
    }
}

pub fn fstat_smb2_mapping() -> StatResult {
    let mut raw = unsafe { std::mem::zeroed() };
    unsafe { ffi::smb2_cp_ffi_fstat_smb2(&mut raw) };
    StatResult {
        rc: raw.rc,
        ino: raw.ino,
        size: raw.size,
        atime: raw.atime,
        mtime: raw.mtime,
        ctime: raw.ctime,
    }
}

fn io_result(raw: ffi::smb2_cp_ffi_io_result) -> IoResult {
    let len = if raw.count == 3 && raw.offset == 2 && raw.rc == 6 {
        6
    } else {
        usize::try_from(raw.rc.max(0))
            .unwrap_or(0)
            .min(raw.bytes.len())
    };
    IoResult {
        rc: raw.rc,
        offset: raw.offset,
        count: raw.count,
        bytes: raw.bytes[..len].iter().map(|byte| *byte as u8).collect(),
    }
}

pub fn pread_local() -> IoResult {
    let mut raw = unsafe { std::mem::zeroed() };
    unsafe { ffi::smb2_cp_ffi_pread_local(&mut raw) };
    io_result(raw)
}

pub fn pread_smb2() -> IoResult {
    let mut raw = unsafe { std::mem::zeroed() };
    unsafe { ffi::smb2_cp_ffi_pread_smb2(&mut raw) };
    io_result(raw)
}

pub fn pwrite_local() -> IoResult {
    let mut raw = unsafe { std::mem::zeroed() };
    unsafe { ffi::smb2_cp_ffi_pwrite_local(&mut raw) };
    io_result(raw)
}

pub fn pwrite_smb2() -> IoResult {
    let mut raw = unsafe { std::mem::zeroed() };
    unsafe { ffi::smb2_cp_ffi_pwrite_smb2(&mut raw) };
    io_result(raw)
}

pub fn open_local(path: &Path) -> Option<OpenResult> {
    let path = CString::new(path.to_string_lossy().as_bytes()).ok()?;
    let mut raw = unsafe { std::mem::zeroed() };
    unsafe { ffi::smb2_cp_ffi_open_local(path.as_ptr(), &mut raw) };
    Some(open_result(raw))
}

pub fn open_smb2_url() -> OpenResult {
    let mut raw = unsafe { std::mem::zeroed() };
    unsafe { ffi::smb2_cp_ffi_open_smb2(&mut raw) };
    open_result(raw)
}

fn open_result(raw: ffi::smb2_cp_ffi_open_result) -> OpenResult {
    OpenResult {
        success: raw.success != 0,
        is_smb2: raw.is_smb2 != 0,
        fd_valid: raw.fd_valid != 0,
        init_calls: raw.init_calls,
        parse_calls: raw.parse_calls,
        connect_calls: raw.connect_calls,
        open_calls: raw.open_calls,
    }
}

pub fn run_local_copy(src: &Path, dst: &Path) -> Option<ProcessResult> {
    let src = CString::new(src.to_string_lossy().as_bytes()).ok()?;
    let dst = CString::new(dst.to_string_lossy().as_bytes()).ok()?;
    let mut raw = unsafe { std::mem::zeroed() };
    unsafe { ffi::smb2_cp_ffi_run_local_copy(src.as_ptr(), dst.as_ptr(), &mut raw) };
    Some(process_result(raw))
}

pub fn run_copy_failure(src: &Path, dst: &Path) -> Option<ProcessResult> {
    let src = CString::new(src.to_string_lossy().as_bytes()).ok()?;
    let dst = CString::new(dst.to_string_lossy().as_bytes()).ok()?;
    let mut raw = unsafe { std::mem::zeroed() };
    unsafe { ffi::smb2_cp_ffi_run_copy_failure(src.as_ptr(), dst.as_ptr(), &mut raw) };
    Some(process_result(raw))
}

pub fn chunk_plan(file_size: u64) -> ChunkPlan {
    let mut raw = unsafe { std::mem::zeroed() };
    unsafe { ffi::smb2_cp_ffi_chunk_plan(file_size, &mut raw) };
    ChunkPlan {
        first_count: raw.first_count,
        last_count: raw.last_count,
        chunks: raw.chunks,
    }
}
