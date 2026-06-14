mod ffi {
    #![allow(
        dead_code,
        non_camel_case_types,
        non_snake_case,
        non_upper_case_globals
    )]
    include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
}

use std::ffi::CStr;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessResult {
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
    pub closedir_calls: i32,
    pub disconnect_calls: i32,
    pub destroy_url_calls: i32,
    pub destroy_context_calls: i32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TypeMapping {
    pub link_type: String,
    pub file_type: String,
    pub directory_type: String,
    pub unknown_type: String,
}

fn text_from_buf(buf: &[i8]) -> String {
    unsafe { CStr::from_ptr(buf.as_ptr()) }
        .to_string_lossy()
        .into_owned()
}

fn process_result(raw: ffi::smb2_ls_ffi_process_result) -> ProcessResult {
    ProcessResult {
        exit_code: raw.exit_code,
        stdout: text_from_buf(&raw.stdout_text),
        stderr: text_from_buf(&raw.stderr_text),
        closedir_calls: raw.closedir_calls,
        disconnect_calls: raw.disconnect_calls,
        destroy_url_calls: raw.destroy_url_calls,
        destroy_context_calls: raw.destroy_context_calls,
    }
}

pub fn usage_missing_arg() -> ProcessResult {
    let mut raw = unsafe { std::mem::zeroed() };
    unsafe { ffi::smb2_ls_ffi_usage_missing_arg(&mut raw) };
    process_result(raw)
}

pub fn list_directory_success() -> ProcessResult {
    let mut raw = unsafe { std::mem::zeroed() };
    unsafe { ffi::smb2_ls_ffi_list_directory_success(&mut raw) };
    process_result(raw)
}

pub fn directory_type_mapping() -> TypeMapping {
    let mut raw = unsafe { std::mem::zeroed() };
    unsafe { ffi::smb2_ls_ffi_directory_type_mapping(&mut raw) };
    TypeMapping {
        link_type: text_from_buf(&raw.link_type),
        file_type: text_from_buf(&raw.file_type),
        directory_type: text_from_buf(&raw.directory_type),
        unknown_type: text_from_buf(&raw.unknown_type),
    }
}

pub fn readlink_success() -> ProcessResult {
    let mut raw = unsafe { std::mem::zeroed() };
    unsafe { ffi::smb2_ls_ffi_readlink_success(&mut raw) };
    process_result(raw)
}

pub fn readlink_failure() -> ProcessResult {
    let mut raw = unsafe { std::mem::zeroed() };
    unsafe { ffi::smb2_ls_ffi_readlink_failure(&mut raw) };
    process_result(raw)
}

pub fn context_init_failure() -> ProcessResult {
    let mut raw = unsafe { std::mem::zeroed() };
    unsafe { ffi::smb2_ls_ffi_context_init_failure(&mut raw) };
    process_result(raw)
}

pub fn url_parse_failure() -> ProcessResult {
    let mut raw = unsafe { std::mem::zeroed() };
    unsafe { ffi::smb2_ls_ffi_url_parse_failure(&mut raw) };
    process_result(raw)
}

pub fn connect_share_failure() -> ProcessResult {
    let mut raw = unsafe { std::mem::zeroed() };
    unsafe { ffi::smb2_ls_ffi_connect_share_failure(&mut raw) };
    process_result(raw)
}

pub fn opendir_failure() -> ProcessResult {
    let mut raw = unsafe { std::mem::zeroed() };
    unsafe { ffi::smb2_ls_ffi_opendir_failure(&mut raw) };
    process_result(raw)
}

pub fn readdir_end_cleanup() -> ProcessResult {
    let mut raw = unsafe { std::mem::zeroed() };
    unsafe { ffi::smb2_ls_ffi_readdir_end_cleanup(&mut raw) };
    process_result(raw)
}
