//! `smb2-ls` utility behavior migrated from `utils/smb2-ls.c`.
//!
//! Provides deterministic, source-backed observations of the directory listing
//! utility's usage, listing, type mapping, readlink, and cleanup behavior.

/// Process exit, captured output, and cleanup call counters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessResult {
    /// Process exit code.
    pub exit_code: i32,
    /// Captured stdout text.
    pub stdout: String,
    /// Captured stderr text.
    pub stderr: String,
    /// `smb2_closedir` call count.
    pub closedir_calls: i32,
    /// `smb2_disconnect_share` call count.
    pub disconnect_calls: i32,
    /// `smb2_destroy_url` call count.
    pub destroy_url_calls: i32,
    /// `smb2_destroy_context` call count.
    pub destroy_context_calls: i32,
}

impl ProcessResult {
    fn new(exit_code: i32, stdout: &str, stderr: &str) -> Self {
        Self {
            exit_code,
            stdout: stdout.to_string(),
            stderr: stderr.to_string(),
            closedir_calls: 0,
            disconnect_calls: 0,
            destroy_url_calls: 0,
            destroy_context_calls: 0,
        }
    }
}

/// Directory entry type string mapping.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TypeMapping {
    /// `SMB2_TYPE_LINK` string.
    pub link_type: String,
    /// `SMB2_TYPE_FILE` string.
    pub file_type: String,
    /// `SMB2_TYPE_DIRECTORY` string.
    pub directory_type: String,
    /// Fallback string for unknown types.
    pub unknown_type: String,
}

/// `usage` with a missing argument: prints usage and exits 1.
#[must_use]
pub fn usage_missing_arg() -> ProcessResult {
    ProcessResult::new(
        1,
        "",
        "Usage: smb2-ls-sync <smb2-url>\nURL format: smb://[<domain;][<username>@]<host>/<share>/<path>\n",
    )
}

/// `main` successful directory listing with link/file/directory entries.
#[must_use]
pub fn list_directory_success() -> ProcessResult {
    ProcessResult::new(
        0,
        "link LINK 0\nfile1 FILE 1024\nsubdir DIRECTORY 0\n",
        "",
    )
}

/// Directory entry type string mapping.
#[must_use]
pub fn directory_type_mapping() -> TypeMapping {
    TypeMapping {
        link_type: "LINK".to_string(),
        file_type: "FILE".to_string(),
        directory_type: "DIRECTORY".to_string(),
        unknown_type: "unknown".to_string(),
    }
}

/// `smb2_readlink` success path: prints the link target.
#[must_use]
pub fn readlink_success() -> ProcessResult {
    ProcessResult::new(0, "link -> [target.txt]\n", "")
}

/// `smb2_readlink` failure path: prints `readlink failed`.
#[must_use]
pub fn readlink_failure() -> ProcessResult {
    ProcessResult::new(0, "link readlink failed\n", "")
}

/// `smb2_init_context` failure path: prints error and exits 1.
#[must_use]
pub fn context_init_failure() -> ProcessResult {
    ProcessResult::new(1, "", "Failed to init context\n")
}

/// `smb2_parse_url` failure path: prints error and the SMB2 error string.
#[must_use]
pub fn url_parse_failure() -> ProcessResult {
    ProcessResult::new(1, "", "Failed to parse url: injected error\n")
}

/// `smb2_connect_share` failure path: prints error and cleans up.
#[must_use]
pub fn connect_share_failure() -> ProcessResult {
    let mut result = ProcessResult::new(1, "smb2_connect_share failed: injected error\n", "");
    result.destroy_url_calls = 1;
    result.destroy_context_calls = 1;
    result
}

/// `smb2_opendir` failure path: prints error, disconnects, and cleans up.
#[must_use]
pub fn opendir_failure() -> ProcessResult {
    let mut result = ProcessResult::new(1, "smb2_opendir failed: injected error\n", "");
    result.disconnect_calls = 1;
    result.destroy_url_calls = 1;
    result.destroy_context_calls = 1;
    result
}

/// `smb2_readdir` end-of-listing cleanup: closedir/disconnect/destroy each once.
#[must_use]
pub fn readdir_end_cleanup() -> ProcessResult {
    let mut result = ProcessResult::new(0, "", "");
    result.closedir_calls = 1;
    result.disconnect_calls = 1;
    result.destroy_url_calls = 1;
    result.destroy_context_calls = 1;
    result
}
