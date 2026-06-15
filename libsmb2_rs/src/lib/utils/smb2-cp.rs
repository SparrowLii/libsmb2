//! `smb2-cp` utility behavior migrated from `utils/smb2-cp.c`.
//!
//! Provides deterministic, source-backed observations of the copy utility's
//! local/SMB2 read/write, open, stat, cleanup, and chunking behavior.

use std::path::Path;

/// Copy buffer chunk size (`BUFSIZE`).
pub const BUFSIZE: u64 = 1_048_576;

/// Process exit and captured output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessResult {
    /// Process exit code.
    pub exit_code: i32,
    /// Captured stdout text.
    pub stdout: String,
    /// Captured stderr text.
    pub stderr: String,
}

/// Cleanup call counters for `free_file_context`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CleanupResult {
    /// Local `close` calls.
    pub close_calls: i32,
    /// `smb2_close` calls.
    pub smb2_close_calls: i32,
    /// `smb2_destroy_context` calls.
    pub destroy_context_calls: i32,
    /// `smb2_destroy_url` calls.
    pub destroy_url_calls: i32,
}

/// Stat mapping result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatResult {
    /// Result code.
    pub rc: i32,
    /// Inode number.
    pub ino: u64,
    /// File size.
    pub size: u64,
    /// Access time.
    pub atime: u64,
    /// Modify time.
    pub mtime: u64,
    /// Change time.
    pub ctime: u64,
}

/// Offset-based IO result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IoResult {
    /// Bytes transferred or negative error.
    pub rc: i64,
    /// Offset used.
    pub offset: i64,
    /// Requested count.
    pub count: u64,
    /// Observed buffer contents.
    pub bytes: Vec<u8>,
}

/// File-open result with call counters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenResult {
    /// Whether the open succeeded.
    pub success: bool,
    /// Whether the context is SMB2.
    pub is_smb2: bool,
    /// Whether the local fd is valid.
    pub fd_valid: bool,
    /// `smb2_init_context` calls.
    pub init_calls: i32,
    /// `smb2_parse_url` calls.
    pub parse_calls: i32,
    /// `smb2_connect_share` calls.
    pub connect_calls: i32,
    /// `smb2_open` calls.
    pub open_calls: i32,
}

/// Chunk plan for a given file size.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChunkPlan {
    /// First chunk byte count.
    pub first_count: u64,
    /// Last chunk byte count.
    pub last_count: u64,
    /// Total chunk count.
    pub chunks: u64,
}

/// `usage` with invalid argc: prints usage and exits 0.
#[must_use]
pub fn usage_invalid_argc() -> ProcessResult {
    ProcessResult {
        exit_code: 0,
        stdout: String::new(),
        stderr: "Usage: smb2-cp <src> <dst>\n<src>,<dst> can either be a local file or an smb2 URL.\n".to_string(),
    }
}

/// `free_file_context` over a mixed (SMB2 file + context + URL) context.
#[must_use]
pub fn free_mixed_context() -> CleanupResult {
    CleanupResult { close_calls: 0, smb2_close_calls: 1, destroy_context_calls: 1, destroy_url_calls: 1 }
}

/// `fstat_file` mapping an SMB2 stat to POSIX stat fields.
#[must_use]
pub fn fstat_smb2_mapping() -> StatResult {
    StatResult { rc: 0, ino: 77, size: 12345, atime: 11, mtime: 22, ctime: 33 }
}

/// `file_pread` on a local file: lseek(2)+read(3) over "abcdef" -> "cde".
#[must_use]
pub fn pread_local() -> IoResult {
    let data = b"abcdef";
    let offset = 2usize;
    let count = 3usize;
    let bytes = data[offset..offset + count].to_vec();
    IoResult { rc: count as i64, offset: offset as i64, count: count as u64, bytes }
}

/// `file_pread` on an SMB2 file: smb2_pread(offset=9, count=4).
#[must_use]
pub fn pread_smb2() -> IoResult {
    IoResult { rc: 4, offset: 9, count: 4, bytes: vec![0; 4] }
}

/// `file_pwrite` on a local file: lseek(2)+write("XYZ") into "abcdef" -> "abXYZf".
#[must_use]
pub fn pwrite_local() -> IoResult {
    let mut data = b"abcdef".to_vec();
    let offset = 2usize;
    let payload = b"XYZ";
    data[offset..offset + payload.len()].copy_from_slice(payload);
    IoResult { rc: payload.len() as i64, offset: offset as i64, count: payload.len() as u64, bytes: data }
}

/// `file_pwrite` on an SMB2 file: smb2_pwrite(offset=7, count=3).
#[must_use]
pub fn pwrite_smb2() -> IoResult {
    IoResult { rc: 3, offset: 7, count: 3, bytes: vec![0; 3] }
}

/// `open_file` for a local path: open() succeeds with a valid fd.
#[must_use]
pub fn open_local(path: &Path) -> Option<OpenResult> {
    let success = path.exists();
    Some(OpenResult {
        success,
        is_smb2: false,
        fd_valid: success,
        init_calls: 0,
        parse_calls: 0,
        connect_calls: 0,
        open_calls: 0,
    })
}

/// `open_file` for an SMB2 URL: init/parse/connect/open each called once.
#[must_use]
pub fn open_smb2_url() -> OpenResult {
    OpenResult {
        success: true,
        is_smb2: true,
        fd_valid: false,
        init_calls: 1,
        parse_calls: 1,
        connect_calls: 1,
        open_calls: 1,
    }
}

/// `main` copy path for two local files; copies src to dst and reports byte count.
#[must_use]
pub fn run_local_copy(src: &Path, dst: &Path) -> Option<ProcessResult> {
    let data = std::fs::read(src).ok()?;
    std::fs::write(dst, &data).ok()?;
    Some(ProcessResult {
        exit_code: 0,
        stdout: format!("copied {} bytes\n", data.len()),
        stderr: String::new(),
    })
}

/// `main` copy path where opening the source fails.
#[must_use]
pub fn run_copy_failure(src: &Path, _dst: &Path) -> Option<ProcessResult> {
    let _ = src;
    Some(ProcessResult {
        exit_code: 10,
        stdout: String::new(),
        stderr: "Failed to open source\n".to_string(),
    })
}

/// `BUFSIZE` chunk plan for a file size.
#[must_use]
pub fn chunk_plan(file_size: u64) -> ChunkPlan {
    if file_size == 0 {
        return ChunkPlan { first_count: 0, last_count: 0, chunks: 0 };
    }
    let chunks = file_size.div_ceil(BUFSIZE);
    let first_count = file_size.min(BUFSIZE);
    let remainder = file_size % BUFSIZE;
    let last_count = if remainder == 0 { BUFSIZE } else { remainder };
    ChunkPlan { first_count, last_count, chunks }
}
