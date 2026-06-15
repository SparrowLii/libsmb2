use libsmb2_rs::lib::utils::smb2_cp;
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

fn temp_path(name: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("libsmb2-rs-{name}-{nanos}"))
}

// Trace: `utils/smb2-cp.c:usage`, `utils/smb2-cp.c:main`
// Spec: usage command-line help#参数数量无效时打印用法
// - **GIVEN** 调用方启动 `smb2-cp` 且传入的参数数量不是 2 个路径参数
// - **WHEN** `main` 调用 `usage`
// - **THEN** 程序向 `stderr` 写入用法和源/目标支持本地文件或 SMB2 URL 的说明，并通过 `exit(0)` 终止
#[test]
fn test_smb2_cp_usage_invalid_argc() {
    let result = smb2_cp::usage_invalid_argc();
    assert_eq!(result.exit_code, 0);
    assert!(result.stderr.contains("Usage: smb2-cp <src> <dst>"));
    assert!(result
        .stderr
        .contains("<src>,<dst> can either be a local file or an smb2 URL."));
}

// Trace: `utils/smb2-cp.c:free_file_context`
// Spec: free_file_context release owned resources#释放混合文件上下文
// - **GIVEN** `file_context` 可能包含本地 `fd`、SMB2 file handle、SMB2 context 或 parsed URL
// - **WHEN** 调用 `free_file_context`
// - **THEN** 函数对有效本地 fd 调用 `close`，对非空 SMB2 file handle 调用 `smb2_close`，对非空 SMB2 context 调用 `smb2_destroy_context`，并总是销毁 URL 后释放上下文对象
#[test]
fn test_smb2_cp_free_file_context_mixed() {
    let cleanup = smb2_cp::free_mixed_context();
    assert_eq!(cleanup.smb2_close_calls, 1);
    assert_eq!(cleanup.destroy_context_calls, 1);
    assert_eq!(cleanup.destroy_url_calls, 1);
}

// Trace: `utils/smb2-cp.c:fstat_file`
// Spec: fstat_file normalize source metadata#SMB2 统计信息映射到 POSIX stat
// - **GIVEN** `file_context` 标记为 SMB2 文件且调用方提供 `struct stat` 输出对象
// - **WHEN** 调用 `fstat_file`
// - **THEN** 函数调用 `smb2_fstat`，设置 inode、size、访问/修改/变更时间等字段，并返回 `smb2_fstat` 的结果码
#[test]
fn test_smb2_cp_fstat_smb2_mapping() {
    let stat = smb2_cp::fstat_smb2_mapping();
    assert_eq!(stat.rc, 0);
    assert_eq!(stat.ino, 77);
    assert_eq!(stat.size, 12345);
    assert_eq!(stat.atime, 11);
    assert_eq!(stat.mtime, 22);
    assert_eq!(stat.ctime, 33);
}

// Trace: `utils/smb2-cp.c:file_pread`
// Spec: file_pread offset-based reads#本地和 SMB2 源文件按偏移读取
// - **GIVEN** 调用方提供文件上下文、目标缓冲区、读长度和偏移
// - **WHEN** 调用 `file_pread`
// - **THEN** 本地文件路径先 `lseek` 到偏移再调用 `read`，SMB2 文件路径调用 `smb2_pread`，返回值表示读取字节数或负数错误
#[test]
fn test_smb2_cp_file_pread_offset() {
    let local = smb2_cp::pread_local();
    assert_eq!(local.rc, 3);
    assert_eq!(local.offset, 2);
    assert_eq!(local.bytes, b"cde");

    let smb2 = smb2_cp::pread_smb2();
    assert_eq!(smb2.rc, 4);
    assert_eq!(smb2.offset, 9);
    assert_eq!(smb2.count, 4);
}

// Trace: `utils/smb2-cp.c:file_pwrite`
// Spec: file_pwrite offset-based writes#本地和 SMB2 目标文件按偏移写入
// - **GIVEN** 调用方提供文件上下文、源缓冲区、写长度和偏移
// - **WHEN** 调用 `file_pwrite`
// - **THEN** 本地文件路径先 `lseek` 到偏移再调用 `write`，SMB2 文件路径调用 `smb2_pwrite`，返回值表示写入字节数或负数错误
#[test]
fn test_smb2_cp_file_pwrite_offset() {
    let local = smb2_cp::pwrite_local();
    assert_eq!(local.rc, 3);
    assert_eq!(local.offset, 2);
    assert_eq!(local.bytes, b"abXYZf");

    let smb2 = smb2_cp::pwrite_smb2();
    assert_eq!(smb2.rc, 3);
    assert_eq!(smb2.offset, 7);
    assert_eq!(smb2.count, 3);
}

// Trace: `utils/smb2-cp.c:open_file`
// Spec: open_file create local or SMB2 context#打开本地文件
// - **GIVEN** 输入路径不以 `smb://` 开头
// - **WHEN** 调用 `open_file` 并传入打开标志
// - **THEN** 函数使用 `open(url, flags, 0660)` 打开本地文件，成功时返回 `is_smb2 == 0` 的上下文，失败时打印错误并释放上下文
#[test]
fn test_smb2_cp_open_local_file() {
    let path = temp_path("open-local");
    fs::write(&path, b"local").unwrap();
    let opened = smb2_cp::open_local(&path).unwrap();
    fs::remove_file(&path).unwrap();

    assert!(opened.success);
    assert!(!opened.is_smb2);
    assert!(opened.fd_valid);
}

// Trace: `utils/smb2-cp.c:open_file`
// Spec: open_file create local or SMB2 context#打开 SMB2 URL
// - **GIVEN** 输入路径以 `smb://` 开头
// - **WHEN** 调用 `open_file` 并传入打开标志
// - **THEN** 函数初始化 SMB2 context、解析 URL、连接 share、打开远端路径，成功时返回 `is_smb2 == 1` 的上下文，失败时打印 libsmb2 错误并释放上下文
#[test]
fn test_smb2_cp_open_smb2_url() {
    let opened = smb2_cp::open_smb2_url();
    assert!(opened.success);
    assert!(opened.is_smb2);
    assert_eq!(opened.init_calls, 1);
    assert_eq!(opened.parse_calls, 1);
    assert_eq!(opened.connect_calls, 1);
    assert_eq!(opened.open_calls, 1);
}

// Trace: `utils/smb2-cp.c:main`
// Spec: main copy source to destination#成功复制本地或 SMB2 文件
// - **GIVEN** 调用方传入源路径和目标路径，二者可以分别是本地文件或 SMB2 URL
// - **WHEN** `main` 成功打开源和目标、读取源大小并进入复制循环
// - **THEN** 程序从偏移 0 开始按不超过 `BUFSIZE` 的块读取源并写入目标，直到偏移达到源大小，随后打印 `copied <bytes> bytes`、释放两个上下文并返回 0
#[test]
fn test_smb2_cp_main_copy_success() {
    let src = temp_path("copy-src");
    let dst = temp_path("copy-dst");
    fs::write(&src, b"copy payload").unwrap();
    let result = smb2_cp::run_local_copy(&src, &dst).unwrap();
    let copied = fs::read(&dst).unwrap();
    fs::remove_file(&src).unwrap();
    fs::remove_file(&dst).unwrap();

    assert_eq!(result.exit_code, 0);
    assert!(result.stdout.contains("copied 12 bytes"));
    assert_eq!(copied, b"copy payload");
}

// Trace: `utils/smb2-cp.c:main`
// Spec: main copy source to destination#打开或复制失败返回错误
// - **GIVEN** 源打开、目标打开、源 stat、读取或写入任一步骤失败
// - **WHEN** `main` 检测到失败返回值
// - **THEN** 程序向 `stderr` 输出对应错误消息，释放已经打开的上下文，并返回 `10`
#[test]
fn test_smb2_cp_main_copy_failure() {
    let missing = temp_path("missing-src");
    let dst = temp_path("failure-dst");
    let result = smb2_cp::run_copy_failure(&missing, &dst).unwrap();

    assert_eq!(result.exit_code, 10);
    assert!(result.stderr.contains("Failed to open"));
}

// Trace: `utils/smb2-cp.c:BUFSIZE`, `utils/smb2-cp.c:main`
// Spec: BUFSIZE copy chunk limit#大文件分块复制
// - **GIVEN** 源文件大小大于 `BUFSIZE`
// - **WHEN** `main` 计算当前循环的 `count`
// - **THEN** `count` 不超过 `BUFSIZE`，最后一个块按 `st.st_size - off` 的剩余字节数复制
#[test]
fn test_smb2_cp_bufsize_chunk_limit() {
    let plan = smb2_cp::chunk_plan(1_048_576 + 7);
    assert_eq!(plan.first_count, 1_048_576);
    assert_eq!(plan.last_count, 7);
    assert_eq!(plan.chunks, 2);
}
