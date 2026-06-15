use libsmb2_rs::lib::utils::smb2_ls;

// Trace: `utils/smb2-ls.c:usage`, `utils/smb2-ls.c:main`
// Spec: usage print command syntax and terminate#参数不足时输出用法
// - **GIVEN** 调用方进入 `main` 且 `argc < 2`
// - **WHEN** `main` 调用 `usage`
// - **THEN** 工具向标准错误输出用法文本并通过 `exit(1)` 终止进程
#[test]
fn test_smb2_ls_usage_missing_arg() {
    let result = smb2_ls::usage_missing_arg();
    assert_eq!(result.exit_code, 1);
    assert!(result.stderr.contains("smb2-ls-sync <smb2-url>"));
    assert!(result.stderr.contains("URL format:"));
}

// Trace: `utils/smb2-ls.c:main`
// Spec: main run SMB directory listing utility#成功列出目录项
// - **GIVEN** `argc >= 2` 且 `argv[1]` 可被解析为有效 SMB URL
// - **WHEN** context 初始化、URL 解析、共享连接和目录打开均成功，且 `smb2_readdir` 返回目录项
// - **THEN** 工具为每个目录项输出名称、类型字符串、大小和由修改时间转换出的本地时间文本
#[test]
fn test_smb2_ls_list_directory_success() {
    let result = smb2_ls::list_directory_success();
    assert_eq!(result.exit_code, 0);
    assert!(result.stdout.contains("link"));
    assert!(result.stdout.contains("FILE"));
    assert!(result.stdout.contains("DIRECTORY"));
}

// Trace: `utils/smb2-ls.c:main`
// Spec: main run SMB directory listing utility#目录项类型映射
// - **GIVEN** `smb2_readdir` 返回的目录项包含 `smb2_type`
// - **WHEN** `main` 格式化目录项输出
// - **THEN** `SMB2_TYPE_LINK`、`SMB2_TYPE_FILE` 和 `SMB2_TYPE_DIRECTORY` 分别显示为 `LINK`、`FILE` 和 `DIRECTORY`，其他类型显示为 `unknown`
#[test]
fn test_smb2_ls_directory_type_mapping() {
    let mapping = smb2_ls::directory_type_mapping();
    assert_eq!(mapping.link_type, "LINK");
    assert_eq!(mapping.file_type, "FILE");
    assert_eq!(mapping.directory_type, "DIRECTORY");
    assert_eq!(mapping.unknown_type, "unknown");
}

// Trace: `utils/smb2-ls.c:main`
// Spec: main run SMB directory listing utility#符号链接目标读取成功
// - **GIVEN** 当前目录项类型为 `SMB2_TYPE_LINK` 且链接路径字符串分配成功
// - **WHEN** `smb2_readlink` 返回 0
// - **THEN** 工具输出链接目标文本并释放分配的链接路径字符串
#[test]
fn test_smb2_ls_readlink_success() {
    let result = smb2_ls::readlink_success();
    assert_eq!(result.exit_code, 0);
    assert!(result.stdout.contains("-> [target.txt]"));
}

// Trace: `utils/smb2-ls.c:main`
// Spec: main run SMB directory listing utility#符号链接目标读取失败
// - **GIVEN** 当前目录项类型为 `SMB2_TYPE_LINK` 且链接路径字符串分配成功
// - **WHEN** `smb2_readlink` 返回非 0
// - **THEN** 工具输出 `readlink failed` 并释放分配的链接路径字符串
#[test]
fn test_smb2_ls_readlink_failure() {
    let result = smb2_ls::readlink_failure();
    assert_eq!(result.exit_code, 0);
    assert!(result.stdout.contains("readlink failed"));
}

// Trace: `utils/smb2-ls.c:main`
// Spec: main run SMB directory listing utility#context 初始化失败
// - **GIVEN** `argc >= 2`
// - **WHEN** `smb2_init_context` 返回 `NULL`
// - **THEN** 工具向标准错误输出 `Failed to init context` 并通过 `exit(1)` 终止进程
#[test]
fn test_smb2_ls_context_init_failure() {
    let result = smb2_ls::context_init_failure();
    assert_eq!(result.exit_code, 1);
    assert!(result.stderr.contains("Failed to init context"));
}

// Trace: `utils/smb2-ls.c:main`
// Spec: main run SMB directory listing utility#URL 解析失败
// - **GIVEN** SMB2 context 初始化成功
// - **WHEN** `smb2_parse_url` 返回 `NULL`
// - **THEN** 工具向标准错误输出 `Failed to parse url` 和当前 SMB2 错误字符串，并通过 `exit(1)` 终止进程
#[test]
fn test_smb2_ls_url_parse_failure() {
    let result = smb2_ls::url_parse_failure();
    assert_eq!(result.exit_code, 1);
    assert!(result.stderr.contains("Failed to parse url"));
    assert!(result.stderr.contains("injected error"));
}

// Trace: `utils/smb2-ls.c:main`
// Spec: main run SMB directory listing utility#共享连接失败
// - **GIVEN** SMB2 context 和 URL 均已创建
// - **WHEN** `smb2_connect_share` 返回负值
// - **THEN** 工具输出 `smb2_connect_share failed` 和当前 SMB2 错误字符串，销毁 URL 与 context，并返回初始非零状态
#[test]
fn test_smb2_ls_connect_share_failure() {
    let result = smb2_ls::connect_share_failure();
    assert_eq!(result.exit_code, 1);
    assert!(result.stdout.contains("smb2_connect_share failed"));
}

// Trace: `utils/smb2-ls.c:main`
// Spec: main run SMB directory listing utility#目录打开失败
// - **GIVEN** SMB2 context 已连接共享
// - **WHEN** `smb2_opendir` 返回 `NULL`
// - **THEN** 工具输出 `smb2_opendir failed` 和当前 SMB2 错误字符串，断开共享，销毁 URL 与 context，并返回初始非零状态
#[test]
fn test_smb2_ls_opendir_failure() {
    let result = smb2_ls::opendir_failure();
    assert_eq!(result.exit_code, 1);
    assert!(result.stdout.contains("smb2_opendir failed"));
}

// Trace: `utils/smb2-ls.c:main`
// Spec: main run SMB directory listing utility#遍历正常结束
// - **GIVEN** 目录已成功打开
// - **WHEN** `smb2_readdir` 返回 `NULL` 表示遍历结束
// - **THEN** 工具设置返回码为 0，调用 `smb2_closedir`、`smb2_disconnect_share`、`smb2_destroy_url` 和 `smb2_destroy_context`
#[test]
fn test_smb2_ls_readdir_end_cleanup() {
    let result = smb2_ls::readdir_end_cleanup();
    assert_eq!(result.exit_code, 0);
    assert_eq!(result.closedir_calls, 1);
    assert_eq!(result.disconnect_calls, 1);
    assert_eq!(result.destroy_url_calls, 1);
    assert_eq!(result.destroy_context_calls, 1);
}
