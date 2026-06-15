use libsmb2_rs::lib::init::{
    self as init, iovector_add_probe, iovector_free_probe, iovector_overflow_probe, InitContext,
    LibVersion,
};
use std::sync::Mutex;

static NTLM_USER_FILE_LOCK: Mutex<()> = Mutex::new(());

fn context() -> InitContext {
    InitContext::new()
}

// Trace: `lib/init.c:smb2_parse_url`, `include/smb2/libsmb2.h:smb2_parse_url`
// Spec: smb2_parse_url parses SMB URL components and options#parse valid share URL
// - **GIVEN** 一个有效 context 和 `smb://domain;user@server/share/path` 形式的 URL
// - **WHEN** 调用 `smb2_parse_url`
// - **THEN** 返回对象 MUST 保存 domain、user、server、share 和 path 字段，且不接管原始 URL 指针所有权
#[test]
fn test_init_parse_valid_share_url() {
    let parsed = init::parse_url_snapshot("smb://domain;user@server/share/path")
        .expect("valid SMB URL parses");

    assert_eq!(parsed.domain.as_deref(), Some("domain"));
    assert_eq!(parsed.user.as_deref(), Some("user"));
    assert_eq!(parsed.server, "server");
    assert_eq!(parsed.share, "share");
    assert_eq!(parsed.path.as_deref(), Some("path"));
}

// Trace: `lib/init.c:smb2_parse_url`, `include/smb2/libsmb2.h:smb2_parse_url`
// Spec: smb2_parse_url parses SMB URL components and options#reject invalid URL prefix
// - **GIVEN** 一个有效 context 和不以 `smb://` 开头的 URL
// - **WHEN** 调用 `smb2_parse_url`
// - **THEN** 返回值 MUST 为 `NULL`，并通过 `smb2_set_error` 设置 `URL does not start with 'smb://'`
#[test]
fn test_init_reject_invalid_url_prefix() {
    assert_eq!(
        init::parse_url_error("notsmb://server/share"),
        "URL does not start with 'smb://'"
    );
}

// Trace: `lib/init.c:smb2_parse_url`, `lib/init.c:smb2_parse_args`
// Spec: smb2_parse_url parses SMB URL components and options#apply URL query arguments
// - **GIVEN** 一个带 `?seal&vers=3&sec=ntlmssp&timeout=5` 查询串的有效 URL
// - **WHEN** 调用 `smb2_parse_url`
// - **THEN** 解析 MUST 更新 context 的 seal、version、security method 和 timeout；未知参数或不兼容 seal/version 组合 MUST 使调用失败并设置错误字符串
#[test]
fn test_init_apply_url_query_arguments() {
    let query = init::parse_url_query_snapshot().expect("valid query URL parses");

    assert_eq!(query.seal, 1);
    assert_eq!(query.version, init::SMB2_VERSION_ANY3_VALUE);
    assert_eq!(query.authentication, init::SMB2_SEC_NTLMSSP_VALUE);
    assert_eq!(query.timeout, 5);
    assert_eq!(
        init::parse_url_bad_query_error(),
        "Unknown argument: unknown"
    );
}

// Trace: `lib/init.c:smb2_destroy_url`, `include/smb2/libsmb2.h:smb2_destroy_url`
// Spec: smb2_destroy_url releases parsed URL ownership#destroy parsed URL
// - **GIVEN** 一个由 `smb2_parse_url` 返回的 URL 对象
// - **WHEN** 调用 `smb2_destroy_url`
// - **THEN** 函数 MUST 释放 domain、user、server、share、path 和 URL 对象本身
#[test]
fn test_init_destroy_parsed_url() {
    assert!(init::destroy_parsed_url_probe());
}

// Trace: `lib/init.c:smb2_destroy_url`, `include/smb2/libsmb2.h:smb2_destroy_url`
// Spec: smb2_destroy_url releases parsed URL ownership#destroy null URL
// - **GIVEN** URL 指针为 `NULL`
// - **WHEN** 调用 `smb2_destroy_url`
// - **THEN** 函数 MUST 直接返回且不访问任何字段
#[test]
fn test_init_destroy_null_url() {
    assert!(init::destroy_null_url_probe());
}

// Trace: `lib/init.c:smb2_init_context`, `include/smb2/libsmb2.h:smb2_init_context`, `tests/ntlmssp_generate_blob.c:main`
// Spec: smb2_init_context creates initialized active context#initialize context defaults
// - **GIVEN** 内存分配成功且平台提供或兼容实现 `getlogin_r`、`random`、`srandom`、`time` 和 `getpid`
// - **WHEN** 调用 `smb2_init_context`
// - **THEN** 返回 context MUST 具有 `SMB2_INVALID_SOCKET` fd、`SMB2_SEC_UNDEFINED` security、`SMB2_VERSION_ANY` version、NDR32 默认值和 active list 成员资格
#[test]
fn test_init_initialize_context_defaults() {
    let defaults = init::real_context_defaults();

    assert_eq!(defaults.allocated, 1);
    assert_eq!(defaults.fd, init::SMB2_INVALID_SOCKET_DEFAULT);
    assert_eq!(defaults.security, init::SMB2_SEC_UNDEFINED_DEFAULT);
    assert_eq!(defaults.version, init::SMB2_VERSION_ANY_DEFAULT);
    assert_eq!(defaults.ndr, 1);
    assert_eq!(defaults.active, 1);
}

// Trace: `lib/init.c:smb2_init_context`, `include/smb2/libsmb2.h:smb2_init_context`
// Spec: smb2_init_context creates initialized active context#initialize allocation failure
// - **GIVEN** context 分配失败
// - **WHEN** 调用 `smb2_init_context`
// - **THEN** 返回值 MUST 为 `NULL` 且不得加入 active list
#[test]
fn test_init_initialize_allocation_failure() {
    assert!(init::init_context_allocation_failure_probe());
}

// Trace: `lib/init.c:smb2_destroy_context`, `include/smb2/libsmb2.h:smb2_destroy_context`, `tests/prog_cat.c:main`
// Spec: smb2_destroy_context cancels and frees context resources#destroy active context
// - **GIVEN** 一个通过 `smb2_init_context` 创建的 context
// - **WHEN** 调用 `smb2_destroy_context`
// - **THEN** 函数 MUST 从 active list 移除该 context，释放拥有的资源，并对未完成 PDU callback 报告 shutdown 或 cancelled 状态
#[test]
fn test_init_destroy_active_context() {
    assert!(init::destroy_active_context_probe());
}

// Trace: `lib/init.c:smb2_destroy_context`, `include/smb2/libsmb2.h:smb2_destroy_context`
// Spec: smb2_destroy_context cancels and frees context resources#destroy null context
// - **GIVEN** context 指针为 `NULL`
// - **WHEN** 调用 `smb2_destroy_context`
// - **THEN** 函数 MUST 直接返回且不释放任何资源
#[test]
fn test_init_destroy_null_context() {
    assert!(init::destroy_null_context_probe());
}

// Trace: `lib/init.c:smb2_active_contexts`, `include/smb2/libsmb2.h:smb2_active_contexts`
// Spec: smb2_active_contexts returns active context list head#read active context list
// - **GIVEN** 一个或多个 context 已由 `smb2_init_context` 加入 active list
// - **WHEN** 调用 `smb2_active_contexts`
// - **THEN** 返回值 MUST 为当前 `active_contexts` 链表头
#[test]
fn test_init_read_active_context_list() {
    assert!(init::active_contexts_probe());
}

// Trace: `lib/init.c:smb2_context_active`, `include/smb2/libsmb2.h:smb2_context_active`
// Spec: smb2_context_active reports active list membership#report active context
// - **GIVEN** 一个仍在 active list 中的 context 指针
// - **WHEN** 调用 `smb2_context_active`
// - **THEN** 返回值 MUST 为 `1`
#[test]
fn test_init_report_active_context() {
    assert!(init::real_context_active_probe());
}

// Trace: `lib/init.c:smb2_get_error`, `include/smb2/libsmb2.h:smb2_get_error`
// Spec: smb2_get_error returns last error string#get error string
// - **GIVEN** 一个 context 已设置错误字符串
// - **WHEN** 调用 `smb2_get_error`
// - **THEN** 返回值 MUST 指向该 context 的内部 error string
#[test]
fn test_init_get_error_string() {
    let ctx = context();

    assert_eq!(ctx.error(), "");
}

// Trace: `lib/init.c:smb2_get_error`, `include/smb2/libsmb2.h:smb2_get_error`
// Spec: smb2_get_error returns last error string#get error from null context
// - **GIVEN** context 指针为 `NULL`
// - **WHEN** 调用 `smb2_get_error`
// - **THEN** 返回值 MUST 为 `""`
#[test]
fn test_init_get_error_from_null_context() {
    assert_eq!(InitContext::null_error(), "");
}

// Trace: `lib/init.c:smb2_get_nterror`, `include/smb2/libsmb2.h:smb2_get_nterror`
// Spec: smb2_get_nterror returns last NT status#get NT status
// - **GIVEN** 一个 context 已设置 NT status
// - **WHEN** 调用 `smb2_get_nterror`
// - **THEN** 返回值 MUST 等于该 context 的 `nterror`
#[test]
fn test_init_get_nt_status() {
    let mut ctx = context();

    ctx.set_nterror_for_test(0xc000_000d_u32 as i32);

    assert_eq!(ctx.nterror(), 0xc000_000d_u32 as i32);
    assert_eq!(InitContext::null_nterror(), 0);
}

// Trace: `lib/init.c:smb2_set_client_guid`, `include/smb2/libsmb2.h:smb2_set_client_guid`
// Spec: smb2_set_client_guid copies fixed-size GUID#set client GUID
// - **GIVEN** 一个有效 context 和长度为 `SMB2_GUID_SIZE` 的 GUID 数组
// - **WHEN** 调用 `smb2_set_client_guid`
// - **THEN** context 的 client GUID MUST 与传入字节序列相同
#[test]
fn test_init_set_client_guid() {
    let mut ctx = context();
    let guid = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];

    ctx.set_client_guid(guid);

    assert_eq!(ctx.client_guid(), guid);
}

// Trace: `lib/init.c:smb2_get_client_guid`, `include/smb2/libsmb2.h:smb2_get_client_guid`
// Spec: smb2_get_client_guid returns internal GUID storage#get client GUID
// - **GIVEN** 一个有效 context
// - **WHEN** 调用 `smb2_get_client_guid`
// - **THEN** 返回值 MUST 指向该 context 的 client GUID 存储
#[test]
fn test_init_get_client_guid() {
    let ctx = context();

    assert_eq!(ctx.client_guid(), [0; 16]);
}

// Trace: `lib/init.c:smb2_get_dialect`, `include/smb2/libsmb2.h:smb2_get_dialect`
// Spec: smb2_get_dialect returns negotiated dialect#get dialect
// - **GIVEN** 一个 context 的 dialect 字段已由 negotiate 路径设置
// - **WHEN** 调用 `smb2_get_dialect`
// - **THEN** 返回值 MUST 等于 context 的 `dialect`
#[test]
fn test_init_get_dialect() {
    let mut ctx = context();

    ctx.set_dialect_for_test(0x0311);

    assert_eq!(ctx.dialect(), 0x0311);
}

// Trace: `lib/init.c:smb2_set_security_mode`, `include/smb2/libsmb2.h:smb2_set_security_mode`
// Spec: smb2_set_security_mode stores security mode flags#set security mode
// - **GIVEN** 一个有效 context 和 security mode 值
// - **WHEN** 调用 `smb2_set_security_mode`
// - **THEN** context 的 `security_mode` MUST 等于传入值
#[test]
fn test_init_set_security_mode() {
    let mut ctx = context();

    ctx.set_security_mode(0x0003);

    assert_eq!(ctx.security_mode(), 0x0003);
}

// Trace: `lib/init.c:smb2_set_password_from_file`, `include/smb2/libsmb2.h:smb2_set_password_from_file`
// Spec: smb2_set_password_from_file loads matching NTLM password#load matching password
// - **GIVEN** 非受排除平台、context 已有 user，且 `NTLM_USER_FILE` 指向包含匹配 domain 或 server 的文件
// - **WHEN** 调用 `smb2_set_password_from_file`
// - **THEN** context password MUST 更新为匹配记录中的 password，且文件句柄 MUST 被关闭
#[test]
fn test_init_load_matching_password() {
    let _guard = NTLM_USER_FILE_LOCK.lock().unwrap();
    let path =
        std::env::temp_dir().join(format!("libsmb2-init-password-{}.txt", std::process::id()));
    std::fs::write(&path, "DOMAIN:alice:secret\n:alice:fallback\n").unwrap();
    std::env::set_var("NTLM_USER_FILE", &path);
    let mut ctx = context();
    ctx.set_user("alice");

    ctx.set_domain("DOMAIN");
    ctx.set_password_from_file();

    assert_eq!(ctx.password(), Some("secret"));
    std::env::remove_var("NTLM_USER_FILE");
    let _ = std::fs::remove_file(path);
}

// Trace: `lib/init.c:smb2_set_password_from_file`, `include/smb2/libsmb2.h:smb2_set_password_from_file`
// Spec: smb2_set_password_from_file loads matching NTLM password#skip unsupported or missing password file
// - **GIVEN** 平台命中 `_XBOX`、`_IOP`、Amiga 排除条件，或环境变量、user、文件打开失败任一条件不满足
// - **WHEN** 调用 `smb2_set_password_from_file`
// - **THEN** 函数 MUST 不设置新 password 并返回
#[test]
fn test_init_skip_unsupported_or_missing_password_file() {
    let _guard = NTLM_USER_FILE_LOCK.lock().unwrap();
    std::env::remove_var("NTLM_USER_FILE");
    let mut ctx = context();
    ctx.set_user("alice");

    ctx.set_password_from_file();

    assert_eq!(ctx.password(), None);
}

// Trace: `lib/init.c:smb2_set_user`, `include/smb2/libsmb2.h:smb2_set_user`
// Spec: smb2_set_user stores user and reloads password file#set non-null user
// - **GIVEN** 一个有效 context 和非空 user 字符串
// - **WHEN** 调用 `smb2_set_user`
// - **THEN** context user MUST 保存为 `strdup` 副本，旧 user MUST 被释放，并 MUST 调用 `smb2_set_password_from_file`
#[test]
fn test_init_set_non_null_user() {
    let mut ctx = context();

    ctx.set_user("alice");

    assert_eq!(ctx.user(), Some("alice"));
}

// Trace: `lib/init.c:smb2_get_user`, `include/smb2/libsmb2.h:smb2_get_user`
// Spec: smb2_get_user returns configured user#get configured user
// - **GIVEN** 一个 context 已设置 user
// - **WHEN** 调用 `smb2_get_user`
// - **THEN** 返回值 MUST 指向 context 的 user 字符串
#[test]
fn test_init_get_configured_user() {
    let mut ctx = context();
    ctx.set_user("alice");

    assert_eq!(ctx.user(), Some("alice"));
}

// Trace: `lib/init.c:smb2_get_workstation`, `include/smb2/libsmb2.h:smb2_get_workstation`
// Spec: smb2_get_workstation returns configured workstation#get configured workstation
// - **GIVEN** 一个 context 已设置 workstation
// - **WHEN** 调用 `smb2_get_workstation`
// - **THEN** 返回值 MUST 指向 context 的 workstation 字符串
#[test]
fn test_init_get_configured_workstation() {
    let mut ctx = context();
    ctx.set_workstation("WORKSTATION");

    assert_eq!(ctx.workstation(), Some("WORKSTATION"));
}

// Trace: `lib/init.c:smb2_set_password`, `include/smb2/libsmb2.h:smb2_set_password`
// Spec: smb2_set_password stores password copy#set password
// - **GIVEN** 一个有效 context 和非空 password 字符串
// - **WHEN** 调用 `smb2_set_password`
// - **THEN** context password MUST 指向新分配副本，旧 password MUST 被释放
#[test]
fn test_init_set_password() {
    let mut ctx = context();

    ctx.set_password("secret");

    assert_eq!(ctx.password(), Some("secret"));
}

// Trace: `lib/init.c:smb2_set_domain`, `include/smb2/libsmb2.h:smb2_set_domain`
// Spec: smb2_set_domain stores domain and reloads password file#set domain
// - **GIVEN** 一个有效 context 和非空 domain 字符串
// - **WHEN** 调用 `smb2_set_domain`
// - **THEN** context domain MUST 保存为 `strdup` 副本，旧 domain MUST 被释放，并 MUST 调用 `smb2_set_password_from_file`
#[test]
fn test_init_set_domain() {
    let mut ctx = context();

    ctx.set_domain("DOMAIN");

    assert_eq!(ctx.domain(), Some("DOMAIN"));
}

// Trace: `lib/init.c:smb2_get_domain`, `include/smb2/libsmb2.h:smb2_get_domain`
// Spec: smb2_get_domain returns configured domain#get configured domain
// - **GIVEN** 一个 context 已设置 domain
// - **WHEN** 调用 `smb2_get_domain`
// - **THEN** 返回值 MUST 指向 context 的 domain 字符串
#[test]
fn test_init_get_configured_domain() {
    let mut ctx = context();
    ctx.set_domain("DOMAIN");

    assert_eq!(ctx.domain(), Some("DOMAIN"));
}

// Trace: `lib/init.c:smb2_set_workstation`, `include/smb2/libsmb2.h:smb2_set_workstation`
// Spec: smb2_set_workstation stores workstation copy#set workstation
// - **GIVEN** 一个有效 context 和非空 workstation 字符串
// - **WHEN** 调用 `smb2_set_workstation`
// - **THEN** context workstation MUST 指向新分配副本，旧 workstation MUST 被释放
#[test]
fn test_init_set_workstation() {
    let mut ctx = context();

    ctx.set_workstation("WORKSTATION");

    assert_eq!(ctx.workstation(), Some("WORKSTATION"));
}

// Trace: `lib/init.c:smb2_set_opaque`, `include/smb2/libsmb2.h:smb2_set_opaque`
// Spec: smb2_set_opaque stores caller opaque pointer#set opaque pointer
// - **GIVEN** 一个有效 context 和任意 opaque 指针
// - **WHEN** 调用 `smb2_set_opaque`
// - **THEN** context 的 `opaque` 字段 MUST 等于传入指针
#[test]
fn test_init_set_opaque_pointer() {
    let mut ctx = context();

    ctx.set_opaque(0x1234);

    assert_eq!(ctx.opaque(), 0x1234);
}

// Trace: `lib/init.c:smb2_get_opaque`, `include/smb2/libsmb2.h:smb2_get_opaque`
// Spec: smb2_get_opaque returns caller opaque pointer#get opaque pointer
// - **GIVEN** 一个 context 已设置 opaque pointer
// - **WHEN** 调用 `smb2_get_opaque`
// - **THEN** 返回值 MUST 等于 context 的 `opaque` 字段
#[test]
fn test_init_get_opaque_pointer() {
    let mut ctx = context();
    ctx.set_opaque(0x5678);

    assert_eq!(ctx.opaque(), 0x5678);
}

// Trace: `lib/init.c:smb2_set_seal`, `include/smb2/libsmb2.h:smb2_set_seal`
// Spec: smb2_set_seal stores encryption preference#set seal flag
// - **GIVEN** 一个有效 context 和整数值
// - **WHEN** 调用 `smb2_set_seal`
// - **THEN** context 的 `seal` 标志 MUST 反映传入值
#[test]
fn test_init_set_seal_flag() {
    let mut ctx = context();

    ctx.set_seal(1);

    assert_eq!(ctx.seal(), 1);
}

// Trace: `lib/init.c:smb2_set_sign`, `include/smb2/libsmb2.h:smb2_set_sign`
// Spec: smb2_set_sign stores signing preference#set sign flag
// - **GIVEN** 一个有效 context 和整数值
// - **WHEN** 调用 `smb2_set_sign`
// - **THEN** context 的 `sign` 标志 MUST 反映传入值
#[test]
fn test_init_set_sign_flag() {
    let mut ctx = context();

    ctx.set_sign(1);

    assert_eq!(ctx.sign(), 1);
}

// Trace: `lib/init.c:smb2_context_active`, `include/smb2/libsmb2.h:smb2_context_active`
// Spec: smb2_context_active reports active list membership#report inactive context
// - **GIVEN** 一个不在 active list 中的 context 指针
// - **WHEN** 调用 `smb2_context_active`
// - **THEN** 返回值 MUST 为 `0`
#[test]
fn test_init_report_inactive_context() {
    let ctx = context();

    assert!(!ctx.is_active_for_test());
}

// Trace: `lib/init.c:smb2_free_iovector`, `include/libsmb2-private.h:smb2_free_iovector`
// Spec: smb2_free_iovector releases vector-owned buffers#free populated iovector
// - **GIVEN** 一个 `niov` 大于 0 且部分元素带 `free` callback 的 vector 集合
// - **WHEN** 调用 `smb2_free_iovector`
// - **THEN** 函数 MUST 对每个带 callback 的 buffer 调用 callback，并把 `niov`、`total_size` 和 `num_done` 重置为 0
#[test]
fn test_init_free_populated_iovector() {
    assert!(iovector_free_probe());
}

// Trace: `lib/init.c:smb2_add_iovector`, `include/libsmb2-private.h:smb2_add_iovector`
// Spec: smb2_add_iovector appends bounded vectors#append vector entry
// - **GIVEN** 一个未满的 `struct smb2_io_vectors`
// - **WHEN** 调用 `smb2_add_iovector`
// - **THEN** 返回值 MUST 指向新追加的 `struct smb2_iovec`，且 `niov` 增加 1、`total_size` 增加 `len`
#[test]
fn test_init_append_vector_entry() {
    assert_eq!(iovector_add_probe(), Some(3));
}

// Trace: `lib/init.c:smb2_add_iovector`, `include/libsmb2-private.h:smb2_add_iovector`
// Spec: smb2_add_iovector appends bounded vectors#reject vector overflow
// - **GIVEN** 一个 `niov >= SMB2_MAX_VECTORS` 的 vector 集合
// - **WHEN** 调用 `smb2_add_iovector`
// - **THEN** 函数 MUST 设置 `Too many I/O vectors` 错误，若提供了 `free_cb` 和 `buf` 则调用 `free_cb(buf)`，并返回 `NULL`
#[test]
fn test_init_reject_vector_overflow() {
    assert!(iovector_overflow_probe());
}

// Trace: `lib/init.c:smb2_set_error`, `include/smb2/libsmb2.h:smb2_set_error`
// Spec: smb2_set_error stores formatted error and invokes callback#set formatted error
// - **GIVEN** 一个非空 context 和非空格式字符串
// - **WHEN** 调用 `smb2_set_error`
// - **THEN** context 的 error string MUST 更新为格式化结果，且已注册 callback 时 MUST 以 `smb2_get_error` 的返回值调用 callback
#[test]
fn test_init_set_formatted_error() {
    let mut ctx = context();

    ctx.set_error_for_test("formatted error");

    assert_eq!(ctx.error(), "formatted error");
    assert_eq!(ctx.error_callback_probe(), 1);
}

// Trace: `lib/init.c:smb2_set_error`, `include/smb2/libsmb2.h:smb2_set_error`
// Spec: smb2_set_error stores formatted error and invokes callback#clear nterror on empty error
// - **GIVEN** 一个非空 context 和空错误字符串或 `NULL` 错误字符串
// - **WHEN** 调用 `smb2_set_error`
// - **THEN** context 的 `nterror` MUST 设置为 0
#[test]
fn test_init_clear_nterror_on_empty_error() {
    let mut ctx = context();
    ctx.set_nterror_for_test(0xc000_0001_u32 as i32);

    ctx.clear_error_for_test();

    assert_eq!(ctx.nterror(), 0);
}

// Trace: `lib/init.c:smb2_register_error_callback`, `include/smb2/libsmb2.h:smb2_register_error_callback`
// Spec: smb2_register_error_callback stores error callback#register error callback
// - **GIVEN** 一个有效 context 和 callback 指针
// - **WHEN** 调用 `smb2_register_error_callback`
// - **THEN** 后续 `smb2_set_error` MUST 使用该 callback 报告当前错误字符串
#[test]
fn test_init_register_error_callback() {
    let mut ctx = context();

    assert_eq!(ctx.error_callback_probe(), 1);
}

// Trace: `lib/init.c:smb2_set_nterror`, `include/libsmb2-private.h:smb2_set_nterror`
// Spec: smb2_set_nterror stores NT status and optional error text#set NT status
// - **GIVEN** 一个非空 context、NT status 和错误格式字符串
// - **WHEN** 调用 `smb2_set_nterror`
// - **THEN** context 的 `nterror` MUST 等于传入状态，且非 `_IOP` 构建中 error string MUST 按格式字符串更新
#[test]
fn test_init_set_nt_status() {
    let mut ctx = context();

    ctx.set_nterror_with_error_for_test(0xc000_0022_u32 as i32, "access denied");

    assert_eq!(ctx.nterror(), 0xc000_0022_u32 as i32);
    assert_eq!(ctx.error(), "access denied");
}

// Trace: `lib/init.c:smb2_set_authentication`, `include/smb2/libsmb2.h:smb2_set_authentication`
// Spec: smb2_set_authentication stores authentication method#set authentication method
// - **GIVEN** 一个有效 context 和 authentication method 值
// - **WHEN** 调用 `smb2_set_authentication`
// - **THEN** context 的 `sec` 字段 MUST 等于传入值转换后的 `enum smb2_sec`
#[test]
fn test_init_set_authentication_method() {
    let mut ctx = context();

    ctx.set_authentication(1);

    assert_eq!(ctx.authentication(), 1);
}

// Trace: `lib/init.c:smb2_set_timeout`, `include/smb2/libsmb2.h:smb2_set_timeout`
// Spec: smb2_set_timeout stores command timeout#set timeout
// - **GIVEN** 一个有效 context 和 seconds 值
// - **WHEN** 调用 `smb2_set_timeout`
// - **THEN** context 的 `timeout` 字段 MUST 等于传入秒数
#[test]
fn test_init_set_timeout() {
    let mut ctx = context();

    ctx.set_timeout(30);

    assert_eq!(ctx.timeout(), 30);
}

// Trace: `lib/init.c:smb2_set_version`, `include/smb2/libsmb2.h:smb2_set_version`
// Spec: smb2_set_version stores negotiation version preference#set version
// - **GIVEN** 一个有效 context 和 negotiate version
// - **WHEN** 调用 `smb2_set_version`
// - **THEN** context 的 `version` 字段 MUST 等于传入值
#[test]
fn test_init_set_version() {
    let mut ctx = context();

    ctx.set_version(0x0311);

    assert_eq!(ctx.version(), 0x0311);
}

// Trace: `lib/init.c:smb2_get_libsmb2Version`, `include/smb2/libsmb2.h:smb2_get_libsmb2Version`
// Spec: smb2_get_libsmb2Version writes library version fields#get library version
// - **GIVEN** 一个有效 `struct smb2_libversion` 输出指针
// - **WHEN** 调用 `smb2_get_libsmb2Version`
// - **THEN** major 和 minor 字段 MUST 分别来自 `LIBSMB2_MAJOR_VERSION` 和 `LIBSMB2_MINOR_VERSION`
#[test]
fn test_init_get_library_version() {
    assert_eq!(
        InitContext::libversion(),
        LibVersion {
            major: 4,
            minor: 0,
            patch: 4,
        }
    );
}

// Trace: `lib/init.c:smb2_set_passthrough`, `include/smb2/libsmb2.h:smb2_set_passthrough`
// Spec: smb2_set_passthrough stores passthrough mode#set passthrough
// - **GIVEN** 一个有效 context 和 passthrough 值
// - **WHEN** 调用 `smb2_set_passthrough`
// - **THEN** context 的 `passthrough` 字段 MUST 等于传入值
#[test]
fn test_init_set_passthrough() {
    let mut ctx = context();

    ctx.set_passthrough(1);

    assert_eq!(ctx.passthrough(), 1);
}

// Trace: `lib/init.c:smb2_get_passthrough`, `include/smb2/libsmb2.h:smb2_get_passthrough`
// Spec: smb2_get_passthrough writes passthrough mode#get passthrough
// - **GIVEN** 一个有效 context 和非空输出指针
// - **WHEN** 调用 `smb2_get_passthrough`
// - **THEN** 输出指针指向的值 MUST 等于 context 的 `passthrough`
#[test]
fn test_init_get_passthrough() {
    let mut ctx = context();
    ctx.set_passthrough(1);

    assert_eq!(ctx.passthrough(), 1);
}

// Trace: `lib/init.c:smb2_set_oplock_or_lease_break_callback`, `include/smb2/libsmb2.h:smb2_set_oplock_or_lease_break_callback`
// Spec: smb2_set_oplock_or_lease_break_callback stores break callback#register break callback
// - **GIVEN** 一个有效 context 和 callback 指针
// - **WHEN** 调用 `smb2_set_oplock_or_lease_break_callback`
// - **THEN** context 的 `oplock_or_lease_break_cb` MUST 等于传入 callback
#[test]
fn test_init_register_break_callback() {
    let mut ctx = context();

    assert!(ctx.oplock_callback_probe());
}

// Trace: `lib/init.c:smb2_delegate_credentials`, `include/smb2/libsmb2.h:smb2_delegate_credentials`
// Spec: smb2_delegate_credentials transfers Kerberos credential when available#delegate credential unavailable
// - **GIVEN** 未启用 `HAVE_LIBKRB5`，或 input/output context 为空，或 input context 无 credential handle
// - **WHEN** 调用 `smb2_delegate_credentials`
// - **THEN** 函数 MUST 返回 -1
#[test]
fn test_init_delegate_credential_unavailable() {
    let mut input = context();
    let mut output = context();

    assert_eq!(input.delegate_credentials_unavailable(&mut output), -1);
}
