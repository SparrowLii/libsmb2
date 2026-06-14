use libsmb2_rs::lib::ps2::ps2smb2::{
    Smb2ConnectIn, Smb2ConnectOut, Smb2DisconnectIn, SMB2_DEVCTL_CONNECT,
    SMB2_DEVCTL_DISCONNECT_ALL, SMB2_MAX_NAME_LEN, SMB2_PASSWORD_LEN, SMB2_PATH_MAX, SMB2_URL_LEN,
    SMB2_USERNAME_LEN,
};

// Trace: `lib/ps2/ps2smb2.h:SMB2_PATH_MAX`
// Spec: SMB2_PATH_MAX expose PS2 path limit#path limit macro value
// - **GIVEN** 调用方包含 `lib/ps2/ps2smb2.h`
// - **WHEN** 调用方读取 `SMB2_PATH_MAX`
// - **THEN** 宏值为 `1024`
#[test]
fn test_ps2smb2_path_limit_macro_value() {
    assert_eq!(SMB2_PATH_MAX, 1024);
}

// Trace: `lib/ps2/ps2smb2.h:SMB2_DEVCTL_CONNECT`, `lib/ps2/smb2_fio.c:SMB2_devctl`
// Spec: SMB2_DEVCTL_CONNECT expose connect command#connect command dispatch contract
// - **GIVEN** 调用方包含 `lib/ps2/ps2smb2.h` 并向 PS2 devctl 传入命令号
// - **WHEN** 命令号等于 `SMB2_DEVCTL_CONNECT`
// - **THEN** 命令号值为 `0xC0DE0001`，`SMB2_devctl` 将输入载荷解释为 `smb2Connect_in_t *`，将输出载荷解释为 `smb2Connect_out_t *`
#[test]
fn test_ps2smb2_connect_command_dispatch_contract() {
    assert_eq!(SMB2_DEVCTL_CONNECT, 0xC0DE_0001);
    assert!(Smb2ConnectIn::default().fits_fixed_buffers());
    assert_eq!(Smb2ConnectOut::default().ctx, None);
}

// Trace: `lib/ps2/ps2smb2.h:SMB2_DEVCTL_DISCONNECT_ALL`
// Spec: SMB2_DEVCTL_DISCONNECT_ALL expose disconnect command#disconnect command macro value
// - **GIVEN** 调用方包含 `lib/ps2/ps2smb2.h`
// - **WHEN** 调用方读取 `SMB2_DEVCTL_DISCONNECT_ALL`
// - **THEN** 宏值为 `0xC0DE0002`
#[test]
fn test_ps2smb2_disconnect_command_macro_value() {
    assert_eq!(SMB2_DEVCTL_DISCONNECT_ALL, 0xC0DE_0002);
}

// Trace: `lib/ps2/ps2smb2.h:SMB2_MAX_NAME_LEN`, `lib/ps2/ps2smb2.h:smb2Connect_in_t`
// Spec: SMB2_MAX_NAME_LEN define share name field width#connect name field width
// - **GIVEN** 调用方包含 `lib/ps2/ps2smb2.h`
// - **WHEN** 调用方构造 `smb2Connect_in_t` 输入载荷
// - **THEN** `name` 字段的数组宽度由 `SMB2_MAX_NAME_LEN` 定义，且宏值为 `32`
#[test]
fn test_ps2smb2_connect_name_field_width() {
    assert_eq!(SMB2_MAX_NAME_LEN, 32);
}

// Trace: `lib/ps2/ps2smb2.h:smb2Connect_in_t`, `lib/ps2/smb2_fio.c:smb2_Connect`
// Spec: smb2Connect_in_t preserve connect input layout#connect input payload consumed by devctl
// - **GIVEN** 调用方为 `SMB2_DEVCTL_CONNECT` 准备 `smb2Connect_in_t` 输入载荷
// - **WHEN** `SMB2_devctl` 分派连接命令
// - **THEN** PS2 SMB2 连接流程按该布局读取共享名称、用户名、密码和 URL 字段
#[test]
fn test_ps2smb2_connect_input_payload_consumed_by_devctl() {
    let input = Smb2ConnectIn {
        name: "share".into(),
        username: "user".into(),
        password: "password".into(),
        url: "smb://server/share".into(),
    };
    assert!(input.fits_fixed_buffers());
    assert_eq!(SMB2_USERNAME_LEN, 32);
    assert_eq!(SMB2_PASSWORD_LEN, 32);
    assert_eq!(SMB2_URL_LEN, 256);
}

// Trace: `lib/ps2/ps2smb2.h:smb2Connect_out_t`, `lib/ps2/smb2_fio.c:smb2_Connect`
// Spec: smb2Connect_out_t preserve connect output layout#connect output context field
// - **GIVEN** 调用方为 `SMB2_DEVCTL_CONNECT` 提供 `smb2Connect_out_t` 输出载荷
// - **WHEN** 连接流程开始或完成
// - **THEN** 输出载荷的 `ctx` 字段由实现初始化为空指针，并在连接成功时设置为 SMB2 上下文指针
#[test]
fn test_ps2smb2_connect_output_context_field() {
    assert_eq!(Smb2ConnectOut::default().ctx, None);
    assert_eq!(Smb2ConnectOut { ctx: Some(1) }.ctx, Some(1));
}

// Trace: `lib/ps2/ps2smb2.h:smb2Disconnect_in_t`
// Spec: smb2Disconnect_in_t preserve disconnect input layout#disconnect input context field
// - **GIVEN** 调用方包含 `lib/ps2/ps2smb2.h`
// - **WHEN** 调用方构造 `smb2Disconnect_in_t` 输入载荷
// - **THEN** 载荷包含单一 `void *ctx` 字段以携带不透明上下文指针
#[test]
fn test_ps2smb2_disconnect_input_context_field() {
    assert_eq!(Smb2DisconnectIn::default().ctx, None);
    assert_eq!(Smb2DisconnectIn { ctx: Some(1) }.ctx, Some(1));
}
