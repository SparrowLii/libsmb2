use libsmb2_rs::lib::ps2::smb2_fio::{
    IopFile, LocalPs2Backend, Smb2ConnectIn, Smb2DevctlCommand, Smb2DeviceState, Smb2Fio,
    Smb2FioError, Smb2PrivData, FIO_S_IFDIR, O_RDONLY,
};

fn connected_device() -> Smb2Fio<LocalPs2Backend> {
    let mut fio = Smb2Fio::new();
    let _device = fio.initdev().unwrap();
    fio.devctl(Smb2DevctlCommand::Connect(Smb2ConnectIn {
        url: "smb://server/share".into(),
        name: "share".into(),
        username: "user".into(),
        password: "password".into(),
    }))
    .unwrap();
    fio
}

// Trace: `lib/ps2/smb2_fio.c:SMB2_initdev`, `lib/ps2/smb2man.c:_start`
// Spec: SMB2_initdev register PS2 SMB device#register succeeds
// - **GIVEN** `SMB2_initdev` 被 PS2 模块 `_start` 调用
// - **WHEN** `AddDrv((iop_device_t *)&smb2dev)` 返回 0
// - **THEN** 函数返回 `MODULE_RESIDENT_END`
#[test]
fn test_smb2_fio_register_succeeds() {
    let mut fio = Smb2Fio::new();
    let device = fio.initdev().unwrap();
    assert_eq!(device.name, "smb");
    assert_eq!(fio.state(), Smb2DeviceState::LocalFallback);
}

// Trace: `lib/ps2/smb2_fio.c:SMB2_initdev`
// Spec: SMB2_initdev register PS2 SMB device#register fails
// - **GIVEN** `SMB2_initdev` 已尝试删除旧的 `smb` 设备
// - **WHEN** `AddDrv((iop_device_t *)&smb2dev)` 返回非零
// - **THEN** 函数返回 `MODULE_NO_RESIDENT_END`
#[test]
fn test_smb2_fio_register_fails() {
    let mut fio = Smb2Fio::with_backend(libsmb2_rs::lib::ps2::smb2_fio::UnavailablePs2Backend);
    assert_eq!(
        fio.initdev().unwrap_err(),
        Smb2FioError::PlatformUnavailable
    );
}

// Trace: `lib/ps2/smb2_fio.c:SMB2_devctl`
// Spec: SMB2_devctl connect shares#connect command succeeds
// - **GIVEN** `cmd` 等于 `SMB2_DEVCTL_CONNECT` 且 `arg` 指向 `smb2Connect_in_t`
// - **WHEN** `SMB2_devctl` 在 I/O 互斥锁内调用连接逻辑
// - **THEN** 成功时返回 0，并在 `bufp` 非空时写入创建的 SMB2 context
#[test]
fn test_smb2_fio_connect_command_succeeds() {
    let fio = connected_device();
    assert_eq!(fio.shares().len(), 1);
    assert_eq!(fio.shares()[0].name, "share");
}

// Trace: `lib/ps2/smb2_fio.c:SMB2_devctl`
// Spec: SMB2_devctl connect shares#unknown command rejected
// - **GIVEN** `cmd` 不是 `SMB2_DEVCTL_CONNECT`
// - **WHEN** `SMB2_devctl` 处理命令分发
// - **THEN** 函数返回 `-EINVAL`
#[test]
fn test_smb2_fio_unknown_command_rejected() {
    let mut fio = connected_device();
    assert_eq!(
        fio.devctl(Smb2DevctlCommand::Unknown(7)).unwrap_err(),
        Smb2FioError::InvalidInput
    );
}

// Trace: `lib/ps2/smb2_fio.c:SMB2_open`
// Spec: SMB2_open open read-only files#read-only file opens
// - **GIVEN** `filename` 非空、`flags` 等于 `O_RDONLY` 且路径解析到已连接共享
// - **WHEN** `SMB2_open` 成功调用 `smb2_open`
// - **THEN** 函数返回 0，并把包含 SMB2 context 和文件句柄的 `struct file_fh` 保存到 `f->privdata`
#[test]
fn test_smb2_fio_read_only_file_opens() {
    let mut fio = connected_device();
    let mut file = IopFile::default();
    fio.open(&mut file, "share/file.txt", O_RDONLY, 0).unwrap();
    assert!(matches!(file.privdata, Some(Smb2PrivData::File(_))));
}

// Trace: `lib/ps2/smb2_fio.c:SMB2_open`
// Spec: SMB2_open open read-only files#write flags rejected
// - **GIVEN** `flags` 不等于 `O_RDONLY`
// - **WHEN** `SMB2_open` 被调用
// - **THEN** 函数返回 `-EROFS`
#[test]
fn test_smb2_fio_write_flags_rejected() {
    let mut fio = connected_device();
    let mut file = IopFile::default();
    assert_eq!(
        fio.open(&mut file, "share/file.txt", 3, 0).unwrap_err(),
        Smb2FioError::ReadOnlyFileSystem
    );
}

// Trace: `lib/ps2/smb2_fio.c:SMB2_close`
// Spec: SMB2_close release file handles#valid file closes
// - **GIVEN** `f->privdata` 指向 `struct file_fh`
// - **WHEN** `SMB2_close` 被调用
// - **THEN** 函数调用 `smb2_close`、释放私有句柄、设置 `f->privdata` 为 `NULL` 并返回 0
#[test]
fn test_smb2_fio_valid_file_closes() {
    let mut fio = connected_device();
    let mut file = IopFile::default();
    fio.open(&mut file, "share/file.txt", O_RDONLY, 0).unwrap();
    fio.close(&mut file).unwrap();
    assert!(file.privdata.is_none());
}

// Trace: `lib/ps2/smb2_fio.c:SMB2_close`
// Spec: SMB2_close release file handles#invalid file handle rejected
// - **GIVEN** `f->privdata` 为 `NULL`
// - **WHEN** `SMB2_close` 被调用
// - **THEN** 函数返回 `-EBADF`
#[test]
fn test_smb2_fio_invalid_file_handle_rejected() {
    let mut fio = connected_device();
    let mut file = IopFile::default();
    assert_eq!(
        fio.close(&mut file).unwrap_err(),
        Smb2FioError::BadFileDescriptor
    );
}

// Trace: `lib/ps2/smb2_fio.c:SMB2_dopen`
// Spec: SMB2_dopen open directories#SMB2 directory opens
// - **GIVEN** `dirname` 非空且路径解析到已连接共享内的非空 remainder
// - **WHEN** `SMB2_dopen` 成功调用 `smb2_opendir`
// - **THEN** 函数保存 `struct dir_fh` 到 `f->privdata` 并返回 0
#[test]
fn test_smb2_fio_smb2_directory_opens() {
    let mut fio = connected_device();
    let mut file = IopFile::default();
    fio.dopen(&mut file, "share").unwrap();
    assert!(matches!(file.privdata, Some(Smb2PrivData::Directory(_))));
}

// Trace: `lib/ps2/smb2_fio.c:SMB2_dopen`
// Spec: SMB2_dopen open directories#missing directory name rejected
// - **GIVEN** `dirname` 为 `NULL`
// - **WHEN** `SMB2_dopen` 被调用
// - **THEN** 函数返回 `-ENOENT`
#[test]
fn test_smb2_fio_missing_directory_name_rejected() {
    let mut fio = connected_device();
    let mut file = IopFile::default();
    assert_eq!(
        fio.dopen(&mut file, "missing").unwrap_err(),
        Smb2FioError::NoEntry
    );
}

// Trace: `lib/ps2/smb2_fio.c:SMB2_dclose`
// Spec: SMB2_dclose release directory handles#valid directory closes
// - **GIVEN** `f->privdata` 指向 `struct dir_fh`
// - **WHEN** `SMB2_dclose` 被调用
// - **THEN** 函数对非 root 目录关闭 SMB2 目录句柄、释放私有数据、清空 `f->privdata` 并返回 0
#[test]
fn test_smb2_fio_valid_directory_closes() {
    let mut fio = connected_device();
    let mut file = IopFile::default();
    fio.dopen(&mut file, "share").unwrap();
    fio.dclose(&mut file).unwrap();
    assert!(file.privdata.is_none());
}

// Trace: `lib/ps2/smb2_fio.c:SMB2_dclose`
// Spec: SMB2_dclose release directory handles#invalid directory handle rejected
// - **GIVEN** `f->privdata` 为 `NULL`
// - **WHEN** `SMB2_dclose` 被调用
// - **THEN** 函数返回 `-EBADF`
#[test]
fn test_smb2_fio_invalid_directory_handle_rejected() {
    let mut fio = connected_device();
    let mut file = IopFile::default();
    assert_eq!(
        fio.dclose(&mut file).unwrap_err(),
        Smb2FioError::BadFileDescriptor
    );
}

// Trace: `lib/ps2/smb2_fio.c:SMB2_dread`
// Spec: SMB2_dread return directory entries#SMB2 directory entry returned
// - **GIVEN** `f->privdata` 指向非 root `struct dir_fh` 且 `smb2_readdir` 返回条目
// - **WHEN** `SMB2_dread` 被调用
// - **THEN** 函数复制条目名称、填充 stat 信息并返回 1
#[test]
fn test_smb2_fio_smb2_directory_entry_returned() {
    let mut fio = connected_device();
    let mut file = IopFile::default();
    fio.open(&mut file, "share/dir/file.txt", O_RDONLY, 0)
        .unwrap();
    fio.close(&mut file).unwrap();
    fio.dopen(&mut file, "share/dir").unwrap();
    let entry = fio.dread(&mut file).unwrap().unwrap();
    assert_eq!(entry.name, "file.txt");
}

// Trace: `lib/ps2/smb2_fio.c:SMB2_dread`
// Spec: SMB2_dread return directory entries#virtual root share returned
// - **GIVEN** `f->privdata` 指向 root `struct dir_fh` 且 `dfh->shares` 非空
// - **WHEN** `SMB2_dread` 被调用
// - **THEN** 函数把共享名作为目录名返回、设置目录模式并返回 1
#[test]
fn test_smb2_fio_virtual_root_share_returned() {
    let mut fio = connected_device();
    let mut file = IopFile::default();
    fio.dopen(&mut file, "").unwrap();
    let entry = fio.dread(&mut file).unwrap().unwrap();
    assert_eq!(entry.name, "share");
    assert_eq!(entry.stat.mode, FIO_S_IFDIR);
}

// Trace: `lib/ps2/smb2_fio.c:SMB2_getstat`
// Spec: SMB2_getstat fill PS2 stat#stat succeeds
// - **GIVEN** `filename` 非空且路径解析到已连接共享
// - **WHEN** `smb2_stat` 返回 0
// - **THEN** `SMB2_getstat` 填充时间、大小和文件类型字段并返回 0
#[test]
fn test_smb2_fio_stat_succeeds() {
    let mut fio = connected_device();
    let mut file = IopFile::default();
    fio.open(&mut file, "share/file.txt", O_RDONLY, 0).unwrap();
    let stat = fio.getstat("share/file.txt").unwrap();
    assert_ne!(stat.mode, 0);
}

// Trace: `lib/ps2/smb2_fio.c:SMB2_getstat`
// Spec: SMB2_getstat fill PS2 stat#filename missing
// - **GIVEN** `filename` 为 `NULL`
// - **WHEN** `SMB2_getstat` 被调用
// - **THEN** 函数返回 `-ENOENT`
#[test]
fn test_smb2_fio_filename_missing() {
    let fio = connected_device();
    assert_eq!(fio.getstat("missing").unwrap_err(), Smb2FioError::NoEntry);
}
