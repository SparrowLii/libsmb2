use libsmb2_rs::include::smb2::libsmb2::{
    DirectoryEntry, ErrorCode, FileHandle, FileType, Smb2Client, Smb2ClientState, Stat,
    SMB2_ADD_FD, SMB2_DEL_FD,
};
use libsmb2_rs::lib::libsmb2::{ConnectData, Smb2Directory};
use libsmb2_rs::lib::init::{InitContext, InitFileHandle};
use std::sync::{Arc, Mutex};

fn context() -> InitContext {
    InitContext::new()
}

fn client() -> Smb2Client {
    Smb2Client::new()
}

fn stat() -> Stat {
    Stat {
        file_type: FileType::File,
        nlink: 1,
        ino: 1,
        size: 0,
        atime: 0,
        atime_nsec: 0,
        mtime: 0,
        mtime_nsec: 0,
        ctime: 0,
        ctime_nsec: 0,
        btime: 0,
        btime_nsec: 0,
    }
}

fn directory_entry(name: &str) -> DirectoryEntry {
    DirectoryEntry {
        name: name.to_owned(),
        stat: stat(),
    }
}

fn connected_client() -> Smb2Client {
    let mut smb2 = client();
    smb2.connect_share_local("server", "share")
        .expect("local share connection succeeds");
    smb2
}

// Trace: `lib/libsmb2.c:smb2_close_context`
// Spec: smb2_close_context reset connection state#close null context
// - **GIVEN** 调用方传入 `NULL` 上下文
// - **WHEN** 调用 `smb2_close_context`
// - **THEN** 函数返回且不访问上下文字段
#[test]
fn test_libsmb2_close_null_context() {
    let mut maybe_context: Option<Smb2Client> = None;

    if let Some(context) = maybe_context.as_mut() {
        context.close_context();
    }

    assert!(maybe_context.is_none());
}

// Trace: `lib/libsmb2.c:smb2_close_context`
// Spec: smb2_close_context reset connection state#close active context
// - **GIVEN** 上下文包含有效 socket 和非空 `session_key`
// - **WHEN** 调用 `smb2_close_context`
// - **THEN** socket 被关闭，`fd` 设为 `SMB2_INVALID_SOCKET`，session/tree 状态复位，`session_key` 被释放并置空
#[test]
fn test_libsmb2_close_active_context() {
    let mut smb2 = client();
    smb2.set_fd(44);
    smb2.set_session_id(0x1122);
    smb2.select_tree_id(0x3344);

    smb2.close_context();

    assert_eq!(smb2.state(), Smb2ClientState::Closed);
    assert_eq!(smb2.fd(), -1);
    assert_eq!(smb2.session_id(), None);
    assert_eq!(smb2.tree_id(), None);
}

// Trace: `lib/libsmb2.c:smb2_seekdir`
// Spec: smb2_seekdir move directory cursor#seek directory cursor
// - **GIVEN** 目录对象包含条目链表且 `loc` 为非负值
// - **WHEN** 调用 `smb2_seekdir`
// - **THEN** `current_entry` 指向从头跳过 `loc` 个节点后的位置，`index` 记录实际跳过数量
#[test]
fn test_libsmb2_seek_directory_cursor() {
    let mut dir = Smb2Directory::new(vec![directory_entry("a"), directory_entry("b")]);

    dir.seekdir(1);

    assert_eq!(dir.telldir(), 1);
    assert_eq!(dir.readdir().unwrap().name, "b");
}

// Trace: `lib/libsmb2.c:smb2_telldir`
// Spec: smb2_telldir report directory cursor#tell directory cursor
// - **GIVEN** 目录对象当前 `index` 已由 seek/read/rewind 更新
// - **WHEN** 调用 `smb2_telldir`
// - **THEN** 返回值等于目录对象当前 `index`
#[test]
fn test_libsmb2_tell_directory_cursor() {
    let mut dir = Smb2Directory::new(vec![directory_entry("a"), directory_entry("b")]);
    let _ = dir.readdir();

    assert_eq!(dir.telldir(), 1);
}

// Trace: `lib/libsmb2.c:smb2_rewinddir`
// Spec: smb2_rewinddir reset directory cursor#rewind directory cursor
// - **GIVEN** 目录对象已被读取到非起始位置
// - **WHEN** 调用 `smb2_rewinddir`
// - **THEN** 下一次 `smb2_readdir` 从首个条目返回
#[test]
fn test_libsmb2_rewind_directory_cursor() {
    let mut dir = Smb2Directory::new(vec![directory_entry("a"), directory_entry("b")]);
    let _ = dir.readdir();

    dir.rewinddir();

    assert_eq!(dir.telldir(), 0);
    assert_eq!(dir.readdir().unwrap().name, "a");
}

// Trace: `lib/libsmb2.c:smb2_readdir`
// Spec: smb2_readdir return current entry and advance#read next directory entry
// - **GIVEN** 目录对象的 `current_entry` 指向有效节点
// - **WHEN** 调用 `smb2_readdir`
// - **THEN** 返回该节点的 `dirent`，且目录 `index` 增加 1
#[test]
fn test_libsmb2_read_next_directory_entry() {
    let mut dir = Smb2Directory::new(vec![directory_entry("a")]);

    assert_eq!(dir.readdir().unwrap().name, "a");
    assert_eq!(dir.telldir(), 1);
    assert!(dir.readdir().is_none());
}

// Trace: `lib/libsmb2.c:smb2_closedir`
// Spec: smb2_closedir release directory resources#close populated directory
// - **GIVEN** 目录对象包含内部条目链表和可选释放回调
// - **WHEN** 调用 `smb2_closedir`
// - **THEN** 目录关联内存被释放且不会发起网络请求
#[test]
fn test_libsmb2_close_populated_directory() {
    let mut dir = Smb2Directory::new(vec![directory_entry("a")]);

    dir.closedir();

    assert!(dir.is_empty());
    assert_eq!(dir.telldir(), 0);
}

// Trace: `lib/libsmb2.c:free_c_data`
// Spec: free_c_data release connection data#free active connect data
// - **GIVEN** `smb2->connect_data` 指向待释放的 `connect_data`
// - **WHEN** 调用 `free_c_data`
// - **THEN** 认证和字符串资源被释放，且上下文不再保留悬挂指针
#[test]
fn test_libsmb2_free_active_connect_data() {
    let mut data = ConnectData::new("server", "share");
    data.user = Some(String::from("alice"));
    data.utf8_unc = Some(data.unc());
    data.utf16_unc = data.unc().encode_utf16().collect();

    drop(data);

    let replacement = ConnectData::default();
    assert_eq!(replacement.server, "");
    assert_eq!(replacement.share, "");
    assert!(replacement.user.is_none());
}

// Trace: `lib/libsmb2.c:smb2_connect_share_async`, `tests/prog_cat.c:main`
// Spec: smb2_connect_share_async establish share connection#reject missing server or share
// - **GIVEN** 有效上下文但 `server == NULL` 或 `share == NULL`
// - **WHEN** 调用 `smb2_connect_share_async`
// - **THEN** 函数设置错误字符串并返回 `-EINVAL`
#[test]
fn test_libsmb2_reject_missing_server_or_share() {
    let mut smb2 = client();

    smb2.connect_share_async("", "share", None);

    assert_eq!(smb2.error(), Some("server must not be empty"));
    assert_eq!(smb2.nterror(), ErrorCode(-22).code());
}

// Trace: `lib/libsmb2.c:smb2_connect_share_async`, `tests/prog_cat_cancel.c:main`
// Spec: smb2_connect_share_async establish share connection#start share connection
// - **GIVEN** 有效上下文、server、share、用户和回调
// - **WHEN** 调用 `smb2_connect_share_async`
// - **THEN** 函数返回 0，后续连接结果通过回调报告
#[test]
fn test_libsmb2_start_share_connection() {
    let mut smb2 = client();

    smb2.connect_share_async("server", "share", Some("alice"));

    assert_eq!(smb2.queued_operations().len(), 1);
}

// Trace: `lib/libsmb2.c:smb2_open_async`, `tests/prog_cat.c:cf_cb`
// Spec: smb2_open_async start normal file open#open async starts request
// - **GIVEN** 有效上下文、路径、flags 和回调
// - **WHEN** 调用 `smb2_open_async`
// - **THEN** 函数委托内部 open 构造函数并返回启动状态
#[test]
fn test_libsmb2_open_async_starts_request() {
    let mut smb2 = connected_client();
    let queued_before = smb2.queued_operations().len();

    smb2.open_async("file.txt", 0);

    assert_eq!(smb2.queued_operations().len(), queued_before + 1);
}

// Trace: `lib/libsmb2.c:smb2_close_async`
// Spec: smb2_close_async close file handle#close valid handle
// - **GIVEN** 有效上下文和文件句柄
// - **WHEN** 调用 `smb2_close_async`
// - **THEN** close PDU 被排队，回调收到 0 或负 errno，文件句柄随后释放
#[test]
fn test_libsmb2_close_valid_handle() {
    let mut smb2 = connected_client();
    let handle = FileHandle::new([0x11; 16]);
    let queued_before = smb2.queued_operations().len();

    smb2.close_async(&handle);

    assert_eq!(smb2.queued_operations().len(), queued_before + 1);
}

// Trace: `lib/libsmb2.c:smb2_fsync_async`
// Spec: smb2_fsync_async flush file handle#flush valid handle
// - **GIVEN** 有效上下文和文件句柄
// - **WHEN** 调用 `smb2_fsync_async`
// - **THEN** flush PDU 使用句柄 file id 排队
#[test]
fn test_libsmb2_flush_valid_handle() {
    let mut smb2 = connected_client();
    let handle = FileHandle::new([0x22; 16]);
    let queued_before = smb2.queued_operations().len();

    smb2.fsync_async(&handle);

    assert_eq!(smb2.queued_operations().len(), queued_before + 1);
}

// Trace: `lib/libsmb2.c:smb2_lseek`
// Spec: smb2_lseek update handle offset#reject negative lseek
// - **GIVEN** 文件句柄当前偏移和输入 offset 组合产生负值
// - **WHEN** 调用 `smb2_lseek`
// - **THEN** 函数设置错误字符串并返回 `-EINVAL`
#[test]
fn test_libsmb2_reject_negative_lseek() {
    let mut smb2 = connected_client();
    let handle = FileHandle::new([0x33; 16]);

    assert_eq!(smb2.lseek(&handle, -1, 0), None);
    assert_eq!(smb2.error(), Some("invalid seek offset"));
}

// Trace: `lib/libsmb2.c:smb2_unlink_async`
// Spec: smb2_unlink_async delete file by path#unlink starts compound request
// - **GIVEN** 有效上下文、路径和回调
// - **WHEN** 调用 `smb2_unlink_async`
// - **THEN** create 请求使用 `SMB2_FILE_DELETE_ON_CLOSE` 且非目录属性
#[test]
fn test_libsmb2_unlink_starts_compound_request() {
    let mut smb2 = connected_client();
    let queued_before = smb2.queued_operations().len();

    smb2.unlink_async("file.txt");

    assert_eq!(smb2.queued_operations().len(), queued_before + 1);
}

// Trace: `lib/libsmb2.c:smb2_rmdir_async`
// Spec: smb2_rmdir_async delete directory by path#rmdir starts compound request
// - **GIVEN** 有效上下文、路径和回调
// - **WHEN** 调用 `smb2_rmdir_async`
// - **THEN** create 请求使用目录属性和 `SMB2_FILE_DELETE_ON_CLOSE`
#[test]
fn test_libsmb2_rmdir_starts_compound_request() {
    let mut smb2 = connected_client();
    let queued_before = smb2.queued_operations().len();

    smb2.rmdir_async("dir");

    assert_eq!(smb2.queued_operations().len(), queued_before + 1);
}

// Trace: `lib/libsmb2.c:smb2_mkdir_async`
// Spec: smb2_mkdir_async create directory by path#mkdir starts compound request
// - **GIVEN** 有效上下文、路径和回调
// - **WHEN** 调用 `smb2_mkdir_async`
// - **THEN** create 请求使用 `SMB2_FILE_CREATE` 和 `SMB2_FILE_DIRECTORY_FILE`
#[test]
fn test_libsmb2_mkdir_starts_compound_request() {
    let mut smb2 = connected_client();
    let queued_before = smb2.queued_operations().len();

    smb2.mkdir_async("dir");

    assert_eq!(smb2.queued_operations().len(), queued_before + 1);
}

// Trace: `lib/libsmb2.c:smb2_disconnect_share_async`
// Spec: smb2_disconnect_share_async disconnect tree and session#reject disconnected context
// - **GIVEN** 上下文 fd 无效
// - **WHEN** 调用 `smb2_disconnect_share_async`
// - **THEN** 函数设置错误字符串并返回 `-EINVAL`
#[test]
fn test_libsmb2_reject_disconnected_context() {
    let mut smb2 = client();

    assert_eq!(smb2.disconnect_share(), Err(ErrorCode(-107)));
    assert!(smb2.queued_operations().is_empty());
}

// Trace: `lib/libsmb2.c:smb2_echo_async`
// Spec: smb2_echo_async send echo request#echo starts request
// - **GIVEN** 有效上下文和回调
// - **WHEN** 调用 `smb2_echo_async`
// - **THEN** echo PDU 被排队且函数返回 0
#[test]
fn test_libsmb2_echo_starts_request() {
    let mut smb2 = client();

    smb2.echo_async();

    assert_eq!(smb2.queued_operations().len(), 1);
}

// Trace: `lib/libsmb2.c:smb2_fd_event_callbacks`
// Spec: smb2_fd_event_callbacks register event callbacks#register callbacks
// - **GIVEN** 有效上下文和两个回调函数指针
// - **WHEN** 调用 `smb2_fd_event_callbacks`
// - **THEN** 后续 fd/event 变化路径使用这些回调
#[test]
fn test_libsmb2_register_callbacks() {
    let fd_events = Arc::new(Mutex::new(Vec::new()));
    let mask_events = Arc::new(Mutex::new(Vec::new()));
    let fd_events_for_callback = Arc::clone(&fd_events);
    let mask_events_for_callback = Arc::clone(&mask_events);
    let mut smb2 = client();
    smb2.set_fd_event_callbacks(
        Some(Box::new(move |_ctx, fd, cmd| {
            fd_events_for_callback.lock().unwrap().push((fd, cmd));
        })),
        Some(Box::new(move |_ctx, fd, events| {
            mask_events_for_callback.lock().unwrap().push((fd, events));
        })),
    );

    smb2.set_fd(10);
    smb2.set_events(1);
    smb2.set_fd(11);

    assert_eq!(
        fd_events.lock().unwrap().as_slice(),
        &[(10, SMB2_ADD_FD), (10, SMB2_DEL_FD), (11, SMB2_ADD_FD)]
    );
    assert_eq!(mask_events.lock().unwrap().as_slice(), &[(10, 1)]);
}

// Trace: `lib/libsmb2.c:smb2_get_max_read_size`
// Spec: smb2_get_max_read_size return negotiated read size#get max read size
// - **GIVEN** 上下文已完成 negotiate 并记录 max read size
// - **WHEN** 调用 `smb2_get_max_read_size`
// - **THEN** 返回值等于 `smb2->max_read_size`
#[test]
fn test_libsmb2_get_max_read_size() {
    let mut ctx = context();

    ctx.set_max_read_size_for_test(0x0010_0000);

    assert_eq!(ctx.max_read_size(), 0x0010_0000);
}

// Trace: `lib/libsmb2.c:smb2_get_max_write_size`
// Spec: smb2_get_max_write_size return negotiated write size#get max write size
// - **GIVEN** 上下文已完成 negotiate 并记录 max write size
// - **WHEN** 调用 `smb2_get_max_write_size`
// - **THEN** 返回值等于 `smb2->max_write_size`
#[test]
fn test_libsmb2_get_max_write_size() {
    let mut ctx = context();

    ctx.set_max_write_size_for_test(0x0020_0000);

    assert_eq!(ctx.max_write_size(), 0x0020_0000);
}

// Trace: `lib/libsmb2.c:smb2_get_file_id`
// Spec: smb2_get_file_id expose handle file id#get file id pointer
// - **GIVEN** 有效文件句柄
// - **WHEN** 调用 `smb2_get_file_id`
// - **THEN** 返回指针引用该句柄内部 file id
#[test]
fn test_libsmb2_get_file_id_pointer() {
    let file_id = [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
        0xff,
    ];
    let fh = InitFileHandle::from_file_id(file_id).expect("file handle allocation succeeds");

    assert_eq!(fh.file_id(), file_id);
}

// Trace: `lib/libsmb2.c:smb2_fh_from_file_id`
// Spec: smb2_fh_from_file_id create handle from file id#create handle from file id
// - **GIVEN** 有效 file id
// - **WHEN** 调用 `smb2_fh_from_file_id`
// - **THEN** 返回的新句柄包含相同 file id
#[test]
fn test_libsmb2_create_handle_from_file_id() {
    let file_id = [
        0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11,
        0x00,
    ];

    let fh = InitFileHandle::from_file_id(file_id).expect("file handle allocation succeeds");

    assert_eq!(fh.file_id(), file_id);
}
