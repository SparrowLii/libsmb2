use libsmb2_rs::include::libsmb2_private::{RecvState, Smb2Header};
use libsmb2_rs::lib::socket::{
    accept_connection_async, bind_and_listen, Events, MemoryTransportAdapter, ReadOutcome,
    ServiceOutcome, SocketAddress, SocketContext, SocketError, SocketPdu,
    HAPPY_EYEBALLS_TIMEOUT_MS, INVALID_SOCKET, POLLIN, POLLOUT,
};

fn pdu(payload: &[u8]) -> SocketPdu {
    SocketPdu {
        header: Smb2Header::default(),
        vectors: vec![payload.to_vec()],
        bytes_done: 0,
        payload_len: payload.len(),
        sealed: false,
        next_compound: Vec::new(),
    }
}

// Trace: `lib/socket.c:smb2_close_connecting_fds`
// Spec: smb2_close_connecting_fds close pending connection resources#close pending fds and resolver state
// - **GIVEN** `smb2->connecting_fds` 包含一个或多个连接中 fd，且其中可能包含当前已连接 `smb2->fd`
// - **WHEN** 调用 `smb2_close_connecting_fds(smb2)`
// - **THEN** 函数关闭非当前连接 fd，按需通过 `change_fd` 发送 `SMB2_DEL_FD`，释放连接 fd 数组和 addrinfo，并将 `connecting_fds`、`addrinfos`、`next_addrinfo` 清为 `NULL` 且计数清零
#[test]
fn test_socket_close_pending_fds_and_resolver_state() {
    let mut context = SocketContext::new();
    context.fd = 42;
    context.connecting_fds = vec![40, 42, 43];
    context.add_addrinfo(libsmb2_rs::lib::socket::AddrInfoEntry {
        family: 0,
        address: libsmb2_rs::lib::socket::SocketAddress::parse("127.0.0.1:445").unwrap(),
    });

    context.close_connecting_fds();

    assert!(context.connecting_fds.is_empty());
    assert!(context.addrinfos.is_empty());
    assert_eq!(context.next_addrinfo, None);
}

// Trace: `lib/socket.c:smb2_which_events`, `include/smb2/libsmb2.h:smb2_which_events`, `tests/prog_cat.c`, `tests/prog_cat_cancel.c`, `tests/metastat-0202-censored.c`
// Spec: smb2_which_events expose required poll events#report socket readiness mask
// - **GIVEN** 调用方在事件循环中持有 `struct smb2_context`
// - **WHEN** 调用 `smb2_which_events(smb2)` 查询应等待事件
// - **THEN** 返回值反映当前连接状态和发送信用状态，使调用方可将该掩码传给 poll/select 集成层
#[test]
fn test_socket_report_socket_readiness_mask() {
    let mut context = SocketContext::new();
    assert_eq!(context.which_events(), Events::from_poll_bits(POLLOUT));

    context.fd = 42;
    context.credits = 1;
    context.outqueue.push(pdu(b"abc"));
    assert_eq!(
        context.which_events(),
        Events::from_poll_bits(POLLIN | POLLOUT)
    );
}

// Trace: `lib/socket.c:smb2_get_fd`, `include/smb2/libsmb2.h:smb2_get_fd`, `tests/prog_cat.c`, `tests/prog_cat_cancel.c`, `tests/metastat-0202-censored.c`
// Spec: smb2_get_fd expose active or first connecting fd#select fd for simple event loop
// - **GIVEN** 调用方使用简单 poll/select 事件循环集成 libsmb2
// - **WHEN** 调用 `smb2_get_fd(smb2)`
// - **THEN** 调用方获得当前应轮询的已连接 fd、首个连接中 fd 或无 fd 标记 `-1`
#[test]
fn test_socket_select_fd_for_simple_event_loop() {
    let mut context = SocketContext::new();
    assert_eq!(context.get_fd(), None);

    context.connecting_fds.push(41);
    assert_eq!(context.get_fd(), Some(41));

    context.fd = 42;
    assert_eq!(context.get_fd(), Some(42));
}

// Trace: `lib/socket.c:smb2_get_fds`, `include/smb2/libsmb2.h:smb2_get_fds`
// Spec: smb2_get_fds expose all active connection candidates#retrieve Happy Eyeballs fd set
// - **GIVEN** 异步连接可能已经启动多个候选 fd
// - **WHEN** 调用 `smb2_get_fds(smb2, fd_count, timeout)`
// - **THEN** 调用方获得需要轮询的 fd 数组、fd 数量和是否需要用 `fd = -1` 触发下一地址连接的 timeout
#[test]
fn test_socket_retrieve_happy_eyeballs_fd_set() {
    let mut context = SocketContext::new();
    context.connecting_fds = vec![41, 42];
    context.next_addrinfo = Some(0);

    let fd_set = context.get_fds();
    assert_eq!(fd_set.fds, &[41, 42]);
    assert_eq!(fd_set.timeout_ms, Some(HAPPY_EYEBALLS_TIMEOUT_MS));

    context.fd = 43;
    let fd_set = context.get_fds();
    assert_eq!(fd_set.fds, &[43]);
    assert_eq!(fd_set.timeout_ms, None);
}

// Trace: `lib/socket.c:smb2_write_to_socket`, `include/libsmb2-private.h:smb2_write_to_socket`
// Spec: smb2_write_to_socket write queued PDUs with credit accounting#send complete queued PDU
// - **GIVEN** `smb2->outqueue` 包含可发送 PDU，socket 有效且 credit 足够
// - **WHEN** 调用 `smb2_write_to_socket(smb2)` 且 writev 完成 SPL 与 payload 写入
// - **THEN** 函数更新 `num_done`，移除已发送 PDU，client 模式扣减 credit 并加入 waitqueue，server 模式重置 credit 并释放回复 PDU
#[test]
fn test_socket_send_complete_queued_pdu() {
    let mut context = SocketContext::new();
    context.fd = 42;
    context.credits = 1;
    context.outqueue.push(pdu(b"abc"));
    let mut transport = MemoryTransportAdapter::new(42);

    let outcome = context.write_to_transport(&mut transport).unwrap();

    assert!(matches!(
        outcome,
        libsmb2_rs::lib::socket::WriteOutcome::Written { bytes_written: 7 }
    ));
    assert!(context.outqueue.is_empty());
    assert_eq!(context.waitqueue.len(), 1);
    assert_eq!(transport.written(), &[0, 0, 0, 3, b'a', b'b', b'c']);
}

// Trace: `lib/socket.c:smb2_read_from_buf`, `include/libsmb2-private.h:smb2_read_from_buf`
// Spec: smb2_read_from_buf process decrypted receive buffers#process encrypted payload after decrypt
// - **GIVEN** `smb2->enc`、`enc_len` 和 `enc_pos` 描述已解密载荷缓冲区
// - **WHEN** 调用 `smb2_read_from_buf(smb2)`
// - **THEN** 函数通过 buffer read adapter 推进接收状态机，并返回状态机产生的成功、EAGAIN 或错误结果
#[test]
fn test_socket_process_encrypted_payload_after_decrypt() {
    let mut context = SocketContext::new();
    context.recv_state = RecvState::Spl;

    assert_eq!(
        context.read_from_buf(),
        Ok(ReadOutcome::Advanced(RecvState::Header))
    );
    assert_eq!(context.recv_state, RecvState::Header);
}

// Trace: `lib/socket.c:smb2_close_connecting_fd`
// Spec: smb2_close_connecting_fd close one pending connection fd#remove failed connecting fd
// - **GIVEN** `connecting_fds` 数组包含一个连接失败的 fd
// - **WHEN** 调用 `smb2_close_connecting_fd(smb2, fd)`
// - **THEN** 函数关闭该 fd，将后续数组元素前移，并减少连接中 fd 计数
#[test]
fn test_socket_remove_failed_connecting_fd() {
    let mut context = SocketContext::new();
    context.connecting_fds = vec![40, 41, 42];

    assert_eq!(
        context.service_fd_with_transport(
            41,
            libsmb2_rs::lib::socket::POLLERR,
            &mut MemoryTransportAdapter::new(41)
        ),
        Ok(ServiceOutcome::Error)
    );
}

// Trace: `lib/socket.c:smb2_service_fd`, `include/smb2/libsmb2.h:smb2_service_fd`
// Spec: smb2_service_fd process fd events and connection progress#complete async connection
// - **GIVEN** 异步连接中的 fd 收到 `POLLOUT` 且 `getsockopt(SO_ERROR)` 返回成功
// - **WHEN** 调用 `smb2_service_fd(smb2, fd, POLLOUT)`
// - **THEN** 函数将 fd 设为 `smb2->fd`，关闭其他连接中 fd，更新事件并以 status 0 调用连接回调
#[test]
fn test_socket_complete_async_connection() {
    let mut context = SocketContext::new();
    context.connecting_fds = vec![41, 42];

    assert_eq!(
        context.service_fd(41, POLLOUT),
        Ok(ServiceOutcome::Connected)
    );
    assert_eq!(context.fd, 41);
    assert!(context.connecting_fds.is_empty());
    assert_eq!(context.events, Events::from_poll_bits(POLLIN));
}

// Trace: `lib/socket.c:smb2_service_fd`, `include/smb2/libsmb2.h:smb2_service_fd`
// Spec: smb2_service_fd process fd events and connection progress#handle read and write readiness
// - **GIVEN** fd 已连接且 revents 包含 `POLLIN` 或可发送 outqueue 的 `POLLOUT`
// - **WHEN** 调用 `smb2_service_fd(smb2, fd, revents)`
// - **THEN** 函数按事件调用 socket 读取或写入路径，任一路径失败时返回 -1，成功处理后返回 0
#[test]
fn test_socket_handle_read_and_write_readiness() {
    let mut context = SocketContext::new();
    context.fd = 42;
    context.credits = 1;
    context.outqueue.push(pdu(b"abc"));
    let mut transport = MemoryTransportAdapter::with_readable(42, [0, 0, 0, 64]);

    assert_eq!(
        context.service_fd_with_transport(42, POLLIN | POLLOUT, &mut transport),
        Ok(ServiceOutcome::Serviced)
    );
    assert!(context.outqueue.is_empty());
    assert_eq!(context.waitqueue.len(), 1);
}

// Trace: `lib/socket.c:smb2_service`, `include/smb2/libsmb2.h:smb2_service`, `tests/prog_cat.c`, `tests/prog_cat_cancel.c`, `tests/metastat-0202-censored.c`
// Spec: smb2_service dispatch current context fd events#service simple event loop result
// - **GIVEN** 调用方使用 `smb2_get_fd` 和 `smb2_which_events` 完成一次 poll/select
// - **WHEN** 调用 `smb2_service(smb2, revents)`
// - **THEN** 函数选择当前连接阶段 fd 或已连接 fd 进行事件处理，并向调用方返回 0 或不可恢复错误码
#[test]
fn test_socket_service_simple_event_loop_result() {
    let mut context = SocketContext::new();
    context.connecting_fds = vec![42];

    assert_eq!(context.service(POLLOUT), Ok(ServiceOutcome::Connected));
    assert_eq!(context.fd, 42);
}

// Trace: `lib/socket.c:smb2_connect_async`, `include/smb2/libsmb2.h:smb2_connect_async`
// Spec: smb2_connect_async initiate asynchronous TCP connection#start async connection
// - **GIVEN** context 尚未连接且 `server` 可解析为一个或多个地址
// - **WHEN** 调用 `smb2_connect_async(smb2, server, cb, cb_data)`
// - **THEN** 函数创建非阻塞 socket 连接候选，保存连接回调数据，并返回 0 表示连接流程已启动
#[test]
fn test_socket_start_async_connection() {
    let mut context = SocketContext::new();

    let outcome = context.connect_async("127.0.0.1:1").unwrap();

    assert!(matches!(outcome, ServiceOutcome::Connecting { .. }));
    assert!(!context.connecting_fds.is_empty());
    assert_eq!(context.fd, INVALID_SOCKET);
}

// Trace: `lib/socket.c:smb2_connect_async`, `include/smb2/libsmb2.h:smb2_connect_async`
// Spec: smb2_connect_async initiate asynchronous TCP connection#reject malformed IPv6 literal
// - **GIVEN** `server` 以 `[` 开始但缺少匹配的 `]`
// - **WHEN** 调用 `smb2_connect_async(smb2, server, cb, cb_data)`
// - **THEN** 函数释放临时地址副本，设置错误消息并返回 `-EINVAL`，且不保存连接回调
#[test]
fn test_socket_reject_malformed_ipv6_literal() {
    let mut context = SocketContext::new();

    assert_eq!(
        context.connect_async("[::1:445"),
        Err(SocketError::InvalidAddress)
    );
    assert!(context.connecting_fds.is_empty());
}

// Trace: `lib/socket.c:smb2_bind_and_listen`, `include/smb2/libsmb2.h:smb2_bind_and_listen`
// Spec: smb2_bind_and_listen create nonblocking server listener#create listen fd
// - **GIVEN** 调用方提供端口、backlog 和 `out_fd` 指针
// - **WHEN** 调用 `smb2_bind_and_listen(port, max_connections, out_fd)` 且 socket/bind/listen 均成功
// - **THEN** 函数返回 0，并通过 `out_fd` 交付非阻塞监听 socket
#[test]
fn test_socket_create_listen_fd() {
    assert_eq!(bind_and_listen(0, -1), Err(SocketError::InvalidAddress));

    let fd = bind_and_listen(0, 16).unwrap();

    assert!(fd >= 0);
}

// Trace: `lib/socket.c:smb2_accept_connection_async`, `include/smb2/libsmb2.h:smb2_accept_connection_async`
// Spec: smb2_accept_connection_async accept one client when ready#accept ready client
// - **GIVEN** 有效监听 fd 在 timeout 内变为可读
// - **WHEN** 调用 `smb2_accept_connection_async(fd, to_msec, cb, cb_data)`
// - **THEN** 函数 accept 一个 client fd，设置 socket 选项，并返回 `cb(clientfd, cb_data)` 的结果
#[test]
fn test_socket_accept_ready_client_process_safe_boundary() {
    let fd = bind_and_listen(0, 16).unwrap();

    assert_eq!(accept_connection_async(fd, 0), Err(SocketError::WouldBlock));
    assert_eq!(
        accept_connection_async(fd + 1, 0),
        Err(SocketError::InvalidSocket)
    );
}

// Trace: `lib/socket.c:smb2_change_events`, `include/libsmb2-private.h:smb2_change_events`
// Spec: smb2_change_events notify only changed event masks#update external event subscription
// - **GIVEN** context 注册了事件变更回调且新事件掩码不同于缓存值
// - **WHEN** 调用 `smb2_change_events(smb2, fd, events)`
// - **THEN** 函数通知调用方更新 fd 订阅，并把新掩码缓存到 `smb2->events`
#[test]
fn test_socket_update_external_event_subscription() {
    let mut context = SocketContext::new();
    let initial = Events::from_poll_bits(POLLOUT);
    let changed = Events::from_poll_bits(POLLIN | POLLOUT);

    context.change_events(initial);
    assert_eq!(context.events, initial);

    context.change_events(initial);
    assert_eq!(context.events, initial);

    context.change_events(changed);
    assert_eq!(context.events, changed);

    let parsed = SocketAddress::parse("[::1]:445").unwrap();
    assert_eq!(parsed.host, "::1");
    assert_eq!(parsed.port, "445");
}
