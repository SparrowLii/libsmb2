# lib/socket.c Specification

## Source Context

- Source: `lib/socket.c`
- Related Headers: `include/smb2/libsmb2.h`, `include/libsmb2-private.h`, `include/slist.h`, `lib/smb3-seal.h`, `include/portable-endian.h`
- Related Tests: `tests/prog_cat.c`, `tests/prog_cat_cancel.c`, `tests/metastat-0202-censored.c`
- Related Dependencies: `smb2_get_credit_charge`, `smb2_add_iovector`, `smb2_decode_header`, `smb2_process_payload_fixed`, `smb2_process_payload_variable`, `smb2_find_pdu`, `smb2_free_pdu`, `smb2_timeout_pdus`, `smb3_decrypt_pdu`, `smb2_set_error`, `SMB2_LIST_ADD_END`, `SMB2_LIST_REMOVE`
- Build/Compile Context: `CMakeLists.txt` and `lib/CMakeLists.txt` build the C library; `configure.ac` probes socket, poll, vector I/O, endian and platform headers; source behavior is conditioned by `HAVE_CONFIG_H`, `_GNU_SOURCE`, `HAVE_*` headers, `_WIN32`, `_XBOX`, `CONFIGURE_OPTION_TCP_LINGER`, `HAVE_LINGER`, `AF_INET6`, `PICO_PLATFORM`, and `LWIP_INETV6`.

## Interface Summary

| Interface | Kind | Signature | Decision | Reason |
| --- | --- | --- | --- | --- |
| smb2_close_connecting_fds | function | void smb2_close_connecting_fds(struct smb2_context *smb2); | Include | 私有跨文件连接清理入口，释放 Happy Eyeballs 连接 fd 数组和 addrinfo。 |
| smb2_get_real_credit_charge_for_one_pdu | function | static int smb2_get_real_credit_charge_for_one_pdu(struct smb2_context *smb2, struct smb2_header *hdr) | Skip | 纯内部 helper，仅为发送信用计算提供单 PDU 折算，无独立对外契约。 |
| smb2_get_credit_charge | function | static int smb2_get_credit_charge(struct smb2_context *smb2, struct smb2_pdu *pdu) | Skip | 纯内部 helper，仅聚合 compound PDU 信用，不作为跨文件接口暴露。 |
| smb2_which_events | function | int smb2_which_events(struct smb2_context *smb2); | Include | 公开事件循环集成 API，调用方依赖其 POLLIN/POLLOUT 掩码。 |
| smb2_get_fd | function | t_socket smb2_get_fd(struct smb2_context *smb2); | Include | 公开事件循环集成 API，返回当前 socket 或连接中的第一个 fd。 |
| smb2_get_fds | function | const t_socket *smb2_get_fds(struct smb2_context *smb2, size_t *fd_count, int *timeout); | Include | 公开 Happy Eyeballs 多 fd 集成 API，输出 fd 数量和连接阶段 timeout。 |
| smb2_write_to_socket | function | int smb2_write_to_socket(struct smb2_context *smb2); | Include | 私有跨文件发送入口，管理 outqueue、writev、credit 和 waitqueue 状态。 |
| smb2_read_data | function | static int smb2_read_data(struct smb2_context *smb2, read_func func, int has_xfrmhdr) | Skip | 静态读取状态机，被 socket/buffer 读取包装器归属，无独立跨文件入口。 |
| smb2_readv_from_socket | function | static ssize_t smb2_readv_from_socket(struct smb2_context *smb2, const struct iovec *iov, int iovcnt) | Skip | 静态 readv 适配器，无独立行为契约。 |
| smb2_read_from_socket | function | static int smb2_read_from_socket(struct smb2_context *smb2) | Skip | 静态 socket 读取包装器，仅由 `smb2_service_fd` 驱动。 |
| smb2_readv_from_buf | function | static ssize_t smb2_readv_from_buf(struct smb2_context *smb2, const struct iovec *iov, int iovcnt) | Skip | 静态解密缓冲区读取适配器，无独立跨文件入口。 |
| smb2_read_from_buf | function | int smb2_read_from_buf(struct smb2_context *smb2); | Include | 私有跨文件解密缓冲区读取入口，复用接收状态机处理已解密载荷。 |
| smb2_close_connecting_fd | function | static void smb2_close_connecting_fd(struct smb2_context *smb2, t_socket fd) | Include | 静态连接失败清理 helper，直接影响 Happy Eyeballs 重试路径中的 fd 数组状态。 |
| smb2_service_fd | function | int smb2_service_fd(struct smb2_context *smb2, t_socket fd, int revents); | Include | 公开事件处理入口，处理连接完成、错误、读取、写入和 timeout。 |
| smb2_service | function | int smb2_service(struct smb2_context *smb2, int revents); | Include | 公开便利事件处理入口，将事件转发到当前连接或首个连接中 fd。 |
| set_nonblocking | function | static void set_nonblocking(t_socket fd) | Skip | 平台适配内部 helper，仅设置 fd 非阻塞，无独立 API。 |
| set_tcp_sockopt | function | static int set_tcp_sockopt(t_socket sockfd, int optname, int value) | Skip | 内部 TCP setsockopt helper，调用方不可见。 |
| connect_async_ai | function | static int connect_async_ai(struct smb2_context *smb2, const struct addrinfo *ai, int *fd_out) | Skip | 静态单地址连接 helper，行为归属 `smb2_connect_async`。 |
| smb2_connect_async_next_addr | function | static int smb2_connect_async_next_addr(struct smb2_context *smb2, const struct addrinfo *base) | Skip | 静态 Happy Eyeballs 连接推进 helper，行为归属连接和 service API。 |
| interleave_addrinfo | function | static void interleave_addrinfo(struct addrinfo *base) | Skip | 静态地址链表重排 helper，服务 IPv4/IPv6 交错连接策略。 |
| smb2_connect_async | function | int smb2_connect_async(struct smb2_context *smb2, const char *server, smb2_command_cb cb, void *cb_data); | Include | 公开异步 TCP 连接入口，解析 host/port、分配连接 fd 数组并注册回调。 |
| smb2_bind_and_listen | function | int smb2_bind_and_listen(const uint16_t port, const int max_connections, int *out_fd); | Include | 公开服务端监听 socket 创建入口，返回非阻塞监听 fd。 |
| smb2_accept_connection_async | function | int smb2_accept_connection_async(const int fd, const int to_msec, smb2_accepted_cb cb, void *cb_data); | Include | 公开服务端 accept 入口，轮询监听 fd 并通过回调交付非阻塞 client fd。 |
| smb2_change_events | function | void smb2_change_events(struct smb2_context *smb2, t_socket fd, int events); | Include | 私有跨文件事件变更通知入口，避免重复通知并更新缓存事件。 |

## Data Model Summary

| Type/Macro | Kind | Definition | Notes |
| --- | --- | --- | --- |
| MAX_URL_SIZE | macro | lib/socket.c:114 | 定义但本文件未使用，可能是遗留 URL 缓冲区限制。 |
| HAPPY_EYEBALLS_TIMEOUT | macro | lib/socket.c:120 | 连接阶段多地址轮询 timeout 固定为 100ms。 |
| struct linger | struct | lib/socket.c:122 | 当平台未提供 `HAVE_LINGER` 时提供本地兼容定义。 |
| read_func | typedef | lib/socket.c:337 | 接收状态机读取适配器签名。 |

## ADDED Requirements

### Requirement: smb2_close_connecting_fds close pending connection resources
系统 MUST 关闭所有仍在连接中的有效 fd，但 MUST NOT 关闭已经成为 `smb2->fd` 的已连接 fd，并 MUST 释放 `connecting_fds` 与 `addrinfos` 后清空相关计数和指针。

#### Scenario: close pending fds and resolver state
- **GIVEN** `smb2->connecting_fds` 包含一个或多个连接中 fd，且其中可能包含当前已连接 `smb2->fd`
- **WHEN** 调用 `smb2_close_connecting_fds(smb2)`
- **THEN** 函数关闭非当前连接 fd，按需通过 `change_fd` 发送 `SMB2_DEL_FD`，释放连接 fd 数组和 addrinfo，并将 `connecting_fds`、`addrinfos`、`next_addrinfo` 清为 `NULL` 且计数清零

Trace: `lib/socket.c:smb2_close_connecting_fds`

### Requirement: smb2_which_events expose required poll events
系统 MUST 在已有有效 socket 时返回以 `POLLIN` 为基础的事件掩码，在尚未连接时返回以 `POLLOUT` 为基础的事件掩码，并 MUST 只在 outqueue 存在且信用足够发送队首 compound PDU 时加入 `POLLOUT`。

#### Scenario: report socket readiness mask
- **GIVEN** 调用方在事件循环中持有 `struct smb2_context`
- **WHEN** 调用 `smb2_which_events(smb2)` 查询应等待事件
- **THEN** 返回值反映当前连接状态和发送信用状态，使调用方可将该掩码传给 poll/select 集成层

Trace: `lib/socket.c:smb2_which_events`, `include/smb2/libsmb2.h:smb2_which_events`, `tests/prog_cat.c`, `tests/prog_cat_cancel.c`, `tests/metastat-0202-censored.c`

### Requirement: smb2_get_fd expose active or first connecting fd
系统 MUST 在 `smb2->fd` 有效时返回该 fd；否则当存在连接中 fd 时 MUST 返回 `connecting_fds[0]`；否则 MUST 返回 `-1`。

#### Scenario: select fd for simple event loop
- **GIVEN** 调用方使用简单 poll/select 事件循环集成 libsmb2
- **WHEN** 调用 `smb2_get_fd(smb2)`
- **THEN** 调用方获得当前应轮询的已连接 fd、首个连接中 fd 或无 fd 标记 `-1`

Trace: `lib/socket.c:smb2_get_fd`, `include/smb2/libsmb2.h:smb2_get_fd`, `tests/prog_cat.c`, `tests/prog_cat_cancel.c`, `tests/metastat-0202-censored.c`

### Requirement: smb2_get_fds expose all active connection candidates
系统 MUST 在已连接时设置 `*fd_count` 为 1、`*timeout` 为 -1 并返回 `&smb2->fd`；在连接阶段 MUST 返回 `connecting_fds`、设置连接 fd 数量，并在仍有 `next_addrinfo` 时设置 100ms timeout，否则设置 -1。

#### Scenario: retrieve Happy Eyeballs fd set
- **GIVEN** 异步连接可能已经启动多个候选 fd
- **WHEN** 调用 `smb2_get_fds(smb2, fd_count, timeout)`
- **THEN** 调用方获得需要轮询的 fd 数组、fd 数量和是否需要用 `fd = -1` 触发下一地址连接的 timeout

Trace: `lib/socket.c:smb2_get_fds`, `include/smb2/libsmb2.h:smb2_get_fds`

### Requirement: smb2_write_to_socket write queued PDUs with credit accounting
系统 MUST 仅在 socket 有效且 credit 足以发送队首 compound PDU 时向 socket 写入 SPL 和 PDU iov；遇到 EAGAIN/EWOULDBLOCK MUST 返回 0；遇到其他 writev 错误 MUST 设置错误并返回 -1；完整发送后 MUST 从 outqueue 移除 PDU、更新事件并按 client/server 模式移动到 waitqueue 或释放回复 PDU。

#### Scenario: send complete queued PDU
- **GIVEN** `smb2->outqueue` 包含可发送 PDU，socket 有效且 credit 足够
- **WHEN** 调用 `smb2_write_to_socket(smb2)` 且 writev 完成 SPL 与 payload 写入
- **THEN** 函数更新 `num_done`，移除已发送 PDU，client 模式扣减 credit 并加入 waitqueue，server 模式重置 credit 并释放回复 PDU

Trace: `lib/socket.c:smb2_write_to_socket`, `include/libsmb2-private.h:smb2_write_to_socket`

### Requirement: smb2_read_from_buf process decrypted receive buffers
系统 MUST 使用已解密缓冲区作为读取源调用共享接收状态机，并 MUST 按 transform-header 已存在的路径处理 payload。

#### Scenario: process encrypted payload after decrypt
- **GIVEN** `smb2->enc`、`enc_len` 和 `enc_pos` 描述已解密载荷缓冲区
- **WHEN** 调用 `smb2_read_from_buf(smb2)`
- **THEN** 函数通过 buffer read adapter 推进接收状态机，并返回状态机产生的成功、EAGAIN 或错误结果

Trace: `lib/socket.c:smb2_read_from_buf`, `include/libsmb2-private.h:smb2_read_from_buf`

### Requirement: smb2_close_connecting_fd close one pending connection fd
系统 MUST 关闭指定连接中 fd，并在该 fd 存在于 `connecting_fds` 数组时 MUST 从数组中移除它且减少 `connecting_fds_count`。

#### Scenario: remove failed connecting fd
- **GIVEN** `connecting_fds` 数组包含一个连接失败的 fd
- **WHEN** 调用 `smb2_close_connecting_fd(smb2, fd)`
- **THEN** 函数关闭该 fd，将后续数组元素前移，并减少连接中 fd 计数

Trace: `lib/socket.c:smb2_close_connecting_fd`

### Requirement: smb2_service_fd process fd events and connection progress
系统 MUST 对指定 fd 的 `POLLERR`、`POLLHUP`、连接完成 `POLLOUT`、读 `POLLIN` 和写 `POLLOUT` 事件执行对应处理；当 `fd` 为无效值且存在 `next_addrinfo` 时 MUST 尝试启动下一地址连接；返回前 SHOULD 在启用 timeout 时调用 `smb2_timeout_pdus`。

#### Scenario: complete async connection
- **GIVEN** 异步连接中的 fd 收到 `POLLOUT` 且 `getsockopt(SO_ERROR)` 返回成功
- **WHEN** 调用 `smb2_service_fd(smb2, fd, POLLOUT)`
- **THEN** 函数将 fd 设为 `smb2->fd`，关闭其他连接中 fd，更新事件并以 status 0 调用连接回调

Trace: `lib/socket.c:smb2_service_fd`, `include/smb2/libsmb2.h:smb2_service_fd`

#### Scenario: handle read and write readiness
- **GIVEN** fd 已连接且 revents 包含 `POLLIN` 或可发送 outqueue 的 `POLLOUT`
- **WHEN** 调用 `smb2_service_fd(smb2, fd, revents)`
- **THEN** 函数按事件调用 socket 读取或写入路径，任一路径失败时返回 -1，成功处理后返回 0

Trace: `lib/socket.c:smb2_service_fd`, `include/smb2/libsmb2.h:smb2_service_fd`

### Requirement: smb2_service dispatch current context fd events
系统 MUST 在存在连接中 fd 时把 revents 转发给 `connecting_fds[0]`，否则 MUST 转发给 `smb2->fd`，并返回 `smb2_service_fd` 的结果。

#### Scenario: service simple event loop result
- **GIVEN** 调用方使用 `smb2_get_fd` 和 `smb2_which_events` 完成一次 poll/select
- **WHEN** 调用 `smb2_service(smb2, revents)`
- **THEN** 函数选择当前连接阶段 fd 或已连接 fd 进行事件处理，并向调用方返回 0 或不可恢复错误码

Trace: `lib/socket.c:smb2_service`, `include/smb2/libsmb2.h:smb2_service`, `tests/prog_cat.c`, `tests/prog_cat_cancel.c`, `tests/metastat-0202-censored.c`

### Requirement: smb2_connect_async initiate asynchronous TCP connection
系统 MUST 拒绝已连接 context；MUST 解析 `server` 中的 host、可选 `:port` 和 `[IPv6]:port` 格式，默认端口为 445；MUST 将 resolver 错误映射为负 errno 风格返回值；解析成功时 MUST 分配连接 fd 数组、交错地址族、启动第一个非阻塞连接并仅在启动成功时保存回调和私有数据。

#### Scenario: start async connection
- **GIVEN** context 尚未连接且 `server` 可解析为一个或多个地址
- **WHEN** 调用 `smb2_connect_async(smb2, server, cb, cb_data)`
- **THEN** 函数创建非阻塞 socket 连接候选，保存连接回调数据，并返回 0 表示连接流程已启动

Trace: `lib/socket.c:smb2_connect_async`, `include/smb2/libsmb2.h:smb2_connect_async`

#### Scenario: reject malformed IPv6 literal
- **GIVEN** `server` 以 `[` 开始但缺少匹配的 `]`
- **WHEN** 调用 `smb2_connect_async(smb2, server, cb, cb_data)`
- **THEN** 函数释放临时地址副本，设置错误消息并返回 `-EINVAL`，且不保存连接回调

Trace: `lib/socket.c:smb2_connect_async`, `include/smb2/libsmb2.h:smb2_connect_async`

### Requirement: smb2_bind_and_listen create nonblocking server listener
系统 MUST 创建 IPv4 TCP socket，设置非阻塞和 TCP_NODELAY，将其绑定到 `INADDR_ANY:port` 并调用 `listen(max_connections)`；成功时 MUST 写入 `*out_fd` 并返回 0，失败时 MUST 关闭已创建 fd 并返回 `-EIO`。

#### Scenario: create listen fd
- **GIVEN** 调用方提供端口、backlog 和 `out_fd` 指针
- **WHEN** 调用 `smb2_bind_and_listen(port, max_connections, out_fd)` 且 socket/bind/listen 均成功
- **THEN** 函数返回 0，并通过 `out_fd` 交付非阻塞监听 socket

Trace: `lib/socket.c:smb2_bind_and_listen`, `include/smb2/libsmb2.h:smb2_bind_and_listen`

### Requirement: smb2_accept_connection_async accept one client when ready
系统 MUST 拒绝无效监听 fd 并返回 `-EINVAL`；否则 MUST 使用 `poll` 等待 `POLLIN`，在有连接时 accept 一个 client fd、设置非阻塞和 TCP_NODELAY，并通过回调交付该 fd；accept 失败 MUST 返回 `-EIO`。

#### Scenario: accept ready client
- **GIVEN** 有效监听 fd 在 timeout 内变为可读
- **WHEN** 调用 `smb2_accept_connection_async(fd, to_msec, cb, cb_data)`
- **THEN** 函数 accept 一个 client fd，设置 socket 选项，并返回 `cb(clientfd, cb_data)` 的结果

Trace: `lib/socket.c:smb2_accept_connection_async`, `include/smb2/libsmb2.h:smb2_accept_connection_async`

### Requirement: smb2_change_events notify only changed event masks
系统 MUST 在请求事件掩码等于 `smb2->events` 时直接返回；当注册了 `change_events` 且事件掩码变化时 MUST 调用回调并更新 `smb2->events`。

#### Scenario: update external event subscription
- **GIVEN** context 注册了事件变更回调且新事件掩码不同于缓存值
- **WHEN** 调用 `smb2_change_events(smb2, fd, events)`
- **THEN** 函数通知调用方更新 fd 订阅，并把新掩码缓存到 `smb2->events`

Trace: `lib/socket.c:smb2_change_events`, `include/libsmb2-private.h:smb2_change_events`

## Open Questions

| ID | Question | Related Interface | Reason |
| --- | --- | --- | --- |
| Q-001 | `smb2_service_fd`、`smb2_bind_and_listen` 和 `smb2_read_from_buf` 的实现符号未被 GitNexus `context --file lib/socket.c` 精确定位，是否需要重建索引以补齐调用关系？ | smb2_service_fd`, `smb2_bind_and_listen`, `smb2_read_from_buf | GitNexus 对部分实现符号返回 not found，但源码和头文件存在定义/声明。 |
| Q-002 | `smb2_write_to_socket` 构造 compound iov 时是否由上游保证 `SMB2_MAX_VECTORS` 容量足够？ | smb2_write_to_socket | 本文件未看到 niov 上限检查，依赖 PDU 构造阶段约束。 |
| Q-003 | `smb2_bind_and_listen` 在入口处无条件写 `*out_fd = -1`，调用方是否必须保证 `out_fd` 非 NULL？ | smb2_bind_and_listen | 源码未做空指针检查，公开声明也未记录前置条件。 |
| Q-004 | `smb2_connect_async` 对 `server == NULL` 的行为是否属于未定义前置条件？ | smb2_connect_async | 源码直接 `strdup(server)` 并访问 `host[0]`，声明未记录空指针约束。 |
