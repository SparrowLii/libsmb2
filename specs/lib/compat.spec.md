# lib/compat.c Specification

## Source Context

- Source: `lib/compat.c`
- Related Headers: `lib/compat.h`
- Related Tests: `none`
- Related Dependencies: GitNexus `context` located implementation symbols for `smb2_getaddrinfo`, `smb2_freeaddrinfo`, `writev`, `readv`, `poll`, `random`, `srandom`, `getlogin_r`, `getpid`, and `be64toh`; `random`, `srandom`, `getlogin_r`, and `getpid` are called from `lib/init.c`, and `be64toh` is called from `lib/dcerpc.c:dcerpc_get_uint64`. GitNexus impact for `smb2_getaddrinfo` and `writev` was ambiguous between `lib/compat.c` and `lib/compat.h` declarations.
- Build/Compile Context: C compatibility implementation selected by platform and feature macros including `_WINDOWS`, `_XBOX`, `XBOX_PLATFORM`, `__DREAMCAST__`, `ESP_PLATFORM`, `__amigaos4__`, `__AMIGA__`, `__AROS__`, `PICO_PLATFORM`, `__PS2__`, `_EE`, `_IOP`, `__ANDROID__`, `PS3_PPU_PLATFORM`, `__vita__`, `__SWITCH__`, `__3DS__`, `__wii__`, `__gamecube__`, `__WIIU__`, `__NDS__`, `NEED_GETADDRINFO`, `NEED_FREEADDRINFO`, `NEED_RANDOM`, `NEED_SRANDOM`, `NEED_GETPID`, `NEED_GETLOGIN_R`, `NEED_WRITEV`, `NEED_READV`, `NEED_POLL`, `NEED_STRDUP`, and `NEED_BE64TOH`.

## Interface Summary

| Interface | Kind | Signature | Decision | Reason |
| --- | --- | --- | --- | --- |
| gethostname | function | int gethostname(char *name, size_t len) | Include | Xbox 和 PS2 平台缺少或需要固定 hostname 时由实现写入平台标识。 |
| time | function | time_t time(time_t *tloc) | Include | PS2 IOP 平台通过系统时钟提供缺失的 time 兼容入口。 |
| asprintf | function | int asprintf(char **strp, const char *fmt, ...) | Include | PS2 IOP 平台提供缺失的格式化分配字符串入口。 |
| errno | variable | int errno; | Include | PS2 IOP 平台显式提供全局 errno 存储供兼容函数写入。 |
| iop_connect | function | int iop_connect(int sockfd, struct sockaddr *addr, socklen_t addrlen) | Include | PS2 IOP 平台包装 lwIP connect 并同步 socket 错误到 errno。 |
| smb2_getaddrinfo | function | int smb2_getaddrinfo(const char *node, const char*service, const struct addrinfo *hints, struct addrinfo **res) | Include | 缺少 getaddrinfo 的平台由实现分配 IPv4-only addrinfo 结果。 |
| smb2_freeaddrinfo | function | void smb2_freeaddrinfo(struct addrinfo *res) | Include | 与兼容 resolver 配套释放 `ai_addr` 和 `addrinfo`。 |
| random | function | long random(void)` / `int random(void) | Include | 缺少 random 的平台返回 ESP、C library 或 PS2 IOP 本地伪随机值。 |
| srandom | function | void srandom(unsigned int seed) | Include | 缺少 srandom 的平台初始化底层或 PS2 IOP 本地伪随机状态。 |
| getpid | function | int getpid() | Include | 缺少 getpid 的平台返回平台配置的兼容进程标识。 |
| getlogin_r | function | int getlogin_r(char *buf, size_t size) | Include | 缺少 getlogin_r 的平台返回平台配置的登录查询状态码。 |
| writev | function | ssize_t writev(t_socket fd, const struct iovec* vector, int count) | Include | 缺少 writev 的平台聚合 iovec 后执行底层 write。 |
| readv | function | ssize_t readv(t_socket fd, const struct iovec* vector, int count) | Include | 缺少 readv 的平台执行单次底层 read 后分散到 iovec。 |
| poll | function | int poll(struct pollfd *fds, unsigned int nfds, int timo) | Include | 缺少 poll 的平台基于 select 实现 readiness 等待和 revents 填充。 |
| strdup | function | char *strdup(const char *s) | Include | 缺少 strdup 的平台分配并复制 NUL 结尾字符串。 |
| be64toh | function | long long int be64toh(long long int x) | Include | 缺少 be64toh 的平台组合两个 32 位网络序转换结果。 |
| login_num | macro | #define login_num ENXIO` / `#define login_num 0` / `#define login_num 1 | Skip | 平台内部返回码宏，行为由 `getlogin_r` Requirement 覆盖。 |
| getpid_num | macro | #define getpid_num() GetCurrentProcessId()` / `#define getpid_num() 0` / `#define getpid_num() 27 | Skip | 平台内部进程标识宏，行为由 `getpid` Requirement 覆盖。 |
| smb2_random | macro | #define smb2_random rand` / `#define smb2_random esp_random | Skip | 平台内部随机源别名，行为由 `random` Requirement 覆盖。 |
| smb2_srandom | macro | #define smb2_srandom srand` / `#define smb2_srandom(seed) | Skip | 平台内部随机种子别名，行为由 `srandom` Requirement 覆盖。 |

## Data Model Summary

| Type/Macro | Kind | Definition | Notes |
| --- | --- | --- | --- |
| errno | variable | lib/compat.c:159 | PS2 IOP 分支提供全局错误码存储。 |
| next | static variable | lib/compat.c:133 | PS2 IOP `random`/`srandom` 使用的线性同余状态。 |
| login_num | macro | lib/compat.c:26`, `lib/compat.c:29`, `lib/compat.c:53`, `lib/compat.c:65`, `lib/compat.c:87`, `lib/compat.c:101`, `lib/compat.c:121`, `lib/compat.c:186`, `lib/compat.c:197`, `lib/compat.c:209`, `lib/compat.c:240 | 平台选择的 `getlogin_r` 返回码。 |
| getpid_num | macro | lib/compat.c:27`, `lib/compat.c:30`, `lib/compat.c:131 | 平台选择的 `getpid` 返回值来源。 |
| smb2_random | macro | lib/compat.c:32`, `lib/compat.c:66`, `lib/compat.c:198 | 非 PS2 IOP 随机数兼容实现的底层随机源。 |
| smb2_srandom | macro | lib/compat.c:33`, `lib/compat.c:67`, `lib/compat.c:199 | 非 PS2 IOP 随机数种子兼容实现的底层种子入口。 |

## ADDED Requirements

### Requirement: gethostname returns fixed console host names
系统 MUST 在 Xbox 和 PS2 兼容分支中提供 `gethostname(char *name, size_t len)`，并 SHALL 将目标平台固定名称复制到调用方缓冲区后返回 `0`。

#### Scenario: Xbox hostname compatibility
- **GIVEN** 编译目标定义 `_XBOX` 且调用方提供 `name` 缓冲区和 `len`
- **WHEN** 调用 `gethostname(name, len)`
- **THEN** 实现 MUST 复制 `XBOX` 或 `XBOX_360` 平台字符串并返回 `0`

Trace: `lib/compat.c:36`

#### Scenario: PS2 hostname compatibility
- **GIVEN** 编译目标定义 `__PS2__` 且调用方提供 `name` 缓冲区和 `len`
- **WHEN** 调用 `gethostname(name, len)`
- **THEN** 实现 MUST 复制 `PS2` 平台字符串并返回 `0`

Trace: `lib/compat.c:123`

### Requirement: time returns PS2 IOP system seconds
系统 MUST 在 PS2 IOP 分支中提供 `time(time_t *tloc)`，并 SHALL 从 IOP 系统时钟换算结果返回秒字段。

#### Scenario: PS2 IOP reads system time
- **GIVEN** 编译目标定义 `__PS2__` 和 `_IOP`
- **WHEN** 调用 `time(tloc)`
- **THEN** 实现 MUST 调用 `GetSystemTime` 和 `SysClock2USec`，并返回换算得到的 `sec` 值

Trace: `lib/compat.c:134`

### Requirement: asprintf allocates a fixed PS2 IOP formatting buffer
系统 MUST 在 PS2 IOP 分支中提供 `asprintf(char **strp, const char *fmt, ...)`，并 SHALL 分配 256 字节缓冲区、格式化内容、写回 `*strp` 并返回格式化长度。

#### Scenario: PS2 IOP formats allocated string
- **GIVEN** 编译目标定义 `__PS2__` 和 `_IOP`，且调用方提供 `strp` 与格式字符串
- **WHEN** 调用 `asprintf(strp, fmt, ...)`
- **THEN** 实现 MUST 分配缓冲区，调用格式化函数写入内容，将缓冲区指针赋给 `*strp`，并返回格式化长度

Trace: `lib/compat.c:145`

### Requirement: errno provides PS2 IOP error storage
系统 MUST 在 PS2 IOP 分支中定义全局 `errno`，使兼容 socket 和分配路径可记录平台错误码。

#### Scenario: PS2 IOP connect writes errno
- **GIVEN** 编译目标定义 `__PS2__` 和 `_IOP`，且 `iop_connect` 检测到底层 socket 错误
- **WHEN** 兼容实现赋值 `errno`
- **THEN** 全局 `errno` MUST 可作为该分支的错误码存储

Trace: `lib/compat.c:159`, `lib/compat.c:170`

### Requirement: iop_connect propagates lwIP socket errors
系统 MUST 在 PS2 IOP 分支中提供 `iop_connect`，并 SHALL 返回 `lwip_connect` 的返回值，同时在连接失败且 `SO_ERROR` 可用时写入 `errno`。

#### Scenario: lwIP connect failure reports socket error
- **GIVEN** 编译目标定义 `_IOP`，且 `lwip_connect(sockfd, addr, addrlen)` 返回负值
- **WHEN** `getsockopt(sockfd, SOL_SOCKET, SO_ERROR, ...)` 失败或返回非零 socket 错误
- **THEN** `iop_connect` MUST 将 `errno` 设置为该错误值并返回底层连接结果

Trace: `lib/compat.c:161`

### Requirement: smb2_getaddrinfo returns IPv4 compatibility results
系统 MUST 在 `NEED_GETADDRINFO` 分支中提供 `smb2_getaddrinfo`，并 SHALL 分配 IPv4 `sockaddr_in` 与 `addrinfo` 结果，成功时返回 `0`。

#### Scenario: numeric or inet_addr resolver result
- **GIVEN** 平台定义 `NEED_GETADDRINFO`，调用方传入 `node`、可选 `service` 和 `res` 输出参数
- **WHEN** 调用 `smb2_getaddrinfo(node, service, hints, res)`
- **THEN** 实现 MUST 设置 `ai_family` 为 `AF_INET`，设置 `ai_addrlen` 为 `sizeof(struct sockaddr_in)`，设置 `ai_addr` 指向分配的 IPv4 socket 地址，并在成功路径返回 `0`

Trace: `lib/compat.c:258`

#### Scenario: Amiga resolver host lookup fails
- **GIVEN** Amiga/AROS 分支下 `node` 不是点分 IPv4 字符串，且 `gethostbyname(node)` 返回 NULL
- **WHEN** 调用 `smb2_getaddrinfo(node, service, hints, res)`
- **THEN** 实现 MUST 返回 `-1`

Trace: `lib/compat.c:286`

#### Scenario: Amiga resolver returns unsupported family
- **GIVEN** Amiga/AROS 分支下 `gethostbyname(node)` 返回非 NULL host，且 `host->h_addrtype` 不是 `AF_INET`
- **WHEN** 调用 `smb2_getaddrinfo(node, service, hints, res)`
- **THEN** 实现 MUST 返回 `-2`

Trace: `lib/compat.c:290`

### Requirement: smb2_freeaddrinfo releases resolver allocations
系统 MUST 在 `NEED_FREEADDRINFO` 分支中提供 `smb2_freeaddrinfo`，并 SHALL 释放兼容 resolver 结果中的地址对象和结果对象。

#### Scenario: caller frees compatibility addrinfo
- **GIVEN** 调用方持有由兼容 resolver 返回的 `struct addrinfo *res`
- **WHEN** 调用 `smb2_freeaddrinfo(res)`
- **THEN** 实现 MUST 先释放 `res->ai_addr`，再释放 `res`

Trace: `lib/compat.c:323`

### Requirement: random returns platform random values
系统 MUST 在 `NEED_RANDOM` 分支中提供 `random`，并 SHALL 根据平台返回 ESP、C library 或 PS2 IOP 本地状态派生的随机值。

#### Scenario: PS2 IOP random advances local state
- **GIVEN** 编译目标定义 `_IOP`
- **WHEN** 调用 `random()`
- **THEN** 实现 MUST 更新静态 `next` 状态并返回 `(unsigned int)(next/65536) % 32768`

Trace: `lib/compat.c:331`

#### Scenario: non-IOP random delegates to platform source
- **GIVEN** 平台定义 `NEED_RANDOM` 但未定义 `_IOP`
- **WHEN** 调用 `random()`
- **THEN** 实现 MUST 返回 `smb2_random()` 的结果

Trace: `lib/compat.c:331`

### Requirement: srandom seeds platform random state
系统 MUST 在 `NEED_SRANDOM` 分支中提供 `srandom(unsigned int seed)`，并 SHALL 初始化 PS2 IOP 本地状态或委托平台 seed 函数。

#### Scenario: PS2 IOP seed updates local state
- **GIVEN** 编译目标定义 `_IOP`
- **WHEN** 调用 `srandom(seed)`
- **THEN** 实现 MUST 将静态 `next` 状态设置为 `seed`

Trace: `lib/compat.c:347`

#### Scenario: non-IOP seed delegates to platform
- **GIVEN** 平台定义 `NEED_SRANDOM` 但未定义 `_IOP`
- **WHEN** 调用 `srandom(seed)`
- **THEN** 实现 MUST 调用 `smb2_srandom(seed)`

Trace: `lib/compat.c:347`

### Requirement: getpid returns configured platform identifier
系统 MUST 在 `NEED_GETPID` 分支中提供 `getpid()`，并 SHALL 返回平台宏 `getpid_num()` 的结果。

#### Scenario: caller requests compatibility process id
- **GIVEN** 平台定义 `NEED_GETPID`
- **WHEN** 调用 `getpid()`
- **THEN** 实现 MUST 返回当前平台 `getpid_num()` 展开的值

Trace: `lib/compat.c:357`

### Requirement: getlogin_r returns configured login status
系统 MUST 在 `NEED_GETLOGIN_R` 分支中提供 `getlogin_r(char *buf, size_t size)`，并 SHALL 返回平台宏 `login_num` 的值。

#### Scenario: caller requests login name compatibility
- **GIVEN** 平台定义 `NEED_GETLOGIN_R`
- **WHEN** 调用 `getlogin_r(buf, size)`
- **THEN** 实现 MUST 返回 `login_num`，且源码未显示写入 `buf`

Trace: `lib/compat.c:365`

### Requirement: writev aggregates vector writes
系统 MUST 在 `NEED_WRITEV` 分支中提供 `writev`，并 SHALL 将调用方 iovec 内容按顺序聚合到临时缓冲区后执行一次底层 `write`。

#### Scenario: vector length overflows ssize_t
- **GIVEN** 调用方传入 `count` 个 iovec，且总长度会超过 `ssize_t` 可表示范围
- **WHEN** 调用 `writev(fd, vector, count)`
- **THEN** 实现 MUST 设置 `errno` 为 `EINVAL` 并返回 `-1`

Trace: `lib/compat.c:371`

#### Scenario: vector write succeeds through temporary buffer
- **GIVEN** 调用方传入可聚合的 iovec 数组，且临时缓冲区分配成功
- **WHEN** 调用 `writev(fd, vector, count)`
- **THEN** 实现 MUST 按 iovec 顺序复制所有字节，调用底层 `write((int)fd, buffer, bytes)`，释放临时缓冲区，并返回底层写入结果

Trace: `lib/compat.c:371`

#### Scenario: vector write allocation fails
- **GIVEN** 调用方传入可聚合的 iovec 数组，但临时缓冲区分配返回 NULL
- **WHEN** 调用 `writev(fd, vector, count)`
- **THEN** 实现 MUST 返回 `-1`

Trace: `lib/compat.c:390`

### Requirement: readv distributes a single read into vectors
系统 MUST 在 `NEED_READV` 分支中提供 `readv`，并 SHALL 通过临时缓冲区执行一次底层 `read` 后按 iovec 顺序复制已读字节。

#### Scenario: vector length overflows ssize_t during read
- **GIVEN** 调用方传入 `count` 个 iovec，且总长度会超过 `ssize_t` 可表示范围
- **WHEN** 调用 `readv(fd, vector, count)`
- **THEN** 实现 MUST 设置 `errno` 为 `EINVAL` 并返回 `-1`

Trace: `lib/compat.c:416`

#### Scenario: vector read succeeds through temporary buffer
- **GIVEN** 调用方传入可聚合的 iovec 数组，临时缓冲区分配成功，且底层 `read` 返回非负字节数
- **WHEN** 调用 `readv(fd, vector, count)`
- **THEN** 实现 MUST 将底层读取的字节按 iovec 顺序复制到调用方缓冲区，释放临时缓冲区，并返回底层读取字节数

Trace: `lib/compat.c:416`

#### Scenario: vector read allocation or syscall fails
- **GIVEN** 临时缓冲区分配失败，或底层 `read` 返回负值
- **WHEN** 调用 `readv(fd, vector, count)`
- **THEN** 实现 MUST 返回 `-1`，且底层 `read` 失败路径 SHALL 释放已分配的临时缓冲区

Trace: `lib/compat.c:433`, `lib/compat.c:438`

### Requirement: poll maps requested events through select
系统 MUST 在 `NEED_POLL` 分支中提供 `poll`，并 SHALL 根据请求事件构造 `select` 集合、转换 timeout、执行 `select`，并将就绪状态写入 `revents`。

#### Scenario: poll prepares select sets
- **GIVEN** 调用方传入 `fds` 数组和 `nfds`
- **WHEN** 调用 `poll(fds, nfds, timo)`
- **THEN** 实现 MUST 清零每个 `revents`，将 `POLLIN` 或 `POLLPRI` 映射到 read fd_set，将 `POLLOUT` 映射到 write fd_set，并将异常 fd_set 用于 hangup 检测

Trace: `lib/compat.c:463`

#### Scenario: poll timeout conversion follows platform branch
- **GIVEN** 调用方传入 `timo` 毫秒超时
- **WHEN** 调用 `poll(fds, nfds, timo)`
- **THEN** 实现 MUST 在非 Amiga 分支中将负超时映射为 NULL timeout，并在其他非负路径中填充 `timeval` 秒与微秒字段

Trace: `lib/compat.c:511`, `lib/compat.c:518`

#### Scenario: poll returns readiness events
- **GIVEN** `select(maxfd + 1, ip, op, &efds, toptr)` 返回正值
- **WHEN** 兼容实现检查 fd_set 结果
- **THEN** 实现 MUST 为就绪读写设置 `POLLIN` 或 `POLLOUT`，并在异常集合命中时设置 `POLLHUP`

Trace: `lib/compat.c:528`, `lib/compat.c:533`, `lib/compat.c:552`

### Requirement: strdup duplicates NUL-terminated strings
系统 MUST 在 `NEED_STRDUP` 分支中提供 `strdup`，并 SHALL 分配包含 NUL 终止符的缓冲区、复制输入字符串并返回新指针。

#### Scenario: duplicate allocation succeeds
- **GIVEN** 调用方传入 NUL 结尾字符串 `s`，且分配成功
- **WHEN** 调用 `strdup(s)`
- **THEN** 实现 MUST 分配 `strlen(s) + 1` 字节，复制包含 NUL 终止符的内容，并返回新分配字符串

Trace: `lib/compat.c:570`

#### Scenario: duplicate allocation fails
- **GIVEN** 调用方传入 NUL 结尾字符串 `s`，但分配返回 NULL
- **WHEN** 调用 `strdup(s)`
- **THEN** 实现 MUST 返回 NULL，并在非 `_IOP` 分支中将 `errno` 设置为 `ENOMEM`

Trace: `lib/compat.c:577`

### Requirement: be64toh converts big-endian 64-bit values
系统 MUST 在 `NEED_BE64TOH` 分支中提供 `be64toh(long long int x)`，并 SHALL 使用两个 32 位 `ntohl` 转换组合 host-order 64 位结果。

#### Scenario: caller converts network-order 64-bit integer
- **GIVEN** 调用方传入 big-endian 64 位整数 `x`
- **WHEN** 调用 `be64toh(x)`
- **THEN** 实现 MUST 转换低 32 位和高 32 位并返回组合后的 host-order 值

Trace: `lib/compat.c:590`

## Open Questions

| ID | Question | Related Interface | Reason |
| --- | --- | --- | --- |
| Q-001 | `asprintf` 在 PS2 IOP 分支中使用固定 256 字节分配且未检查 malloc 失败，调用方是否保证格式化结果长度和内存可用性？ | asprintf | `lib/compat.c` 分配固定大小后立即调用 `sprintf` 并写回 `*strp`。 |
| Q-002 | `smb2_getaddrinfo` 的 `hints` 参数在兼容实现中未被读取，调用方是否依赖 socktype、protocol、flags 或 IPv6 约束？ | smb2_getaddrinfo | 实现只分配 IPv4 `sockaddr_in` 并设置 `ai_family`、`ai_addrlen` 和 `ai_addr`。 |
| Q-003 | `smb2_getaddrinfo` 在多条分配路径未检查 NULL，目标平台是否由外层避免内存分配失败？ | smb2_getaddrinfo | `sin` 和 `*res` 分配后立即解引用。 |
| Q-004 | `getlogin_r` 是否允许完全不写入调用方 `buf`？ | getlogin_r | 实现仅返回 `login_num`，未使用 `buf` 或 `size`。 |
| Q-005 | `poll` 的 Amiga 分支在 `timo < 0` 时未显示初始化 `toptr`，是否依赖平台宏或调用约束避免负超时？ | poll | Amiga 分支仅在 `timo >= 0` 时设置 `toptr`。 |
