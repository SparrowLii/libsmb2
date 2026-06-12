# lib/ps2/ps2smb2.h Specification

## Source Context

- Source: `lib/ps2/ps2smb2.h`
- Related Headers: `lib/ps2/smb2_fio.c` includes this header for PS2 filesystem devctl command and payload definitions.
- Related Tests: `none`
- Related Dependencies: GitNexus context found header-local macro/type definitions only; source review shows `SMB2_devctl` in `lib/ps2/smb2_fio.c` dispatches `SMB2_DEVCTL_CONNECT` to `smb2_Connect` using `smb2Connect_in_t` and `smb2Connect_out_t`.
- Build/Compile Context: PS2 platform header used by `lib/ps2/smb2_fio.c`; project context records platform switches including `IOP`, `BUILD_IRX`, `EE`, `PS2RPC`, `__ps2sdk_iop__`, and `PS2RPC`.

## Interface Summary

| Interface | Kind | Signature | Decision | Reason |
| --- | --- | --- | --- | --- |
| SMB2_PATH_MAX | macro | `#define SMB2_PATH_MAX 1024` | Include | 公开路径长度上限宏，对 PS2 调用方可见。 |
| SMB2_DEVCTL_CONNECT | macro | `#define SMB2_DEVCTL_CONNECT		0xC0DE0001` | Include | 公开 devctl 连接命令号，被 `SMB2_devctl` 分派使用。 |
| SMB2_DEVCTL_DISCONNECT_ALL | macro | `#define SMB2_DEVCTL_DISCONNECT_ALL	0xC0DE0002` | Include | 公开 devctl 断开命令号，对调用方可见但当前源码未确认分派实现。 |
| SMB2_MAX_NAME_LEN | macro | `#define SMB2_MAX_NAME_LEN 32` | Include | 公开连接名称字段长度，并用于 `smb2Connect_in_t.name` 数组布局。 |
| smb2Connect_in_t | type | `typedef struct { char name[SMB2_MAX_NAME_LEN]; char username[32]; char password[32]; char url[256]; } smb2Connect_in_t;` | Include | 公开连接 devctl 输入载荷布局，被 `smb2_Connect` 读取。 |
| smb2Connect_out_t | type | `typedef struct { void *ctx; } smb2Connect_out_t;` | Include | 公开连接 devctl 输出载荷布局，被 `smb2_Connect` 写入连接上下文。 |
| smb2Disconnect_in_t | type | `typedef struct { void *ctx; } smb2Disconnect_in_t;` | Include | 公开断开 devctl 输入载荷布局，对调用方可见但当前源码未确认分派实现。 |

## Data Model Summary

| Type/Macro | Kind | Definition | Notes |
| --- | --- | --- | --- |
| SMB2_PATH_MAX | macro | `lib/ps2/ps2smb2.h:9` | PS2 SMB2 路径最大长度常量为 1024。 |
| SMB2_DEVCTL_CONNECT | macro | `lib/ps2/ps2smb2.h:13` | PS2 devctl 连接命令号为 `0xC0DE0001`。 |
| SMB2_DEVCTL_DISCONNECT_ALL | macro | `lib/ps2/ps2smb2.h:14` | PS2 devctl 断开全部连接命令号为 `0xC0DE0002`。 |
| SMB2_MAX_NAME_LEN | macro | `lib/ps2/ps2smb2.h:19` | 连接名称数组长度为 32 字节。 |
| smb2Connect_in_t | typedef | `lib/ps2/ps2smb2.h:20` | 连接输入载荷包含 `name[SMB2_MAX_NAME_LEN]`、`username[32]`、`password[32]` 和 `url[256]`。 |
| smb2Connect_out_t | typedef | `lib/ps2/ps2smb2.h:27` | 连接输出载荷包含不透明 `ctx` 指针。 |
| smb2Disconnect_in_t | typedef | `lib/ps2/ps2smb2.h:31` | 断开输入载荷包含不透明 `ctx` 指针。 |

## ADDED Requirements

### Requirement: SMB2_PATH_MAX expose PS2 path limit
系统 MUST 将 `SMB2_PATH_MAX` 暴露为值为 `1024` 的编译期宏，供 PS2 SMB2 调用方按相同路径长度上限分配或校验缓冲区。

#### Scenario: path limit macro value
- **GIVEN** 调用方包含 `lib/ps2/ps2smb2.h`
- **WHEN** 调用方读取 `SMB2_PATH_MAX`
- **THEN** 宏值为 `1024`

Trace: `lib/ps2/ps2smb2.h:SMB2_PATH_MAX`

### Requirement: SMB2_DEVCTL_CONNECT expose connect command
系统 MUST 将 `SMB2_DEVCTL_CONNECT` 暴露为值为 `0xC0DE0001` 的 devctl 命令号，并由 PS2 devctl 分派层用于触发 SMB2 连接流程。

#### Scenario: connect command dispatch contract
- **GIVEN** 调用方包含 `lib/ps2/ps2smb2.h` 并向 PS2 devctl 传入命令号
- **WHEN** 命令号等于 `SMB2_DEVCTL_CONNECT`
- **THEN** 命令号值为 `0xC0DE0001`，`SMB2_devctl` 将输入载荷解释为 `smb2Connect_in_t *`，将输出载荷解释为 `smb2Connect_out_t *`

Trace: `lib/ps2/ps2smb2.h:SMB2_DEVCTL_CONNECT`, `lib/ps2/smb2_fio.c:SMB2_devctl`

### Requirement: SMB2_DEVCTL_DISCONNECT_ALL expose disconnect command
系统 MUST 将 `SMB2_DEVCTL_DISCONNECT_ALL` 暴露为值为 `0xC0DE0002` 的 devctl 命令号，使调用方能够以稳定常量表示断开全部连接请求。

#### Scenario: disconnect command macro value
- **GIVEN** 调用方包含 `lib/ps2/ps2smb2.h`
- **WHEN** 调用方读取 `SMB2_DEVCTL_DISCONNECT_ALL`
- **THEN** 宏值为 `0xC0DE0002`

Trace: `lib/ps2/ps2smb2.h:SMB2_DEVCTL_DISCONNECT_ALL`

### Requirement: SMB2_MAX_NAME_LEN define share name field width
系统 MUST 将 `SMB2_MAX_NAME_LEN` 暴露为值为 `32` 的编译期宏，并使 `smb2Connect_in_t.name` 使用该宏定义的数组宽度。

#### Scenario: connect name field width
- **GIVEN** 调用方包含 `lib/ps2/ps2smb2.h`
- **WHEN** 调用方构造 `smb2Connect_in_t` 输入载荷
- **THEN** `name` 字段的数组宽度由 `SMB2_MAX_NAME_LEN` 定义，且宏值为 `32`

Trace: `lib/ps2/ps2smb2.h:SMB2_MAX_NAME_LEN`, `lib/ps2/ps2smb2.h:smb2Connect_in_t`

### Requirement: smb2Connect_in_t preserve connect input layout
系统 MUST 将 `smb2Connect_in_t` 定义为连接 devctl 输入载荷，并保持字段顺序和数组宽度为 `name[SMB2_MAX_NAME_LEN]`、`username[32]`、`password[32]`、`url[256]`。

#### Scenario: connect input payload consumed by devctl
- **GIVEN** 调用方为 `SMB2_DEVCTL_CONNECT` 准备 `smb2Connect_in_t` 输入载荷
- **WHEN** `SMB2_devctl` 分派连接命令
- **THEN** PS2 SMB2 连接流程按该布局读取共享名称、用户名、密码和 URL 字段

Trace: `lib/ps2/ps2smb2.h:smb2Connect_in_t`, `lib/ps2/smb2_fio.c:smb2_Connect`

### Requirement: smb2Connect_out_t preserve connect output layout
系统 MUST 将 `smb2Connect_out_t` 定义为连接 devctl 输出载荷，并保持单一 `void *ctx` 字段用于返回 SMB2 上下文指针或空指针。

#### Scenario: connect output context field
- **GIVEN** 调用方为 `SMB2_DEVCTL_CONNECT` 提供 `smb2Connect_out_t` 输出载荷
- **WHEN** 连接流程开始或完成
- **THEN** 输出载荷的 `ctx` 字段由实现初始化为空指针，并在连接成功时设置为 SMB2 上下文指针

Trace: `lib/ps2/ps2smb2.h:smb2Connect_out_t`, `lib/ps2/smb2_fio.c:smb2_Connect`

### Requirement: smb2Disconnect_in_t preserve disconnect input layout
系统 MUST 将 `smb2Disconnect_in_t` 定义为断开 devctl 输入载荷，并保持单一 `void *ctx` 字段用于携带调用方要断开的上下文指针。

#### Scenario: disconnect input context field
- **GIVEN** 调用方包含 `lib/ps2/ps2smb2.h`
- **WHEN** 调用方构造 `smb2Disconnect_in_t` 输入载荷
- **THEN** 载荷包含单一 `void *ctx` 字段以携带不透明上下文指针

Trace: `lib/ps2/ps2smb2.h:smb2Disconnect_in_t`

## Open Questions

| ID | Question | Related Interface | Reason |
| --- | --- | --- | --- |
| Q-001 | 当前源码是否存在 `SMB2_DEVCTL_DISCONNECT_ALL` 的实际 devctl 分派实现？ | SMB2_DEVCTL_DISCONNECT_ALL, smb2Disconnect_in_t | `lib/ps2/ps2smb2.h` 声明命令号和输入载荷，但已回读的 `SMB2_devctl` switch 仅确认 `SMB2_DEVCTL_CONNECT` 分支。 |
