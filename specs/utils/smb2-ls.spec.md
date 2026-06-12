# utils/smb2-ls.c Specification

## Source Context

- Source: `utils/smb2-ls.c`
- Related Headers: `include/smb2/smb2.h`, `include/smb2/libsmb2.h`, `include/smb2/libsmb2-raw.h`
- Related Tests: `none`
- Related Dependencies: GitNexus context for `Function:utils/smb2-ls.c:main` reports outgoing calls to `lib/init.c:smb2_init_context`, `lib/init.c:smb2_parse_url`, `lib/init.c:smb2_get_error`, `lib/init.c:smb2_set_security_mode`, `lib/init.c:smb2_destroy_url`, `lib/init.c:smb2_destroy_context`, `lib/sync.c:smb2_connect_share`, `lib/sync.c:smb2_disconnect_share`, `lib/sync.c:smb2_opendir`, `lib/sync.c:smb2_readlink`, `lib/libsmb2.c:smb2_readdir`, `lib/libsmb2.c:smb2_closedir`, `lib/compat.c:asprintf`, and local `usage`; GitNexus context for `Function:utils/smb2-ls.c:usage` reports incoming call from local `main`.
- Build/Compile Context: C utility source; defines `_GNU_SOURCE` when absent; includes `<poll.h>` except on Amiga-family platforms; includes `asprintf.h` on `__AROS__`; project C standard is unknown from `specs/PROJECT_CONTEXT.md`.

## Interface Summary

| Interface | Kind | Signature | Decision | Reason |
| --- | --- | --- | --- | --- |
| usage | function | int usage(void) | Include | 命令行参数不足时由 `main` 调用，向标准错误输出固定用法并终止进程，具有调用方可观察行为。 |
| main | function | int main(int argc, char *argv[]) | Include | 作为 `smb2-ls-sync` 工具入口，解析 SMB URL、连接共享、列出目录项、读取符号链接目标并管理连接和上下文资源。 |

## Data Model Summary

| Type/Macro | Kind | Definition | Notes |
| --- | --- | --- | --- |
| _GNU_SOURCE | macro | utils/smb2-ls.c:14 | 若外部未定义，文件本地定义该宏以启用 GNU/POSIX 扩展声明。 |
| SMB2_TYPE_LINK | macro | include/smb2/smb2.h | `main` 将该目录项类型显示为 `LINK`，并对该项调用 `smb2_readlink`。 |
| SMB2_TYPE_FILE | macro | include/smb2/smb2.h | `main` 将该目录项类型显示为 `FILE`。 |
| SMB2_TYPE_DIRECTORY | macro | include/smb2/smb2.h | `main` 将该目录项类型显示为 `DIRECTORY`。 |
| SMB2_NEGOTIATE_SIGNING_ENABLED | macro | include/smb2/smb2.h | `main` 在连接共享前设置 SMB2 signing enabled 安全模式。 |

## ADDED Requirements

### Requirement: usage print command syntax and terminate
系统 MUST 在调用 `usage` 时向标准错误输出 `smb2-ls-sync <smb2-url>` 和 SMB URL 格式说明，并以退出码 1 终止当前进程。

#### Scenario: 参数不足时输出用法
- **GIVEN** 调用方进入 `main` 且 `argc < 2`
- **WHEN** `main` 调用 `usage`
- **THEN** 工具向标准错误输出用法文本并通过 `exit(1)` 终止进程

Trace: `utils/smb2-ls.c:usage`, `utils/smb2-ls.c:main`

### Requirement: main run SMB directory listing utility
系统 MUST 使用第一个命令行参数作为 SMB URL，创建 SMB2 context，解析 URL，启用 `SMB2_NEGOTIATE_SIGNING_ENABLED`，连接目标共享，打开 URL 路径目录，逐项输出目录内容，并在完成或可恢复失败路径上释放已获得的 SMB2 资源。

#### Scenario: 成功列出目录项
- **GIVEN** `argc >= 2` 且 `argv[1]` 可被解析为有效 SMB URL
- **WHEN** context 初始化、URL 解析、共享连接和目录打开均成功，且 `smb2_readdir` 返回目录项
- **THEN** 工具为每个目录项输出名称、类型字符串、大小和由修改时间转换出的本地时间文本

Trace: `utils/smb2-ls.c:main`

#### Scenario: 目录项类型映射
- **GIVEN** `smb2_readdir` 返回的目录项包含 `smb2_type`
- **WHEN** `main` 格式化目录项输出
- **THEN** `SMB2_TYPE_LINK`、`SMB2_TYPE_FILE` 和 `SMB2_TYPE_DIRECTORY` 分别显示为 `LINK`、`FILE` 和 `DIRECTORY`，其他类型显示为 `unknown`

Trace: `utils/smb2-ls.c:main`

#### Scenario: 符号链接目标读取成功
- **GIVEN** 当前目录项类型为 `SMB2_TYPE_LINK` 且链接路径字符串分配成功
- **WHEN** `smb2_readlink` 返回 0
- **THEN** 工具输出链接目标文本并释放分配的链接路径字符串

Trace: `utils/smb2-ls.c:main`

#### Scenario: 符号链接目标读取失败
- **GIVEN** 当前目录项类型为 `SMB2_TYPE_LINK` 且链接路径字符串分配成功
- **WHEN** `smb2_readlink` 返回非 0
- **THEN** 工具输出 `readlink failed` 并释放分配的链接路径字符串

Trace: `utils/smb2-ls.c:main`

#### Scenario: context 初始化失败
- **GIVEN** `argc >= 2`
- **WHEN** `smb2_init_context` 返回 `NULL`
- **THEN** 工具向标准错误输出 `Failed to init context` 并通过 `exit(1)` 终止进程

Trace: `utils/smb2-ls.c:main`

#### Scenario: URL 解析失败
- **GIVEN** SMB2 context 初始化成功
- **WHEN** `smb2_parse_url` 返回 `NULL`
- **THEN** 工具向标准错误输出 `Failed to parse url` 和当前 SMB2 错误字符串，并通过 `exit(1)` 终止进程

Trace: `utils/smb2-ls.c:main`

#### Scenario: 共享连接失败
- **GIVEN** SMB2 context 和 URL 均已创建
- **WHEN** `smb2_connect_share` 返回负值
- **THEN** 工具输出 `smb2_connect_share failed` 和当前 SMB2 错误字符串，销毁 URL 与 context，并返回初始非零状态

Trace: `utils/smb2-ls.c:main`

#### Scenario: 目录打开失败
- **GIVEN** SMB2 context 已连接共享
- **WHEN** `smb2_opendir` 返回 `NULL`
- **THEN** 工具输出 `smb2_opendir failed` 和当前 SMB2 错误字符串，断开共享，销毁 URL 与 context，并返回初始非零状态

Trace: `utils/smb2-ls.c:main`

#### Scenario: 遍历正常结束
- **GIVEN** 目录已成功打开
- **WHEN** `smb2_readdir` 返回 `NULL` 表示遍历结束
- **THEN** 工具设置返回码为 0，调用 `smb2_closedir`、`smb2_disconnect_share`、`smb2_destroy_url` 和 `smb2_destroy_context`

Trace: `utils/smb2-ls.c:main`

## Open Questions

| ID | Question | Related Interface | Reason |
| --- | --- | --- | --- |
| Q-001 | `smb2_parse_url` 失败路径未调用 `smb2_destroy_context` 是否为工具既有资源释放契约，还是遗漏？ | main | 源码直接 `exit(1)`，未进入 `out_context` 清理路径；未发现测试证据确认该行为。 |
| Q-002 | `asprintf` 失败后跳转到 `out_disconnect` 是否需要先释放已打开目录？ | main | 符号链接路径分配失败时未调用 `smb2_closedir`；未发现测试证据确认失败路径资源契约。 |
