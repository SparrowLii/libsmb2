# utils/smb2-cp.c Specification

## Source Context

- Source: `utils/smb2-cp.c`
- Related Headers: `include/smb2/smb2.h`, `include/smb2/libsmb2.h`, `include/smb2/libsmb2-raw.h`
- Related Tests: `none`
- Related Dependencies: GitNexus context shows `main` calls `usage`, `open_file`, `fstat_file`, `file_pread`, `file_pwrite`, and `free_file_context`; `open_file` depends on `smb2_init_context`, `smb2_parse_url`, `smb2_connect_share`, `smb2_open`, and `smb2_get_error`; `free_file_context` depends on `smb2_close`, `smb2_destroy_context`, and `smb2_destroy_url`; `fstat_file`, `file_pread`, and `file_pwrite` bridge local POSIX file APIs to `smb2_fstat`, `smb2_pread`, and `smb2_pwrite`.
- Build/Compile Context: C utility source with `_FILE_OFFSET_BITS 64` and `_GNU_SOURCE`; WIN32 branch initializes Winsock before processing arguments; AROS branch initializes sockets; Amiga-family builds avoid `<poll.h>` and AROS may include `asprintf.h`.

## Interface Summary

| Interface | Kind | Signature | Decision | Reason |
| --- | --- | --- | --- | --- |
| usage | function | void usage(void) | Include | 命令行错误路径直接调用并终止进程，用户可观察输出和退出行为需要记录。 |
| free_file_context | function | static void free_file_context(struct file_context *file_context) | Include | 统一释放本工具本地 fd、SMB2 file handle、context、URL 和堆对象，影响错误路径资源语义。 |
| fstat_file | function | static int fstat_file(struct file_context *fc, struct stat *st) | Include | 本地和 SMB2 source 统计信息统一为 `struct stat`，驱动复制长度和时间字段映射。 |
| file_pread | function | static ssize_t file_pread(struct file_context *fc, uint8_t *buf, size_t count, off_t off) | Include | 复制循环通过该接口统一本地和 SMB2 偏移读语义。 |
| file_pwrite | function | static ssize_t file_pwrite(struct file_context *fc, uint8_t *buf, size_t count, off_t off) | Include | 复制循环通过该接口统一本地和 SMB2 偏移写语义。 |
| open_file | function | static struct file_context *open_file(const char *url, int flags) | Include | 根据路径前缀建立本地或 SMB2 文件上下文，错误路径清理和连接流程可观察。 |
| main | function | int main(int argc, char *argv[]) | Include | 工具程序入口，定义参数校验、打开源/目标、复制循环、错误码和成功输出。 |
| BUFSIZE | macro | #define BUFSIZE 1024*1024 | Include | 公开决定复制循环每次最多读写 1 MiB 的块大小。 |

## Data Model Summary

| Type/Macro | Kind | Definition | Notes |
| --- | --- | --- | --- |
| struct file_context | struct | utils/smb2-cp.c:44 | 保存本地或 SMB2 文件上下文；`is_smb2` 决定调用本地 POSIX API 还是 libsmb2 同步 API。 |
| BUFSIZE | macro | utils/smb2-cp.c:190 | 复制缓冲区大小为 `1024*1024` 字节，静态缓冲区 `buf` 按该值分配。 |

## ADDED Requirements

### Requirement: usage command-line help
系统 MUST 在参数数量错误时向标准错误输出 `smb2-cp <src> <dst>` 用法和本地文件或 SMB2 URL 说明，并以成功状态终止进程。

#### Scenario: 参数数量无效时打印用法
- **GIVEN** 调用方启动 `smb2-cp` 且传入的参数数量不是 2 个路径参数
- **WHEN** `main` 调用 `usage`
- **THEN** 程序向 `stderr` 写入用法和源/目标支持本地文件或 SMB2 URL 的说明，并通过 `exit(0)` 终止

Trace: `utils/smb2-cp.c:usage`, `utils/smb2-cp.c:main`

### Requirement: free_file_context release owned resources
系统 MUST 按上下文中已成功初始化的资源释放本地文件描述符、SMB2 文件句柄、SMB2 context、SMB2 URL 和 `file_context` 堆内存。

#### Scenario: 释放混合文件上下文
- **GIVEN** `file_context` 可能包含本地 `fd`、SMB2 file handle、SMB2 context 或 parsed URL
- **WHEN** 调用 `free_file_context`
- **THEN** 函数对有效本地 fd 调用 `close`，对非空 SMB2 file handle 调用 `smb2_close`，对非空 SMB2 context 调用 `smb2_destroy_context`，并总是销毁 URL 后释放上下文对象

Trace: `utils/smb2-cp.c:free_file_context`

### Requirement: fstat_file normalize source metadata
系统 MUST 对本地文件转发 `fstat` 结果，对 SMB2 文件调用 `smb2_fstat` 并把 SMB2 64 位统计信息映射到调用方提供的 `struct stat`。

#### Scenario: SMB2 统计信息映射到 POSIX stat
- **GIVEN** `file_context` 标记为 SMB2 文件且调用方提供 `struct stat` 输出对象
- **WHEN** 调用 `fstat_file`
- **THEN** 函数调用 `smb2_fstat`，设置 inode、size、访问/修改/变更时间等字段，并返回 `smb2_fstat` 的结果码

Trace: `utils/smb2-cp.c:fstat_file`

### Requirement: file_pread offset-based reads
系统 MUST 根据文件上下文类型执行指定偏移和长度的读操作，并把底层读返回值直接返回给复制循环。

#### Scenario: 本地和 SMB2 源文件按偏移读取
- **GIVEN** 调用方提供文件上下文、目标缓冲区、读长度和偏移
- **WHEN** 调用 `file_pread`
- **THEN** 本地文件路径先 `lseek` 到偏移再调用 `read`，SMB2 文件路径调用 `smb2_pread`，返回值表示读取字节数或负数错误

Trace: `utils/smb2-cp.c:file_pread`

### Requirement: file_pwrite offset-based writes
系统 MUST 根据文件上下文类型执行指定偏移和长度的写操作，并把底层写返回值直接返回给复制循环。

#### Scenario: 本地和 SMB2 目标文件按偏移写入
- **GIVEN** 调用方提供文件上下文、源缓冲区、写长度和偏移
- **WHEN** 调用 `file_pwrite`
- **THEN** 本地文件路径先 `lseek` 到偏移再调用 `write`，SMB2 文件路径调用 `smb2_pwrite`，返回值表示写入字节数或负数错误

Trace: `utils/smb2-cp.c:file_pwrite`

### Requirement: open_file create local or SMB2 context
系统 MUST 根据 `smb://` 前缀创建本地文件上下文或 SMB2 文件上下文，并在任一步骤失败时打印错误、释放已获得资源并返回 `NULL`。

#### Scenario: 打开本地文件
- **GIVEN** 输入路径不以 `smb://` 开头
- **WHEN** 调用 `open_file` 并传入打开标志
- **THEN** 函数使用 `open(url, flags, 0660)` 打开本地文件，成功时返回 `is_smb2 == 0` 的上下文，失败时打印错误并释放上下文

Trace: `utils/smb2-cp.c:open_file`

#### Scenario: 打开 SMB2 URL
- **GIVEN** 输入路径以 `smb://` 开头
- **WHEN** 调用 `open_file` 并传入打开标志
- **THEN** 函数初始化 SMB2 context、解析 URL、连接 share、打开远端路径，成功时返回 `is_smb2 == 1` 的上下文，失败时打印 libsmb2 错误并释放上下文

Trace: `utils/smb2-cp.c:open_file`

### Requirement: main copy source to destination
系统 MUST 接受一个源路径和一个目标路径，将源文件内容按最多 `BUFSIZE` 字节的块复制到目标路径，并在错误时释放已打开资源且返回 `10`。

#### Scenario: 成功复制本地或 SMB2 文件
- **GIVEN** 调用方传入源路径和目标路径，二者可以分别是本地文件或 SMB2 URL
- **WHEN** `main` 成功打开源和目标、读取源大小并进入复制循环
- **THEN** 程序从偏移 0 开始按不超过 `BUFSIZE` 的块读取源并写入目标，直到偏移达到源大小，随后打印 `copied <bytes> bytes`、释放两个上下文并返回 0

Trace: `utils/smb2-cp.c:main`

#### Scenario: 打开或复制失败返回错误
- **GIVEN** 源打开、目标打开、源 stat、读取或写入任一步骤失败
- **WHEN** `main` 检测到失败返回值
- **THEN** 程序向 `stderr` 输出对应错误消息，释放已经打开的上下文，并返回 `10`

Trace: `utils/smb2-cp.c:main`

### Requirement: BUFSIZE copy chunk limit
系统 MUST 使用 `BUFSIZE` 作为单次复制操作的最大字节数，并基于剩余源文件大小缩小最后一次读写长度。

#### Scenario: 大文件分块复制
- **GIVEN** 源文件大小大于 `BUFSIZE`
- **WHEN** `main` 计算当前循环的 `count`
- **THEN** `count` 不超过 `BUFSIZE`，最后一个块按 `st.st_size - off` 的剩余字节数复制

Trace: `utils/smb2-cp.c:BUFSIZE`, `utils/smb2-cp.c:main`

## Open Questions

| ID | Question | Related Interface | Reason |
| --- | --- | --- | --- |
| Q-001 | `fstat_file` 中 `st_blocks` 使用 `(smb2_size + 4096 - 1) % 4096` 是否为预期块数语义？ | fstat_file | 源码显示取模而非除法，无法仅凭当前文件确认是否为缺陷或兼容行为。 |
| Q-002 | 本地 `file_pread` 和 `file_pwrite` 忽略 `lseek` 失败是否为既有契约？ | file_pread`, `file_pwrite | 源码未检查 `lseek` 返回值，调用方仅观察 `read`/`write` 结果。 |
| Q-003 | 复制循环在 `read` 返回 0 但 `off < st.st_size` 时是否可能无限循环？ | main`, `file_pread | 源码只将负返回值视为错误，零字节读写边界未在当前文件或测试中确认。 |
