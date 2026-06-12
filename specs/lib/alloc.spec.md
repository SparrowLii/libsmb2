# lib/alloc.c Specification

## Source Context

- Source: `lib/alloc.c`
- Related Headers: `include/libsmb2-private.h`, `include/smb2/libsmb2-raw.h`
- Related Tests: `tests/smb2-dcerpc-coder-test.c`
- Related Dependencies: `smb2_alloc_init` is called by SMB2 PDU variable request decoders and `dcerpc_call_cb`; `smb2_alloc_data` is called by DCERPC LSA/SRVSVC coders, DCERPC UTF-16 decode/bind paths, SMB2 file/filesystem/security decode paths, and calls `smb2_set_error`; `smb2_free_data` is called by raw API examples, DCERPC cleanup paths, high-level libsmb2 callbacks, and indirectly by `tests/smb2-dcerpc-coder-test.c` through DCERPC context destruction.
- Build/Compile Context: C project; `lib/alloc.c` includes config-gated standard headers, `compat.h`, public SMB2 headers, `libsmb2-private.h`, and uses `_MSC_VER` to select the container header calculation path.

## Interface Summary

| Interface | Kind | Signature | Decision | Reason |
| --- | --- | --- | --- | --- |
| smb2_alloc_init | function | void *smb2_alloc_init(struct smb2_context *smb2, size_t size); | Include | 跨 SMB2 PDU/DCERPC 解码路径创建可追加释放的内存上下文，调用方可观察返回指针和 NULL 失败结果。 |
| smb2_alloc_data | function | void *smb2_alloc_data(struct smb2_context *smb2, void *memctx, size_t size); | Include | 跨 DCERPC、SMB2 数据解码和错误传播路径追加上下文托管分配，调用方可观察返回指针、错误字符串和释放归属。 |
| smb2_free_data | function | void smb2_free_data(struct smb2_context *smb2, void *ptr); | Include | 对外 raw API 暴露的释放入口，负责释放上下文头和所有追加分配，NULL 输入行为对调用方可见。 |
| container_of | macro | #define container_of(ptr, type, member) ({ const typeof( ((type *)0)->member ) *__mptr = (ptr); (type *)(void *)( (char *)__mptr - offsetof(type,member) );}) | Skip | 文件内部实现宏，且 `_MSC_VER` 分支提供等价指针回退逻辑，无独立调用方契约。 |

## Data Model Summary

| Type/Macro | Kind | Definition | Notes |
| --- | --- | --- | --- |
| smb2_alloc_entry | struct | lib/alloc.c:73 | 内部追加分配链表节点，`buf[0]` 是返回给调用方的数据区域，`next` 由 allocator 维护。 |
| smb2_alloc_header | struct | lib/alloc.c:81 | 内存上下文头，`mem` 保存所有 `smb2_alloc_data` 追加分配，`buf[0]` 是 `smb2_alloc_init` 返回的数据区域。 |
| container_of | macro | lib/alloc.c:69 | 非 MSVC 构建中根据返回给调用方的 `buf` 地址恢复内部头地址。 |

## ADDED Requirements

### Requirement: smb2_alloc_init creates a zeroed allocation context
系统 MUST 为请求的初始大小创建一个带内部头的零初始化内存上下文，并在成功时返回上下文数据区域的起始地址。

#### Scenario: successful context allocation
- **GIVEN** 调用方提供任意 `struct smb2_context *smb2` 和待分配的 `size`
- **WHEN** `smb2_alloc_init` 的内部 `calloc` 成功
- **THEN** 返回值 MUST 指向内部 `struct smb2_alloc_header` 的 `buf` 区域，并且该上下文的追加分配链初始为空

Trace: `lib/alloc.c:smb2_alloc_init`, `include/libsmb2-private.h:smb2_alloc_init`

#### Scenario: initial allocation failure
- **GIVEN** 调用方请求创建内存上下文
- **WHEN** `smb2_alloc_init` 的内部 `calloc` 返回 `NULL`
- **THEN** 函数 MUST 返回 `NULL`，且源码未显示该路径设置 `smb2` 错误字符串

Trace: `lib/alloc.c:smb2_alloc_init`

### Requirement: smb2_alloc_data appends zeroed child allocations to a context
系统 MUST 在既有内存上下文中追加零初始化子分配，并使后续 `smb2_free_data` 能通过上下文一次性释放这些子分配。

#### Scenario: successful child allocation
- **GIVEN** `memctx` 是 `smb2_alloc_init` 返回的上下文数据指针
- **WHEN** `smb2_alloc_data` 的内部 `calloc` 成功
- **THEN** 返回值 MUST 指向新 `struct smb2_alloc_entry` 的 `buf` 区域，且该 entry MUST 插入上下文头的 `mem` 链表

Trace: `lib/alloc.c:smb2_alloc_data`, `include/libsmb2-private.h:smb2_alloc_data`, `tests/smb2-dcerpc-coder-test.c:test_dcerpc_coder`

#### Scenario: child allocation failure records context error
- **GIVEN** 调用方提供 `smb2` 和有效的 `memctx`
- **WHEN** `smb2_alloc_data` 的内部 `calloc` 返回 `NULL`
- **THEN** 函数 MUST 调用 `smb2_set_error` 记录失败分配大小并返回 `NULL`

Trace: `lib/alloc.c:smb2_alloc_data`, `lib/init.c:smb2_set_error`

### Requirement: smb2_free_data releases allocation contexts and tolerates NULL
系统 MUST 释放 `smb2_alloc_init` 创建的上下文头以及通过 `smb2_alloc_data` 追加到该上下文的所有子分配。

#### Scenario: freeing a populated context
- **GIVEN** `ptr` 是 `smb2_alloc_init` 返回的上下文数据指针，且该上下文包含零个或多个 `smb2_alloc_data` 子分配
- **WHEN** 调用方调用 `smb2_free_data`
- **THEN** 函数 MUST 遍历并释放上下文链表中的每个子分配，然后释放上下文头本身

Trace: `lib/alloc.c:smb2_free_data`, `include/smb2/libsmb2-raw.h:smb2_free_data`, `tests/smb2-dcerpc-coder-test.c:main`

#### Scenario: freeing NULL is a no-op
- **GIVEN** 调用方传入 `ptr == NULL`
- **WHEN** 调用方调用 `smb2_free_data`
- **THEN** 函数 MUST 直接返回且 SHALL NOT 调用 `free`

Trace: `lib/alloc.c:smb2_free_data`

## Open Questions

| ID | Question | Related Interface | Reason |
| --- | --- | --- | --- |
| Q-001 | `smb2_alloc_init` 的 `smb2` 参数是否预期保留用于未来错误报告或上下文关联？ | smb2_alloc_init | 当前实现未使用该参数，头文件声明也未说明调用方可观察语义。 |
| Q-002 | `size + offsetof(...)` 溢出时的行为是否应定义为调用方责任？ | smb2_alloc_init, smb2_alloc_data | 当前源码未检查 `size_t` 加法溢出，测试未覆盖超大 size。 |
| Q-003 | `smb2_free_data` 的 `smb2` 参数是否应参与错误报告或调试钩子？ | smb2_free_data | 当前实现未使用该参数，公开 raw header 只说明用于释放 query 返回数据。 |
