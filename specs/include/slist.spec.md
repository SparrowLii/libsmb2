# include/slist.h Specification

## Source Context

- Source: `include/slist.h`
- Related Headers: `lib/smb2-signing.h`
- Related Tests: `none`
- Related Dependencies: `lib/init.c`, `lib/libsmb2.c`, `lib/pdu.c`, `lib/socket.c`, `lib/smb2-data-security-descriptor.c`
- Build/Compile Context: C project; header-only macro list helpers; protected by `__smb2_slist_h__` include guard; no file-local compile conditions.

## Interface Summary

| Interface | Kind | Signature | Decision | Reason |
| --- | --- | --- | --- | --- |
| SMB2_LIST_ADD | macro | #define SMB2_LIST_ADD(list, item) | Include | 公开 header-only 链表插入宏，被上下文生命周期和目录项解码路径使用，调用方可观察链表头变化。 |
| SMB2_LIST_ADD_END | macro | #define SMB2_LIST_ADD_END(list, item) | Include | 公开 header-only 链表尾插宏，被 PDU 队列和 ACL 解码路径使用，调用方可观察追加顺序和 head 恢复。 |
| SMB2_LIST_REMOVE | macro | #define SMB2_LIST_REMOVE(list, item) | Include | 公开 header-only 链表删除宏，被上下文清理、socket 发送和 PDU 关联路径使用，调用方可观察链表成员移除。 |
| SMB2_LIST_LENGTH | macro | #define SMB2_LIST_LENGTH(list, length) | Include | 公开 header-only 链表长度宏，对传入 head 指针和输出计数有可观察契约。 |

## Data Model Summary

| Type/Macro | Kind | Definition | Notes |
| --- | --- | --- | --- |
| SMB2_LIST_ADD | macro | include/slist.h:21 | 要求 `list` 表达式指向链表 head 指针，`item` 指向含 `next` 成员的节点。 |
| SMB2_LIST_ADD_END | macro | include/slist.h:27 | 遍历 `next` 链直到尾节点，空链表时复用 `SMB2_LIST_ADD`。 |
| SMB2_LIST_REMOVE | macro | include/slist.h:39 | 只按指针相等移除第一个匹配节点，不释放被移除节点。 |
| SMB2_LIST_LENGTH | macro | include/slist.h:52 | 遍历 `next` 链并写入调用方提供的 `length` 变量。 |

## ADDED Requirements

### Requirement: SMB2_LIST_ADD head insertion behavior
系统 MUST 将 `item` 插入到 `*list` 当前 head 之前，并将 `*list` 更新为 `item`，同时让 `item->next` 保存旧 head。

#### Scenario: prepend item to list
- **GIVEN** 调用方提供指向链表 head 的 `list` 参数，且 `item` 包含可写 `next` 成员
- **WHEN** 调用方执行 `SMB2_LIST_ADD(list, item)`
- **THEN** `item->next` 指向调用前的 `*list`，并且调用后的 `*list` 指向 `item`

Trace: `include/slist.h:SMB2_LIST_ADD`, `lib/init.c:smb2_init_context`, `lib/libsmb2.c:decode_dirents`

### Requirement: SMB2_LIST_ADD_END tail insertion behavior
系统 MUST 在非空链表中沿 `next` 链追加 `item` 到尾节点之后，将 `item->next` 置为 `NULL`，并在追加完成后恢复 `*list` 为原始 head。

#### Scenario: append item to non-empty list
- **GIVEN** 调用方提供指向非空链表 head 的 `list` 参数，且链表节点和 `item` 均包含可写 `next` 成员
- **WHEN** 调用方执行 `SMB2_LIST_ADD_END(list, item)`
- **THEN** 原尾节点的 `next` 指向 `item`，`item->next` 为 `NULL`，并且 `*list` 仍指向调用前的 head

Trace: `include/slist.h:SMB2_LIST_ADD_END`, `lib/pdu.c:smb2_add_to_outqueue`, `lib/socket.c:smb2_write_to_socket`, `lib/smb2-data-security-descriptor.c:decode_acl`

#### Scenario: append item to empty list
- **GIVEN** 调用方提供指向空链表 head 的 `list` 参数，且 `item` 包含可写 `next` 成员
- **WHEN** 调用方执行 `SMB2_LIST_ADD_END(list, item)`
- **THEN** 宏通过 `SMB2_LIST_ADD` 将 `*list` 更新为 `item`，并让 `item->next` 保存调用前的空 head

Trace: `include/slist.h:SMB2_LIST_ADD_END`, `include/slist.h:SMB2_LIST_ADD`

### Requirement: SMB2_LIST_REMOVE pointer removal behavior
系统 MUST 按节点指针相等从链表中移除第一个匹配的 `item`，并在遍历非 head 节点后恢复 `*list` 为原始 head。

#### Scenario: remove head item
- **GIVEN** 调用方提供指向链表 head 的 `list` 参数，且调用前 `*list == item`
- **WHEN** 调用方执行 `SMB2_LIST_REMOVE(list, item)`
- **THEN** 调用后的 `*list` 指向调用前 `item->next`

Trace: `include/slist.h:SMB2_LIST_REMOVE`, `lib/init.c:smb2_destroy_context`, `lib/socket.c:smb2_write_to_socket`

#### Scenario: remove later item
- **GIVEN** 调用方提供指向非空链表 head 的 `list` 参数，且某个后继节点等于 `item`
- **WHEN** 调用方执行 `SMB2_LIST_REMOVE(list, item)`
- **THEN** 匹配节点前一个节点的 `next` 指向匹配节点调用前的 `next`，并且 `*list` 恢复为原始 head

Trace: `include/slist.h:SMB2_LIST_REMOVE`, `lib/pdu.c:smb2_correlate_reply`

#### Scenario: remove missing item
- **GIVEN** 调用方提供指向空链表或不包含 `item` 的链表 head 的 `list` 参数
- **WHEN** 调用方执行 `SMB2_LIST_REMOVE(list, item)`
- **THEN** 宏不改变空链表 head；非空链表遍历完成后 `*list` 恢复为原始 head

Trace: `include/slist.h:SMB2_LIST_REMOVE`

### Requirement: SMB2_LIST_LENGTH traversal count behavior
系统 MUST 从 `*list` 当前 head 开始沿 `next` 链计数，将节点数量写入 `length`，并在遍历完成后恢复 `*list` 为原始 head。

#### Scenario: count list items
- **GIVEN** 调用方提供指向链表 head 的 `list` 参数和可写 `length` 变量，且链表节点包含可读 `next` 成员
- **WHEN** 调用方执行 `SMB2_LIST_LENGTH(list, length)`
- **THEN** `length` 等于沿 `next` 链可达的节点数量，并且 `*list` 恢复为调用前的 head

Trace: `include/slist.h:SMB2_LIST_LENGTH`

## Open Questions

| ID | Question | Related Interface | Reason |
| --- | --- | --- | --- |
| Q-001 | GitNexus `context` 和 `impact --include-tests` 未返回宏调用者，但源码搜索确认多个实现文件使用这些宏；是否需要重新索引以捕获宏展开调用关系？ | SMB2_LIST_ADD, SMB2_LIST_ADD_END, SMB2_LIST_REMOVE | GitNexus 对宏调用边的索引结果与源码证据不一致。 |
| Q-002 | `SMB2_LIST_ADD_END` 在空链表路径未显式将 `item->next` 置为 `NULL`，是否要求调用方在传入前保证 `item->next` 已为期望值？ | SMB2_LIST_ADD_END | 源码仅复用 `SMB2_LIST_ADD`，未声明新节点初始化责任。 |
