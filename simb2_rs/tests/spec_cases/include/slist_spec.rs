use libsmb2_sys::include::slist::{SListHead, SListNode};

// Trace: `include/slist.h:SMB2_LIST_ADD`, `lib/init.c:smb2_init_context`, `lib/libsmb2.c:decode_dirents`
// Spec: SMB2_LIST_ADD head insertion behavior#prepend item to list
// - **GIVEN** 调用方提供指向链表 head 的 `list` 参数，且 `item` 包含可写 `next` 成员
// - **WHEN** 调用方执行 `SMB2_LIST_ADD(list, item)`
// - **THEN** `item->next` 指向调用前的 `*list`，并且调用后的 `*list` 指向 `item`
#[test]
fn test_slist_prepend_item_to_list() {
    let mut old_head = SListNode::new();
    let mut item = SListNode::new();
    let mut list = SListHead::from_head(&mut old_head);

    list.add(&mut item);

    assert!(item.next_is(Some(&old_head)));
    assert!(list.head_is(Some(&item)));
}

// Trace: `include/slist.h:SMB2_LIST_ADD_END`, `lib/pdu.c:smb2_add_to_outqueue`, `lib/socket.c:smb2_write_to_socket`, `lib/smb2-data-security-descriptor.c:decode_acl`
// Spec: SMB2_LIST_ADD_END tail insertion behavior#append item to non-empty list
// - **GIVEN** 调用方提供指向非空链表 head 的 `list` 参数，且链表节点和 `item` 均包含可写 `next` 成员
// - **WHEN** 调用方执行 `SMB2_LIST_ADD_END(list, item)`
// - **THEN** 原尾节点的 `next` 指向 `item`，`item->next` 为 `NULL`，并且 `*list` 仍指向调用前的 head
#[test]
fn test_slist_append_item_to_non_empty_list() {
    let mut head = SListNode::new();
    let mut item = SListNode::new();
    let mut list = SListHead::from_head(&mut head);

    list.add_end(&mut item);

    assert!(head.next_is(Some(&item)));
    assert!(item.next_is(None));
    assert!(list.head_is(Some(&head)));
}

// Trace: `include/slist.h:SMB2_LIST_ADD_END`, `include/slist.h:SMB2_LIST_ADD`
// Spec: SMB2_LIST_ADD_END tail insertion behavior#append item to empty list
// - **GIVEN** 调用方提供指向空链表 head 的 `list` 参数，且 `item` 包含可写 `next` 成员
// - **WHEN** 调用方执行 `SMB2_LIST_ADD_END(list, item)`
// - **THEN** 宏通过 `SMB2_LIST_ADD` 将 `*list` 更新为 `item`，并让 `item->next` 保存调用前的空 head
#[test]
fn test_slist_append_item_to_empty_list() {
    let mut item = SListNode::new();
    let mut list = SListHead::empty();

    list.add_end(&mut item);

    assert!(list.head_is(Some(&item)));
    assert!(item.next_is(None));
}

// Trace: `include/slist.h:SMB2_LIST_REMOVE`, `lib/init.c:smb2_destroy_context`, `lib/socket.c:smb2_write_to_socket`
// Spec: SMB2_LIST_REMOVE pointer removal behavior#remove head item
// - **GIVEN** 调用方提供指向链表 head 的 `list` 参数，且调用前 `*list == item`
// - **WHEN** 调用方执行 `SMB2_LIST_REMOVE(list, item)`
// - **THEN** 调用后的 `*list` 指向调用前 `item->next`
#[test]
fn test_slist_remove_head_item() {
    let mut head = SListNode::new();
    let mut next = SListNode::new();
    let mut list = SListHead::from_head(&mut next);
    list.add(&mut head);

    list.remove(&mut head);

    assert!(list.head_is(Some(&next)));
}

// Trace: `include/slist.h:SMB2_LIST_REMOVE`, `lib/pdu.c:smb2_correlate_reply`
// Spec: SMB2_LIST_REMOVE pointer removal behavior#remove later item
// - **GIVEN** 调用方提供指向非空链表 head 的 `list` 参数，且某个后继节点等于 `item`
// - **WHEN** 调用方执行 `SMB2_LIST_REMOVE(list, item)`
// - **THEN** 匹配节点前一个节点的 `next` 指向匹配节点调用前的 `next`，并且 `*list` 恢复为原始 head
#[test]
fn test_slist_remove_later_item() {
    let mut head = SListNode::new();
    let mut item = SListNode::new();
    let mut tail = SListNode::new();
    let mut list = SListHead::from_head(&mut head);
    list.add_end(&mut item);
    list.add_end(&mut tail);

    list.remove(&mut item);

    assert!(head.next_is(Some(&tail)));
    assert!(list.head_is(Some(&head)));
}

// Trace: `include/slist.h:SMB2_LIST_REMOVE`
// Spec: SMB2_LIST_REMOVE pointer removal behavior#remove missing item
// - **GIVEN** 调用方提供指向空链表或不包含 `item` 的链表 head 的 `list` 参数
// - **WHEN** 调用方执行 `SMB2_LIST_REMOVE(list, item)`
// - **THEN** 宏不改变空链表 head；非空链表遍历完成后 `*list` 恢复为原始 head
#[test]
fn test_slist_remove_missing_item() {
    let mut missing = SListNode::new();
    let mut empty = SListHead::empty();

    empty.remove(&mut missing);
    assert!(empty.head_is(None));

    let mut head = SListNode::new();
    let mut tail = SListNode::new();
    let mut non_empty = SListHead::from_head(&mut head);
    non_empty.add_end(&mut tail);

    non_empty.remove(&mut missing);

    assert!(non_empty.head_is(Some(&head)));
    assert!(head.next_is(Some(&tail)));
}

// Trace: `include/slist.h:SMB2_LIST_LENGTH`
// Spec: SMB2_LIST_LENGTH traversal count behavior#count list items
// - **GIVEN** 调用方提供指向链表 head 的 `list` 参数和可写 `length` 变量，且链表节点包含可读 `next` 成员
// - **WHEN** 调用方执行 `SMB2_LIST_LENGTH(list, length)`
// - **THEN** `length` 等于沿 `next` 链可达的节点数量，并且 `*list` 恢复为调用前的 head
#[test]
fn test_slist_count_list_items() {
    let mut first = SListNode::new();
    let mut second = SListNode::new();
    let mut third = SListNode::new();
    let mut list = SListHead::from_head(&mut first);
    list.add_end(&mut second);
    list.add_end(&mut third);

    assert_eq!(list.len(), 3);
    assert!(list.head_is(Some(&first)));
}
