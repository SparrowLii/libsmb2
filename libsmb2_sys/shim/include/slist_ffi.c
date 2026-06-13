#include "slist_ffi.h"

#include "slist.h"

void slist_ffi_add(struct slist_ffi_node **list, struct slist_ffi_node *item) {
    SMB2_LIST_ADD(list, item);
}

void slist_ffi_add_end(struct slist_ffi_node **list, struct slist_ffi_node *item) {
    SMB2_LIST_ADD_END(list, item);
}

void slist_ffi_remove(struct slist_ffi_node **list, struct slist_ffi_node *item) {
    SMB2_LIST_REMOVE(list, item);
}

size_t slist_ffi_length(struct slist_ffi_node **list) {
    size_t length;
    SMB2_LIST_LENGTH(list, length);
    return length;
}
