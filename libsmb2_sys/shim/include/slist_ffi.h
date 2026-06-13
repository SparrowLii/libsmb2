#pragma once

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

struct slist_ffi_node {
    struct slist_ffi_node *next;
};

void slist_ffi_add(struct slist_ffi_node **list, struct slist_ffi_node *item);
void slist_ffi_add_end(struct slist_ffi_node **list, struct slist_ffi_node *item);
void slist_ffi_remove(struct slist_ffi_node **list, struct slist_ffi_node *item);
size_t slist_ffi_length(struct slist_ffi_node **list);

#ifdef __cplusplus
}
#endif
