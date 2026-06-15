#include "smb2_data_filesystem_info_ffi.h"

#define HAVE_STDINT_H 1
#define HAVE_TIME_H 1
#include <time.h>

#include "smb2/smb2.h"
#include "compat.h"
#include "smb2/libsmb2.h"
#include "libsmb2-private.h"

#include <stdlib.h>
#include <string.h>

#define smb2_get_uint8 smb2_data_filesystem_info_ffi_get_uint8
#define smb2_get_uint32 smb2_data_filesystem_info_ffi_get_uint32
#define smb2_get_uint64 smb2_data_filesystem_info_ffi_get_uint64
#define smb2_set_uint8 smb2_data_filesystem_info_ffi_set_uint8
#define smb2_set_uint32 smb2_data_filesystem_info_ffi_set_uint32
#define smb2_set_uint64 smb2_data_filesystem_info_ffi_set_uint64

static int smb2_data_filesystem_info_ffi_get_uint8(struct smb2_iovec *iov, int offset,
                                                   uint8_t *value);
static int smb2_data_filesystem_info_ffi_get_uint32(struct smb2_iovec *iov, int offset,
                                                    uint32_t *value);
static int smb2_data_filesystem_info_ffi_get_uint64(struct smb2_iovec *iov, int offset,
                                                    uint64_t *value);
static int smb2_data_filesystem_info_ffi_set_uint8(struct smb2_iovec *iov, int offset,
                                                   uint8_t value);
static int smb2_data_filesystem_info_ffi_set_uint32(struct smb2_iovec *iov, int offset,
                                                    uint32_t value);
static int smb2_data_filesystem_info_ffi_set_uint64(struct smb2_iovec *iov, int offset,
                                                    uint64_t value);

#define smb2_decode_file_fs_volume_info smb2_data_filesystem_info_ffi_real_decode_volume
#define smb2_encode_file_fs_volume_info smb2_data_filesystem_info_ffi_real_encode_volume
#define smb2_decode_file_fs_attribute_info smb2_data_filesystem_info_ffi_real_decode_attribute
#define smb2_encode_file_fs_attribute_info smb2_data_filesystem_info_ffi_real_encode_attribute
#include "../../../lib/smb2-data-filesystem-info.c"
#undef smb2_decode_file_fs_volume_info
#undef smb2_encode_file_fs_volume_info
#undef smb2_decode_file_fs_attribute_info
#undef smb2_encode_file_fs_attribute_info
#undef smb2_get_uint8
#undef smb2_get_uint32
#undef smb2_get_uint64
#undef smb2_set_uint8
#undef smb2_set_uint32
#undef smb2_set_uint64

static void set_timeval(struct smb2_timeval *tv, int64_t seconds, int64_t microseconds)
{
        tv->tv_sec = seconds;
        tv->tv_usec = microseconds;
}

static uint32_t get_u32(const uint8_t *buf, size_t offset)
{
        return ((uint32_t)buf[offset]) |
               ((uint32_t)buf[offset + 1] << 8) |
               ((uint32_t)buf[offset + 2] << 16) |
               ((uint32_t)buf[offset + 3] << 24);
}

static uint64_t get_u64(const uint8_t *buf, size_t offset)
{
        return ((uint64_t)get_u32(buf, offset)) |
               ((uint64_t)get_u32(buf, offset + 4) << 32);
}

static void set_u32(uint8_t *buf, size_t offset, uint32_t value)
{
        buf[offset] = (uint8_t)(value & 0xff);
        buf[offset + 1] = (uint8_t)((value >> 8) & 0xff);
        buf[offset + 2] = (uint8_t)((value >> 16) & 0xff);
        buf[offset + 3] = (uint8_t)((value >> 24) & 0xff);
}

static void set_u64(uint8_t *buf, size_t offset, uint64_t value)
{
        set_u32(buf, offset, (uint32_t)(value & 0xffffffffu));
        set_u32(buf, offset + 4, (uint32_t)(value >> 32));
}

static int smb2_data_filesystem_info_ffi_get_uint8(struct smb2_iovec *iov, int offset,
                                                   uint8_t *value)
{
        if ((size_t)offset + 1 > iov->len) { return -1; }
        *value = iov->buf[offset];
        return 0;
}

static int smb2_data_filesystem_info_ffi_get_uint32(struct smb2_iovec *iov, int offset,
                                                    uint32_t *value)
{
        if ((size_t)offset + 4 > iov->len) { return -1; }
        *value = get_u32(iov->buf, (size_t)offset);
        return 0;
}

static int smb2_data_filesystem_info_ffi_get_uint64(struct smb2_iovec *iov, int offset,
                                                    uint64_t *value)
{
        if ((size_t)offset + 8 > iov->len) { return -1; }
        *value = get_u64(iov->buf, (size_t)offset);
        return 0;
}

static int smb2_data_filesystem_info_ffi_set_uint8(struct smb2_iovec *iov, int offset,
                                                   uint8_t value)
{
        if ((size_t)offset + 1 > iov->len) { return -1; }
        iov->buf[offset] = value;
        return 0;
}

static int smb2_data_filesystem_info_ffi_set_uint32(struct smb2_iovec *iov, int offset,
                                                    uint32_t value)
{
        if ((size_t)offset + 4 > iov->len) { return -1; }
        set_u32(iov->buf, (size_t)offset, value);
        return 0;
}

static int smb2_data_filesystem_info_ffi_set_uint64(struct smb2_iovec *iov, int offset,
                                                    uint64_t value)
{
        if ((size_t)offset + 8 > iov->len) { return -1; }
        set_u64(iov->buf, (size_t)offset, value);
        return 0;
}

int smb2_data_filesystem_info_ffi_decode_size(const uint8_t *buf, size_t len,
                                              struct fs_size_info_ffi *out)
{
        if (len < 24) { return -1; }
        out->total_allocation_units = get_u64(buf, 0);
        out->available_allocation_units = get_u64(buf, 8);
        out->sectors_per_allocation_unit = get_u32(buf, 16);
        out->bytes_per_sector = get_u32(buf, 20);
        return 0;
}

int smb2_data_filesystem_info_ffi_encode_size(const struct fs_size_info_ffi *info,
                                              uint8_t *buf, size_t len)
{
        if (len < 24) { return -1; }
        set_u64(buf, 0, info->total_allocation_units);
        set_u64(buf, 8, info->available_allocation_units);
        set_u32(buf, 16, info->sectors_per_allocation_unit);
        set_u32(buf, 20, info->bytes_per_sector);
        return 24;
}

int smb2_data_filesystem_info_ffi_decode_device(const uint8_t *buf, size_t len,
                                                struct fs_device_info_ffi *out)
{
        if (len < 8) { return -1; }
        out->device_type = get_u32(buf, 0);
        out->characteristics = get_u32(buf, 4);
        return 0;
}

int smb2_data_filesystem_info_ffi_encode_device(const struct fs_device_info_ffi *info,
                                                uint8_t *buf, size_t len)
{
        if (len < 8) { return -1; }
        set_u32(buf, 0, info->device_type);
        set_u32(buf, 4, info->characteristics);
        return 8;
}

int smb2_data_filesystem_info_ffi_decode_volume(const uint8_t *buf, size_t len,
                                                struct fs_volume_info_ffi *out,
                                                char *label_buf,
                                                size_t label_buf_len)
{
        struct smb2_file_fs_volume_info fs;
        struct smb2_iovec vec;
        void *memctx;

        memset(&fs, 0, sizeof(fs));
        vec.buf = discard_const(buf);
        vec.len = len;

        /* smb2_decode_file_fs_volume_info uses smb2_alloc_data, which
           interprets memctx as an smb2_alloc_header. Pass a real allocation
           context (not the caller's raw label buffer) so the C allocator does
           not corrupt Rust-owned memory. */
        memctx = smb2_alloc_init(NULL, 0);
        if (memctx == NULL) {
                return -1;
        }

        if (smb2_data_filesystem_info_ffi_real_decode_volume(NULL, memctx, &fs, &vec) < 0) {
                smb2_free_data(NULL, memctx);
                return -1;
        }
        if (fs.volume_label_length > 0 && fs.volume_label == NULL) {
                smb2_free_data(NULL, memctx);
                return -1;
        }

        out->creation_time_seconds = fs.creation_time.tv_sec;
        out->creation_time_microseconds = fs.creation_time.tv_usec;
        out->volume_serial_number = fs.volume_serial_number;
        out->supports_objects = fs.supports_objects;
        out->reserved = fs.reserved;
        if (fs.volume_label != NULL) {
                if (strlen(fs.volume_label) + 1 > label_buf_len) {
                        smb2_free_data(NULL, memctx);
                        return -1;
                }
                strcpy(label_buf, fs.volume_label);
                out->volume_label = label_buf;
        } else {
                if (label_buf_len > 0) {
                        label_buf[0] = '\0';
                }
                out->volume_label = label_buf_len > 0 ? label_buf : NULL;
        }

        smb2_free_data(NULL, memctx);
        return 0;
}

int smb2_data_filesystem_info_ffi_encode_volume(const struct fs_volume_info_ffi *info,
                                                uint8_t *buf, size_t len)
{
        struct smb2_file_fs_volume_info fs;
        struct smb2_iovec vec;

        memset(&fs, 0, sizeof(fs));
        set_timeval(&fs.creation_time, info->creation_time_seconds,
                    info->creation_time_microseconds);
        fs.volume_serial_number = info->volume_serial_number;
        fs.supports_objects = info->supports_objects;
        fs.reserved = info->reserved;
        fs.volume_label = info->volume_label;
        vec.buf = buf;
        vec.len = len;

        return smb2_data_filesystem_info_ffi_real_encode_volume(NULL, &fs, &vec);
}

int smb2_data_filesystem_info_ffi_decode_attribute(const uint8_t *buf, size_t len,
                                                   struct fs_attribute_info_ffi *out,
                                                   char *name_buf,
                                                   size_t name_buf_len)
{
        struct smb2_file_fs_attribute_info fs;
        struct smb2_iovec vec;
        void *memctx;

        memset(&fs, 0, sizeof(fs));
        vec.buf = discard_const(buf);
        vec.len = len;

        /* smb2_decode_file_fs_attribute_info uses smb2_alloc_data, which
           interprets memctx as an smb2_alloc_header. Pass a real allocation
           context (not the caller's raw name buffer) so the C allocator does
           not corrupt Rust-owned memory. */
        memctx = smb2_alloc_init(NULL, 0);
        if (memctx == NULL) {
                return -1;
        }

        if (smb2_data_filesystem_info_ffi_real_decode_attribute(NULL, memctx, &fs, &vec) < 0) {
                smb2_free_data(NULL, memctx);
                return -1;
        }

        out->filesystem_attributes = fs.filesystem_attributes;
        out->maximum_component_name_length = fs.maximum_component_name_length;
        if (fs.filesystem_name != NULL) {
                if (strlen(fs.filesystem_name) + 1 > name_buf_len) {
                        smb2_free_data(NULL, memctx);
                        return -1;
                }
                strcpy(name_buf, fs.filesystem_name);
                out->filesystem_name = name_buf;
        } else {
                if (name_buf_len > 0) {
                        name_buf[0] = '\0';
                }
                out->filesystem_name = name_buf_len > 0 ? name_buf : NULL;
        }

        smb2_free_data(NULL, memctx);
        return 0;
}

int smb2_data_filesystem_info_ffi_encode_attribute(const struct fs_attribute_info_ffi *info,
                                                   uint8_t *buf, size_t len)
{
        struct smb2_file_fs_attribute_info fs;
        struct smb2_iovec vec;

        memset(&fs, 0, sizeof(fs));
        fs.filesystem_attributes = info->filesystem_attributes;
        fs.maximum_component_name_length = info->maximum_component_name_length;
        fs.filesystem_name = info->filesystem_name;
        vec.buf = buf;
        vec.len = len;

        return smb2_data_filesystem_info_ffi_real_encode_attribute(NULL, &fs, &vec);
}

int smb2_data_filesystem_info_ffi_decode_control(const uint8_t *buf, size_t len,
                                                 struct fs_control_info_ffi *out)
{
        if (len < 44) { return -1; }
        out->free_space_start_filtering = get_u64(buf, 0);
        out->free_space_threshold = get_u64(buf, 8);
        out->free_space_stop_filtering = get_u64(buf, 16);
        out->default_quota_threshold = get_u64(buf, 24);
        out->default_quota_limit = get_u64(buf, 32);
        out->file_system_control_flags = get_u32(buf, 40);
        return 44;
}

int smb2_data_filesystem_info_ffi_encode_control(const struct fs_control_info_ffi *info,
                                                 uint8_t *buf, size_t len)
{
        if (len < 48) { return -1; }
        set_u64(buf, 0, info->free_space_start_filtering);
        set_u64(buf, 8, info->free_space_threshold);
        set_u64(buf, 16, info->free_space_stop_filtering);
        set_u64(buf, 24, info->default_quota_threshold);
        set_u64(buf, 32, info->default_quota_limit);
        set_u32(buf, 40, info->file_system_control_flags);
        return 44;
}

int smb2_data_filesystem_info_ffi_decode_full_size(const uint8_t *buf, size_t len,
                                                   struct fs_full_size_info_ffi *out)
{
        if (len < 32) { return -1; }
        out->total_allocation_units = get_u64(buf, 0);
        out->caller_available_allocation_units = get_u64(buf, 8);
        out->actual_available_allocation_units = get_u64(buf, 16);
        out->sectors_per_allocation_unit = get_u32(buf, 24);
        out->bytes_per_sector = get_u32(buf, 28);
        return 0;
}

int smb2_data_filesystem_info_ffi_encode_full_size(const struct fs_full_size_info_ffi *info,
                                                   uint8_t *buf, size_t len)
{
        if (len < 32) { return -1; }
        set_u64(buf, 0, info->total_allocation_units);
        set_u64(buf, 8, info->caller_available_allocation_units);
        set_u64(buf, 16, info->actual_available_allocation_units);
        set_u32(buf, 24, info->sectors_per_allocation_unit);
        set_u32(buf, 28, info->bytes_per_sector);
        return 32;
}

int smb2_data_filesystem_info_ffi_decode_object_id(const uint8_t *buf, size_t len,
                                                   struct fs_object_id_info_ffi *out)
{
        if (len < 64) { return -1; }
        memcpy(out->object_id, buf, 16);
        memcpy(out->extended_info, buf + 16, sizeof(out->extended_info));
        return 0;
}
