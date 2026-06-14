#ifndef LIBSMB2_SYS_SMB2_DATA_FILESYSTEM_INFO_FFI_H
#define LIBSMB2_SYS_SMB2_DATA_FILESYSTEM_INFO_FFI_H

#include <stddef.h>
#include <stdint.h>

struct fs_size_info_ffi {
        uint64_t total_allocation_units;
        uint64_t available_allocation_units;
        uint32_t sectors_per_allocation_unit;
        uint32_t bytes_per_sector;
};

struct fs_device_info_ffi {
        uint32_t device_type;
        uint32_t characteristics;
};

struct fs_volume_info_ffi {
        int64_t creation_time_seconds;
        int64_t creation_time_microseconds;
        uint32_t volume_serial_number;
        uint8_t supports_objects;
        uint8_t reserved;
        const char *volume_label;
};

struct fs_attribute_info_ffi {
        uint32_t filesystem_attributes;
        uint32_t maximum_component_name_length;
        const char *filesystem_name;
};

struct fs_control_info_ffi {
        uint64_t free_space_start_filtering;
        uint64_t free_space_threshold;
        uint64_t free_space_stop_filtering;
        uint64_t default_quota_threshold;
        uint64_t default_quota_limit;
        uint32_t file_system_control_flags;
};

struct fs_full_size_info_ffi {
        uint64_t total_allocation_units;
        uint64_t caller_available_allocation_units;
        uint64_t actual_available_allocation_units;
        uint32_t sectors_per_allocation_unit;
        uint32_t bytes_per_sector;
};

struct fs_object_id_info_ffi {
        uint8_t object_id[16];
        uint8_t extended_info[48];
};

int smb2_data_filesystem_info_ffi_decode_size(const uint8_t *buf, size_t len,
                                              struct fs_size_info_ffi *out);
int smb2_data_filesystem_info_ffi_encode_size(const struct fs_size_info_ffi *info,
                                              uint8_t *buf, size_t len);
int smb2_data_filesystem_info_ffi_decode_device(const uint8_t *buf, size_t len,
                                                struct fs_device_info_ffi *out);
int smb2_data_filesystem_info_ffi_encode_device(const struct fs_device_info_ffi *info,
                                                uint8_t *buf, size_t len);
int smb2_data_filesystem_info_ffi_decode_volume(const uint8_t *buf, size_t len,
                                                struct fs_volume_info_ffi *out,
                                                char *label_buf,
                                                size_t label_buf_len);
int smb2_data_filesystem_info_ffi_encode_volume(const struct fs_volume_info_ffi *info,
                                                uint8_t *buf, size_t len);
int smb2_data_filesystem_info_ffi_decode_attribute(const uint8_t *buf, size_t len,
                                                   struct fs_attribute_info_ffi *out,
                                                   char *name_buf,
                                                   size_t name_buf_len);
int smb2_data_filesystem_info_ffi_encode_attribute(const struct fs_attribute_info_ffi *info,
                                                   uint8_t *buf, size_t len);
int smb2_data_filesystem_info_ffi_decode_control(const uint8_t *buf, size_t len,
                                                 struct fs_control_info_ffi *out);
int smb2_data_filesystem_info_ffi_encode_control(const struct fs_control_info_ffi *info,
                                                 uint8_t *buf, size_t len);
int smb2_data_filesystem_info_ffi_decode_full_size(const uint8_t *buf, size_t len,
                                                   struct fs_full_size_info_ffi *out);
int smb2_data_filesystem_info_ffi_encode_full_size(const struct fs_full_size_info_ffi *info,
                                                   uint8_t *buf, size_t len);
int smb2_data_filesystem_info_ffi_decode_object_id(const uint8_t *buf, size_t len,
                                                   struct fs_object_id_info_ffi *out);

#endif
