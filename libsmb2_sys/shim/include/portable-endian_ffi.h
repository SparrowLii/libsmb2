#pragma once

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

uint16_t portable_endian_ffi_be16toh(uint16_t value);
uint16_t portable_endian_ffi_htobe16(uint16_t value);
uint16_t portable_endian_ffi_htole16(uint16_t value);
uint16_t portable_endian_ffi_le16toh(uint16_t value);
uint32_t portable_endian_ffi_be32toh(uint32_t value);
uint32_t portable_endian_ffi_htobe32(uint32_t value);
uint32_t portable_endian_ffi_htole32(uint32_t value);
uint32_t portable_endian_ffi_le32toh(uint32_t value);
uint64_t portable_endian_ffi_be64toh(uint64_t value);
uint64_t portable_endian_ffi_htobe64(uint64_t value);
uint64_t portable_endian_ffi_htole64(uint64_t value);
uint64_t portable_endian_ffi_le64toh(uint64_t value);

#ifdef __cplusplus
}
#endif
