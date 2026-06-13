#include "portable-endian_ffi.h"

#include "portable-endian.h"

uint16_t portable_endian_ffi_be16toh(uint16_t value) { return be16toh(value); }
uint16_t portable_endian_ffi_htobe16(uint16_t value) { return htobe16(value); }
uint16_t portable_endian_ffi_htole16(uint16_t value) { return htole16(value); }
uint16_t portable_endian_ffi_le16toh(uint16_t value) { return le16toh(value); }
uint32_t portable_endian_ffi_be32toh(uint32_t value) { return be32toh(value); }
uint32_t portable_endian_ffi_htobe32(uint32_t value) { return htobe32(value); }
uint32_t portable_endian_ffi_htole32(uint32_t value) { return htole32(value); }
uint32_t portable_endian_ffi_le32toh(uint32_t value) { return le32toh(value); }
uint64_t portable_endian_ffi_be64toh(uint64_t value) { return be64toh(value); }
uint64_t portable_endian_ffi_htobe64(uint64_t value) { return htobe64(value); }
uint64_t portable_endian_ffi_htole64(uint64_t value) { return htole64(value); }
uint64_t portable_endian_ffi_le64toh(uint64_t value) { return le64toh(value); }
