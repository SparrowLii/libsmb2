use libsmb2_sys::include::portable_endian::{
    be16_to_host, be32_to_host, be64_to_host, host_to_be16, host_to_be32, host_to_be64,
    host_to_le16, host_to_le32, host_to_le64, le16_to_host, le32_to_host, le64_to_host,
};

// Trace: `include/portable-endian.h:26`, `include/portable-endian.h:44`, `include/portable-endian.h:88`, `include/portable-endian.h:118`, `include/portable-endian.h:140`, `include/portable-endian.h:158`, `include/portable-endian.h:184`, `include/portable-endian.h:217`, `include/portable-endian.h:253`, `include/portable-endian.h:270`, `include/portable-endian.h:320`, `include/portable-endian.h:337`, `include/portable-endian.h:360`
// Spec: be16toh converts 16-bit big-endian input to host order#supported platform converts big-endian 16-bit value
// - **GIVEN** 编译目标命中 `include/portable-endian.h` 中任一支持的平台分支
// - **WHEN** 调用方使用 `be16toh(x)` 读取 16 位 big-endian 协议字段
// - **THEN** 宏展开 MUST 使用该平台的网络序转换、byteswap 内建、系统 endian API 或恒等表达式返回 host-order 值
#[test]
fn test_portable_endian_supported_platform_converts_big_endian_16_bit_value() {
    assert_eq!(be16_to_host(0x1234_u16.to_be()), 0x1234);
}

// Trace: `include/portable-endian.h:27`, `include/portable-endian.h:45`, `include/portable-endian.h:116`, `include/portable-endian.h:138`, `include/portable-endian.h:156`, `include/portable-endian.h:182`, `include/portable-endian.h:215`, `include/portable-endian.h:251`, `include/portable-endian.h:268`, `include/portable-endian.h:318`, `include/portable-endian.h:335`, `include/portable-endian.h:358`
// Spec: htobe16 converts 16-bit host input to big-endian order#supported platform writes big-endian 16-bit value
// - **GIVEN** 编译目标命中 `include/portable-endian.h` 中任一支持的平台分支
// - **WHEN** 调用方使用 `htobe16(x)` 写入 16 位 big-endian 协议字段
// - **THEN** 宏展开 MUST 使用该平台的网络序转换、byteswap 内建、系统 endian API 或恒等表达式生成 big-endian 值
#[test]
fn test_portable_endian_supported_platform_writes_big_endian_16_bit_value() {
    assert_eq!(host_to_be16(0x1234), 0x1234_u16.to_be());
}

// Trace: `include/portable-endian.h:28`, `include/portable-endian.h:46`, `include/portable-endian.h:117`, `include/portable-endian.h:139`, `include/portable-endian.h:157`, `include/portable-endian.h:183`, `include/portable-endian.h:216`, `include/portable-endian.h:252`, `include/portable-endian.h:269`, `include/portable-endian.h:319`, `include/portable-endian.h:336`, `include/portable-endian.h:359`
// Spec: htole16 converts 16-bit host input to little-endian order#supported platform writes little-endian 16-bit value
// - **GIVEN** 编译目标命中 `include/portable-endian.h` 中任一支持的平台分支
// - **WHEN** 调用方使用 `htole16(x)` 写入 SMB、DCERPC 或 NTLM little-endian 16 位字段
// - **THEN** 宏展开 MUST 在 little-endian 平台保持值不变，或在 big-endian 平台执行 16 位 byteswap
#[test]
fn test_portable_endian_supported_platform_writes_little_endian_16_bit_value() {
    assert_eq!(host_to_le16(0x1234), 0x1234_u16.to_le());
}

// Trace: `include/portable-endian.h:29`, `include/portable-endian.h:47`, `include/portable-endian.h:92`, `include/portable-endian.h:119`, `include/portable-endian.h:141`, `include/portable-endian.h:159`, `include/portable-endian.h:185`, `include/portable-endian.h:218`, `include/portable-endian.h:254`, `include/portable-endian.h:271`, `include/portable-endian.h:321`, `include/portable-endian.h:338`, `include/portable-endian.h:361`
// Spec: le16toh converts 16-bit little-endian input to host order#supported platform reads little-endian 16-bit value
// - **GIVEN** 编译目标命中 `include/portable-endian.h` 中任一支持的平台分支
// - **WHEN** 调用方使用 `le16toh(x)` 解析 SMB、DCERPC 或 NTLM little-endian 16 位字段
// - **THEN** 宏展开 MUST 在 little-endian 平台保持值不变，或在 big-endian 平台执行 16 位 byteswap
#[test]
fn test_portable_endian_supported_platform_reads_little_endian_16_bit_value() {
    assert_eq!(le16_to_host(0x1234_u16.to_le()), 0x1234);
}

// Trace: `include/portable-endian.h:31`, `include/portable-endian.h:49`, `include/portable-endian.h:96`, `include/portable-endian.h:123`, `include/portable-endian.h:145`, `include/portable-endian.h:163`, `include/portable-endian.h:189`, `include/portable-endian.h:222`, `include/portable-endian.h:258`, `include/portable-endian.h:275`, `include/portable-endian.h:325`, `include/portable-endian.h:342`, `include/portable-endian.h:365`
// Spec: be32toh converts 32-bit big-endian input to host order#supported platform reads big-endian 32-bit value
// - **GIVEN** 编译目标命中 `include/portable-endian.h` 中任一支持的平台分支
// - **WHEN** 调用方使用 `be32toh(x)` 读取 32 位 big-endian 网络或协议字段
// - **THEN** 宏展开 MUST 使用该平台的网络序转换、byteswap 内建、系统 endian API 或恒等表达式返回 host-order 值
#[test]
fn test_portable_endian_supported_platform_reads_big_endian_32_bit_value() {
    assert_eq!(be32_to_host(0x1234_5678_u32.to_be()), 0x1234_5678);
}

// Trace: `include/portable-endian.h:32`, `include/portable-endian.h:50`, `include/portable-endian.h:121`, `include/portable-endian.h:143`, `include/portable-endian.h:161`, `include/portable-endian.h:187`, `include/portable-endian.h:220`, `include/portable-endian.h:256`, `include/portable-endian.h:273`, `include/portable-endian.h:323`, `include/portable-endian.h:340`, `include/portable-endian.h:363`
// Spec: htobe32 converts 32-bit host input to big-endian order#supported platform writes big-endian 32-bit value
// - **GIVEN** 编译目标命中 `include/portable-endian.h` 中任一支持的平台分支
// - **WHEN** 调用方使用 `htobe32(x)` 写入 32 位 big-endian 网络或协议字段
// - **THEN** 宏展开 MUST 使用该平台的网络序转换、byteswap 内建、系统 endian API 或恒等表达式生成 big-endian 值
#[test]
fn test_portable_endian_supported_platform_writes_big_endian_32_bit_value() {
    assert_eq!(host_to_be32(0x1234_5678), 0x1234_5678_u32.to_be());
}

// Trace: `include/portable-endian.h:33`, `include/portable-endian.h:51`, `include/portable-endian.h:122`, `include/portable-endian.h:144`, `include/portable-endian.h:162`, `include/portable-endian.h:188`, `include/portable-endian.h:221`, `include/portable-endian.h:257`, `include/portable-endian.h:274`, `include/portable-endian.h:324`, `include/portable-endian.h:341`, `include/portable-endian.h:364`
// Spec: htole32 converts 32-bit host input to little-endian order#supported platform writes little-endian 32-bit value
// - **GIVEN** 编译目标命中 `include/portable-endian.h` 中任一支持的平台分支
// - **WHEN** 调用方使用 `htole32(x)` 写入 SMB、DCERPC 或 NTLM little-endian 32 位字段
// - **THEN** 宏展开 MUST 在 little-endian 平台保持值不变，或在 big-endian 平台执行 32 位 byteswap
#[test]
fn test_portable_endian_supported_platform_writes_little_endian_32_bit_value() {
    assert_eq!(host_to_le32(0x1234_5678), 0x1234_5678_u32.to_le());
}

// Trace: `include/portable-endian.h:34`, `include/portable-endian.h:52`, `include/portable-endian.h:100`, `include/portable-endian.h:124`, `include/portable-endian.h:146`, `include/portable-endian.h:164`, `include/portable-endian.h:190`, `include/portable-endian.h:223`, `include/portable-endian.h:259`, `include/portable-endian.h:276`, `include/portable-endian.h:326`, `include/portable-endian.h:343`, `include/portable-endian.h:366`
// Spec: le32toh converts 32-bit little-endian input to host order#supported platform reads little-endian 32-bit value
// - **GIVEN** 编译目标命中 `include/portable-endian.h` 中任一支持的平台分支
// - **WHEN** 调用方使用 `le32toh(x)` 解析 SMB、DCERPC 或 NTLM little-endian 32 位字段
// - **THEN** 宏展开 MUST 在 little-endian 平台保持值不变，或在 big-endian 平台执行 32 位 byteswap
#[test]
fn test_portable_endian_supported_platform_reads_little_endian_32_bit_value() {
    assert_eq!(le32_to_host(0x1234_5678_u32.to_le()), 0x1234_5678);
}

// Trace: `include/portable-endian.h:54`, `include/portable-endian.h:128`, `include/portable-endian.h:150`, `include/portable-endian.h:168`, `include/portable-endian.h:194`, `include/portable-endian.h:227`, `include/portable-endian.h:263`, `include/portable-endian.h:280`, `include/portable-endian.h:330`, `include/portable-endian.h:347`, `include/portable-endian.h:370`
// Spec: be64toh converts 64-bit big-endian input to host order#supported platform reads big-endian 64-bit value
// - **GIVEN** 编译目标命中 `include/portable-endian.h` 中定义 `be64toh(x)` 的平台分支，或系统头已提供该宏
// - **WHEN** 调用方使用 `be64toh(x)` 读取 64 位 big-endian 协议字段
// - **THEN** 宏展开 MUST 使用该平台的 64 位 byteswap、系统 endian API 或恒等表达式返回 host-order 值
#[test]
fn test_portable_endian_supported_platform_reads_big_endian_64_bit_value() {
    assert_eq!(
        be64_to_host(0x1234_5678_9abc_def0_u64.to_be()),
        0x1234_5678_9abc_def0
    );
}

// Trace: `include/portable-endian.h:36`, `include/portable-endian.h:55`, `include/portable-endian.h:126`, `include/portable-endian.h:148`, `include/portable-endian.h:166`, `include/portable-endian.h:192`, `include/portable-endian.h:225`, `include/portable-endian.h:261`, `include/portable-endian.h:278`, `include/portable-endian.h:328`, `include/portable-endian.h:345`, `include/portable-endian.h:368`
// Spec: htobe64 converts 64-bit host input to big-endian order#supported platform writes big-endian 64-bit value
// - **GIVEN** 编译目标命中 `include/portable-endian.h` 中任一支持的平台分支
// - **WHEN** 调用方使用 `htobe64(x)` 写入 64 位 big-endian 协议字段
// - **THEN** 宏展开 MUST 使用该平台的 64 位 byteswap、系统 endian API、`be64toh(x)` 代理或恒等表达式生成 big-endian 值
#[test]
fn test_portable_endian_supported_platform_writes_big_endian_64_bit_value() {
    assert_eq!(
        host_to_be64(0x1234_5678_9abc_def0),
        0x1234_5678_9abc_def0_u64.to_be()
    );
}

// Trace: `include/portable-endian.h:37`, `include/portable-endian.h:56`, `include/portable-endian.h:127`, `include/portable-endian.h:149`, `include/portable-endian.h:167`, `include/portable-endian.h:193`, `include/portable-endian.h:226`, `include/portable-endian.h:262`, `include/portable-endian.h:279`, `include/portable-endian.h:329`, `include/portable-endian.h:346`, `include/portable-endian.h:369`
// Spec: htole64 converts 64-bit host input to little-endian order#supported platform writes little-endian 64-bit value
// - **GIVEN** 编译目标命中 `include/portable-endian.h` 中任一支持的平台分支
// - **WHEN** 调用方使用 `htole64(x)` 写入 SMB、DCERPC 或 NTLM little-endian 64 位字段
// - **THEN** 宏展开 MUST 在 little-endian 平台保持值不变，或在 big-endian 平台执行 64 位 byteswap
#[test]
fn test_portable_endian_supported_platform_writes_little_endian_64_bit_value() {
    assert_eq!(
        host_to_le64(0x1234_5678_9abc_def0),
        0x1234_5678_9abc_def0_u64.to_le()
    );
}

// Trace: `include/portable-endian.h:38`, `include/portable-endian.h:57`, `include/portable-endian.h:108`, `include/portable-endian.h:129`, `include/portable-endian.h:151`, `include/portable-endian.h:169`, `include/portable-endian.h:195`, `include/portable-endian.h:228`, `include/portable-endian.h:264`, `include/portable-endian.h:281`, `include/portable-endian.h:331`, `include/portable-endian.h:348`, `include/portable-endian.h:371`
// Spec: le64toh converts 64-bit little-endian input to host order#supported platform reads little-endian 64-bit value
// - **GIVEN** 编译目标命中 `include/portable-endian.h` 中任一支持的平台分支
// - **WHEN** 调用方使用 `le64toh(x)` 解析 SMB、DCERPC 或 NTLM little-endian 64 位字段
// - **THEN** 宏展开 MUST 在 little-endian 平台保持值不变，或在 big-endian 平台执行 64 位 byteswap
#[test]
fn test_portable_endian_supported_platform_reads_little_endian_64_bit_value() {
    assert_eq!(
        le64_to_host(0x1234_5678_9abc_def0_u64.to_le()),
        0x1234_5678_9abc_def0
    );
}
