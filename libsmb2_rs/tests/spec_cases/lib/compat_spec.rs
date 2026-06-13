use libsmb2_sys::include::portable_endian;

// Trace: `lib/compat.c:590`
// Spec: be64toh converts big-endian 64-bit values#caller converts network-order 64-bit integer
// - **GIVEN** 调用方传入 big-endian 64 位整数 `x`
// - **WHEN** 调用 `be64toh(x)`
// - **THEN** 实现 MUST 转换低 32 位和高 32 位并返回组合后的 host-order 值
#[test]
fn test_compat_caller_converts_network_order_64_bit_integer() {
    let host_value = 0x0102_0304_0506_0708_u64;
    let network_order = host_value.to_be();

    assert_eq!(portable_endian::be64_to_host(network_order), host_value);
}
