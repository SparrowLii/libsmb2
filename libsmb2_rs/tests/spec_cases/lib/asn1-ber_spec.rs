use libsmb2_sys::legacy::asn1_ber::{BerType, Decoder, Encoder, OidValue};

// Trace: `lib/asn1-ber.c:asn1ber_save_out_state`
// Spec: asn1ber_save_out_state snapshots encoder position#save valid output state
// - **GIVEN** `actx` 指向有效上下文，`actx->dst` 非空，`actx->dst_head < actx->dst_size`，且 `out_pos` 非空
// - **WHEN** 调用 `asn1ber_save_out_state(actx, out_pos)`
// - **THEN** 函数把当前 `actx->dst_head` 写入 `*out_pos` 并返回 `0`
#[test]
fn test_asn1_ber_save_valid_output_state() {
    let mut encoder = Encoder::with_capacity(8);

    assert_eq!(encoder.save_out_state(), Ok(0));
}

// Trace: `lib/asn1-ber.c:asn1ber_save_out_state`
// Spec: asn1ber_save_out_state snapshots encoder position#reject invalid save state inputs
// - **GIVEN** `out_pos`、`actx` 或 `actx->dst` 为空，或输出游标已经到达目标缓冲区容量
// - **WHEN** 调用 `asn1ber_save_out_state(actx, out_pos)`
// - **THEN** 函数返回 `-1`
#[test]
fn test_asn1_ber_reject_invalid_save_state_inputs() {
    let mut encoder = Encoder::with_capacity(0);

    assert_eq!(encoder.save_out_state(), Err(0));
}

// Trace: `lib/asn1-ber.c:asn1ber_annotate_length`
// Spec: asn1ber_annotate_length backfills reserved length bytes#backfill reserved length field
// - **GIVEN** 输出上下文有效，`out_pos` 是先前保存的位置，且其后已经预留 `reserved` 字节并写入负载
// - **WHEN** 调用 `asn1ber_annotate_length(actx, out_pos, reserved)`
// - **THEN** 函数根据 `dst_head - out_pos - reserved` 生成 BER 长度，必要时移动负载覆盖未使用预留空间，并把 `dst_head` 恢复到新结束位置
#[test]
fn test_asn1_ber_backfill_reserved_length_field() {
    let mut encoder = Encoder::with_capacity(16);
    let out_pos = encoder.save_out_state().unwrap();
    encoder.reserve_length(4).unwrap();
    encoder
        .encode_bytes(BerType::OctetString, &[1, 2, 3])
        .unwrap();

    encoder.annotate_length(out_pos, 4).unwrap();

    assert_eq!(encoder.bytes(), &[5, 4, 3, 1, 2, 3]);
}

// Trace: `lib/asn1-ber.c:asn1ber_length_from_ber`
// Spec: asn1ber_length_from_ber decodes BER length#decode short form length
// - **GIVEN** 输入流下一个字节最高位未置位
// - **WHEN** 调用 `asn1ber_length_from_ber(actx, len)`
// - **THEN** 函数把该字节值写入 `*len` 并返回 `0`
#[test]
fn test_asn1_ber_decode_short_form_length() {
    let mut decoder = Decoder::new(&[0x7f]);

    assert_eq!(decoder.decode_length(), Ok(0x7f));
}

// Trace: `lib/asn1-ber.c:asn1ber_length_from_ber`
// Spec: asn1ber_length_from_ber decodes BER length#reject oversized long form length
// - **GIVEN** 输入流长度首字节最高位置位且低 7 位大于 `4`
// - **WHEN** 调用 `asn1ber_length_from_ber(actx, len)`
// - **THEN** 函数设置 `actx->last_error` 为 `-E2BIG` 并返回 `-1`
#[test]
fn test_asn1_ber_reject_oversized_long_form_length() {
    let mut decoder = Decoder::new(&[0x85]);
    let err = decoder.decode_length().unwrap_err();

    assert_eq!(err, -7);
    assert_eq!(decoder.last_error(), -7);
}

// Trace: `lib/asn1-ber.c:ber_typecode_from_ber`
// Spec: ber_typecode_from_ber decodes type code#decode direct type code
// - **GIVEN** 输入流下一个 BER 类型字节的低 5 位不是 `0x1F`
// - **WHEN** 调用 `ber_typecode_from_ber(actx, typecode)`
// - **THEN** 函数把该字节转换为 `ber_type_t` 写入 `*typecode` 并返回 `0`
#[test]
fn test_asn1_ber_decode_direct_type_code() {
    let mut decoder = Decoder::new(&[0x04]);

    assert_eq!(decoder.decode_typecode(), Ok(0x04));
}

// Trace: `lib/asn1-ber.c:ber_typelen_from_ber`
// Spec: ber_typelen_from_ber decodes type and length#decode type followed by length
// - **GIVEN** 输入流包含有效 BER 类型码和长度字段
// - **WHEN** 调用 `ber_typelen_from_ber(actx, typecode, len)`
// - **THEN** 函数写入 `*typecode` 与 `*len` 并返回 `0`
#[test]
fn test_asn1_ber_decode_type_followed_by_length() {
    let mut decoder = Decoder::new(&[0x04, 0x03]);

    assert_eq!(decoder.decode_typelen(), Ok((0x04, 3)));
}

// Trace: `lib/asn1-ber.c:asn1ber_request_from_ber`
// Spec: asn1ber_request_from_ber decodes request header#decode request opcode and length
// - **GIVEN** 输入流当前位置包含请求类型码和 BER 长度
// - **WHEN** 调用 `asn1ber_request_from_ber(actx, opcode, len)`
// - **THEN** 函数写入 `*opcode` 和 `*len`，并在成功时返回 `0`
#[test]
fn test_asn1_ber_decode_request_opcode_and_length() {
    let mut decoder = Decoder::new(&[0x30, 0x02]);

    assert_eq!(decoder.decode_request(), Ok((0x30, 2)));
}

// Trace: `lib/asn1-ber.c:asn1ber_struct_from_ber`
// Spec: asn1ber_struct_from_ber validates structure type#reject non-structure type
// - **GIVEN** 输入流包含的类型长度字段类型码不是 `asnSTRUCT`
// - **WHEN** 调用 `asn1ber_struct_from_ber(actx, len)`
// - **THEN** 函数设置 `actx->last_error` 为 `-EINVAL` 并返回 `-1`
#[test]
fn test_asn1_ber_reject_non_structure_type() {
    let mut decoder = Decoder::new(&[0x05, 0x00]);
    let err = decoder.decode_struct_len().unwrap_err();

    assert_eq!(err, -22);
    assert_eq!(decoder.last_error(), -22);
}

// Trace: `lib/asn1-ber.c:asn1ber_null_from_ber`
// Spec: asn1ber_null_from_ber validates NULL type#reject non-NULL type
// - **GIVEN** 输入流包含的类型长度字段类型码不是 `asnNULL`
// - **WHEN** 调用 `asn1ber_null_from_ber(actx, len)`
// - **THEN** 函数设置 `actx->last_error` 为 `-EINVAL` 并返回 `-1`
#[test]
fn test_asn1_ber_reject_non_null_type() {
    let mut decoder = Decoder::new(&[0x30, 0x00]);
    let err = decoder.decode_null_len().unwrap_err();

    assert_eq!(err, -22);
    assert_eq!(decoder.last_error(), -22);
}

// Trace: `lib/asn1-ber.c:asn1ber_int32_from_ber`
// Spec: asn1ber_int32_from_ber decodes signed 32-bit integer#decode signed 32-bit value
// - **GIVEN** 输入流包含 `BER_INTEGER` 或 `BER_COUNTER`，长度为 `1..4`，且后续值字节完整
// - **WHEN** 调用 `asn1ber_int32_from_ber(actx, val)`
// - **THEN** 函数按大端顺序组合值字节，依据首字节最高位符号扩展，写入 `*val` 并返回 `0`
#[test]
fn test_asn1_ber_decode_signed_32_bit_value() {
    let mut decoder = Decoder::new(&[0x02, 0x02, 0xff, 0xfe]);

    assert_eq!(decoder.decode_int32(), Ok(-2));
}

// Trace: `lib/asn1-ber.c:asn1ber_int32_from_ber`
// Spec: asn1ber_int32_from_ber decodes signed 32-bit integer#reject invalid int32 type or length
// - **GIVEN** 输入类型不是允许的整数类型，或长度为 `0` 或大于 `4`
// - **WHEN** 调用 `asn1ber_int32_from_ber(actx, val)`
// - **THEN** 函数设置 `actx->last_error` 为 `-EINVAL` 或 `-E2BIG`，返回 `-1`，并在长度错误路径把 `*val` 置为 `0`
#[test]
fn test_asn1_ber_reject_invalid_int32_type_or_length() {
    let mut decoder = Decoder::new(&[0x02, 0x00]);
    let err = decoder.decode_int32().unwrap_err();

    assert_eq!(err, -7);
    assert_eq!(decoder.last_error(), -7);
}

// Trace: `lib/asn1-ber.c:asn1ber_uint32_from_ber`
// Spec: asn1ber_uint32_from_ber decodes unsigned 32-bit value#decode unsigned 32-bit value
// - **GIVEN** 输入流包含允许的 32 位无符号兼容类型，长度为 `1..4`，且后续值字节完整
// - **WHEN** 调用 `asn1ber_uint32_from_ber(actx, val)`
// - **THEN** 函数按大端顺序组合值字节，写入 `*val` 并返回 `0`
#[test]
fn test_asn1_ber_decode_unsigned_32_bit_value() {
    let mut decoder = Decoder::new(&[0x42, 0x04, 0x12, 0x34, 0x56, 0x78]);

    assert_eq!(decoder.decode_uint32(), Ok(0x1234_5678));
}

// Trace: `lib/asn1-ber.c:asn1ber_int64_from_ber`
// Spec: asn1ber_int64_from_ber decodes signed 64-bit integer#decode signed 64-bit value
// - **GIVEN** 输入流包含 `BER_INTEGER64`，长度为 `1..8`，且后续值字节完整
// - **WHEN** 调用 `asn1ber_int64_from_ber(actx, val)`
// - **THEN** 函数按大端顺序组合值字节，依据首字节最高位符号扩展，写入 `*val` 并返回 `0`
#[test]
fn test_asn1_ber_decode_signed_64_bit_value() {
    let mut decoder = Decoder::new(&[0x4a, 0x02, 0xff, 0xfe]);

    assert_eq!(decoder.decode_int64(), Ok(-2));
}

// Trace: `lib/asn1-ber.c:asn1ber_uint64_from_ber`
// Spec: asn1ber_uint64_from_ber decodes unsigned 64-bit value#decode unsigned 64-bit value
// - **GIVEN** 输入流包含 `BER_UNSIGNED64` 或 `BER_COUNTER64`，长度为 `1..8`，且后续值字节完整
// - **WHEN** 调用 `asn1ber_uint64_from_ber(actx, val)`
// - **THEN** 函数按大端顺序组合值字节，写入 `*val` 并返回 `0`
#[test]
fn test_asn1_ber_decode_unsigned_64_bit_value() {
    let mut decoder = Decoder::new(&[0x4b, 0x08, 1, 2, 3, 4, 5, 6, 7, 8]);

    assert_eq!(decoder.decode_uint64(), Ok(0x0102_0304_0506_0708));
}

// Trace: `lib/asn1-ber.c:asn1ber_oid_from_ber`
// Spec: asn1ber_oid_from_ber decodes object identifier#decode object identifier elements
// - **GIVEN** 输入流包含 `BER_OBJECT_ID`、有效长度和完整 OID value 字节
// - **WHEN** 调用 `asn1ber_oid_from_ber(actx, oid)`
// - **THEN** 函数写入 `oid->elements`，把 `oid->length` 设置为解码出的元素数量，并返回 `0`
#[test]
fn test_asn1_ber_decode_object_identifier_elements() {
    let mut decoder = Decoder::new(&[0x06, 0x06, 43, 6, 1, 5, 5, 2]);

    assert_eq!(
        decoder.decode_oid().unwrap().elements,
        vec![1, 3, 6, 1, 5, 5, 2]
    );
}

// Trace: `lib/asn1-ber.c:asn1ber_oid_from_ber`
// Spec: asn1ber_oid_from_ber decodes object identifier#reject oversized or empty OID payload
// - **GIVEN** OID 长度为 `0` 或大于 `BER_MAX_OID_ELEMENTS`
// - **WHEN** 调用 `asn1ber_oid_from_ber(actx, oid)`
// - **THEN** 函数设置 `actx->last_error` 为 `-E2BIG` 并返回 `-1`
#[test]
fn test_asn1_ber_reject_oversized_or_empty_oid_payload() {
    let mut decoder = Decoder::new(&[0x06, 0x00]);
    let err = decoder.decode_oid().unwrap_err();

    assert_eq!(err, -7);
    assert_eq!(decoder.last_error(), -7);
}

// Trace: `lib/asn1-ber.c:asn1ber_bytes_from_ber`
// Spec: asn1ber_bytes_from_ber decodes octet string bytes#decode non-empty octet string
// - **GIVEN** 输入流包含 `asnOCTET_STRING`、长度不超过 `maxlen` 且后续字节完整
// - **WHEN** 调用 `asn1ber_bytes_from_ber(actx, val, maxlen, lenout)`
// - **THEN** 函数复制所有值字节，写入实际长度到 `*lenout`，并在 `i < maxlen` 时写入一个 NUL 终止字节
#[test]
fn test_asn1_ber_decode_non_empty_octet_string() {
    let mut decoder = Decoder::new(&[0x04, 0x03, b'a', b'b', b'c']);

    assert_eq!(decoder.decode_bytes(4), Ok((vec![b'a', b'b', b'c', 0], 3)));
}

// Trace: `lib/asn1-ber.c:asn1ber_string_from_ber`
// Spec: asn1ber_string_from_ber delegates to byte decoder#decode string as octet string
// - **GIVEN** 调用方提供字符缓冲区、容量和长度输出指针
// - **WHEN** 调用 `asn1ber_string_from_ber(actx, val, maxlen, lenout)`
// - **THEN** 函数以 `uint8_t *` 形式转发 `val` 给 `asn1ber_bytes_from_ber` 并返回其结果
#[test]
fn test_asn1_ber_decode_string_as_octet_string() {
    let mut decoder = Decoder::new(&[0x04, 0x03, b'a', b'b', b'c']);

    assert_eq!(decoder.decode_string(4), Ok(("abc".to_string(), 3)));
}

// Trace: `lib/asn1-ber.c:asn1ber_ber_from_length`
// Spec: asn1ber_ber_from_length encodes BER length#encode long form length
// - **GIVEN** `lenin` 大于或等于 `128` 且输出缓冲区有足够空间
// - **WHEN** 调用 `asn1ber_ber_from_length(actx, lenin, lenout)`
// - **THEN** 函数写入 `0x80 | lenbytesneeded` 以及大端长度字节，写入长度字段字节数到 `*lenout` 并返回 `0`
#[test]
fn test_asn1_ber_encode_long_form_length() {
    let mut encoder = Encoder::with_capacity(4);

    assert_eq!(encoder.encode_length(0x1234), Ok(3));
    assert_eq!(encoder.bytes(), &[0x82, 0x12, 0x34]);
}

// Trace: `lib/asn1-ber.c:asn1ber_ber_reserve_length`
// Spec: asn1ber_ber_reserve_length writes zero placeholders#reserve length bytes
// - **GIVEN** 输出缓冲区可写入请求数量的占位字节
// - **WHEN** 调用 `asn1ber_ber_reserve_length(actx, len)`
// - **THEN** 函数写入 `len` 个 `0` 字节并返回 `0`
#[test]
fn test_asn1_ber_reserve_length_bytes() {
    let mut encoder = Encoder::with_capacity(4);

    encoder.reserve_length(3).unwrap();

    assert_eq!(encoder.bytes(), &[0, 0, 0]);
}

// Trace: `lib/asn1-ber.c:asn1ber_ber_from_typecode`
// Spec: asn1ber_ber_from_typecode writes BER type byte#write type code byte
// - **GIVEN** 输出缓冲区可写入一个字节
// - **WHEN** 调用 `asn1ber_ber_from_typecode(actx, typecode)`
// - **THEN** 函数写入类型码字节并返回 `0`
#[test]
fn test_asn1_ber_write_type_code_byte() {
    let mut encoder = Encoder::with_capacity(1);

    encoder.encode_typecode(BerType::OctetString).unwrap();

    assert_eq!(encoder.bytes(), &[0x04]);
}

// Trace: `lib/asn1-ber.c:asn1ber_ber_from_typelen`
// Spec: asn1ber_ber_from_typelen writes type and length#write BER type and length prefix
// - **GIVEN** 输出缓冲区可容纳类型码和 `lenin` 对应的 BER 长度字段
// - **WHEN** 调用 `asn1ber_ber_from_typelen(actx, typecode, lenin, lenout)`
// - **THEN** 函数写入类型码和长度字段，将 `*lenout` 设置为长度字段字节数加 `1`，并返回 `0`
#[test]
fn test_asn1_ber_write_ber_type_and_length_prefix() {
    let mut encoder = Encoder::with_capacity(4);

    assert_eq!(encoder.encode_typelen(BerType::OctetString, 0x80), Ok(3));
    assert_eq!(encoder.bytes(), &[0x04, 0x81, 0x80]);
}

// Trace: `lib/asn1-ber.c:asn1ber_ber_from_int32`
// Spec: asn1ber_ber_from_int32 encodes signed 32-bit integer#encode signed 32-bit value
// - **GIVEN** 输出缓冲区可容纳 type-length 前缀和计算出的值字节
// - **WHEN** 调用 `asn1ber_ber_from_int32(actx, type, val)`
// - **THEN** 函数写入给定类型、最短 BER 长度和值字节，并返回 `0`
#[test]
fn test_asn1_ber_encode_signed_32_bit_value() {
    let mut encoder = Encoder::with_capacity(4);

    encoder.encode_int32(BerType::Integer, 0x1234).unwrap();

    assert_eq!(encoder.bytes(), &[0x02, 0x02, 0x12, 0x34]);
}

// Trace: `lib/asn1-ber.c:asn1ber_ber_from_uint32`
// Spec: asn1ber_ber_from_uint32 encodes unsigned 32-bit integer#encode unsigned 32-bit value
// - **GIVEN** 输出缓冲区可容纳 type-length 前缀和计算出的值字节
// - **WHEN** 调用 `asn1ber_ber_from_uint32(actx, type, val)`
// - **THEN** 函数写入给定类型、最短 BER 长度和值字节，并返回 `0`
#[test]
fn test_asn1_ber_encode_unsigned_32_bit_value() {
    let mut encoder = Encoder::with_capacity(6);

    encoder.encode_uint32(BerType::Unsigned, 0x1234).unwrap();

    assert_eq!(encoder.bytes(), &[0x42, 0x02, 0x12, 0x34]);
}

// Trace: `lib/asn1-ber.c:asn1ber_ber_from_int64`
// Spec: asn1ber_ber_from_int64 encodes signed 64-bit integer#encode signed 64-bit value
// - **GIVEN** 输出缓冲区可容纳 type-length 前缀和计算出的值字节
// - **WHEN** 调用 `asn1ber_ber_from_int64(actx, type, val)`
// - **THEN** 函数写入给定类型、最短 BER 长度和值字节，并返回 `0`
#[test]
fn test_asn1_ber_encode_signed_64_bit_value() {
    let mut encoder = Encoder::with_capacity(6);

    encoder.encode_int64(BerType::Integer64, 0x1234).unwrap();

    assert_eq!(encoder.bytes(), &[0x4a, 0x02, 0x12, 0x34]);
}

// Trace: `lib/asn1-ber.c:asn1ber_ber_from_uint64`
// Spec: asn1ber_ber_from_uint64 encodes unsigned 64-bit integer#encode unsigned 64-bit value
// - **GIVEN** 输出缓冲区可容纳 type-length 前缀和计算出的值字节
// - **WHEN** 调用 `asn1ber_ber_from_uint64(actx, type, val)`
// - **THEN** 函数写入给定类型、计算出的 BER 长度和值字节，并返回 `0`
#[test]
fn test_asn1_ber_encode_unsigned_64_bit_value() {
    let mut encoder = Encoder::with_capacity(8);

    encoder
        .encode_uint64(BerType::Unsigned64, 0x0102_0304_0506_0708)
        .unwrap();

    assert_eq!(encoder.bytes(), &[0x4b, 0x04, 0x05, 0x06, 0x07, 0x08]);
}

// Trace: `lib/asn1-ber.c:asn1ber_ber_from_oid`, `tests/ntlmssp_generate_blob.c:main`
// Spec: asn1ber_ber_from_oid encodes object identifier#encode OID with combined first two elements
// - **GIVEN** `oid` 非空，`oid->length` 小于 `BER_MAX_OID_ELEMENTS`，且前两个元素存在并且第一个元素小于 `40`
// - **WHEN** 调用 `asn1ber_ber_from_oid(actx, oid)`
// - **THEN** 函数写入 `BER_OBJECT_ID`，将前两个元素编码为 `elements[0] * 40 + elements[1]`，编码后续元素，回填长度并返回 `0`
#[test]
fn test_asn1_ber_encode_oid_with_combined_first_two_elements() {
    let mut encoder = Encoder::with_capacity(16);

    encoder
        .encode_oid(&OidValue {
            elements: vec![1, 3, 6, 1, 5, 5, 2],
        })
        .unwrap();

    assert_eq!(encoder.bytes(), &[0x06, 0x06, 43, 6, 1, 5, 5, 2]);
}

// Trace: `lib/asn1-ber.c:asn1ber_ber_from_bytes`
// Spec: asn1ber_ber_from_bytes encodes byte string#encode bytes with caller-specified type
// - **GIVEN** 输出缓冲区可容纳 type-length 前缀和 `len` 个输入字节
// - **WHEN** 调用 `asn1ber_ber_from_bytes(actx, type, val, len)`
// - **THEN** 函数写入指定类型、长度和每个输入字节，并返回 `0`
#[test]
fn test_asn1_ber_encode_bytes_with_caller_specified_type() {
    let mut encoder = Encoder::with_capacity(8);

    encoder.encode_bytes(BerType::OctetString, b"abc").unwrap();

    assert_eq!(encoder.bytes(), &[0x04, 0x03, b'a', b'b', b'c']);
}

// Trace: `lib/asn1-ber.c:asn1ber_ber_from_string`
// Spec: asn1ber_ber_from_string encodes string as octet string#encode string payload
// - **GIVEN** 调用方提供字符指针和长度
// - **WHEN** 调用 `asn1ber_ber_from_string(actx, val, len)`
// - **THEN** 函数以 `BER_OCTET_STRING` 和 `uint8_t *` 形式转发给 `asn1ber_ber_from_bytes` 并返回其结果
#[test]
fn test_asn1_ber_encode_string_payload() {
    let mut encoder = Encoder::with_capacity(8);

    encoder.encode_string("abc").unwrap();

    assert_eq!(encoder.bytes(), &[0x04, 0x03, b'a', b'b', b'c']);
}
