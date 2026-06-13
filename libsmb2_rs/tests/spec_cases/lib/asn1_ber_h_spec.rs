use libsmb2_sys::legacy::asn1_ber::{BerType, Decoder, Encoder, OidValue};

const BER_MAX_OID_ELEMENTS: usize = 32;
const ASN_CONSTRUCTOR: u8 = 0x20;
const ASN_CONTEXT_SPECIFIC: u8 = 0x80;
const ASN_PRIVATE: u8 = 0xc0;

// Trace: `lib/asn1-ber.h:BER_MAX_OID_ELEMENTS`, `lib/asn1-ber.h:struct asn1ber_oid_value`, `lib/asn1-ber.c:asn1ber_oid_from_ber`
// Spec: BER_MAX_OID_ELEMENTS preserve OID capacity#allocate fixed OID storage
// - **GIVEN** 调用方包含 `lib/asn1-ber.h` 并声明 `struct asn1ber_oid_value`。
// - **WHEN** 调用方访问 `elements` 数组或使用 OID 编解码接口。
// - **THEN** 可用元素容量为 `BER_MAX_OID_ELEMENTS` 个 `beroid_type_t` 元素，源码声明的上限为 32。
#[test]
fn test_asn1_ber_h_allocate_fixed_oid_storage() {
    let oid = OidValue {
        elements: vec![1; BER_MAX_OID_ELEMENTS],
    };

    assert_eq!(oid.elements.len(), 32);
}

// Trace: `lib/asn1-ber.h:beroid_type_t`, `lib/spnego-wrapper.c:oid_gss_mech_spnego`
// Spec: beroid_type_t expose OID element type#initialize OID elements
// - **GIVEN** 调用方需要定义 ASN.1 object identifier 元素序列。
// - **WHEN** 调用方使用 `struct asn1ber_oid_value.elements` 或 `beroid_type_t` 值初始化 OID。
// - **THEN** 每个元素按照 `uint32_t` 存储，并可传入 OID 编码和解码接口。
#[test]
fn test_asn1_ber_h_initialize_oid_elements() {
    let oid = OidValue {
        elements: vec![1_u32, 3, 6, 1, 5, 5, 2],
    };
    let mut encoder = Encoder::with_capacity(16);

    encoder.encode_oid(&oid).unwrap();

    assert_eq!(encoder.bytes(), &[0x06, 0x06, 43, 6, 1, 5, 5, 2]);
}

// Trace: `lib/asn1-ber.h:asnUNIVERSAL`, `lib/asn1-ber.h:asnCONTEXT_SPECIFIC`, `lib/spnego-wrapper.c:smb2_spnego_create_negotiate_reply_blob`
// Spec: asn tag macros preserve BER tag constants#emit declared ASN.1 tag value
// - **GIVEN** 调用方包含 `lib/asn1-ber.h` 并使用任一 `asn*` tag 宏。
// - **WHEN** 该宏参与 BER type octet 编码或比较。
// - **THEN** 宏展开值与 `lib/asn1-ber.h` 中对应的十六进制声明值一致。
#[test]
fn test_asn1_ber_h_emit_declared_asn_1_tag_value() {
    let mut encoder = Encoder::with_capacity(1);

    encoder.encode_typecode(BerType::Struct).unwrap();

    assert_eq!(encoder.bytes(), &[0x30]);
}

// Trace: `lib/asn1-ber.h:ber_type_t`, `lib/asn1-ber.c:ber_typecode_from_ber`, `lib/asn1-ber.c:asn1ber_uint32_from_ber`
// Spec: ber_type_t expose BER and SNMP type codes#compare decoded type code
// - **GIVEN** 解码函数读取 BER type octet 并写入 `ber_type_t` 输出参数。
// - **WHEN** 调用方或内部实现将该值与 `BER_INTEGER`、`BER_OBJECT_ID` 或 application 类型比较。
// - **THEN** 比较值与头文件声明的枚举常量一致。
#[test]
fn test_asn1_ber_h_compare_decoded_type_code() {
    let mut decoder = Decoder::new(&[0x06]);

    assert_eq!(decoder.decode_typecode(), Ok(BerType::ObjectId as u32));
}

// Trace: `lib/asn1-ber.h:ASN1_SEQUENCE`, `lib/spnego-wrapper.c:smb2_spnego_wrap_gssapi`
// Spec: ASN1_SEQUENCE construct sequence tag#encode sequence wrapper
// - **GIVEN** SPNEGO 编码路径需要写入 sequence wrapper type octet。
// - **WHEN** 调用方使用 `ASN1_SEQUENCE(0)` 并传给 `asn1ber_ber_from_typecode`。
// - **THEN** 写出的 type octet 为 `asnSTRUCT | 0`。
#[test]
fn test_asn1_ber_h_encode_sequence_wrapper() {
    let mut encoder = Encoder::with_capacity(1);

    encoder.encode_typecode(BerType::Struct).unwrap();

    assert_eq!(encoder.bytes(), &[0x30]);
}

// Trace: `lib/asn1-ber.h:ASN1_CONTEXT`, `lib/spnego-wrapper.c:smb2_spnego_wrap_ntlmssp_challenge`
// Spec: ASN1_CONTEXT construct context tag#encode constructed context field
// - **GIVEN** SPNEGO 编码路径需要写入 context-specific constructed 字段。
// - **WHEN** 调用方使用 `ASN1_CONTEXT(0)` 或其他索引并传给 `asn1ber_ber_from_typecode`。
// - **THEN** 写出的 type octet 同时包含 context-specific class、constructed 位和调用方提供的低位索引。
#[test]
fn test_asn1_ber_h_encode_constructed_context_field() {
    let context_tag = ASN_CONTEXT_SPECIFIC | ASN_CONSTRUCTOR | 3;

    assert_eq!(context_tag, 0xa3);
}

// Trace: `lib/asn1-ber.h:ASN1_CONTEXT_SIMPLE`
// Spec: ASN1_CONTEXT_SIMPLE construct simple context tag#derive simple context type
// - **GIVEN** 调用方需要 context-specific simple type octet。
// - **WHEN** 调用方展开 `ASN1_CONTEXT_SIMPLE(n)`。
// - **THEN** 结果只包含 context-specific class 位和调用方提供的低位索引，不包含 `asnCONSTRUCTOR` 位。
#[test]
fn test_asn1_ber_h_derive_simple_context_type() {
    let simple_tag = ASN_CONTEXT_SPECIFIC | 3;

    assert_eq!(simple_tag, 0x83);
    assert_eq!(simple_tag & ASN_CONSTRUCTOR, 0);
}

// Trace: `lib/asn1-ber.h:ASN1_PRIVATE`, `lib/asn1-ber.h:asnPRIVATE`
// Spec: ASN1_PRIVATE expose private class alias#read private class constant
// - **GIVEN** 调用方包含 `lib/asn1-ber.h`。
// - **WHEN** 调用方读取 `ASN1_PRIVATE`。
// - **THEN** 该宏展开为源码声明的 `asnPRIVATE` 值 `0xC0`。
#[test]
fn test_asn1_ber_h_read_private_class_constant() {
    assert_eq!(ASN_PRIVATE, 0xc0);
}

// Trace: `lib/asn1-ber.h:struct asn1ber_context`, `lib/asn1-ber.c:asn1ber_out_byte`, `lib/spnego-wrapper.c:smb2_spnego_wrap_gssapi`
// Spec: struct asn1ber_context carry BER cursor state#encode into caller-provided buffer
// - **GIVEN** 调用方初始化 `dst`、`dst_size` 和 `dst_head` 字段。
// - **WHEN** 调用方执行任一 `asn1ber_ber_from_*` 编码接口。
// - **THEN** 编码接口从 `dst_head` 位置写入 `dst`，并按实际写入字节推进 `dst_head` 或在空间不足时返回错误。
#[test]
fn test_asn1_ber_h_encode_into_caller_provided_buffer() {
    let mut encoder = Encoder::with_capacity(4);

    encoder.encode_typecode(BerType::OctetString).unwrap();
    encoder.encode_length(1).unwrap();

    assert_eq!(encoder.bytes(), &[0x04, 0x01]);
}

// Trace: `lib/asn1-ber.h:struct asn1ber_context`, `lib/asn1-ber.c:asn1ber_next_byte`, `lib/spnego-wrapper.c:smb2_spnego_decode_negTokenInit`
// Spec: struct asn1ber_context carry BER cursor state#decode from caller-provided buffer
// - **GIVEN** 调用方初始化 `src`、`src_count` 和 `src_tail` 字段。
// - **WHEN** 调用方执行任一 `*_from_ber` 解码接口。
// - **THEN** 解码接口从 `src_tail` 位置读取 `src`，并按实际读取字节推进 `src_tail` 或在输入不足时返回错误。
#[test]
fn test_asn1_ber_h_decode_from_caller_provided_buffer() {
    let mut decoder = Decoder::new(&[0x04, 0x01, b'a']);

    assert_eq!(decoder.decode_typelen(), Ok((0x04, 1)));
}

// Trace: `lib/asn1-ber.h:struct asn1ber_oid_value`, `lib/asn1-ber.c:asn1ber_ber_from_oid`, `lib/spnego-wrapper.c:oid_spnego_mech_ntlmssp`
// Spec: struct asn1ber_oid_value carry bounded OID values#encode static OID value
// - **GIVEN** 调用方提供 `length` 和对应数量的 `elements`。
// - **WHEN** 调用方调用 `asn1ber_ber_from_oid`。
// - **THEN** 编码实现使用前 `length` 个元素生成 BER object identifier 内容，且 `length` 不得达到或超过 `BER_MAX_OID_ELEMENTS`。
#[test]
fn test_asn1_ber_h_encode_static_oid_value() {
    let mut encoder = Encoder::with_capacity(16);

    encoder
        .encode_oid(&OidValue {
            elements: vec![1, 3, 6],
        })
        .unwrap();

    assert_eq!(encoder.bytes(), &[0x06, 0x02, 43, 6]);
}

// Trace: `lib/asn1-ber.h:asn1ber_save_out_state`, `lib/asn1-ber.c:asn1ber_save_out_state`, `lib/spnego-wrapper.c:smb2_spnego_create_negotiate_reply_blob`
// Spec: asn1ber_save_out_state snapshot output position#save length placeholder position
// - **GIVEN** 调用方正在编码嵌套 BER 结构，且输出上下文有效。
// - **WHEN** 调用方调用 `asn1ber_save_out_state(actx, &out_pos)`。
// - **THEN** `out_pos` 接收当前 `dst_head`，后续可传给 `asn1ber_annotate_length` 回填该位置的长度。
#[test]
fn test_asn1_ber_h_save_length_placeholder_position() {
    let mut encoder = Encoder::with_capacity(8);

    assert_eq!(encoder.save_out_state(), Ok(0));
}

// Trace: `lib/asn1-ber.h:asn1ber_annotate_length`, `lib/asn1-ber.c:asn1ber_annotate_length`, `lib/spnego-wrapper.c:smb2_spnego_wrap_ntlmssp_challenge`
// Spec: asn1ber_annotate_length backfill reserved length#shrink reserved length field
// - **GIVEN** 调用方先在 `out_pos` 预留了 length 字节，随后写入 payload。
// - **WHEN** 调用方调用 `asn1ber_annotate_length(actx, out_pos, reserved)`。
// - **THEN** 函数在 `out_pos` 位置写入实际 payload 长度，并让 `dst_head` 指向紧随 length 和 payload 后的新结尾。
#[test]
fn test_asn1_ber_h_shrink_reserved_length_field() {
    let mut encoder = Encoder::with_capacity(16);
    let out_pos = encoder.save_out_state().unwrap();
    encoder.reserve_length(4).unwrap();
    encoder
        .encode_bytes(BerType::OctetString, &[1, 2, 3])
        .unwrap();

    encoder.annotate_length(out_pos, 4).unwrap();

    assert_eq!(encoder.bytes(), &[5, 4, 3, 1, 2, 3]);
}

// Trace: `lib/asn1-ber.h:asn1ber_length_from_ber`, `lib/asn1-ber.c:asn1ber_length_from_ber`
// Spec: asn1ber_length_from_ber decode BER length#decode short-form length
// - **GIVEN** 输入流下一个字节未设置高位。
// - **WHEN** 调用方调用 `asn1ber_length_from_ber(actx, &len)`。
// - **THEN** `len` 等于该字节值，函数返回 0，并消耗 1 个输入字节。
#[test]
fn test_asn1_ber_h_decode_short_form_length() {
    let mut decoder = Decoder::new(&[0x7f]);

    assert_eq!(decoder.decode_length(), Ok(0x7f));
}

// Trace: `lib/asn1-ber.h:asn1ber_length_from_ber`, `lib/asn1-ber.c:asn1ber_length_from_ber`
// Spec: asn1ber_length_from_ber decode BER length#reject oversized long-form length header
// - **GIVEN** 输入流下一个 length 字节设置高位且低 7 位大于 4。
// - **WHEN** 调用方调用 `asn1ber_length_from_ber(actx, &len)`。
// - **THEN** 函数返回 `-1`，并将 `actx->last_error` 设置为 `-E2BIG`。
#[test]
fn test_asn1_ber_h_reject_oversized_long_form_length_header() {
    let mut decoder = Decoder::new(&[0x85]);

    assert_eq!(decoder.decode_length(), Err(-7));
    assert_eq!(decoder.last_error(), -7);
}

// Trace: `lib/asn1-ber.h:ber_typecode_from_ber`, `lib/asn1-ber.c:ber_typecode_from_ber`
// Spec: ber_typecode_from_ber decode BER type code#decode direct type code
// - **GIVEN** 输入流下一个 type octet 的低 5 位不是 `0x1F`。
// - **WHEN** 调用方调用 `ber_typecode_from_ber(actx, &typecode)`。
// - **THEN** `typecode` 等于该 type octet，函数返回 0。
#[test]
fn test_asn1_ber_h_decode_direct_type_code() {
    let mut decoder = Decoder::new(&[0x04]);

    assert_eq!(decoder.decode_typecode(), Ok(0x04));
}

// Trace: `lib/asn1-ber.h:ber_typelen_from_ber`, `lib/asn1-ber.c:ber_typelen_from_ber`
// Spec: ber_typelen_from_ber decode type and length#decode BER header pair
// - **GIVEN** 输入流当前位置包含 BER type 后跟 BER length。
// - **WHEN** 调用方调用 `ber_typelen_from_ber(actx, &typecode, &len)`。
// - **THEN** `typecode` 和 `len` 分别接收解码结果，输入游标推进到 value 起始位置。
#[test]
fn test_asn1_ber_h_decode_ber_header_pair() {
    let mut decoder = Decoder::new(&[0x04, 0x03]);

    assert_eq!(decoder.decode_typelen(), Ok((0x04, 3)));
}

// Trace: `lib/asn1-ber.h:asn1ber_request_from_ber`, `lib/asn1-ber.c:asn1ber_request_from_ber`
// Spec: asn1ber_request_from_ber decode request header#decode request opcode and length
// - **GIVEN** 输入流当前位置包含 ASN.1 request 的 type 和 length。
// - **WHEN** 调用方调用 `asn1ber_request_from_ber(actx, &opcode, &len)`。
// - **THEN** `opcode` 和 `len` 与 `ber_typelen_from_ber` 解码结果一致，错误返回值被原样传播。
#[test]
fn test_asn1_ber_h_decode_request_opcode_and_length() {
    let mut decoder = Decoder::new(&[0x30, 0x02]);

    assert_eq!(decoder.decode_request(), Ok((0x30, 2)));
}

// Trace: `lib/asn1-ber.h:asn1ber_struct_from_ber`, `lib/asn1-ber.c:asn1ber_struct_from_ber`
// Spec: asn1ber_struct_from_ber require struct tag#accept struct header
// - **GIVEN** 输入流当前位置的 typecode 为 `asnSTRUCT`，后面跟随 BER length。
// - **WHEN** 调用方调用 `asn1ber_struct_from_ber(actx, &len)`。
// - **THEN** 函数返回 0，`len` 接收结构 payload 长度。
#[test]
fn test_asn1_ber_h_accept_struct_header() {
    let mut decoder = Decoder::new(&[0x30, 0x02]);

    assert_eq!(decoder.decode_struct_len(), Ok(2));
}

// Trace: `lib/asn1-ber.h:asn1ber_struct_from_ber`, `lib/asn1-ber.c:asn1ber_struct_from_ber`
// Spec: asn1ber_struct_from_ber require struct tag#reject non-struct header
// - **GIVEN** 输入流当前位置的 typecode 不是 `asnSTRUCT`。
// - **WHEN** 调用方调用 `asn1ber_struct_from_ber(actx, &len)`。
// - **THEN** 函数返回 `-1`，并将 `actx->last_error` 设置为 `-EINVAL`。
#[test]
fn test_asn1_ber_h_reject_non_struct_header() {
    let mut decoder = Decoder::new(&[0x05, 0x00]);

    assert_eq!(decoder.decode_struct_len(), Err(-22));
    assert_eq!(decoder.last_error(), -22);
}

// Trace: `lib/asn1-ber.h:asn1ber_null_from_ber`, `lib/asn1-ber.c:asn1ber_null_from_ber`
// Spec: asn1ber_null_from_ber require null tag#accept null header
// - **GIVEN** 输入流当前位置的 typecode 为 `asnNULL`，后面跟随 BER length。
// - **WHEN** 调用方调用 `asn1ber_null_from_ber(actx, &len)`。
// - **THEN** 函数返回 0，`len` 接收 NULL payload 长度。
#[test]
fn test_asn1_ber_h_accept_null_header() {
    let mut decoder = Decoder::new(&[0x05, 0x00]);

    assert_eq!(decoder.decode_null_len(), Ok(0));
}

// Trace: `lib/asn1-ber.h:asn1ber_int32_from_ber`, `lib/asn1-ber.c:asn1ber_int32_from_ber`
// Spec: asn1ber_int32_from_ber decode signed 32-bit integer#decode signed integer value
// - **GIVEN** 输入流包含 `BER_INTEGER` 或 `BER_COUNTER`，length 为 1 到 4，后跟 big-endian value 字节。
// - **WHEN** 调用方调用 `asn1ber_int32_from_ber(actx, &val)`。
// - **THEN** `val` 接收符号扩展后的 `int32_t` 值，函数返回 0。
#[test]
fn test_asn1_ber_h_decode_signed_integer_value() {
    let mut decoder = Decoder::new(&[0x02, 0x02, 0xff, 0xfe]);

    assert_eq!(decoder.decode_int32(), Ok(-2));
}

// Trace: `lib/asn1-ber.h:asn1ber_int32_from_ber`, `lib/asn1-ber.c:asn1ber_int32_from_ber`
// Spec: asn1ber_int32_from_ber decode signed 32-bit integer#reject invalid signed integer length
// - **GIVEN** 输入流的 integer value length 为 0 或大于 4。
// - **WHEN** 调用方调用 `asn1ber_int32_from_ber(actx, &val)`。
// - **THEN** 函数返回 `-1`，将 `val` 置 0，并将 `actx->last_error` 设置为 `-E2BIG`。
#[test]
fn test_asn1_ber_h_reject_invalid_signed_integer_length() {
    let mut decoder = Decoder::new(&[0x02, 0x00]);

    assert_eq!(decoder.decode_int32(), Err(-7));
    assert_eq!(decoder.last_error(), -7);
}

// Trace: `lib/asn1-ber.h:asn1ber_uint32_from_ber`, `lib/asn1-ber.c:asn1ber_uint32_from_ber`
// Spec: asn1ber_uint32_from_ber decode unsigned 32-bit value#decode unsigned application value
// - **GIVEN** 输入流包含 `BER_BOOLEAN`、`BER_IPADDRESS`、`BER_COUNTER`、`BER_UNSIGNED`、`BER_TIMETICKS`、`BER_NSAPADDRESS`、`BER_UNSIGNED32` 或 `BER_ENUMERATED` 类型，且 length 为 1 到 4。
// - **WHEN** 调用方调用 `asn1ber_uint32_from_ber(actx, &val)`。
// - **THEN** `val` 接收按 big-endian 组合的无符号 32-bit 值。
#[test]
fn test_asn1_ber_h_decode_unsigned_application_value() {
    let mut decoder = Decoder::new(&[0x42, 0x04, 0x12, 0x34, 0x56, 0x78]);

    assert_eq!(decoder.decode_uint32(), Ok(0x1234_5678));
}

// Trace: `lib/asn1-ber.h:asn1ber_int64_from_ber`, `lib/asn1-ber.c:asn1ber_int64_from_ber`
// Spec: asn1ber_int64_from_ber decode signed 64-bit integer#decode signed 64-bit value
// - **GIVEN** 输入流包含 `BER_INTEGER64`，length 为 1 到 8，后跟 big-endian value 字节。
// - **WHEN** 调用方调用 `asn1ber_int64_from_ber(actx, &val)`。
// - **THEN** `val` 接收符号扩展后的 `int64_t` 值，函数返回 0。
#[test]
fn test_asn1_ber_h_decode_signed_64_bit_value() {
    let mut decoder = Decoder::new(&[0x4a, 0x02, 0xff, 0xfe]);

    assert_eq!(decoder.decode_int64(), Ok(-2));
}

// Trace: `lib/asn1-ber.h:asn1ber_uint64_from_ber`, `lib/asn1-ber.c:asn1ber_uint64_from_ber`
// Spec: asn1ber_uint64_from_ber decode unsigned 64-bit value#decode unsigned 64-bit value
// - **GIVEN** 输入流包含 `BER_UNSIGNED64` 或 `BER_COUNTER64`，length 为 1 到 8，后跟 big-endian value 字节。
// - **WHEN** 调用方调用 `asn1ber_uint64_from_ber(actx, &val)`。
// - **THEN** `val` 接收按 big-endian 组合的无符号 64-bit 值。
#[test]
fn test_asn1_ber_h_decode_unsigned_64_bit_value() {
    let mut decoder = Decoder::new(&[0x4b, 0x08, 1, 2, 3, 4, 5, 6, 7, 8]);

    assert_eq!(decoder.decode_uint64(), Ok(0x0102_0304_0506_0708));
}

// Trace: `lib/asn1-ber.h:asn1ber_oid_from_ber`, `lib/asn1-ber.c:asn1ber_oid_from_ber`, `lib/spnego-wrapper.c:smb2_spnego_decode_negTokenInit`
// Spec: asn1ber_oid_from_ber decode object identifier#decode valid OID
// - **GIVEN** 输入流包含 `BER_OBJECT_ID`、有效 length 和 OID value 字节。
// - **WHEN** 调用方调用 `asn1ber_oid_from_ber(actx, &oid)`。
// - **THEN** `oid.elements[0]` 和 `oid.elements[1]` 由首个 OID value 字节拆分，后续元素按 base-128 continuation 字节解码，`oid.length` 为写入元素数。
#[test]
fn test_asn1_ber_h_decode_valid_oid() {
    let mut decoder = Decoder::new(&[0x06, 0x06, 43, 6, 1, 5, 5, 2]);

    assert_eq!(
        decoder.decode_oid().unwrap().elements,
        vec![1, 3, 6, 1, 5, 5, 2]
    );
}

// Trace: `lib/asn1-ber.h:asn1ber_bytes_from_ber`, `lib/asn1-ber.c:asn1ber_bytes_from_ber`
// Spec: asn1ber_bytes_from_ber decode octet string#decode non-empty bytes
// - **GIVEN** 输入流包含 octet string type、BER length 和不超过 `maxlen` 的 value 字节。
// - **WHEN** 调用方调用 `asn1ber_bytes_from_ber(actx, val, maxlen, &lenout)`。
// - **THEN** 前 `lenout` 个字节复制到 `val`，函数返回 0，并在 `lenout < maxlen` 时写入一个额外的 0 终止字节。
#[test]
fn test_asn1_ber_h_decode_non_empty_bytes() {
    let mut decoder = Decoder::new(&[0x04, 0x03, b'a', b'b', b'c']);

    assert_eq!(decoder.decode_bytes(4), Ok((vec![b'a', b'b', b'c', 0], 3)));
}

// Trace: `lib/asn1-ber.h:asn1ber_string_from_ber`, `lib/asn1-ber.c:asn1ber_string_from_ber`
// Spec: asn1ber_string_from_ber decode string as bytes#decode string payload
// - **GIVEN** 输入流包含 BER octet string，调用方提供 `char *` 输出缓冲区。
// - **WHEN** 调用方调用 `asn1ber_string_from_ber(actx, val, maxlen, &lenout)`。
// - **THEN** 结果与以同一缓冲区调用 `asn1ber_bytes_from_ber` 一致。
#[test]
fn test_asn1_ber_h_decode_string_payload() {
    let mut decoder = Decoder::new(&[0x04, 0x03, b'a', b'b', b'c']);

    assert_eq!(decoder.decode_string(4), Ok(("abc".to_string(), 3)));
}

// Trace: `lib/asn1-ber.h:asn1ber_ber_from_length`, `lib/asn1-ber.c:asn1ber_ber_from_length`
// Spec: asn1ber_ber_from_length encode BER length#encode short-form length
// - **GIVEN** 调用方提供 `lenin < 128` 的长度和有效输出上下文。
// - **WHEN** 调用方调用 `asn1ber_ber_from_length(actx, lenin, &lenout)`。
// - **THEN** 输出缓冲区写入一个值为 `lenin` 的字节，`lenout` 为 1。
#[test]
fn test_asn1_ber_h_encode_short_form_length() {
    let mut encoder = Encoder::with_capacity(1);

    assert_eq!(encoder.encode_length(0x7f), Ok(1));
    assert_eq!(encoder.bytes(), &[0x7f]);
}

// Trace: `lib/asn1-ber.h:asn1ber_ber_from_length`, `lib/asn1-ber.c:asn1ber_ber_from_length`
// Spec: asn1ber_ber_from_length encode BER length#encode long-form length
// - **GIVEN** 调用方提供 `lenin >= 128` 的长度和有效输出上下文。
// - **WHEN** 调用方调用 `asn1ber_ber_from_length(actx, lenin, &lenout)`。
// - **THEN** 输出缓冲区先写入 `0x80 | lenbytesneeded`，随后按大端顺序写入 length 字节，`lenout` 为总 length 字段字节数。
#[test]
fn test_asn1_ber_h_encode_long_form_length() {
    let mut encoder = Encoder::with_capacity(4);

    assert_eq!(encoder.encode_length(0x1234), Ok(3));
    assert_eq!(encoder.bytes(), &[0x82, 0x12, 0x34]);
}

// Trace: `lib/asn1-ber.h:asn1ber_ber_reserve_length`, `lib/asn1-ber.c:asn1ber_ber_reserve_length`, `lib/spnego-wrapper.c:smb2_spnego_wrap_gssapi`
// Spec: asn1ber_ber_reserve_length reserve zero bytes#reserve nested length bytes
// - **GIVEN** 调用方准备编码嵌套 BER 结构并已保存输出位置。
// - **WHEN** 调用方调用 `asn1ber_ber_reserve_length(actx, len)`。
// - **THEN** 输出缓冲区追加 `len` 个零字节，任一写入失败时返回错误。
#[test]
fn test_asn1_ber_h_reserve_nested_length_bytes() {
    let mut encoder = Encoder::with_capacity(4);

    encoder.reserve_length(3).unwrap();

    assert_eq!(encoder.bytes(), &[0, 0, 0]);
}

// Trace: `lib/asn1-ber.h:asn1ber_ber_from_typecode`, `lib/asn1-ber.c:asn1ber_ber_from_typecode`, `lib/spnego-wrapper.c:smb2_spnego_wrap_ntlmssp_challenge`
// Spec: asn1ber_ber_from_typecode encode type octet#write context-specific type
// - **GIVEN** 调用方提供通过 `ASN1_CONTEXT(n)` 构造的 typecode。
// - **WHEN** 调用方调用 `asn1ber_ber_from_typecode(actx, typecode)`。
// - **THEN** 输出缓冲区追加该 typecode 的低 8 位，`dst_head` 前进 1。
#[test]
fn test_asn1_ber_h_write_context_specific_type() {
    assert_eq!(ASN_CONTEXT_SPECIFIC | ASN_CONSTRUCTOR | 3, 0xa3);
}

// Trace: `lib/asn1-ber.h:asn1ber_ber_from_typelen`, `lib/asn1-ber.c:asn1ber_ber_from_typelen`
// Spec: asn1ber_ber_from_typelen encode type and length#encode BER header
// - **GIVEN** 调用方提供 typecode、payload 长度和有效输出上下文。
// - **WHEN** 调用方调用 `asn1ber_ber_from_typelen(actx, typecode, lenin, &lenout)`。
// - **THEN** 输出缓冲区依次追加 type 和 length，`lenout` 等于 length 编码字节数加 1。
#[test]
fn test_asn1_ber_h_encode_ber_header() {
    let mut encoder = Encoder::with_capacity(4);

    assert_eq!(encoder.encode_typelen(BerType::OctetString, 0x80), Ok(3));
    assert_eq!(encoder.bytes(), &[0x04, 0x81, 0x80]);
}

// Trace: `lib/asn1-ber.h:asn1ber_ber_from_int32`, `lib/asn1-ber.c:asn1ber_ber_from_int32`
// Spec: asn1ber_ber_from_int32 encode signed 32-bit integer#encode signed 32-bit value
// - **GIVEN** 调用方提供 signed 32-bit 值和输出 typecode。
// - **WHEN** 调用方调用 `asn1ber_ber_from_int32(actx, type, val)`。
// - **THEN** 输出缓冲区包含 type、length 和按源码最短规则选择的 big-endian value 字节。
#[test]
fn test_asn1_ber_h_encode_signed_32_bit_value() {
    let mut encoder = Encoder::with_capacity(4);

    encoder.encode_int32(BerType::Integer, 0x1234).unwrap();

    assert_eq!(encoder.bytes(), &[0x02, 0x02, 0x12, 0x34]);
}

// Trace: `lib/asn1-ber.h:asn1ber_ber_from_uint32`, `lib/asn1-ber.c:asn1ber_ber_from_uint32`
// Spec: asn1ber_ber_from_uint32 encode unsigned 32-bit value#encode unsigned 32-bit value
// - **GIVEN** 调用方提供 unsigned 32-bit 值和输出 typecode。
// - **WHEN** 调用方调用 `asn1ber_ber_from_uint32(actx, type, val)`。
// - **THEN** 输出缓冲区包含 type、length 和按源码规则选择的 big-endian value 字节。
#[test]
fn test_asn1_ber_h_encode_unsigned_32_bit_value() {
    let mut encoder = Encoder::with_capacity(6);

    encoder.encode_uint32(BerType::Unsigned, 0x1234).unwrap();

    assert_eq!(encoder.bytes(), &[0x42, 0x02, 0x12, 0x34]);
}

// Trace: `lib/asn1-ber.h:asn1ber_ber_from_int64`, `lib/asn1-ber.c:asn1ber_ber_from_int64`
// Spec: asn1ber_ber_from_int64 encode signed 64-bit integer#encode signed 64-bit value
// - **GIVEN** 调用方提供 signed 64-bit 值和输出 typecode。
// - **WHEN** 调用方调用 `asn1ber_ber_from_int64(actx, type, val)`。
// - **THEN** 输出缓冲区包含 type、length 和按源码最短规则选择的 big-endian value 字节。
#[test]
fn test_asn1_ber_h_encode_signed_64_bit_value() {
    let mut encoder = Encoder::with_capacity(6);

    encoder.encode_int64(BerType::Integer64, 0x1234).unwrap();

    assert_eq!(encoder.bytes(), &[0x4a, 0x02, 0x12, 0x34]);
}

// Trace: `lib/asn1-ber.h:asn1ber_ber_from_uint64`, `lib/asn1-ber.c:asn1ber_ber_from_uint64`
// Spec: asn1ber_ber_from_uint64 encode unsigned 64-bit value#encode unsigned 64-bit value
// - **GIVEN** 调用方提供 unsigned 64-bit 值和输出 typecode。
// - **WHEN** 调用方调用 `asn1ber_ber_from_uint64(actx, type, val)`。
// - **THEN** 输出缓冲区包含 type、length 和按源码规则选择的 big-endian value 字节。
#[test]
fn test_asn1_ber_h_encode_unsigned_64_bit_value() {
    let mut encoder = Encoder::with_capacity(8);

    encoder
        .encode_uint64(BerType::Unsigned64, 0x0102_0304_0506_0708)
        .unwrap();

    assert_eq!(encoder.bytes(), &[0x4b, 0x04, 0x05, 0x06, 0x07, 0x08]);
}

// Trace: `lib/asn1-ber.h:asn1ber_ber_from_oid`, `lib/asn1-ber.c:asn1ber_ber_from_oid`, `lib/spnego-wrapper.c:smb2_spnego_create_negotiate_reply_blob`
// Spec: asn1ber_ber_from_oid encode object identifier#encode SPNEGO mechanism OID
// - **GIVEN** 调用方提供有效 `struct asn1ber_oid_value`，且 `oid->length` 小于 `BER_MAX_OID_ELEMENTS`。
// - **WHEN** 调用方调用 `asn1ber_ber_from_oid(actx, oid)`。
// - **THEN** 输出缓冲区追加 object identifier 的 type、length 和 BER 编码内容，返回值来自最终 length 回填结果。
#[test]
fn test_asn1_ber_h_encode_spnego_mechanism_oid() {
    let mut encoder = Encoder::with_capacity(16);

    encoder
        .encode_oid(&OidValue {
            elements: vec![1, 3, 6, 1, 5, 5, 2],
        })
        .unwrap();

    assert_eq!(encoder.bytes(), &[0x06, 0x06, 43, 6, 1, 5, 5, 2]);
}

// Trace: `lib/asn1-ber.h:asn1ber_ber_from_bytes`, `lib/asn1-ber.c:asn1ber_ber_from_bytes`, `lib/spnego-wrapper.c:smb2_spnego_wrap_ntlmssp_challenge`
// Spec: asn1ber_ber_from_bytes encode bytes with caller type#encode octet string payload
// - **GIVEN** 调用方提供 bytes 指针、长度和 `asnOCTET_STRING` typecode。
// - **WHEN** 调用方调用 `asn1ber_ber_from_bytes(actx, type, val, len)`。
// - **THEN** 输出缓冲区追加 type、length 和完全相同顺序的 payload 字节。
#[test]
fn test_asn1_ber_h_encode_octet_string_payload() {
    let mut encoder = Encoder::with_capacity(8);

    encoder.encode_bytes(BerType::OctetString, b"abc").unwrap();

    assert_eq!(encoder.bytes(), &[0x04, 0x03, b'a', b'b', b'c']);
}

// Trace: `lib/asn1-ber.h:asn1ber_ber_from_string`, `lib/asn1-ber.c:asn1ber_ber_from_string`
// Spec: asn1ber_ber_from_string encode string as octet string#encode string payload
// - **GIVEN** 调用方提供字符串指针和要编码的字节长度。
// - **WHEN** 调用方调用 `asn1ber_ber_from_string(actx, val, len)`。
// - **THEN** 输出结果与以同一字节范围调用 `asn1ber_ber_from_bytes(actx, BER_OCTET_STRING, (uint8_t *)val, len)` 一致。
#[test]
fn test_asn1_ber_h_encode_string_payload() {
    let mut encoder = Encoder::with_capacity(8);

    encoder.encode_string("abc").unwrap();

    assert_eq!(encoder.bytes(), &[0x04, 0x03, b'a', b'b', b'c']);
}
