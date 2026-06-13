use libsmb2_sys::include::libsmb2_private::{
    pad_to_32bit, pad_to_64bit, private_constants, RecvState,
};

// Trace: `include/libsmb2-private.h:PAD_TO_32BIT`
// Spec: PAD_TO_32BIT align length to four-byte boundary#unaligned length is padded to 32-bit boundary
// - **GIVEN** 调用方传入长度表达式 `len`
// - **WHEN** 调用 `PAD_TO_32BIT(len)`
// - **THEN** 结果 MUST 清除低两位并表示不小于原长度的 4 字节对齐长度
#[test]
fn test_libsmb2_private_unaligned_length_is_padded_to_32_bit_boundary() {
    for len in [0_u32, 1, 2, 3, 4, 5, 6, 7, 255, 256, 257] {
        let padded = pad_to_32bit(len);

        assert_eq!(padded & 0x03, 0);
        assert!(padded >= len);
        assert!(padded - len < 4);
    }
}

// Trace: `include/libsmb2-private.h:PAD_TO_64BIT`
// Spec: PAD_TO_64BIT align length to eight-byte boundary#unaligned length is padded to 64-bit boundary
// - **GIVEN** 调用方传入长度表达式 `len`
// - **WHEN** 调用 `PAD_TO_64BIT(len)`
// - **THEN** 结果 MUST 清除低三位并表示不小于原长度的 8 字节对齐长度
#[test]
fn test_libsmb2_private_unaligned_length_is_padded_to_64_bit_boundary() {
    for len in [0_u32, 1, 2, 3, 4, 5, 6, 7, 8, 9, 255, 256, 257] {
        let padded = pad_to_64bit(len);

        assert_eq!(padded & 0x07, 0);
        assert!(padded >= len);
        assert!(padded - len < 8);
    }
}

// Trace: `include/libsmb2-private.h:SMB2_SPL_SIZE`, `include/libsmb2-private.h:smb2_recv_state`
// Spec: SMB2_SPL_SIZE define SPL read size#receive state starts with SPL
// - **GIVEN** 接收状态机处于 `SMB2_RECV_SPL`
// - **WHEN** 实现代码需要 SPL 字段大小
// - **THEN** `SMB2_SPL_SIZE` MUST 提供值 `4`
#[test]
fn test_libsmb2_private_receive_state_starts_with_spl() {
    assert_eq!(private_constants().spl_size, 4);
    assert_eq!(RecvState::Spl.value(), Some(0));
}

// Trace: `include/libsmb2-private.h:SMB2_SIGNATURE_SIZE`
// Spec: SMB2_SIGNATURE_SIZE define signature byte count#signature size is referenced by callers
// - **GIVEN** 调用方需要 SMB2 signature 字节数
// - **WHEN** 读取 `SMB2_SIGNATURE_SIZE`
// - **THEN** 宏值 MUST 为 `16`
#[test]
fn test_libsmb2_private_signature_size_is_referenced_by_callers() {
    assert_eq!(private_constants().signature_size, 16);
}

// Trace: `include/libsmb2-private.h:smb2_recv_state`, `lib/socket.c:recv_state`
// Spec: smb2_recv_state enumerate receive state machine stages#socket receive loop dispatches state
// - **GIVEN** `lib/socket.c` 按 `smb2->recv_state` 分派接收流程
// - **WHEN** 状态机进入 SPL、header、fixed、variable、pad、transform 或 unknown 阶段
// - **THEN** `smb2_recv_state` MUST 提供对应枚举值 `SMB2_RECV_SPL`、`SMB2_RECV_HEADER`、`SMB2_RECV_FIXED`、`SMB2_RECV_VARIABLE`、`SMB2_RECV_PAD`、`SMB2_RECV_TRFM` 和 `SMB2_RECV_UNKNOWN`
#[test]
fn test_libsmb2_private_socket_receive_loop_dispatches_state() {
    assert_eq!(RecvState::Spl.value(), Some(0));
    assert_eq!(RecvState::Header.value(), Some(1));
    assert_eq!(RecvState::Fixed.value(), Some(2));
    assert_eq!(RecvState::Variable.value(), Some(3));
    assert_eq!(RecvState::Pad.value(), Some(4));
    assert_eq!(RecvState::Transform.value(), Some(5));
    assert_eq!(RecvState::Unknown.value(), Some(6));
}

// Trace: `include/libsmb2-private.h:MAX_CREDITS`
// Spec: MAX_CREDITS define credit ceiling#credit-related logic needs maximum value
// - **GIVEN** 实现代码需要内部 credit 上限
// - **WHEN** 读取 `MAX_CREDITS`
// - **THEN** 宏值 MUST 为 `1024`
#[test]
fn test_libsmb2_private_credit_related_logic_needs_maximum_value() {
    assert_eq!(private_constants().max_credits, 1024);
}

// Trace: `include/libsmb2-private.h:SMB2_MAX_PDU_SIZE`
// Spec: SMB2_MAX_PDU_SIZE define maximum PDU expression#implementation checks or allocates PDU size
// - **GIVEN** 实现代码需要内部最大 PDU 大小
// - **WHEN** 读取 `SMB2_MAX_PDU_SIZE`
// - **THEN** 宏表达式 MUST 为 `16*1024*1024`
#[test]
fn test_libsmb2_private_implementation_checks_or_allocates_pdu_size() {
    assert_eq!(private_constants().max_pdu_size, 16 * 1024 * 1024);
}
