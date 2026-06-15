use libsmb2_rs::include::config::{PICOW_LWIPOPTS, PICOW_LWIP_COMMON};

// Trace: `include/picow/lwipopts.h:LWIP_SO_RCVBUF`
// Spec: LWIP_SO_RCVBUF enable receive buffers#Pico W socket receive-buffer option
// - **GIVEN** Pico W code includes `include/picow/lwipopts.h`
// - **WHEN** lwIP evaluates `LWIP_SO_RCVBUF`
// - **THEN** the macro expands to `1`
#[test]
fn test_lwipopts_pico_w_socket_receive_buffer_option() {
    assert_eq!(PICOW_LWIPOPTS.so_rcvbuf, 1);
}

// Trace: `include/picow/lwipopts.h:LWIP_TIMEVAL_PRIVATE`
// Spec: LWIP_TIMEVAL_PRIVATE use external timeval#Pico W timeval ownership option
// - **GIVEN** Pico W code includes `include/picow/lwipopts.h`
// - **WHEN** lwIP evaluates `LWIP_TIMEVAL_PRIVATE`
// - **THEN** the macro expands to `0`
#[test]
fn test_lwipopts_pico_w_timeval_ownership_option() {
    assert_eq!(PICOW_LWIPOPTS.timeval_private, 0);
}

// Trace: `include/picow/lwipopts.h:TCPIP_THREAD_STACKSIZE`
// Spec: TCPIP_THREAD_STACKSIZE set tcpip stack size#NO_SYS disabled tcpip stack sizing
// - **GIVEN** `NO_SYS` evaluates false after including `include/picow/lwipopts_examples_common.h`
// - **WHEN** lwIP evaluates `TCPIP_THREAD_STACKSIZE`
// - **THEN** the macro expands to `1024`
#[test]
fn test_lwipopts_no_sys_disabled_tcpip_stack_sizing() {
    assert_eq!(PICOW_LWIP_COMMON.no_sys_default, 1);
    assert_eq!(PICOW_LWIPOPTS.tcpip_thread_stacksize, Some(1024));
}

// Trace: `include/picow/lwipopts.h:DEFAULT_THREAD_STACKSIZE`
// Spec: DEFAULT_THREAD_STACKSIZE set default stack size#NO_SYS disabled default stack sizing
// - **GIVEN** `NO_SYS` evaluates false after including `include/picow/lwipopts_examples_common.h`
// - **WHEN** lwIP evaluates `DEFAULT_THREAD_STACKSIZE`
// - **THEN** the macro expands to `1024`
#[test]
fn test_lwipopts_no_sys_disabled_default_stack_sizing() {
    assert_eq!(PICOW_LWIP_COMMON.no_sys_default, 1);
    assert_eq!(PICOW_LWIPOPTS.default_thread_stacksize, Some(1024));
}

// Trace: `include/picow/lwipopts.h:DEFAULT_RAW_RECVMBOX_SIZE`
// Spec: DEFAULT_RAW_RECVMBOX_SIZE set raw mailbox size#NO_SYS disabled raw receive mailbox sizing
// - **GIVEN** `NO_SYS` evaluates false after including `include/picow/lwipopts_examples_common.h`
// - **WHEN** lwIP evaluates `DEFAULT_RAW_RECVMBOX_SIZE`
// - **THEN** the macro expands to `8`
#[test]
fn test_lwipopts_no_sys_disabled_raw_receive_mailbox_sizing() {
    assert_eq!(PICOW_LWIP_COMMON.no_sys_default, 1);
    assert_eq!(PICOW_LWIPOPTS.default_raw_recvmbox_size, Some(8));
}

// Trace: `include/picow/lwipopts.h:TCPIP_MBOX_SIZE`
// Spec: TCPIP_MBOX_SIZE set shared mailbox size#NO_SYS disabled shared mailbox sizing
// - **GIVEN** `NO_SYS` evaluates false after including `include/picow/lwipopts_examples_common.h`
// - **WHEN** lwIP evaluates `TCPIP_MBOX_SIZE`
// - **THEN** the macro expands to `8`
#[test]
fn test_lwipopts_no_sys_disabled_shared_mailbox_sizing() {
    assert_eq!(PICOW_LWIP_COMMON.no_sys_default, 1);
    assert_eq!(PICOW_LWIPOPTS.tcpip_mbox_size, Some(8));
}

// Trace: `include/picow/lwipopts.h:DEFAULT_UDP_RECVMBOX_SIZE`
// Spec: DEFAULT_UDP_RECVMBOX_SIZE alias shared mailbox size#NO_SYS disabled UDP receive mailbox sizing
// - **GIVEN** `NO_SYS` evaluates false and `TCPIP_MBOX_SIZE` is defined by `include/picow/lwipopts.h`
// - **WHEN** lwIP evaluates `DEFAULT_UDP_RECVMBOX_SIZE`
// - **THEN** the macro expands to `TCPIP_MBOX_SIZE`
#[test]
fn test_lwipopts_no_sys_disabled_udp_receive_mailbox_sizing() {
    assert_eq!(PICOW_LWIPOPTS.tcpip_mbox_size, Some(8));
    assert_eq!(
        PICOW_LWIPOPTS.default_udp_recvmbox_size_alias,
        Some("TCPIP_MBOX_SIZE")
    );
}

// Trace: `include/picow/lwipopts.h:DEFAULT_TCP_RECVMBOX_SIZE`
// Spec: DEFAULT_TCP_RECVMBOX_SIZE alias shared mailbox size#NO_SYS disabled TCP receive mailbox sizing
// - **GIVEN** `NO_SYS` evaluates false and `TCPIP_MBOX_SIZE` is defined by `include/picow/lwipopts.h`
// - **WHEN** lwIP evaluates `DEFAULT_TCP_RECVMBOX_SIZE`
// - **THEN** the macro expands to `TCPIP_MBOX_SIZE`
#[test]
fn test_lwipopts_no_sys_disabled_tcp_receive_mailbox_sizing() {
    assert_eq!(PICOW_LWIPOPTS.tcpip_mbox_size, Some(8));
    assert_eq!(
        PICOW_LWIPOPTS.default_tcp_recvmbox_size_alias,
        Some("TCPIP_MBOX_SIZE")
    );
}

// Trace: `include/picow/lwipopts.h:DEFAULT_ACCEPTMBOX_SIZE`
// Spec: DEFAULT_ACCEPTMBOX_SIZE alias shared mailbox size#NO_SYS disabled accept mailbox sizing
// - **GIVEN** `NO_SYS` evaluates false and `TCPIP_MBOX_SIZE` is defined by `include/picow/lwipopts.h`
// - **WHEN** lwIP evaluates `DEFAULT_ACCEPTMBOX_SIZE`
// - **THEN** the macro expands to `TCPIP_MBOX_SIZE`
#[test]
fn test_lwipopts_no_sys_disabled_accept_mailbox_sizing() {
    assert_eq!(PICOW_LWIPOPTS.tcpip_mbox_size, Some(8));
    assert_eq!(
        PICOW_LWIPOPTS.default_acceptmbox_size_alias,
        Some("TCPIP_MBOX_SIZE")
    );
}

// Trace: `include/picow/lwipopts.h:LWIP_TCPIP_CORE_LOCKING_INPUT`
// Spec: LWIP_TCPIP_CORE_LOCKING_INPUT enable core-locking input#NO_SYS disabled core-locking input option
// - **GIVEN** `NO_SYS` evaluates false after including `include/picow/lwipopts_examples_common.h`
// - **WHEN** lwIP evaluates `LWIP_TCPIP_CORE_LOCKING_INPUT`
// - **THEN** the macro expands to `1`
#[test]
fn test_lwipopts_no_sys_disabled_core_locking_input_option() {
    assert_eq!(PICOW_LWIP_COMMON.no_sys_default, 1);
    assert_eq!(PICOW_LWIPOPTS.tcpip_core_locking_input, Some(1));
}
