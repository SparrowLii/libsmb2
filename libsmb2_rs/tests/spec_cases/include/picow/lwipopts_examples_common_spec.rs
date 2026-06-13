use libsmb2_sys::include::config::{PICOW_LWIPOPTS, PICOW_LWIP_COMMON};

// Trace: `include/picow/lwipopts_examples_common.h:NO_SYS`, `include/picow/lwipopts.h:NO_SYS`
// Spec: NO_SYS default and override behavior#默认启用 NO_SYS
// - **GIVEN** 编译单元包含 `include/picow/lwipopts_examples_common.h` 且未预定义 `NO_SYS`
// - **WHEN** 预处理该头文件
// - **THEN** `NO_SYS` 的可见宏值为 `1`
#[test]
fn test_lwipopts_examples_common_no_sys_default_enabled() {
    assert_eq!(PICOW_LWIP_COMMON.no_sys_default, 1);
}

// Trace: `include/picow/lwipopts_examples_common.h:NO_SYS`
// Spec: NO_SYS default and override behavior#调用方覆盖 NO_SYS
// - **GIVEN** 编译单元在包含该头文件前已经定义 `NO_SYS`
// - **WHEN** 预处理该头文件
// - **THEN** 该头文件不重新定义 `NO_SYS`，调用方提供的值保持可见
#[test]
fn test_lwipopts_examples_common_no_sys_caller_override() {
    assert!(PICOW_LWIP_COMMON.no_sys_preserves_caller_override);
}

// Trace: `include/picow/lwipopts_examples_common.h:LWIP_SOCKET`
// Spec: LWIP_SOCKET default and override behavior#默认启用 socket 支持
// - **GIVEN** 编译单元包含 `include/picow/lwipopts_examples_common.h` 且未预定义 `LWIP_SOCKET`
// - **WHEN** 预处理该头文件
// - **THEN** `LWIP_SOCKET` 的可见宏值为 `1`
#[test]
fn test_lwipopts_examples_common_lwip_socket_default_enabled() {
    assert_eq!(PICOW_LWIP_COMMON.lwip_socket_default, 1);
}

// Trace: `include/picow/lwipopts_examples_common.h:LWIP_SOCKET`
// Spec: LWIP_SOCKET default and override behavior#调用方覆盖 LWIP_SOCKET
// - **GIVEN** 编译单元在包含该头文件前已经定义 `LWIP_SOCKET`
// - **WHEN** 预处理该头文件
// - **THEN** 该头文件不重新定义 `LWIP_SOCKET`，调用方提供的值保持可见
#[test]
fn test_lwipopts_examples_common_lwip_socket_caller_override() {
    assert!(PICOW_LWIP_COMMON.lwip_socket_preserves_caller_override);
}

// Trace: `include/picow/lwipopts_examples_common.h:MEM_LIBC_MALLOC`
// Spec: MEM_LIBC_MALLOC polling architecture selection#轮询架构启用 libc malloc
// - **GIVEN** 编译单元包含该头文件且 `PICO_CYW43_ARCH_POLL` 条件为真
// - **WHEN** 预处理 `MEM_LIBC_MALLOC` 配置分支
// - **THEN** `MEM_LIBC_MALLOC` 的可见宏值为 `1`
#[test]
fn test_lwipopts_examples_common_polling_architecture_enables_libc_malloc() {
    assert_eq!(PICOW_LWIP_COMMON.mem_libc_malloc_poll, 1);
}

// Trace: `include/picow/lwipopts_examples_common.h:MEM_LIBC_MALLOC`
// Spec: MEM_LIBC_MALLOC polling architecture selection#非轮询架构禁用 libc malloc
// - **GIVEN** 编译单元包含该头文件且 `PICO_CYW43_ARCH_POLL` 条件为假
// - **WHEN** 预处理 `MEM_LIBC_MALLOC` 配置分支
// - **THEN** `MEM_LIBC_MALLOC` 的可见宏值为 `0`
#[test]
fn test_lwipopts_examples_common_non_polling_architecture_disables_libc_malloc() {
    assert_eq!(PICOW_LWIP_COMMON.mem_libc_malloc_non_poll, 0);
}

// Trace: `include/picow/lwipopts_examples_common.h:lwIP option constants`
// Spec: lwIP option constants common configuration#公共 lwIP 常量可见
// - **GIVEN** 编译单元包含该头文件
// - **WHEN** 预处理公共 lwIP option 常量定义
// - **THEN** 调用方可见 `MEM_ALIGNMENT` 为 `4`、`MEM_SIZE` 为 `4000`、`TCP_MSS` 为 `1460`、`TCP_WND` 为 `(8 * TCP_MSS)`、`TCP_SND_BUF` 为 `(8 * TCP_MSS)`，且协议、DHCP、IPv4、TCP、UDP、DNS、keepalive 和 netif 单包发送相关开关按源码定义为启用或关闭
#[test]
fn test_lwipopts_examples_common_common_lwip_constants_visible() {
    assert_eq!(PICOW_LWIP_COMMON.mem_alignment, 4);
    assert_eq!(PICOW_LWIP_COMMON.mem_size, 4000);
    assert_eq!(PICOW_LWIP_COMMON.tcp_mss, 1460);
    assert_eq!(PICOW_LWIP_COMMON.tcp_wnd_expr, "8 * TCP_MSS");
    assert_eq!(PICOW_LWIP_COMMON.tcp_snd_buf_expr, "8 * TCP_MSS");
    assert_eq!(PICOW_LWIP_COMMON.memp_num_tcp_seg, 32);
    assert_eq!(PICOW_LWIP_COMMON.memp_num_arp_queue, 10);
    assert_eq!(PICOW_LWIP_COMMON.pbuf_pool_size, 24);
    assert_eq!(PICOW_LWIP_COMMON.lwip_arp, 1);
    assert_eq!(PICOW_LWIP_COMMON.lwip_ethernet, 1);
    assert_eq!(PICOW_LWIP_COMMON.lwip_icmp, 1);
    assert_eq!(PICOW_LWIP_COMMON.lwip_raw, 1);
    assert_eq!(PICOW_LWIP_COMMON.lwip_dhcp, 1);
    assert_eq!(PICOW_LWIP_COMMON.lwip_ipv4, 1);
    assert_eq!(PICOW_LWIP_COMMON.lwip_tcp, 1);
    assert_eq!(PICOW_LWIP_COMMON.lwip_udp, 1);
    assert_eq!(PICOW_LWIP_COMMON.lwip_dns, 1);
    assert_eq!(PICOW_LWIP_COMMON.lwip_tcp_keepalive, 1);
    assert_eq!(PICOW_LWIP_COMMON.lwip_netif_tx_single_pbuf, 1);
    assert_eq!(PICOW_LWIP_COMMON.lwip_netif_status_callback, 1);
    assert_eq!(PICOW_LWIP_COMMON.lwip_netif_link_callback, 1);
    assert_eq!(PICOW_LWIP_COMMON.lwip_netif_hostname, 1);
    assert_eq!(PICOW_LWIP_COMMON.lwip_netconn, 0);
    assert_eq!(PICOW_LWIP_COMMON.mem_stats, 0);
    assert_eq!(PICOW_LWIP_COMMON.sys_stats, 0);
    assert_eq!(PICOW_LWIP_COMMON.memp_stats, 0);
    assert_eq!(PICOW_LWIP_COMMON.link_stats, 0);
    assert_eq!(PICOW_LWIP_COMMON.lwip_chksum_algorithm, 3);
    assert_eq!(PICOW_LWIP_COMMON.dhcp_does_arp_check, 0);
    assert_eq!(PICOW_LWIP_COMMON.lwip_dhcp_does_acd_check, 0);
    assert_eq!(PICOW_LWIPOPTS.so_rcvbuf, 1);
}

// Trace: `include/picow/lwipopts_examples_common.h:LWIP_DEBUG`
// Spec: debug option constants conditional configuration#非 NDEBUG 构建启用总体调试统计
// - **GIVEN** 编译单元包含该头文件且未定义 `NDEBUG`
// - **WHEN** 预处理调试配置块
// - **THEN** `LWIP_DEBUG`、`LWIP_STATS` 和 `LWIP_STATS_DISPLAY` 的可见宏值均为 `1`
#[test]
fn test_lwipopts_examples_common_non_ndebug_build_enables_debug_stats() {
    assert_eq!(PICOW_LWIP_COMMON.lwip_debug, Some(1));
    assert_eq!(PICOW_LWIP_COMMON.lwip_stats, Some(1));
    assert_eq!(PICOW_LWIP_COMMON.lwip_stats_display, Some(1));
}

// Trace: `include/picow/lwipopts_examples_common.h:debug option constants`
// Spec: debug option constants conditional configuration#调试类别默认关闭
// - **GIVEN** 编译单元包含该头文件
// - **WHEN** 预处理调试类别宏定义
// - **THEN** `ETHARP_DEBUG`、`NETIF_DEBUG`、`PBUF_DEBUG`、`API_LIB_DEBUG`、`API_MSG_DEBUG`、`SOCKETS_DEBUG`、`ICMP_DEBUG`、`INET_DEBUG`、`IP_DEBUG`、`IP_REASS_DEBUG`、`RAW_DEBUG`、`MEM_DEBUG`、`MEMP_DEBUG`、`SYS_DEBUG`、`TCP_DEBUG`、`TCP_INPUT_DEBUG`、`TCP_OUTPUT_DEBUG`、`TCP_RTO_DEBUG`、`TCP_CWND_DEBUG`、`TCP_WND_DEBUG`、`TCP_FR_DEBUG`、`TCP_QLEN_DEBUG`、`TCP_RST_DEBUG`、`UDP_DEBUG`、`TCPIP_DEBUG`、`PPP_DEBUG`、`SLIP_DEBUG` 和 `DHCP_DEBUG` 的可见宏值均为 `LWIP_DBG_OFF`
#[test]
fn test_lwipopts_examples_common_debug_categories_default_disabled() {
    assert_eq!(PICOW_LWIP_COMMON.debug_category_value, "LWIP_DBG_OFF");
    assert_eq!(
        PICOW_LWIP_COMMON.debug_categories,
        &[
            "ETHARP_DEBUG",
            "NETIF_DEBUG",
            "PBUF_DEBUG",
            "API_LIB_DEBUG",
            "API_MSG_DEBUG",
            "SOCKETS_DEBUG",
            "ICMP_DEBUG",
            "INET_DEBUG",
            "IP_DEBUG",
            "IP_REASS_DEBUG",
            "RAW_DEBUG",
            "MEM_DEBUG",
            "MEMP_DEBUG",
            "SYS_DEBUG",
            "TCP_DEBUG",
            "TCP_INPUT_DEBUG",
            "TCP_OUTPUT_DEBUG",
            "TCP_RTO_DEBUG",
            "TCP_CWND_DEBUG",
            "TCP_WND_DEBUG",
            "TCP_FR_DEBUG",
            "TCP_QLEN_DEBUG",
            "TCP_RST_DEBUG",
            "UDP_DEBUG",
            "TCPIP_DEBUG",
            "PPP_DEBUG",
            "SLIP_DEBUG",
            "DHCP_DEBUG",
        ]
    );
}
