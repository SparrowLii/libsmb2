# include/picow/lwipopts_examples_common.h Specification

## Source Context

- Source: `include/picow/lwipopts_examples_common.h`
- Related Headers: `include/picow/lwipopts.h`
- Related Tests: `none`
- Related Dependencies: GitNexus `context` found indexed macros `NO_SYS`, `LWIP_SOCKET`, `MEM_LIBC_MALLOC`, and `LWIP_DEBUG` in this file with no incoming callers or process flows; source review shows `include/picow/lwipopts.h` includes this header and reads `NO_SYS`.
- Build/Compile Context: PICO build path enables C/CXX/ASM; this header provides common lwIP option macros for Pico W examples and is affected by `PICO_CYW43_ARCH_POLL`, `NDEBUG`, caller-provided `NO_SYS`, and caller-provided `LWIP_SOCKET`.

## Interface Summary

| Interface | Kind | Signature | Decision | Reason |
| --- | --- | --- | --- | --- |
| NO_SYS | macro | #ifndef NO_SYS` / `#define NO_SYS 1 | Include | 头文件显式允许调用方覆盖该 lwIP 系统模式宏，且 `include/picow/lwipopts.h` 根据该值选择是否声明 Pico 系统宏。 |
| LWIP_SOCKET | macro | #ifndef LWIP_SOCKET` / `#define LWIP_SOCKET 1 | Include | 头文件显式允许调用方覆盖 socket 支持开关，属于调用方可见的 lwIP 配置契约。 |
| MEM_LIBC_MALLOC | macro | #if PICO_CYW43_ARCH_POLL` / `#define MEM_LIBC_MALLOC 1` / `#else` / `#define MEM_LIBC_MALLOC 0 | Include | 宏值随 Pico CYW43 轮询架构切换，并由源码注释说明非轮询版本不兼容 libc malloc。 |
| lwIP option constants | macro | #define MEM_ALIGNMENT 4`, `#define MEM_SIZE 4000`, `#define MEMP_NUM_TCP_SEG 32`, `#define MEMP_NUM_ARP_QUEUE 10`, `#define PBUF_POOL_SIZE 24`, `#define LWIP_ARP 1`, `#define LWIP_ETHERNET 1`, `#define LWIP_ICMP 1`, `#define LWIP_RAW 1`, `#define TCP_WND (8 * TCP_MSS)`, `#define TCP_MSS 1460`, `#define TCP_SND_BUF (8 * TCP_MSS)`, `#define TCP_SND_QUEUELEN ((4 * (TCP_SND_BUF) + (TCP_MSS - 1)) / (TCP_MSS))`, `#define LWIP_NETIF_STATUS_CALLBACK 1`, `#define LWIP_NETIF_LINK_CALLBACK 1`, `#define LWIP_NETIF_HOSTNAME 1`, `#define LWIP_NETCONN 0`, `#define MEM_STATS 0`, `#define SYS_STATS 0`, `#define MEMP_STATS 0`, `#define LINK_STATS 0`, `#define LWIP_CHKSUM_ALGORITHM 3`, `#define LWIP_DHCP 1`, `#define LWIP_IPV4 1`, `#define LWIP_TCP 1`, `#define LWIP_UDP 1`, `#define LWIP_DNS 1`, `#define LWIP_TCP_KEEPALIVE 1`, `#define LWIP_NETIF_TX_SINGLE_PBUF 1`, `#define DHCP_DOES_ARP_CHECK 0`, `#define LWIP_DHCP_DOES_ACD_CHECK 0 | Include | 这些宏构成 Pico W 示例共同使用的 lwIP 内存、协议、TCP、DHCP、校验和、统计和 netif 配置表面。 |
| debug option constants | macro | #ifndef NDEBUG` / `#define LWIP_DEBUG 1` / `#define LWIP_STATS 1` / `#define LWIP_STATS_DISPLAY 1`; debug category macros defined as `LWIP_DBG_OFF | Include | 调试和统计宏在非 `NDEBUG` 构建中启用总体调试能力，同时逐项关闭 lwIP 调试类别。 |

## Data Model Summary

| Type/Macro | Kind | Definition | Notes |
| --- | --- | --- | --- |
| NO_SYS | macro | include/picow/lwipopts_examples_common.h:9 | 未由调用方预定义时默认为 `1`。 |
| LWIP_SOCKET | macro | include/picow/lwipopts_examples_common.h:13 | 未由调用方预定义时默认为 `1`。 |
| MEM_LIBC_MALLOC | macro | include/picow/lwipopts_examples_common.h:16 | `PICO_CYW43_ARCH_POLL` 为真时为 `1`，否则为 `0`。 |
| lwIP option constants | macro | include/picow/lwipopts_examples_common.h:22 | 固定定义内存、协议、TCP、DHCP、校验和、统计和 netif 相关 lwIP 选项。 |
| debug option constants | macro | include/picow/lwipopts_examples_common.h:55 | 非 `NDEBUG` 构建定义 `LWIP_DEBUG`、`LWIP_STATS`、`LWIP_STATS_DISPLAY`，调试类别宏固定为 `LWIP_DBG_OFF`。 |

## ADDED Requirements

### Requirement: NO_SYS default and override behavior
系统 MUST 在调用方未预定义 `NO_SYS` 时将 `NO_SYS` 定义为 `1`，并 MUST 保留调用方预定义值而不覆盖。

#### Scenario: 默认启用 NO_SYS
- **GIVEN** 编译单元包含 `include/picow/lwipopts_examples_common.h` 且未预定义 `NO_SYS`
- **WHEN** 预处理该头文件
- **THEN** `NO_SYS` 的可见宏值为 `1`

Trace: `include/picow/lwipopts_examples_common.h:NO_SYS`, `include/picow/lwipopts.h:NO_SYS`

#### Scenario: 调用方覆盖 NO_SYS
- **GIVEN** 编译单元在包含该头文件前已经定义 `NO_SYS`
- **WHEN** 预处理该头文件
- **THEN** 该头文件不重新定义 `NO_SYS`，调用方提供的值保持可见

Trace: `include/picow/lwipopts_examples_common.h:NO_SYS`

### Requirement: LWIP_SOCKET default and override behavior
系统 MUST 在调用方未预定义 `LWIP_SOCKET` 时将 `LWIP_SOCKET` 定义为 `1`，并 MUST 保留调用方预定义值而不覆盖。

#### Scenario: 默认启用 socket 支持
- **GIVEN** 编译单元包含 `include/picow/lwipopts_examples_common.h` 且未预定义 `LWIP_SOCKET`
- **WHEN** 预处理该头文件
- **THEN** `LWIP_SOCKET` 的可见宏值为 `1`

Trace: `include/picow/lwipopts_examples_common.h:LWIP_SOCKET`

#### Scenario: 调用方覆盖 LWIP_SOCKET
- **GIVEN** 编译单元在包含该头文件前已经定义 `LWIP_SOCKET`
- **WHEN** 预处理该头文件
- **THEN** 该头文件不重新定义 `LWIP_SOCKET`，调用方提供的值保持可见

Trace: `include/picow/lwipopts_examples_common.h:LWIP_SOCKET`

### Requirement: MEM_LIBC_MALLOC polling architecture selection
系统 MUST 根据 `PICO_CYW43_ARCH_POLL` 选择 `MEM_LIBC_MALLOC`，轮询架构下值为 `1`，非轮询架构下值为 `0`。

#### Scenario: 轮询架构启用 libc malloc
- **GIVEN** 编译单元包含该头文件且 `PICO_CYW43_ARCH_POLL` 条件为真
- **WHEN** 预处理 `MEM_LIBC_MALLOC` 配置分支
- **THEN** `MEM_LIBC_MALLOC` 的可见宏值为 `1`

Trace: `include/picow/lwipopts_examples_common.h:MEM_LIBC_MALLOC`

#### Scenario: 非轮询架构禁用 libc malloc
- **GIVEN** 编译单元包含该头文件且 `PICO_CYW43_ARCH_POLL` 条件为假
- **WHEN** 预处理 `MEM_LIBC_MALLOC` 配置分支
- **THEN** `MEM_LIBC_MALLOC` 的可见宏值为 `0`

Trace: `include/picow/lwipopts_examples_common.h:MEM_LIBC_MALLOC`

### Requirement: lwIP option constants common configuration
系统 MUST 为 Pico W 示例提供固定的 lwIP 常量集合，覆盖内存尺寸、协议开关、TCP 缓冲区派生值、netif 回调、统计关闭、DHCP/IPv4/TCP/UDP/DNS 开关和校验和算法。

#### Scenario: 公共 lwIP 常量可见
- **GIVEN** 编译单元包含该头文件
- **WHEN** 预处理公共 lwIP option 常量定义
- **THEN** 调用方可见 `MEM_ALIGNMENT` 为 `4`、`MEM_SIZE` 为 `4000`、`TCP_MSS` 为 `1460`、`TCP_WND` 为 `(8 * TCP_MSS)`、`TCP_SND_BUF` 为 `(8 * TCP_MSS)`，且协议、DHCP、IPv4、TCP、UDP、DNS、keepalive 和 netif 单包发送相关开关按源码定义为启用或关闭

Trace: `include/picow/lwipopts_examples_common.h:lwIP option constants`

### Requirement: debug option constants conditional configuration
系统 MUST 在非 `NDEBUG` 构建中启用 lwIP 总体调试和统计显示宏，并 MUST 将列出的各调试类别宏定义为 `LWIP_DBG_OFF`。

#### Scenario: 非 NDEBUG 构建启用总体调试统计
- **GIVEN** 编译单元包含该头文件且未定义 `NDEBUG`
- **WHEN** 预处理调试配置块
- **THEN** `LWIP_DEBUG`、`LWIP_STATS` 和 `LWIP_STATS_DISPLAY` 的可见宏值均为 `1`

Trace: `include/picow/lwipopts_examples_common.h:LWIP_DEBUG`

#### Scenario: 调试类别默认关闭
- **GIVEN** 编译单元包含该头文件
- **WHEN** 预处理调试类别宏定义
- **THEN** `ETHARP_DEBUG`、`NETIF_DEBUG`、`PBUF_DEBUG`、`API_LIB_DEBUG`、`API_MSG_DEBUG`、`SOCKETS_DEBUG`、`ICMP_DEBUG`、`INET_DEBUG`、`IP_DEBUG`、`IP_REASS_DEBUG`、`RAW_DEBUG`、`MEM_DEBUG`、`MEMP_DEBUG`、`SYS_DEBUG`、`TCP_DEBUG`、`TCP_INPUT_DEBUG`、`TCP_OUTPUT_DEBUG`、`TCP_RTO_DEBUG`、`TCP_CWND_DEBUG`、`TCP_WND_DEBUG`、`TCP_FR_DEBUG`、`TCP_QLEN_DEBUG`、`TCP_RST_DEBUG`、`UDP_DEBUG`、`TCPIP_DEBUG`、`PPP_DEBUG`、`SLIP_DEBUG` 和 `DHCP_DEBUG` 的可见宏值均为 `LWIP_DBG_OFF`

Trace: `include/picow/lwipopts_examples_common.h:debug option constants`

## Open Questions

| ID | Question | Related Interface | Reason |
| --- | --- | --- | --- |
| Q-001 | `PICO_CYW43_ARCH_POLL` 未定义时预处理器取值是否在所有 Pico SDK 构建中等价于非轮询分支？ | MEM_LIBC_MALLOC | 当前文件只使用 `#if PICO_CYW43_ARCH_POLL`，项目上下文未确认 Pico SDK 对该宏的默认定义策略。 |
