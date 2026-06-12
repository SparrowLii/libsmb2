# include/picow/lwipopts.h Specification

## Source Context

- Source: `include/picow/lwipopts.h`
- Related Headers: `include/picow/lwipopts_examples_common.h`
- Related Tests: `none`
- Related Dependencies: `GitNexus context found macros in include/picow/lwipopts.h with no incoming callers, outgoing calls, or processes; grep confirmed references are limited to include/picow/lwipopts.h and include/picow/lwipopts_examples_common.h.`
- Build/Compile Context: `PICO build path enables C, CXX, and ASM; include/picow/lwipopts.h includes lwipopts_examples_common.h; NO_SYS defaults to 1 unless overridden before the common header include.`

## Interface Summary

| Interface | Kind | Signature | Decision | Reason |
| --- | --- | --- | --- | --- |
| LWIP_SO_RCVBUF | macro | #define LWIP_SO_RCVBUF 1 | Include | Pico W lwIP socket receive-buffer behavior is a caller-visible configuration macro. |
| LWIP_TIMEVAL_PRIVATE | macro | #define LWIP_TIMEVAL_PRIVATE 0 | Include | Pico W lwIP timeval ownership is a caller-visible configuration macro. |
| TCPIP_THREAD_STACKSIZE | macro | #define TCPIP_THREAD_STACKSIZE 1024 | Include | When `NO_SYS` is false, the lwIP TCP/IP thread stack size affects runtime resource sizing. |
| DEFAULT_THREAD_STACKSIZE | macro | #define DEFAULT_THREAD_STACKSIZE 1024 | Include | When `NO_SYS` is false, the default lwIP thread stack size affects runtime resource sizing. |
| DEFAULT_RAW_RECVMBOX_SIZE | macro | #define DEFAULT_RAW_RECVMBOX_SIZE 8 | Include | When `NO_SYS` is false, the raw receive mailbox size affects lwIP queue sizing. |
| TCPIP_MBOX_SIZE | macro | #define TCPIP_MBOX_SIZE 8 | Include | When `NO_SYS` is false, this macro provides the shared TCP/IP mailbox size used by other mailbox defaults. |
| DEFAULT_UDP_RECVMBOX_SIZE | macro | #define DEFAULT_UDP_RECVMBOX_SIZE TCPIP_MBOX_SIZE | Include | When `NO_SYS` is false, the UDP receive mailbox size aliases the shared TCP/IP mailbox size. |
| DEFAULT_TCP_RECVMBOX_SIZE | macro | #define DEFAULT_TCP_RECVMBOX_SIZE TCPIP_MBOX_SIZE | Include | When `NO_SYS` is false, the TCP receive mailbox size aliases the shared TCP/IP mailbox size. |
| DEFAULT_ACCEPTMBOX_SIZE | macro | #define DEFAULT_ACCEPTMBOX_SIZE TCPIP_MBOX_SIZE | Include | When `NO_SYS` is false, the accept mailbox size aliases the shared TCP/IP mailbox size. |
| LWIP_TCPIP_CORE_LOCKING_INPUT | macro | #define LWIP_TCPIP_CORE_LOCKING_INPUT 1 | Include | When `NO_SYS` is false, this macro enables lwIP core-locking input behavior. |

## Data Model Summary

| Type/Macro | Kind | Definition | Notes |
| --- | --- | --- | --- |
| LWIP_SO_RCVBUF | macro | include/picow/lwipopts.h:10 | Defines socket receive-buffer support as enabled. |
| LWIP_TIMEVAL_PRIVATE | macro | include/picow/lwipopts.h:11 | Defines lwIP timeval as non-private for this configuration. |
| TCPIP_THREAD_STACKSIZE | macro | include/picow/lwipopts.h:13 | Defined only when `!NO_SYS` evaluates true. |
| DEFAULT_THREAD_STACKSIZE | macro | include/picow/lwipopts.h:14 | Defined only when `!NO_SYS` evaluates true. |
| DEFAULT_RAW_RECVMBOX_SIZE | macro | include/picow/lwipopts.h:15 | Defined only when `!NO_SYS` evaluates true. |
| TCPIP_MBOX_SIZE | macro | include/picow/lwipopts.h:16 | Defined only when `!NO_SYS` evaluates true and used by mailbox default macros. |
| DEFAULT_UDP_RECVMBOX_SIZE | macro | include/picow/lwipopts.h:19 | Defined only when `!NO_SYS` evaluates true and expands to `TCPIP_MBOX_SIZE`. |
| DEFAULT_TCP_RECVMBOX_SIZE | macro | include/picow/lwipopts.h:20 | Defined only when `!NO_SYS` evaluates true and expands to `TCPIP_MBOX_SIZE`. |
| DEFAULT_ACCEPTMBOX_SIZE | macro | include/picow/lwipopts.h:21 | Defined only when `!NO_SYS` evaluates true and expands to `TCPIP_MBOX_SIZE`. |
| LWIP_TCPIP_CORE_LOCKING_INPUT | macro | include/picow/lwipopts.h:24 | Defined only when `!NO_SYS` evaluates true. |

## ADDED Requirements

### Requirement: LWIP_SO_RCVBUF enable receive buffers
系统 MUST expose `LWIP_SO_RCVBUF` as `1` whenever `include/picow/lwipopts.h` is included.

#### Scenario: Pico W socket receive-buffer option
- **GIVEN** Pico W code includes `include/picow/lwipopts.h`
- **WHEN** lwIP evaluates `LWIP_SO_RCVBUF`
- **THEN** the macro expands to `1`

Trace: `include/picow/lwipopts.h:LWIP_SO_RCVBUF`

### Requirement: LWIP_TIMEVAL_PRIVATE use external timeval
系统 MUST expose `LWIP_TIMEVAL_PRIVATE` as `0` whenever `include/picow/lwipopts.h` is included.

#### Scenario: Pico W timeval ownership option
- **GIVEN** Pico W code includes `include/picow/lwipopts.h`
- **WHEN** lwIP evaluates `LWIP_TIMEVAL_PRIVATE`
- **THEN** the macro expands to `0`

Trace: `include/picow/lwipopts.h:LWIP_TIMEVAL_PRIVATE`

### Requirement: TCPIP_THREAD_STACKSIZE set tcpip stack size
系统 MUST define `TCPIP_THREAD_STACKSIZE` as `1024` only within the `#if !NO_SYS` configuration block.

#### Scenario: NO_SYS disabled tcpip stack sizing
- **GIVEN** `NO_SYS` evaluates false after including `include/picow/lwipopts_examples_common.h`
- **WHEN** lwIP evaluates `TCPIP_THREAD_STACKSIZE`
- **THEN** the macro expands to `1024`

Trace: `include/picow/lwipopts.h:TCPIP_THREAD_STACKSIZE`

### Requirement: DEFAULT_THREAD_STACKSIZE set default stack size
系统 MUST define `DEFAULT_THREAD_STACKSIZE` as `1024` only within the `#if !NO_SYS` configuration block.

#### Scenario: NO_SYS disabled default stack sizing
- **GIVEN** `NO_SYS` evaluates false after including `include/picow/lwipopts_examples_common.h`
- **WHEN** lwIP evaluates `DEFAULT_THREAD_STACKSIZE`
- **THEN** the macro expands to `1024`

Trace: `include/picow/lwipopts.h:DEFAULT_THREAD_STACKSIZE`

### Requirement: DEFAULT_RAW_RECVMBOX_SIZE set raw mailbox size
系统 MUST define `DEFAULT_RAW_RECVMBOX_SIZE` as `8` only within the `#if !NO_SYS` configuration block.

#### Scenario: NO_SYS disabled raw receive mailbox sizing
- **GIVEN** `NO_SYS` evaluates false after including `include/picow/lwipopts_examples_common.h`
- **WHEN** lwIP evaluates `DEFAULT_RAW_RECVMBOX_SIZE`
- **THEN** the macro expands to `8`

Trace: `include/picow/lwipopts.h:DEFAULT_RAW_RECVMBOX_SIZE`

### Requirement: TCPIP_MBOX_SIZE set shared mailbox size
系统 MUST define `TCPIP_MBOX_SIZE` as `8` only within the `#if !NO_SYS` configuration block.

#### Scenario: NO_SYS disabled shared mailbox sizing
- **GIVEN** `NO_SYS` evaluates false after including `include/picow/lwipopts_examples_common.h`
- **WHEN** lwIP evaluates `TCPIP_MBOX_SIZE`
- **THEN** the macro expands to `8`

Trace: `include/picow/lwipopts.h:TCPIP_MBOX_SIZE`

### Requirement: DEFAULT_UDP_RECVMBOX_SIZE alias shared mailbox size
系统 MUST define `DEFAULT_UDP_RECVMBOX_SIZE` as `TCPIP_MBOX_SIZE` only within the `#if !NO_SYS` configuration block.

#### Scenario: NO_SYS disabled UDP receive mailbox sizing
- **GIVEN** `NO_SYS` evaluates false and `TCPIP_MBOX_SIZE` is defined by `include/picow/lwipopts.h`
- **WHEN** lwIP evaluates `DEFAULT_UDP_RECVMBOX_SIZE`
- **THEN** the macro expands to `TCPIP_MBOX_SIZE`

Trace: `include/picow/lwipopts.h:DEFAULT_UDP_RECVMBOX_SIZE`

### Requirement: DEFAULT_TCP_RECVMBOX_SIZE alias shared mailbox size
系统 MUST define `DEFAULT_TCP_RECVMBOX_SIZE` as `TCPIP_MBOX_SIZE` only within the `#if !NO_SYS` configuration block.

#### Scenario: NO_SYS disabled TCP receive mailbox sizing
- **GIVEN** `NO_SYS` evaluates false and `TCPIP_MBOX_SIZE` is defined by `include/picow/lwipopts.h`
- **WHEN** lwIP evaluates `DEFAULT_TCP_RECVMBOX_SIZE`
- **THEN** the macro expands to `TCPIP_MBOX_SIZE`

Trace: `include/picow/lwipopts.h:DEFAULT_TCP_RECVMBOX_SIZE`

### Requirement: DEFAULT_ACCEPTMBOX_SIZE alias shared mailbox size
系统 MUST define `DEFAULT_ACCEPTMBOX_SIZE` as `TCPIP_MBOX_SIZE` only within the `#if !NO_SYS` configuration block.

#### Scenario: NO_SYS disabled accept mailbox sizing
- **GIVEN** `NO_SYS` evaluates false and `TCPIP_MBOX_SIZE` is defined by `include/picow/lwipopts.h`
- **WHEN** lwIP evaluates `DEFAULT_ACCEPTMBOX_SIZE`
- **THEN** the macro expands to `TCPIP_MBOX_SIZE`

Trace: `include/picow/lwipopts.h:DEFAULT_ACCEPTMBOX_SIZE`

### Requirement: LWIP_TCPIP_CORE_LOCKING_INPUT enable core-locking input
系统 MUST define `LWIP_TCPIP_CORE_LOCKING_INPUT` as `1` only within the `#if !NO_SYS` configuration block.

#### Scenario: NO_SYS disabled core-locking input option
- **GIVEN** `NO_SYS` evaluates false after including `include/picow/lwipopts_examples_common.h`
- **WHEN** lwIP evaluates `LWIP_TCPIP_CORE_LOCKING_INPUT`
- **THEN** the macro expands to `1`

Trace: `include/picow/lwipopts.h:LWIP_TCPIP_CORE_LOCKING_INPUT`

## Open Questions

| ID | Question | Related Interface | Reason |
| --- | --- | --- | --- |
| Q-001 | `NO_SYS` 默认由 `include/picow/lwipopts_examples_common.h` 定义为 `1`，当前文件的 `#if !NO_SYS` 分支是否依赖外部编译单元预先覆盖 `NO_SYS`？ | TCPIP_THREAD_STACKSIZE, DEFAULT_THREAD_STACKSIZE, DEFAULT_RAW_RECVMBOX_SIZE, TCPIP_MBOX_SIZE, DEFAULT_UDP_RECVMBOX_SIZE, DEFAULT_TCP_RECVMBOX_SIZE, DEFAULT_ACCEPTMBOX_SIZE, LWIP_TCPIP_CORE_LOCKING_INPUT | 源码只显示 common header 允许预先覆盖 `NO_SYS`，未在本文件或 GitNexus 调用关系中确认覆盖来源。 |
