# include/picow/FreeRTOSConfig.h Specification

## Source Context

- Source: `include/picow/FreeRTOSConfig.h`
- Related Headers: `<assert.h>`
- Related Tests: `none`
- Related Dependencies: `GitNexus context configUSE_PREEMPTION/configUSE_TIMERS/configNUM_CORES/configSUPPORT_PICO_SYNC_INTEROP/configASSERT reported no incoming callers, no outgoing callees, and no execution processes; GitNexus impact configUSE_PREEMPTION/configASSERT reported LOW risk with 0 direct callers and 0 affected processes.`
- Build/Compile Context: `PICO build path enables C/CXX/ASM; compile conditions include PICO_BOARD/PICO_PLATFORM from project context; this header has conditional SMP macros guarded by FREE_RTOS_KERNEL_SMP.`

## Interface Summary

| Interface | Kind | Signature | Decision | Reason |
| --- | --- | --- | --- | --- |
| configUSE_PREEMPTION | macro | #define configUSE_PREEMPTION                    1 | Include | 调度器抢占配置对 FreeRTOS 内核编译行为可见。 |
| configUSE_TICKLESS_IDLE | macro | #define configUSE_TICKLESS_IDLE                 0 | Include | tickless idle 配置对调度节拍行为可见。 |
| configTICK_RATE_HZ | macro | #define configTICK_RATE_HZ                      ( ( TickType_t ) 1000 ) | Include | 系统 tick 频率是调用方可观察的时间基准。 |
| configMAX_PRIORITIES | macro | #define configMAX_PRIORITIES                    32 | Include | 最大任务优先级数量影响任务创建和调度范围。 |
| configMINIMAL_STACK_SIZE | macro | #define configMINIMAL_STACK_SIZE                ( configSTACK_DEPTH_TYPE ) 2048 | Include | 最小栈深度影响 FreeRTOS 任务资源契约。 |
| configUSE_MUTEXES | macro | #define configUSE_MUTEXES                       1 | Include | mutex 支持开关影响同步 API 可用性。 |
| configUSE_RECURSIVE_MUTEXES | macro | #define configUSE_RECURSIVE_MUTEXES             1 | Include | recursive mutex 支持开关影响同步 API 可用性。 |
| configUSE_COUNTING_SEMAPHORES | macro | #define configUSE_COUNTING_SEMAPHORES           1 | Include | counting semaphore 支持开关影响同步 API 可用性。 |
| configQUEUE_REGISTRY_SIZE | macro | #define configQUEUE_REGISTRY_SIZE               8 | Include | queue registry 容量是 FreeRTOS 可见配置限制。 |
| configENABLE_BACKWARD_COMPATIBILITY | macro | #define configENABLE_BACKWARD_COMPATIBILITY     1 | Include | 兼容性开关影响 lwIP FreeRTOS sys_arch 编译兼容。 |
| configNUM_THREAD_LOCAL_STORAGE_POINTERS | macro | #define configNUM_THREAD_LOCAL_STORAGE_POINTERS 5 | Include | TLS 指针数量影响任务本地存储容量。 |
| configSTACK_DEPTH_TYPE | macro | #define configSTACK_DEPTH_TYPE                  uint32_t | Include | 栈深度类型影响配置宏和 FreeRTOS ABI 类型契约。 |
| configMESSAGE_BUFFER_LENGTH_TYPE | macro | #define configMESSAGE_BUFFER_LENGTH_TYPE        size_t | Include | message buffer 长度类型影响 FreeRTOS buffer API 类型契约。 |
| configSUPPORT_STATIC_ALLOCATION | macro | #define configSUPPORT_STATIC_ALLOCATION         0 | Include | 静态分配开关影响内核对象分配模式。 |
| configSUPPORT_DYNAMIC_ALLOCATION | macro | #define configSUPPORT_DYNAMIC_ALLOCATION        1 | Include | 动态分配开关影响内核对象分配模式。 |
| configTOTAL_HEAP_SIZE | macro | #define configTOTAL_HEAP_SIZE                   (128*1024) | Include | heap 大小是动态分配资源上限。 |
| configCHECK_FOR_STACK_OVERFLOW | macro | #define configCHECK_FOR_STACK_OVERFLOW          0 | Include | 栈溢出检查开关影响开发期诊断行为。 |
| configUSE_TRACE_FACILITY | macro | #define configUSE_TRACE_FACILITY                1 | Include | trace facility 开关影响调试/跟踪数据可用性。 |
| configUSE_CO_ROUTINES | macro | #define configUSE_CO_ROUTINES                   0 | Include | co-routine 支持开关影响旧式 FreeRTOS API 可用性。 |
| configUSE_TIMERS | macro | #define configUSE_TIMERS                        1 | Include | software timer 支持开关影响 timer API 可用性。 |
| configTIMER_TASK_PRIORITY | macro | #define configTIMER_TASK_PRIORITY               ( configMAX_PRIORITIES - 1 ) | Include | timer task 优先级影响 timer 服务任务调度。 |
| configTIMER_QUEUE_LENGTH | macro | #define configTIMER_QUEUE_LENGTH                10 | Include | timer queue 长度影响可排队 timer 命令容量。 |
| configTIMER_TASK_STACK_DEPTH | macro | #define configTIMER_TASK_STACK_DEPTH            1024 | Include | timer task 栈深度影响 timer 服务任务资源。 |
| configNUM_CORES | macro | #define configNUM_CORES                         2 | Include | SMP 条件下核心数量配置影响 RP2040 SMP 内核编译行为。 |
| configTICK_CORE | macro | #define configTICK_CORE                         0 | Include | SMP 条件下 tick core 选择影响 tick 归属。 |
| configRUN_MULTIPLE_PRIORITIES | macro | #define configRUN_MULTIPLE_PRIORITIES           1 | Include | SMP 条件下多优先级并行运行配置影响调度行为。 |
| configUSE_CORE_AFFINITY | macro | #define configUSE_CORE_AFFINITY                 1 | Include | SMP 条件下 core affinity 支持影响任务亲和性 API 行为。 |
| configSUPPORT_PICO_SYNC_INTEROP | macro | #define configSUPPORT_PICO_SYNC_INTEROP         1 | Include | Pico sync interop 支持开关影响 RP2040 SDK 集成。 |
| configSUPPORT_PICO_TIME_INTEROP | macro | #define configSUPPORT_PICO_TIME_INTEROP         1 | Include | Pico time interop 支持开关影响 RP2040 SDK 集成。 |
| configASSERT | macro | #define configASSERT(x)                         assert(x) | Include | 断言宏映射到 C assert，影响开发期错误陷阱。 |
| INCLUDE_vTaskPrioritySet | macro | #define INCLUDE_vTaskPrioritySet                1 | Include | FreeRTOS API include 开关影响任务优先级设置 API 可用性。 |
| INCLUDE_uxTaskPriorityGet | macro | #define INCLUDE_uxTaskPriorityGet               1 | Include | FreeRTOS API include 开关影响任务优先级查询 API 可用性。 |
| INCLUDE_vTaskDelete | macro | #define INCLUDE_vTaskDelete                     1 | Include | FreeRTOS API include 开关影响任务删除 API 可用性。 |
| INCLUDE_vTaskSuspend | macro | #define INCLUDE_vTaskSuspend                    1 | Include | FreeRTOS API include 开关影响任务挂起 API 可用性。 |
| INCLUDE_vTaskDelayUntil | macro | #define INCLUDE_vTaskDelayUntil                 1 | Include | FreeRTOS API include 开关影响周期延迟 API 可用性。 |
| INCLUDE_vTaskDelay | macro | #define INCLUDE_vTaskDelay                      1 | Include | FreeRTOS API include 开关影响任务延迟 API 可用性。 |
| INCLUDE_xTaskGetSchedulerState | macro | #define INCLUDE_xTaskGetSchedulerState          1 | Include | FreeRTOS API include 开关影响调度器状态查询 API 可用性。 |
| INCLUDE_xTaskGetCurrentTaskHandle | macro | #define INCLUDE_xTaskGetCurrentTaskHandle       1 | Include | FreeRTOS API include 开关影响当前任务句柄 API 可用性。 |
| INCLUDE_uxTaskGetStackHighWaterMark | macro | #define INCLUDE_uxTaskGetStackHighWaterMark     1 | Include | FreeRTOS API include 开关影响栈高水位查询 API 可用性。 |
| INCLUDE_xTaskGetIdleTaskHandle | macro | #define INCLUDE_xTaskGetIdleTaskHandle          1 | Include | FreeRTOS API include 开关影响 idle task 句柄 API 可用性。 |
| INCLUDE_eTaskGetState | macro | #define INCLUDE_eTaskGetState                   1 | Include | FreeRTOS API include 开关影响任务状态查询 API 可用性。 |
| INCLUDE_xTimerPendFunctionCall | macro | #define INCLUDE_xTimerPendFunctionCall          1 | Include | FreeRTOS API include 开关影响 timer pend function API 可用性。 |
| INCLUDE_xTaskAbortDelay | macro | #define INCLUDE_xTaskAbortDelay                 1 | Include | FreeRTOS API include 开关影响 abort delay API 可用性。 |
| INCLUDE_xTaskGetHandle | macro | #define INCLUDE_xTaskGetHandle                  1 | Include | FreeRTOS API include 开关影响按名查询任务句柄 API 可用性。 |
| INCLUDE_xTaskResumeFromISR | macro | #define INCLUDE_xTaskResumeFromISR              1 | Include | FreeRTOS API include 开关影响 ISR 恢复任务 API 可用性。 |
| INCLUDE_xQueueGetMutexHolder | macro | #define INCLUDE_xQueueGetMutexHolder            1 | Include | FreeRTOS API include 开关影响 mutex holder 查询 API 可用性。 |
| configUSE_IDLE_HOOK | macro | #define configUSE_IDLE_HOOK                     0 | Skip | 简单 hook 开关且源码未显示项目自定义 idle hook 行为。 |
| configUSE_TICK_HOOK | macro | #define configUSE_TICK_HOOK                     0 | Skip | 简单 hook 开关且源码未显示项目自定义 tick hook 行为。 |
| configUSE_16_BIT_TICKS | macro | #define configUSE_16_BIT_TICKS                  0 | Skip | 简单类型宽度开关，已由 tick rate/栈类型相关契约覆盖。 |
| configIDLE_SHOULD_YIELD | macro | #define configIDLE_SHOULD_YIELD                 1 | Skip | 调度细节开关，无独立项目可观察接口。 |
| configUSE_APPLICATION_TASK_TAG | macro | #define configUSE_APPLICATION_TASK_TAG          0 | Skip | task tag 扩展开关禁用，无独立可用 API 契约。 |
| configUSE_QUEUE_SETS | macro | #define configUSE_QUEUE_SETS                    1 | Skip | 简单功能开关，未发现项目源码直接依赖。 |
| configUSE_TIME_SLICING | macro | #define configUSE_TIME_SLICING                  1 | Skip | 调度细节开关，无独立项目可观察接口。 |
| configUSE_NEWLIB_REENTRANT | macro | #define configUSE_NEWLIB_REENTRANT              0 | Skip | newlib reentrant 支持禁用，未发现项目源码依赖。 |
| configAPPLICATION_ALLOCATED_HEAP | macro | #define configAPPLICATION_ALLOCATED_HEAP        0 | Skip | heap 放置策略细节，无独立项目接口。 |
| configUSE_MALLOC_FAILED_HOOK | macro | #define configUSE_MALLOC_FAILED_HOOK            0 | Skip | malloc failed hook 禁用，未发现项目自定义 hook。 |
| configUSE_DAEMON_TASK_STARTUP_HOOK | macro | #define configUSE_DAEMON_TASK_STARTUP_HOOK      0 | Skip | daemon startup hook 禁用，未发现项目自定义 hook。 |
| configGENERATE_RUN_TIME_STATS | macro | #define configGENERATE_RUN_TIME_STATS           0 | Skip | runtime stats 生成禁用，未发现项目统计接口依赖。 |
| configUSE_STATS_FORMATTING_FUNCTIONS | macro | #define configUSE_STATS_FORMATTING_FUNCTIONS    0 | Skip | stats formatting 禁用，未发现项目统计接口依赖。 |
| configMAX_CO_ROUTINE_PRIORITIES | macro | #define configMAX_CO_ROUTINE_PRIORITIES         1 | Skip | co-routine 已禁用，该优先级限制无独立有效契约。 |

## Data Model Summary

| Type/Macro | Kind | Definition | Notes |
| --- | --- | --- | --- |
| configUSE_PREEMPTION | macro | include/picow/FreeRTOSConfig.h:44 | 启用抢占式调度。 |
| configTICK_RATE_HZ | macro | include/picow/FreeRTOSConfig.h:48 | tick 频率为 1000Hz，类型转换为 `TickType_t`。 |
| configMAX_PRIORITIES | macro | include/picow/FreeRTOSConfig.h:49 | 最大优先级数量为 32。 |
| configSTACK_DEPTH_TYPE | macro | include/picow/FreeRTOSConfig.h:69 | 栈深度类型为 `uint32_t`。 |
| configMESSAGE_BUFFER_LENGTH_TYPE | macro | include/picow/FreeRTOSConfig.h:70 | message buffer 长度类型为 `size_t`。 |
| configTOTAL_HEAP_SIZE | macro | include/picow/FreeRTOSConfig.h:75 | 动态 heap 上限为 128 KiB。 |
| configNUM_CORES | macro | include/picow/FreeRTOSConfig.h:107 | 仅在 `FREE_RTOS_KERNEL_SMP` 为真时定义，核心数为 2。 |
| configASSERT | macro | include/picow/FreeRTOSConfig.h:119 | 断言表达式转发给 `<assert.h>` 的 `assert(x)`。 |

## ADDED Requirements

### Requirement: configUSE_PREEMPTION scheduler mode
系统 MUST 将 `configUSE_PREEMPTION` 定义为 `1`，使 FreeRTOS 内核以抢占式调度配置编译。

#### Scenario: 抢占式调度启用
- **GIVEN** Pico FreeRTOS 配置头被内核或应用构建包含
- **WHEN** 编译单元读取 `configUSE_PREEMPTION`
- **THEN** 宏展开结果为 `1`

Trace: `include/picow/FreeRTOSConfig.h:configUSE_PREEMPTION`

### Requirement: configUSE_TICKLESS_IDLE tickless idle disabled
系统 MUST 将 `configUSE_TICKLESS_IDLE` 定义为 `0`，使 tickless idle 不作为该 Pico 配置的编译能力启用。

#### Scenario: tickless idle 禁用
- **GIVEN** Pico FreeRTOS 配置头被内核或应用构建包含
- **WHEN** 编译单元读取 `configUSE_TICKLESS_IDLE`
- **THEN** 宏展开结果为 `0`

Trace: `include/picow/FreeRTOSConfig.h:configUSE_TICKLESS_IDLE`

### Requirement: configTICK_RATE_HZ tick frequency
系统 MUST 将 `configTICK_RATE_HZ` 定义为 `( ( TickType_t ) 1000 )`，使 FreeRTOS tick 频率配置为 1000Hz。

#### Scenario: tick 频率配置
- **GIVEN** Pico FreeRTOS 配置头被内核或应用构建包含
- **WHEN** 编译单元读取 `configTICK_RATE_HZ`
- **THEN** 宏展开为强制转换到 `TickType_t` 的 `1000`

Trace: `include/picow/FreeRTOSConfig.h:configTICK_RATE_HZ`

### Requirement: configMAX_PRIORITIES priority count
系统 MUST 将 `configMAX_PRIORITIES` 定义为 `32`，使 FreeRTOS 任务优先级范围以 32 个等级编译。

#### Scenario: 最大优先级数量
- **GIVEN** Pico FreeRTOS 配置头被内核或应用构建包含
- **WHEN** 编译单元读取 `configMAX_PRIORITIES`
- **THEN** 宏展开结果为 `32`

Trace: `include/picow/FreeRTOSConfig.h:configMAX_PRIORITIES`

### Requirement: configMINIMAL_STACK_SIZE minimal stack
系统 MUST 将 `configMINIMAL_STACK_SIZE` 定义为 `( configSTACK_DEPTH_TYPE ) 2048`，使最小任务栈深度使用配置的栈深度类型表达。

#### Scenario: 最小栈深度配置
- **GIVEN** Pico FreeRTOS 配置头被内核或应用构建包含
- **WHEN** 编译单元读取 `configMINIMAL_STACK_SIZE`
- **THEN** 宏展开为 `2048` 且转换到 `configSTACK_DEPTH_TYPE`

Trace: `include/picow/FreeRTOSConfig.h:configMINIMAL_STACK_SIZE`

### Requirement: configUSE_MUTEXES mutex support
系统 MUST 将 `configUSE_MUTEXES` 定义为 `1`，使 FreeRTOS mutex 支持参与编译。

#### Scenario: mutex 支持启用
- **GIVEN** Pico FreeRTOS 配置头被内核或应用构建包含
- **WHEN** 编译单元读取 `configUSE_MUTEXES`
- **THEN** 宏展开结果为 `1`

Trace: `include/picow/FreeRTOSConfig.h:configUSE_MUTEXES`

### Requirement: configUSE_RECURSIVE_MUTEXES recursive mutex support
系统 MUST 将 `configUSE_RECURSIVE_MUTEXES` 定义为 `1`，使 recursive mutex 支持参与编译。

#### Scenario: recursive mutex 支持启用
- **GIVEN** Pico FreeRTOS 配置头被内核或应用构建包含
- **WHEN** 编译单元读取 `configUSE_RECURSIVE_MUTEXES`
- **THEN** 宏展开结果为 `1`

Trace: `include/picow/FreeRTOSConfig.h:configUSE_RECURSIVE_MUTEXES`

### Requirement: configUSE_COUNTING_SEMAPHORES counting semaphore support
系统 MUST 将 `configUSE_COUNTING_SEMAPHORES` 定义为 `1`，使 counting semaphore 支持参与编译。

#### Scenario: counting semaphore 支持启用
- **GIVEN** Pico FreeRTOS 配置头被内核或应用构建包含
- **WHEN** 编译单元读取 `configUSE_COUNTING_SEMAPHORES`
- **THEN** 宏展开结果为 `1`

Trace: `include/picow/FreeRTOSConfig.h:configUSE_COUNTING_SEMAPHORES`

### Requirement: configQUEUE_REGISTRY_SIZE queue registry capacity
系统 MUST 将 `configQUEUE_REGISTRY_SIZE` 定义为 `8`，使 FreeRTOS queue registry 容量限制为 8 个条目。

#### Scenario: queue registry 容量
- **GIVEN** Pico FreeRTOS 配置头被内核或应用构建包含
- **WHEN** 编译单元读取 `configQUEUE_REGISTRY_SIZE`
- **THEN** 宏展开结果为 `8`

Trace: `include/picow/FreeRTOSConfig.h:configQUEUE_REGISTRY_SIZE`

### Requirement: configENABLE_BACKWARD_COMPATIBILITY compatibility mode
系统 MUST 将 `configENABLE_BACKWARD_COMPATIBILITY` 定义为 `1`，使依赖 FreeRTOS 兼容名称的 lwIP sys_arch 编译路径可用。

#### Scenario: 兼容性启用
- **GIVEN** Pico FreeRTOS 配置头被 lwIP FreeRTOS sys_arch 或应用构建包含
- **WHEN** 编译单元读取 `configENABLE_BACKWARD_COMPATIBILITY`
- **THEN** 宏展开结果为 `1`

Trace: `include/picow/FreeRTOSConfig.h:configENABLE_BACKWARD_COMPATIBILITY`

### Requirement: configNUM_THREAD_LOCAL_STORAGE_POINTERS TLS pointer count
系统 MUST 将 `configNUM_THREAD_LOCAL_STORAGE_POINTERS` 定义为 `5`，使每个任务的线程本地存储指针数量配置为 5。

#### Scenario: TLS 指针数量
- **GIVEN** Pico FreeRTOS 配置头被内核或应用构建包含
- **WHEN** 编译单元读取 `configNUM_THREAD_LOCAL_STORAGE_POINTERS`
- **THEN** 宏展开结果为 `5`

Trace: `include/picow/FreeRTOSConfig.h:configNUM_THREAD_LOCAL_STORAGE_POINTERS`

### Requirement: configSTACK_DEPTH_TYPE stack depth type
系统 MUST 将 `configSTACK_DEPTH_TYPE` 定义为 `uint32_t`，使栈深度相关配置使用 32 位无符号整数类型。

#### Scenario: 栈深度类型
- **GIVEN** Pico FreeRTOS 配置头被内核或应用构建包含
- **WHEN** 编译单元读取 `configSTACK_DEPTH_TYPE`
- **THEN** 宏展开结果为 `uint32_t`

Trace: `include/picow/FreeRTOSConfig.h:configSTACK_DEPTH_TYPE`

### Requirement: configMESSAGE_BUFFER_LENGTH_TYPE message buffer length type
系统 MUST 将 `configMESSAGE_BUFFER_LENGTH_TYPE` 定义为 `size_t`，使 message buffer 长度使用 C 标准大小类型表达。

#### Scenario: message buffer 长度类型
- **GIVEN** Pico FreeRTOS 配置头被内核或应用构建包含
- **WHEN** 编译单元读取 `configMESSAGE_BUFFER_LENGTH_TYPE`
- **THEN** 宏展开结果为 `size_t`

Trace: `include/picow/FreeRTOSConfig.h:configMESSAGE_BUFFER_LENGTH_TYPE`

### Requirement: configSUPPORT_STATIC_ALLOCATION static allocation mode
系统 MUST 将 `configSUPPORT_STATIC_ALLOCATION` 定义为 `0`，使静态分配支持不作为该 Pico 配置的内核对象分配模式启用。

#### Scenario: 静态分配禁用
- **GIVEN** Pico FreeRTOS 配置头被内核或应用构建包含
- **WHEN** 编译单元读取 `configSUPPORT_STATIC_ALLOCATION`
- **THEN** 宏展开结果为 `0`

Trace: `include/picow/FreeRTOSConfig.h:configSUPPORT_STATIC_ALLOCATION`

### Requirement: configSUPPORT_DYNAMIC_ALLOCATION dynamic allocation mode
系统 MUST 将 `configSUPPORT_DYNAMIC_ALLOCATION` 定义为 `1`，使动态分配支持作为该 Pico 配置的内核对象分配模式启用。

#### Scenario: 动态分配启用
- **GIVEN** Pico FreeRTOS 配置头被内核或应用构建包含
- **WHEN** 编译单元读取 `configSUPPORT_DYNAMIC_ALLOCATION`
- **THEN** 宏展开结果为 `1`

Trace: `include/picow/FreeRTOSConfig.h:configSUPPORT_DYNAMIC_ALLOCATION`

### Requirement: configTOTAL_HEAP_SIZE heap capacity
系统 MUST 将 `configTOTAL_HEAP_SIZE` 定义为 `(128*1024)`，使 FreeRTOS 动态 heap 容量配置为 128 KiB。

#### Scenario: heap 容量配置
- **GIVEN** Pico FreeRTOS 配置头被内核或应用构建包含
- **WHEN** 编译单元读取 `configTOTAL_HEAP_SIZE`
- **THEN** 宏展开为 `128*1024`

Trace: `include/picow/FreeRTOSConfig.h:configTOTAL_HEAP_SIZE`

### Requirement: configCHECK_FOR_STACK_OVERFLOW stack overflow checking
系统 MUST 将 `configCHECK_FOR_STACK_OVERFLOW` 定义为 `0`，使 FreeRTOS 栈溢出检查不作为该配置的运行时诊断启用。

#### Scenario: 栈溢出检查禁用
- **GIVEN** Pico FreeRTOS 配置头被内核或应用构建包含
- **WHEN** 编译单元读取 `configCHECK_FOR_STACK_OVERFLOW`
- **THEN** 宏展开结果为 `0`

Trace: `include/picow/FreeRTOSConfig.h:configCHECK_FOR_STACK_OVERFLOW`

### Requirement: configUSE_TRACE_FACILITY trace facility support
系统 MUST 将 `configUSE_TRACE_FACILITY` 定义为 `1`，使 FreeRTOS trace facility 支持参与编译。

#### Scenario: trace facility 启用
- **GIVEN** Pico FreeRTOS 配置头被内核或应用构建包含
- **WHEN** 编译单元读取 `configUSE_TRACE_FACILITY`
- **THEN** 宏展开结果为 `1`

Trace: `include/picow/FreeRTOSConfig.h:configUSE_TRACE_FACILITY`

### Requirement: configUSE_CO_ROUTINES co-routine support
系统 MUST 将 `configUSE_CO_ROUTINES` 定义为 `0`，使 FreeRTOS co-routine 支持不作为该配置的编译能力启用。

#### Scenario: co-routine 禁用
- **GIVEN** Pico FreeRTOS 配置头被内核或应用构建包含
- **WHEN** 编译单元读取 `configUSE_CO_ROUTINES`
- **THEN** 宏展开结果为 `0`

Trace: `include/picow/FreeRTOSConfig.h:configUSE_CO_ROUTINES`

### Requirement: configUSE_TIMERS software timer support
系统 MUST 将 `configUSE_TIMERS` 定义为 `1`，使 FreeRTOS software timer 支持参与编译。

#### Scenario: software timer 启用
- **GIVEN** Pico FreeRTOS 配置头被内核或应用构建包含
- **WHEN** 编译单元读取 `configUSE_TIMERS`
- **THEN** 宏展开结果为 `1`

Trace: `include/picow/FreeRTOSConfig.h:configUSE_TIMERS`

### Requirement: configTIMER_TASK_PRIORITY timer task priority
系统 MUST 将 `configTIMER_TASK_PRIORITY` 定义为 `( configMAX_PRIORITIES - 1 )`，使 timer 服务任务使用最高配置优先级。

#### Scenario: timer task 优先级
- **GIVEN** Pico FreeRTOS 配置头被内核或应用构建包含
- **WHEN** 编译单元读取 `configTIMER_TASK_PRIORITY`
- **THEN** 宏展开为 `configMAX_PRIORITIES - 1`

Trace: `include/picow/FreeRTOSConfig.h:configTIMER_TASK_PRIORITY`

### Requirement: configTIMER_QUEUE_LENGTH timer queue capacity
系统 MUST 将 `configTIMER_QUEUE_LENGTH` 定义为 `10`，使 timer command queue 容量配置为 10。

#### Scenario: timer queue 容量
- **GIVEN** Pico FreeRTOS 配置头被内核或应用构建包含
- **WHEN** 编译单元读取 `configTIMER_QUEUE_LENGTH`
- **THEN** 宏展开结果为 `10`

Trace: `include/picow/FreeRTOSConfig.h:configTIMER_QUEUE_LENGTH`

### Requirement: configTIMER_TASK_STACK_DEPTH timer task stack
系统 MUST 将 `configTIMER_TASK_STACK_DEPTH` 定义为 `1024`，使 timer 服务任务栈深度配置为 1024。

#### Scenario: timer task 栈深度
- **GIVEN** Pico FreeRTOS 配置头被内核或应用构建包含
- **WHEN** 编译单元读取 `configTIMER_TASK_STACK_DEPTH`
- **THEN** 宏展开结果为 `1024`

Trace: `include/picow/FreeRTOSConfig.h:configTIMER_TASK_STACK_DEPTH`

### Requirement: configNUM_CORES SMP core count
系统 MUST 在 `FREE_RTOS_KERNEL_SMP` 为真时将 `configNUM_CORES` 定义为 `2`，使 RP2040 SMP FreeRTOS 内核按双核心配置编译。

#### Scenario: SMP 核心数量配置
- **GIVEN** `FREE_RTOS_KERNEL_SMP` 为真且 Pico FreeRTOS 配置头被内核构建包含
- **WHEN** 编译单元读取 `configNUM_CORES`
- **THEN** 宏展开结果为 `2`

Trace: `include/picow/FreeRTOSConfig.h:configNUM_CORES`

### Requirement: configTICK_CORE SMP tick core
系统 MUST 在 `FREE_RTOS_KERNEL_SMP` 为真时将 `configTICK_CORE` 定义为 `0`，使 SMP tick 归属核心配置为 core 0。

#### Scenario: SMP tick core 配置
- **GIVEN** `FREE_RTOS_KERNEL_SMP` 为真且 Pico FreeRTOS 配置头被内核构建包含
- **WHEN** 编译单元读取 `configTICK_CORE`
- **THEN** 宏展开结果为 `0`

Trace: `include/picow/FreeRTOSConfig.h:configTICK_CORE`

### Requirement: configRUN_MULTIPLE_PRIORITIES SMP multi-priority scheduling
系统 MUST 在 `FREE_RTOS_KERNEL_SMP` 为真时将 `configRUN_MULTIPLE_PRIORITIES` 定义为 `1`，使 SMP 调度允许多个优先级并行运行的配置参与编译。

#### Scenario: SMP 多优先级运行启用
- **GIVEN** `FREE_RTOS_KERNEL_SMP` 为真且 Pico FreeRTOS 配置头被内核构建包含
- **WHEN** 编译单元读取 `configRUN_MULTIPLE_PRIORITIES`
- **THEN** 宏展开结果为 `1`

Trace: `include/picow/FreeRTOSConfig.h:configRUN_MULTIPLE_PRIORITIES`

### Requirement: configUSE_CORE_AFFINITY SMP core affinity
系统 MUST 在 `FREE_RTOS_KERNEL_SMP` 为真时将 `configUSE_CORE_AFFINITY` 定义为 `1`，使任务 core affinity 支持参与 SMP 内核编译。

#### Scenario: SMP core affinity 启用
- **GIVEN** `FREE_RTOS_KERNEL_SMP` 为真且 Pico FreeRTOS 配置头被内核构建包含
- **WHEN** 编译单元读取 `configUSE_CORE_AFFINITY`
- **THEN** 宏展开结果为 `1`

Trace: `include/picow/FreeRTOSConfig.h:configUSE_CORE_AFFINITY`

### Requirement: configSUPPORT_PICO_SYNC_INTEROP Pico sync interop
系统 MUST 将 `configSUPPORT_PICO_SYNC_INTEROP` 定义为 `1`，使 RP2040 Pico SDK sync interop 支持参与 FreeRTOS 编译。

#### Scenario: Pico sync interop 启用
- **GIVEN** Pico FreeRTOS 配置头被 RP2040 FreeRTOS 或应用构建包含
- **WHEN** 编译单元读取 `configSUPPORT_PICO_SYNC_INTEROP`
- **THEN** 宏展开结果为 `1`

Trace: `include/picow/FreeRTOSConfig.h:configSUPPORT_PICO_SYNC_INTEROP`

### Requirement: configSUPPORT_PICO_TIME_INTEROP Pico time interop
系统 MUST 将 `configSUPPORT_PICO_TIME_INTEROP` 定义为 `1`，使 RP2040 Pico SDK time interop 支持参与 FreeRTOS 编译。

#### Scenario: Pico time interop 启用
- **GIVEN** Pico FreeRTOS 配置头被 RP2040 FreeRTOS 或应用构建包含
- **WHEN** 编译单元读取 `configSUPPORT_PICO_TIME_INTEROP`
- **THEN** 宏展开结果为 `1`

Trace: `include/picow/FreeRTOSConfig.h:configSUPPORT_PICO_TIME_INTEROP`

### Requirement: configASSERT assertion mapping
系统 MUST 将 `configASSERT(x)` 定义为 `assert(x)`，使 FreeRTOS 断言表达式转发到 C 标准断言机制。

#### Scenario: 断言宏转发
- **GIVEN** Pico FreeRTOS 配置头被内核或应用构建包含且 `<assert.h>` 可用
- **WHEN** 编译单元调用 `configASSERT(x)`
- **THEN** 该调用展开为 `assert(x)`

Trace: `include/picow/FreeRTOSConfig.h:configASSERT`

### Requirement: INCLUDE_vTaskPrioritySet task priority setter availability
系统 MUST 将 `INCLUDE_vTaskPrioritySet` 定义为 `1`，使 `vTaskPrioritySet` API 被 FreeRTOS 编译包含。

#### Scenario: vTaskPrioritySet 包含
- **GIVEN** Pico FreeRTOS 配置头被内核构建包含
- **WHEN** 编译单元读取 `INCLUDE_vTaskPrioritySet`
- **THEN** 宏展开结果为 `1`

Trace: `include/picow/FreeRTOSConfig.h:INCLUDE_vTaskPrioritySet`

### Requirement: INCLUDE_uxTaskPriorityGet task priority getter availability
系统 MUST 将 `INCLUDE_uxTaskPriorityGet` 定义为 `1`，使 `uxTaskPriorityGet` API 被 FreeRTOS 编译包含。

#### Scenario: uxTaskPriorityGet 包含
- **GIVEN** Pico FreeRTOS 配置头被内核构建包含
- **WHEN** 编译单元读取 `INCLUDE_uxTaskPriorityGet`
- **THEN** 宏展开结果为 `1`

Trace: `include/picow/FreeRTOSConfig.h:INCLUDE_uxTaskPriorityGet`

### Requirement: INCLUDE_vTaskDelete task delete availability
系统 MUST 将 `INCLUDE_vTaskDelete` 定义为 `1`，使 `vTaskDelete` API 被 FreeRTOS 编译包含。

#### Scenario: vTaskDelete 包含
- **GIVEN** Pico FreeRTOS 配置头被内核构建包含
- **WHEN** 编译单元读取 `INCLUDE_vTaskDelete`
- **THEN** 宏展开结果为 `1`

Trace: `include/picow/FreeRTOSConfig.h:INCLUDE_vTaskDelete`

### Requirement: INCLUDE_vTaskSuspend task suspend availability
系统 MUST 将 `INCLUDE_vTaskSuspend` 定义为 `1`，使 `vTaskSuspend` API 被 FreeRTOS 编译包含。

#### Scenario: vTaskSuspend 包含
- **GIVEN** Pico FreeRTOS 配置头被内核构建包含
- **WHEN** 编译单元读取 `INCLUDE_vTaskSuspend`
- **THEN** 宏展开结果为 `1`

Trace: `include/picow/FreeRTOSConfig.h:INCLUDE_vTaskSuspend`

### Requirement: INCLUDE_vTaskDelayUntil periodic delay availability
系统 MUST 将 `INCLUDE_vTaskDelayUntil` 定义为 `1`，使 `vTaskDelayUntil` API 被 FreeRTOS 编译包含。

#### Scenario: vTaskDelayUntil 包含
- **GIVEN** Pico FreeRTOS 配置头被内核构建包含
- **WHEN** 编译单元读取 `INCLUDE_vTaskDelayUntil`
- **THEN** 宏展开结果为 `1`

Trace: `include/picow/FreeRTOSConfig.h:INCLUDE_vTaskDelayUntil`

### Requirement: INCLUDE_vTaskDelay task delay availability
系统 MUST 将 `INCLUDE_vTaskDelay` 定义为 `1`，使 `vTaskDelay` API 被 FreeRTOS 编译包含。

#### Scenario: vTaskDelay 包含
- **GIVEN** Pico FreeRTOS 配置头被内核构建包含
- **WHEN** 编译单元读取 `INCLUDE_vTaskDelay`
- **THEN** 宏展开结果为 `1`

Trace: `include/picow/FreeRTOSConfig.h:INCLUDE_vTaskDelay`

### Requirement: INCLUDE_xTaskGetSchedulerState scheduler state availability
系统 MUST 将 `INCLUDE_xTaskGetSchedulerState` 定义为 `1`，使 `xTaskGetSchedulerState` API 被 FreeRTOS 编译包含。

#### Scenario: xTaskGetSchedulerState 包含
- **GIVEN** Pico FreeRTOS 配置头被内核构建包含
- **WHEN** 编译单元读取 `INCLUDE_xTaskGetSchedulerState`
- **THEN** 宏展开结果为 `1`

Trace: `include/picow/FreeRTOSConfig.h:INCLUDE_xTaskGetSchedulerState`

### Requirement: INCLUDE_xTaskGetCurrentTaskHandle current task handle availability
系统 MUST 将 `INCLUDE_xTaskGetCurrentTaskHandle` 定义为 `1`，使 `xTaskGetCurrentTaskHandle` API 被 FreeRTOS 编译包含。

#### Scenario: xTaskGetCurrentTaskHandle 包含
- **GIVEN** Pico FreeRTOS 配置头被内核构建包含
- **WHEN** 编译单元读取 `INCLUDE_xTaskGetCurrentTaskHandle`
- **THEN** 宏展开结果为 `1`

Trace: `include/picow/FreeRTOSConfig.h:INCLUDE_xTaskGetCurrentTaskHandle`

### Requirement: INCLUDE_uxTaskGetStackHighWaterMark stack high-water API availability
系统 MUST 将 `INCLUDE_uxTaskGetStackHighWaterMark` 定义为 `1`，使 `uxTaskGetStackHighWaterMark` API 被 FreeRTOS 编译包含。

#### Scenario: uxTaskGetStackHighWaterMark 包含
- **GIVEN** Pico FreeRTOS 配置头被内核构建包含
- **WHEN** 编译单元读取 `INCLUDE_uxTaskGetStackHighWaterMark`
- **THEN** 宏展开结果为 `1`

Trace: `include/picow/FreeRTOSConfig.h:INCLUDE_uxTaskGetStackHighWaterMark`

### Requirement: INCLUDE_xTaskGetIdleTaskHandle idle task handle availability
系统 MUST 将 `INCLUDE_xTaskGetIdleTaskHandle` 定义为 `1`，使 `xTaskGetIdleTaskHandle` API 被 FreeRTOS 编译包含。

#### Scenario: xTaskGetIdleTaskHandle 包含
- **GIVEN** Pico FreeRTOS 配置头被内核构建包含
- **WHEN** 编译单元读取 `INCLUDE_xTaskGetIdleTaskHandle`
- **THEN** 宏展开结果为 `1`

Trace: `include/picow/FreeRTOSConfig.h:INCLUDE_xTaskGetIdleTaskHandle`

### Requirement: INCLUDE_eTaskGetState task state availability
系统 MUST 将 `INCLUDE_eTaskGetState` 定义为 `1`，使 `eTaskGetState` API 被 FreeRTOS 编译包含。

#### Scenario: eTaskGetState 包含
- **GIVEN** Pico FreeRTOS 配置头被内核构建包含
- **WHEN** 编译单元读取 `INCLUDE_eTaskGetState`
- **THEN** 宏展开结果为 `1`

Trace: `include/picow/FreeRTOSConfig.h:INCLUDE_eTaskGetState`

### Requirement: INCLUDE_xTimerPendFunctionCall timer pend function availability
系统 MUST 将 `INCLUDE_xTimerPendFunctionCall` 定义为 `1`，使 `xTimerPendFunctionCall` API 被 FreeRTOS 编译包含。

#### Scenario: xTimerPendFunctionCall 包含
- **GIVEN** Pico FreeRTOS 配置头被内核构建包含
- **WHEN** 编译单元读取 `INCLUDE_xTimerPendFunctionCall`
- **THEN** 宏展开结果为 `1`

Trace: `include/picow/FreeRTOSConfig.h:INCLUDE_xTimerPendFunctionCall`

### Requirement: INCLUDE_xTaskAbortDelay abort delay availability
系统 MUST 将 `INCLUDE_xTaskAbortDelay` 定义为 `1`，使 `xTaskAbortDelay` API 被 FreeRTOS 编译包含。

#### Scenario: xTaskAbortDelay 包含
- **GIVEN** Pico FreeRTOS 配置头被内核构建包含
- **WHEN** 编译单元读取 `INCLUDE_xTaskAbortDelay`
- **THEN** 宏展开结果为 `1`

Trace: `include/picow/FreeRTOSConfig.h:INCLUDE_xTaskAbortDelay`

### Requirement: INCLUDE_xTaskGetHandle named task handle availability
系统 MUST 将 `INCLUDE_xTaskGetHandle` 定义为 `1`，使 `xTaskGetHandle` API 被 FreeRTOS 编译包含。

#### Scenario: xTaskGetHandle 包含
- **GIVEN** Pico FreeRTOS 配置头被内核构建包含
- **WHEN** 编译单元读取 `INCLUDE_xTaskGetHandle`
- **THEN** 宏展开结果为 `1`

Trace: `include/picow/FreeRTOSConfig.h:INCLUDE_xTaskGetHandle`

### Requirement: INCLUDE_xTaskResumeFromISR ISR resume availability
系统 MUST 将 `INCLUDE_xTaskResumeFromISR` 定义为 `1`，使 `xTaskResumeFromISR` API 被 FreeRTOS 编译包含。

#### Scenario: xTaskResumeFromISR 包含
- **GIVEN** Pico FreeRTOS 配置头被内核构建包含
- **WHEN** 编译单元读取 `INCLUDE_xTaskResumeFromISR`
- **THEN** 宏展开结果为 `1`

Trace: `include/picow/FreeRTOSConfig.h:INCLUDE_xTaskResumeFromISR`

### Requirement: INCLUDE_xQueueGetMutexHolder mutex holder availability
系统 MUST 将 `INCLUDE_xQueueGetMutexHolder` 定义为 `1`，使 `xQueueGetMutexHolder` API 被 FreeRTOS 编译包含。

#### Scenario: xQueueGetMutexHolder 包含
- **GIVEN** Pico FreeRTOS 配置头被内核构建包含
- **WHEN** 编译单元读取 `INCLUDE_xQueueGetMutexHolder`
- **THEN** 宏展开结果为 `1`

Trace: `include/picow/FreeRTOSConfig.h:INCLUDE_xQueueGetMutexHolder`

## Open Questions

| ID | Question | Related Interface | Reason |
| --- | --- | --- | --- |
| Q-001 | `FREE_RTOS_KERNEL_SMP` 的定义来源和默认值未在当前文件内确认。 | configNUM_CORES, configTICK_CORE, configRUN_MULTIPLE_PRIORITIES, configUSE_CORE_AFFINITY | 当前 header 仅以 `#if FREE_RTOS_KERNEL_SMP` 使用该条件，GitNexus context 未返回定义来源。 |
