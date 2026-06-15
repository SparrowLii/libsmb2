use libsmb2_rs::include::config::PICOW_FREERTOS_CONFIG;

// Trace: `include/picow/FreeRTOSConfig.h:configUSE_PREEMPTION`
// Spec: configUSE_PREEMPTION scheduler mode#抢占式调度启用
// - **GIVEN** Pico FreeRTOS 配置头被内核或应用构建包含
// - **WHEN** 编译单元读取 `configUSE_PREEMPTION`
// - **THEN** 宏展开结果为 `1`
#[test]
fn test_freertosconfig_scenario() {
    assert_eq!(PICOW_FREERTOS_CONFIG.use_preemption, 1);
}

// Trace: `include/picow/FreeRTOSConfig.h:configUSE_TICKLESS_IDLE`
// Spec: configUSE_TICKLESS_IDLE tickless idle disabled#tickless idle 禁用
// - **GIVEN** Pico FreeRTOS 配置头被内核或应用构建包含
// - **WHEN** 编译单元读取 `configUSE_TICKLESS_IDLE`
// - **THEN** 宏展开结果为 `0`
#[test]
fn test_freertosconfig_tickless_idle() {
    assert_eq!(PICOW_FREERTOS_CONFIG.use_tickless_idle, 0);
}

// Trace: `include/picow/FreeRTOSConfig.h:configTICK_RATE_HZ`
// Spec: configTICK_RATE_HZ tick frequency#tick 频率配置
// - **GIVEN** Pico FreeRTOS 配置头被内核或应用构建包含
// - **WHEN** 编译单元读取 `configTICK_RATE_HZ`
// - **THEN** 宏展开为强制转换到 `TickType_t` 的 `1000`
#[test]
fn test_freertosconfig_tick() {
    assert_eq!(PICOW_FREERTOS_CONFIG.tick_rate_hz, 1000);
}

// Trace: `include/picow/FreeRTOSConfig.h:configMAX_PRIORITIES`
// Spec: configMAX_PRIORITIES priority count#最大优先级数量
// - **GIVEN** Pico FreeRTOS 配置头被内核或应用构建包含
// - **WHEN** 编译单元读取 `configMAX_PRIORITIES`
// - **THEN** 宏展开结果为 `32`
#[test]
fn test_freertosconfig_scenario_2() {
    assert_eq!(PICOW_FREERTOS_CONFIG.max_priorities, 32);
}

// Trace: `include/picow/FreeRTOSConfig.h:configMINIMAL_STACK_SIZE`
// Spec: configMINIMAL_STACK_SIZE minimal stack#最小栈深度配置
// - **GIVEN** Pico FreeRTOS 配置头被内核或应用构建包含
// - **WHEN** 编译单元读取 `configMINIMAL_STACK_SIZE`
// - **THEN** 宏展开为 `2048` 且转换到 `configSTACK_DEPTH_TYPE`
#[test]
fn test_freertosconfig_scenario_3() {
    assert_eq!(PICOW_FREERTOS_CONFIG.minimal_stack_size, 2048);
}

// Trace: `include/picow/FreeRTOSConfig.h:configUSE_MUTEXES`
// Spec: configUSE_MUTEXES mutex support#mutex 支持启用
// - **GIVEN** Pico FreeRTOS 配置头被内核或应用构建包含
// - **WHEN** 编译单元读取 `configUSE_MUTEXES`
// - **THEN** 宏展开结果为 `1`
#[test]
fn test_freertosconfig_mutex() {
    assert_eq!(PICOW_FREERTOS_CONFIG.use_mutexes, 1);
}

// Trace: `include/picow/FreeRTOSConfig.h:configUSE_RECURSIVE_MUTEXES`
// Spec: configUSE_RECURSIVE_MUTEXES recursive mutex support#recursive mutex 支持启用
// - **GIVEN** Pico FreeRTOS 配置头被内核或应用构建包含
// - **WHEN** 编译单元读取 `configUSE_RECURSIVE_MUTEXES`
// - **THEN** 宏展开结果为 `1`
#[test]
fn test_freertosconfig_recursive_mutex() {
    assert_eq!(PICOW_FREERTOS_CONFIG.use_recursive_mutexes, 1);
}

// Trace: `include/picow/FreeRTOSConfig.h:configUSE_COUNTING_SEMAPHORES`
// Spec: configUSE_COUNTING_SEMAPHORES counting semaphore support#counting semaphore 支持启用
// - **GIVEN** Pico FreeRTOS 配置头被内核或应用构建包含
// - **WHEN** 编译单元读取 `configUSE_COUNTING_SEMAPHORES`
// - **THEN** 宏展开结果为 `1`
#[test]
fn test_freertosconfig_counting_semaphore() {
    assert_eq!(PICOW_FREERTOS_CONFIG.use_counting_semaphores, 1);
}

// Trace: `include/picow/FreeRTOSConfig.h:configQUEUE_REGISTRY_SIZE`
// Spec: configQUEUE_REGISTRY_SIZE queue registry capacity#queue registry 容量
// - **GIVEN** Pico FreeRTOS 配置头被内核或应用构建包含
// - **WHEN** 编译单元读取 `configQUEUE_REGISTRY_SIZE`
// - **THEN** 宏展开结果为 `8`
#[test]
fn test_freertosconfig_queue_registry() {
    assert_eq!(PICOW_FREERTOS_CONFIG.queue_registry_size, 8);
}

// Trace: `include/picow/FreeRTOSConfig.h:configENABLE_BACKWARD_COMPATIBILITY`
// Spec: configENABLE_BACKWARD_COMPATIBILITY compatibility mode#兼容性启用
// - **GIVEN** Pico FreeRTOS 配置头被 lwIP FreeRTOS sys_arch 或应用构建包含
// - **WHEN** 编译单元读取 `configENABLE_BACKWARD_COMPATIBILITY`
// - **THEN** 宏展开结果为 `1`
#[test]
fn test_freertosconfig_scenario_4() {
    assert_eq!(PICOW_FREERTOS_CONFIG.enable_backward_compatibility, 1);
}

// Trace: `include/picow/FreeRTOSConfig.h:configNUM_THREAD_LOCAL_STORAGE_POINTERS`
// Spec: configNUM_THREAD_LOCAL_STORAGE_POINTERS TLS pointer count#TLS 指针数量
// - **GIVEN** Pico FreeRTOS 配置头被内核或应用构建包含
// - **WHEN** 编译单元读取 `configNUM_THREAD_LOCAL_STORAGE_POINTERS`
// - **THEN** 宏展开结果为 `5`
#[test]
fn test_freertosconfig_tls() {
    assert_eq!(PICOW_FREERTOS_CONFIG.num_thread_local_storage_pointers, 5);
}

// Trace: `include/picow/FreeRTOSConfig.h:configSTACK_DEPTH_TYPE`
// Spec: configSTACK_DEPTH_TYPE stack depth type#栈深度类型
// - **GIVEN** Pico FreeRTOS 配置头被内核或应用构建包含
// - **WHEN** 编译单元读取 `configSTACK_DEPTH_TYPE`
// - **THEN** 宏展开结果为 `uint32_t`
#[test]
fn test_freertosconfig_scenario_5() {
    assert_eq!(PICOW_FREERTOS_CONFIG.stack_depth_type, "uint32_t");
}

// Trace: `include/picow/FreeRTOSConfig.h:configMESSAGE_BUFFER_LENGTH_TYPE`
// Spec: configMESSAGE_BUFFER_LENGTH_TYPE message buffer length type#message buffer 长度类型
// - **GIVEN** Pico FreeRTOS 配置头被内核或应用构建包含
// - **WHEN** 编译单元读取 `configMESSAGE_BUFFER_LENGTH_TYPE`
// - **THEN** 宏展开结果为 `size_t`
#[test]
fn test_freertosconfig_message_buffer() {
    assert_eq!(PICOW_FREERTOS_CONFIG.message_buffer_length_type, "size_t");
}

// Trace: `include/picow/FreeRTOSConfig.h:configSUPPORT_STATIC_ALLOCATION`
// Spec: configSUPPORT_STATIC_ALLOCATION static allocation mode#静态分配禁用
// - **GIVEN** Pico FreeRTOS 配置头被内核或应用构建包含
// - **WHEN** 编译单元读取 `configSUPPORT_STATIC_ALLOCATION`
// - **THEN** 宏展开结果为 `0`
#[test]
fn test_freertosconfig_scenario_6() {
    assert_eq!(PICOW_FREERTOS_CONFIG.support_static_allocation, 0);
}

// Trace: `include/picow/FreeRTOSConfig.h:configSUPPORT_DYNAMIC_ALLOCATION`
// Spec: configSUPPORT_DYNAMIC_ALLOCATION dynamic allocation mode#动态分配启用
// - **GIVEN** Pico FreeRTOS 配置头被内核或应用构建包含
// - **WHEN** 编译单元读取 `configSUPPORT_DYNAMIC_ALLOCATION`
// - **THEN** 宏展开结果为 `1`
#[test]
fn test_freertosconfig_scenario_7() {
    assert_eq!(PICOW_FREERTOS_CONFIG.support_dynamic_allocation, 1);
}

// Trace: `include/picow/FreeRTOSConfig.h:configTOTAL_HEAP_SIZE`
// Spec: configTOTAL_HEAP_SIZE heap capacity#heap 容量配置
// - **GIVEN** Pico FreeRTOS 配置头被内核或应用构建包含
// - **WHEN** 编译单元读取 `configTOTAL_HEAP_SIZE`
// - **THEN** 宏展开为 `128*1024`
#[test]
fn test_freertosconfig_heap() {
    assert_eq!(PICOW_FREERTOS_CONFIG.total_heap_size, 128 * 1024);
}

// Trace: `include/picow/FreeRTOSConfig.h:configCHECK_FOR_STACK_OVERFLOW`
// Spec: configCHECK_FOR_STACK_OVERFLOW stack overflow checking#栈溢出检查禁用
// - **GIVEN** Pico FreeRTOS 配置头被内核或应用构建包含
// - **WHEN** 编译单元读取 `configCHECK_FOR_STACK_OVERFLOW`
// - **THEN** 宏展开结果为 `0`
#[test]
fn test_freertosconfig_scenario_8() {
    assert_eq!(PICOW_FREERTOS_CONFIG.check_for_stack_overflow, 0);
}

// Trace: `include/picow/FreeRTOSConfig.h:configUSE_TRACE_FACILITY`
// Spec: configUSE_TRACE_FACILITY trace facility support#trace facility 启用
// - **GIVEN** Pico FreeRTOS 配置头被内核或应用构建包含
// - **WHEN** 编译单元读取 `configUSE_TRACE_FACILITY`
// - **THEN** 宏展开结果为 `1`
#[test]
fn test_freertosconfig_trace_facility() {
    assert_eq!(PICOW_FREERTOS_CONFIG.use_trace_facility, 1);
}

// Trace: `include/picow/FreeRTOSConfig.h:configUSE_CO_ROUTINES`
// Spec: configUSE_CO_ROUTINES co-routine support#co-routine 禁用
// - **GIVEN** Pico FreeRTOS 配置头被内核或应用构建包含
// - **WHEN** 编译单元读取 `configUSE_CO_ROUTINES`
// - **THEN** 宏展开结果为 `0`
#[test]
fn test_freertosconfig_co_routine() {
    assert_eq!(PICOW_FREERTOS_CONFIG.use_co_routines, 0);
}

// Trace: `include/picow/FreeRTOSConfig.h:configUSE_TIMERS`
// Spec: configUSE_TIMERS software timer support#software timer 启用
// - **GIVEN** Pico FreeRTOS 配置头被内核或应用构建包含
// - **WHEN** 编译单元读取 `configUSE_TIMERS`
// - **THEN** 宏展开结果为 `1`
#[test]
fn test_freertosconfig_software_timer() {
    assert_eq!(PICOW_FREERTOS_CONFIG.use_timers, 1);
}

// Trace: `include/picow/FreeRTOSConfig.h:configTIMER_TASK_PRIORITY`
// Spec: configTIMER_TASK_PRIORITY timer task priority#timer task 优先级
// - **GIVEN** Pico FreeRTOS 配置头被内核或应用构建包含
// - **WHEN** 编译单元读取 `configTIMER_TASK_PRIORITY`
// - **THEN** 宏展开为 `configMAX_PRIORITIES - 1`
#[test]
fn test_freertosconfig_timer_task() {
    assert_eq!(PICOW_FREERTOS_CONFIG.timer_task_priority_delta, -1);
}

// Trace: `include/picow/FreeRTOSConfig.h:configTIMER_QUEUE_LENGTH`
// Spec: configTIMER_QUEUE_LENGTH timer queue capacity#timer queue 容量
// - **GIVEN** Pico FreeRTOS 配置头被内核或应用构建包含
// - **WHEN** 编译单元读取 `configTIMER_QUEUE_LENGTH`
// - **THEN** 宏展开结果为 `10`
#[test]
fn test_freertosconfig_timer_queue() {
    assert_eq!(PICOW_FREERTOS_CONFIG.timer_queue_length, 10);
}

// Trace: `include/picow/FreeRTOSConfig.h:configTIMER_TASK_STACK_DEPTH`
// Spec: configTIMER_TASK_STACK_DEPTH timer task stack#timer task 栈深度
// - **GIVEN** Pico FreeRTOS 配置头被内核或应用构建包含
// - **WHEN** 编译单元读取 `configTIMER_TASK_STACK_DEPTH`
// - **THEN** 宏展开结果为 `1024`
#[test]
fn test_freertosconfig_timer_task_2() {
    assert_eq!(PICOW_FREERTOS_CONFIG.timer_task_stack_depth, 1024);
}

// Trace: `include/picow/FreeRTOSConfig.h:configNUM_CORES`
// Spec: configNUM_CORES SMP core count#SMP 核心数量配置
// - **GIVEN** `FREE_RTOS_KERNEL_SMP` 为真且 Pico FreeRTOS 配置头被内核构建包含
// - **WHEN** 编译单元读取 `configNUM_CORES`
// - **THEN** 宏展开结果为 `2`
#[test]
fn test_freertosconfig_smp() {
    assert_eq!(PICOW_FREERTOS_CONFIG.num_cores, Some(2));
}

// Trace: `include/picow/FreeRTOSConfig.h:configTICK_CORE`
// Spec: configTICK_CORE SMP tick core#SMP tick core 配置
// - **GIVEN** `FREE_RTOS_KERNEL_SMP` 为真且 Pico FreeRTOS 配置头被内核构建包含
// - **WHEN** 编译单元读取 `configTICK_CORE`
// - **THEN** 宏展开结果为 `0`
#[test]
fn test_freertosconfig_smp_tick_core() {
    assert_eq!(PICOW_FREERTOS_CONFIG.tick_core, Some(0));
}

// Trace: `include/picow/FreeRTOSConfig.h:configRUN_MULTIPLE_PRIORITIES`
// Spec: configRUN_MULTIPLE_PRIORITIES SMP multi-priority scheduling#SMP 多优先级运行启用
// - **GIVEN** `FREE_RTOS_KERNEL_SMP` 为真且 Pico FreeRTOS 配置头被内核构建包含
// - **WHEN** 编译单元读取 `configRUN_MULTIPLE_PRIORITIES`
// - **THEN** 宏展开结果为 `1`
#[test]
fn test_freertosconfig_smp_2() {
    assert_eq!(PICOW_FREERTOS_CONFIG.run_multiple_priorities, Some(1));
}

// Trace: `include/picow/FreeRTOSConfig.h:configUSE_CORE_AFFINITY`
// Spec: configUSE_CORE_AFFINITY SMP core affinity#SMP core affinity 启用
// - **GIVEN** `FREE_RTOS_KERNEL_SMP` 为真且 Pico FreeRTOS 配置头被内核构建包含
// - **WHEN** 编译单元读取 `configUSE_CORE_AFFINITY`
// - **THEN** 宏展开结果为 `1`
#[test]
fn test_freertosconfig_smp_core_affinity() {
    assert_eq!(PICOW_FREERTOS_CONFIG.use_core_affinity, Some(1));
}

// Trace: `include/picow/FreeRTOSConfig.h:configSUPPORT_PICO_SYNC_INTEROP`
// Spec: configSUPPORT_PICO_SYNC_INTEROP Pico sync interop#Pico sync interop 启用
// - **GIVEN** Pico FreeRTOS 配置头被 RP2040 FreeRTOS 或应用构建包含
// - **WHEN** 编译单元读取 `configSUPPORT_PICO_SYNC_INTEROP`
// - **THEN** 宏展开结果为 `1`
#[test]
fn test_freertosconfig_pico_sync_interop() {
    assert_eq!(PICOW_FREERTOS_CONFIG.support_pico_sync_interop, 1);
}

// Trace: `include/picow/FreeRTOSConfig.h:configSUPPORT_PICO_TIME_INTEROP`
// Spec: configSUPPORT_PICO_TIME_INTEROP Pico time interop#Pico time interop 启用
// - **GIVEN** Pico FreeRTOS 配置头被 RP2040 FreeRTOS 或应用构建包含
// - **WHEN** 编译单元读取 `configSUPPORT_PICO_TIME_INTEROP`
// - **THEN** 宏展开结果为 `1`
#[test]
fn test_freertosconfig_pico_time_interop() {
    assert_eq!(PICOW_FREERTOS_CONFIG.support_pico_time_interop, 1);
}

// Trace: `include/picow/FreeRTOSConfig.h:configASSERT`
// Spec: configASSERT assertion mapping#断言宏转发
// - **GIVEN** Pico FreeRTOS 配置头被内核或应用构建包含且 `<assert.h>` 可用
// - **WHEN** 编译单元调用 `configASSERT(x)`
// - **THEN** 该调用展开为 `assert(x)`
#[test]
fn test_freertosconfig_scenario_9() {
    assert_eq!(PICOW_FREERTOS_CONFIG.assert_maps_to_assert, true);
}

// Trace: `include/picow/FreeRTOSConfig.h:INCLUDE_vTaskPrioritySet`
// Spec: INCLUDE_vTaskPrioritySet task priority setter availability#vTaskPrioritySet 包含
// - **GIVEN** Pico FreeRTOS 配置头被内核构建包含
// - **WHEN** 编译单元读取 `INCLUDE_vTaskPrioritySet`
// - **THEN** 宏展开结果为 `1`
#[test]
fn test_freertosconfig_vtaskpriorityset() {
    assert_eq!(PICOW_FREERTOS_CONFIG.include_v_task_priority_set, 1);
}

// Trace: `include/picow/FreeRTOSConfig.h:INCLUDE_uxTaskPriorityGet`
// Spec: INCLUDE_uxTaskPriorityGet task priority getter availability#uxTaskPriorityGet 包含
// - **GIVEN** Pico FreeRTOS 配置头被内核构建包含
// - **WHEN** 编译单元读取 `INCLUDE_uxTaskPriorityGet`
// - **THEN** 宏展开结果为 `1`
#[test]
fn test_freertosconfig_uxtaskpriorityget() {
    assert_eq!(PICOW_FREERTOS_CONFIG.include_ux_task_priority_get, 1);
}

// Trace: `include/picow/FreeRTOSConfig.h:INCLUDE_vTaskDelete`
// Spec: INCLUDE_vTaskDelete task delete availability#vTaskDelete 包含
// - **GIVEN** Pico FreeRTOS 配置头被内核构建包含
// - **WHEN** 编译单元读取 `INCLUDE_vTaskDelete`
// - **THEN** 宏展开结果为 `1`
#[test]
fn test_freertosconfig_vtaskdelete() {
    assert_eq!(PICOW_FREERTOS_CONFIG.include_v_task_delete, 1);
}

// Trace: `include/picow/FreeRTOSConfig.h:INCLUDE_vTaskSuspend`
// Spec: INCLUDE_vTaskSuspend task suspend availability#vTaskSuspend 包含
// - **GIVEN** Pico FreeRTOS 配置头被内核构建包含
// - **WHEN** 编译单元读取 `INCLUDE_vTaskSuspend`
// - **THEN** 宏展开结果为 `1`
#[test]
fn test_freertosconfig_vtasksuspend() {
    assert_eq!(PICOW_FREERTOS_CONFIG.include_v_task_suspend, 1);
}

// Trace: `include/picow/FreeRTOSConfig.h:INCLUDE_vTaskDelayUntil`
// Spec: INCLUDE_vTaskDelayUntil periodic delay availability#vTaskDelayUntil 包含
// - **GIVEN** Pico FreeRTOS 配置头被内核构建包含
// - **WHEN** 编译单元读取 `INCLUDE_vTaskDelayUntil`
// - **THEN** 宏展开结果为 `1`
#[test]
fn test_freertosconfig_vtaskdelayuntil() {
    assert_eq!(PICOW_FREERTOS_CONFIG.include_v_task_delay_until, 1);
}

// Trace: `include/picow/FreeRTOSConfig.h:INCLUDE_vTaskDelay`
// Spec: INCLUDE_vTaskDelay task delay availability#vTaskDelay 包含
// - **GIVEN** Pico FreeRTOS 配置头被内核构建包含
// - **WHEN** 编译单元读取 `INCLUDE_vTaskDelay`
// - **THEN** 宏展开结果为 `1`
#[test]
fn test_freertosconfig_vtaskdelay() {
    assert_eq!(PICOW_FREERTOS_CONFIG.include_v_task_delay, 1);
}

// Trace: `include/picow/FreeRTOSConfig.h:INCLUDE_xTaskGetSchedulerState`
// Spec: INCLUDE_xTaskGetSchedulerState scheduler state availability#xTaskGetSchedulerState 包含
// - **GIVEN** Pico FreeRTOS 配置头被内核构建包含
// - **WHEN** 编译单元读取 `INCLUDE_xTaskGetSchedulerState`
// - **THEN** 宏展开结果为 `1`
#[test]
fn test_freertosconfig_xtaskgetschedulerstate() {
    assert_eq!(PICOW_FREERTOS_CONFIG.include_x_task_get_scheduler_state, 1);
}

// Trace: `include/picow/FreeRTOSConfig.h:INCLUDE_xTaskGetCurrentTaskHandle`
// Spec: INCLUDE_xTaskGetCurrentTaskHandle current task handle availability#xTaskGetCurrentTaskHandle 包含
// - **GIVEN** Pico FreeRTOS 配置头被内核构建包含
// - **WHEN** 编译单元读取 `INCLUDE_xTaskGetCurrentTaskHandle`
// - **THEN** 宏展开结果为 `1`
#[test]
fn test_freertosconfig_xtaskgetcurrenttaskhandle() {
    assert_eq!(
        PICOW_FREERTOS_CONFIG.include_x_task_get_current_task_handle,
        1
    );
}

// Trace: `include/picow/FreeRTOSConfig.h:INCLUDE_uxTaskGetStackHighWaterMark`
// Spec: INCLUDE_uxTaskGetStackHighWaterMark stack high-water API availability#uxTaskGetStackHighWaterMark 包含
// - **GIVEN** Pico FreeRTOS 配置头被内核构建包含
// - **WHEN** 编译单元读取 `INCLUDE_uxTaskGetStackHighWaterMark`
// - **THEN** 宏展开结果为 `1`
#[test]
fn test_freertosconfig_uxtaskgetstackhighwatermark() {
    assert_eq!(
        PICOW_FREERTOS_CONFIG.include_ux_task_get_stack_high_water_mark,
        1
    );
}

// Trace: `include/picow/FreeRTOSConfig.h:INCLUDE_xTaskGetIdleTaskHandle`
// Spec: INCLUDE_xTaskGetIdleTaskHandle idle task handle availability#xTaskGetIdleTaskHandle 包含
// - **GIVEN** Pico FreeRTOS 配置头被内核构建包含
// - **WHEN** 编译单元读取 `INCLUDE_xTaskGetIdleTaskHandle`
// - **THEN** 宏展开结果为 `1`
#[test]
fn test_freertosconfig_xtaskgetidletaskhandle() {
    assert_eq!(PICOW_FREERTOS_CONFIG.include_x_task_get_idle_task_handle, 1);
}

// Trace: `include/picow/FreeRTOSConfig.h:INCLUDE_eTaskGetState`
// Spec: INCLUDE_eTaskGetState task state availability#eTaskGetState 包含
// - **GIVEN** Pico FreeRTOS 配置头被内核构建包含
// - **WHEN** 编译单元读取 `INCLUDE_eTaskGetState`
// - **THEN** 宏展开结果为 `1`
#[test]
fn test_freertosconfig_etaskgetstate() {
    assert_eq!(PICOW_FREERTOS_CONFIG.include_e_task_get_state, 1);
}

// Trace: `include/picow/FreeRTOSConfig.h:INCLUDE_xTimerPendFunctionCall`
// Spec: INCLUDE_xTimerPendFunctionCall timer pend function availability#xTimerPendFunctionCall 包含
// - **GIVEN** Pico FreeRTOS 配置头被内核构建包含
// - **WHEN** 编译单元读取 `INCLUDE_xTimerPendFunctionCall`
// - **THEN** 宏展开结果为 `1`
#[test]
fn test_freertosconfig_xtimerpendfunctioncall() {
    assert_eq!(PICOW_FREERTOS_CONFIG.include_x_timer_pend_function_call, 1);
}

// Trace: `include/picow/FreeRTOSConfig.h:INCLUDE_xTaskAbortDelay`
// Spec: INCLUDE_xTaskAbortDelay abort delay availability#xTaskAbortDelay 包含
// - **GIVEN** Pico FreeRTOS 配置头被内核构建包含
// - **WHEN** 编译单元读取 `INCLUDE_xTaskAbortDelay`
// - **THEN** 宏展开结果为 `1`
#[test]
fn test_freertosconfig_xtaskabortdelay() {
    assert_eq!(PICOW_FREERTOS_CONFIG.include_x_task_abort_delay, 1);
}

// Trace: `include/picow/FreeRTOSConfig.h:INCLUDE_xTaskGetHandle`
// Spec: INCLUDE_xTaskGetHandle named task handle availability#xTaskGetHandle 包含
// - **GIVEN** Pico FreeRTOS 配置头被内核构建包含
// - **WHEN** 编译单元读取 `INCLUDE_xTaskGetHandle`
// - **THEN** 宏展开结果为 `1`
#[test]
fn test_freertosconfig_xtaskgethandle() {
    assert_eq!(PICOW_FREERTOS_CONFIG.include_x_task_get_handle, 1);
}

// Trace: `include/picow/FreeRTOSConfig.h:INCLUDE_xTaskResumeFromISR`
// Spec: INCLUDE_xTaskResumeFromISR ISR resume availability#xTaskResumeFromISR 包含
// - **GIVEN** Pico FreeRTOS 配置头被内核构建包含
// - **WHEN** 编译单元读取 `INCLUDE_xTaskResumeFromISR`
// - **THEN** 宏展开结果为 `1`
#[test]
fn test_freertosconfig_xtaskresumefromisr() {
    assert_eq!(PICOW_FREERTOS_CONFIG.include_x_task_resume_from_isr, 1);
}

// Trace: `include/picow/FreeRTOSConfig.h:INCLUDE_xQueueGetMutexHolder`
// Spec: INCLUDE_xQueueGetMutexHolder mutex holder availability#xQueueGetMutexHolder 包含
// - **GIVEN** Pico FreeRTOS 配置头被内核构建包含
// - **WHEN** 编译单元读取 `INCLUDE_xQueueGetMutexHolder`
// - **THEN** 宏展开结果为 `1`
#[test]
fn test_freertosconfig_xqueuegetmutexholder() {
    assert_eq!(PICOW_FREERTOS_CONFIG.include_x_queue_get_mutex_holder, 1);
}
