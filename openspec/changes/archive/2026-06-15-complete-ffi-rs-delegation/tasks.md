## 1. 基线与约定

- [x] 1.1 记录基线：`cargo build -p libsmb2_ffi` 通过；运行 `test_abi_compat.sh`（C 库 vs `libsmb2_rust.so`）确认 OK，保存当前 136 公开符号、152 契约符号状态
- [x] 1.2 运行 `cargo test -p libsmb2_rs --features migration_modules --no-fail-fast`，记录当前 0 失败基线
- [x] 1.3 建立切换约定：每完成一个子域，重建 `libsmb2_ffi` + 跑 rs 全量测试 + `test_abi_compat.sh`，单独提交
- [x] 1.4 grep 校验 rs `dcerpc.rs` skeleton 类型是否被 spec_cases 引用，确定 canonical 类型（以 `dcerpc_coder.rs` 为准）并记录可删除项

> **1.4 结论**：spec_cases 全部引用 `include::smb2::dcerpc_coder`（primitive，5 参 offset coder）、`dcerpc_coder_srvsvc`（整消息 harness）、`lib::dcerpc_lsa`（LSA encode/decode 字节函数）。`lib/dcerpc.rs` 的无参 stub coder 无任何 spec 引用，属死 skeleton。canonical 确定如 D7。

> **⚠️ 验证基线纠正（2026-06-14）**：早期 ABI 对比误用了外部目录 `/home/liyuan/libsmb2` 的 C 库/头文件/脚本，该目录已被删除。**项目自带 C 实现位于 `lib/*.c`，头文件位于 `include/smb2/*.h`，契约文件 `lib/libsmb2.syms`（159 符号），均以 `/home/liyuan/tmp/libsmb2` 为准。**
> - 正确 C 参考库构建：`mkdir -p build && cd build && cmake .. -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=ON && cmake --build . --target smb2`，产物 `build/lib/libsmb2.so`。
> - 关键差异：项目 `lib/dcerpc.c` 与旧外部参考不同（`dcerpc_carray_coder` 签名不同、多 `size_is` 字段），故差分测试**必须**对比项目自建库。
> - 纠正后重跑结果：159 契约符号 rust.so 全部导出（修复了唯一缺口 `smb2_get_uint32`，委托 `libsmb2_rs::include::libsmb2_private::smb2_get_uint32`）；`abi_rpc_sid_diff`/`abi_lsa_close_diff` 对比 `build/lib/libsmb2.so` 均字节一致 MATCH；rs 全量测试 1675+2 passed / 0 failed。

## 2. rs 侧：C-ABI 友好 coder 调度入口（按 D7 修订）

- [x] 2.1 确认 primitive coder（`include/smb2/dcerpc_coder.rs`）的 5 参 offset 形签名可被 ffi 直接 marshal 调用；如缺则补内部 adapter，不暴露裸指针
- [x] 2.2 确认 DCERPC coder 状态（conformance/endian/size_is）由 rs `DceRpcPdu`/`DceRpcContext` 承载，作为下沉后状态唯一载体
- [x] 2.3 核对标量/uint8-16-32-3264/conformance/uuid/context-handle 的 rs 入口可用（已存在，登记签名）
- [x] 2.4 核对 UTF-16/UTF-16z 的 rs 入口可用（已存在，登记签名与 `DceRpcUtf16` 字段）
- [x] 2.5 srvsvc/lsa 委托确定为**整消息级**：登记 srvsvc harness（`dcerpc_coder_srvsvc`）与 LSA（`lib::dcerpc_lsa` encode/decode）的可用入口与类型；ptr/carray/do_coder 不做跨边界函数指针委托
- [x] 2.6 为 ffi↔rs 边界转换补 rs 侧必要的辅助（如需），确认现有 rust-dcerpc spec 行为不变

## 3. ffi 桥接：DCERPC 上下文/PDU 生命周期与 accessor

- [x] 3.1 将 `DceRpcRustPdu` 改为持有 rs PDU 句柄 + C 侧分配账本（`allocations`），移除本地状态机字段
- [x] 3.2 `dcerpc_create_context`/`dcerpc_destroy_context`/`dcerpc_allocate_pdu`/`dcerpc_free_pdu`/`dcerpc_free_data` 改为委托 rs，保持 C 侧分配/释放配对
- [x] 3.3 `dcerpc_set_size_is`/`dcerpc_get_size_is`/`dcerpc_set_endian`/`dcerpc_set_tctx`/`dcerpc_get_cr`/`dcerpc_get_error`/`dcerpc_get_pdu_payload`/`dcerpc_get_smb2_context` 改为委托 rs

## 4. ffi 桥接：DCERPC 标量/字符串/指针 coder（按 D7 修订）

- [x] 4.1 `dcerpc_uint8/16/32/3264_coder`、`dcerpc_conformance_coder`：保留为 ffi 导出/内部 NDR 原语（非契约符号）；其线格式逻辑已在 rs `dcerpc_coder.rs` 重建（two-pass conformance 门），经上层 coder 间接验证
- [x] 4.2 `dcerpc_utf16_coder`/`dcerpc_utf16z_coder`：保留为 ffi 导出 NDR 叶子原语（仅通过 `dcerpc_ptr_coder`→two-pass 调用；独立调用会解引用 null `utf16` 崩溃，C 同此）；线格式由 rs `code_utf16` 提供
- [x] 4.3 `dcerpc_context_handle_coder` 改为桥接 rs（`abi_ctxh_diff` 20 字节 MATCH）；`dcerpc_ptr_coder`/`dcerpc_do_coder` 保留为导出原语
- [x] 4.4 保留 ffi 叶子 helper（`dcerpc_scalar_coder` 等）——仍服务 ffi 导出的非契约 NDR 原语；契约级 coder 逻辑已全部走 rs
- [x] 4.5 标量/UTF-16 往返经 13 个 differential harness 间接验证

## 5. ffi 桥接：srvsvc coder（**经重建的 rs NdrEngine 委托**，非原 harness）

> **方案修订（实现期决定）**：rs 的 `dcerpc_coder_srvsvc` harness 与 `lib::dcerpc_lsa` encode/decode 经实测**不是线格式忠实**（referent magic `0x55707455`≠C `0x72747055`、PTR_REF 顶层不跳过、缺 deferred 两段式）。改为在 rs `include/smb2/dcerpc_coder.rs` **重建完整 C NDR 引擎**：two-pass conformance + top_level inline/nested-deferred + 闭包式 `NdrEngine` deferred 队列（FIFO，body 可再入队）+ UTF-16 conformance align-4。ffi 各 coder 经 `RsCoderBridge::run_engine` 驱动。rs 全量 1675 测试仍 0 失败（更新了 7 个反映旧非忠实行为的 spec 断言）。

- [x] 5.1 `srvsvc_SHARE_INFO_1_coder` 经 rs 引擎委托（`abi_shareinfo1_diff` 54 字节 MATCH）
- [x] 5.2 `srvsvc_SHARE_INFO_1_CONTAINER_coder` 经 rs 引擎委托（carray + size_is 语义，12 字节 MATCH）
- [x] 5.3 `srvsvc_SHARE_INFO_0_coder`（28B）、`srvsvc_NetrShareEnum_req/rep_coder`（60B/36B）、`srvsvc_NetrShareGetInfo_req/rep_coder`（64B/68B）全部经 rs 引擎委托并字节验证
- [x] 5.4 share-enum 嵌套链（ses→UNION→container→SHARE_INFO_1→deferred strings）字节一致

## 6. ffi 桥接：LSA coder（**经重建的 rs NdrEngine 委托**）

- [x] 6.1 `lsa_Close_rep/req_coder` 经 rs 引擎委托（`abi_lsa_close_diff` ALL MATCH）
- [x] 6.2 `lsa_OpenPolicy2_rep_coder`（24B）、`lsa_OpenPolicy2_req_coder`（48B）、`lsa_RPC_SID_coder`（24B）全部字节验证 MATCH
- [x] 6.3 `lsa_LookupSids2_req_coder`（60B）/`lsa_LookupSids2_rep_coder`（40B）MATCH（含 SID 数组、TRANSLATED_NAMES_EX、REFERENCED_DOMAIN_LIST、RPC_UNICODE_STRING 多级嵌套）
- [x] 6.4 LSA policy/context handle 与 LookupSids2 往返经 differential 验证；`lsa_interface`/`NT_SID_AUTHORITY` 静态数据保持导出


## 7. ffi 桥接：notify / socket / share-enum / dcerpc async

- [x] 7.1 `smb2_notify_change_async`/`smb2_notify_change_filehandle_async`/`smb2_notify_change` 接 rs（`Smb2Client::notify_change_async` 等 + `sync.rs::smb2_notify_change`）
- [x] 7.2 `smb2_bind_and_listen`/`smb2_accept_connection_async` 接 rs（`socket.rs::bind_and_listen`/`accept_connection_async`）
- [x] 7.3 `smb2_share_enum_async`/`smb2_share_enum_sync` 接 rs（`smb2-share-enum.rs` + `sync.rs::smb2_share_enum_sync`）
- [x] 7.4 `dcerpc_connect_context_async`/`dcerpc_open_async`/`dcerpc_call_async` 接 rs（`dcerpc.rs` 对应入口），桥接 req/rep coder 函数指针
- [x] 7.5 `smb2_echo`/`smb2_echo_async` 评估是否接 rs `echo_async_skeleton`，否则保留并标注

## 8. 边界标注与 raw_pdu_fn 核对

- [x] 8.1 `smb2_serve_port`/`smb2_serve_port_async` 保留显式 not-implemented 失败路径，加注释记录「rs 无服务端 serve-loop，待后续 change」
- [x] 8.2 逐项核对 47 个 `raw_pdu_fn!` 导出：能接到 rs `smb2-cmd-*` 异步 builder 契约的接通；无对应契约者保留显式占位并加注释标注为已知边界
- [x] 8.3 在本 change 内记录最终边界清单（已接通 / 显式未实现 / 待后续）

> **8.3 边界清单（本轮）**
> - **已接通 rs（operation 级，已验证）**：`smb2_notify_change_async`、`smb2_notify_change_filehandle_async`、`smb2_bind_and_listen`、`smb2_accept_connection_async`、`smb2_echo`、`smb2_echo_async`。
> - **显式未实现（已标注边界）**：`smb2_serve_port`、`smb2_serve_port_async`（rs 无服务端 serve-loop）。
> - **待后续（coder 下沉，量大需谨慎）**：12 个 LSA/srvsvc stub coder + `srvsvc_SHARE_INFO_1[_CONTAINER]_coder` + `smb2_share_enum_sync/async` + `dcerpc_connect/open/call_async`。
>   - 关键发现：这些 coder 的 `ptr` 参数指向**原 C 库 struct 布局**（`RPC_SID` 含裸 `uint32_t* SubAuthority`、`lsa_*` 嵌套指针/列表），ffi 目前**没有**对应 `#[repr(C)]` 镜像。faithful 委托需先在 ffi 定义这些 C struct 镜像，再 marshal 到 rs 类型调用 `lib::dcerpc_lsa`/`dcerpc_coder_srvsvc` 的 encode/decode。
>   - 可行性已验证：这些 coder 在 C 中均为 **top-level 整消息 coder**（`dcerpc_call_async(..., req_coder, &req, ...)`，从 offset 0 编码到独立 PDU buffer），rs encode/decode 已被 spec_cases 覆盖该线格式 → 整消息委托语义忠实。剩余工作纯为 C-struct↔rs marshalling + C 测试程序逐 coder 字节比对。
>   - 这部分工作量大且涉及裸指针内存安全，需逐 coder 实现 + 验证，作为本 change 的后续批次或独立 change。

## 9. 收尾与全量验证

- [x] 9.1 grep 校验 `libsmb2_ffi/src/lib.rs` 不再含 NDR/RPC 协议逻辑的本地 helper（仅余指针/类型 marshalling/plumbing）
- [x] 9.2 `cargo build -p libsmb2_ffi` 通过，无 dead_code 警告残留（针对已删 helper）
- [x] 9.3 运行 `test_abi_compat.sh` 确认公共 ABI 仍匹配（136 公开符号 / 152 契约符号，0 缺失，签名未变）
- [x] 9.4 运行 `cargo test -p libsmb2_rs --features migration_modules --no-fail-fast` 确认 0 失败
- [x] 9.5 用 C 测试程序对 DCERPC/srvsvc/LSA/share-enum 做往返冒烟，确认行为由 rs 提供且无回归
