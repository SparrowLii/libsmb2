## Why

`libsmb2_ffi`（C-ABI 门面，产物 `libsmb2_rust.so`）早于 Rust 迁移存在。它的 SMB2 客户端核心（约 104 个导出）已通过 `inner: Smb2Client` 真正委托给 `libsmb2_rs`，但 DCERPC/LSA/srvsvc 这一整块没有：它在 ffi crate 内自带了一套并行的 NDR coder 实现，且有 12 个 LSA/srvsvc coder 是空桩（返回 0）、约 10 个函数返回 `not_implemented_code()`、47 个 `raw_pdu_fn!` 导出只产出空 PDU。结果是 ABI 符号齐全（`test_abi_compat.sh` 通过），但行为上 RPC coder 是 no-op、异步 DCERPC 调用未实现，与 `libsmb2_rs` 中已存在的真实实现脱节，形成两份并行代码与行为缺口。

## What Changes

- 将 DCERPC/LSA/srvsvc 的 NDR coder **调度逻辑下沉到 `libsmb2_rs`**：在 rs 侧提供 C-ABI 友好的 coder 入口，`libsmb2_ffi` 退化为只做原始指针 ↔ rs 类型的薄桥接（marshalling）。
- 用 rs 实现替换 12 个 `dcerpc_stub_coder!` 空桩（LSA Close/LookupSids2/OpenPolicy2/RPC_SID、srvsvc SHARE_INFO_0/NetrShareEnum/NetrShareGetInfo coder）。
- 将返回 `not_implemented_code()`/null 的导出接到已有的 rs 实现：`smb2_notify_change[_async/_filehandle_async]`、`smb2_bind_and_listen`、`smb2_accept_connection_async`、`smb2_share_enum_async`、`smb2_share_enum_sync`、`dcerpc_connect_context_async`、`dcerpc_open_async`、`dcerpc_call_async`。
- 删除下沉后 `libsmb2_ffi` 中变为死代码的本地 DCERPC NDR 辅助函数（约 15 个 `dcerpc_*` 私有 helper）。
- 为目前缺乏 rs 等价实现的导出（`smb2_serve_port`/`smb2_serve_port_async` 服务端 serve-loop）明确标注语义：要么在 rs 补齐，要么保留显式 not-implemented 失败路径并记录在案。
- 核对 47 个 `raw_pdu_fn!` 导出：能接到 rs `smb2-cmd-*` 编解码的接通，无对应异步 PDU builder 契约的保留显式占位并标注。
- 保持公共 ABI 不变：`test_abi_compat.sh` 仍须通过（符号集与签名不回退）。

## Capabilities

### New Capabilities
- `ffi-rs-delegation`: 规定 `libsmb2_ffi` 的每个导出函数都必须将其行为委托给 `libsmb2_rs`（直接调用或经薄桥接 marshalling），不得在 ffi 层重复实现协议逻辑；明确允许保留的 ffi 本地代码范围（纯指针/结构体 plumbing、类型转换）与禁止范围（NDR/RPC 协议逻辑）。

### Modified Capabilities
- `rust-dcerpc`: 新增要求——DCERPC/LSA/srvsvc 的 NDR coder 调度入口由 `libsmb2_rs` 提供 C-ABI 友好接口，使 ffi 层可委托而非自带实现。

## Impact

- **代码**：`libsmb2_ffi/src/lib.rs`（约 5154 行，所有导出集中于此）；`libsmb2_rs/src/include/smb2/dcerpc_coder*.rs`、`libsmb2_rs/src/lib/dcerpc*.rs`、`smb2-share-enum.rs`、`socket.rs`、`include/smb2/libsmb2.rs`（补 C-ABI 友好入口）。
- **ABI 契约**：`/home/liyuan/libsmb2/lib/libsmb2.syms`（152 符号）、`test_abi_compat.sh`（136 公开函数）须持续通过。
- **类型 marshalling**：ffi `#[repr(C)]` 类型（`DceRpcRustPdu`/`DceRpcRustContext`/`Smb2Iovec`/`DceRpcUtf16C`/`SrvsvcShareInfo1C` 等）与 rs owned 类型之间需显式转换；rs coder 当前是引用式 `Result` 返回，需提供指针式 C-ABI thunk 或将调度整体移入 rs。
- **测试**：`cargo test -p libsmb2_rs --features migration_modules --no-fail-fast` 须保持 0 失败；`libsmb2_ffi` 须 `cargo build` 通过并能用 C 测试程序验证 DCERPC/share-enum 往返。
- **依赖**：无新增 crate 依赖。
