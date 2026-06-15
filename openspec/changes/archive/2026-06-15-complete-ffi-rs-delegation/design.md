## Context

`libsmb2_ffi`（产物 `libsmb2_rust.so`）是 libsmb2 的 C-ABI 门面，导出 152 个契约符号（`lib/libsmb2.syms`），`test_abi_compat.sh` 已通过。但其行为分三类：

- **DELEGATES_RS（约 104 个）**：SMB2 客户端核心，通过 `Smb2RustContext.inner: Smb2Client` 与 `libsmb2_rs::lib::sync::*` 真正委托给 rs。无需改动。
- **FFI_LOCAL（约 22 个）**：DCERPC/NDR coder 在 ffi crate 内自带并行实现，使用本地私有 helper（`dcerpc_scalar_coder`、`dcerpc_code_utf16_string`、`dcerpc_count_size`、`dcerpc_code_pointer_referent`、`dcerpc_read_count`/`write_count` 等约 15 个），**不调用 rs**——尽管 rs 在 `include/smb2/dcerpc_coder*.rs` 与 `lib/dcerpc*.rs` 中已有等价实现。
- **STUB（约 64 个）**：12 个 `dcerpc_stub_coder!`（LSA/srvsvc，返回 0）、10 个 `not_implemented_code()`/null、47 个 `raw_pdu_fn!`（产出空 PDU）。

核心矛盾不是「逻辑缺失」，而是 **ABI 形状不匹配**：rs 的 DCERPC coder 是引用式 Rust 函数（`fn(&mut DceRpcContext, &mut DceRpcPdu, &mut Smb2Iovec, &mut i32, &mut T) -> Result<()>`），而 ffi 导出与内部分发使用原始指针 C-ABI（`DceRpcCoder = Option<unsafe extern "C" fn(dce, pdu, iov, offset, ptr) -> i32>`）。此外 rs 内部存在两套 DCERPC PDU/Context/iovec 类型（`dcerpc_coder.rs` 的 owned 版与 `dcerpc.rs` 的 skeleton 版），与 ffi 的 `#[repr(C)]` 类型均不布局兼容。

约束：(1) 公共 ABI 不可回退——`test_abi_compat.sh` 与 152 符号契约必须持续通过；(2) `cargo test -p libsmb2_rs --features migration_modules --no-fail-fast` 必须保持 0 失败；(3) 不引入新 crate 依赖。

## Goals / Non-Goals

**Goals:**
- 让 `libsmb2_ffi` 每个导出的**行为**都来源于 `libsmb2_rs`，消除 ffi 层的并行协议实现与 no-op 桩。
- 将 DCERPC/LSA/srvsvc 的 NDR coder **调度逻辑下沉到 rs**，在 rs 侧提供 C-ABI 友好的稳定入口；ffi 退化为薄 marshalling 桥接。
- 把已有 rs 实现接到 not-implemented 导出：notify_change 系列、bind/listen、accept、share_enum（sync+async）、dcerpc connect/open/call async。
- 删除下沉后变为死代码的 ffi 本地 DCERPC helper。
- 保持公共 ABI 与全量测试绿。

**Non-Goals:**
- 不改 SMB2 客户端核心已委托的 ~104 个导出。
- 不实现 rs 中尚不存在的服务端 serve-loop（`smb2_serve_port[_async]`）——本次仅明确其语义并保留显式失败路径，补齐另立 change。
- 不改变异步运行时模型（仍是 C 事件循环直译，不引入 ylong）。
- 不重写 47 个 `raw_pdu_fn!` 中缺乏对应 rs 异步 PDU builder 契约的项——本次仅接通有等价的、其余保留显式占位并标注。
- 不改动 `test_abi_compat.sh`/`abi_symbol_audit.py` 脚本本身。

## Decisions

### D1：coder 调度下沉到 rs，ffi 仅做指针 marshalling
在 `libsmb2_rs` 提供一组 **C-ABI 友好的 coder 入口**（接收已由 ffi 转换好的、rs 可直接操作的数据，执行完整 NDR 编解码与指针/对齐/conformance 逻辑，返回状态码或 `Result`）。`libsmb2_ffi` 的每个 `*_coder` 导出只负责：校验原始指针 → 将 `#[repr(C)]` 输入（`DceRpcRustPdu`/`Smb2Iovec`/`DceRpcUtf16C`/`SrvsvcShareInfo1C` 等）转换为 rs 类型 → 调用 rs 入口 → 把结果/分配回写到 C 侧（含 `dcerpc_free_pdu` 的 `allocations` 所有权管理）。

- **为何**：rs 已有真实实现且被 spec_cases 覆盖；下沉后单一事实来源，消除两份并行 NDR 代码。
- **替代方案**：(a) 在 rs 直接写 `#[no_mangle] extern "C"` coder——但会把 C-ABI 关注点泄漏进 rs 核心，污染 rs 的纯 Rust 测试面；(b) 保持 ffi 自带实现只共享叶子函数——治标不治本，仍是两份逻辑。选下沉是因为它根除重复。

### D2：rs coder 入口的形态——内部 reference-based，rs 内薄 adapter
rs 侧维持现有引用式 coder（`dcerpc_coder.rs`），新增一层 rs-internal adapter 把「ffi 转换出来的 owned 输入」喂给引用式 coder，避免在 rs 暴露裸指针。ffi↔rs 边界只传递 owned/slice 类型与基本标量。

- **为何**：保留 rs 既有引用式 API 与测试不动；裸指针仅存在于 ffi 这一层。
- **替代**：让 rs 入口直接吃 `*mut` 裸指针——会把 unsafe 边界推进 rs，违背 rs「纯 Rust、可独立测试」的定位。

### D3：DCERPC PDU/Context 类型归一
ffi 的 `DceRpcRustPdu`/`DceRpcRustContext` 仍作为 C 侧不透明句柄存在，但其承载的 coder 状态机字段（`deferred_pointers`/`conformance_run`/`max_alignment` 等）随调度下沉转移到 rs 的 PDU 类型。ffi PDU 退化为「持有 rs PDU + C 侧分配账本」。rs 内部统一以 `dcerpc_coder.rs` 的类型为 canonical，淘汰 `dcerpc.rs` 中的 skeleton 重复定义（若仍被 spec 引用则保留但不参与 ffi 路径）。

- **为何**：状态机必须和 coder 逻辑在同一侧，否则桥接要来回同步状态，极易出错。

### D4：not-implemented 导出按 rs 现成 API 逐一接通
notify_change（`Smb2Client::notify_change_async` 等）、bind/listen（`socket.rs::bind_and_listen`）、accept（`socket.rs::accept_connection_async`）、share_enum（`smb2-share-enum.rs` + `sync.rs`）、dcerpc connect/open/call async（`dcerpc.rs`）均有 rs 入口，按 D1/D2 的桥接方式接通。

### D5：无 rs 等价的导出显式标注
`smb2_serve_port[_async]` 保留 `not_implemented_code()`，并在 tasks/spec 中明确记录「rs 无服务端 serve-loop，待后续 change」，使其不再是隐性缺口而是已登记的边界。

### D6：分批切换 + 持续验证
按子域分批（dcerpc accessor → 标量/字符串 coder → srvsvc → lsa → notify/socket/share-enum → 清理死代码），每批后跑 `libsmb2_ffi` 构建 + rs 全量测试 + `test_abi_compat.sh`，确保 ABI 与行为不回退。

### D7（实现期修订，基于 rs 实际 API 核对）
代码核对后发现 rs coder 并非单一统一形状，委托边界需按子域区分：

- **primitive coder**（`include/smb2/dcerpc_coder.rs`）：确为 5 参 offset 形 `fn(&mut ctx, &mut pdu, &mut iov, &mut offset, &mut value) -> Result<()>`，与 D1/D2 一致。ffi 逐调用 marshal（含 iovec `*mut u8`↔`Vec<u8>` 拷入拷出）。
- **srvsvc**（`include/smb2/dcerpc_coder_srvsvc.rs`）：是**整消息字节 harness**（`fn(&Struct)->Vec<u8>` / `fn(&[u8])->Struct`），非 offset coder。委托边界放在**整消息级**。
- **LSA**：`include/smb2/dcerpc_coder_lsa.rs` 只有类型、无 coder；真实编解码在 `lib/dcerpc-lsa.rs` 的 `encode_*/decode_*` 字节函数，且用其自有类型集。ffi LSA 委托目标改为 `lib::dcerpc_lsa`。
- **`dcerpc_ptr_coder`/`carray_coder`/`do_coder`**：接收 coder **函数指针**参数。C 函数指针无法跨边界 marshal 成 rs 函数指针并正确递归，因此这些**不做逐调用委托**——保持其分发逻辑在单侧。本次将它们作为 ffi 本地 plumbing 保留（仅当 ffi 不再持有协议叶子逻辑时其本身退化为对 rs primitive 入口的组织），或随 srvsvc/lsa 整消息委托而不再被独立导出路径使用。

修订影响：Group 5（srvsvc）/Group 6（LSA）的委托从「per-field coder 桥接」改为「整消息 encode/decode 桥接」；Group 4 中 `ptr/carray/do_coder` 不强制删除其组织逻辑，只要求其叶子不再重复 rs 协议逻辑。canonical 类型确认为 `include/smb2/dcerpc_coder.rs`（primitive）+ `dcerpc_coder_srvsvc.rs`（srvsvc harness）+ `lib/dcerpc-lsa.rs`（LSA）；`lib/dcerpc.rs` 的无参 stub coder 无 spec 引用，属死 skeleton。

## Risks / Trade-offs

- **类型 marshalling 出错导致内存安全问题（UTF-16/share 数组/分配所有权）** → 桥接层集中在 ffi、严格配对 malloc/free，复用现有 `allocations` 账本；为每个跨边界结构写往返单测，用 C 测试程序验证 share-enum/lookup-sids 实际字节往返。
- **下沉后 rs coder 行为与原 ffi 自带实现存在细微差异（对齐/conformance/referent id）** → 以 rs spec_cases 为基准；对 ffi 侧原有行为差异点（如 `srvsvc_SHARE_INFO_1_CONTAINER` 的 referent `0x7274_7055`、caller-owned 数组约定）逐项核对，必要时在 rs 入口参数化。
- **ABI 符号集意外回退（删 helper 误删导出 / 改签名）** → 每批后跑 `test_abi_compat.sh` 与 152 符号 `nm` 比对；helper 删除只针对私有 `fn`，导出函数签名冻结。
- **rs 两套 DCERPC 类型造成 canonical 选择混乱** → D3 明确以 `dcerpc_coder.rs` 为准；若 `dcerpc.rs` skeleton 仍被 spec 引用则隔离，不进入 ffi 路径。
- **47 个 `raw_pdu_fn!` 缺乏统一 async builder 契约** → 非本次目标范围；仅接通有明确 rs 等价者，其余保留占位并在 spec 标注为已知边界，避免范围蔓延。

## Migration Plan

1. 在 rs 提供/整理 C-ABI 友好的 coder 调度入口与 adapter（不动现有引用式 API）。
2. ffi DCERPC accessor（get/set size_is、endian、tctx、cr、context/pdu 生命周期）改为委托 rs。
3. ffi 标量/字符串/指针/conformance/uuid/context-handle coder 改为桥接 rs，删除对应本地 helper。
4. ffi srvsvc（SHARE_INFO_0/1/CONTAINER、NetrShareEnum/GetInfo）与 lsa（Close/LookupSids2/OpenPolicy2/RPC_SID）coder 接 rs，替换 `dcerpc_stub_coder!`。
5. ffi notify_change / bind / accept / share_enum / dcerpc async 接 rs。
6. 删除残余死 helper；标注 `serve_port` 与无契约 `raw_pdu_fn!` 边界。
7. 全量验证：`cargo build -p libsmb2_ffi`、rs 全量测试 0 失败、`test_abi_compat.sh` OK、C 程序往返冒烟。

**Rollback**：每批独立提交；如某批引入回归，回退该批提交即可，不影响已委托的 SMB2 核心。

## Open Questions

- `raw_pdu_fn!` 系列是否在本 change 内尽量接通，还是统一留到「服务端/异步 PDU」专项 change？当前设计倾向后者（仅接有现成等价者）。
- rs `dcerpc.rs` skeleton 类型是否可在确认无 spec 依赖后直接删除，以彻底归一类型？需在实现期 grep 校验。
