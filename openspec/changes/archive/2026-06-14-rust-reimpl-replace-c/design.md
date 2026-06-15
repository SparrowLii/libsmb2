## Context

`libsmb2_rs` 在 `Cargo.toml` 中以 `migration_modules` feature 门控全部模块，源码树镜像原始 C 项目（`src/lib/**`、`src/include/**`）。运行 `cargo test -p libsmb2_rs --features migration_modules --no-fail-fast` 当前结果：spec_tests 1660 通过 / 15 失败，lib 单测 57 通过 / 1 失败。

关键现状：`libsmb2_rs/tests/spec_cases/` 下 97 个测试文件中有 65 个 `use libsmb2_sys::...`，即通过 FFI 调用原始 C，而非 Rust。这些 spec 测试名义上验证 Rust crate，实际验证的是 C。要真正完成去 C 化，必须（a）在 `libsmb2_rs` 内补全等价 Rust 实现，（b）把这些测试的导入从 `libsmb2_sys` 切到 `libsmb2_rs`，让断言运行在 Rust 上。

参考资产：`libsmb2-rs-pro` 是一份已完成的惯用 Rust 重写（`src/{crypto,protocol,dcerpc,auth,...}`），复用 `aes`/`sha2`/`hmac`/`cmac`/`ccm`/`md-5`/`md4` 等 crate。但它的模块布局与 API 形状（idiomatic）与 `libsmb2_rs`（镜像 C、贴合 spec 测试期望）不同，因此 pro 作为**实现参考**而非直接复制源。

行为真值来源：`specs/**/*.spec.md`（102 个 spec），以 GIVEN/WHEN/THEN 描述 C 的可观察行为。

## Goals / Non-Goals

**Goals:**

- 在 `libsmb2_rs` 中补全纯 Rust 实现，覆盖 65 个目前依赖 C 的 spec 所对应的能力。
- 将 65 个 `spec_cases` 测试逐步从 `libsmb2_sys` 切换到 `libsmb2_rs`，保持每个测试的断言语义不变。
- 修复当前 16 个失败用例，使 `cargo test -p libsmb2_rs --features migration_modules --no-fail-fast` 全量通过。
- Rust 实现的可观察行为与 spec 文档一致（字节级编解码、错误码、长度字段等）。
- 最终移除 `libsmb2_rs` 对 `libsmb2_sys` 的依赖。

**Non-Goals:**

- 不修改原始 C 源码树（`lib/`、`include/`、`utils/`），它只作为 spec 真值。
- 不实现真实网络 SMB2 会话（连接真实服务器）——spec 测试是单元级的编解码/行为契约，不需要 live server。本变更不触及 `plan.md` 中 Phase 3+ 的网络状态机。
- 不改动 `libsmb2_ffi`（C ABI facade）。
- 不要求逐字复制 `libsmb2-rs-pro`;仅借鉴其算法与 crate 选型。
- 平台专属低频面（PS2、Dreamcast、Amiga 运行时）除非是测试阻塞项，否则不在本轮深入。

## Decisions

### D1: 测试驱动、逐能力切换，而非一次性重写

按 proposal 列出的 10 个 capability 分批推进。每批：先确保 `libsmb2_rs` 侧 Rust 实现满足该 capability 对应 spec 测试的 API 与行为，再把这些测试文件的 `use libsmb2_sys::X` 改为 `use libsmb2_rs::X`，跑该批测试至绿，再进入下一批。

理由：65 个文件一次性切换会产生巨量编译错误难以定位;按 capability 切换可保持每步可验证、可回退。备选（一次性切换全部导入）被否决，因不可增量验证。

### D2: 加密原语复用成熟 crate，对齐 pro

AES/AES128-CCM/MD4/MD5/SHA1/SHA2/HMAC/CMAC 复用 `aes`/`ccm`/`md4`/`md-5`/`sha1`/`sha2`/`hmac`/`cmac` crate（与 `libsmb2-rs-pro/Cargo.toml` 一致），但在 `libsmb2_rs` 侧保留 spec 测试期望的类型与函数签名（如 `AesBlock`、`Md5Context::{init,update,finalize}`、`encrypt_block`），作为薄封装。

理由：手写密码学易错;成熟 crate 已被 pro 验证。备选（保留 C 移植的手写实现）风险高且无收益。注意：spec 中某些断言关注 C 特有的内部结构（如 `Md5Context` 暴露 `buf()`/`bytes()`），封装层须保留这些可观察接口。

### D3: 协议命令编解码以 spec 字节契约为准

`smb2-cmd-*` 与 `smb2-data-*` 的 Rust 实现按 spec 的固定结构大小、变长区偏移、长度字段语义实现 encode/decode。已知失败用例（lock reply size、write variable length/area、tree-disconnect fixed size 校验）说明现有 Rust 实现的字段宽度/偏移有偏差，需按 spec 与 pro `src/protocol/*` 对照修正。

理由：spec 测试直接断言字节数组与长度值，必须精确匹配。

### D4: 签名实现补齐真实 HMAC-SHA256 / AES-CMAC

当前 `smb2-signing` 失败用例显示返回 `Err(MissingVectors)` 或 no-op，spec 期望 `Ok(())` 与可校验签名。参考 `libsmb2-rs-pro/src/crypto/signing.rs` 用 `Hmac<Sha256>` 与 `Cmac<Aes128>` 实现 calc/check signature。

### D5: DCERPC transport 状态机修正

lib 单测 `transport_state_machine_opens_binds_calls_and_decodes_response` 因 bind 响应被拒（ErrorCode -22 = EINVAL）失败。参考 pro `src/dcerpc/{mod,ndr,srvsvc,lsa}.rs` 修正 bind 接收与 NDR 解码路径。

### D6: 平台 config spec 用常量表达

`include/*/config.spec.md` 是编译期宏/能力契约。在 Rust 侧以常量/`cfg` 模块表达可观察值（如头文件能力布尔、TCP linger 配置），spec 测试断言这些常量。无需运行时。

## Risks / Trade-offs

- [字节级不匹配] 协议编解码与 C 的精确字节布局偏差会导致 spec 测试失败 → 以 spec 文档的固定/变长结构定义为唯一真值，逐字段对照 pro 实现核对。
- [crypto 类型契约] 替换为 crate 实现可能丢失 spec 期望的内部可观察接口（如 `Md5Context` 字段访问）→ 在封装层显式保留这些 getter，必要时用 Rust 复刻内部状态而非纯 crate 包装。
- [测试导入切换引入大面积编译错误] → 采用 D1 的按 capability 分批切换，每批独立编译验证。
- [krb5/gssapi 不可用] spnego/krb5 的成功认证路径需要外部库与凭据，spec 中多为 skipped → 这些保持桩/能力探测语义，不在本轮强求 live 行为，但需让对应 spec 测试（多为声明/能力级）在 Rust 侧通过。
- [pro 与 libsmb2_rs 布局分歧] 直接复制会破坏 spec 测试期望的 API → pro 仅作算法参考;API 形状服从 `libsmb2_rs` 现有 spec 测试。
- [范围蔓延到网络层] → 明确 Non-Goal:本轮只做单元级编解码/行为契约，不做 live SMB2 会话。

## Migration Plan

1. 在 `libsmb2_rs/Cargo.toml` 增加 crypto/工具 crate 依赖（对齐 pro）。
2. 按 capability 顺序补全/修正 Rust 实现（crypto → encoding → signing → smb2-commands → smb2-data → dcerpc → auth → core-runtime → utils → platform-config）。
3. 每个 capability 完成后，将其对应 spec_cases 测试的 `libsmb2_sys` 导入切换为 `libsmb2_rs`，运行该批测试至绿。
4. 全部切换后，运行 `cargo test -p libsmb2_rs --features migration_modules --no-fail-fast`，确认 0 失败且无测试链接 C。
5. 移除 `libsmb2_rs` 对 `libsmb2_sys` 的 `Cargo.toml` 依赖，再次全量测试。

回退策略：每批切换是独立 commit;若某批 Rust 实现无法达到 spec 行为，可将该批测试导入暂时保留在 `libsmb2_sys` 并记录为待办，不阻塞其余批次。

## Open Questions

- 部分 spec 标记为 `skipped`（krb5/gssapi、PS2 IOP 运行时、大端 Xbox 360 分支）——这些在 Rust 侧应保持 skipped/能力探测，还是需要 `cfg` 伪造覆盖？倾向于保持与当前 manifest 一致的 skipped 语义。
- `migration_modules` feature 是否在重构完成后设为默认？倾向于完成后让模块默认编译（去掉门控），但这可作为收尾步骤单独评估。
