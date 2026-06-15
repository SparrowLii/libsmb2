## Why

`libsmb2_rs` 目前只是迁移骨架：65 个 `spec_cases` 测试文件直接 `use libsmb2_sys::...`，通过 FFI 调用原始 C 实现来验证 spec，并未真正执行任何 Rust 代码。这意味着「Rust 重构」尚未发生——C 仍是唯一的真实实现。我们需要在 `libsmb2_rs` 中用纯 Rust 补全全部 C 行为，让 spec 测试改为驱动 Rust 实现，从而真正完成去 C 化，并以 `libsmb2-rs-pro`（已完成的惯用 Rust 重写）作为参考。

## What Changes

- 在 `libsmb2_rs` 中补全所有当前缺失或仅为骨架的纯 Rust 实现，覆盖加密原语、编解码、SMB2 协议命令、DCERPC、认证、核心上下文/同步/socket、数据结构与 utils。
- 将 65 个 `spec_cases` 测试从 `use libsmb2_sys::...` 切换为 `use libsmb2_rs::...`，使其断言运行在 Rust 实现上而非 C FFI。
- 实现层参考 `libsmb2-rs-pro` 的惯用 Rust 写法（crypto 复用 `aes`/`sha2`/`hmac`/`cmac` 等 crate，协议层用类型安全的编解码），但 API 形状须满足现有 spec 测试的期望。
- 修复当前 `--features migration_modules` 下已暴露的 16 个失败用例（签名、lock/write/tree-disconnect 编码、cp/ls、errors、dcerpc transport 等）。
- **BREAKING**: `spec_cases` 测试不再依赖 `libsmb2_sys`;`libsmb2_rs` 对 `libsmb2_sys` 的依赖在重构完成后移除。
- 目标终态：`cargo test -p libsmb2_rs --features migration_modules --no-fail-fast` 全量通过，且测试不再链接 C。

## Capabilities

### New Capabilities
- `rust-crypto-primitives`: 纯 Rust 的 AES/AES128-CCM/MD4/MD5/SHA1/SHA2/HMAC/USHA 原语，满足 aes、aes128ccm、md4c、md5、sha*、hmac*、usha 等 spec。
- `rust-encoding`: 纯 Rust 的 ASN.1-BER、UTF-16 unicode、timestamps、portable-endian、slist、asprintf 编解码，满足对应 spec。
- `rust-smb2-commands`: 纯 Rust 的 SMB2 命令请求/响应编解码（negotiate、session-setup、tree-connect/disconnect、create、read、write、close、query-info、query-directory、set-info、flush、lock、echo、logoff、notify-change、oplock-break、ioctl、error），满足 smb2-cmd-* spec。
- `rust-smb2-data`: 纯 Rust 的 SMB2 数据结构编解码（file-info、filesystem-info、reparse-point、security-descriptor），满足 smb2-data-* spec。
- `rust-dcerpc`: 纯 Rust 的 DCERPC 编解码与 srvsvc/lsa 接口（NDR coder、pointer/scalar/UTF-16/UUID 编解码、share-enum、lsa），满足 dcerpc*、libsmb2-dcerpc* spec。
- `rust-auth`: 纯 Rust 的 NTLMSSP，以及 spnego-wrapper、krb5-wrapper 的 Rust 封装/桩，满足 ntlmssp、spnego-wrapper、krb5-wrapper spec。
- `rust-core-runtime`: 纯 Rust 的 context/init、PDU 生命周期、sync 包装、socket/transport、alloc、errors、compat，满足 init、sync、socket、pdu、alloc、errors、compat、libsmb2 spec。
- `rust-signing`: 纯 Rust 的 SMB2/3 签名（HMAC-SHA256 与 AES-CMAC）及 smb3 seal，满足 smb2-signing*、smb3-seal spec。
- `rust-utils`: 纯 Rust 的 smb2-cp、smb2-ls 工具行为，满足 utils spec。
- `rust-platform-config`: 纯 Rust 的平台配置常量（amiga_os/apple/esp/picow/ps3/xbox/xbox 360 config、FreeRTOSConfig、lwipopts、libsmb2-private 常量），满足 include/* config spec。

### Modified Capabilities
<!-- openspec/specs/ 为空，无已建立的 capability spec，无需 delta。 -->

## Impact

- 受影响代码：`libsmb2_rs/src/lib/**`、`libsmb2_rs/src/include/**`（补全实现）、`libsmb2_rs/tests/spec_cases/**`（切换导入到 Rust）、`libsmb2_rs/Cargo.toml`（新增 crypto 等依赖、最终移除对 `libsmb2_sys` 的依赖）。
- 受影响依赖：新增 `aes`/`sha1`/`sha2`/`md-5`/`md4`/`hmac`/`cmac`/`ccm`/`bitflags`/`thiserror` 等（对齐 `libsmb2-rs-pro`）。
- 参考来源：`libsmb2-rs-pro/src/**` 的惯用实现;`specs/**/*.spec.md` 为行为契约。
- 不影响：原始 C 源码树（`lib/`、`include/`、`utils/`）保持不动，仅作为 spec 真值来源;`libsmb2_ffi` C ABI facade 在本变更范围外。
