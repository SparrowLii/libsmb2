# FFI_MANIFEST

| Source Type | Source | C ABI Shims | Safe Binding | Status | Reason |
| --- | --- | --- | --- | --- | --- |
| baseline | examples/picow/main.cpp | none | none | skipped | upstream-skip: legacy-spec 已跳过该 examples 样例源文件，FFI 不为样例单独建立基础链路。 |
| baseline | examples/picow/smb-ls-sync.c | none | none | skipped | upstream-skip: legacy-spec 已跳过该 examples 样例源文件，FFI 不为样例单独建立基础链路。 |
| baseline | examples/smb2-CMD-FIND.c | none | none | skipped | upstream-skip: legacy-spec 已跳过该 examples 样例源文件，FFI 不为样例单独建立基础链路。 |
| baseline | examples/smb2-cat-async.c | none | none | skipped | upstream-skip: legacy-spec 已跳过该 examples 样例源文件，FFI 不为样例单独建立基础链路。 |
| baseline | examples/smb2-cat-sync.c | none | none | skipped | upstream-skip: legacy-spec 已跳过该 examples 样例源文件，FFI 不为样例单独建立基础链路。 |
| baseline | examples/smb2-ftruncate-sync.c | none | none | skipped | upstream-skip: legacy-spec 已跳过该 examples 样例源文件，FFI 不为样例单独建立基础链路。 |
| baseline | examples/smb2-ls-async.c | none | none | skipped | upstream-skip: legacy-spec 已跳过该 examples 样例源文件，FFI 不为样例单独建立基础链路。 |
| baseline | examples/smb2-ls-epoll.c | none | none | skipped | upstream-skip: legacy-spec 已跳过该 examples 样例源文件，FFI 不为样例单独建立基础链路。 |
| baseline | examples/smb2-lsa-lookupsids.c | none | none | skipped | upstream-skip: legacy-spec 已跳过该 examples 样例源文件，FFI 不为样例单独建立基础链路。 |
| baseline | examples/smb2-lseek-sync.c | none | none | skipped | upstream-skip: legacy-spec 已跳过该 examples 样例源文件，FFI 不为样例单独建立基础链路。 |
| baseline | examples/smb2-notify.c | none | none | skipped | upstream-skip: legacy-spec 已跳过该 examples 样例源文件，FFI 不为样例单独建立基础链路。 |
| baseline | examples/smb2-put-async.c | none | none | skipped | upstream-skip: legacy-spec 已跳过该 examples 样例源文件，FFI 不为样例单独建立基础链路。 |
| baseline | examples/smb2-put-sync.c | none | none | skipped | upstream-skip: legacy-spec 已跳过该 examples 样例源文件，FFI 不为样例单独建立基础链路。 |
| baseline | examples/smb2-raw-fsstat-async.c | none | none | skipped | upstream-skip: legacy-spec 已跳过该 examples 样例源文件，FFI 不为样例单独建立基础链路。 |
| baseline | examples/smb2-raw-getsd-async.c | none | none | skipped | upstream-skip: legacy-spec 已跳过该 examples 样例源文件，FFI 不为样例单独建立基础链路。 |
| baseline | examples/smb2-raw-stat-async.c | none | none | skipped | upstream-skip: legacy-spec 已跳过该 examples 样例源文件，FFI 不为样例单独建立基础链路。 |
| baseline | examples/smb2-readlink.c | none | none | skipped | upstream-skip: legacy-spec 已跳过该 examples 样例源文件，FFI 不为样例单独建立基础链路。 |
| baseline | examples/smb2-rename-sync.c | none | none | skipped | upstream-skip: legacy-spec 已跳过该 examples 样例源文件，FFI 不为样例单独建立基础链路。 |
| baseline | examples/smb2-server-sync.c | none | none | skipped | upstream-skip: legacy-spec 已跳过该 examples 样例源文件，FFI 不为样例单独建立基础链路。 |
| baseline | examples/smb2-share-enum-sync.c | none | none | skipped | upstream-skip: legacy-spec 已跳过该 examples 样例源文件，FFI 不为样例单独建立基础链路。 |
| baseline | examples/smb2-share-enum.c | none | none | skipped | upstream-skip: legacy-spec 已跳过该 examples 样例源文件，FFI 不为样例单独建立基础链路。 |
| baseline | examples/smb2-share-info.c | none | none | skipped | upstream-skip: legacy-spec 已跳过该 examples 样例源文件，FFI 不为样例单独建立基础链路。 |
| baseline | examples/smb2-stat-sync.c | none | none | skipped | upstream-skip: legacy-spec 已跳过该 examples 样例源文件，FFI 不为样例单独建立基础链路。 |
| baseline | examples/smb2-statvfs-sync.c | none | none | skipped | upstream-skip: legacy-spec 已跳过该 examples 样例源文件，FFI 不为样例单独建立基础链路。 |
| baseline | examples/smb2-truncate-sync.c | none | none | skipped | upstream-skip: legacy-spec 已跳过该 examples 样例源文件，FFI 不为样例单独建立基础链路。 |
| baseline | include/amiga_os/config.h | none | none | skipped | ffi-blocked: Autotools 生成的平台配置宏 header，仅提供 CONFIGURE_OPTION_TCP_LINGER、HAVE_*、PACKAGE_VERSION、VERSION 等预处理期宏；无运行时函数、稳定 C ABI 类型、对象生命周期或可调用符号。 |
| baseline | include/apple/config.h | none | none | skipped | ffi-blocked: 仅包含 Autotools 生成的平台配置宏和包元数据宏，无运行时函数、对象生命周期入口、可调用 ABI 或可安全导出的数据结构；宏值仅影响条件编译。 |
| baseline | include/asprintf.h | none | none | skipped | ffi-blocked: header-only 平台兼容 static inline/宏入口，无独立链接符号或稳定运行时 ABI；运行时行为应由实际调用方或实现侧链路覆盖。 |
| baseline | include/esp/config.h | none | none | skipped | ffi-blocked: 仅包含 ESP 平台编译期 config 宏，无运行时函数、生命周期入口或稳定 C ABI；代表性宏 CONFIGURE_OPTION_TCP_LINGER 仅影响条件编译分支。 |
| baseline | include/libsmb2-private.h | libsmb2_sys/shim/include/libsmb2_private_ffi.h,libsmb2_sys/shim/include/libsmb2_private_ffi.c | libsmb2_sys/src/include/libsmb2_private.rs | generated | minimal macro/type boundary: 已生成私有常量、PAD_TO_32BIT/PAD_TO_64BIT、recv state 和代表性内部布局 size 的 C ABI shim 与 safe binding；函数声明仍归属实现文件 FFI 条目。 |
| baseline | include/picow/FreeRTOSConfig.h | none | none | skipped | ffi-blocked: 仅包含 PicoW/FreeRTOS 编译期配置宏、typedef 依赖表达式和 assert 映射，无运行时函数、对象生命周期或可调用 C ABI。 |
| baseline | include/picow/config.h | none | none | skipped | ffi-blocked: 生成型平台 config header，仅包含预处理宏和包元数据字符串；GitNexus/源码证据显示仅用于条件编译，不适合生成运行时 FFI。 |
| baseline | include/picow/lwipopts.h | none | none | skipped | ffi-blocked: 仅定义 PicoW/lwIP 编译期配置宏并包含 lwipopts_examples_common.h，无运行时函数、对象生命周期或稳定 C ABI。 |
| baseline | include/picow/lwipopts_examples_common.h | none | none | skipped | ffi-blocked: 仅定义 PicoW/lwIP 编译期配置宏；spec 证据为预处理契约，适合构建配置/spec 验证而非运行时 FFI。 |
| baseline | include/portable-endian.h | libsmb2_sys/shim/include/portable-endian_ffi.h,libsmb2_sys/shim/include/portable-endian_ffi.c | libsmb2_sys/src/include/portable_endian.rs | generated | macro wrapper boundary: endian 转换为 function-like 宏，bindgen 不能直接提供稳定 callable binding；已通过最小 C ABI shim 包装 16/32/64 位 host/big/little-endian 转换并生成 safe binding 与 smoke test。 |
| baseline | include/ps3/config.h | none | none | skipped | ffi-blocked: 仅包含 PS3 平台 Autoconf 生成配置宏和包元数据宏，无运行时函数、对象生命周期入口、可跨 FFI 暴露的数据结构或稳定 C ABI；宏仅影响条件编译。 |
| baseline | include/slist.h | none | none | skipped | ffi-blocked: header-only intrusive list 宏无可链接函数符号或稳定 C ABI；行为应由使用宏的具体实现文件 FFI target 覆盖。 |
| baseline | include/smb2/libsmb2-dcerpc-lsa.h | none | libsmb2_sys/src/smb2/libsmb2_dcerpc_lsa.rs | generated | direct bindgen/direct constant data-model binding: LSA opnum/access-mask 宏、NT_SID_AUTHORITY、lookup level 枚举和 OpenPolicy2/RPC SID 最小 Rust 数据模型已生成；GitNexus context 显示 callable lsa_*_coder 行为归属 lib/dcerpc-lsa.c 条目，本条目不生成 C ABI shim。 |
| baseline | include/smb2/libsmb2-dcerpc-srvsvc.h | none | none | skipped | ffi-blocked: header 声明 SRVSVC DCERPC share enum/getinfo 数据模型、coder 和 async/sync share API；可调用行为依赖 DCERPC context、SMB2 context、网络 pipe 和 lib/dcerpc-srvsvc.c/lib/smb2-share-enum.c 生命周期，无法作为 header 独立生成最小安全 FFI smoke。 |
| baseline | include/smb2/libsmb2-dcerpc.h | none | none | skipped | ffi-blocked: header 声明 DCERPC context/PDU 生命周期、NDR coder、async open/call 等大接口；最小 safe binding 需要 smb2_context、pipe file id、PDU payload allocator 和 callback 生命周期，无法脱离 lib/dcerpc.c 真实状态独立 smoke。 |
| baseline | include/smb2/libsmb2-raw.h | none | none | skipped | ffi-blocked: RAW SMB2 header 声明 40+ PDU 构造/回复接口和 smb2_free_data；接口需要 smb2_context、pdu 队列、command_data 所有权和回调，无法在无会话/无 PDU 状态下建立可信最小 smoke。 |
| baseline | include/smb2/libsmb2.h | none | none | skipped | ffi-blocked: public API header 覆盖 context、URL、连接、目录、文件 I/O、server、unicode 等多族接口；已对可离线验证的 errors/timestamps/unicode 子集生成 binding，其余接口依赖网络 share、server handler 或内部 context 状态，不能把 header 整体标为 generated。 |
| baseline | include/smb2/smb2-errors.h | none | libsmb2_sys/src/smb2/smb2_errors.rs | generated | direct bindgen/direct constant binding: 该 header 仅定义 SMB2/NTSTATUS 数值宏常量，无函数 ABI、资源所有权、字符串或生命周期语义；已生成 Rust 常量 binding 和 smoke test，无需 C ABI shim。 |
| baseline | include/smb2/smb2-ioctl.h | none | libsmb2_sys/src/smb2/smb2_ioctl.rs | generated | direct bindgen/direct constant binding: 该 header 仅公开 FSCTL 数值宏常量，无函数 ABI、资源所有权或生命周期；已生成 Rust 常量 binding 和 smoke test，无需 C ABI shim。 |
| baseline | include/smb2/smb2.h | none | none | skipped | ffi-blocked: 协议数据模型 header 包含大量 SMB2 request/reply struct、宏和少量 helper 声明；helper 行为归属 lib/libsmb2.c 与具体 command/data 实现文件，struct-only ABI 无独立 runtime smoke，常量子集已由 smb2-errors/ioctl 覆盖。 |
| baseline | include/xbox 360/config.h | none | none | skipped | ffi-blocked: Xbox 360 平台 Autotools 生成 config 宏 header，仅提供 CONFIGURE_OPTION_TCP_LINGER、HAVE_*、PACKAGE*、LT_OBJDIR、STDC_HEADERS、VERSION 等预处理期宏；无运行时函数、稳定 C ABI 类型、对象生命周期或可调用符号。 |
| baseline | include/xbox/config.h | none | none | skipped | ffi-blocked: Xbox 平台 Autotools 生成 config 宏 header，仅提供 CONFIGURE_OPTION_TCP_LINGER、HAVE_*、PACKAGE*、LT_OBJDIR、STDC_HEADERS、VERSION 等预处理期宏；无运行时函数、稳定 C ABI 类型、对象生命周期或可调用符号。 |
| baseline | lib/aes.c | none | libsmb2_sys/src/lib/aes.rs | generated | direct bindgen: AES128_ECB_encrypt 是稳定 C ABI 平台分派入口；已生成固定 16-byte block/key safe binding 和 smoke test，后端由 lib/aes_apple.c/lib/aes_reference.c 编译提供。 |
| baseline | lib/aes.h | none | none | skipped | ffi-blocked: 该 header 仅声明 AES128_ECB_encrypt，运行时 ABI 与 expected 归属 lib/aes.c；不为声明文件单独生成 safe binding。 |
| baseline | lib/aes128ccm.c | none | libsmb2_sys/src/lib/aes128ccm.rs | generated | direct bindgen: lib/aes128ccm.h 暴露稳定 C ABI aes128ccm_encrypt/aes128ccm_decrypt；已编译 lib/aes128ccm.c、AES 分派和后端，safe binding 使用调用方拥有的 buffer 并通过 legacy 测试向量 smoke 验证。 |
| baseline | lib/aes128ccm.h | none | none | skipped | ffi-blocked: 该 header 仅声明 aes128ccm_encrypt/aes128ccm_decrypt，实际 FFI target 和验证归属 lib/aes128ccm.c；不为声明文件单独生成 safe binding。 |
| baseline | lib/aes_apple.c | none | none | skipped | ffi-blocked: macOS 专用 AES 后端实现，仅由 lib/aes.c 的 AES128_ECB_encrypt 在 __APPLE__ 分支调用；独立暴露会绕过平台后端选择，FFI target 已归属 lib/aes.c。 |
| baseline | lib/aes_apple.h | none | none | skipped | ffi-blocked: 该 header 仅声明 macOS AES 后端 AES128_ECB_encrypt_apple，运行时入口和平台选择归属 lib/aes.c；不为后端声明文件单独生成 safe binding。 |
| baseline | lib/aes_reference.c | none | none | skipped | ffi-blocked: AES reference backend 已作为 lib/aes.c 生成链路的非 Apple 后端编译并由 AES128_ECB_encrypt smoke 间接覆盖；直接暴露 backend-only ECB/CBC reference 函数会绕过平台分派和未确认 CBC 编译期开关/NULL key 语义。 |
| baseline | lib/aes_reference.h | none | none | skipped | ffi-blocked: 该 header 仅提供 AES reference 编译期开关和 ECB/CBC reference 函数声明；可调用行为由 lib/aes_reference.c 实现，公开平台分派入口已归属 lib/aes.c，不为声明 header 单独生成 safe binding。 |
| baseline | lib/alloc.c | none | none | skipped | ffi-blocked: allocation context API 使用内部 zero-length buffer header/container_of 约定，smb2_alloc_data 失败路径依赖 smb2_set_error 和 memctx 归属；公开 safe binding 需要完整 context/error 生命周期，不能用裸指针 smoke 保证安全。 |
| baseline | lib/asn1-ber.c | none | none | skipped | ffi-blocked: ASN.1 BER 编解码 API 操作可变 asn1ber_context 输入/输出指针、offset 和 last_error 状态，且被 SPNEGO/NTLMSSP 流程驱动；缺少独立构造/释放/错误 expected 的安全所有权边界，暂不生成裸 buffer FFI。 |
| baseline | lib/asn1-ber.h | none | none | skipped | ffi-blocked: header-only declarations/types are implementation-owned by lib/asn1-ber.c; standalone direct binding would not own callable behavior, use lib/asn1-ber.c FFI target for BER API. |
| baseline | lib/compat.c | none | none | skipped | ffi-blocked: platform/internal-only compatibility layer; functions are conditionally compiled libc/POSIX/socket replacement symbols gated by platform and NEED_* macros, not stable standalone libsmb2 runtime APIs. |
| baseline | lib/compat.h | none | none | skipped | ffi-blocked: platform compatibility header only declares or macro-maps fallback types/functions; callable behavior and ownership belong to lib/compat.c or platform APIs, so no standalone FFI target is generated for the declaration header. |
| baseline | lib/dcerpc-lsa.c | none | none | skipped | ffi-blocked: LSA coder 实现依赖 dcerpc_pdu payload allocator、NDR direction/alignment、context handle 和 smb2_alloc_data；已生成 header 常量/数据模型 binding，但 coder smoke 需要完整 DCERPC PDU 状态，不能安全独立调用。 |
| baseline | lib/dcerpc-srvsvc.c | none | none | skipped | ffi-blocked: SRVSVC coder 实现依赖 dcerpc pointer/carray/UTF16 coder、payload allocator 和 share enum/getinfo RPC union 状态；缺少可独立构造的 safe PDU/context 生命周期，无法生成可信 smoke。 |
| baseline | lib/dcerpc.c | none | none | skipped | ffi-blocked: DCERPC core 管理 SMB2 pipe open、bind/call async、fragment reassembly、PDU allocator、callback 和 pointer table；最小 smoke 需要真实 smb2_context/PDU 生命周期及网络/pipe 状态，不适合直接暴露。 |
| baseline | lib/dreamcast/vfs.c | none | none | skipped | ffi-blocked: Dreamcast/KallistiOS VFS adapter 依赖 kos mutex、vfs_handler_t、/smb 注册和全局 SMB context/url；当前 macOS sys crate 无 KOS SDK 和 VFS runtime，无法构建或 smoke。 |
| baseline | lib/dreamcast/vfs.h | none | none | skipped | ffi-blocked: header only declares Dreamcast/KallistiOS VFS lifecycle entries kos_smb_init/kos_smb_shutdown; runtime ABI, resources, global state, /smb VFS registration, and expected behavior are implementation-owned by lib/dreamcast/vfs.c. |
| baseline | lib/errors.c | none | libsmb2_sys/src/lib/errors.rs | generated | direct bindgen: nterror_to_str/nterror_to_errno 是稳定 C ABI 错误码转换入口；impact 为 HIGH，13 个直接调用者集中在 lib/libsmb2.c 回调流程，本批只新增 Rust safe binding 和 smoke test，不修改 C 语义。 |
| baseline | lib/hmac-md5.c | none | libsmb2_sys/src/lib/hmac_md5.rs | generated | direct bindgen: smb2_hmac_md5 是稳定 C ABI HMAC-MD5 one-shot digest 入口；impact 为 CRITICAL，直接影响 NTLMSSP 认证/会话流程，本批只新增 Rust safe binding 和 RFC2104 smoke vector，不修改 C 语义。 |
| baseline | lib/hmac-md5.h | none | none | skipped | ffi-blocked: 该 header 仅声明 smb2_hmac_md5 并定义编译期兼容宏/typedef；可调用行为和验证归属 lib/hmac-md5.c，不为声明 header 单独生成 safe binding。 |
| baseline | lib/hmac.c | none | libsmb2_sys/src/lib/sha.rs | generated | direct bindgen: hmac/hmacReset/hmacInput/hmacFinalBits/hmacResult 是稳定 C ABI HMAC-SHA 入口；hmac impact 为 LOW，本批通过 HMAC-SHA256 RFC4231 vector smoke 验证，不修改 C 语义。 |
| baseline | lib/init.c | none | none | skipped | ffi-blocked: context lifecycle、URL parsing、error state、setter/getter、iovector 和 credential delegation API 共享 struct smb2_context 内部布局；空指针/释放/active-list 同步仍有 open questions，不能以局部 shim 弱化 smoke。 |
| baseline | lib/krb5-wrapper.c | none | none | skipped | ffi-blocked: Kerberos/GSSAPI wrapper 受 HAVE_LIBKRB5 和系统 krb5/gssapi 库约束，包含 credential/cache/principal/token 生命周期；当前 sys crate 未链接外部 KRB5/GSS 库且缺少可信 test realm expected。 |
| baseline | lib/krb5-wrapper.h | none | none | skipped | ffi-blocked: 该 header 的公开声明受 HAVE_LIBKRB5 条件和系统 krb5/GSSAPI 头库约束；可调用行为、外部库链接和资源生命周期归属 lib/krb5-wrapper.c，不为声明 header 单独生成 safe binding。 |
| baseline | lib/libsmb2.c | none | none | skipped | ffi-blocked: core async client/server API 依赖 socket、PDU 队列、session/tree/file handles、callbacks 和网络 share；无外部 SMB server 或完整 mock PDU 状态时无法生成可信最小 smoke。 |
| baseline | lib/md4.h | none | none | skipped | ffi-blocked: 该 header 仅声明 MD4_CTX 与 MD4Init/MD4Update/MD4Final；可调用算法实现和 smoke vector 归属 lib/md4c.c，不为声明 header 单独生成 safe binding。 |
| baseline | lib/md4c.c | none | libsmb2_sys/src/lib/md4.rs | generated | direct bindgen: MD4Init/MD4Update/MD4Final 是稳定 C ABI MD4 算法入口；impact 为 HIGH，影响 NTLMSSP NTOWFv1 认证链路，本批只新增 Rust one-shot safe binding 和 RFC1320 smoke vector，不修改 C 语义。 |
| baseline | lib/md5.c | none | libsmb2_sys/src/lib/md5.rs | generated | direct bindgen: MD5Init/MD5Update/MD5Final 是稳定 C ABI MD5 算法入口；impact 为 HIGH，影响 HMAC-MD5/NTLMSSP 链路，本批只新增 Rust one-shot safe binding 和 RFC1321 smoke vector，不修改 C 语义。 |
| baseline | lib/md5.h | none | none | skipped | ffi-blocked: 该 header 仅声明 MD5Context 与 MD5Init/MD5Update/MD5Final/MD5Transform；可调用算法实现和 smoke vector 归属 lib/md5.c，不为声明 header 单独生成 safe binding。 |
| baseline | lib/ntlmssp.c | none | none | skipped | ffi-blocked: NTLMSSP blob generation/authentication owns opaque auth_data、SPNEGO wrapping、challenge parsing、session key buffers and time-dependent fields; safe smoke requires full protocol fixtures and ownership release guarantees beyond minimal FFI. |
| baseline | lib/ntlmssp.h | none | none | skipped | ffi-blocked: 该 header 仅声明 NTLMSSP auth_data 生命周期、blob 生成/认证和 session key 访问入口；可调用行为、缓冲区所有权和 expected 归属 lib/ntlmssp.c，不为声明 header 单独生成 safe binding。 |
| baseline | lib/pdu.c | none | none | skipped | ffi-blocked: PDU allocation/queue/dispatch/timeout code depends on internal smb2_context lists, socket callbacks, command payload ownership and async callbacks; direct binding would expose internal mutable state without safe construction boundary. |
| baseline | lib/ps2/irx_imports.h | none | none | skipped | ffi-blocked: PS2 IOP SDK import aggregation header，仅包含 irx/intrman/ioman/ps2ip/sifman/sysmem/thbase 等平台外部头；无项目自有运行时函数或可在通用 sys crate smoke 的稳定 ABI。 |
| baseline | lib/ps2/ps2smb2.h | none | none | skipped | ffi-blocked: PS2 devctl 常量和 I/O struct 仅服务 PS2 SMB2MAN 平台驱动协议；运行时 ABI、ctx 生命周期和 DEVCTL 行为归属 lib/ps2/smb2man.c/lib/ps2/smb2_fio.c，不为平台消息 header 单独生成 safe binding。 |
| baseline | lib/ps2/smb2_fio.c | none | none | skipped | ffi-blocked: PS2 FIO implementation includes PS2SDK headers/types, semaphores, iomanX device callbacks and global share list; current host sys crate cannot compile or smoke PS2 IOP runtime ABI. |
| baseline | lib/ps2/smb2_fio.h | none | none | skipped | ffi-blocked: 该 header 仅声明 PS2 I/O driver 初始化入口 SMB2_initdev；实现、平台依赖和可验证行为归属 lib/ps2/smb2_fio.c，不为声明 header 单独生成 safe binding。 |
| baseline | lib/ps2/smb2man.c | none | none | skipped | ffi-blocked: PS2 IRX module entry defines _start plus PS2 AllocSysMemory/FreeSysMemory malloc wrappers and IRX_ID metadata; requires PS2SDK/loadcore runtime, not a portable Rust FFI target. |
| baseline | lib/sha-private.h | none | none | skipped | ffi-blocked: 该 private header 仅定义 SHA_Ch/SHA_Maj/SHA_Parity 等编译期 helper 宏，无可链接函数符号或独立运行时 ABI；行为由 SHA 实现文件 smoke 覆盖。 |
| baseline | lib/sha.h | none | libsmb2_sys/src/lib/sha.rs | generated | direct bindgen: 该 header 定义 SHA/USHA/HMAC 公开 C ABI 类型、错误码、hash size 常量和函数声明；safe binding 已封装 SHA1/SHA224/SHA256/SHA384/SHA512 与 HMAC-SHA256 最小 one-shot API。 |
| baseline | lib/sha1.c | none | libsmb2_sys/src/lib/sha.rs | generated | direct bindgen: SHA1Reset/SHA1Input/SHA1Result 是稳定 C ABI SHA-1 入口；本批通过 FIPS 180 abc vector smoke 验证，不修改 C 语义。 |
| baseline | lib/sha224-256.c | none | libsmb2_sys/src/lib/sha.rs | generated | direct bindgen: SHA224/SHA256 C ABI 入口已生成；SHA256Result impact 为 CRITICAL，影响 SMB3 preauth/session/signing 相关链路，本批只新增 Rust safe binding 和 FIPS 180 SHA224/SHA256 vectors，不修改 C 语义。 |
| baseline | lib/sha384-512.c | none | libsmb2_sys/src/lib/sha.rs | generated | direct bindgen: SHA384/SHA512 C ABI 入口已生成；SHA512Result impact 为 CRITICAL，影响 USHA/HMAC/SMB3 链路，本批只新增 Rust safe binding 和 FIPS 180 SHA384/SHA512 vectors，不修改 C 语义。 |
| baseline | lib/smb2-cmd-close.c | none | none | skipped | ffi-blocked: SMB2 close PDU builder/parser depends on smb2_context, smb2_pdu allocation, iovector ownership and command callback state; no standalone safe construction/release boundary for smoke. |
| baseline | lib/smb2-cmd-create.c | none | none | skipped | ffi-blocked: SMB2 create request/reply parsing includes variable buffers, UTF-16 names, create contexts, file ids and PDU payload ownership; safe smoke requires full PDU/context fixture. |
| baseline | lib/smb2-cmd-echo.c | none | none | skipped | ffi-blocked: Echo PDU construction/reply parser requires smb2_context PDU allocator and callback queue; isolated binding would expose internal PDU pointers without lifecycle owner. |
| baseline | lib/smb2-cmd-error.c | none | none | skipped | ffi-blocked: Error reply construction/parsing relies on smb2_pdu payload buffers and error context ownership; expected requires protocol payload fixture and context release path. |
| baseline | lib/smb2-cmd-flush.c | none | none | skipped | ffi-blocked: Flush PDU helpers depend on file id, PDU allocation and reply payload lifecycle; no independent safe Rust smoke without smb2_context/PDU setup. |
| baseline | lib/smb2-cmd-ioctl.c | none | none | skipped | ffi-blocked: Ioctl request/reply handles variable input/output buffers, FSCTL pipe transceive and allocated reply data; ownership and length checks require full PDU fixture. |
| baseline | lib/smb2-cmd-lock.c | none | none | skipped | ffi-blocked: Lock PDU construction uses lock arrays, file ids and variable payload encoding under smb2_context/PDU ownership; not safe to expose as standalone FFI. |
| baseline | lib/smb2-cmd-logoff.c | none | none | skipped | ffi-blocked: Logoff command helpers are PDU allocator/parser internals tied to session state and callback queue; no independent runtime expected. |
| baseline | lib/smb2-cmd-negotiate.c | none | none | skipped | ffi-blocked: Negotiate request/reply parsing includes dialect/security blobs, negotiate contexts, preauth hash and server/client state; smoke requires protocol fixture and context mutation. |
| baseline | lib/smb2-cmd-notify-change.c | none | none | skipped | ffi-blocked: Change-notify helpers depend on file ids, output buffer ownership, callback state and notify result release semantics; no standalone safe construction boundary. |
| baseline | lib/smb2-cmd-oplock-break.c | none | none | skipped | ffi-blocked: Oplock/lease break command/reply/notification helpers operate on PDU/server state and lease keys; expected requires SMB2 event fixture. |
| baseline | lib/smb2-cmd-query-directory.c | none | none | skipped | ffi-blocked: Query-directory PDU and directory-info decode paths use UTF-16 conversion, memctx allocations and variable entry chains; safe smoke requires full iovec/memctx fixture. |
| baseline | lib/smb2-cmd-query-info.c | none | none | skipped | ffi-blocked: Query-info PDU/parser routes many info classes to file/filesystem/security decoders with variable buffers and memctx ownership; cannot validate minimal expected safely in isolation. |
| baseline | lib/smb2-cmd-read.c | none | none | skipped | ffi-blocked: Read PDU helpers depend on file id, channel fields, output buffer ownership and callback payload state; no independent FFI smoke without SMB2 PDU lifecycle. |
| baseline | lib/smb2-cmd-session-setup.c | none | none | skipped | ffi-blocked: Session setup PDU helpers mutate authentication/session state and security buffer ownership; expected requires NTLMSSP/KRB5/SPNEGO protocol fixture. |
| baseline | lib/smb2-cmd-set-info.c | none | none | skipped | ffi-blocked: Set-info PDU helpers handle rename/disposition/security buffers and transfer input_data ownership to PDU; standalone binding risks double-free or leaked ownership. |
| baseline | lib/smb2-cmd-tree-connect.c | none | none | skipped | ffi-blocked: Tree-connect command helpers require session context, share path UTF-16 encoding and PDU callback state; no isolated safe smoke. |
| baseline | lib/smb2-cmd-tree-disconnect.c | none | none | skipped | ffi-blocked: Tree-disconnect command helpers depend on tree/session state and PDU queue lifecycle; standalone FFI would not own required context. |
| baseline | lib/smb2-cmd-write.c | none | none | skipped | ffi-blocked: Write PDU helpers manage data buffer ownership, channel info, credit charge and file id state; safe smoke needs full context/PDU lifecycle. |
| baseline | lib/smb2-data-file-info.c | none | none | skipped | ffi-blocked: File-info encoders/decoders operate on many variable-length SMB2 structs, memctx allocations and timestamp/unicode helpers; minimal safe smoke would need full iovec fixtures and ownership rules. |
| baseline | lib/smb2-data-filesystem-info.c | none | none | skipped | ffi-blocked: Filesystem-info encoders/decoders use UTF-16 volume labels, length checks and memctx allocations; no standalone safe Rust owner for decoded buffers. |
| baseline | lib/smb2-data-reparse-point.c | none | none | skipped | ffi-blocked: Reparse point decoder depends on memctx allocation, UTF-16 conversion, path buffer lengths and variable output ownership; isolated smoke lacks safe allocation owner. |
| baseline | lib/smb2-data-security-descriptor.c | none | none | skipped | ffi-blocked: Security descriptor decoder builds nested SID/ACL/ACE structures in memctx with offset/length trust boundaries; safe FFI requires complete memctx/context lifecycle. |
| baseline | lib/smb2-share-enum.c | none | none | skipped | ffi-blocked: Share enum async flow depends on DCERPC open/call/close, network share pipe, callbacks and result free ownership; no standalone expected without SMB server. |
| baseline | lib/smb2-signing.c | none | none | skipped | ffi-blocked: Signing/checking depends on smb2_context keys, dialect, PDU header/signature bytes and encryption/signing state; expected requires complete session/PDU fixture and key material. |
| baseline | lib/smb2-signing.h | none | none | skipped | ffi-blocked: 该 header 仅声明 smb2_pdu_add_signature/smb2_pdu_check_signature；可调用行为依赖 smb2_context/smb2_pdu 内部状态并归属 lib/smb2-signing.c，不为声明 header 单独生成 safe binding。 |
| baseline | lib/smb3-seal.c | none | none | skipped | ffi-blocked: SMB3 sealing encrypt/decrypt depends on session encryption keys, transform headers, PDU chain and socket send/error handling; no independent safe smoke without negotiated session state. |
| baseline | lib/smb3-seal.h | none | none | skipped | ffi-blocked: 该 header 仅声明 smb3_encrypt_pdu/smb3_decrypt_pdu；可调用行为依赖 session keys、PDU 队列和 libsmb2 内部状态并归属 lib/smb3-seal.c，不为声明 header 单独生成 safe binding。 |
| baseline | lib/socket.c | none | none | skipped | ffi-blocked: Socket/event-loop implementation wraps platform sockets, poll/select, connect/read/write callbacks and server accept state; requires OS/network integration and live fd state beyond minimal FFI smoke. |
| baseline | lib/spnego-wrapper.c | none | none | skipped | ffi-blocked: SPNEGO wrapper builds/parses ASN.1 BER blobs with smb2_context error state and output buffer ownership; safe expected requires full DER fixtures and release contract not exposed independently. |
| baseline | lib/spnego-wrapper.h | none | none | skipped | ffi-blocked: 该 header 仅声明 SPNEGO wrap/unwrap blob helpers 和机制常量；输出 blob 所有权、ASN.1 BER 编码依赖和 expected 归属 lib/spnego-wrapper.c，不为声明 header 单独生成 safe binding。 |
| baseline | lib/sync.c | none | none | skipped | ffi-blocked: Sync wrappers drive async APIs through event loop, cancellation and callback data; smoke requires live SMB server or fully mocked socket/PDU stack, not minimal FFI. |
| baseline | lib/timestamps.c | none | libsmb2_sys/src/lib/timestamps.rs | generated | direct bindgen: smb2_timeval_to_win/smb2_win_to_timeval 是稳定 C ABI SMB2/Windows 时间转换入口；impact 为 CRITICAL，影响 query/info 编解码和 NTLMSSP 相关链路，本批只新增 Rust safe binding 和 Unix epoch round-trip smoke，不修改 C 语义。 |
| baseline | lib/unicode.c | libsmb2_sys/shim/lib/unicode_ffi.h,libsmb2_sys/shim/lib/unicode_ffi.c | libsmb2_sys/src/lib/unicode.rs | generated | shim-backed binding: smb2_utf8_to_utf16/smb2_utf16_to_utf8 返回 C malloc 内存，已新增 unicode_ffi_free 释放 shim 并生成 owned Rust Vec/String safe binding；impact 为 CRITICAL，影响 NTLMSSP、DCERPC 和 SMB2 create/query/set-info 编解码，本批只新增释放安全 smoke，不修改 C 语义。 |
| baseline | lib/usha.c | none | libsmb2_sys/src/lib/sha.rs | generated | direct bindgen: USHAReset/USHAInput/USHAResult 统一 SHA 入口已生成；USHAResult impact 为 CRITICAL，影响 HMAC、SMB3 preauth、session setup 和 signing 链路，本批通过各 SHA one-shot safe wrappers 间接验证，不修改 C 语义。 |
| baseline | utils/smb2-cp.c | none | none | skipped | ffi-blocked: CLI utility owns process argv/exit, local file descriptors and optional SMB URL/network copy flow; not a reusable library ABI or safe binding target. |
| baseline | utils/smb2-ls.c | none | none | skipped | ffi-blocked: CLI utility owns process argv/exit and synchronous network directory listing flow; not a reusable library ABI or safe binding target. |

## 统计信息

- generated: 19
- skipped: 108
- pending: 0
- total: 127
