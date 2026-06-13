# TRANSLATION_MANIFEST

| Test File | Test Function | Rust Test | FFI Request | Assertion Count | Status | Reason |
| --- | --- | --- | --- | --- | --- | --- |
| tests/aes128ccm_test.c | test_1 | tests::aes128ccm_test_translated::test_translate_aes128ccm_test_test_1 | none | 2 | generated | 已翻译本地 AES-CCM 向量测试，真实 legacy 源为 tests/aes128ccm-test.c；2 条断言对应原 rc == 0 和 memcmp(p, buf) == 0，测试通过且 Cargo 可发现。 |
| tests/aes128ccm_test.c | test_2 | tests::aes128ccm_test_translated::test_translate_aes128ccm_test_test_2 | none | 2 | generated | 已翻译本地 AES-CCM 向量测试，真实 legacy 源为 tests/aes128ccm-test.c；2 条断言对应原 rc == 0 和 memcmp(p, buf) == 0，测试通过且 Cargo 可发现。 |
| tests/smb2-dcerpc-coder-test.c | test_utf16_ndr32_le | none | none | 0 | skipped | ffi-skip: 回读该函数调用 test_dcerpc_coder，依赖 dcerpc_create_context、dcerpc_allocate_pdu、dcerpc_ptr_coder、dcerpc_set_tctx/endian 和 DCERPC PDU 内部状态；FFI_MANIFEST 已将 include/smb2/libsmb2-dcerpc.h、include/smb2/libsmb2-dcerpc-srvsvc.h、lib/dcerpc.c、lib/dcerpc-lsa.c、lib/dcerpc-srvsvc.c 标记 skipped，当前 safe binding 不足且本轮不创建 FFI request。 |
| tests/smb2-dcerpc-coder-test.c | test_utf16_ndr32_be | none | none | 0 | skipped | ffi-skip: 回读该函数调用 test_dcerpc_coder，依赖 dcerpc_create_context、dcerpc_allocate_pdu、dcerpc_ptr_coder、dcerpc_set_tctx/endian 和 DCERPC PDU 内部状态；FFI_MANIFEST 已将 include/smb2/libsmb2-dcerpc.h、lib/dcerpc.c、lib/dcerpc-lsa.c 标记 skipped，当前 safe binding 不足且本轮不创建 FFI request。 |
| tests/smb2-dcerpc-coder-test.c | test_utf16_ndr64_le | none | none | 0 | skipped | ffi-skip: 回读该函数调用 test_dcerpc_coder，依赖 dcerpc_create_context、dcerpc_allocate_pdu、dcerpc_ptr_coder、dcerpc_set_tctx/endian 和 DCERPC PDU 内部状态；FFI_MANIFEST 已将 include/smb2/libsmb2-dcerpc.h、lib/dcerpc.c、lib/dcerpc-lsa.c 标记 skipped，当前 safe binding 不足且本轮不创建 FFI request。 |
| tests/smb2-dcerpc-coder-test.c | test_SHARE_INFO_1_ndr32_le | none | none | 0 | skipped | ffi-skip: 回读该函数调用 SRVSVC/DCERPC coder 和 compare_SHARE_INFO_1，依赖完整 DCERPC PDU payload allocator、NDR context 和 SRVSVC share-info 数据模型；FFI_MANIFEST 已将 include/smb2/libsmb2-dcerpc-srvsvc.h、lib/dcerpc-srvsvc.c、lib/dcerpc.c 标记 skipped，当前 safe binding 不足且本轮不创建 FFI request。 |
| tests/smb2-dcerpc-coder-test.c | test_SHARE_INFO_1_CONTAINER_ndr32_le | none | none | 0 | skipped | ffi-skip: 回读该函数调用 SRVSVC/DCERPC container coder 和 compare_SHARE_INFO_1_CONTAINER，依赖完整 DCERPC PDU payload allocator、NDR context、数组指针重建和 SRVSVC 内部状态；FFI_MANIFEST 已将 include/smb2/libsmb2-dcerpc-srvsvc.h、lib/dcerpc-srvsvc.c、lib/dcerpc.c 标记 skipped，当前 safe binding 不足且本轮不创建 FFI request。 |
| tests/smb2-dcerpc-coder-test.c | test_SHARE_INFO_1_CONTAINER_ndr64_le | none | none | 0 | skipped | ffi-skip: 回读该函数调用 SRVSVC/DCERPC container coder 和 compare_SHARE_INFO_1_CONTAINER，依赖完整 DCERPC PDU payload allocator、NDR64 context、数组指针重建和 SRVSVC 内部状态；FFI_MANIFEST 已将 include/smb2/libsmb2-dcerpc-srvsvc.h、lib/dcerpc-srvsvc.c、lib/dcerpc.c 标记 skipped，当前 safe binding 不足且本轮不创建 FFI request。 |
| tests/ntlmssp_generate_blob.c | main | none | none | 1 | skipped | ffi-skip: 回读 main 依赖 smb2_init_context、ntlmssp_init_context、ntlmssp_generate_blob、smb2_session_setup_request 和内部 auth_data/security_buffer 所有权，并用 memcmp 验证完整 NTLMSSP blob；FFI_MANIFEST 已将 lib/ntlmssp.c、lib/ntlmssp.h、lib/spnego-wrapper.c 和 lib/asn1-ber.c 标记 skipped，当前 safe binding 不足且需要完整 NTLMSSP 内部状态，本轮不创建 FFI request。 |
| tests/ld_sockerr.c | readv | none | none | 0 | skipped | mock-only: 回读文件仅重定义 readv 并通过 LD_PRELOAD/dlsym(RTLD_NEXT) 与 READV_CLOSE 环境变量注入 socket/readv 错误，无独立被测业务断言，属于 mock 基础设施。 |
| tests/prog_rmdir.c | main | none | none | 0 | skipped | external-env: 回读 main 要求 argv[1] 为 smb:// URL，调用 smb2_connect_share 和 smb2_rmdir 操作真实 SMB share；依赖外部 SMB server/凭据/网络环境。 |
| tests/prog_ls.c | main | none | none | 0 | skipped | external-env: 回读 main 要求 smb:// URL，调用 smb2_connect_share、smb2_opendir、smb2_readdir、smb2_readlink 并可通过 ALLOC_FAIL/dlsym mock 分配失败；依赖外部 SMB server/CLI 环境和 mock 基础设施。 |
| tests/metastat-0202-censored.c | main | none | none | 0 | skipped | external-env: 回读 main 要求 smb:// URL、可选密码和多个远端文件名，调用 smb2_connect_share、smb2_stat_async、poll/service_loop；依赖外部 SMB server、凭据、网络和 CLI 参数。 |
| tests/prog_cat_cancel.c | main | none | none | 1 | skipped | external-env: 回读 main 和回调链依赖 smb:// URL、smb2_connect_share_async、smb2_open_async_pdu/free_pdu、smb2_open_async、smb2_pread_async、poll/service；需要外部 SMB server/网络事件循环，ofc_cb 的 exit(10) 是异步取消路径哨兵。 |
| tests/prog_mkdir.c | main | none | none | 0 | skipped | external-env: 回读 main 要求 argv[1] 为 smb:// URL，调用 smb2_connect_share、smb2_rmdir、smb2_mkdir 操作真实 SMB share；依赖外部 SMB server/凭据/网络环境。 |
| tests/prog_cat.c | main | none | none | 0 | skipped | external-env: 回读 main 和回调链要求 smb:// URL，调用 smb2_connect_share_async、smb2_open_async、smb2_pread_async、poll/service 并向 stdout 写远端文件；依赖外部 SMB server/网络事件循环/CLI 真实环境。 |

## 统计信息

- generated: 2
- skipped: 14
- ffi_pending: 0
- discovered: 0
- pending: 0
- total: 16
