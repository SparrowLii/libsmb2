# libsmb2_rs Remaining Refactor Plan

Goal: make `libsmb2_rs` functionally equivalent to `libsmb2`, expose the original C ABI, and pass the existing shell-based integration tests that compile C programs and drive the library through C headers.

Constraint: do not plan or prioritize work by any manifest. Drive the remaining work by C ABI compatibility, integration-test call paths, and protocol behavior.

## Current State

- `libsmb2_rs` mirrors much of the original C source tree and has many Rust-side protocol/data modules.
- The top-level Rust crate still acts mostly as a migration skeleton and does not yet expose the original C ABI symbols.
- Existing Rust modules provide useful safe models and command encoders, but several paths remain local-completion or skeleton behavior rather than full network behavior.
- The original integration tests are shell scripts under `tests/` and C test programs linked against `libsmb2`; final validation must use those scripts against the Rust-backed ABI library.

## Phase 1: C ABI Facade

- Add a C ABI facade that exports the original public symbols, including context, URL, sync, async, raw, and DCERPC entry points required by tests.
- Represent public C structs with `#[repr(C)]` where layout is public, and opaque pointers where the C API treats the type as opaque.
- Keep the ABI layer thin: pointer checks, C string conversion, callback trampolines, ownership transfer, error mapping, and delegation into existing Rust implementation.
- Preserve legacy return conventions: `NULL` on allocation/init failure, `0` on success, negative errno-style values on failure, and `smb2_get_error()` for human-readable diagnostics.
- Start with symbols used by the integration tests, then expand to broader header coverage.

## Phase 2: Integration-Test Public Surface

- Support `prog_ls`: `smb2_init_context`, `smb2_parse_url`, `smb2_set_security_mode`, `smb2_connect_share`, `smb2_opendir`, `smb2_readdir`, `smb2_readlink`, `smb2_closedir`, `smb2_disconnect_share`, `smb2_destroy_url`, and `smb2_destroy_context`.
- Support `prog_mkdir` and `prog_rmdir`: `smb2_mkdir`, `smb2_rmdir`, sync connection lifecycle, and error reporting for missing or invalid paths.
- Support `prog_cat`: `smb2_connect_share_async`, `smb2_open_async`, `smb2_pread_async`, `smb2_close_async`, `smb2_disconnect_share_async`, `smb2_get_fd`, `smb2_which_events`, and `smb2_service`.
- Support `prog_cat_cancel`: `smb2_open_async_pdu`, `smb2_free_pdu`, and cancellation semantics where the canceled callback never fires.
- Support `metastat-0202-censored`: multiple concurrent `smb2_stat_async` requests on one connection, response matching, and callback completion through the event loop.
- Support `smb2-dcerpc-coder-test`: DCERPC context creation, PDU allocation/free, endian/tctx control, pointer coder, UTF-16 coder, integer coders, and srvsvc/lsa coder behavior.

## Phase 3: Real Network State Machine

- Implement the full connect-share path: TCP connect, SMB negotiate, session setup, authentication, and tree connect.
- Prioritize NTLMSSP authentication because the original test setup uses `NTLM_USER_FILE`.
- Make all async operations enter a single PDU queue driven by `smb2_service()`.
- Implement `smb2_get_fd()`, `smb2_get_fds()`, `smb2_which_events()`, `smb2_service()`, and `smb2_service_fd()` with real poll-compatible semantics.
- Keep callbacks ordered and fired only from service-loop progress, matching the C library behavior.
- Map NTSTATUS and socket errors to the same negative errno-style statuses as the original implementation.

## Phase 4: File, Directory, And Metadata Operations

- Implement directory listing with `CREATE` directory handle, `QUERY_DIRECTORY` loop, decoded entries, and `CLOSE`.
- Implement file open/read/write/close with sequential offset handling, partial read/write handling, and EOF returning zero bytes.
- Implement sync wrappers on top of the async/event-loop path rather than a separate behavior path.
- Implement `stat`, `fstat`, and `statvfs` using query-info responses and fill the public C structs exactly as expected by callers.
- Implement `mkdir`, `rmdir`, `unlink`, `rename`, `truncate`, and `ftruncate` through create/set-info/close command chains or protocol-equivalent operations.
- Implement `readlink` through reparse-point/symlink metadata so `prog_ls` can display link targets.

## Phase 5: PDU Lifecycle And Cancellation

- Make `struct smb2_pdu` a real object representing queued or in-flight work.
- Track whether a PDU is queued, sent, completed, canceled, or detached from callbacks.
- Ensure `smb2_free_pdu()` removes pending work safely and prevents the associated callback from firing.
- Define behavior for already-sent PDUs: ignore/discard late replies when canceled, but keep stream state valid.
- On context destruction, cancel and release all pending PDUs, open file handles, directory handles, callback state, and allocated buffers.
- Preserve memory safety when callbacks destroy the context or free objects during callback execution.

## Phase 6: DCERPC And Share Enumeration

- First pass the coder-only DCERPC integration test without requiring a live SMB server.
- Expose DCERPC C ABI functions for context lifecycle, PDU allocation/free, payload access, `size_is`, pointer coding, scalar coding, UTF-16 coding, and UUID/context-handle coding.
- Complete NDR32/NDR64 differences, endian handling, conformant arrays, varying arrays, unique/ref/full pointer behavior, and alignment rules.
- Add named-pipe transport over SMB2 for `srvsvc` and `lsarpc`: open pipe, bind, call, fragment/reassemble, decode response, and close pipe.
- Wire high-level share enumeration and LSA calls through the same DCERPC transport instead of local-only placeholders.

## Phase 7: Memory Ownership And Failure Paths

- Audit every C-visible allocation and release path: `smb2_url`, `smb2fh`, `smb2dir`, `smb2dirent`, returned data, DCERPC data, PDU, and error strings.
- Implement `smb2_free_data()`, `dcerpc_free_data()`, `smb2_destroy_url()`, and related destroy APIs for Rust-owned allocations.
- Ensure callback `command_data` remains valid for the full callback duration and is released according to original API ownership rules.
- Match allocation-failure behavior expected by the `ALLOC_FAIL` tests.
- Match socket-error behavior expected by `LD_PRELOAD=./ld_sockerr.so` tests.
- Run valgrind-driven scripts as acceptance checks for leaks, invalid reads/writes, use-after-free, and cleanup on error paths.

## Phase 8: Acceptance Order

1. Build a Rust-backed C ABI library and link a minimal C smoke program against it.
2. Run `tests/test_900_dcerpc.sh` to validate ABI plus DCERPC coder behavior without a live SMB server.
3. Run `tests/test_0100_ls_basic.sh` to validate connect, list directory, directory errors, and disconnect.
4. Run `tests/test_0200_mkdir.sh` to validate directory create/remove.
5. Run `tests/test_0210_cp_basic.sh` to validate file create, read, write, close, and missing-file errors.
6. Run `tests/test_0300_cat_basic.sh` to validate async open/read/close through the service loop.
7. Run `tests/test_0310_cancel_pdu.sh` to validate PDU cancellation semantics.
8. Run valgrind and socket-error variants to close cleanup and failure-path gaps.
9. Run `tests/test_0400_overdrawn_0202.sh` to validate SMB 2.0.2 negotiation, concurrent stat requests, queueing, and response matching.
10. Run the full `tests/Makefile.am` shell test sequence as the final gate.

## Priority

- P0: C ABI facade, opaque/public type mapping, context lifecycle, URL lifecycle, error strings, and callback trampolines.
- P0: Real event loop, PDU queue, fd/event reporting, connect/session/tree setup, and NTLMSSP authentication.
- P0: Core file and directory behavior required by `ls`, `mkdir`, `rmdir`, `cp`, `cat`, and `stat` tests.
- P1: PDU cancellation, socket failure behavior, allocation failure behavior, and context-destroy cleanup.
- P1: DCERPC coder C ABI and coder-test parity.
- P2: Full DCERPC named-pipe calls, share enumeration, LSA, and broader examples.
- P2: Low-frequency platform-specific surfaces such as PS2, Dreamcast, Amiga, and server-side APIs unless they become test blockers.

## Guiding Rule

Drive completion by observable compatibility: original C headers, original C ABI symbol names, original callback/lifetime semantics, original shell scripts, and real SMB2 protocol behavior. Do not treat source-file or manifest coverage as evidence of functional equivalence.
