# C Test Memory-Safety Findings

Date: 2026-06-15

This note records the memory-safety failures found while running the original C implementation test suite under valgrind with coverage instrumentation.

## Test Setup

- Build directory: `build-c-coverage`
- Coverage flags: `CFLAGS="-O0 -g --coverage"`, `LDFLAGS="--coverage"`
- Test target: local Samba share via `TESTURL=smb://libsmb2cov@127.0.0.1/Share`
- Auth file: `NTLM_USER_FILE=/home/liyuan/tmp/libsmb2/build-c-coverage/tests/NTLM`
- Primary failing tests so far:
  - `test_0102_ls_basic_socket_error.sh`
  - `test_0211_cp_valgrind.sh`
  - `test_0212_cp_valgrind_socket_error.sh`

## Issues Fixed

### 1. Coverage preload runtime linkage

Failure:

```text
/bin/bash: symbol lookup error: ./ld_sockerr.so: undefined symbol: __gcov_merge_add
```

Cause:

`ld_sockerr.so` was compiled with coverage instrumentation but linked without coverage runtime flags.

Fix:

`tests/Makefile.am` now links the preload library with `$(LDFLAGS)`:

```make
ld_sockerr.so: ld_sockerr.o
	$(CC) $(LDFLAGS) -shared -o ld_sockerr.so ld_sockerr.o -ldl
```

### 2. Open success-path sync callback leak

Failure:

`test_0211_cp_valgrind.sh` reported a 16-byte leak allocated in `smb2_open` from `sync_cb_data`.

Cause:

The synchronous `smb2_open` wrapper allocated callback data that could be retained by the returned file handle and not released consistently.

Fix:

File handles now track callback data ownership through `free_cb_data`, and successful open clears that ownership after handing the handle to the caller.

### 3. Async open handle leaks on socket errors

Failure:

Socket-error tests leaked `struct smb2fh` allocations when an async open was orphaned by an injected socket failure.

Cause:

Open handles were allocated before the request completed but were not reachable from context destruction if the request failed mid-flight.

Fix:

The SMB2 context now tracks outstanding file handles in `smb2->files`, and `smb2_destroy_context` releases them via `smb2_free_all_filehandles`.

### 4. Async opendir leaks on socket errors

Failure:

`test_0102_ls_basic_socket_error.sh` leaked directory handles allocated by `_smb2_opendir_async`.

Cause:

Outstanding directory handles were not tracked for cleanup on context destruction.

Fix:

The SMB2 context now tracks outstanding directories in `smb2->dirs`, and `smb2_destroy_context` releases them via `smb2_free_all_dirs`.

### 5. Stale active PDU pointer use-after-free

Failure:

Valgrind reported use-after-free during context destruction after a PDU had already been freed by a synchronous wrapper.

Cause:

`smb2->pdu` and `smb2->next_pdu` could still point at a freed PDU.

Fix:

`smb2_free_pdu` now clears `smb2->pdu` and `smb2->next_pdu` when either points at the PDU being freed.

### 6. Open failure-path sync callback use-after-free / double-free

Failure:

`test_0211_cp_valgrind.sh` failed on the missing-file case with invalid reads and invalid free in `smb2_open` / `wait_for_reply`.

Cause:

`open_cb` freed sync callback data via file-handle cleanup before the synchronous wrapper finished reading it.

Fix:

The open failure path now clears file-handle callback-data ownership before freeing the failed file handle, leaving `smb2_open` to release its own sync callback data.

### 7. Open socket-error sync callback leak / double-free

Failure:

`test_0212_cp_valgrind_socket_error.sh` alternated between a leaked 16-byte `sync_cb_data` block and an invalid free during context destruction.

Cause:

The synchronous `smb2_open` wrapper passed `free` as callback-data ownership to the async open path, while also trying to manage that same allocation itself.

Fix:

`smb2_open` now passes `NULL` for async callback-data ownership and frees its sync callback data directly on the paths it owns.

### 8. Write socket-error callback-data leak

Failure:

`test_0212_cp_valgrind_socket_error.sh` failed during `smb2_pwrite` with a 16-byte `sync_cb_data` leak.

Cause:

A write callback could set `is_finished` and an error status, then `wait_for_reply` returned failure; `smb2_pwrite` returned immediately before freeing its callback data.

Fix:

`smb2_pwrite` now checks whether the callback already completed before returning from the error path. If completed, it falls through to local cleanup.

### 9. Fstat socket-error callback-data leak

Failure:

`test_0212_cp_valgrind_socket_error.sh` reached the copy-from-share path and failed during `smb2_fstat` with a 16-byte `sync_cb_data` leak.

Cause:

This matched the `smb2_pwrite` pattern: the callback had already completed, but `wait_for_reply` returned failure and the wrapper returned before freeing `cb_data`.

Fix:

`smb2_fstat` now falls through to local cleanup when `cb_data->is_finished` is already set on the error path.

### 10. Pread socket-error callback-data leak

Failure:

After fixing `smb2_fstat`, the same socket-error test failed later in `smb2_pread` with another 16-byte `sync_cb_data` leak.

Cause:

`smb2_pread` used the same synchronous-wrapper error path that returned before freeing completed callback data.

Fix:

`smb2_pread` now uses the same narrow cleanup rule as `smb2_pwrite` and `smb2_fstat`.

## Final Verification

The full original C test suite passed under coverage instrumentation after the fixes.

Coverage summary from `build-c-coverage/coverage.info`:

```text
lines......: 32.0% (4435 of 13852 lines)
functions..: 46.3% (340 of 735 functions)
branches...: no data found
```

Generated artifacts:

- LCOV trace: `build-c-coverage/coverage.info`
- HTML report: `build-c-coverage/coverage-html/index.html`
