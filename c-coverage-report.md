# C Coverage Report

Date: 2026-06-15

This report records the coverage result from running the original C libsmb2 test suite with GCC/gcov instrumentation.

## Test Setup

- Build directory: `build-c-coverage`
- Coverage flags: `CFLAGS="-O0 -g --coverage"`, `LDFLAGS="--coverage"`
- Test target: local Samba share via `TESTURL=smb://libsmb2cov@127.0.0.1/Share`
- Auth file: `NTLM_USER_FILE=/home/liyuan/tmp/libsmb2/build-c-coverage/tests/NTLM`
- Test command: `make test`
- Coverage capture: `lcov --capture --directory /home/liyuan/tmp/libsmb2/build-c-coverage --output-file coverage.info`
- HTML generation: `genhtml coverage.info --output-directory coverage-html`

## Test Result

The full original C test suite completed successfully under coverage instrumentation.

The suite included normal tests, valgrind tests, socket-error injection tests, credit/metadata stress testing, and DCE/RPC coder tests.

## Overall Coverage

```text
lines......: 32.0% (4435 of 13852 lines)
functions..: 46.3% (340 of 735 functions)
branches...: no data found
```

Branch coverage is unavailable because the current capture did not collect branch data.

## Generated Artifacts

- LCOV trace file: `build-c-coverage/coverage.info`
- HTML report entry point: `build-c-coverage/coverage-html/index.html`

## High-Coverage Areas

| File | Line Coverage | Function Coverage |
| --- | ---: | ---: |
| `lib/aes.c` | 100.0% | 100.0% |
| `lib/timestamps.c` | 100.0% | 100.0% |
| `lib/md4c.c` | 98.2% | 100.0% |
| `lib/md5.c` | 95.7% | 100.0% |
| `utils/smb2-cp.c` | 86.2% | 85.7% |
| `lib/alloc.c` | 83.3% | 100.0% |
| `lib/smb2-signing.c` | 80.8% | 85.7% |
| `tests/metastat-0202-censored.c` | 80.3% | 75.0% |
| `tests/smb2-dcerpc-coder-test.c` | 79.0% | 91.7% |
| `lib/hmac-md5.c` | 78.3% | 100.0% |

## Low or Untested Areas

| File | Line Coverage | Function Coverage |
| --- | ---: | ---: |
| `lib/aes128ccm.c` | 0.0% | 0.0% |
| `lib/dcerpc-lsa.c` | 0.0% | 0.0% |
| `lib/smb2-cmd-echo.c` | 0.0% | 0.0% |
| `lib/smb2-cmd-flush.c` | 0.0% | 0.0% |
| `lib/smb2-cmd-ioctl.c` | 0.0% | 0.0% |
| `lib/smb2-cmd-lock.c` | 0.0% | 0.0% |
| `lib/smb2-cmd-notify-change.c` | 0.0% | 0.0% |
| `lib/smb2-cmd-oplock-break.c` | 0.0% | 0.0% |
| `lib/smb2-cmd-set-info.c` | 0.0% | 0.0% |
| `lib/smb2-data-filesystem-info.c` | 0.0% | 0.0% |
| `lib/smb2-data-reparse-point.c` | 0.0% | 0.0% |
| `lib/smb2-data-security-descriptor.c` | 0.0% | 0.0% |
| `lib/smb2-share-enum.c` | 0.0% | 0.0% |

## Core Library Coverage

| File | Line Coverage | Covered / Total Lines | Function Coverage | Covered / Total Functions |
| --- | ---: | ---: | ---: | ---: |
| `lib/libsmb2.c` | 34.0% | 747 / 2197 | 43.8% | 49 / 112 |
| `lib/sync.c` | 37.1% | 184 / 496 | 47.1% | 16 / 34 |
| `lib/init.c` | 51.6% | 196 / 380 | 43.6% | 17 / 39 |
| `lib/pdu.c` | 43.7% | 283 / 648 | 61.9% | 26 / 42 |
| `lib/socket.c` | 50.3% | 330 / 656 | 75.0% | 18 / 24 |
| `lib/ntlmssp.c` | 50.1% | 351 / 701 | 66.7% | 14 / 21 |
| `lib/dcerpc.c` | 32.1% | 278 / 867 | 53.4% | 31 / 58 |
| `lib/asn1-ber.c` | 11.4% | 56 / 492 | 17.2% | 5 / 29 |
| `lib/errors.c` | 1.3% | 14 / 1082 | 100.0% | 2 / 2 |

## SMB2 Command Coverage

| File | Line Coverage | Function Coverage |
| --- | ---: | ---: |
| `lib/smb2-cmd-close.c` | 35.1% | 50.0% |
| `lib/smb2-cmd-create.c` | 30.2% | 37.5% |
| `lib/smb2-cmd-error.c` | 23.4% | 25.0% |
| `lib/smb2-cmd-logoff.c` | 25.8% | 50.0% |
| `lib/smb2-cmd-negotiate.c` | 40.6% | 53.3% |
| `lib/smb2-cmd-query-directory.c` | 26.1% | 55.6% |
| `lib/smb2-cmd-query-info.c` | 13.5% | 50.0% |
| `lib/smb2-cmd-read.c` | 29.1% | 44.4% |
| `lib/smb2-cmd-session-setup.c` | 35.2% | 50.0% |
| `lib/smb2-cmd-tree-connect.c` | 35.1% | 42.9% |
| `lib/smb2-cmd-tree-disconnect.c` | 33.3% | 50.0% |
| `lib/smb2-cmd-write.c` | 28.5% | 42.9% |

## Test Utility Coverage

| File | Line Coverage | Function Coverage |
| --- | ---: | ---: |
| `tests/ld_sockerr.c` | 100.0% | n/a |
| `tests/metastat-0202-censored.c` | 80.3% | 75.0% |
| `tests/prog_cat.c` | 67.5% | 85.7% |
| `tests/prog_cat_cancel.c` | 55.4% | 75.0% |
| `tests/prog_ls.c` | 61.7% | 50.0% |
| `tests/prog_mkdir.c` | 58.6% | 50.0% |
| `tests/prog_rmdir.c` | 64.3% | 50.0% |
| `tests/smb2-dcerpc-coder-test.c` | 79.0% | 91.7% |
| `utils/smb2-cp.c` | 86.2% | 85.7% |

## Notes

- The current tests exercise the basic SMB2 connect/session/tree/open/read/write/list/copy paths and several injected socket-error paths.
- Untested command modules are mostly protocol features that are not covered by the current shell test suite, such as ioctl, lock, notify-change, set-info, filesystem-info, and share-enum paths.
- `lib/errors.c` has low line coverage because most generated error mapping entries are not individually exercised, even though both functions are covered.
