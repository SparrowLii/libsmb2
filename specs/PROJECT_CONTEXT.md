# Project Context

## Build System

- CMake: `CMakeLists.txt` declares project `libsmb2` version `6.1.0` with C as the normal project language, optional PICO C/CXX/ASM mode, optional examples, Kerberos/GSSAPI switches, platform definitions, and `add_subdirectory(lib)`.
- Library CMake: `lib/CMakeLists.txt` declares the core `smb2` library source list, public headers under `include/smb2`, platform-specific PS2/PICO/ESP/Dreamcast branches, and install targets.
- Autotools: `configure.ac` declares package `libsmb2` version `6.1.0`, `AC_PROG_CC`, `LT_INIT`, config header generation, optional examples, optional libkrb5, TCP linger option, header/platform checks, and Makefile outputs for `examples`, `include`, `lib`, `tests`, and `utils`.

## Language/Standard

- Primary language: C, based on CMake `project(libsmb2 LANGUAGES C)` and Autotools `AC_PROG_CC`.
- Mixed mode: PICO build path enables C, CXX, and ASM via `project(libsmb2 C CXX ASM)`; `examples/picow/main.cpp` is a C++ example entry.
- C standard: unknown; no explicit `C_STANDARD` or Autotools standard flag was confirmed during Step 1.
- C++ standard: unknown; no explicit standard flag was confirmed during Step 1.

## Compile Conditions

- Build options and platform switches affecting included sources and public behavior include `ESP_PLATFORM`, `IOP`, `BUILD_IRX`, `PICO_BOARD`, `ENABLE_EXAMPLES`, `ENABLE_LIBKRB5`, `ENABLE_GSSAPI`, `BUILD_SHARED_LIBS`, `EE`, `PS2RPC`, `MSVC`, `IOS`, and `VITA`.
- Platform definitions from top-level CMake include `_WIN32`/Windows library linkage, `WIN32_LEAN_AND_MEAN`, `_CRT_SECURE_NO_WARNINGS`, `HAVE_LINGER`, `NEED_GETLOGIN_R`, `NEED_GETPID`, `NEED_RANDOM`, `NEED_SRANDOM`, `NEED_READV`, `NEED_WRITEV`, `NEED_GETADDRINFO`, `NEED_FREEADDRINFO`, `NEED_POLL`, `NEED_BE64TOH`, `PS4_PLATFORM`, `PS2RPC`, `__ps2sdk_iop__`, and `HAVE_CONFIG_H`.
- Autotools configure-time conditions include `_FILE_OFFSET_BITS=64`, `HAVE_LIBKRB5`, `CONFIGURE_OPTION_TCP_LINGER`, `HAVE_WIN32`, and header/member probes such as `HAVE_SOCKADDR_LEN`, `HAVE_SOCKADDR_STORAGE`, and `HAVE_LINGER`.
- Source-level `#if/#ifdef/#ifndef/defined()` conditions require per-file analysis in Step 2+; Step 1 records them as pending context rather than resolving behavior.

## Tests

- Test directory exists at `tests/` and includes C test programs discovered during glob scanning, but tests are excluded from Manifest generation per Step 1c.
- Autotools emits `tests/Makefile` from `configure.ac`.
- GitNexus caller/test-caller attribution was not performed in Step 1 because no per-interface spec generation was requested.

## GitNexus

- `gitnexus status` reported repository `/Users/vaynnecol/WorkSpace/libsmb2`, indexed commit `b72d485`, current commit `b72d485`, status up-to-date.
- Initial `gitnexus query "C C++ source header public API" ... --content` failed because multiple repositories are indexed and the CLI required a repo selector.
- Re-run with `--repo libsmb2` succeeded and returned project-owned candidates such as `lib/socket.c`, `lib/md5.h`, `lib/smb2-cmd-negotiate.c`, `lib/smb2-cmd-read.c`, `utils/smb2-cp.c`, and related symbols.
- Glob/git tracked file discovery supplemented GitNexus and produced the Manifest source/header candidate set, excluding configured ignored directories and tests.

## GitNexus Impact

- Step 1 did not edit production symbols and did not run per-symbol impact analysis.
- Key interface impact analysis remains pending for Step 2+ when concrete source files and public interfaces are selected for spec generation.
