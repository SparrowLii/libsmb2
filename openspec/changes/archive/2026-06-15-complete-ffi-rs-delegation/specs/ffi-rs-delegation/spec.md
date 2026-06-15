## ADDED Requirements

### Requirement: FFI exports delegate to libsmb2_rs

Every function exported by `libsmb2_ffi` (the C-ABI facade producing `libsmb2_rust.so`) SHALL derive its behavior from `libsmb2_rs`, either by directly calling a `libsmb2_rs` function/method or through a thin marshalling bridge that converts C-ABI pointers/structs to/from `libsmb2_rs` types. `libsmb2_ffi` MUST NOT contain a parallel implementation of protocol logic (NDR/RPC encoding, SMB2 command coding, transport behavior) that duplicates logic already present in `libsmb2_rs`.

#### Scenario: An export's behavior is sourced from rs
- **WHEN** a C caller invokes any exported `libsmb2_ffi` function that performs protocol work
- **THEN** the observable result MUST be produced by `libsmb2_rs` code, not by logic implemented solely inside `libsmb2_ffi`

#### Scenario: No duplicate protocol logic remains in ffi
- **WHEN** the codebase is inspected after this change
- **THEN** `libsmb2_ffi` MUST NOT retain private NDR/RPC coder helpers whose logic duplicates `libsmb2_rs` implementations

### Requirement: Permitted ffi-local code is limited to marshalling and plumbing

`libsmb2_ffi` SHALL be permitted to retain only code that performs C-ABI concerns: pointer validation, `#[repr(C)]` type definitions, conversion between C types and `libsmb2_rs` types, allocation/ownership bookkeeping (malloc/free pairing), opaque-handle lifecycle, and callback registration. Such retained code MUST NOT encode protocol semantics.

#### Scenario: Pointer plumbing without rs equivalent is allowed
- **WHEN** an export performs only opaque pointer/struct plumbing (e.g. file-id accessors, directory cursor state, PDU handle accessors) for which no protocol logic exists
- **THEN** that ffi-local code MAY remain, provided it carries no protocol encoding/decoding logic

#### Scenario: Marshalling bridge converts types at the boundary
- **WHEN** an export must call an rs function whose signature uses Rust-native types
- **THEN** `libsmb2_ffi` SHALL convert the C `#[repr(C)]` inputs to rs types, invoke rs, and marshal results/allocations back to the C side

### Requirement: Stubbed exports are replaced with rs-backed behavior

Exports that currently return `not_implemented_code()`, a no-op `0`, or null where `libsmb2_rs` provides an equivalent SHALL be wired to delegate to that `libsmb2_rs` implementation. This includes the notify-change family, bind/listen, accept-connection, share-enum (sync and async), and the DCERPC connect/open/call async entries.

#### Scenario: Previously stubbed export now performs real work
- **WHEN** a C caller invokes an export that previously returned not-implemented but has an rs equivalent
- **THEN** the export MUST delegate to `libsmb2_rs` and produce the behavior defined by that rs implementation

#### Scenario: Export without an rs equivalent is explicitly documented
- **WHEN** an export (e.g. server-side `smb2_serve_port` / `smb2_serve_port_async`) has no `libsmb2_rs` equivalent
- **THEN** it MUST retain an explicit, documented not-implemented failure path rather than a silent no-op, and the gap MUST be recorded as known scope

### Requirement: Public ABI is preserved

This change SHALL NOT alter the public ABI. The exported symbol set MUST continue to satisfy the `lib/libsmb2.syms` contract and exported function signatures MUST NOT change.

#### Scenario: ABI compatibility check still passes
- **WHEN** `test_abi_compat.sh` is run against the C library and the rebuilt `libsmb2_rust.so`
- **THEN** it MUST report the public ABI symbols match with no missing symbols

#### Scenario: Full rs test suite remains green
- **WHEN** `cargo test -p libsmb2_rs --features migration_modules --no-fail-fast` is run after the change
- **THEN** it MUST report zero failures
