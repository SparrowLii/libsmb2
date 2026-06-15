## ADDED Requirements

### Requirement: Rust DCERPC coder exposes a C-ABI-friendly dispatch entry

`libsmb2_rs` SHALL provide a coder dispatch surface that the C-ABI facade can delegate to, such that the full NDR/LSA/srvsvc coder logic — including pointer/referent handling, alignment, conformance-run state, and the per-RPC request/response coders — lives in `libsmb2_rs` and not in `libsmb2_ffi`. The DCERPC PDU/context state machine driving these coders SHALL reside on the `libsmb2_rs` side so the facade does not re-implement it.

The internal coder functions MAY remain reference-based Rust APIs; `libsmb2_rs` SHALL provide a thin internal adapter that accepts owned/slice inputs (as marshalled by the facade) and feeds the reference-based coders, keeping raw-pointer handling confined to `libsmb2_ffi`.

#### Scenario: Facade delegates a coder call to rs
- **WHEN** `libsmb2_ffi` receives a C-ABI coder invocation, marshals its inputs, and calls the rs dispatch entry
- **THEN** the encode/decode result MUST be produced by `libsmb2_rs` coder logic and match the existing rust-dcerpc NDR behavior

#### Scenario: Coder state machine lives in rs
- **WHEN** a multi-step coder operation requires deferred-pointer and conformance-run state
- **THEN** that state MUST be carried by `libsmb2_rs` PDU types, with `libsmb2_ffi` holding only an opaque handle plus C-side allocation bookkeeping

#### Scenario: LSA and srvsvc coders are available for delegation
- **WHEN** the facade delegates LSA (Close/LookupSids2/OpenPolicy2/RPC_SID) or srvsvc (SHARE_INFO_0/1/CONTAINER, NetrShareEnum, NetrShareGetInfo) coding
- **THEN** `libsmb2_rs` MUST supply the corresponding coder logic so the facade contains no LSA/srvsvc encoding/decoding of its own
