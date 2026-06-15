## Requirements

### Requirement: Rust DCERPC NDR coder

`libsmb2_rs` SHALL provide pure-Rust DCERPC NDR encoding/decoding covering pointer coders, scalar/integer coders, UTF-16 coders, UUID and context-handle coders, with endian and alignment handling matching the C `dcerpc` contract.

#### Scenario: Integer coder round-trips with alignment
- **WHEN** a caller encodes an integer through the NDR coder and decodes it
- **THEN** the recovered value MUST equal the original and the cursor MUST honor NDR alignment

#### Scenario: UTF-16 coder round-trips a string
- **WHEN** a caller encodes a string through the NDR UTF-16 coder and decodes it
- **THEN** the recovered string MUST equal the original

#### Scenario: Pointer coder encodes referent
- **WHEN** a caller encodes a referenced value through the pointer coder
- **THEN** the encoded bytes MUST carry the referent id and value per NDR rules

### Requirement: Rust DCERPC transport state machine

`libsmb2_rs` SHALL drive the DCERPC bind/call/response state machine matching the C contract: a well-formed bind response MUST be accepted and the call response MUST decode successfully.

#### Scenario: Bind, call, and decode response
- **WHEN** the transport opens a pipe, sends a bind, receives a valid bind-ack, issues a call, and receives a response
- **THEN** the bind response MUST be accepted and the response payload MUST decode without error

### Requirement: Rust srvsvc share enumeration coder

`libsmb2_rs` SHALL encode srvsvc share-enum requests and decode share-enum responses matching the C `dcerpc-srvsvc` / `libsmb2-dcerpc-srvsvc` contract.

#### Scenario: Share-enum response decodes entries
- **WHEN** a caller decodes a srvsvc NetShareEnum response buffer
- **THEN** the decoded share entries (name and type) MUST match the spec-defined layout

### Requirement: Rust LSA coder

`libsmb2_rs` SHALL encode LSA requests and decode LSA responses matching the C `dcerpc-lsa` / `libsmb2-dcerpc-lsa` contract, including context-handle and policy-handle coding.

#### Scenario: LSA policy handle round-trips
- **WHEN** a caller encodes an LSA policy/context handle and decodes it
- **THEN** the recovered handle bytes MUST equal the original

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
