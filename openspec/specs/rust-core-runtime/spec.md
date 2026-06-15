## Requirements

### Requirement: Rust context and init lifecycle

`libsmb2_rs` SHALL provide pure-Rust SMB2 context creation, initialization, and destruction matching the C `init` / `libsmb2` lifecycle contract, including default field values and clean teardown.

#### Scenario: Context initializes with defaults
- **WHEN** a caller creates a new SMB2 context
- **THEN** the context MUST be initialized with the spec-defined default fields

#### Scenario: Context destruction releases owned state
- **WHEN** a caller destroys a context holding allocated state
- **THEN** all owned buffers and handles MUST be released without leak or double-free

### Requirement: Rust PDU lifecycle

`libsmb2_rs` SHALL model the SMB2 PDU as a Rust object supporting message-id assignment, fixed/variable size queries, timeout configuration, and timeout sweeping matching the C `pdu` contract.

#### Scenario: PDU message id is assigned
- **WHEN** a caller sets a PDU message id
- **THEN** the PDU MUST report that message id

#### Scenario: Fixed and request sizes match command
- **WHEN** a caller queries the fixed size for a command kind
- **THEN** the reported size MUST equal the spec-defined fixed size for that command

#### Scenario: Timed-out PDUs are swept
- **WHEN** a caller configures a PDU timeout and advances time past it, then runs the timeout sweep
- **THEN** the expired PDU MUST be reported as timed out

### Requirement: Rust synchronous operation wrappers

`libsmb2_rs` SHALL provide pure-Rust synchronous wrappers matching the C `sync` contract, returning the spec-defined status codes for operations such as ftruncate.

#### Scenario: Ftruncate completes with success status
- **WHEN** a caller invokes the synchronous ftruncate wrapper on a valid handle
- **THEN** the wrapper MUST complete and return status 0

### Requirement: Rust socket and transport

`libsmb2_rs` SHALL provide pure-Rust socket/transport helpers matching the C `socket` contract, including event bit mapping, NetBIOS frame read/write state, and parameter validation, without requiring a live network for unit behavior.

#### Scenario: Event bits round-trip poll flags
- **WHEN** a caller maps SMB2 desired events to poll bits and back
- **THEN** the recovered event set MUST equal the original

#### Scenario: Transport read advances frame state
- **WHEN** a caller feeds NetBIOS frame bytes to the transport read state
- **THEN** the collected payload and read state MUST advance per the spec contract

### Requirement: Rust allocation, errors, and compat helpers

`libsmb2_rs` SHALL provide pure-Rust allocation helpers, error string/code mapping, and compatibility shims matching the C `alloc`, `errors`, and `compat` contracts.

#### Scenario: Error code maps to expected string and value
- **WHEN** a caller converts an NTSTATUS or errno-style code via the error mapper
- **THEN** the produced numeric value and message MUST match the spec-defined mapping

#### Scenario: Retryable network reset maps to expected code
- **WHEN** a caller converts a network reset condition
- **THEN** the mapped error code MUST equal the spec-defined value
