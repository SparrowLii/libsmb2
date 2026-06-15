## ADDED Requirements

### Requirement: Rust SMB2 command request encoding

`libsmb2_rs` SHALL encode SMB2 command requests (negotiate, session-setup, tree-connect, tree-disconnect, create, read, write, close, query-info, query-directory, set-info, flush, lock, echo, logoff, notify-change, oplock-break, ioctl) into byte buffers whose fixed-structure sizes, variable-area offsets, and length fields match the C command encoders and the spec byte contracts.

#### Scenario: Fixed structure size matches spec
- **WHEN** a caller encodes a request whose spec defines a fixed structure size
- **THEN** the encoded fixed area length MUST equal that declared size

#### Scenario: Write request reports variable length and maps data
- **WHEN** a caller encodes a write request carrying channel info and write payload
- **THEN** the reported variable length MUST equal the combined channel-info plus data length, and the variable area bytes MUST contain the write data at the correct offset

#### Scenario: Tree-disconnect rejects invalid fixed sizes
- **WHEN** a caller validates a tree-disconnect structure whose fixed size is not the spec-defined value
- **THEN** the implementation MUST reject it as invalid

### Requirement: Rust SMB2 command reply decoding and validation

`libsmb2_rs` SHALL decode and validate SMB2 command replies, accepting structures whose sizes match the spec and rejecting those that do not, matching the C reply handlers.

#### Scenario: Accept valid lock reply size
- **WHEN** a caller validates a lock reply whose structure size equals the spec-defined value
- **THEN** the implementation MUST accept it

#### Scenario: Reject invalid lock reply size
- **WHEN** a caller validates a lock reply whose structure size differs from the spec-defined value
- **THEN** the implementation MUST reject it as invalid

#### Scenario: Construct successful lock reply bytes
- **WHEN** a caller constructs a successful lock reply
- **THEN** the produced fixed-area bytes MUST equal the spec-defined byte sequence

### Requirement: Rust SMB2 error command handling

`libsmb2_rs` SHALL encode and decode the SMB2 error response and map command kinds consistently with the C `smb2-cmd-error` contract.

#### Scenario: Error response carries status and structure size
- **WHEN** a caller decodes an SMB2 error response
- **THEN** the decoded structure size and status fields MUST match the spec-defined values
