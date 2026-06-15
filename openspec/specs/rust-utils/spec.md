## Requirements

### Requirement: Rust smb2-cp file copy behavior

`libsmb2_rs` SHALL provide pure-Rust `smb2-cp` utility behavior matching the C contract, including offset-correct writes and successful end-to-end copy.

#### Scenario: pwrite writes at the correct offset
- **WHEN** the copy utility writes a chunk at a given offset
- **THEN** the destination MUST contain the chunk at that offset and report the written byte count

#### Scenario: Main copy succeeds for a valid source and destination
- **WHEN** the copy utility copies a readable source to a writable destination
- **THEN** the destination content MUST equal the source and the operation MUST report success

### Requirement: Rust smb2-ls listing behavior

`libsmb2_rs` SHALL provide pure-Rust `smb2-ls` utility behavior matching the C contract, including URL-parse failure, connect/opendir failure reporting, readlink failure, and end-of-listing cleanup.

#### Scenario: URL parse failure is reported
- **WHEN** the listing utility is given an unparsable URL
- **THEN** it MUST report a parse failure with the spec-defined nonzero status

#### Scenario: Opendir failure is reported
- **WHEN** the listing utility fails to open a directory
- **THEN** it MUST report the failure with the spec-defined status

#### Scenario: End of listing cleans up resources
- **WHEN** the listing utility reaches the end of a directory enumeration
- **THEN** it MUST release directory and connection resources exactly once
