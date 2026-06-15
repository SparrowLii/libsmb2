## ADDED Requirements

### Requirement: Rust SMB2 file information structures

`libsmb2_rs` SHALL encode and decode SMB2 file-information structures matching the C `smb2-data-file-info` contract, including the fields consumed by stat/query-info callers.

#### Scenario: File info decodes declared fields
- **WHEN** a caller decodes a file-information buffer
- **THEN** the decoded size, attribute, and timestamp fields MUST match the spec-defined layout

### Requirement: Rust SMB2 filesystem information structures

`libsmb2_rs` SHALL encode and decode SMB2 filesystem-information structures matching the C `smb2-data-filesystem-info` contract, including UTF-16 volume labels.

#### Scenario: Volume info round-trips declared UTF-16 label
- **WHEN** a caller encodes filesystem volume info with a UTF-16 label and decodes it
- **THEN** the recovered label and length fields MUST equal the original

### Requirement: Rust SMB2 reparse-point structures

`libsmb2_rs` SHALL encode and decode SMB2 reparse-point structures (symlink and mount-point) matching the C `smb2-data-reparse-point` contract and rejecting malformed inputs.

#### Scenario: Symlink reparse round-trips UTF-16 names
- **WHEN** a caller encodes a symlink reparse point with UTF-16 substitute and print names and decodes it
- **THEN** the recovered names MUST equal the originals

#### Scenario: Reject odd UTF-16 name length
- **WHEN** a caller decodes a reparse point whose declared name length is odd
- **THEN** the implementation MUST reject it as malformed

#### Scenario: Reject truncated declared payload
- **WHEN** a caller decodes a reparse point whose declared payload exceeds available bytes
- **THEN** the implementation MUST reject it rather than read out of bounds

### Requirement: Rust SMB2 security-descriptor structures

`libsmb2_rs` SHALL encode and decode SMB2 security-descriptor structures (owner, group, DACL) matching the C `smb2-data-security-descriptor` contract and rejecting malformed offsets and sizes.

#### Scenario: Security descriptor round-trips owner and DACL
- **WHEN** a caller encodes a security descriptor with an owner SID and a DACL and decodes it
- **THEN** the recovered owner and ACL entries MUST equal the originals

#### Scenario: Reject offsets inside the header
- **WHEN** a caller decodes a security descriptor whose component offset points inside the fixed header
- **THEN** the implementation MUST reject it as malformed

#### Scenario: Reject ACL size smaller than header
- **WHEN** a caller decodes an ACL whose declared size is smaller than the ACL header
- **THEN** the implementation MUST reject it as malformed
