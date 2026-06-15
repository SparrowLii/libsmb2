## Requirements

### Requirement: Rust SMB2 PDU signing

`libsmb2_rs` SHALL compute and verify SMB2 PDU signatures in pure Rust matching the C `smb2-signing` contract: HMAC-SHA256 for dialects up to 2.1 and AES-128-CMAC for dialects 3.0 and above, using the provided session/signing key.

#### Scenario: Add signature sets flag and signature field
- **WHEN** a caller signs a PDU with a valid signing key
- **THEN** the PDU MUST have its signed flag set and a non-zero signature written over the cleared-signature header

#### Scenario: Check signature accepts valid and rejects tampered
- **WHEN** a caller verifies a correctly signed PDU and then a tampered one with the same key
- **THEN** verification MUST return success for the valid PDU and failure for the tampered PDU

#### Scenario: Signing rejects missing key material
- **WHEN** a caller attempts to sign with a missing or all-zero key
- **THEN** the implementation MUST reject the operation rather than produce a bogus signature

#### Scenario: Inbound signature check succeeds with vectors present
- **WHEN** a caller provides the required key and PDU vectors to the inbound signature check
- **THEN** the check MUST return success rather than a missing-vectors error

### Requirement: Rust SMB3 sealing

`libsmb2_rs` SHALL provide pure-Rust SMB3 transform (seal/unseal) matching the C `smb3-seal` contract, including nonce handling and rejection of malformed transform headers.

#### Scenario: Encrypt then decrypt round-trips
- **WHEN** a caller seals a PDU with a key and nonce and then unseals it
- **THEN** the recovered plaintext MUST equal the original

#### Scenario: Reject duplicate nonce
- **WHEN** a caller seals two PDUs reusing the same nonce
- **THEN** the implementation MUST reject the duplicate nonce

#### Scenario: Reject malformed transform header
- **WHEN** a caller decodes a transform header with an invalid protocol id or parameters
- **THEN** the implementation MUST reject it
