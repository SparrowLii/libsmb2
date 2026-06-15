## Requirements

### Requirement: Rust NTLMSSP message encoding and decoding

`libsmb2_rs` SHALL provide pure-Rust NTLMSSP NEGOTIATE/CHALLENGE/AUTHENTICATE message encoding and decoding matching the C `ntlmssp` contract, including signature, message type, and field offsets.

#### Scenario: Negotiate message carries signature and type
- **WHEN** a caller encodes an NTLMSSP NEGOTIATE message
- **THEN** the encoded bytes MUST begin with the `NTLMSSP\0` signature and message type 1

#### Scenario: Challenge message decodes target info
- **WHEN** a caller decodes a well-formed CHALLENGE message
- **THEN** the decoded server challenge and target-info fields MUST match the spec-defined offsets

#### Scenario: Authenticate message computes NTLMv2 response
- **WHEN** a caller, given a challenge and credentials, builds an AUTHENTICATE message
- **THEN** the message MUST contain an NTLMv2 response over the spec-defined inputs

### Requirement: Rust SPNEGO wrapper

`libsmb2_rs` SHALL provide pure-Rust SPNEGO token wrapping/unwrapping matching the C `spnego-wrapper` contract, building NegTokenInit/NegTokenResp over the BER encoder.

#### Scenario: Wrap NTLMSSP token in NegTokenInit
- **WHEN** a caller wraps an NTLMSSP token via SPNEGO
- **THEN** the produced bytes MUST be a valid NegTokenInit carrying the inner mechToken

#### Scenario: Unwrap NegTokenResp recovers inner token
- **WHEN** a caller unwraps a NegTokenResp
- **THEN** the recovered inner response token MUST equal the embedded bytes

### Requirement: Rust krb5 wrapper capability surface

`libsmb2_rs` SHALL expose a pure-Rust krb5-wrapper API surface matching the C `krb5-wrapper` declarations. When Kerberos support is not available, the wrapper SHALL expose the declared interface and report unavailability rather than panic.

#### Scenario: Krb5 wrapper declarations are available
- **WHEN** a caller references the krb5-wrapper API in a build without Kerberos libraries
- **THEN** the API MUST compile and the declared entry points MUST exist

#### Scenario: Krb5 unavailable path reports error
- **WHEN** a caller invokes a krb5 operation in a build without Kerberos support
- **THEN** the implementation MUST return an unavailability error rather than crash
