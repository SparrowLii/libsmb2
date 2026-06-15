## ADDED Requirements

### Requirement: Rust ASN.1 BER encoding and decoding

`libsmb2_rs` SHALL provide pure-Rust ASN.1 BER encode/decode matching the C `asn1-ber` contract, used by SPNEGO/GSS token wrapping.

#### Scenario: Encode then decode preserves structure
- **WHEN** a caller encodes a tagged BER value and decodes the produced bytes
- **THEN** the decoded tag, length, and content MUST equal the original

#### Scenario: Reject malformed length
- **WHEN** a caller decodes a buffer whose declared length exceeds the available bytes
- **THEN** the implementation MUST report a decode error rather than reading out of bounds

### Requirement: Rust UTF-16 unicode conversion

`libsmb2_rs` SHALL provide pure-Rust UTF-8 ↔ UTF-16LE conversion matching the C `unicode` contract used across SMB2 name fields.

#### Scenario: UTF-8 to UTF-16LE round-trips
- **WHEN** a caller converts a UTF-8 string to UTF-16LE and back
- **THEN** the resulting UTF-8 string MUST equal the original

#### Scenario: UTF-16LE byte length is even
- **WHEN** a caller encodes a string to UTF-16LE
- **THEN** the produced byte length MUST be twice the UTF-16 code-unit count

### Requirement: Rust timestamp conversion

`libsmb2_rs` SHALL provide pure-Rust conversion between Windows FILETIME and Unix time matching the C `timestamps` contract.

#### Scenario: Unix time to FILETIME and back
- **WHEN** a caller converts a Unix timestamp to Windows time and back
- **THEN** the recovered Unix timestamp MUST equal the original within the documented resolution

### Requirement: Rust endian and list helpers

`libsmb2_rs` SHALL provide pure-Rust portable-endian byte-order helpers, intrusive list (`slist`) operations, and `asprintf`-style formatting matching the corresponding C contracts.

#### Scenario: Endian helpers convert host and little-endian
- **WHEN** a caller converts a multi-byte integer to little-endian bytes and back
- **THEN** the recovered integer MUST equal the original on the test target

#### Scenario: Singly linked list add and remove
- **WHEN** a caller adds entries to and removes entries from an `slist`
- **THEN** traversal MUST visit the expected remaining entries in order

#### Scenario: asprintf produces formatted owned string
- **WHEN** a caller formats a string with arguments
- **THEN** the returned owned string MUST equal the expected formatted text
