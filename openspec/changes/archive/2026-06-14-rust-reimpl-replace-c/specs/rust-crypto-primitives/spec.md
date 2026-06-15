## ADDED Requirements

### Requirement: Rust AES-128 ECB block encryption

`libsmb2_rs` SHALL provide pure-Rust AES-128 ECB single-block encryption exposed through the existing `aes` module API (`AesBlock`, `encrypt_block`) so that callers obtain deterministic 16-byte ciphertext for a given 16-byte input and key, matching the C `AES128_ECB_encrypt` contract.

#### Scenario: Single block encrypts to 16 bytes
- **WHEN** a caller invokes `encrypt_block(input, key)` with a 16-byte input block and 16-byte key
- **THEN** the implementation MUST return a 16-byte `AesBlock` produced by AES-128 ECB

#### Scenario: Deterministic output for CCM callers
- **WHEN** the same input block and key are encrypted twice
- **THEN** both results MUST be byte-identical so AES-CCM authentication block generation is stable

### Requirement: Rust AES-128-CCM authenticated encryption

`libsmb2_rs` SHALL provide pure-Rust AES-128-CCM encrypt and decrypt matching the C `aes128ccm_encrypt` / `aes128ccm_decrypt` contract, including known-answer vectors and encrypt/decrypt round-trip.

#### Scenario: Encrypt then decrypt round-trips plaintext
- **WHEN** a caller encrypts plaintext with a key, nonce, and AAD, then decrypts the resulting ciphertext and tag with the same parameters
- **THEN** the decrypted output MUST equal the original plaintext and the tag MUST verify

#### Scenario: Known-answer vectors match
- **WHEN** the documented test vectors are encrypted
- **THEN** the produced ciphertext and authentication tag MUST equal the expected vector bytes

### Requirement: Rust hash primitives

`libsmb2_rs` SHALL provide pure-Rust MD4, MD5, SHA-1, SHA-224/256, and SHA-384/512 implementations exposing the streaming `init`/`update`/`finalize` interface and producing digests matching the C implementations.

#### Scenario: MD5 streaming digest matches known vector
- **WHEN** a caller initializes an MD5 context, updates it with input, and finalizes
- **THEN** the resulting digest MUST equal the expected MD5 digest for that input

#### Scenario: SHA family one-shot and streaming agree
- **WHEN** the same message is hashed in one update versus multiple updates
- **THEN** the finalized digests MUST be identical

### Requirement: Rust HMAC and USHA

`libsmb2_rs` SHALL provide pure-Rust HMAC (including HMAC-MD5 and the one-shot HMAC declaration) and USHA dispatch matching the C `hmac`, `hmac-md5`, and `usha` contracts.

#### Scenario: HMAC over known key and message
- **WHEN** a caller computes HMAC with a given hash, key, and message
- **THEN** the result MUST equal the expected MAC for that primitive

#### Scenario: USHA dispatches by algorithm id
- **WHEN** a caller requests a digest through USHA with a specific SHA algorithm id
- **THEN** the produced digest length and value MUST match that algorithm
