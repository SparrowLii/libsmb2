## ADDED Requirements

### Requirement: Rust platform configuration constants

`libsmb2_rs` SHALL expose pure-Rust platform configuration values (header-capability flags, feature toggles, and platform constants) for the supported platforms (amiga_os, apple, esp, picow, ps3, xbox, xbox 360) matching the C config-header contracts, so config spec tests assert against Rust constants rather than C macros.

#### Scenario: Header capability flag matches platform config
- **WHEN** a caller reads a header-capability constant for a given platform
- **THEN** the value MUST equal the spec-defined macro value for that platform

#### Scenario: TCP linger configuration is exposed
- **WHEN** a caller reads the TCP linger configuration constant
- **THEN** the value MUST match the spec-defined configure option

#### Scenario: Krb5 and GSSAPI disabled by default
- **WHEN** a caller reads the krb5/GSSAPI capability constants in the default configuration
- **THEN** they MUST report disabled per the spec

### Requirement: Rust private library constants

`libsmb2_rs` SHALL expose pure-Rust internal constants and the `libsmb2-private` surface (header struct size, recv-state values, private constants) matching the C contract used by command and PDU code.

#### Scenario: Header struct size constant matches spec
- **WHEN** a caller reads the SMB2 header struct size constant
- **THEN** the value MUST equal the spec-defined fixed header size

#### Scenario: Recv-state values match spec
- **WHEN** a caller enumerates the receive-state values
- **THEN** they MUST match the spec-defined ordering and values

### Requirement: Rust embedded RTOS configuration constants

`libsmb2_rs` SHALL expose pure-Rust values for the picow embedded configuration surfaces (FreeRTOSConfig, lwipopts, lwipopts examples common) matching the C header contracts.

#### Scenario: FreeRTOS configuration constant matches spec
- **WHEN** a caller reads a FreeRTOSConfig constant
- **THEN** the value MUST equal the spec-defined configuration

#### Scenario: lwIP options constant matches spec
- **WHEN** a caller reads an lwipopts constant
- **THEN** the value MUST equal the spec-defined option
