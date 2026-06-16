## ADDED Requirements

### Requirement: Rust 1.72.0 build compatibility
`libsmb2_rs` SHALL compile successfully with Rust 1.72.0 when the `migration_modules` feature is enabled.

#### Scenario: Build with migration modules
- **WHEN** the Rust 1.72.0 toolchain builds `libsmb2_rs` with `migration_modules` enabled
- **THEN** compilation MUST complete without requiring newer stable Rust features or unstable Rust feature gates

### Requirement: Stable feature usage
`libsmb2_rs` SHALL avoid Rust unstable feature gates and APIs in code paths required by the `migration_modules` feature.

#### Scenario: Feature-gated code compiles on stable Rust 1.72.0
- **WHEN** code enabled by `migration_modules` is compiled with Rust 1.72.0
- **THEN** the build MUST NOT require nightly Rust or `#![feature(...)]` gates

### Requirement: Full regression test compatibility
The project SHALL pass the full 1600+ test suite with the `migration_modules` feature enabled after Rust 1.72.0 compatibility changes.

#### Scenario: Full tests run with required feature
- **WHEN** the full project test suite is run using Rust 1.72.0 with `migration_modules` enabled
- **THEN** all tests MUST pass without compatibility regressions

### Requirement: Behavior preservation
Rust 1.72.0 compatibility changes SHALL preserve existing public behavior of `libsmb2_rs`.

#### Scenario: Existing test expectations remain valid
- **WHEN** existing tests exercise `libsmb2_rs` APIs after compatibility changes
- **THEN** the expected outputs, errors, and side effects MUST remain unchanged
