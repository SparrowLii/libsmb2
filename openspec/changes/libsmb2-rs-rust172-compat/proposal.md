## Why

`libsmb2_rs` currently depends on Rust language/library features that require a newer or unstable toolchain, preventing builds with the installed Rust 1.72.0 toolchain. This change makes the Rust implementation compile on Rust 1.72.0 while preserving the existing behavior validated by the full 1600+ test suite with the `migration_modules` feature enabled.

## What Changes

- Replace usages of Rust features newer than 1.72.0 with stable Rust 1.72-compatible equivalents.
- Remove or avoid unstable feature gates and APIs in `libsmb2_rs` implementation and tests.
- Verify `libsmb2_rs` builds with Rust 1.72.0 using the required `migration_modules` feature.
- Verify the full 1600+ test suite passes with `migration_modules` enabled.
- Preserve public behavior and APIs unless an incompatibility is strictly required to support Rust 1.72.0.

## Capabilities

### New Capabilities
- `rust-172-compatibility`: Covers building and testing `libsmb2_rs` successfully with Rust 1.72.0 and the `migration_modules` feature.

### Modified Capabilities

## Impact

- Affected code: `libsmb2_rs` crate implementation, feature-gated modules, and Rust tests that currently require newer or unstable Rust features.
- Affected tooling: Rust 1.72.0 build and test commands, especially with `migration_modules` enabled.
- APIs: No intentional public API or behavioral changes; compatibility edits should be implementation-level substitutions.
- Dependencies: May require adjusting dependency versions or feature usage if current versions require Rust newer than 1.72.0.
