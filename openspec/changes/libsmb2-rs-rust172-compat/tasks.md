
## 1. Diagnose Rust 1.72.0 Incompatibilities

- [x] 1.1 Confirm the active Rust 1.72.0 toolchain and record the exact compiler version.
- [x] 1.2 Run a targeted `libsmb2_rs` build with `migration_modules` enabled to collect compiler errors.
- [x] 1.3 Identify all Rust language, standard library, unstable feature, and dependency MSRV blockers reported by Rust 1.72.0.
- [x] 1.4 Determine the canonical full 1600+ test command for this checkout and its required feature flags.

## 2. Implement Compatibility Fixes

- [x] 2.1 Replace newer-than-1.72 Rust syntax or APIs in `libsmb2_rs` with stable Rust 1.72-compatible equivalents.
- [x] 2.2 Remove unstable feature gates and nightly-only APIs from `migration_modules` code paths.
- [x] 2.3 Adjust dependency versions or feature selections that require Rust newer than 1.72.0.
- [x] 2.4 Preserve public APIs and existing behavior while applying compatibility substitutions.

## 3. Targeted Verification

- [x] 3.1 Re-run the targeted Rust 1.72.0 build with `migration_modules` enabled until it succeeds.
- [x] 3.2 Run focused Rust tests for `libsmb2_rs` with `migration_modules` enabled.
- [x] 3.3 Inspect warnings or skipped code paths to ensure `migration_modules` coverage is active.

## 4. Full Regression Verification

- [x] 4.1 Run the full 1600+ test suite with `migration_modules` enabled.
- [x] 4.2 Fix any failures caused by Rust 1.72.0 compatibility changes.
- [x] 4.3 Document any remaining failures only if they are confirmed unrelated to this change.
- [x] 4.4 Run OpenSpec validation/status checks and confirm the change is implementation-ready or complete.
