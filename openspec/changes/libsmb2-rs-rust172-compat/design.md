## Context

`libsmb2_rs` must build in an environment where Rust 1.72.0 is installed. The current implementation uses language, standard library, dependency, or unstable feature usage that is not accepted by that toolchain, so compatibility work must focus on removing Rust-version blockers without changing runtime behavior.

The required verification path includes building and running the full 1600+ test suite with the `migration_modules` feature enabled.

## Goals / Non-Goals

**Goals:**
- Make `libsmb2_rs` compile with Rust 1.72.0.
- Remove unstable Rust feature usage from the crate and feature-gated code paths needed by `migration_modules`.
- Keep existing public APIs and behavior unchanged unless a Rust 1.72.0 incompatibility makes an implementation-only substitution impossible.
- Validate with full tests using `migration_modules`.

**Non-Goals:**
- Modernize unrelated Rust code.
- Change C library behavior or unrelated C test infrastructure.
- Introduce new public APIs.
- Replace the project build system beyond what is needed for Rust 1.72.0 compatibility.

## Decisions

1. Prefer stable-compatible rewrites over toolchain changes.
   - Rationale: The target environment is fixed at Rust 1.72.0, so implementation must adapt to the toolchain rather than requiring users to upgrade.
   - Alternative considered: Installing or pinning a newer Rust toolchain. This does not satisfy the compatibility requirement.

2. Treat dependency MSRV as part of the compatibility surface.
   - Rationale: Even if project code is Rust 1.72-compatible, dependencies may pull APIs or editions requiring newer compilers.
   - Alternative considered: Only patching source code. This risks leaving builds broken due to transitive dependency MSRV constraints.

3. Validate with the same feature set used by full tests.
   - Rationale: `migration_modules` can enable code paths that normal builds skip, so compatibility must include that feature.
   - Alternative considered: Verifying default features only. This would not cover the required test configuration.

4. Keep changes surgical and behavior-preserving.
   - Rationale: The goal is compiler compatibility, not semantic redesign.
   - Alternative considered: Broader refactors while touching Rust code. This increases regression risk for the 1600+ tests.

## Risks / Trade-offs

- Rust-version-specific dependency conflicts → Pin or downgrade only the dependencies that require a newer compiler, then verify lockfile resolution with Rust 1.72.0.
- Hidden unstable usage behind feature gates → Build and test with `migration_modules` so those paths compile.
- Behavior drift from replacing newer APIs → Prefer direct equivalents and rely on existing full tests for regression coverage.
- Long full-test runtime → First run targeted Rust build/test checks, then run the full required suite before completion.

## Migration Plan

1. Identify Rust 1.72.0 compile failures in `libsmb2_rs` with `migration_modules` enabled.
2. Replace incompatible syntax, APIs, feature gates, or dependency versions with Rust 1.72-compatible equivalents.
3. Re-run targeted Rust checks until the crate compiles on Rust 1.72.0.
4. Run the full 1600+ test suite with `migration_modules` enabled.
5. If failures remain, classify them as compatibility regressions or pre-existing unrelated failures before final handoff.

## Open Questions

- Which exact command is the canonical full 1600+ test invocation in this checkout?
- Whether any current dependency versions intentionally require a newer MSRV and should be pinned in `Cargo.lock` or replaced at the manifest level.
