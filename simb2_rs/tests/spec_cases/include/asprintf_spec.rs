// Pending spec-origin scenarios for specs/include/asprintf.spec.md.
//
// These scenarios intentionally remain without generated #[test] functions because the
// source interfaces are header-only static inline functions that require C varargs or
// va_list construction (`asprintf`, `vasprintf`, `_vscprintf_so`). The current
// libsmb2_sys safe binding layer has no portable safe API for forwarding Rust values
// through C varargs or constructing a C va_list, and binding that boundary by guessing
// would violate the spec-origin FFI rule.
//
// Manifest Test refs pending:
// - specs/include/asprintf.spec.md | _vscprintf_so computes formatted output length#non-Xbox length calculation uses a copied va_list
// - specs/include/asprintf.spec.md | vasprintf allocates and formats an owned buffer#successful allocation and formatting
// - specs/include/asprintf.spec.md | vasprintf allocates and formats an owned buffer#length calculation or allocation failure
// - specs/include/asprintf.spec.md | vasprintf allocates and formats an owned buffer#formatting failure releases allocated storage
// - specs/include/asprintf.spec.md | asprintf wraps vasprintf with varargs lifecycle#varargs forwarding to vasprintf
// - specs/include/asprintf.spec.md | inline macro maps Xbox inline spelling#Xbox compile condition rewrites inline keyword
