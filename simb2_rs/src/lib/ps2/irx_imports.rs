//! PS2 IRX import surface marker migrated from `lib/ps2/irx_imports.h`.

/// Imported PS2SDK module family.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IrxImport {
    /// Interrupt manager.
    Intrman,
    /// I/O manager.
    Ioman,
    /// PS2IP networking stack.
    Ps2ip,
    /// SIF manager.
    Sifman,
    /// C stdio imports.
    Stdio,
    /// C library imports.
    Sysclib,
    /// System memory manager.
    Sysmem,
    /// Thread base manager.
    Thbase,
    /// Thread semaphore manager.
    Thsemap,
}

/// Returns the import list represented by `irx_imports.h`.
#[must_use]
pub const fn imports() -> [IrxImport; 9] {
    [
        IrxImport::Intrman,
        IrxImport::Ioman,
        IrxImport::Ps2ip,
        IrxImport::Sifman,
        IrxImport::Stdio,
        IrxImport::Sysclib,
        IrxImport::Sysmem,
        IrxImport::Thbase,
        IrxImport::Thsemap,
    ]
}
