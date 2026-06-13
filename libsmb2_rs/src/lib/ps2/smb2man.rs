//! PS2 SMB2 manager migrated from `lib/ps2/smb2man.c`.

/// Legacy IRX module name used by `lib/ps2/smb2man.c`.
pub const MODNAME: &str = "smb2man";

/// Major version passed to the legacy `IRX_ID` declaration.
pub const VER_MAJOR: u8 = 2;

/// Minor version passed to the legacy `IRX_ID` declaration.
pub const VER_MINOR: u8 = 2;

/// Negative errno returned when PS2SDK device registration is unavailable.
pub const ENOSYS_UNSUPPORTED: i32 = -38;

/// Allocation strategy selected by the legacy `malloc` wrapper.
pub const ALLOC_FIRST: AllocationMode = AllocationMode::First;

/// Rust representation of the `IRX_ID(MODNAME, VER_MAJOR, VER_MINOR)` metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IrxId {
    /// Module name registered with the PS2 IOP loader.
    pub module_name: &'static str,
    /// Major module version.
    pub major: u8,
    /// Minor module version.
    pub minor: u8,
}

impl IrxId {
    /// Creates module metadata matching the C `IRX_ID` macro inputs.
    #[must_use]
    pub const fn new(module_name: &'static str, major: u8, minor: u8) -> Self {
        Self {
            module_name,
            major,
            minor,
        }
    }

    /// Returns the packed display version used by the legacy startup banner.
    #[must_use]
    pub const fn packed_version(self) -> u16 {
        ((self.major as u16) << 8) | self.minor as u16
    }
}

/// Module metadata for `smb2man`.
pub const SMB2MAN_IRX_ID: IrxId = IrxId::new(MODNAME, VER_MAJOR, VER_MINOR);

/// Initialization callback corresponding to the legacy `SMB2_initdev` call.
pub trait Smb2DeviceInitializer {
    /// Initializes the SMB2 device driver layer and returns a legacy status code.
    fn smb2_initdev(&mut self) -> i32;
}

/// No-op initializer for non-PS2 builds and migration tests.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct NoopDeviceInitializer;

impl Smb2DeviceInitializer for NoopDeviceInitializer {
    fn smb2_initdev(&mut self) -> i32 {
        ENOSYS_UNSUPPORTED
    }
}

/// Runtime model for the `_start` entry point in `lib/ps2/smb2man.c`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Smb2Man<I> {
    /// Static IRX module metadata.
    pub irx_id: IrxId,
    initializer: I,
}

impl<I> Smb2Man<I> {
    /// Creates an SMB2 manager entry-point wrapper around a device initializer.
    #[must_use]
    pub const fn new(initializer: I) -> Self {
        Self {
            irx_id: SMB2MAN_IRX_ID,
            initializer,
        }
    }

    /// Returns shared access to the configured initializer.
    #[must_use]
    pub const fn initializer(&self) -> &I {
        &self.initializer
    }

    /// Returns mutable access to the configured initializer.
    pub fn initializer_mut(&mut self) -> &mut I {
        &mut self.initializer
    }
}

impl<I: Smb2DeviceInitializer> Smb2Man<I> {
    /// Starts the manager and delegates device registration to `SMB2_initdev`.
    #[must_use]
    pub fn start(&mut self, _args: &[&str]) -> i32 {
        self.initializer.smb2_initdev()
    }
}

impl Default for Smb2Man<NoopDeviceInitializer> {
    fn default() -> Self {
        Self::new(NoopDeviceInitializer)
    }
}

/// Convenience `_start` equivalent for callers that provide an initializer.
#[must_use]
pub fn start<I: Smb2DeviceInitializer>(initializer: &mut I, _args: &[&str]) -> i32 {
    initializer.smb2_initdev()
}

/// Memory allocation policy mirrored from `AllocSysMemory` mode constants.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AllocationMode {
    /// Allocate from the first suitable memory region.
    First,
}

/// Owned block returned by the Rust `malloc` and `calloc` skeletons.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SystemMemoryBlock {
    mode: AllocationMode,
    bytes: Vec<u8>,
}

impl SystemMemoryBlock {
    /// Creates a zero-filled block with a specific legacy allocation mode.
    #[must_use]
    pub fn zeroed(size: usize, mode: AllocationMode) -> Self {
        Self {
            mode,
            bytes: vec![0; size],
        }
    }

    /// Creates a block with the requested size for `malloc` semantics.
    #[must_use]
    pub fn with_size(size: usize, mode: AllocationMode) -> Self {
        Self {
            mode,
            bytes: vec![0; size],
        }
    }

    /// Returns the allocation mode associated with this block.
    #[must_use]
    pub const fn mode(&self) -> AllocationMode {
        self.mode
    }

    /// Returns the allocated size in bytes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Returns true when the block contains no bytes.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Returns an immutable view of the modeled memory bytes.
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns a mutable view of the modeled memory bytes.
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.bytes
    }
}

/// Allocation failures represented by the Rust memory skeleton.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryError {
    /// The requested member count and member size overflowed `usize`.
    SizeOverflow,
}

/// Result type used by PS2 manager memory helpers.
pub type MemoryResult<T> = core::result::Result<T, MemoryError>;

/// Allocator interface matching the `malloc`, `free`, and `calloc` wrappers.
pub trait Ps2MemoryAllocator {
    /// Allocates a block using the legacy `malloc` semantics.
    fn malloc(&mut self, size: usize) -> MemoryResult<SystemMemoryBlock>;

    /// Releases a block using the legacy `free` semantics.
    fn free(&mut self, block: SystemMemoryBlock);

    /// Allocates and clears a block using the legacy `calloc` semantics.
    fn calloc(&mut self, nmemb: usize, size: usize) -> MemoryResult<SystemMemoryBlock>;
}

/// Platform-independent allocator model for migration scaffolding.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ModeledSysMemory;

impl Ps2MemoryAllocator for ModeledSysMemory {
    fn malloc(&mut self, size: usize) -> MemoryResult<SystemMemoryBlock> {
        Ok(SystemMemoryBlock::with_size(size, ALLOC_FIRST))
    }

    fn free(&mut self, block: SystemMemoryBlock) {
        drop(block);
    }

    fn calloc(&mut self, nmemb: usize, size: usize) -> MemoryResult<SystemMemoryBlock> {
        let total = nmemb.checked_mul(size).ok_or(MemoryError::SizeOverflow)?;
        Ok(SystemMemoryBlock::zeroed(total, ALLOC_FIRST))
    }
}

/// Allocates a modeled PS2 memory block with the legacy `malloc` name.
///
/// # Errors
///
/// Returns a [`MemoryError`] if the allocator cannot model the requested block.
pub fn malloc<A: Ps2MemoryAllocator>(
    allocator: &mut A,
    size: usize,
) -> MemoryResult<SystemMemoryBlock> {
    allocator.malloc(size)
}

/// Releases a modeled PS2 memory block with the legacy `free` name.
pub fn free<A: Ps2MemoryAllocator>(allocator: &mut A, block: SystemMemoryBlock) {
    allocator.free(block);
}

/// Allocates a zeroed modeled PS2 memory block with the legacy `calloc` name.
///
/// # Errors
///
/// Returns [`MemoryError::SizeOverflow`] when `nmemb * size` cannot fit in `usize`.
pub fn calloc<A: Ps2MemoryAllocator>(
    allocator: &mut A,
    nmemb: usize,
    size: usize,
) -> MemoryResult<SystemMemoryBlock> {
    allocator.calloc(nmemb, size)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_initializer_reports_unsupported() {
        let mut manager = Smb2Man::default();

        assert_eq!(manager.start(&[]), ENOSYS_UNSUPPORTED);
    }
}
