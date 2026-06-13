//! Allocation ownership model migrated from `lib/alloc.c`.
//!
//! The C implementation returns a caller-visible pointer inside an allocation
//! header and links child allocations to that header. This Rust skeleton keeps
//! the same ownership shape without exposing raw pointer arithmetic.

/// Stable handle for an allocation owned by an [`Arena`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Smb2AllocHandle {
    index: usize,
}

impl Smb2AllocHandle {
    /// Returns the arena-local allocation index represented by this handle.
    #[must_use]
    pub const fn index(self) -> usize {
        self.index
    }
}

/// Rust counterpart of `struct smb2_alloc_entry`.
#[derive(Debug, Clone)]
pub struct Smb2AllocEntry {
    next: Option<Smb2AllocHandle>,
    buf: Vec<u8>,
}

impl Smb2AllocEntry {
    /// Creates a zeroed allocation entry with the requested payload size.
    #[must_use]
    pub fn zeroed(size: usize) -> Self {
        Self {
            next: None,
            buf: vec![0; size],
        }
    }

    /// Returns the next linked allocation in the arena chain.
    #[must_use]
    pub const fn next(&self) -> Option<Smb2AllocHandle> {
        self.next
    }

    /// Returns the immutable payload bytes for this allocation.
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        &self.buf
    }

    /// Returns the mutable payload bytes for this allocation.
    #[must_use]
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.buf
    }
}

/// Rust counterpart of `struct smb2_alloc_header`.
#[derive(Debug, Clone)]
pub struct Smb2AllocHeader {
    mem: Option<Smb2AllocHandle>,
    buf: Vec<u8>,
}

impl Smb2AllocHeader {
    /// Creates the root allocation header with a zeroed caller payload.
    #[must_use]
    pub fn zeroed(size: usize) -> Self {
        Self {
            mem: None,
            buf: vec![0; size],
        }
    }

    /// Returns the first child allocation linked to this header.
    #[must_use]
    pub const fn first_allocation(&self) -> Option<Smb2AllocHandle> {
        self.mem
    }

    /// Returns the immutable root payload bytes.
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        &self.buf
    }

    /// Returns the mutable root payload bytes.
    #[must_use]
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.buf
    }
}

/// Memory arena used to preserve C allocation lifetimes during migration.
#[derive(Debug, Default)]
pub struct Arena {
    header: Option<Smb2AllocHeader>,
    allocations: Vec<Smb2AllocEntry>,
}

impl Arena {
    /// Creates an empty arena with no initialized root allocation.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Mirrors `smb2_alloc_init` by creating the zeroed root allocation.
    pub fn smb2_alloc_init(&mut self, size: usize) -> &mut [u8] {
        self.allocations.clear();
        self.header = Some(Smb2AllocHeader::zeroed(size));
        self.header_payload_mut()
    }

    /// Mirrors `smb2_alloc_data` by linking a zeroed child allocation.
    pub fn smb2_alloc_data(&mut self, size: usize) -> Option<Smb2AllocHandle> {
        let header = self.header.as_mut()?;
        let handle = Smb2AllocHandle {
            index: self.allocations.len(),
        };
        let mut entry = Smb2AllocEntry::zeroed(size);
        entry.next = header.mem;
        header.mem = Some(handle);
        self.allocations.push(entry);
        Some(handle)
    }

    /// Mirrors `smb2_free_data` by releasing the root and child allocations.
    pub fn smb2_free_data(&mut self) {
        self.allocations.clear();
        self.header = None;
    }

    /// Allocates zeroed bytes owned by the arena and returns the allocation index.
    #[must_use]
    pub fn alloc_zeroed(&mut self, size: usize) -> usize {
        match self.smb2_alloc_data(size) {
            Some(handle) => handle.index(),
            None => {
                self.smb2_alloc_init(0);
                match self.smb2_alloc_data(size) {
                    Some(handle) => handle.index(),
                    None => 0,
                }
            }
        }
    }

    /// Returns the current root allocation header.
    #[must_use]
    pub fn header(&self) -> Option<&Smb2AllocHeader> {
        self.header.as_ref()
    }

    /// Returns a child allocation by handle.
    #[must_use]
    pub fn allocation(&self, handle: Smb2AllocHandle) -> Option<&Smb2AllocEntry> {
        self.allocations.get(handle.index)
    }

    /// Returns a mutable child allocation by handle.
    #[must_use]
    pub fn allocation_mut(&mut self, handle: Smb2AllocHandle) -> Option<&mut Smb2AllocEntry> {
        self.allocations.get_mut(handle.index)
    }

    /// Returns the number of child allocations linked to this arena.
    #[must_use]
    pub fn allocation_count(&self) -> usize {
        self.allocations.len()
    }

    fn header_payload_mut(&mut self) -> &mut [u8] {
        match self.header.as_mut() {
            Some(header) => header.as_mut_slice(),
            None => &mut [],
        }
    }
}
