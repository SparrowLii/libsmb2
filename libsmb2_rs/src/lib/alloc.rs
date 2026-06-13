//! Allocation ownership model migrated from `lib/alloc.c`.
//!
//! The C implementation returns a caller-visible pointer inside an allocation
//! header and links child allocations to that header. This Rust skeleton keeps
//! the same ownership shape without exposing raw pointer arithmetic.

use std::any::Any;

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

/// Stable handle for a typed Rust value owned by an [`Arena`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Smb2OwnedHandle {
    index: usize,
}

impl Smb2OwnedHandle {
    /// Returns the arena-local owned allocation index represented by this handle.
    #[must_use]
    pub const fn index(self) -> usize {
        self.index
    }
}

struct Smb2OwnedAllocation {
    value: Box<dyn Any>,
}

impl core::fmt::Debug for Smb2OwnedAllocation {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Smb2OwnedAllocation")
            .finish_non_exhaustive()
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
    owned: Vec<Smb2OwnedAllocation>,
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
        self.owned.clear();
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
        self.owned.clear();
        self.header = None;
    }

    /// Allocates zeroed bytes owned by the arena and returns the allocation index.
    #[must_use]
    pub fn alloc_zeroed(&mut self, size: usize) -> usize {
        self.ensure_initialized();
        match self.smb2_alloc_data(size) {
            Some(handle) => handle.index(),
            None => 0,
        }
    }

    /// Stores a typed Rust value under the arena lifetime and returns its handle.
    pub fn alloc_owned<T: 'static>(&mut self, value: T) -> Smb2OwnedHandle {
        self.ensure_initialized();
        let handle = Smb2OwnedHandle {
            index: self.owned.len(),
        };
        self.owned.push(Smb2OwnedAllocation {
            value: Box::new(value),
        });
        handle
    }

    /// Returns a typed Rust-owned allocation by handle.
    #[must_use]
    pub fn owned<T: 'static>(&self, handle: Smb2OwnedHandle) -> Option<&T> {
        self.owned.get(handle.index)?.value.downcast_ref()
    }

    /// Returns a mutable typed Rust-owned allocation by handle.
    #[must_use]
    pub fn owned_mut<T: 'static>(&mut self, handle: Smb2OwnedHandle) -> Option<&mut T> {
        self.owned.get_mut(handle.index)?.value.downcast_mut()
    }

    /// Returns the number of typed Rust-owned allocations in this arena.
    #[must_use]
    pub fn owned_count(&self) -> usize {
        self.owned.len()
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

    /// Returns true when the arena has an initialized root allocation.
    #[must_use]
    pub fn is_initialized(&self) -> bool {
        self.header.is_some()
    }

    fn ensure_initialized(&mut self) {
        if self.header.is_none() {
            self.smb2_alloc_init(0);
        }
    }

    fn header_payload_mut(&mut self) -> &mut [u8] {
        match self.header.as_mut() {
            Some(header) => header.as_mut_slice(),
            None => &mut [],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Arena;

    #[test]
    fn owned_allocations_follow_arena_lifetime() {
        let mut arena = Arena::new();
        let handle = arena.alloc_owned(String::from("secret"));

        assert!(arena.is_initialized());
        assert_eq!(arena.owned_count(), 1);
        assert_eq!(
            arena.owned::<String>(handle).map(String::as_str),
            Some("secret")
        );

        arena.smb2_free_data();
        assert!(!arena.is_initialized());
        assert_eq!(arena.owned_count(), 0);
        assert!(arena.owned::<String>(handle).is_none());
    }

    #[test]
    fn byte_allocations_are_linked_to_root() {
        let mut arena = Arena::new();
        let first = arena.smb2_alloc_data(4);
        assert!(first.is_none());

        arena.smb2_alloc_init(2);
        let first = arena
            .smb2_alloc_data(4)
            .expect("initialized arena allocates");
        let second = arena
            .smb2_alloc_data(8)
            .expect("initialized arena allocates");

        assert_eq!(arena.allocation_count(), 2);
        assert_eq!(
            arena.header().and_then(|header| header.first_allocation()),
            Some(second)
        );
        assert_eq!(
            arena.allocation(second).and_then(|entry| entry.next()),
            Some(first)
        );
    }
}
