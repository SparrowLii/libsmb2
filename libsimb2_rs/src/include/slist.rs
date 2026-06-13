//! Safe Rust skeleton for the singly-linked list helpers in `include/slist.h`.
//!
//! The C header provides intrusive macros that expect each item to expose a
//! mutable `next` field. This module intentionally does not reproduce that macro
//! pattern. Instead, it offers a small owned list wrapper that mirrors the macro
//! responsibilities: add at the front, add at the end, remove an item, and report
//! length.

use std::collections::LinkedList;

/// Owned, safe counterpart for the `SMB2_LIST_*` helper macros.
///
/// `Smb2SList` keeps ownership of inserted values and does not require values to
/// contain a public `next` pointer. This makes it suitable as a migration
/// skeleton for Rust code that needs list-like behavior without adopting the C
/// header's intrusive representation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Smb2SList<T> {
    entries: LinkedList<T>,
}

impl<T> Smb2SList<T> {
    /// Creates an empty list.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            entries: LinkedList::new(),
        }
    }

    /// Adds `item` to the front of the list.
    ///
    /// This is the safe owned equivalent of `SMB2_LIST_ADD`.
    pub fn add(&mut self, item: T) {
        self.entries.push_front(item);
    }

    /// Adds `item` to the end of the list.
    ///
    /// This is the safe owned equivalent of `SMB2_LIST_ADD_END`.
    pub fn add_end(&mut self, item: T) {
        self.entries.push_back(item);
    }

    /// Removes and returns the first item that matches `predicate`.
    ///
    /// This mirrors the role of `SMB2_LIST_REMOVE` without exposing pointer
    /// identity or requiring an intrusive `next` field.
    pub fn remove_first_by(&mut self, mut predicate: impl FnMut(&T) -> bool) -> Option<T> {
        let original_len = self.entries.len();
        let mut removed = None;

        for _ in 0..original_len {
            if let Some(item) = self.entries.pop_front() {
                if removed.is_none() && predicate(&item) {
                    removed = Some(item);
                } else {
                    self.entries.push_back(item);
                }
            }
        }

        removed
    }

    /// Removes and returns the first item equal to `item`.
    ///
    /// Equality-based removal is a safe approximation of the C macro's pointer
    /// identity removal and is intended for non-intrusive Rust callers.
    pub fn remove_first(&mut self, item: &T) -> Option<T>
    where
        T: PartialEq,
    {
        self.remove_first_by(|candidate| candidate == item)
    }

    /// Removes and returns the first item in the list.
    #[must_use]
    pub fn pop_front(&mut self) -> Option<T> {
        self.entries.pop_front()
    }

    /// Returns the number of items currently in the list.
    ///
    /// This is the safe owned equivalent of `SMB2_LIST_LENGTH`.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns `true` when the list contains no items.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Returns an iterator over list items from head to tail.
    pub fn iter(&self) -> impl Iterator<Item = &T> {
        self.entries.iter()
    }

    /// Removes all items from the list.
    pub fn clear(&mut self) {
        self.entries.clear();
    }
}

impl<T> Default for Smb2SList<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> FromIterator<T> for Smb2SList<T> {
    fn from_iter<I: IntoIterator<Item = T>>(iter: I) -> Self {
        Self {
            entries: iter.into_iter().collect(),
        }
    }
}

impl<T> Extend<T> for Smb2SList<T> {
    fn extend<I: IntoIterator<Item = T>>(&mut self, iter: I) {
        self.entries.extend(iter);
    }
}
