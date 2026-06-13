mod ffi {
    #![allow(
        dead_code,
        non_camel_case_types,
        non_snake_case,
        non_upper_case_globals
    )]
    include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
}

pub struct SListNode {
    raw: ffi::slist_ffi_node,
}

impl SListNode {
    pub fn new() -> Self {
        Self {
            raw: ffi::slist_ffi_node {
                next: std::ptr::null_mut(),
            },
        }
    }

    pub fn next_is(&self, other: Option<&Self>) -> bool {
        self.raw.next == other.map_or(std::ptr::null_mut(), Self::as_ptr)
    }

    fn as_ptr(&self) -> *mut ffi::slist_ffi_node {
        std::ptr::from_ref(&self.raw).cast_mut()
    }
}

impl Default for SListNode {
    fn default() -> Self {
        Self::new()
    }
}

pub struct SListHead {
    head: *mut ffi::slist_ffi_node,
}

impl SListHead {
    pub fn empty() -> Self {
        Self {
            head: std::ptr::null_mut(),
        }
    }

    pub fn from_head(head: &mut SListNode) -> Self {
        Self {
            head: head.as_ptr(),
        }
    }

    pub fn head_is(&self, node: Option<&SListNode>) -> bool {
        self.head == node.map_or(std::ptr::null_mut(), SListNode::as_ptr)
    }

    pub fn add(&mut self, item: &mut SListNode) {
        unsafe { ffi::slist_ffi_add(&mut self.head, item.as_ptr()) }
    }

    pub fn add_end(&mut self, item: &mut SListNode) {
        unsafe { ffi::slist_ffi_add_end(&mut self.head, item.as_ptr()) }
    }

    pub fn remove(&mut self, item: &mut SListNode) {
        unsafe { ffi::slist_ffi_remove(&mut self.head, item.as_ptr()) }
    }

    pub fn len(&mut self) -> usize {
        unsafe { ffi::slist_ffi_length(&mut self.head) }
    }

    pub fn is_empty(&mut self) -> bool {
        self.len() == 0
    }
}

impl Default for SListHead {
    fn default() -> Self {
        Self::empty()
    }
}
