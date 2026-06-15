//! Rust counterparts for headers under `include/smb2/`.

pub mod libsmb2;
#[path = "libsmb2-dcerpc.rs"]
pub mod libsmb2_dcerpc;
#[path = "libsmb2-dcerpc-lsa.rs"]
pub mod libsmb2_dcerpc_lsa;
#[path = "libsmb2-dcerpc-srvsvc.rs"]
pub mod libsmb2_dcerpc_srvsvc;
/// Pure-Rust DCERPC NDR coder facade (matches the C `libsmb2-dcerpc` coder API).
pub mod dcerpc_coder;
/// Pure-Rust LSA coder facade.
pub mod dcerpc_coder_lsa;
/// Pure-Rust srvsvc coder facade.
pub mod dcerpc_coder_srvsvc;
#[path = "libsmb2-raw.rs"]
pub mod libsmb2_raw;
#[path = "smb2.rs"]
pub mod protocol;
#[path = "smb2-errors.rs"]
pub mod smb2_errors;
#[path = "smb2-ioctl.rs"]
pub mod smb2_ioctl;

pub use protocol as smb2;
