//! SMB2 protocol constants, command ids, and packet data skeletons.
//!
//! This module mirrors the public responsibilities of `include/smb2/smb2.h` for
//! Rust callers. It intentionally models data carried by SMB2 requests and
//! replies without implementing wire encoding, decoding, transport, or complete
//! protocol behavior.

/// SMB2 protocol id bytes used in packet headers.
pub const SMB2_PROTOCOL_ID: [u8; 4] = [0xFE, b'S', b'M', b'B'];

/// Number of bytes in an SMB2 GUID.
pub const SMB2_GUID_SIZE: usize = 16;
/// Number of bytes in an SMB2 file id.
pub const SMB2_FD_SIZE: usize = 16;
/// Number of bytes in an SMB2 lease key.
pub const SMB2_LEASE_KEY_SIZE: usize = 16;
/// Number of bytes in an SMB2 ACE object type GUID.
pub const SMB2_OBJECT_TYPE_SIZE: usize = 16;
/// Number of bytes in a SID identifier authority.
pub const SID_ID_AUTH_LEN: usize = 6;
/// Maximum number of dialects carried by the fixed negotiate request skeleton.
pub const SMB2_NEGOTIATE_MAX_DIALECTS: usize = 10;

/// SMB2 GUID bytes.
pub type Smb2Guid = [u8; SMB2_GUID_SIZE];
/// SMB2 file id bytes.
pub type Smb2FileId = [u8; SMB2_FD_SIZE];
/// SMB2 lease key bytes.
pub type Smb2LeaseKey = [u8; SMB2_LEASE_KEY_SIZE];

/// Size of an SMB2 error reply structure on the wire.
pub const SMB2_ERROR_REPLY_SIZE: u16 = 9;
/// SMB2 header flag: server-to-redirector packet.
pub const SMB2_FLAGS_SERVER_TO_REDIR: u32 = 0x0000_0001;
/// SMB2 header flag: asynchronous command.
pub const SMB2_FLAGS_ASYNC_COMMAND: u32 = 0x0000_0002;
/// SMB2 header flag: related operation.
pub const SMB2_FLAGS_RELATED_OPERATIONS: u32 = 0x0000_0004;
/// SMB2 header flag: signed packet.
pub const SMB2_FLAGS_SIGNED: u32 = 0x0000_0008;
/// SMB2 header flag mask for priority bits.
pub const SMB2_FLAGS_PRIORITY_MASK: u32 = 0x0000_0070;
/// SMB2 header flag: DFS operation.
pub const SMB2_FLAGS_DFS_OPERATIONS: u32 = 0x1000_0000;
/// SMB2 header flag: replay operation.
pub const SMB2_FLAGS_REPLAY_OPERATION: u32 = 0x2000_0000;

/// SMB2 NEGOTIATE signing mode: signing enabled.
pub const SMB2_NEGOTIATE_SIGNING_ENABLED: u16 = 0x0001;
/// SMB2 NEGOTIATE signing mode: signing required.
pub const SMB2_NEGOTIATE_SIGNING_REQUIRED: u16 = 0x0002;
/// Global capability: DFS.
pub const SMB2_GLOBAL_CAP_DFS: u32 = 0x0000_0001;
/// Global capability: leasing.
pub const SMB2_GLOBAL_CAP_LEASING: u32 = 0x0000_0002;
/// Global capability: large MTU.
pub const SMB2_GLOBAL_CAP_LARGE_MTU: u32 = 0x0000_0004;
/// Global capability: multi-channel.
pub const SMB2_GLOBAL_CAP_MULTI_CHANNEL: u32 = 0x0000_0008;
/// Global capability: persistent handles.
pub const SMB2_GLOBAL_CAP_PERSISTENT_HANDLES: u32 = 0x0000_0010;
/// Global capability: directory leasing.
pub const SMB2_GLOBAL_CAP_DIRECTORY_LEASING: u32 = 0x0000_0020;
/// Global capability: encryption.
pub const SMB2_GLOBAL_CAP_ENCRYPTION: u32 = 0x0000_0040;
/// Session setup legacy capability bit 1.
pub const SMB2_GLOBAL_CAP_UNUSED1: u32 = 0x0000_0002;
/// Session setup legacy capability bit 2.
pub const SMB2_GLOBAL_CAP_UNUSED2: u32 = 0x0000_0004;
/// Session setup legacy capability bit 4.
pub const SMB2_GLOBAL_CAP_UNUSED4: u32 = 0x0000_0008;
/// Negotiate context type: pre-auth integrity capabilities.
pub const SMB2_PREAUTH_INTEGRITY_CAP: u16 = 0x0001;
/// Negotiate context type: encryption capabilities.
pub const SMB2_ENCRYPTION_CAP: u16 = 0x0002;
/// Negotiate context type: compression capabilities.
pub const SMB2_COMPRESSION_CAP: u16 = 0x0003;
/// Negotiate context type: netname.
pub const SMB2_NETNAME_NEGOTIATE_CONTEXT_ID: u16 = 0x0005;
/// Negotiate context type: transport capabilities.
pub const SMB2_TRANSPORT_CAP: u16 = 0x0006;
/// Negotiate context type: RDMA transform capabilities.
pub const SMB2_RDMA_TRANSFORM_CAP: u16 = 0x0007;
/// Negotiate context type: signing capabilities.
pub const SMB2_SIGNING_CAP: u16 = 0x0008;
/// Reserved negotiate context type.
pub const SMB2_CONTEXTTYPE_RESERVED: u16 = 0x0100;
/// Pre-auth hash id: SHA-512.
pub const SMB2_HASH_SHA_512: u16 = 0x0001;
/// Pre-auth hash output size.
pub const SMB2_PREAUTH_HASH_SIZE: usize = 64;
/// Encryption cipher id: AES-128-CCM.
pub const SMB2_ENCRYPTION_AES_128_CCM: u16 = 0x0001;
/// Encryption cipher id: AES-128-GCM.
pub const SMB2_ENCRYPTION_AES_128_GCM: u16 = 0x0002;
/// Legacy encryption cipher id: AES-128-CCM.
pub const SMB_ENCRYPTION_AES128_CCM: u16 = 0x0001;
/// Wire size of an SMB2 NEGOTIATE request.
pub const SMB2_NEGOTIATE_REQUEST_SIZE: u16 = 36;
/// Wire size of an SMB2 NEGOTIATE reply.
pub const SMB2_NEGOTIATE_REPLY_SIZE: u16 = 65;

/// Session setup request flag: bind to an existing session.
pub const SMB2_SESSION_FLAG_BINDING: u8 = 0x01;
/// Wire size of an SMB2 SESSION_SETUP request.
pub const SMB2_SESSION_SETUP_REQUEST_SIZE: u16 = 25;
/// Session reply flag: guest session.
pub const SMB2_SESSION_FLAG_IS_GUEST: u16 = 0x0001;
/// Session reply flag: null session.
pub const SMB2_SESSION_FLAG_IS_NULL: u16 = 0x0002;
/// Session reply flag: encrypted data required.
pub const SMB2_SESSION_FLAG_IS_ENCRYPT_DATA: u16 = 0x0004;
/// Wire size of an SMB2 SESSION_SETUP reply.
pub const SMB2_SESSION_SETUP_REPLY_SIZE: u16 = 9;

/// Wire size of an SMB2 TREE_CONNECT request.
pub const SMB2_TREE_CONNECT_REQUEST_SIZE: u16 = 9;
/// Tree connect flag: cluster reconnect.
pub const SMB2_SHAREFLAG_CLUSTER_RECONNECT: u16 = 0x0001;
/// Share type: disk.
pub const SMB2_SHARE_TYPE_DISK: u8 = 0x01;
/// Share type: pipe.
pub const SMB2_SHARE_TYPE_PIPE: u8 = 0x02;
/// Share type: print.
pub const SMB2_SHARE_TYPE_PRINT: u8 = 0x03;
/// Share flag: manual caching.
pub const SMB2_SHAREFLAG_MANUAL_CACHING: u32 = 0x0000_0000;
/// Share flag: DFS.
pub const SMB2_SHAREFLAG_DFS: u32 = 0x0000_0001;
/// Share flag: DFS root.
pub const SMB2_SHAREFLAG_DFS_ROOT: u32 = 0x0000_0002;
/// Share flag: auto caching.
pub const SMB2_SHAREFLAG_AUTO_CACHING: u32 = 0x0000_0010;
/// Share flag: VDO caching.
pub const SMB2_SHAREFLAG_VDO_CACHING: u32 = 0x0000_0020;
/// Share flag: no caching.
pub const SMB2_SHAREFLAG_NO_CACHING: u32 = 0x0000_0030;
/// Share flag: restrict exclusive opens.
pub const SMB2_SHAREFLAG_RESTRICT_EXCLUSIVE_OPENS: u32 = 0x0000_0100;
/// Share flag: force shared delete.
pub const SMB2_SHAREFLAG_FORCE_SHARED_DELETE: u32 = 0x0000_0200;
/// Share flag: allow namespace caching.
pub const SMB2_SHAREFLAG_ALLOW_NAMESPACE_CACHING: u32 = 0x0000_0400;
/// Share flag: access-based directory enumeration.
pub const SMB2_SHAREFLAG_ACCESS_BASED_DIRECTORY_ENUM: u32 = 0x0000_0800;
/// Share flag: force level II oplock.
pub const SMB2_SHAREFLAG_FORCE_LEVELII_OPLOCK: u32 = 0x0000_1000;
/// Share flag: enable hash v1.
pub const SMB2_SHAREFLAG_ENABLE_HASH_V1: u32 = 0x0000_2000;
/// Share flag: enable hash v2.
pub const SMB2_SHAREFLAG_ENABLE_HASH_V2: u32 = 0x0000_4000;
/// Share flag: encrypt data.
pub const SMB2_SHAREFLAG_ENCRYPT_DATA: u32 = 0x0000_8000;
/// Share capability: DFS.
pub const SMB2_SHARE_CAP_DFS: u32 = 0x0000_0008;
/// Share capability: continuous availability.
pub const SMB2_SHARE_CAP_CONTINUOUS_AVAILABILITY: u32 = 0x0000_0010;
/// Share capability: scaleout.
pub const SMB2_SHARE_CAP_SCALEOUT: u32 = 0x0000_0020;
/// Share capability: cluster.
pub const SMB2_SHARE_CAP_CLUSTER: u32 = 0x0000_0040;
/// Share capability: asymmetric.
pub const SMB2_SHARE_CAP_ASYMMETRIC: u32 = 0x0000_0080;
/// Wire size of an SMB2 TREE_CONNECT reply.
pub const SMB2_TREE_CONNECT_REPLY_SIZE: u16 = 16;

/// Wire size of an SMB2 CREATE request.
pub const SMB2_CREATE_REQUEST_SIZE: u16 = 57;
/// Oplock level: none.
pub const SMB2_OPLOCK_LEVEL_NONE: u8 = 0x00;
/// Oplock level: level II.
pub const SMB2_OPLOCK_LEVEL_II: u8 = 0x01;
/// Oplock level: exclusive.
pub const SMB2_OPLOCK_LEVEL_EXCLUSIVE: u8 = 0x08;
/// Oplock level: batch.
pub const SMB2_OPLOCK_LEVEL_BATCH: u8 = 0x09;
/// Oplock level: lease.
pub const SMB2_OPLOCK_LEVEL_LEASE: u8 = 0xFF;
/// Wire size of a create lease context.
pub const SMB2_CREATE_REQUEST_LEASE_SIZE: u16 = 32;
/// Impersonation level: anonymous.
pub const SMB2_IMPERSONATION_ANONYMOUS: u32 = 0x0000_0000;
/// Impersonation level: identification.
pub const SMB2_IMPERSONATION_IDENTIFICATION: u32 = 0x0000_0001;
/// Impersonation level: impersonation.
pub const SMB2_IMPERSONATION_IMPERSONATION: u32 = 0x0000_0002;
/// Impersonation level: delegate.
pub const SMB2_IMPERSONATION_DELEGATE: u32 = 0x0000_0003;

/// Access mask common to all object types: read extended attributes.
pub const SMB2_FILE_READ_EA: u32 = 0x0000_0008;
/// Access mask common to all object types: write extended attributes.
pub const SMB2_FILE_WRITE_EA: u32 = 0x0000_0010;
/// Access mask common to all object types: delete child.
pub const SMB2_FILE_DELETE_CHILD: u32 = 0x0000_0040;
/// Access mask common to all object types: read attributes.
pub const SMB2_FILE_READ_ATTRIBUTES: u32 = 0x0000_0080;
/// Access mask common to all object types: write attributes.
pub const SMB2_FILE_WRITE_ATTRIBUTES: u32 = 0x0000_0100;
/// Access mask: delete.
pub const SMB2_DELETE: u32 = 0x0001_0000;
/// Access mask: read control.
pub const SMB2_READ_CONTROL: u32 = 0x0002_0000;
/// Access mask: write DACL.
pub const SMB2_WRITE_DACL: u32 = 0x0004_0000;
/// Access mask: write owner.
pub const SMB2_WRITE_OWNER: u32 = 0x0008_0000;
/// Access mask: synchronize.
pub const SMB2_SYNCHRONIZE: u32 = 0x0010_0000;
/// Access mask: access system security.
pub const SMB2_ACCESS_SYSTEM_SECURITY: u32 = 0x0100_0000;
/// Access mask: maximum allowed.
pub const SMB2_MAXIMUM_ALLOWED: u32 = 0x0200_0000;
/// Access mask: generic all.
pub const SMB2_GENERIC_ALL: u32 = 0x1000_0000;
/// Access mask: generic execute.
pub const SMB2_GENERIC_EXECUTE: u32 = 0x2000_0000;
/// Access mask: generic write.
pub const SMB2_GENERIC_WRITE: u32 = 0x4000_0000;
/// Access mask: generic read.
pub const SMB2_GENERIC_READ: u32 = 0x8000_0000;
/// Access mask for files, pipes, and printers: read data.
pub const SMB2_FILE_READ_DATA: u32 = 0x0000_0001;
/// Access mask for files, pipes, and printers: write data.
pub const SMB2_FILE_WRITE_DATA: u32 = 0x0000_0002;
/// Access mask for files, pipes, and printers: append data.
pub const SMB2_FILE_APPEND_DATA: u32 = 0x0000_0004;
/// Access mask for files, pipes, and printers: execute.
pub const SMB2_FILE_EXECUTE: u32 = 0x0000_0020;
/// Access mask for directories: list directory.
pub const SMB2_FILE_LIST_DIRECTORY: u32 = 0x0000_0001;
/// Access mask for directories: add file.
pub const SMB2_FILE_ADD_FILE: u32 = 0x0000_0002;
/// Access mask for directories: add subdirectory.
pub const SMB2_FILE_ADD_SUBDIRECTORY: u32 = 0x0000_0004;
/// Access mask for directories: traverse.
pub const SMB2_FILE_TRAVERSE: u32 = 0x0000_0020;

/// File attribute: readonly.
pub const SMB2_FILE_ATTRIBUTE_READONLY: u32 = 0x0000_0001;
/// File attribute: hidden.
pub const SMB2_FILE_ATTRIBUTE_HIDDEN: u32 = 0x0000_0002;
/// File attribute: system.
pub const SMB2_FILE_ATTRIBUTE_SYSTEM: u32 = 0x0000_0004;
/// File attribute: directory.
pub const SMB2_FILE_ATTRIBUTE_DIRECTORY: u32 = 0x0000_0010;
/// File attribute: archive.
pub const SMB2_FILE_ATTRIBUTE_ARCHIVE: u32 = 0x0000_0020;
/// File attribute: normal.
pub const SMB2_FILE_ATTRIBUTE_NORMAL: u32 = 0x0000_0080;
/// File attribute: temporary.
pub const SMB2_FILE_ATTRIBUTE_TEMPORARY: u32 = 0x0000_0100;
/// File attribute: sparse file.
pub const SMB2_FILE_ATTRIBUTE_SPARSE_FILE: u32 = 0x0000_0200;
/// File attribute: reparse point.
pub const SMB2_FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
/// File attribute: compressed.
pub const SMB2_FILE_ATTRIBUTE_COMPRESSED: u32 = 0x0000_0800;
/// File attribute: offline.
pub const SMB2_FILE_ATTRIBUTE_OFFLINE: u32 = 0x0000_1000;
/// File attribute: not content indexed.
pub const SMB2_FILE_ATTRIBUTE_NOT_CONTENT_INDEXED: u32 = 0x0000_2000;
/// File attribute: encrypted.
pub const SMB2_FILE_ATTRIBUTE_ENCRYPTED: u32 = 0x0000_4000;
/// File attribute: integrity stream.
pub const SMB2_FILE_ATTRIBUTE_INTEGRITY_STREAM: u32 = 0x0000_8000;
/// File attribute: no scrub data.
pub const SMB2_FILE_ATTRIBUTE_NO_SCRUB_DATA: u32 = 0x0002_0000;
/// Share access: read.
pub const SMB2_FILE_SHARE_READ: u32 = 0x0000_0001;
/// Share access: write.
pub const SMB2_FILE_SHARE_WRITE: u32 = 0x0000_0002;
/// Share access: delete.
pub const SMB2_FILE_SHARE_DELETE: u32 = 0x0000_0004;
/// Create disposition: supersede.
pub const SMB2_FILE_SUPERSEDE: u32 = 0x0000_0000;
/// Create disposition: open.
pub const SMB2_FILE_OPEN: u32 = 0x0000_0001;
/// Create disposition: create.
pub const SMB2_FILE_CREATE: u32 = 0x0000_0002;
/// Create disposition: open if exists.
pub const SMB2_FILE_OPEN_IF: u32 = 0x0000_0003;
/// Create disposition: overwrite.
pub const SMB2_FILE_OVERWRITE: u32 = 0x0000_0004;
/// Create disposition: overwrite if exists.
pub const SMB2_FILE_OVERWRITE_IF: u32 = 0x0000_0005;
/// Create option: directory file.
pub const SMB2_FILE_DIRECTORY_FILE: u32 = 0x0000_0001;
/// Create option: write through.
pub const SMB2_FILE_WRITE_THROUGH: u32 = 0x0000_0002;
/// Create option: sequential only.
pub const SMB2_FILE_SEQUENTIAL_ONLY: u32 = 0x0000_0004;
/// Create option: no intermediate buffering.
pub const SMB2_FILE_NO_INTERMEDIATE_BUFFERING: u32 = 0x0000_0008;
/// Create option: synchronous I/O alert.
pub const SMB2_FILE_SYNCHRONOUS_IO_ALERT: u32 = 0x0000_0010;
/// Create option: synchronous I/O non-alert.
pub const SMB2_FILE_SYNCHRONOUS_IO_NONALERT: u32 = 0x0000_0020;
/// Create option: non-directory file.
pub const SMB2_FILE_NON_DIRECTORY_FILE: u32 = 0x0000_0040;
/// Create option: complete if oplocked.
pub const SMB2_FILE_COMPLETE_IF_OPLOCKED: u32 = 0x0000_0100;
/// Create option: no EA knowledge.
pub const SMB2_FILE_NO_EA_KNOWLEDGE: u32 = 0x0000_0200;
/// Create option: open remote instance.
pub const SMB2_FILE_OPEN_REMOTE_INSTANCE: u32 = 0x0000_0400;
/// Create option: random access.
pub const SMB2_FILE_RANDOM_ACCESS: u32 = 0x0000_0800;
/// Create option: delete on close.
pub const SMB2_FILE_DELETE_ON_CLOSE: u32 = 0x0000_1000;
/// Create option: open by file id.
pub const SMB2_FILE_OPEN_BY_FILE_ID: u32 = 0x0000_2000;
/// Create option: open for backup intent.
pub const SMB2_FILE_OPEN_FOR_BACKUP_INTENT: u32 = 0x0000_4000;
/// Create option: no compression.
pub const SMB2_FILE_NO_COMPRESSION: u32 = 0x0000_8000;
/// Create option: open requiring oplock.
pub const SMB2_FILE_OPEN_REQUIRING_OPLOCK: u32 = 0x0001_0000;
/// Create option: disallow exclusive.
pub const SMB2_FILE_DISALLOW_EXCLUSIVE: u32 = 0x0002_0000;
/// Create option: reserve opfilter.
pub const SMB2_FILE_RESERVE_OPFILTER: u32 = 0x0010_0000;
/// Create option: open reparse point.
pub const SMB2_FILE_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
/// Create option: open no recall.
pub const SMB2_FILE_OPEN_NO_RECALL: u32 = 0x0040_0000;
/// Create option: open for free space query.
pub const SMB2_FILE_OPEN_FOR_FREE_SPACE_QUERY: u32 = 0x0080_0000;
/// Wire size of an SMB2 CREATE reply.
pub const SMB2_CREATE_REPLY_SIZE: u16 = 89;
/// Wire size of an SMB2 CLOSE request.
pub const SMB2_CLOSE_REQUEST_SIZE: u16 = 24;
/// Close flag: post-query attributes.
pub const SMB2_CLOSE_FLAG_POSTQUERY_ATTRIB: u16 = 0x0001;
/// Wire size of an SMB2 CLOSE reply.
pub const SMB2_CLOSE_REPLY_SIZE: u16 = 60;
/// Wire size of an SMB2 FLUSH request.
pub const SMB2_FLUSH_REQUEST_SIZE: u16 = 24;
/// Wire size of an SMB2 FLUSH reply.
pub const SMB2_FLUSH_REPLY_SIZE: u16 = 4;
/// Misspelled legacy logoff request size macro preserved from the C header.
pub const SMB2_LOGFF_REQUEST_SIZE: u16 = 4;
/// Wire size of an SMB2 LOGOFF request.
pub const SMB2_LOGOFF_REQUEST_SIZE: u16 = 4;
/// Wire size of an SMB2 LOGOFF reply.
pub const SMB2_LOGOFF_REPLY_SIZE: u16 = 4;
/// Wire size of an SMB2 ECHO request.
pub const SMB2_ECHO_REQUEST_SIZE: u16 = 4;
/// Wire size of an SMB2 ECHO reply.
pub const SMB2_ECHO_REPLY_SIZE: u16 = 4;
/// Wire size of an SMB2 CANCEL request.
pub const SMB2_CANCEL_REQUEST_SIZE: u16 = 4;
/// Wire size of an SMB2 TREE_DISCONNECT request.
pub const SMB2_TREE_DISCONNECT_REQUEST_SIZE: u16 = 4;
/// Wire size of an SMB2 TREE_DISCONNECT reply.
pub const SMB2_TREE_DISCONNECT_REPLY_SIZE: u16 = 4;

/// File information class: directory information.
pub const SMB2_FILE_DIRECTORY_INFORMATION: u8 = 0x01;
/// File information class: full directory information.
pub const SMB2_FILE_FULL_DIRECTORY_INFORMATION: u8 = 0x02;
/// File information class: both directory information.
pub const SMB2_FILE_BOTH_DIRECTORY_INFORMATION: u8 = 0x03;
/// File information class: basic information.
pub const SMB2_FILE_BASIC_INFORMATION: u8 = 0x04;
/// File information class: standard information.
pub const SMB2_FILE_STANDARD_INFORMATION: u8 = 0x05;
/// File information class: internal information.
pub const SMB2_FILE_INTERNAL_INFORMATION: u8 = 0x06;
/// File information class: EA information.
pub const SMB2_FILE_EA_INFORMATION: u8 = 0x07;
/// File information class: access information.
pub const SMB2_FILE_ACCESS_INFORMATION: u8 = 0x08;
/// File information class: name information.
pub const SMB2_FILE_NAME_INFORMATION: u8 = 0x09;
/// File information class: rename information.
pub const SMB2_FILE_RENAME_INFORMATION: u8 = 0x0A;
/// File information class: link information.
pub const SMB2_FILE_LINK_INFORMATION: u8 = 0x0B;
/// File information class: names information.
pub const SMB2_FILE_NAMES_INFORMATION: u8 = 0x0C;
/// File information class: disposition information.
pub const SMB2_FILE_DISPOSITION_INFORMATION: u8 = 0x0D;
/// File information class: position information.
pub const SMB2_FILE_POSITION_INFORMATION: u8 = 0x0E;
/// File information class: full EA information.
pub const SMB2_FILE_FULL_EA_INFORMATION: u8 = 0x0F;
/// File information class: mode information.
pub const SMB2_FILE_MODE_INFORMATION: u8 = 0x10;
/// File information class: alignment information.
pub const SMB2_FILE_ALIGNMENT_INFORMATION: u8 = 0x11;
/// File information class: all information.
pub const SMB2_FILE_ALL_INFORMATION: u8 = 0x12;
/// File information class: allocation information.
pub const SMB2_FILE_ALLOCATION_INFORMATION: u8 = 0x13;
/// File information class: end-of-file information.
pub const SMB2_FILE_END_OF_FILE_INFORMATION: u8 = 0x14;
/// File information class: alternate name information.
pub const SMB2_FILE_ALTERNATE_NAME_INFORMATION: u8 = 0x15;
/// File information class: stream information.
pub const SMB2_FILE_STREAM_INFORMATION: u8 = 0x16;
/// File information class: pipe information.
pub const SMB2_FILE_PIPE_INFORMATION: u8 = 0x17;
/// File information class: pipe local information.
pub const SMB2_FILE_PIPE_LOCAL_INFORMATION: u8 = 0x18;
/// File information class: pipe remote information.
pub const SMB2_FILE_PIPE_REMOTE_INFORMATION: u8 = 0x19;
/// File information class: mailslot query information.
pub const SMB2_FILE_MAILSLOT_QUERY_INFORMATION: u8 = 0x1A;
/// File information class: mailslot set information.
pub const SMB2_FILE_MAILSLOT_SET_INFORMATION: u8 = 0x1B;
/// File information class: compression information.
pub const SMB2_FILE_COMPRESSION_INFORMATION: u8 = 0x1C;
/// File information class: object id information.
pub const SMB2_FILE_OBJECT_ID_INFORMATION: u8 = 0x1D;
/// File information class: quota information.
pub const SMB2_FILE_QUOTA_INFORMATION: u8 = 0x20;
/// File information class: reparse point information.
pub const SMB2_FILE_REPARSE_POINT_INFORMATION: u8 = 0x21;
/// File information class: network open information.
pub const SMB2_FILE_NETWORK_OPEN_INFORMATION: u8 = 0x22;
/// File information class: attribute tag information.
pub const SMB2_FILE_ATTRIBUTE_TAG_INFORMATION: u8 = 0x23;
/// File information class: file id both directory information.
pub const SMB2_FILE_ID_BOTH_DIRECTORY_INFORMATION: u8 = 0x25;
/// File information class: file id full directory information.
pub const SMB2_FILE_ID_FULL_DIRECTORY_INFORMATION: u8 = 0x26;
/// File information class: valid data length information.
pub const SMB2_FILE_VALID_DATA_LENGTH_INFORMATION: u8 = 0x27;
/// File information class: normalized name information.
pub const SMB2_FILE_NORMALIZED_NAME_INFORMATION: u8 = 0x30;
/// File information class: file id information.
pub const SMB2_FILE_ID_INFORMATION: u8 = 0x3B;
/// Reserved file information class boundary.
pub const SMB2_FILE_INFO_CLASS_RESERVED: u8 = 0x40;
/// Query directory flag: restart scans.
pub const SMB2_RESTART_SCANS: u8 = 0x01;
/// Query directory flag: return a single entry.
pub const SMB2_RETURN_SINGLE_ENTRY: u8 = 0x02;
/// Query directory flag: index specified.
pub const SMB2_INDEX_SPECIFIED: u8 = 0x04;
/// Query directory flag: reopen.
pub const SMB2_REOPEN: u8 = 0x10;
/// Wire size of SMB2_FILE_ID_FULL_DIRECTORY_INFORMATION.
pub const SMB2_FILEID_FULL_DIRECTORY_INFORMATION_SIZE: u16 = 80;
/// Wire size of SMB2_FILE_ID_BOTH_DIRECTORY_INFORMATION.
pub const SMB2_FILEID_BOTH_DIRECTORY_INFORMATION_SIZE: u16 = 104;
/// Wire size of an SMB2 QUERY_DIRECTORY request.
pub const SMB2_QUERY_DIRECTORY_REQUEST_SIZE: u16 = 33;
/// Wire size of an SMB2 QUERY_DIRECTORY reply.
pub const SMB2_QUERY_DIRECTORY_REPLY_SIZE: u16 = 9;
/// Wire size of an SMB2 READ request.
pub const SMB2_READ_REQUEST_SIZE: u16 = 49;
/// Read flag: read unbuffered.
pub const SMB2_READFLAG_READ_UNBUFFERED: u8 = 0x01;
/// Channel: none.
pub const SMB2_CHANNEL_NONE: u32 = 0x0000_0000;
/// Channel: RDMA v1.
pub const SMB2_CHANNEL_RDMA_V1: u32 = 0x0000_0001;
/// Channel: RDMA v1 invalidate.
pub const SMB2_CHANNEL_RDMA_V1_INVALIDATE: u32 = 0x0000_0002;
/// Wire size of an SMB2 READ reply.
pub const SMB2_READ_REPLY_SIZE: u16 = 17;

/// Wire size of an SMB2 QUERY_INFO request.
pub const SMB2_QUERY_INFO_REQUEST_SIZE: u16 = 41;
/// Info type: file.
pub const SMB2_0_INFO_FILE: u8 = 0x01;
/// Info type: filesystem.
pub const SMB2_0_INFO_FILESYSTEM: u8 = 0x02;
/// Info type: security.
pub const SMB2_0_INFO_SECURITY: u8 = 0x03;
/// Info type: quota.
pub const SMB2_0_INFO_QUOTA: u8 = 0x04;
/// Filesystem information class: volume information.
pub const SMB2_FILE_FS_VOLUME_INFORMATION: u8 = 1;
/// Filesystem information class: size information.
pub const SMB2_FILE_FS_SIZE_INFORMATION: u8 = 3;
/// Filesystem information class: device information.
pub const SMB2_FILE_FS_DEVICE_INFORMATION: u8 = 4;
/// Filesystem information class: attribute information.
pub const SMB2_FILE_FS_ATTRIBUTE_INFORMATION: u8 = 5;
/// Filesystem information class: control information.
pub const SMB2_FILE_FS_CONTROL_INFORMATION: u8 = 6;
/// Filesystem information class: full size information.
pub const SMB2_FILE_FS_FULL_SIZE_INFORMATION: u8 = 7;
/// Filesystem information class: object id information.
pub const SMB2_FILE_FS_OBJECT_ID_INFORMATION: u8 = 8;
/// Filesystem information class: sector size information.
pub const SMB2_FILE_FS_SECTOR_SIZE_INFORMATION: u8 = 11;
/// Security information selector: owner.
pub const SMB2_OWNER_SECURITY_INFORMATION: u32 = 0x0000_0001;
/// Security information selector: group.
pub const SMB2_GROUP_SECURITY_INFORMATION: u32 = 0x0000_0002;
/// Security information selector: DACL.
pub const SMB2_DACL_SECURITY_INFORMATION: u32 = 0x0000_0004;
/// Security information selector: SACL.
pub const SMB2_SACL_SECURITY_INFORMATION: u32 = 0x0000_0008;
/// Security information selector: label.
pub const SMB2_LABEL_SECURITY_INFORMATION: u32 = 0x0000_0010;
/// Security information selector: attribute.
pub const SMB2_ATTRIBUTE_SECURITY_INFORMATION: u32 = 0x0000_0020;
/// Security information selector: scope.
pub const SMB2_SCOPE_SECURITY_INFORMATION: u32 = 0x0000_0040;
/// Security information selector: backup.
pub const SMB2_BACKUP_SECURITY_INFORMATION: u32 = 0x0001_0000;
/// Query flag: restart scan.
pub const SL_RESTART_SCAN: u32 = 0x0000_0001;
/// Query flag: return a single entry.
pub const SL_RETURN_SINGLE_ENTRY: u32 = 0x0000_0002;
/// Query flag: index specified.
pub const SL_INDEX_SPECIFIED: u32 = 0x0000_0004;
/// Wire size of an SMB2 SET_INFO request.
pub const SMB2_SET_INFO_REQUEST_SIZE: u16 = 33;
/// Wire size of an SMB2 SET_INFO reply.
pub const SMB2_SET_INFO_REPLY_SIZE: u16 = 2;
/// Wire size of an SMB2 QUERY_INFO reply.
pub const SMB2_QUERY_INFO_REPLY_SIZE: u16 = 9;

/// ACE type: access allowed.
pub const SMB2_ACCESS_ALLOWED_ACE_TYPE: u8 = 0x00;
/// ACE type: access denied.
pub const SMB2_ACCESS_DENIED_ACE_TYPE: u8 = 0x01;
/// ACE type: system audit.
pub const SMB2_SYSTEM_AUDIT_ACE_TYPE: u8 = 0x02;
/// ACE type: access allowed object.
pub const SMB2_ACCESS_ALLOWED_OBJECT_ACE_TYPE: u8 = 0x05;
/// ACE type: access denied object.
pub const SMB2_ACCESS_DENIED_OBJECT_ACE_TYPE: u8 = 0x06;
/// ACE type: system audit object.
pub const SMB2_SYSTEM_AUDIT_OBJECT_ACE_TYPE: u8 = 0x07;
/// ACE type: access allowed callback.
pub const SMB2_ACCESS_ALLOWED_CALLBACK_ACE_TYPE: u8 = 0x09;
/// ACE type: access denied callback.
pub const SMB2_ACCESS_DENIED_CALLBACK_ACE_TYPE: u8 = 0x10;
/// ACE type: system mandatory label.
pub const SMB2_SYSTEM_MANDATORY_LABEL_ACE_TYPE: u8 = 0x11;
/// ACE type: system resource attribute.
pub const SMB2_SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE: u8 = 0x12;
/// ACE type: system scoped policy id.
pub const SMB2_SYSTEM_SCOPED_POLICY_ID_ACE_TYPE: u8 = 0x13;
/// ACE flag: object inherit.
pub const SMB2_OBJECT_INHERIT_ACE: u8 = 0x01;
/// ACE flag: container inherit.
pub const SMB2_CONTAINER_INHERIT_ACE: u8 = 0x02;
/// ACE flag: no propagate inherit.
pub const SMB2_NO_PROPAGATE_INHERIT_ACE: u8 = 0x04;
/// ACE flag: inherit only.
pub const SMB2_INHERIT_ONLY_ACE: u8 = 0x08;
/// ACE flag: inherited.
pub const SMB2_INHERITED_ACE: u8 = 0x10;
/// ACE flag: successful access audit.
pub const SMB2_SUCCESSFUL_ACCESS_ACE_FLAG: u8 = 0x40;
/// ACE flag: failed access audit.
pub const SMB2_FAILED_ACCESS_ACE_FLAG: u8 = 0x80;
/// ACL revision.
pub const SMB2_ACL_REVISION: u8 = 0x02;
/// Directory service ACL revision.
pub const SMB2_ACL_REVISION_DS: u8 = 0x04;
/// Security descriptor control flag: owner defaulted.
pub const SMB2_SD_CONTROL_OD: u16 = 0x0001;
/// Security descriptor control flag: group defaulted.
pub const SMB2_SD_CONTROL_GD: u16 = 0x0002;
/// Security descriptor control flag: DACL present.
pub const SMB2_SD_CONTROL_DP: u16 = 0x0004;
/// Security descriptor control flag: DACL defaulted.
pub const SMB2_SD_CONTROL_DD: u16 = 0x0008;
/// Security descriptor control flag: SACL present.
pub const SMB2_SD_CONTROL_SP: u16 = 0x0010;
/// Security descriptor control flag: SACL defaulted.
pub const SMB2_SD_CONTROL_SD: u16 = 0x0020;
/// Security descriptor control flag: server security.
pub const SMB2_SD_CONTROL_SS: u16 = 0x0040;
/// Security descriptor control flag: DACL trusted.
pub const SMB2_SD_CONTROL_DT: u16 = 0x0080;
/// Security descriptor control flag: DACL computed.
pub const SMB2_SD_CONTROL_DC: u16 = 0x0100;
/// Security descriptor control flag: SACL computed.
pub const SMB2_SD_CONTROL_SC: u16 = 0x0200;
/// Security descriptor control flag: DACL inherited.
pub const SMB2_SD_CONTROL_DI: u16 = 0x0400;
/// Security descriptor control flag: SACL inherited.
pub const SMB2_SD_CONTROL_SI: u16 = 0x0800;
/// Security descriptor control flag: DACL protected.
pub const SMB2_SD_CONTROL_PD: u16 = 0x1000;
/// Security descriptor control flag: SACL protected.
pub const SMB2_SD_CONTROL_PS: u16 = 0x2000;
/// Security descriptor control flag: resource manager control valid.
pub const SMB2_SD_CONTROL_RM: u16 = 0x4000;
/// Security descriptor control flag: self-relative.
pub const SMB2_SD_CONTROL_SR: u16 = 0x8000;

/// Filesystem device type: CD-ROM.
pub const FILE_DEVICE_CD_ROM: u32 = 0x0000_0002;
/// Filesystem device type: disk.
pub const FILE_DEVICE_DISK: u32 = 0x0000_0007;
/// Filesystem characteristic: removable media.
pub const FILE_REMOVABLE_MEDIA: u32 = 0x0000_0001;
/// Filesystem characteristic: read-only device.
pub const FILE_READ_ONLY_DEVICE: u32 = 0x0000_0002;
/// Filesystem characteristic: floppy diskette.
pub const FILE_FLOPPY_DISKETTE: u32 = 0x0000_0004;
/// Filesystem characteristic: write-once media.
pub const FILE_WRITE_ONCE_MEDIA: u32 = 0x0000_0008;
/// Filesystem characteristic: remote device.
pub const FILE_REMOTE_DEVICE: u32 = 0x0000_0010;
/// Filesystem characteristic: mounted device.
pub const FILE_DEVICE_IS_MOUNTED: u32 = 0x0000_0020;
/// Filesystem characteristic: virtual volume.
pub const FILE_VIRTUAL_VOLUME: u32 = 0x0000_0040;
/// Filesystem characteristic: secure open.
pub const FILE_DEVICE_SECURE_OPEN: u32 = 0x0000_0100;
/// Filesystem characteristic: terminal services device.
pub const FILE_CHARACTERISTIC_TS_DEVICE: u32 = 0x0000_1000;
/// Filesystem characteristic: WebDAV device.
pub const FILE_CHARACTERISTIC_WEBDAV_DEVICE: u32 = 0x0000_2000;
/// Filesystem characteristic: appcontainer traversal allowed.
pub const FILE_DEVICE_ALLOW_APPCONTAINER_TRAVERSAL: u32 = 0x0002_0000;
/// Filesystem characteristic: portable device.
pub const FILE_PORTABLE_DEVICE: u32 = 0x0004_0000;
/// Filesystem control flag: quota track.
pub const FILE_VC_QUOTA_TRACK: u32 = 0x0000_0001;
/// Filesystem control flag: quota enforce.
pub const FILE_VC_QUOTA_ENFORCE: u32 = 0x0000_0002;
/// Filesystem control flag: content index disabled.
pub const FILE_VC_CONTENT_INDEX_DISABLED: u32 = 0x0000_0008;
/// Filesystem control flag: log quota threshold.
pub const FILE_VC_LOG_QUOTA_THRESHOLD: u32 = 0x0000_0010;
/// Filesystem control flag: log quota limit.
pub const FILE_VC_LOG_QUOTA_LIMIT: u32 = 0x0000_0020;
/// Filesystem control flag: log volume threshold.
pub const FILE_VC_LOG_VOLUME_THRESHOLD: u32 = 0x0000_0040;
/// Filesystem control flag: log volume limit.
pub const FILE_VC_LOG_VOLUME_LIMIT: u32 = 0x0000_0080;
/// Filesystem control flag: quotas incomplete.
pub const FILE_VC_QUOTAS_INCOMPLETE: u32 = 0x0000_0100;
/// Filesystem control flag: quotas rebuilding.
pub const FILE_VC_QUOTAS_REBUILDING: u32 = 0x0000_0200;
/// Sector size information flag: aligned device.
pub const SSINFO_FLAGS_ALIGNED_DEVICE: u32 = 0x0000_0001;
/// Sector size information flag: partition aligned on device.
pub const SSINFO_FLAGS_PARTITION_ALIGNED_ON_DEVICE: u32 = 0x0000_0002;
/// Sector size information flag: no seek penalty.
pub const SSINFO_FLAGS_NO_SEEK_PENALTY: u32 = 0x0000_0004;
/// Sector size information flag: trim enabled.
pub const SSINFO_FLAGS_TRIM_ENABLED: u32 = 0x0000_0008;

/// Wire size of an SMB2 IOCTL request.
pub const SMB2_IOCTL_REQUEST_SIZE: u16 = 57;
/// IOCTL control code: DFS get referrals.
pub const SMB2_FSCTL_DFS_GET_REFERRALS: u32 = 0x0006_0194;
/// IOCTL control code: pipe peek.
pub const SMB2_FSCTL_PIPE_PEEK: u32 = 0x0011_400C;
/// IOCTL control code: pipe wait.
pub const SMB2_FSCTL_PIPE_WAIT: u32 = 0x0011_0018;
/// IOCTL control code: pipe transceive.
pub const SMB2_FSCTL_PIPE_TRANSCEIVE: u32 = 0x0011_C017;
/// IOCTL control code: server copy chunk.
pub const SMB2_FSCTL_SRV_COPYCHUNK: u32 = 0x0014_40F2;
/// IOCTL control code: enumerate snapshots.
pub const SMB2_FSCTL_SRV_ENUMERATE_SNAPSHOTS: u32 = 0x0014_4064;
/// IOCTL control code: request resume key.
pub const SMB2_FSCTL_SRV_REQUEST_RESUME_KEY: u32 = 0x0014_0078;
/// IOCTL control code: read hash.
pub const SMB2_FSCTL_SRV_READ_HASH: u32 = 0x0014_41BB;
/// IOCTL control code: copy chunk write.
pub const SMB2_FSCTL_SRV_COPYCHUNK_WRITE: u32 = 0x0014_80F2;
/// IOCTL control code: request resiliency.
pub const SMB2_FSCTL_LMR_REQUEST_RESILIENCY: u32 = 0x0014_01D4;
/// IOCTL control code: query network interface info.
pub const SMB2_FSCTL_QUERY_NETWORK_INTERFACE_INFO: u32 = 0x0014_01FC;
/// IOCTL control code: set reparse point.
pub const SMB2_FSCTL_SET_REPARSE_POINT: u32 = 0x0009_00A4;
/// IOCTL control code: get reparse point.
pub const SMB2_FSCTL_GET_REPARSE_POINT: u32 = 0x0009_00A8;
/// IOCTL control code: DFS get referrals extended.
pub const SMB2_FSCTL_DFS_GET_REFERRALS_EX: u32 = 0x0006_01B0;
/// IOCTL control code: file level trim.
pub const SMB2_FSCTL_FILE_LEVEL_TRIM: u32 = 0x0009_8208;
/// IOCTL control code: validate negotiate info.
pub const SMB2_FSCTL_VALIDATE_NEGOTIATE_INFO: u32 = 0x0014_0204;
/// IOCTL flag: control code is FSCTL.
pub const SMB2_0_IOCTL_IS_FSCTL: u32 = 0x0000_0001;
/// Symlink reparse buffer flag: relative target.
pub const SMB2_SYMLINK_FLAG_RELATIVE: u32 = 0x0000_0001;
/// Reparse tag: symlink.
pub const SMB2_REPARSE_TAG_SYMLINK: u32 = 0xA000_000C;
/// Wire size of an SMB2 IOCTL reply.
pub const SMB2_IOCTL_REPLY_SIZE: u16 = 49;
/// Wire size of SMB2 validate negotiate info.
pub const SMB2_IOCTL_VALIDIATE_NEGOTIATE_INFO_SIZE: u16 = 24;

/// Change notify filter: file name.
pub const SMB2_CHANGE_NOTIFY_FILE_NOTIFY_CHANGE_FILE_NAME: u32 = 0x0000_0001;
/// Change notify filter: directory name.
pub const SMB2_CHANGE_NOTIFY_FILE_NOTIFY_CHANGE_DIR_NAME: u32 = 0x0000_0002;
/// Change notify filter: attributes.
pub const SMB2_CHANGE_NOTIFY_FILE_NOTIFY_CHANGE_ATTRIBUTES: u32 = 0x0000_0004;
/// Change notify filter: size.
pub const SMB2_CHANGE_NOTIFY_FILE_NOTIFY_CHANGE_SIZE: u32 = 0x0000_0008;
/// Change notify filter: last write.
pub const SMB2_CHANGE_NOTIFY_FILE_NOTIFY_CHANGE_LAST_WRITE: u32 = 0x0000_0010;
/// Change notify filter: last access.
pub const SMB2_CHANGE_NOTIFY_FILE_NOTIFY_CHANGE_LAST_ACCESS: u32 = 0x0000_0020;
/// Change notify filter: creation.
pub const SMB2_CHANGE_NOTIFY_FILE_NOTIFY_CHANGE_CREATION: u32 = 0x0000_0040;
/// Change notify filter: EA.
pub const SMB2_CHANGE_NOTIFY_FILE_NOTIFY_CHANGE_EA: u32 = 0x0000_0080;
/// Change notify filter: security.
pub const SMB2_CHANGE_NOTIFY_FILE_NOTIFY_CHANGE_SECURITY: u32 = 0x0000_0100;
/// Change notify filter: stream name.
pub const SMB2_CHANGE_NOTIFY_FILE_NOTIFY_CHANGE_STREAM_NAME: u32 = 0x0000_0200;
/// Change notify filter: stream size.
pub const SMB2_CHANGE_NOTIFY_FILE_NOTIFY_CHANGE_STREAM_SIZE: u32 = 0x0000_0400;
/// Change notify filter: stream write.
pub const SMB2_CHANGE_NOTIFY_FILE_NOTIFY_CHANGE_STREAM_WRITE: u32 = 0x0000_0800;
/// Change notify flag: watch tree.
pub const SMB2_CHANGE_NOTIFY_WATCH_TREE: u16 = 0x0001;
/// Wire size of an SMB2 CHANGE_NOTIFY request.
pub const SMB2_CHANGE_NOTIFY_REQUEST_SIZE: u16 = 32;
/// File action: added.
pub const SMB2_NOTIFY_CHANGE_FILE_ACTION_ADDED: u32 = 0x0001;
/// File action: removed.
pub const SMB2_NOTIFY_CHANGE_FILE_ACTION_REMOVED: u32 = 0x0002;
/// File action: modified.
pub const SMB2_NOTIFY_CHANGE_FILE_ACTION_MODIFIED: u32 = 0x0003;
/// File action: renamed old name.
pub const SMB2_NOTIFY_CHANGE_FILE_ACTION_RENAMED_OLD_NAME: u32 = 0x0004;
/// File action: renamed new name.
pub const SMB2_NOTIFY_CHANGE_FILE_ACTION_RENAMED_NEW_NAME: u32 = 0x0005;
/// File action: added stream.
pub const SMB2_NOTIFY_CHANGE_FILE_ACTION_ADDED_STREAM: u32 = 0x0006;
/// File action: removed stream.
pub const SMB2_NOTIFY_CHANGE_FILE_ACTION_REMOVED_STREAM: u32 = 0x0007;
/// File action: modified stream.
pub const SMB2_NOTIFY_CHANGE_FILE_ACTION_MODIFIED_STREAM: u32 = 0x0008;
/// Wire size of an SMB2 CHANGE_NOTIFY reply.
pub const SMB2_CHANGE_NOTIFY_REPLY_SIZE: u16 = 9;

/// Wire size of an SMB2 oplock break notification.
pub const SMB2_OPLOCK_BREAK_NOTIFICATION_SIZE: u16 = 24;
/// Wire size of an SMB2 oplock break acknowledgement.
pub const SMB2_OPLOCK_BREAK_ACKNOWLEDGE_SIZE: u16 = 24;
/// Wire size of an SMB2 oplock break reply.
pub const SMB2_OPLOCK_BREAK_REPLY_SIZE: u16 = 24;
/// Lease state: none.
pub const SMB2_LEASE_NONE: u32 = 0x00;
/// Lease state: read caching.
pub const SMB2_LEASE_READ_CACHING: u32 = 0x01;
/// Lease state: handle caching.
pub const SMB2_LEASE_HANDLE_CACHING: u32 = 0x02;
/// Lease state: write caching.
pub const SMB2_LEASE_WRITE_CACHING: u32 = 0x04;
/// Break type: oplock notification.
pub const SMB2_BREAK_TYPE_OPLOCK_NOTIFICATION: i32 = 0x01;
/// Break type: oplock response.
pub const SMB2_BREAK_TYPE_OPLOCK_RESPONSE: i32 = 0x02;
/// Break type: oplock acknowledgement.
pub const SMB2_BREAK_TYPE_OPLOCK_ACKNOWLEDGE: i32 = 0x03;
/// Break type: lease notification.
pub const SMB2_BREAK_TYPE_LEASE_NOTIFICATION: i32 = 0x04;
/// Break type: lease response.
pub const SMB2_BREAK_TYPE_LEASE_RESPONSE: i32 = 0x05;
/// Break type: lease acknowledgement.
pub const SMB2_BREAK_TYPE_LEASE_ACKNOWLEDGE: i32 = 0x06;
/// Wire size of an SMB2 lease break notification.
pub const SMB2_LEASE_BREAK_NOTIFICATION_SIZE: u16 = 44;
/// Wire size of an SMB2 lease break acknowledgement.
pub const SMB2_LEASE_BREAK_ACKNOWLEDGE_SIZE: u16 = 36;
/// Wire size of an SMB2 lease break reply.
pub const SMB2_LEASE_BREAK_REPLY_SIZE: u16 = 36;
/// Wire size of an SMB2 WRITE request.
pub const SMB2_WRITE_REQUEST_SIZE: u16 = 49;
/// Write flag: write through.
pub const SMB2_WRITEFLAG_WRITE_THROUGH: u32 = 0x0000_0001;
/// Write flag: write unbuffered.
pub const SMB2_WRITEFLAG_WRITE_UNBUFFERED: u32 = 0x0000_0002;
/// Wire size of an SMB2 WRITE reply.
pub const SMB2_WRITE_REPLY_SIZE: u16 = 17;
/// Wire size of an SMB2 lock element.
pub const SMB2_LOCK_ELEMENT_SIZE: u16 = 24;
/// Wire size of an SMB2 LOCK request including one lock element.
pub const SMB2_LOCK_REQUEST_SIZE: u16 = 48;
/// Wire size of an SMB2 LOCK reply.
pub const SMB2_LOCK_REPLY_SIZE: u16 = 4;

/// SMB2 command ids.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum Command {
    /// NEGOTIATE command.
    Negotiate = 0,
    /// SESSION_SETUP command.
    SessionSetup = 1,
    /// LOGOFF command.
    Logoff = 2,
    /// TREE_CONNECT command.
    TreeConnect = 3,
    /// TREE_DISCONNECT command.
    TreeDisconnect = 4,
    /// CREATE command.
    Create = 5,
    /// CLOSE command.
    Close = 6,
    /// FLUSH command.
    Flush = 7,
    /// READ command.
    Read = 8,
    /// WRITE command.
    Write = 9,
    /// LOCK command.
    Lock = 10,
    /// IOCTL command.
    Ioctl = 11,
    /// CANCEL command.
    Cancel = 12,
    /// ECHO command.
    Echo = 13,
    /// QUERY_DIRECTORY command.
    QueryDirectory = 14,
    /// CHANGE_NOTIFY command.
    ChangeNotify = 15,
    /// QUERY_INFO command.
    QueryInfo = 16,
    /// SET_INFO command.
    SetInfo = 17,
    /// OPLOCK_BREAK command.
    OplockBreak = 18,
    /// SMB1 NEGOTIATE command id accepted by the C header enum.
    Smb1Negotiate = 114,
}

impl Command {
    /// Returns the numeric SMB command id.
    #[must_use]
    pub const fn as_u16(self) -> u16 {
        self as u16
    }

    /// Maps a numeric command id to a known command variant.
    #[must_use]
    pub const fn from_u16(value: u16) -> Option<Self> {
        match value {
            0 => Some(Self::Negotiate),
            1 => Some(Self::SessionSetup),
            2 => Some(Self::Logoff),
            3 => Some(Self::TreeConnect),
            4 => Some(Self::TreeDisconnect),
            5 => Some(Self::Create),
            6 => Some(Self::Close),
            7 => Some(Self::Flush),
            8 => Some(Self::Read),
            9 => Some(Self::Write),
            10 => Some(Self::Lock),
            11 => Some(Self::Ioctl),
            12 => Some(Self::Cancel),
            13 => Some(Self::Echo),
            14 => Some(Self::QueryDirectory),
            15 => Some(Self::ChangeNotify),
            16 => Some(Self::QueryInfo),
            17 => Some(Self::SetInfo),
            18 => Some(Self::OplockBreak),
            114 => Some(Self::Smb1Negotiate),
            _ => None,
        }
    }
}

/// Rust representation of `struct smb2_timeval`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Smb2Timeval {
    /// Seconds component.
    pub tv_sec: i64,
    /// Microseconds component.
    pub tv_usec: i64,
}

/// Rust representation of `struct smb2_error_reply`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Smb2ErrorReply {
    /// Number of error contexts.
    pub error_context_count: u8,
    /// Number of bytes in `error_data`.
    pub byte_count: u32,
    /// Error payload bytes.
    pub error_data: Vec<u8>,
}

/// Rust representation of `struct smb2_negotiate_request`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Smb2NegotiateRequest {
    /// Number of dialect entries that are meaningful in `dialects`.
    pub dialect_count: u16,
    /// Requested security mode flags.
    pub security_mode: u16,
    /// Client capabilities.
    pub capabilities: u32,
    /// Client GUID.
    pub client_guid: Smb2Guid,
    /// Offset to negotiate contexts.
    pub negotiate_context_offset: u32,
    /// Number of negotiate contexts.
    pub negotiate_context_count: u16,
    /// Fixed dialect array matching the C header skeleton.
    pub dialects: [u16; SMB2_NEGOTIATE_MAX_DIALECTS],
}

/// Rust representation of `struct smb2_negotiate_reply`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Smb2NegotiateReply {
    /// Server security mode flags.
    pub security_mode: u16,
    /// Selected dialect revision.
    pub dialect_revision: u16,
    /// Selected cipher id as named in the C header.
    pub cypher: u16,
    /// Server GUID.
    pub server_guid: Smb2Guid,
    /// Server capabilities.
    pub capabilities: u32,
    /// Maximum transact size.
    pub max_transact_size: u32,
    /// Maximum read size.
    pub max_read_size: u32,
    /// Maximum write size.
    pub max_write_size: u32,
    /// Server system time in SMB timestamp form.
    pub system_time: u64,
    /// Server start time in SMB timestamp form.
    pub server_start_time: u64,
    /// Offset to negotiate contexts.
    pub negotiate_context_offset: u32,
    /// Number of negotiate contexts.
    pub negotiate_context_count: u16,
    /// Security buffer length.
    pub security_buffer_length: u16,
    /// Security buffer offset.
    pub security_buffer_offset: u16,
    /// Security buffer bytes.
    pub security_buffer: Vec<u8>,
}

/// Rust representation of `struct smb2_session_setup_request`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Smb2SessionSetupRequest {
    /// Session setup flags.
    pub flags: u8,
    /// Security mode flags.
    pub security_mode: u8,
    /// Client capabilities.
    pub capabilities: u32,
    /// Channel id.
    pub channel: u32,
    /// Previous session id.
    pub previous_session_id: u64,
    /// Security buffer length.
    pub security_buffer_length: u16,
    /// Security buffer bytes.
    pub security_buffer: Vec<u8>,
}

/// Rust representation of `struct smb2_session_setup_reply`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Smb2SessionSetupReply {
    /// Session flags.
    pub session_flags: u16,
    /// Security buffer length.
    pub security_buffer_length: u16,
    /// Security buffer offset.
    pub security_buffer_offset: u16,
    /// Security buffer bytes.
    pub security_buffer: Vec<u8>,
}

/// Rust representation of `struct smb2_tree_connect_request`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Smb2TreeConnectRequest {
    /// Tree connect flags.
    pub flags: u16,
    /// Path offset.
    pub path_offset: u16,
    /// Path length in bytes.
    pub path_length: u16,
    /// UTF-16 path units.
    pub path: Vec<u16>,
}

/// Rust representation of `struct smb2_tree_connect_reply`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Smb2TreeConnectReply {
    /// Share type.
    pub share_type: u8,
    /// Share flags.
    pub share_flags: u32,
    /// Share capabilities.
    pub capabilities: u32,
    /// Maximal access mask.
    pub maximal_access: u32,
}

/// Rust representation of `struct smb2_create_request`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Smb2CreateRequest {
    /// Security flags.
    pub security_flags: u8,
    /// Requested oplock level.
    pub requested_oplock_level: u8,
    /// Impersonation level.
    pub impersonation_level: u32,
    /// SMB create flags.
    pub smb_create_flags: u64,
    /// Desired access mask.
    pub desired_access: u32,
    /// File attributes.
    pub file_attributes: u32,
    /// Share access flags.
    pub share_access: u32,
    /// Create disposition.
    pub create_disposition: u32,
    /// Create options.
    pub create_options: u32,
    /// Name offset.
    pub name_offset: u16,
    /// Name length in bytes.
    pub name_length: u16,
    /// File name in UTF-8.
    pub name: String,
    /// Create context offset.
    pub create_context_offset: u32,
    /// Create context length.
    pub create_context_length: u32,
    /// Create context bytes.
    pub create_context: Vec<u8>,
}

/// Rust representation of an SMB2 file handle skeleton.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Smb2FileHandle {
    /// File id associated with the handle.
    pub file_id: Smb2FileId,
}

impl Smb2FileHandle {
    /// Creates a file handle skeleton from a file id.
    #[must_use]
    pub const fn from_file_id(file_id: Smb2FileId) -> Self {
        Self { file_id }
    }

    /// Returns the file id associated with this handle.
    #[must_use]
    pub const fn file_id(&self) -> &Smb2FileId {
        &self.file_id
    }
}

/// Rust representation of `struct smb2_create_reply`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Smb2CreateReply {
    /// Granted oplock level.
    pub oplock_level: u8,
    /// Reply flags.
    pub flags: u8,
    /// Create action.
    pub create_action: u32,
    /// Creation time in SMB timestamp form.
    pub creation_time: u64,
    /// Last access time in SMB timestamp form.
    pub last_access_time: u64,
    /// Last write time in SMB timestamp form.
    pub last_write_time: u64,
    /// Change time in SMB timestamp form.
    pub change_time: u64,
    /// Allocation size.
    pub allocation_size: u64,
    /// End-of-file size.
    pub end_of_file: u64,
    /// File attributes.
    pub file_attributes: u32,
    /// File id.
    pub file_id: Smb2FileId,
    /// Create context length.
    pub create_context_length: u32,
    /// Create context offset.
    pub create_context_offset: u32,
    /// Create context bytes.
    pub create_context: Vec<u8>,
}

/// Rust representation of `struct smb2_close_request`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Smb2CloseRequest {
    /// Close flags.
    pub flags: u16,
    /// File id.
    pub file_id: Smb2FileId,
}

/// Rust representation of `struct smb2_close_reply`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Smb2CloseReply {
    /// Close flags.
    pub flags: u16,
    /// Creation time in SMB timestamp form.
    pub creation_time: u64,
    /// Last access time in SMB timestamp form.
    pub last_access_time: u64,
    /// Last write time in SMB timestamp form.
    pub last_write_time: u64,
    /// Change time in SMB timestamp form.
    pub change_time: u64,
    /// Allocation size.
    pub allocation_size: u64,
    /// End-of-file size.
    pub end_of_file: u64,
    /// File attributes.
    pub file_attributes: u32,
}

/// Rust representation of `struct smb2_flush_request`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Smb2FlushRequest {
    /// File id.
    pub file_id: Smb2FileId,
}

/// Rust representation of `struct smb2_logoff_request`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Smb2LogoffRequest {
    /// Reserved field.
    pub reserved: u16,
}

/// Rust representation of `struct smb2_echo_request`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Smb2EchoRequest {
    /// Reserved field.
    pub reserved: u16,
}

/// Rust representation of `struct smb2_fileidfulldirectoryinformation`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Smb2FileIdFullDirectoryInformation {
    /// Offset to the next entry.
    pub next_entry_offset: u32,
    /// File index.
    pub file_index: u32,
    /// Creation time.
    pub creation_time: Smb2Timeval,
    /// Last access time.
    pub last_access_time: Smb2Timeval,
    /// Last write time.
    pub last_write_time: Smb2Timeval,
    /// Change time.
    pub change_time: Smb2Timeval,
    /// End-of-file size.
    pub end_of_file: u64,
    /// Allocation size.
    pub allocation_size: u64,
    /// File attributes.
    pub file_attributes: u32,
    /// File name length in bytes.
    pub file_name_length: u32,
    /// Extended attribute size.
    pub ea_size: u32,
    /// File id.
    pub file_id: u64,
    /// UTF-8 name or reserved payload label.
    pub name: String,
}

/// Rust representation of `struct smb2_fileidbothdirectoryinformation`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Smb2FileIdBothDirectoryInformation {
    /// Offset to the next entry.
    pub next_entry_offset: u32,
    /// File index.
    pub file_index: u32,
    /// Creation time.
    pub creation_time: Smb2Timeval,
    /// Last access time.
    pub last_access_time: Smb2Timeval,
    /// Last write time.
    pub last_write_time: Smb2Timeval,
    /// Change time.
    pub change_time: Smb2Timeval,
    /// End-of-file size.
    pub end_of_file: u64,
    /// Allocation size.
    pub allocation_size: u64,
    /// File attributes.
    pub file_attributes: u32,
    /// File name length in bytes.
    pub file_name_length: u32,
    /// Extended attribute size.
    pub ea_size: u32,
    /// Short name length.
    pub short_name_length: u8,
    /// Short name bytes.
    pub short_name: [u8; 24],
    /// File id.
    pub file_id: u64,
    /// UTF-8 name or reserved payload label.
    pub name: String,
}

/// Rust representation of `struct smb2_query_directory_request`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Smb2QueryDirectoryRequest {
    /// File information class.
    pub file_information_class: u8,
    /// Query directory flags.
    pub flags: u8,
    /// File index.
    pub file_index: u32,
    /// File id.
    pub file_id: Smb2FileId,
    /// Requested output buffer length.
    pub output_buffer_length: u32,
    /// File name offset.
    pub file_name_offset: u16,
    /// File name length in bytes.
    pub file_name_length: u16,
    /// File name in UTF-8.
    pub name: String,
}

/// Rust representation of `struct smb2_query_directory_reply`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Smb2QueryDirectoryReply {
    /// Output buffer offset.
    pub output_buffer_offset: u16,
    /// Output buffer length.
    pub output_buffer_length: u32,
    /// Output buffer bytes.
    pub output_buffer: Vec<u8>,
}

/// Rust representation of `struct smb2_read_request`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Smb2ReadRequest {
    /// Read flags.
    pub flags: u8,
    /// Requested byte length.
    pub length: u32,
    /// File offset.
    pub offset: u64,
    /// Optional read target buffer skeleton.
    pub buf: Vec<u8>,
    /// File id.
    pub file_id: Smb2FileId,
    /// Minimum count.
    pub minimum_count: u32,
    /// Channel id.
    pub channel: u32,
    /// Remaining bytes.
    pub remaining_bytes: u32,
    /// Read channel info offset.
    pub read_channel_info_offset: u16,
    /// Read channel info length.
    pub read_channel_info_length: u16,
    /// Read channel info bytes.
    pub read_channel_info: Vec<u8>,
}

/// Rust representation of `struct smb2_read_reply`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Smb2ReadReply {
    /// Data offset.
    pub data_offset: u8,
    /// Data length.
    pub data_length: u32,
    /// Remaining data count.
    pub data_remaining: u32,
    /// Data bytes.
    pub data: Vec<u8>,
}

/// Rust representation of `struct smb2_file_basic_info`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Smb2FileBasicInfo {
    /// Creation time.
    pub creation_time: Smb2Timeval,
    /// Last access time.
    pub last_access_time: Smb2Timeval,
    /// Last write time.
    pub last_write_time: Smb2Timeval,
    /// Change time.
    pub change_time: Smb2Timeval,
    /// File attributes.
    pub file_attributes: u32,
}

/// Rust representation of `struct smb2_file_standard_info`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Smb2FileStandardInfo {
    /// Allocation size.
    pub allocation_size: u64,
    /// End-of-file size.
    pub end_of_file: u64,
    /// Number of links.
    pub number_of_links: u32,
    /// Delete pending flag.
    pub delete_pending: u8,
    /// Directory flag.
    pub directory: u8,
}

/// Rust representation of `struct smb2_file_stream_info`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Smb2FileStreamInfo {
    /// Offset to the next entry.
    pub next_entry_offset: u32,
    /// Stream name length in bytes.
    pub stream_name_length: u32,
    /// Stream size.
    pub stream_size: u64,
    /// Stream allocation size.
    pub stream_allocation_size: u64,
    /// Stream name.
    pub stream_name: String,
}

/// Rust representation of `struct smb2_file_position_info`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Smb2FilePositionInfo {
    /// Current byte offset.
    pub current_byte_offset: u64,
}

/// Rust representation of `struct smb2_file_name_info`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Smb2FileNameInfo {
    /// File name length in bytes.
    pub file_name_length: u32,
    /// File name bytes.
    pub name: Vec<u8>,
}

/// Rust representation of `struct smb2_file_all_info`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Smb2FileAllInfo {
    /// Basic file information.
    pub basic: Smb2FileBasicInfo,
    /// Standard file information.
    pub standard: Smb2FileStandardInfo,
    /// Index number.
    pub index_number: u64,
    /// Extended attribute size.
    pub ea_size: u32,
    /// Access flags.
    pub access_flags: u32,
    /// Current byte offset.
    pub current_byte_offset: u64,
    /// File mode.
    pub mode: u32,
    /// Alignment requirement.
    pub alignment_requirement: u32,
    /// File name bytes.
    pub name: Vec<u8>,
}

/// Rust representation of `struct smb2_query_info_request`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Smb2QueryInfoRequest {
    /// Information type.
    pub info_type: u8,
    /// File information class.
    pub file_info_class: u8,
    /// Requested output buffer length.
    pub output_buffer_length: u32,
    /// Input buffer offset.
    pub input_buffer_offset: u16,
    /// Input buffer length.
    pub input_buffer_length: u32,
    /// Input buffer bytes.
    pub input_buffer: Vec<u8>,
    /// Additional information flags.
    pub additional_information: u32,
    /// Query flags.
    pub flags: u32,
    /// File id.
    pub file_id: Smb2FileId,
    /// Input payload bytes.
    pub input: Vec<u8>,
}

/// Rust representation of `struct smb2_file_end_of_file_info`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Smb2FileEndOfFileInfo {
    /// End-of-file size.
    pub end_of_file: u64,
}

/// Rust representation of `struct smb2_file_disposition_info`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Smb2FileDispositionInfo {
    /// Delete pending flag.
    pub delete_pending: u8,
}

/// Rust representation of `struct smb2_file_rename_info`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Smb2FileRenameInfo {
    /// Replace-if-exists flag.
    pub replace_if_exist: u8,
    /// Target file name bytes.
    pub file_name: Vec<u8>,
}

/// Rust representation of `struct smb2_file_network_open_info`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Smb2FileNetworkOpenInfo {
    /// Creation time.
    pub creation_time: Smb2Timeval,
    /// Last access time.
    pub last_access_time: Smb2Timeval,
    /// Last write time.
    pub last_write_time: Smb2Timeval,
    /// Change time.
    pub change_time: Smb2Timeval,
    /// Allocation size.
    pub allocation_size: u64,
    /// End-of-file size.
    pub end_of_file: u64,
    /// File attributes.
    pub file_attributes: u32,
}

/// Rust representation of `struct smb2_set_info_request`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Smb2SetInfoRequest {
    /// Information type.
    pub info_type: u8,
    /// File information class.
    pub file_info_class: u8,
    /// Buffer length.
    pub buffer_length: u32,
    /// Buffer offset.
    pub buffer_offset: u16,
    /// Additional information flags.
    pub additional_information: u32,
    /// File id.
    pub file_id: Smb2FileId,
    /// Input data bytes.
    pub input_data: Vec<u8>,
}

/// Rust representation of `struct smb2_sid`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Smb2Sid {
    /// SID revision.
    pub revision: u8,
    /// Number of sub authorities.
    pub sub_auth_count: u8,
    /// Identifier authority bytes.
    pub id_auth: [u8; SID_ID_AUTH_LEN],
    /// Variable-length sub authority values.
    pub sub_auth: Vec<u32>,
}

/// Rust representation of `struct smb2_ace`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Smb2Ace {
    /// Next ACE in a linked-list style skeleton.
    pub next: Option<Box<Smb2Ace>>,
    /// ACE type.
    pub ace_type: u8,
    /// ACE flags.
    pub ace_flags: u8,
    /// ACE size.
    pub ace_size: u16,
    /// Access mask.
    pub mask: u32,
    /// Object ACE flags.
    pub flags: u32,
    /// Optional SID.
    pub sid: Option<Smb2Sid>,
    /// Object type GUID bytes.
    pub object_type: [u8; SMB2_OBJECT_TYPE_SIZE],
    /// Inherited object type GUID bytes.
    pub inherited_object_type: [u8; SMB2_OBJECT_TYPE_SIZE],
    /// Application data or attribute data bytes.
    pub ad_data: Vec<u8>,
    /// Raw bytes for unknown ACE types.
    pub raw_data: Vec<u8>,
}

/// Rust representation of `struct smb2_acl`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Smb2Acl {
    /// ACL revision.
    pub revision: u8,
    /// Number of ACEs.
    pub ace_count: u16,
    /// ACE entries.
    pub aces: Vec<Smb2Ace>,
}

/// Rust representation of `struct smb2_security_descriptor`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Smb2SecurityDescriptor {
    /// Security descriptor revision.
    pub revision: u8,
    /// Control flags.
    pub control: u16,
    /// Owner SID.
    pub owner: Option<Smb2Sid>,
    /// Group SID.
    pub group: Option<Smb2Sid>,
    /// Discretionary ACL.
    pub dacl: Option<Smb2Acl>,
}

/// Rust representation of `struct smb2_file_fs_volume_info`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Smb2FileFsVolumeInfo {
    /// Volume creation time.
    pub creation_time: Smb2Timeval,
    /// Volume serial number.
    pub volume_serial_number: u32,
    /// Volume label length in bytes.
    pub volume_label_length: u32,
    /// Supports objects flag.
    pub supports_objects: u8,
    /// Reserved field.
    pub reserved: u8,
    /// Volume label bytes.
    pub volume_label: Vec<u8>,
}

/// Rust representation of `struct smb2_file_fs_size_info`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Smb2FileFsSizeInfo {
    /// Total allocation units.
    pub total_allocation_units: u64,
    /// Available allocation units.
    pub available_allocation_units: u64,
    /// Sectors per allocation unit.
    pub sectors_per_allocation_unit: u32,
    /// Bytes per sector.
    pub bytes_per_sector: u32,
}

/// Rust representation of `struct smb2_file_fs_attribute_info`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Smb2FileFsAttributeInfo {
    /// Filesystem attributes.
    pub filesystem_attributes: u32,
    /// Maximum component name length.
    pub maximum_component_name_length: u32,
    /// Filesystem name length in bytes.
    pub filesystem_name_length: u32,
    /// Filesystem name bytes.
    pub filesystem_name: Vec<u8>,
}

/// Rust representation of `struct smb2_file_fs_device_info`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Smb2FileFsDeviceInfo {
    /// Device type.
    pub device_type: u32,
    /// Device characteristics.
    pub characteristics: u32,
}

/// Rust representation of `struct smb2_file_fs_control_info`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Smb2FileFsControlInfo {
    /// Free-space start filtering value.
    pub free_space_start_filtering: u64,
    /// Free-space threshold value.
    pub free_space_threshold: u64,
    /// Free-space stop filtering value.
    pub free_space_stop_filtering: u64,
    /// Default quota threshold.
    pub default_quota_threshold: u64,
    /// Default quota limit.
    pub default_quota_limit: u64,
    /// Filesystem control flags.
    pub file_system_control_flags: u32,
}

/// Rust representation of `struct smb2_file_fs_full_size_info`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Smb2FileFsFullSizeInfo {
    /// Total allocation units.
    pub total_allocation_units: u64,
    /// Caller available allocation units.
    pub caller_available_allocation_units: u64,
    /// Actual available allocation units.
    pub actual_available_allocation_units: u64,
    /// Sectors per allocation unit.
    pub sectors_per_allocation_unit: u32,
    /// Bytes per sector.
    pub bytes_per_sector: u32,
}

/// Rust representation of `struct smb2_file_fs_object_id_info`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Smb2FileFsObjectIdInfo {
    /// Object id GUID.
    pub object_id: Smb2Guid,
    /// Extended information bytes.
    pub extended_info: [u8; 48],
}

impl Default for Smb2FileFsObjectIdInfo {
    /// Creates an empty filesystem object-id information skeleton.
    fn default() -> Self {
        Self {
            object_id: [0; SMB2_GUID_SIZE],
            extended_info: [0; 48],
        }
    }
}

/// Rust representation of `struct smb2_file_fs_sector_size_info`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Smb2FileFsSectorSizeInfo {
    /// Logical bytes per sector.
    pub logical_bytes_per_sector: u32,
    /// Physical bytes per sector for atomicity.
    pub physical_bytes_per_sector_for_atomicity: u32,
    /// Physical bytes per sector for performance.
    pub physical_bytes_per_sector_for_performance: u32,
    /// Effective physical bytes per sector for atomicity.
    pub file_system_effective_physical_bytes_per_sector_for_atomicity: u32,
    /// Sector size information flags.
    pub flags: u32,
    /// Byte offset for sector alignment.
    pub byte_offset_for_sector_alignment: u32,
    /// Byte offset for partition alignment.
    pub byte_offset_for_partition_alignment: u32,
}

/// Rust representation of `struct smb2_query_info_reply`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Smb2QueryInfoReply {
    /// Output buffer offset.
    pub output_buffer_offset: u16,
    /// Output buffer length.
    pub output_buffer_length: u32,
    /// Output buffer bytes.
    pub output_buffer: Vec<u8>,
}

/// Rust representation of `struct smb2_symlink_reparse_buffer`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Smb2SymlinkReparseBuffer {
    /// Symlink flags.
    pub flags: u32,
    /// Substitute name.
    pub subname: String,
    /// Print name.
    pub printname: String,
}

/// Reparse data payload variants.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Smb2ReparseData {
    /// Symlink reparse data.
    Symlink(Smb2SymlinkReparseBuffer),
}

/// Rust representation of `struct smb2_reparse_data_buffer`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Smb2ReparseDataBuffer {
    /// Reparse tag.
    pub reparse_tag: u32,
    /// Reparse data length.
    pub reparse_data_length: u16,
    /// Optional typed reparse payload.
    pub data: Option<Smb2ReparseData>,
}

/// Rust representation of `struct smb2_ioctl_request`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Smb2IoctlRequest {
    /// Control code.
    pub ctl_code: u32,
    /// File id.
    pub file_id: Smb2FileId,
    /// Input offset.
    pub input_offset: u32,
    /// Input count.
    pub input_count: u32,
    /// Maximum input response size.
    pub max_input_response: u32,
    /// Output offset.
    pub output_offset: u32,
    /// Output count.
    pub output_count: u32,
    /// Maximum output response size.
    pub max_output_response: u32,
    /// IOCTL flags.
    pub flags: u32,
    /// Input bytes.
    pub input: Vec<u8>,
}

/// Rust representation of `struct smb2_ioctl_reply`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Smb2IoctlReply {
    /// Control code.
    pub ctl_code: u32,
    /// File id.
    pub file_id: Smb2FileId,
    /// Input offset.
    pub input_offset: u32,
    /// Input count.
    pub input_count: u32,
    /// Output offset.
    pub output_offset: u32,
    /// Output count.
    pub output_count: u32,
    /// IOCTL flags.
    pub flags: u32,
    /// Output bytes.
    pub output: Vec<u8>,
}

/// Rust representation of `struct smb2_ioctl_validate_negotiate_info`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Smb2IoctlValidateNegotiateInfo {
    /// Capabilities.
    pub capabilities: u32,
    /// Client or server GUID bytes.
    pub guid: Smb2Guid,
    /// Security mode.
    pub security_mode: u16,
    /// Dialect id.
    pub dialect: u16,
}

/// Rust representation of `struct smb2_change_notify_request`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Smb2ChangeNotifyRequest {
    /// Change notify flags.
    pub flags: u16,
    /// Output buffer length.
    pub output_buffer_length: u32,
    /// File id.
    pub file_id: Smb2FileId,
    /// Completion filter mask.
    pub completion_filter: u32,
}

/// Rust representation of `struct smb2_change_notify_reply`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Smb2ChangeNotifyReply {
    /// Output buffer offset.
    pub output_buffer_offset: u16,
    /// Output buffer length.
    pub output_buffer_length: u32,
    /// Output bytes.
    pub output: Vec<u8>,
}

/// Rust representation of `struct smb2_file_notify_change_information`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Smb2FileNotifyChangeInformation {
    /// File action.
    pub action: u32,
    /// File name.
    pub name: String,
    /// Next notification entry in a linked-list style skeleton.
    pub next: Option<Box<Smb2FileNotifyChangeInformation>>,
}

/// Rust representation of `struct smb2_oplock_break_notification`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Smb2OplockBreakNotification {
    /// New oplock level.
    pub oplock_level: u8,
    /// File id.
    pub file_id: Smb2FileId,
}

/// Rust representation of `struct smb2_oplock_break_acknowledgement`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Smb2OplockBreakAcknowledgement {
    /// Acknowledged oplock level.
    pub oplock_level: u8,
    /// File id.
    pub file_id: Smb2FileId,
}

/// Rust representation of `struct smb2_oplock_break_reply`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Smb2OplockBreakReply {
    /// Oplock level.
    pub oplock_level: u8,
    /// File id.
    pub file_id: Smb2FileId,
}

/// Rust representation of `struct smb2_lease_break_notification`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Smb2LeaseBreakNotification {
    /// New epoch.
    pub new_epoch: u16,
    /// Lease break flags.
    pub flags: u32,
    /// Lease key.
    pub lease_key: Smb2LeaseKey,
    /// Current lease state.
    pub current_lease_state: u32,
    /// New lease state.
    pub new_lease_state: u32,
    /// Break reason.
    pub break_reason: u32,
    /// Access mask hint.
    pub access_mask_hint: u32,
    /// Share mask hint.
    pub share_mask_hint: u32,
}

/// Rust representation of `struct smb2_lease_break_acknowledgement`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Smb2LeaseBreakAcknowledgement {
    /// Lease break flags.
    pub flags: u32,
    /// Lease key.
    pub lease_key: Smb2LeaseKey,
    /// Lease state.
    pub lease_state: u32,
    /// Lease duration.
    pub lease_duration: u64,
}

/// Rust representation of `struct smb2_lease_break_reply`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Smb2LeaseBreakReply {
    /// Lease break flags.
    pub flags: u32,
    /// Lease key.
    pub lease_key: Smb2LeaseKey,
    /// Lease state.
    pub lease_state: u32,
    /// Lease duration.
    pub lease_duration: u64,
}

/// Payload variants for server-side oplock or lease break replies.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Smb2OplockOrLeaseBreakReplyLock {
    /// Oplock break notification payload.
    Oplock(Smb2OplockBreakNotification),
    /// Oplock break reply payload.
    OplockReply(Smb2OplockBreakReply),
    /// Lease break notification payload.
    Lease(Smb2LeaseBreakNotification),
    /// Lease break reply payload.
    LeaseReply(Smb2LeaseBreakReply),
}

/// Rust representation of `struct smb2_oplock_or_lease_break_reply`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Smb2OplockOrLeaseBreakReply {
    /// Structure size.
    pub struct_size: u16,
    /// Break type discriminator.
    pub break_type: i32,
    /// Optional typed lock payload.
    pub lock: Option<Smb2OplockOrLeaseBreakReplyLock>,
}

/// Payload variants for client-side oplock or lease break requests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Smb2OplockOrLeaseBreakRequestLock {
    /// Oplock break acknowledgement payload.
    Oplock(Smb2OplockBreakAcknowledgement),
    /// Lease break acknowledgement payload.
    Lease(Smb2LeaseBreakAcknowledgement),
}

/// Rust representation of `struct smb2_oplock_or_lease_break_request`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Smb2OplockOrLeaseBreakRequest {
    /// Structure size.
    pub struct_size: u16,
    /// Break type discriminator.
    pub break_type: i32,
    /// Optional typed lock payload.
    pub lock: Option<Smb2OplockOrLeaseBreakRequestLock>,
}

/// Rust representation of `struct smb2_write_request`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Smb2WriteRequest {
    /// Data offset.
    pub data_offset: u16,
    /// Data length.
    pub length: u32,
    /// File offset.
    pub offset: u64,
    /// Data bytes to write.
    pub buf: Vec<u8>,
    /// File id.
    pub file_id: Smb2FileId,
    /// Channel id.
    pub channel: u32,
    /// Remaining bytes.
    pub remaining_bytes: u32,
    /// Write channel info offset.
    pub write_channel_info_offset: u16,
    /// Write channel info length.
    pub write_channel_info_length: u16,
    /// Write channel info bytes.
    pub write_channel_info: Vec<u8>,
    /// Write flags.
    pub flags: u32,
}

/// Rust representation of `struct smb2_write_reply`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Smb2WriteReply {
    /// Number of bytes written.
    pub count: u32,
    /// Remaining bytes.
    pub remaining: u32,
}

/// Rust representation of `struct smb2_lock_element`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Smb2LockElement {
    /// Lock offset.
    pub offset: u64,
    /// Lock length.
    pub length: u64,
    /// Lock flags.
    pub flags: u32,
    /// Reserved field.
    pub reserved: u32,
}

/// Rust representation of `struct smb2_lock_request`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Smb2LockRequest {
    /// Number of lock elements.
    pub lock_count: u16,
    /// Lock sequence number.
    pub lock_sequence_number: u8,
    /// Lock sequence index.
    pub lock_sequence_index: u32,
    /// File id.
    pub file_id: Smb2FileId,
    /// Lock elements.
    pub locks: Vec<Smb2LockElement>,
}

/// Skeleton interface for decoding file-id full directory information.
pub trait FileIdFullDirectoryInformationDecoder {
    /// Decodes directory information from bytes when an implementation is supplied.
    ///
    /// The protocol module only defines the interface; concrete decoders belong in
    /// higher-level parser code.
    #[must_use]
    fn decode_fileid_full_directory_information(
        &self,
        data: &[u8],
    ) -> Option<Smb2FileIdFullDirectoryInformation>;
}

/// Skeleton interface for decoding file notify change information.
pub trait FileNotifyChangeInformationDecoder {
    /// Decodes notify change information from bytes when an implementation is supplied.
    ///
    /// The protocol module only defines the interface; concrete decoders belong in
    /// higher-level parser code.
    #[must_use]
    fn decode_file_notify_change_information(
        &self,
        data: &[u8],
        next_entry_offset: u32,
    ) -> Option<Smb2FileNotifyChangeInformation>;
}
