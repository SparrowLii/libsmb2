//! ASN.1 BER helpers migrated from `lib/asn1-ber.c`.
//!
//! This module mirrors the legacy C file's data model and function surface. The
//! protocol encoders and decoders are intentionally skeletal until each call path
//! is migrated with parity tests.

/// Maximum number of object identifier elements accepted by the legacy BER code.
pub const BER_MAX_OID_ELEMENTS: usize = 32;

/// ASN.1 universal class tag mask.
pub const ASN_UNIVERSAL: u8 = 0x00;
/// ASN.1 boolean tag number.
pub const ASN_BOOLEAN: u8 = 0x01;
/// ASN.1 integer tag number.
pub const ASN_INTEGER: u8 = 0x02;
/// ASN.1 bit string tag number.
pub const ASN_BIT_STRING: u8 = 0x03;
/// ASN.1 octet string tag number.
pub const ASN_OCTET_STRING: u8 = 0x04;
/// ASN.1 null tag number.
pub const ASN_NULL: u8 = 0x05;
/// ASN.1 object identifier tag number.
pub const ASN_OBJECT_ID: u8 = 0x06;
/// ASN.1 enumerated tag number.
pub const ASN_ENUMERATED: u8 = 0x0a;
/// ASN.1 sequence tag number.
pub const ASN_SEQUENCE: u8 = 0x10;
/// ASN.1 set tag number.
pub const ASN_SET: u8 = 0x11;
/// ASN.1 printable string tag number.
pub const ASN_PRINTABLE_STR: u8 = 0x13;
/// ASN.1 UTC time tag number.
pub const ASN_UTC_TIME: u8 = 0x17;
/// ASN.1 extension-id marker used for long-form tags.
pub const ASN_EXTENSION_ID: u8 = 0x1f;
/// ASN.1 constructed bit.
pub const ASN_CONSTRUCTOR: u8 = 0x20;
/// ASN.1 sequence/structure type byte used by the legacy C code.
pub const ASN_STRUCT: u8 = 0x30;
/// ASN.1 application class bit pattern.
pub const ASN_APPLICATION: u8 = 0x40;
/// ASN.1 context-specific class bit pattern.
pub const ASN_CONTEXT_SPECIFIC: u8 = 0x80;
/// ASN.1 private class bit pattern.
pub const ASN_PRIVATE: u8 = 0xc0;

/// ASN.1 BER tag descriptor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BerTag {
    /// Tag class and constructed bits.
    pub class: u8,
    /// Tag number.
    pub number: u32,
}

impl BerTag {
    /// Builds a tag descriptor from a single-byte BER type code.
    #[must_use]
    pub const fn from_type_code(type_code: BerType) -> Self {
        Self {
            class: type_code.value() & 0xe0,
            number: (type_code.value() & ASN_EXTENSION_ID) as u32,
        }
    }
}

/// BER type code wrapper matching `ber_type_t` values from `lib/asn1-ber.h`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BerType(u8);

impl BerType {
    /// BER boolean type.
    pub const BOOLEAN: Self = Self(ASN_BOOLEAN);
    /// BER signed integer type.
    pub const INTEGER: Self = Self(ASN_INTEGER);
    /// BER bit string type.
    pub const BIT_STRING: Self = Self(ASN_BIT_STRING);
    /// BER octet string type.
    pub const OCTET_STRING: Self = Self(ASN_OCTET_STRING);
    /// BER null type.
    pub const NULL: Self = Self(ASN_NULL);
    /// BER object identifier type.
    pub const OBJECT_ID: Self = Self(ASN_OBJECT_ID);
    /// BER enumerated type.
    pub const ENUMERATED: Self = Self(ASN_ENUMERATED);
    /// BER sequence type.
    pub const SEQUENCE: Self = Self(ASN_SEQUENCE);
    /// BER set-of type.
    pub const SETOF: Self = Self(ASN_SET);
    /// BER printable string type.
    pub const PRINTABLE_STR: Self = Self(ASN_PRINTABLE_STR);
    /// BER UTC time type.
    pub const UTC_TIME: Self = Self(ASN_UTC_TIME);
    /// RFC-1442 IP address type.
    pub const IPADDRESS: Self = Self(ASN_APPLICATION);
    /// RFC-1442 counter type.
    pub const COUNTER: Self = Self(ASN_APPLICATION | 0x01);
    /// RFC-1442 gauge type.
    pub const GAUGE: Self = Self(ASN_APPLICATION | 0x02);
    /// RFC-1442 unsigned type, an alias of gauge in the C header.
    pub const UNSIGNED: Self = Self(ASN_APPLICATION | 0x02);
    /// RFC-1442 timeticks type.
    pub const TIMETICKS: Self = Self(ASN_APPLICATION | 0x03);
    /// RFC-1442 opaque type.
    pub const OPAQUE: Self = Self(ASN_APPLICATION | 0x04);
    /// RFC-1442 NSAP address type.
    pub const NSAPADDRESS: Self = Self(ASN_APPLICATION | 0x05);
    /// RFC-1442 64-bit counter type.
    pub const COUNTER64: Self = Self(ASN_APPLICATION | 0x06);
    /// RFC-1442 32-bit unsigned type.
    pub const UNSIGNED32: Self = Self(ASN_APPLICATION | 0x07);
    /// RFC-1442 float type.
    pub const FLOAT: Self = Self(ASN_APPLICATION | 0x08);
    /// RFC-1442 double type.
    pub const DOUBLE: Self = Self(ASN_APPLICATION | 0x09);
    /// RFC-3781 64-bit integer type.
    pub const INTEGER64: Self = Self(ASN_APPLICATION | 0x0a);
    /// RFC-3781 64-bit unsigned type.
    pub const UNSIGNED64: Self = Self(ASN_APPLICATION | 0x0b);
    /// RFC-3781 32-bit float type.
    pub const FLOAT32: Self = Self(ASN_APPLICATION | 0x0c);
    /// RFC-3781 64-bit float type.
    pub const FLOAT64: Self = Self(ASN_APPLICATION | 0x0d);
    /// RFC-3781 128-bit float type.
    pub const FLOAT128: Self = Self(ASN_APPLICATION | 0x0e);

    /// Creates a BER sequence type byte from a low tag number.
    #[must_use]
    pub const fn sequence(number: u8) -> Self {
        Self(ASN_STRUCT | number)
    }

    /// Creates a BER context-specific constructed type byte from a low tag number.
    #[must_use]
    pub const fn context(number: u8) -> Self {
        Self(ASN_CONTEXT_SPECIFIC | ASN_CONSTRUCTOR | number)
    }

    /// Creates a BER context-specific primitive type byte from a low tag number.
    #[must_use]
    pub const fn context_simple(number: u8) -> Self {
        Self(ASN_CONTEXT_SPECIFIC | number)
    }

    /// Returns the raw BER type byte.
    #[must_use]
    pub const fn value(self) -> u8 {
        self.0
    }
}

impl From<u8> for BerType {
    fn from(value: u8) -> Self {
        Self(value)
    }
}

impl From<BerType> for u8 {
    fn from(value: BerType) -> Self {
        value.value()
    }
}

/// Error category for BER migration skeleton operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BerError {
    /// Input was exhausted before the requested BER item could be read.
    UnexpectedEof,
    /// Output buffer does not have enough capacity for the requested write.
    OutputTooSmall,
    /// The encountered BER type does not match the requested operation.
    InvalidType,
    /// The encoded length or value exceeds the supported Rust skeleton bounds.
    TooLarge,
    /// The requested C function counterpart has not been migrated yet.
    Unsupported(&'static str),
}

/// Result type used by ASN.1 BER helpers.
pub type BerResult<T> = Result<T, BerError>;

/// Object identifier storage matching `struct asn1ber_oid_value`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Asn1BerOidValue {
    elements: [u32; BER_MAX_OID_ELEMENTS],
    length: usize,
}

impl Asn1BerOidValue {
    /// Creates an empty OID container.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            elements: [0; BER_MAX_OID_ELEMENTS],
            length: 0,
        }
    }

    /// Returns the number of populated OID elements.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.length
    }

    /// Returns whether the OID contains no elements.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.length == 0
    }

    /// Returns the populated OID elements.
    #[must_use]
    pub fn elements(&self) -> &[u32] {
        &self.elements[..self.length]
    }

    /// Clears the OID without changing its fixed storage.
    pub fn clear(&mut self) {
        self.length = 0;
    }
}

impl Default for Asn1BerOidValue {
    fn default() -> Self {
        Self::new()
    }
}

/// Input/output state matching the legacy `struct asn1ber_context`.
#[derive(Debug)]
pub struct Asn1BerContext<'src, 'dst> {
    src: &'src [u8],
    src_tail: usize,
    dst: Option<&'dst mut [u8]>,
    dst_head: usize,
    last_error: Option<BerError>,
}

impl<'src, 'dst> Asn1BerContext<'src, 'dst> {
    /// Creates a context with only an input buffer.
    #[must_use]
    pub const fn from_src(src: &'src [u8]) -> Self {
        Self {
            src,
            src_tail: 0,
            dst: None,
            dst_head: 0,
            last_error: None,
        }
    }

    /// Creates a context with only an output buffer.
    #[must_use]
    pub fn from_dst(dst: &'dst mut [u8]) -> Self {
        Self {
            src: &[],
            src_tail: 0,
            dst: Some(dst),
            dst_head: 0,
            last_error: None,
        }
    }

    /// Creates a context with both input and output buffers.
    #[must_use]
    pub fn from_src_dst(src: &'src [u8], dst: &'dst mut [u8]) -> Self {
        Self {
            src,
            src_tail: 0,
            dst: Some(dst),
            dst_head: 0,
            last_error: None,
        }
    }

    /// Returns the current input cursor offset.
    #[must_use]
    pub const fn src_tail(&self) -> usize {
        self.src_tail
    }

    /// Returns the current output cursor offset.
    #[must_use]
    pub const fn dst_head(&self) -> usize {
        self.dst_head
    }

    /// Returns the last BER error recorded on this context.
    #[must_use]
    pub const fn last_error(&self) -> Option<BerError> {
        self.last_error
    }

    /// Reads the next byte from the input buffer.
    ///
    /// # Errors
    ///
    /// Returns [`BerError::UnexpectedEof`] when the input cursor is at the end.
    pub fn next_byte(&mut self) -> BerResult<u8> {
        if self.src_tail >= self.src.len() {
            return self.record_error(BerError::UnexpectedEof);
        }

        let byte = self.src[self.src_tail];
        self.src_tail += 1;
        Ok(byte)
    }

    /// Writes one byte to the output buffer.
    ///
    /// # Errors
    ///
    /// Returns [`BerError::OutputTooSmall`] when no output buffer is present or full.
    pub fn out_byte(&mut self, value: u8) -> BerResult<()> {
        match self.dst.as_deref_mut() {
            Some(dst) if self.dst_head < dst.len() => {
                dst[self.dst_head] = value;
                self.dst_head += 1;
                Ok(())
            }
            Some(_) | None => self.record_error(BerError::OutputTooSmall),
        }
    }

    /// Saves the current output cursor for later length back-annotation.
    ///
    /// # Errors
    ///
    /// Returns [`BerError::OutputTooSmall`] when no output buffer is present or full.
    pub fn save_out_state(&mut self) -> BerResult<usize> {
        match self.dst.as_deref() {
            Some(dst) if self.dst_head < dst.len() => Ok(self.dst_head),
            Some(_) | None => self.record_error(BerError::OutputTooSmall),
        }
    }

    /// Placeholder for `asn1ber_annotate_length` length back-annotation.
    ///
    /// # Errors
    ///
    /// Returns [`BerError::Unsupported`] until the BER length rewrite logic is migrated.
    pub fn annotate_length(&mut self, _out_pos: usize, _reserved: usize) -> BerResult<()> {
        self.record_error(BerError::Unsupported("asn1ber_annotate_length"))
    }

    /// Placeholder for `asn1ber_length_from_ber`.
    ///
    /// # Errors
    ///
    /// Returns [`BerError::Unsupported`] until BER length decoding is migrated.
    pub fn length_from_ber(&mut self) -> BerResult<u32> {
        self.record_error(BerError::Unsupported("asn1ber_length_from_ber"))
    }

    /// Placeholder for `ber_typecode_from_ber`.
    ///
    /// # Errors
    ///
    /// Returns [`BerError::Unsupported`] until BER tag decoding is migrated.
    pub fn typecode_from_ber(&mut self) -> BerResult<BerType> {
        self.record_error(BerError::Unsupported("ber_typecode_from_ber"))
    }

    /// Placeholder for `ber_typelen_from_ber`.
    ///
    /// # Errors
    ///
    /// Returns [`BerError::Unsupported`] until BER tag and length decoding is migrated.
    pub fn typelen_from_ber(&mut self) -> BerResult<BerTypeLen> {
        self.record_error(BerError::Unsupported("ber_typelen_from_ber"))
    }

    /// Placeholder for `asn1ber_request_from_ber`.
    ///
    /// # Errors
    ///
    /// Returns [`BerError::Unsupported`] until request header decoding is migrated.
    pub fn request_from_ber(&mut self) -> BerResult<BerTypeLen> {
        self.record_error(BerError::Unsupported("asn1ber_request_from_ber"))
    }

    /// Placeholder for `asn1ber_struct_from_ber`.
    ///
    /// # Errors
    ///
    /// Returns [`BerError::Unsupported`] until structure decoding is migrated.
    pub fn struct_from_ber(&mut self) -> BerResult<u32> {
        self.record_error(BerError::Unsupported("asn1ber_struct_from_ber"))
    }

    /// Placeholder for `asn1ber_null_from_ber`.
    ///
    /// # Errors
    ///
    /// Returns [`BerError::Unsupported`] until null decoding is migrated.
    pub fn null_from_ber(&mut self) -> BerResult<u32> {
        self.record_error(BerError::Unsupported("asn1ber_null_from_ber"))
    }

    /// Placeholder for `asn1ber_int32_from_ber`.
    ///
    /// # Errors
    ///
    /// Returns [`BerError::Unsupported`] until signed 32-bit integer decoding is migrated.
    pub fn int32_from_ber(&mut self) -> BerResult<i32> {
        self.record_error(BerError::Unsupported("asn1ber_int32_from_ber"))
    }

    /// Placeholder for `asn1ber_uint32_from_ber`.
    ///
    /// # Errors
    ///
    /// Returns [`BerError::Unsupported`] until unsigned 32-bit integer decoding is migrated.
    pub fn uint32_from_ber(&mut self) -> BerResult<u32> {
        self.record_error(BerError::Unsupported("asn1ber_uint32_from_ber"))
    }

    /// Placeholder for `asn1ber_int64_from_ber`.
    ///
    /// # Errors
    ///
    /// Returns [`BerError::Unsupported`] until signed 64-bit integer decoding is migrated.
    pub fn int64_from_ber(&mut self) -> BerResult<i64> {
        self.record_error(BerError::Unsupported("asn1ber_int64_from_ber"))
    }

    /// Placeholder for `asn1ber_uint64_from_ber`.
    ///
    /// # Errors
    ///
    /// Returns [`BerError::Unsupported`] until unsigned 64-bit integer decoding is migrated.
    pub fn uint64_from_ber(&mut self) -> BerResult<u64> {
        self.record_error(BerError::Unsupported("asn1ber_uint64_from_ber"))
    }

    /// Placeholder for `asn1ber_oid_from_ber`.
    ///
    /// # Errors
    ///
    /// Returns [`BerError::Unsupported`] until OID decoding is migrated.
    pub fn oid_from_ber(&mut self) -> BerResult<Asn1BerOidValue> {
        self.record_error(BerError::Unsupported("asn1ber_oid_from_ber"))
    }

    /// Placeholder for `asn1ber_bytes_from_ber`.
    ///
    /// # Errors
    ///
    /// Returns [`BerError::Unsupported`] until octet-string decoding is migrated.
    pub fn bytes_from_ber(&mut self, _max_len: usize) -> BerResult<Vec<u8>> {
        self.record_error(BerError::Unsupported("asn1ber_bytes_from_ber"))
    }

    /// Placeholder for `asn1ber_string_from_ber`.
    ///
    /// # Errors
    ///
    /// Returns [`BerError::Unsupported`] until string decoding is migrated.
    pub fn string_from_ber(&mut self, _max_len: usize) -> BerResult<String> {
        self.record_error(BerError::Unsupported("asn1ber_string_from_ber"))
    }

    /// Placeholder for `asn1ber_ber_from_length`.
    ///
    /// # Errors
    ///
    /// Returns [`BerError::Unsupported`] until BER length encoding is migrated.
    pub fn ber_from_length(&mut self, _len: u32) -> BerResult<usize> {
        self.record_error(BerError::Unsupported("asn1ber_ber_from_length"))
    }

    /// Reserves zero-filled bytes in the output BER stream.
    ///
    /// # Errors
    ///
    /// Returns [`BerError::OutputTooSmall`] when the output buffer cannot hold the reservation.
    pub fn ber_reserve_length(&mut self, len: usize) -> BerResult<()> {
        for _ in 0..len {
            self.out_byte(0)?;
        }
        Ok(())
    }

    /// Writes a single BER type code byte.
    ///
    /// # Errors
    ///
    /// Returns [`BerError::OutputTooSmall`] when the output buffer cannot hold the type byte.
    pub fn ber_from_typecode(&mut self, type_code: BerType) -> BerResult<()> {
        self.out_byte(type_code.value())
    }

    /// Placeholder for `asn1ber_ber_from_typelen`.
    ///
    /// # Errors
    ///
    /// Returns [`BerError::Unsupported`] until BER tag and length encoding is migrated.
    pub fn ber_from_typelen(&mut self, _type_code: BerType, _len: u32) -> BerResult<usize> {
        self.record_error(BerError::Unsupported("asn1ber_ber_from_typelen"))
    }

    /// Placeholder for `asn1ber_ber_from_int32`.
    ///
    /// # Errors
    ///
    /// Returns [`BerError::Unsupported`] until signed 32-bit integer encoding is migrated.
    pub fn ber_from_int32(&mut self, _type_code: BerType, _value: i32) -> BerResult<()> {
        self.record_error(BerError::Unsupported("asn1ber_ber_from_int32"))
    }

    /// Placeholder for `asn1ber_ber_from_uint32`.
    ///
    /// # Errors
    ///
    /// Returns [`BerError::Unsupported`] until unsigned 32-bit integer encoding is migrated.
    pub fn ber_from_uint32(&mut self, _type_code: BerType, _value: u32) -> BerResult<()> {
        self.record_error(BerError::Unsupported("asn1ber_ber_from_uint32"))
    }

    /// Placeholder for `asn1ber_ber_from_int64`.
    ///
    /// # Errors
    ///
    /// Returns [`BerError::Unsupported`] until signed 64-bit integer encoding is migrated.
    pub fn ber_from_int64(&mut self, _type_code: BerType, _value: i64) -> BerResult<()> {
        self.record_error(BerError::Unsupported("asn1ber_ber_from_int64"))
    }

    /// Placeholder for `asn1ber_ber_from_uint64`.
    ///
    /// # Errors
    ///
    /// Returns [`BerError::Unsupported`] until unsigned 64-bit integer encoding is migrated.
    pub fn ber_from_uint64(&mut self, _type_code: BerType, _value: u64) -> BerResult<()> {
        self.record_error(BerError::Unsupported("asn1ber_ber_from_uint64"))
    }

    /// Placeholder for `asn1ber_ber_from_oid`.
    ///
    /// # Errors
    ///
    /// Returns [`BerError::Unsupported`] until OID encoding is migrated.
    pub fn ber_from_oid(&mut self, _oid: &Asn1BerOidValue) -> BerResult<()> {
        self.record_error(BerError::Unsupported("asn1ber_ber_from_oid"))
    }

    /// Placeholder for `asn1ber_ber_from_bytes`.
    ///
    /// # Errors
    ///
    /// Returns [`BerError::Unsupported`] until byte string encoding is migrated.
    pub fn ber_from_bytes(&mut self, _type_code: BerType, _value: &[u8]) -> BerResult<()> {
        self.record_error(BerError::Unsupported("asn1ber_ber_from_bytes"))
    }

    /// Placeholder for `asn1ber_ber_from_string`.
    ///
    /// # Errors
    ///
    /// Returns [`BerError::Unsupported`] until string encoding is migrated.
    pub fn ber_from_string(&mut self, value: &str) -> BerResult<()> {
        self.ber_from_bytes(BerType::OCTET_STRING, value.as_bytes())
    }

    fn record_error<T>(&mut self, error: BerError) -> BerResult<T> {
        self.last_error = Some(error);
        Err(error)
    }
}

/// BER type and length pair returned by tag-length decoding helpers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BerTypeLen {
    /// BER type code.
    pub type_code: BerType,
    /// BER payload length.
    pub len: u32,
}
