//! ASN.1 BER helpers migrated from `lib/asn1-ber.c`.
//!
//! This module mirrors the legacy C file's data model and function surface. The
//! protocol encoders and decoders are migrated incrementally as call paths gain
//! parity coverage.

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
    /// The BER value is malformed or cannot be represented by this API.
    InvalidValue,
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

    /// Replaces the OID contents with the provided elements.
    ///
    /// # Errors
    ///
    /// Returns [`BerError::TooLarge`] when more than [`BER_MAX_OID_ELEMENTS`]
    /// elements are supplied.
    pub fn set_elements(&mut self, elements: &[u32]) -> BerResult<()> {
        if elements.len() > BER_MAX_OID_ELEMENTS {
            return Err(BerError::TooLarge);
        }
        self.elements[..elements.len()].copy_from_slice(elements);
        self.length = elements.len();
        Ok(())
    }

    /// Builds an OID value from a slice of elements.
    ///
    /// # Errors
    ///
    /// Returns [`BerError::TooLarge`] when more than [`BER_MAX_OID_ELEMENTS`]
    /// elements are supplied.
    pub fn from_elements(elements: &[u32]) -> BerResult<Self> {
        let mut oid = Self::new();
        oid.set_elements(elements)?;
        Ok(oid)
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

    /// Returns the number of unread input bytes.
    #[must_use]
    pub const fn remaining_src(&self) -> usize {
        self.src.len().saturating_sub(self.src_tail)
    }

    /// Advances the input cursor by `len` bytes.
    ///
    /// # Errors
    ///
    /// Returns [`BerError::UnexpectedEof`] when fewer than `len` bytes remain.
    pub fn skip_src(&mut self, len: usize) -> BerResult<()> {
        let end = self.src_tail.checked_add(len).ok_or(BerError::TooLarge)?;
        if end > self.src.len() {
            return self.record_error(BerError::UnexpectedEof);
        }
        self.src_tail = end;
        Ok(())
    }

    /// Returns the bytes written to the destination buffer so far.
    #[must_use]
    pub fn dst_written(&self) -> Option<&[u8]> {
        self.dst.as_deref().map(|dst| &dst[..self.dst_head])
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

    /// Back-annotates a reserved BER length field at `out_pos`.
    ///
    /// # Errors
    ///
    /// Returns [`BerError::OutputTooSmall`] when no destination buffer exists,
    /// [`BerError::InvalidValue`] when the saved position is invalid, or
    /// [`BerError::TooLarge`] when the reserved field cannot hold the encoded length.
    pub fn annotate_length(&mut self, out_pos: usize, reserved: usize) -> BerResult<()> {
        let old_head = self.dst_head;
        let bytes_made = old_head
            .checked_sub(out_pos)
            .and_then(|written| written.checked_sub(reserved))
            .ok_or(BerError::InvalidValue)?;
        if bytes_made > u32::MAX as usize {
            return self.record_error(BerError::TooLarge);
        }

        self.dst_head = out_pos;
        let lenbytes = self.ber_from_length(bytes_made as u32)?;
        if lenbytes > reserved {
            self.dst_head = old_head;
            return self.record_error(BerError::TooLarge);
        }

        if reserved > lenbytes {
            match self.dst.as_deref_mut() {
                Some(dst) => {
                    let src_start = out_pos + reserved;
                    let src_end = src_start + bytes_made;
                    let dst_start = out_pos + lenbytes;
                    if src_end > dst.len() || dst_start + bytes_made > dst.len() {
                        self.dst_head = old_head;
                        return self.record_error(BerError::OutputTooSmall);
                    }
                    dst.copy_within(src_start..src_end, dst_start);
                }
                None => {
                    self.dst_head = old_head;
                    return self.record_error(BerError::OutputTooSmall);
                }
            }
        }
        self.dst_head = out_pos + lenbytes + bytes_made;
        Ok(())
    }

    /// Decodes a BER definite length.
    ///
    /// # Errors
    ///
    /// Returns [`BerError::UnexpectedEof`] when the length bytes are truncated or
    /// [`BerError::TooLarge`] when the length needs more than four bytes.
    pub fn length_from_ber(&mut self) -> BerResult<u32> {
        let first = self.next_byte()?;
        if first & 0x80 == 0 {
            return Ok(u32::from(first));
        }

        let mut count = first & 0x7f;
        if count == 0 {
            return self.record_error(BerError::InvalidValue);
        }
        if count > 4 {
            return self.record_error(BerError::TooLarge);
        }
        let mut len = 0_u32;
        while count > 0 {
            len = (len << 8) | u32::from(self.next_byte()?);
            count -= 1;
        }
        Ok(len)
    }

    /// Decodes the next BER type code.
    ///
    /// # Errors
    ///
    /// Returns [`BerError::UnexpectedEof`] when the tag bytes are truncated.
    pub fn typecode_from_ber(&mut self) -> BerResult<BerType> {
        let first = self.next_byte()?;
        if first & ASN_EXTENSION_ID != ASN_EXTENSION_ID {
            return Ok(BerType::from(first));
        }
        let mut next = self.next_byte()?;
        if next >= ASN_STRUCT {
            next -= ASN_STRUCT;
        }
        Ok(BerType::from(next))
    }

    /// Decodes a BER type code and definite length pair.
    ///
    /// # Errors
    ///
    /// Returns an error from tag or length decoding when the BER header is invalid.
    pub fn typelen_from_ber(&mut self) -> BerResult<BerTypeLen> {
        let type_code = self.typecode_from_ber()?;
        let len = self.length_from_ber()?;
        Ok(BerTypeLen { type_code, len })
    }

    /// Placeholder for `asn1ber_request_from_ber`.
    ///
    /// # Errors
    ///
    /// Returns [`BerError::Unsupported`] until request header decoding is migrated.
    pub fn request_from_ber(&mut self) -> BerResult<BerTypeLen> {
        self.typelen_from_ber()
    }

    /// Placeholder for `asn1ber_struct_from_ber`.
    ///
    /// # Errors
    ///
    /// Returns [`BerError::Unsupported`] until structure decoding is migrated.
    pub fn struct_from_ber(&mut self) -> BerResult<u32> {
        let BerTypeLen { type_code, len } = self.typelen_from_ber()?;
        if type_code != BerType::from(ASN_STRUCT) {
            return self.record_error(BerError::InvalidType);
        }
        Ok(len)
    }

    /// Placeholder for `asn1ber_null_from_ber`.
    ///
    /// # Errors
    ///
    /// Returns [`BerError::Unsupported`] until null decoding is migrated.
    pub fn null_from_ber(&mut self) -> BerResult<u32> {
        let BerTypeLen { type_code, len } = self.typelen_from_ber()?;
        if type_code != BerType::NULL {
            return self.record_error(BerError::InvalidType);
        }
        Ok(len)
    }

    /// Decodes a signed 32-bit BER integer value.
    ///
    /// # Errors
    ///
    /// Returns [`BerError::InvalidType`] when the BER tag is not a supported
    /// signed 32-bit integer tag, [`BerError::TooLarge`] when the value length
    /// cannot fit in `i32`, or [`BerError::UnexpectedEof`] when truncated.
    pub fn int32_from_ber(&mut self) -> BerResult<i32> {
        let BerTypeLen { type_code, len } = self.typelen_from_ber()?;
        match type_code {
            BerType::INTEGER | BerType::COUNTER => {
                self.decode_signed_integer(len, 4).map(|v| v as i32)
            }
            _ => self.record_error(BerError::InvalidType),
        }
    }

    /// Decodes an unsigned 32-bit BER integer value.
    ///
    /// # Errors
    ///
    /// Returns [`BerError::InvalidType`] when the BER tag is not a supported
    /// unsigned 32-bit integer tag, [`BerError::TooLarge`] when the value length
    /// cannot fit in `u32`, or [`BerError::UnexpectedEof`] when truncated.
    pub fn uint32_from_ber(&mut self) -> BerResult<u32> {
        let BerTypeLen { type_code, len } = self.typelen_from_ber()?;
        match type_code {
            BerType::BOOLEAN
            | BerType::IPADDRESS
            | BerType::COUNTER
            | BerType::UNSIGNED
            | BerType::TIMETICKS
            | BerType::NSAPADDRESS
            | BerType::UNSIGNED32
            | BerType::ENUMERATED => self.decode_unsigned_integer(len, 4).map(|v| v as u32),
            _ => self.record_error(BerError::InvalidType),
        }
    }

    /// Decodes a signed 64-bit BER integer value.
    ///
    /// # Errors
    ///
    /// Returns [`BerError::InvalidType`] when the BER tag is not a supported
    /// signed 64-bit integer tag, [`BerError::TooLarge`] when the value length
    /// cannot fit in `i64`, or [`BerError::UnexpectedEof`] when truncated.
    pub fn int64_from_ber(&mut self) -> BerResult<i64> {
        let BerTypeLen { type_code, len } = self.typelen_from_ber()?;
        match type_code {
            BerType::INTEGER64 => self.decode_signed_integer(len, 8),
            _ => self.record_error(BerError::InvalidType),
        }
    }

    /// Decodes an unsigned 64-bit BER integer value.
    ///
    /// # Errors
    ///
    /// Returns [`BerError::InvalidType`] when the BER tag is not a supported
    /// unsigned 64-bit integer tag, [`BerError::TooLarge`] when the value length
    /// cannot fit in `u64`, or [`BerError::UnexpectedEof`] when truncated.
    pub fn uint64_from_ber(&mut self) -> BerResult<u64> {
        let BerTypeLen { type_code, len } = self.typelen_from_ber()?;
        match type_code {
            BerType::UNSIGNED64 | BerType::COUNTER64 => self.decode_unsigned_integer(len, 8),
            _ => self.record_error(BerError::InvalidType),
        }
    }

    /// Placeholder for `asn1ber_oid_from_ber`.
    ///
    /// # Errors
    ///
    /// Returns [`BerError::Unsupported`] until OID decoding is migrated.
    pub fn oid_from_ber(&mut self) -> BerResult<Asn1BerOidValue> {
        let BerTypeLen { type_code, len } = self.typelen_from_ber()?;
        if type_code != BerType::OBJECT_ID {
            return self.record_error(BerError::InvalidType);
        }
        if len == 0 || len as usize > BER_MAX_OID_ELEMENTS {
            return self.record_error(BerError::TooLarge);
        }

        let end = self
            .src_tail
            .checked_add(len as usize)
            .ok_or(BerError::TooLarge)?;
        if end > self.src.len() {
            return self.record_error(BerError::UnexpectedEof);
        }

        let first = u32::from(self.next_byte()?);
        let mut oid = Asn1BerOidValue::new();
        oid.elements[0] = first / 40;
        oid.elements[1] = first - oid.elements[0] * 40;
        oid.length = 2;

        while self.src_tail < end {
            if oid.length >= BER_MAX_OID_ELEMENTS {
                return self.record_error(BerError::TooLarge);
            }
            let mut value = 0_u32;
            loop {
                if self.src_tail >= end {
                    return self.record_error(BerError::InvalidValue);
                }
                let byte = self.next_byte()?;
                value = value
                    .checked_shl(7)
                    .and_then(|shifted| shifted.checked_add(u32::from(byte & 0x7f)))
                    .ok_or(BerError::TooLarge)?;
                if byte & 0x80 == 0 {
                    break;
                }
            }
            oid.elements[oid.length] = value;
            oid.length += 1;
        }
        Ok(oid)
    }

    /// Placeholder for `asn1ber_bytes_from_ber`.
    ///
    /// # Errors
    ///
    /// Returns [`BerError::Unsupported`] until octet-string decoding is migrated.
    pub fn bytes_from_ber(&mut self, _max_len: usize) -> BerResult<Vec<u8>> {
        let max_len = _max_len;
        let BerTypeLen { type_code, len } = self.typelen_from_ber()?;
        if type_code != BerType::OCTET_STRING {
            return self.record_error(BerError::InvalidType);
        }
        if len as usize > max_len {
            return self.record_error(BerError::TooLarge);
        }
        let end = self
            .src_tail
            .checked_add(len as usize)
            .ok_or(BerError::TooLarge)?;
        if end > self.src.len() {
            return self.record_error(BerError::UnexpectedEof);
        }
        let value = self.src[self.src_tail..end].to_vec();
        self.src_tail = end;
        Ok(value)
    }

    /// Placeholder for `asn1ber_string_from_ber`.
    ///
    /// # Errors
    ///
    /// Returns [`BerError::Unsupported`] until string decoding is migrated.
    pub fn string_from_ber(&mut self, _max_len: usize) -> BerResult<String> {
        let bytes = self.bytes_from_ber(_max_len)?;
        String::from_utf8(bytes).map_err(|_| BerError::InvalidValue)
    }

    /// Encodes a BER definite length.
    ///
    /// # Errors
    ///
    /// Returns [`BerError::OutputTooSmall`] when the output buffer cannot hold
    /// the encoded length.
    pub fn ber_from_length(&mut self, _len: u32) -> BerResult<usize> {
        let len = _len;
        if len < 128 {
            self.out_byte(len as u8)?;
            return Ok(1);
        }

        let mut lenbytesneeded = 0_u32;
        let mut lenbytes = len;
        while lenbytes != 0 {
            lenbytesneeded += 1;
            lenbytes >>= 8;
        }
        self.out_byte(0x80 | lenbytesneeded as u8)?;
        let mut remaining = lenbytesneeded;
        while remaining > 0 {
            self.out_byte((len >> (8 * (remaining - 1))) as u8)?;
            remaining -= 1;
        }
        Ok(1 + lenbytesneeded as usize)
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
        let type_code = _type_code;
        let len = _len;
        self.out_byte(type_code.value())?;
        let len_bytes = self.ber_from_length(len)?;
        Ok(len_bytes + 1)
    }

    /// Encodes a signed 32-bit value as a minimal BER integer payload.
    ///
    /// # Errors
    ///
    /// Returns [`BerError::OutputTooSmall`] when the output buffer cannot hold
    /// the encoded type, length, and value bytes.
    pub fn ber_from_int32(&mut self, _type_code: BerType, _value: i32) -> BerResult<()> {
        self.encode_signed_integer(_type_code, &_value.to_be_bytes())
    }

    /// Encodes an unsigned 32-bit value as a minimal BER integer payload.
    ///
    /// # Errors
    ///
    /// Returns [`BerError::OutputTooSmall`] when the output buffer cannot hold
    /// the encoded type, length, and value bytes.
    pub fn ber_from_uint32(&mut self, _type_code: BerType, _value: u32) -> BerResult<()> {
        self.encode_unsigned_integer(_type_code, &_value.to_be_bytes())
    }

    /// Encodes a signed 64-bit value as a minimal BER integer payload.
    ///
    /// # Errors
    ///
    /// Returns [`BerError::OutputTooSmall`] when the output buffer cannot hold
    /// the encoded type, length, and value bytes.
    pub fn ber_from_int64(&mut self, _type_code: BerType, _value: i64) -> BerResult<()> {
        self.encode_signed_integer(_type_code, &_value.to_be_bytes())
    }

    /// Encodes an unsigned 64-bit value as a minimal BER integer payload.
    ///
    /// # Errors
    ///
    /// Returns [`BerError::OutputTooSmall`] when the output buffer cannot hold
    /// the encoded type, length, and value bytes.
    pub fn ber_from_uint64(&mut self, _type_code: BerType, _value: u64) -> BerResult<()> {
        self.encode_unsigned_integer(_type_code, &_value.to_be_bytes())
    }

    /// Placeholder for `asn1ber_ber_from_oid`.
    ///
    /// # Errors
    ///
    /// Returns [`BerError::Unsupported`] until OID encoding is migrated.
    pub fn ber_from_oid(&mut self, _oid: &Asn1BerOidValue) -> BerResult<()> {
        let oid = _oid;
        if oid.len() >= BER_MAX_OID_ELEMENTS {
            return self.record_error(BerError::TooLarge);
        }

        let mut encoded = Vec::new();
        if oid.len() > 1 && oid.elements()[0] < 40 {
            encode_oid_component(
                oid.elements()[0]
                    .checked_mul(40)
                    .and_then(|base| base.checked_add(oid.elements()[1]))
                    .ok_or(BerError::TooLarge)?,
                &mut encoded,
            )?;
            for component in &oid.elements()[2..] {
                encode_oid_component(*component, &mut encoded)?;
            }
        } else {
            for component in oid.elements() {
                encode_oid_component(*component, &mut encoded)?;
            }
        }
        if encoded.len() > u32::MAX as usize {
            return self.record_error(BerError::TooLarge);
        }
        self.ber_from_typelen(BerType::OBJECT_ID, encoded.len() as u32)?;
        for byte in encoded {
            self.out_byte(byte)?;
        }
        Ok(())
    }

    /// Placeholder for `asn1ber_ber_from_bytes`.
    ///
    /// # Errors
    ///
    /// Returns [`BerError::Unsupported`] until byte string encoding is migrated.
    pub fn ber_from_bytes(&mut self, _type_code: BerType, _value: &[u8]) -> BerResult<()> {
        let type_code = _type_code;
        let value = _value;
        if value.len() > u32::MAX as usize {
            return self.record_error(BerError::TooLarge);
        }
        self.ber_from_typelen(type_code, value.len() as u32)?;
        for byte in value {
            self.out_byte(*byte)?;
        }
        Ok(())
    }

    /// Placeholder for `asn1ber_ber_from_string`.
    ///
    /// # Errors
    ///
    /// Returns [`BerError::Unsupported`] until string encoding is migrated.
    pub fn ber_from_string(&mut self, value: &str) -> BerResult<()> {
        self.ber_from_bytes(BerType::OCTET_STRING, value.as_bytes())
    }

    fn decode_signed_integer(&mut self, len: u32, max_len: usize) -> BerResult<i64> {
        let len = len as usize;
        if len == 0 || len > max_len {
            return self.record_error(BerError::TooLarge);
        }

        let first = self.next_byte()?;
        let mut value = if first & 0x80 == 0 { 0_i64 } else { -1_i64 };
        value = (value << 8) | i64::from(first);
        for _ in 1..len {
            value = (value << 8) | i64::from(self.next_byte()?);
        }
        Ok(value)
    }

    fn decode_unsigned_integer(&mut self, len: u32, max_len: usize) -> BerResult<u64> {
        let len = len as usize;
        if len == 0 || len > max_len + 1 {
            return self.record_error(BerError::TooLarge);
        }

        let first = self.next_byte()?;
        if len == max_len + 1 && first != 0 {
            return self.record_error(BerError::TooLarge);
        }

        let mut value = u64::from(first);
        for _ in 1..len {
            value = (value << 8) | u64::from(self.next_byte()?);
        }
        Ok(value)
    }

    fn encode_signed_integer(&mut self, type_code: BerType, bytes: &[u8]) -> BerResult<()> {
        let value = minimal_signed_integer_bytes(bytes);
        self.ber_from_typelen(type_code, value.len() as u32)?;
        for byte in value {
            self.out_byte(*byte)?;
        }
        Ok(())
    }

    fn encode_unsigned_integer(&mut self, type_code: BerType, bytes: &[u8]) -> BerResult<()> {
        let value = minimal_unsigned_integer_bytes(bytes);
        let needs_sign_pad = value[0] & 0x80 != 0;
        self.ber_from_typelen(type_code, value.len() as u32 + u32::from(needs_sign_pad))?;
        if needs_sign_pad {
            self.out_byte(0)?;
        }
        for byte in value {
            self.out_byte(*byte)?;
        }
        Ok(())
    }

    fn record_error<T>(&mut self, error: BerError) -> BerResult<T> {
        self.last_error = Some(error);
        Err(error)
    }
}

fn minimal_signed_integer_bytes(bytes: &[u8]) -> &[u8] {
    let mut start = 0;
    while start + 1 < bytes.len() {
        let byte = bytes[start];
        let next = bytes[start + 1];
        if (byte == 0x00 && next & 0x80 == 0) || (byte == 0xff && next & 0x80 != 0) {
            start += 1;
        } else {
            break;
        }
    }
    &bytes[start..]
}

fn minimal_unsigned_integer_bytes(bytes: &[u8]) -> &[u8] {
    let mut start = 0;
    while start + 1 < bytes.len() && bytes[start] == 0 {
        start += 1;
    }
    &bytes[start..]
}

fn encode_oid_component(mut value: u32, out: &mut Vec<u8>) -> BerResult<()> {
    let mut stack = [0_u8; 5];
    let mut count = 0_usize;
    stack[count] = (value & 0x7f) as u8;
    count += 1;
    value >>= 7;
    while value != 0 {
        if count >= stack.len() {
            return Err(BerError::TooLarge);
        }
        stack[count] = ((value & 0x7f) as u8) | 0x80;
        count += 1;
        value >>= 7;
    }
    while count > 0 {
        count -= 1;
        out.push(stack[count]);
    }
    Ok(())
}

/// BER type and length pair returned by tag-length decoding helpers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BerTypeLen {
    /// BER type code.
    pub type_code: BerType,
    /// BER payload length.
    pub len: u32,
}
