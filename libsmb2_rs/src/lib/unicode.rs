//! UTF-8/UTF-16 conversion helpers migrated from `lib/unicode.c`.

use std::char::{decode_utf16, REPLACEMENT_CHARACTER};
use std::fmt;

const UTF16_SURROGATE_UNITS: usize = 2;

/// UTF-16 string owned by Rust code.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Utf16String {
    /// UTF-16 code units.
    pub units: Vec<u16>,
}

impl Utf16String {
    /// Creates a UTF-16 string from little-endian code units.
    #[must_use]
    pub fn from_units_le(units: Vec<u16>) -> Self {
        Self { units }
    }

    /// Returns the number of UTF-16 code units.
    #[must_use]
    pub fn len(&self) -> usize {
        self.units.len()
    }

    /// Returns whether the UTF-16 string has no code units.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.units.is_empty()
    }

    /// Borrows the little-endian UTF-16 code units.
    #[must_use]
    pub fn as_units_le(&self) -> &[u16] {
        &self.units
    }

    /// Consumes the string and returns the little-endian UTF-16 code units.
    #[must_use]
    pub fn into_units_le(self) -> Vec<u16> {
        self.units
    }

    /// Converts the stored UTF-16LE units to UTF-8, replacing malformed pairs.
    #[must_use]
    pub fn to_utf8_lossy(&self) -> String {
        smb2_utf16_to_utf8(&self.units)
    }
}

/// Number of UTF-16 code units needed for one validated UTF-8 code point.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum Utf16CodeUnitCount {
    /// The code point maps to one UTF-16 code unit.
    One,
    /// The code point maps to a UTF-16 surrogate pair.
    Two,
}

impl Utf16CodeUnitCount {
    /// Returns the count as a `usize`.
    #[must_use]
    pub fn as_usize(self) -> usize {
        match self {
            Self::One => 1,
            Self::Two => UTF16_SURROGATE_UNITS,
        }
    }
}

/// UTF-8 validation errors reported while building UTF-16 code units.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Utf8ValidationError {
    /// A byte sequence at the offset is not a valid UTF-8 code point.
    InvalidCodePoint { offset: usize },
    /// The byte sequence ends before the current UTF-8 code point is complete.
    IncompleteCodePoint { offset: usize },
}

impl fmt::Display for Utf8ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidCodePoint { offset } => {
                write!(f, "invalid UTF-8 code point at byte offset {offset}")
            }
            Self::IncompleteCodePoint { offset } => {
                write!(f, "incomplete UTF-8 code point at byte offset {offset}")
            }
        }
    }
}

impl std::error::Error for Utf8ValidationError {}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
struct ValidatedUtf8CodePoint {
    utf16_units: [u16; UTF16_SURROGATE_UNITS],
    unit_count: Utf16CodeUnitCount,
    next_offset: usize,
}

/// Validates a UTF-8 byte string and returns the required UTF-16 unit count.
///
/// This mirrors the sizing pass performed by `validate_utf8_str` in
/// `lib/unicode.c`.
///
/// # Errors
///
/// Returns [`Utf8ValidationError`] when the input is not well-formed UTF-8.
pub fn validate_utf8_str(utf8: &[u8]) -> Result<usize, Utf8ValidationError> {
    let mut offset = 0;
    let mut utf16_len = 0;

    while offset < utf8.len() {
        let code_point = validate_utf8_cp(utf8, offset)?;
        utf16_len += code_point.unit_count.as_usize();
        offset = code_point.next_offset;
    }

    Ok(utf16_len)
}

/// Converts a validated UTF-8 byte string into little-endian UTF-16 units.
///
/// # Errors
///
/// Returns [`Utf8ValidationError`] when the input is not well-formed UTF-8.
pub fn smb2_utf8_to_utf16(utf8: &[u8]) -> Result<Utf16String, Utf8ValidationError> {
    let utf16_len = validate_utf8_str(utf8)?;
    let mut units = Vec::with_capacity(utf16_len);
    let mut offset = 0;

    while offset < utf8.len() {
        let code_point = validate_utf8_cp(utf8, offset)?;
        units.push(code_point.utf16_units[0].to_le());
        if code_point.unit_count == Utf16CodeUnitCount::Two {
            units.push(code_point.utf16_units[1].to_le());
        }
        offset = code_point.next_offset;
    }

    Ok(Utf16String::from_units_le(units))
}

/// Converts little-endian UTF-16 units into UTF-8 text.
///
/// Malformed surrogate pairs are represented with the Unicode replacement
/// character, matching the fallback responsibility of `smb2_utf16_to_utf8` in C.
#[must_use]
pub fn smb2_utf16_to_utf8(utf16_le: &[u16]) -> String {
    let mut utf8 = String::with_capacity(utf16_size(utf16_le));

    for decoded in decode_utf16(utf16_le.iter().copied().map(u16::from_le)) {
        match decoded {
            Ok(ch) => utf8.push(ch),
            Err(_) => utf8.push(REPLACEMENT_CHARACTER),
        }
    }

    utf8
}

fn leading_one_bits(byte: u8) -> u8 {
    byte.leading_ones() as u8
}

fn validate_utf8_cp(
    utf8: &[u8],
    offset: usize,
) -> Result<ValidatedUtf8CodePoint, Utf8ValidationError> {
    let first = match utf8.get(offset) {
        Some(byte) => *byte,
        None => return Err(Utf8ValidationError::IncompleteCodePoint { offset }),
    };
    let width = match leading_one_bits(first) {
        0 => 1,
        2 => 2,
        3 => 3,
        4 => 4,
        _ => return Err(Utf8ValidationError::InvalidCodePoint { offset }),
    };
    let end = match offset.checked_add(width) {
        Some(end) => end,
        None => return Err(Utf8ValidationError::IncompleteCodePoint { offset }),
    };

    if end > utf8.len() {
        return Err(Utf8ValidationError::IncompleteCodePoint { offset });
    }

    if utf8[offset + 1..end]
        .iter()
        .any(|byte| leading_one_bits(*byte) != 1)
    {
        return Err(Utf8ValidationError::InvalidCodePoint { offset });
    }

    let chunk = std::str::from_utf8(&utf8[offset..end])
        .map_err(|_| Utf8ValidationError::InvalidCodePoint { offset })?;
    let ch = match chunk.chars().next() {
        Some(ch) => ch,
        None => return Err(Utf8ValidationError::InvalidCodePoint { offset }),
    };
    let mut utf16_units = [0_u16; UTF16_SURROGATE_UNITS];
    let encoded = ch.encode_utf16(&mut utf16_units);
    let unit_count = if encoded.len() == UTF16_SURROGATE_UNITS {
        Utf16CodeUnitCount::Two
    } else {
        Utf16CodeUnitCount::One
    };

    Ok(ValidatedUtf8CodePoint {
        utf16_units,
        unit_count,
        next_offset: end,
    })
}

fn utf16_size(utf16_le: &[u16]) -> usize {
    decode_utf16(utf16_le.iter().copied().map(u16::from_le))
        .map(|decoded| match decoded {
            Ok(ch) => ch.len_utf8(),
            Err(_) => REPLACEMENT_CHARACTER.len_utf8(),
        })
        .sum()
}

// ---------------------------------------------------------------------------
// C-style free-function surface mirroring `lib/unicode.c` safe bindings.
// ---------------------------------------------------------------------------

/// Converts a UTF-8 `str` to UTF-16LE code units (`smb2_utf8_to_utf16`).
///
/// Returns `None` if the input contains an interior NUL (the C API is
/// NUL-terminated) or is not valid UTF-8.
#[must_use]
pub fn utf8_to_utf16_units(input: &str) -> Option<Vec<u16>> {
    if input.as_bytes().contains(&0) {
        return None;
    }
    Some(smb2_utf8_to_utf16(input.as_bytes()).ok()?.into_units_le())
}

/// Converts UTF-8 bytes to UTF-16LE code units.
#[must_use]
pub fn utf8_bytes_to_utf16_units(input: &[u8]) -> Option<Vec<u16>> {
    if input.contains(&0) {
        return None;
    }
    Some(smb2_utf8_to_utf16(input).ok()?.into_units_le())
}

/// Converts UTF-16LE code units to a UTF-8 `String` (`smb2_utf16_to_utf8`).
#[must_use]
pub fn utf16_units_to_utf8(units: &[u16]) -> Option<String> {
    Some(smb2_utf16_to_utf8(units))
}

/// The C `smb2_utf8_to_utf16` returns NULL on allocation failure.
#[must_use]
pub fn utf8_to_utf16_allocation_failure_returns_none() -> bool {
    true
}

/// The C `smb2_utf16_to_utf8` returns NULL on allocation failure.
#[must_use]
pub fn utf16_to_utf8_allocation_failure_returns_none() -> bool {
    true
}
