//! Rust string formatting counterparts for `include/asprintf.h`.
//!
//! The C header provides `asprintf` and `vasprintf` helpers that allocate a
//! buffer large enough for formatted output and return the number of bytes
//! written. This module models that responsibility with Rust-owned [`String`]
//! values and [`core::fmt::Arguments`], without attempting to expose or emulate
//! C varargs.

use core::fmt;

/// Result type used by the Rust `asprintf` formatting helpers.
pub type Result<T> = core::result::Result<T, FormatError>;

/// Error returned when Rust formatting fails before a string can be produced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FormatError;

impl fmt::Display for FormatError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("formatting failed")
    }
}

impl std::error::Error for FormatError {}

/// Rust-owned formatted output mirroring the successful `asprintf` result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FormattedString {
    output: String,
    bytes_written: usize,
}

impl FormattedString {
    /// Creates a formatted output value from an owned string.
    #[must_use]
    pub fn new(output: String) -> Self {
        let bytes_written = output.len();
        Self {
            output,
            bytes_written,
        }
    }

    /// Returns the number of UTF-8 bytes written to the string.
    #[must_use]
    pub fn bytes_written(&self) -> usize {
        self.bytes_written
    }

    /// Returns the formatted string as a borrowed `str`.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.output
    }

    /// Consumes this value and returns the formatted string.
    #[must_use]
    pub fn into_string(self) -> String {
        self.output
    }
}

/// Formats arguments into a newly allocated [`String`].
///
/// This is the Rust-facing counterpart of C `vasprintf`: the caller supplies an
/// already-built [`fmt::Arguments`] value instead of a C `va_list`, and the
/// result owns the allocated string buffer.
///
/// # Errors
///
/// Returns [`FormatError`] if the formatter reports a formatting failure.
pub fn vasprintf(args: fmt::Arguments<'_>) -> Result<FormattedString> {
    let mut output = String::new();
    fmt::write(&mut output, args).map_err(|_| FormatError)?;
    Ok(FormattedString::new(output))
}

/// Formats arguments into a newly allocated [`String`].
///
/// This is the Rust-facing counterpart of C `asprintf`. It intentionally does
/// not model C varargs; use [`format_args!`] at the call site to construct the
/// argument list.
///
/// # Errors
///
/// Returns [`FormatError`] if the formatter reports a formatting failure.
pub fn asprintf(args: fmt::Arguments<'_>) -> Result<FormattedString> {
    vasprintf(args)
}
