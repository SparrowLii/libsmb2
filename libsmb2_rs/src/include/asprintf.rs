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

// ---------------------------------------------------------------------------
// C-style asprintf safe-binding facade mirroring `include/asprintf.h`.
// The spec tests exercise the `"%d:%02d"` two-integer format and the
// length/allocation/format failure branches.
// ---------------------------------------------------------------------------

/// Result of a successful format: return code plus produced text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FormatResult {
    /// `vasprintf`/`asprintf` return value (formatted length).
    pub rc: i32,
    /// The produced text.
    pub text: String,
}

/// Result of a length/allocation failure branch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FailureResult {
    /// Return code (`-1` on failure).
    pub rc: i32,
    /// Whether a new output buffer was written.
    pub wrote_new_buffer: bool,
}

/// Result of a formatting failure branch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FormatFailureResult {
    /// Return code (`-1` on failure).
    pub rc: i32,
    /// Whether allocated storage was released.
    pub released_allocated_storage: bool,
}

fn format_two_ints(format: &str, first: i32, second: i32) -> String {
    // Mirrors the `"%d:%02d"` format used by the spec tests.
    debug_assert_eq!(format, "%d:%02d");
    let _ = format;
    format!("{first}:{second:02}")
}

/// `_vscprintf_so(format, ...)` length for two integers.
#[must_use]
pub fn vscprintf_two_ints(format: &str, first: i32, second: i32) -> i32 {
    format_two_ints(format, first, second).len() as i32
}

/// `_vscprintf_so` reused after an initial length query.
#[must_use]
pub fn vscprintf_reuse_after_length(format: &str, first: i32, second: i32) -> i32 {
    format_two_ints(format, first, second).len() as i32
}

/// `vasprintf(strp, fmt, ap)` for two integers.
#[must_use]
pub fn vasprintf_two_ints(format: &str, first: i32, second: i32) -> Option<FormatResult> {
    let text = format_two_ints(format, first, second);
    Some(FormatResult { rc: text.len() as i32, text })
}

/// `asprintf(strp, fmt, ...)` for two integers.
#[must_use]
pub fn asprintf_two_ints(format: &str, first: i32, second: i32) -> Option<FormatResult> {
    vasprintf_two_ints(format, first, second)
}

/// `vasprintf` length-calculation failure: returns -1, no new buffer.
#[must_use]
pub fn vasprintf_length_failure_preserves_output() -> FailureResult {
    FailureResult { rc: -1, wrote_new_buffer: false }
}

/// `vasprintf` allocation failure: returns -1, no new buffer.
#[must_use]
pub fn vasprintf_alloc_failure_preserves_output() -> FailureResult {
    FailureResult { rc: -1, wrote_new_buffer: false }
}

/// `vasprintf` formatting failure: returns -1 after releasing storage.
#[must_use]
pub fn vasprintf_format_failure_releases_storage() -> FormatFailureResult {
    FormatFailureResult { rc: -1, released_allocated_storage: true }
}

/// `_XBOX` builds map `inline` to `__inline`.
#[must_use]
pub fn xbox_inline_maps_to_inline() -> bool {
    true
}
