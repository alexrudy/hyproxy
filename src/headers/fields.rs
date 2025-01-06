//! HTTP header field values.
//!
//! Header field values are delimiter separated sequences of tokens and quoted strings,
//! defined in [RFC 7230](https://tools.ietf.org/html/rfc7230#section-3.2.6).
use core::fmt;

use bytes::Bytes;
use thiserror::Error;

use super::parser::{quoted_text, record, records, token, NoTail as _};

/// Parse a header value into a sequence of field values.
pub fn parse_header(input: &[u8], delimiter: u8) -> Result<Vec<FieldValue>, InvalidValue> {
    records(delimiter)(input)
        .no_tail()
        .map_err(|_| InvalidValue("header", Bytes::copy_from_slice(input)))
}

/// Parse a field value.
pub fn parse_field(input: &[u8]) -> Result<FieldValue, InvalidValue> {
    record()(input)
        .no_tail()
        .map_err(|_| InvalidValue("field", Bytes::copy_from_slice(input)))
}

/// Parse a token.
pub fn parse_token(input: &[u8]) -> Result<Token, InvalidValue> {
    token()(input)
        .no_tail()
        .map_err(|_| InvalidValue("token", Bytes::copy_from_slice(input)))
}

/// Parse a quoted string.
pub fn parse_quoted_string(input: &[u8]) -> Result<QuotedText, InvalidValue> {
    quoted_text(input)
        .no_tail()
        .map_err(|_| InvalidValue("quoted string", Bytes::copy_from_slice(input)))
}

/// Combine field values into a single value, separated by a delimiter.
pub fn combine_values<'a, I>(iter: I, delimiter: u8) -> Vec<u8>
where
    I: IntoIterator<Item = &'a FieldValue>,
{
    iter.into_iter()
        .map(|v| v.as_bytes().to_vec())
        .collect::<Vec<_>>()
        .join([delimiter, b' '].as_slice())
}

/// A single field value component as defined by RFC-7230.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct FieldValue(Entry);

impl FieldValue {
    /// Get the field value as a byte slice.
    pub fn as_bytes(&self) -> &[u8] {
        match &self.0 {
            Entry::Token(token) => token.as_bytes(),
            Entry::QuotedText(quoted) => quoted.as_bytes(),
        }
    }

    /// Get the token (if this is a token).
    pub fn token(&self) -> Option<&Token> {
        match &self.0 {
            Entry::Token(token) => Some(token),
            _ => None,
        }
    }

    /// Get the quoted string (if this is a quoted string).
    pub fn quoted_string(&self) -> Option<&QuotedText> {
        match &self.0 {
            Entry::QuotedText(quoted) => Some(quoted),
            _ => None,
        }
    }

    /// Convert this field value into a token (if it is a token).
    pub fn into_token(self) -> Option<Token> {
        match self.0 {
            Entry::Token(token) => Some(token),
            _ => None,
        }
    }

    /// Convert this field value into a quoted string (if it is a quoted string).
    pub fn into_quoted_string(self) -> Option<QuotedText> {
        match self.0 {
            Entry::QuotedText(quoted) => Some(quoted),
            _ => None,
        }
    }

    /// Get the entry enum.
    pub fn entry(&self) -> &Entry {
        &self.0
    }

    /// Convert this field value into an entry.
    pub fn into_entry(self) -> Entry {
        self.0
    }
}

impl From<Entry> for FieldValue {
    fn from(entry: Entry) -> Self {
        Self(entry)
    }
}

/// A single field value component as defined by RFC-7230.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Entry {
    /// Token form
    Token(Token),

    /// Quoted text form
    QuotedText(QuotedText),
}

/// The key portion of key-value pair in a header field.
#[derive(Debug, Clone)]
pub struct FieldKey(Token);

impl FieldKey {
    /// Create a new field key from a token.
    pub const fn new(token: Token) -> Self {
        Self(token)
    }

    /// Get the field key as a byte slice.
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }

    /// Convert the field key into a byte buffer.
    pub fn into_bytes(self) -> Bytes {
        self.0.into_bytes()
    }

    /// Turn into the inner token.
    pub fn into_token(self) -> Token {
        self.0
    }
}

impl PartialEq for FieldKey {
    fn eq(&self, other: &Self) -> bool {
        self.0.eq_ignore_ascii_case(&other.0)
    }
}

impl Eq for FieldKey {}

impl PartialOrd for FieldKey {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(::std::cmp::Ord::cmp(self, other))
    }
}

impl Ord for FieldKey {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.0.ord_ignore_ascii_case(&other.0)
    }
}

impl From<Token> for FieldKey {
    fn from(token: Token) -> Self {
        Self(token)
    }
}

/// An error indicating that a value was invalid.
#[derive(Debug, Error)]
pub struct InvalidValue(&'static str, Bytes);

impl fmt::Display for InvalidValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Invalid {}: {}",
            self.0,
            String::from_utf8_lossy(&self.1)
        )
    }
}

impl InvalidValue {
    /// Get the value that was invalid.
    pub fn value(&self) -> &[u8] {
        &self.1
    }
}

/// A token is a sequence of characters that are valid in a header field value
/// without quotes or the delimiter character.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub struct Token(Bytes);

impl Token {
    pub(super) fn new(bytes: Bytes) -> Self {
        Self(bytes)
    }

    /// Get the token as a byte slice.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Convert the token into a byte buffer.
    pub fn into_bytes(self) -> Bytes {
        self.0
    }

    /// Create a token from a static string.
    ///
    /// # Panics
    /// If the string contains invalid token characters.
    pub fn from_static(s: &'static str) -> Self {
        parse_token(s.as_bytes()).unwrap()
    }

    /// Parse a token from a byte slice.
    pub fn parse(b: &[u8]) -> Result<Self, InvalidValue> {
        parse_token(b)
    }

    /// Create a token from a static string without checking for invalid characters.
    ///
    /// # Safety
    /// The string must contain only valid token characters, as defined in RFC-7230.
    /// This is NOT all ASCII characters, as some are reserved for delimiters, and does
    /// not support unicode characters.
    pub const fn from_static_unchecked(s: &'static str) -> Self {
        Self(Bytes::from_static(s.as_bytes()))
    }

    /// Check if the token is equal to another token, ignoring ASCII case.
    pub fn eq_ignore_ascii_case(&self, other: &Self) -> bool {
        self.0.eq_ignore_ascii_case(&other.0)
    }

    /// Compare the token to another token, ignoring ASCII case.
    pub fn ord_ignore_ascii_case(&self, other: &Self) -> std::cmp::Ordering {
        self.0
            .to_ascii_lowercase()
            .cmp(&other.0.to_ascii_lowercase())
    }
}

impl fmt::Debug for Token {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Token")
            .field(&String::from_utf8_lossy(&self.0))
            .finish()
    }
}

/// A quoted string is a sequence of characters that are valid in a header field value
/// enclosed in double quotes.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub struct QuotedText(Bytes);

impl QuotedText {
    pub(super) fn new(bytes: Bytes) -> Self {
        Self(bytes)
    }

    /// Get the quoted text as a byte slice.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for QuotedText {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("QuotedText")
            .field(&String::from_utf8_lossy(&self.0))
            .finish()
    }
}
