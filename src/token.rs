use core::fmt;
use std::{ops, str::FromStr};

use thiserror::Error;

const RFC_7230_TOKEN_SPECIAL: [char; 15] = [
    '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~',
];

pub(crate) fn is_rfc7230_token(item: &str) -> bool {
    item.chars()
        .all(|c| c.is_ascii_alphanumeric() || RFC_7230_TOKEN_SPECIAL.contains(&c))
}

#[derive(Debug, Error, PartialEq, Eq, Clone)]
#[error("invalid RFC-7230 token")]
pub struct InvalidToken(pub String);

/// A token as defined by RFC-7230.
#[derive(Debug, PartialEq, Eq, Clone, PartialOrd, Ord, Hash)]
pub struct Token(String);

impl fmt::Display for Token {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

macro_rules! token_equals_ord {
    ($target:ty, $expr:expr) => {
        impl PartialEq<$target> for Token {
            fn eq(&self, other: &$target) -> bool {
                let value = $expr(other);
                self.0 == value
            }
        }

        impl PartialEq<Token> for $target {
            fn eq(&self, other: &Token) -> bool {
                let value = $expr(self);
                value == other.0
            }
        }

        impl PartialOrd<$target> for Token {
            fn partial_cmp(&self, other: &$target) -> Option<std::cmp::Ordering> {
                let value = $expr(other);
                self.0.as_str().partial_cmp(value)
            }
        }

        impl PartialOrd<Token> for $target {
            fn partial_cmp(&self, other: &Token) -> Option<std::cmp::Ordering> {
                let value = $expr(self);
                value.partial_cmp(other.0.as_str())
            }
        }
    };
}

fn token_str(value: &str) -> &str {
    value
}

fn token_deref_str<'a>(value: &&'a str) -> &'a str {
    value
}

fn token_deref_string<'a>(value: &&'a String) -> &'a str {
    value
}

token_equals_ord!(str, token_str);
token_equals_ord!(&str, token_deref_str);
token_equals_ord!(String, token_str);
token_equals_ord!(&String, token_deref_string);

impl ops::Deref for Token {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        self.0.as_str()
    }
}

impl TryFrom<String> for Token {
    type Error = InvalidToken;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        if is_rfc7230_token(&value) {
            Ok(Token(value))
        } else {
            Err(InvalidToken(value.to_string()))
        }
    }
}

impl TryFrom<&str> for Token {
    type Error = InvalidToken;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        if is_rfc7230_token(value) {
            Ok(Token(value.to_string()))
        } else {
            Err(InvalidToken(value.to_string()))
        }
    }
}

impl From<Token> for String {
    fn from(value: Token) -> Self {
        value.0
    }
}

impl FromStr for Token {
    type Err = InvalidToken;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if is_rfc7230_token(value) {
            Ok(Token(value.to_string()))
        } else {
            Err(InvalidToken(value.to_string()))
        }
    }
}

/// A quoted string as defined by RFC-7230.
#[derive(Debug, PartialEq, Eq, Clone, Hash)]
pub struct QuotedString(String);

impl QuotedString {
    pub fn into_inner(self) -> String {
        self.0
    }

    pub fn consume(value: &str) -> Result<(QuotedString, &str), InvalidToken> {
        take_quoted_string(value)
            .map(|(value, rest)| (QuotedString(value.to_string()), rest))
            .ok_or_else(|| InvalidToken(value.to_string()))
    }
}

impl fmt::Display for QuotedString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "\"{}\"", self.0)
    }
}

impl ops::Deref for QuotedString {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        self.0.as_str()
    }
}

pub(crate) const fn is_valid(c: u8) -> bool {
    c == b' ' || c == b'\t' || (c > 0x21 && c < 0x7F) || (c > 0x7F)
}

pub(crate) const fn is_visible_ascii(c: u8) -> bool {
    c >= 32 && c < 127 || c == b'\t'
}

const fn is_qd_text(c: u8) -> bool {
    is_valid(c) && c != b'\\' && c != b'"'
}

const fn is_escapable(second: u8) -> bool {
    second == b'\t' || second == b' ' || is_visible_ascii(second)
}

#[allow(dead_code)]
pub fn is_quoted_string(value: &str) -> bool {
    let mut chars = value.bytes();
    let nbytes = chars.len();

    if nbytes < 2 {
        return false;
    }

    if chars.next() != Some(b'"') {
        return false;
    }

    if value.bytes().last() != Some(b'"') {
        return false;
    }

    if nbytes == 2 {
        return true;
    }

    let mut escaped = false;

    for c in chars.take(nbytes - 2) {
        if escaped {
            if !is_escapable(c) {
                return false;
            }
            escaped = false;
        } else if c == b'\\' {
            escaped = true;
        } else if !is_qd_text(c) {
            return false;
        }
    }

    !escaped
}

fn take_quoted_string(value: &str) -> Option<(&str, &str)> {
    let mut chars = value.bytes().enumerate();

    if chars.next() != Some((0, b'"')) {
        return None;
    }

    let mut escaped = false;

    for (i, c) in chars {
        if escaped {
            if !is_escapable(c) {
                return None;
            }
            escaped = false;
        } else if c == b'\\' {
            escaped = true;
        } else if c == b'"' {
            return Some((&value[1..i], &value[i + 1..]));
        } else if !is_qd_text(c) {
            return None;
        }
    }

    if escaped {
        return None;
    }

    let n = value.len();

    Some((&value[1..n - 1], ""))
}

impl TryFrom<String> for QuotedString {
    type Error = InvalidToken;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        if let Some((part, "")) = take_quoted_string(&value) {
            Ok(QuotedString(part.to_string()))
        } else {
            Err(InvalidToken(value))
        }
    }
}

impl FromStr for QuotedString {
    type Err = InvalidToken;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if let Some((part, "")) = take_quoted_string(value) {
            Ok(QuotedString(part.to_string()))
        } else {
            Err(InvalidToken(value.to_string()))
        }
    }
}

/// A field value component as defined by RFC-7230.
#[derive(Debug, PartialEq, Eq, Clone, Hash)]
pub enum FieldValue {
    Token(Token),
    QuotedString(QuotedString),
}

impl fmt::Display for FieldValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FieldValue::Token(value) => value.fmt(f),
            FieldValue::QuotedString(value) => value.fmt(f),
        }
    }
}

impl AsRef<str> for FieldValue {
    fn as_ref(&self) -> &str {
        match self {
            FieldValue::Token(value) => value.as_ref(),
            FieldValue::QuotedString(value) => value.as_ref(),
        }
    }
}

impl From<QuotedString> for FieldValue {
    fn from(value: QuotedString) -> Self {
        FieldValue::QuotedString(value)
    }
}

impl From<Token> for FieldValue {
    fn from(value: Token) -> Self {
        FieldValue::Token(value)
    }
}

impl FromStr for FieldValue {
    type Err = InvalidToken;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        value
            .parse::<Token>()
            .map(FieldValue::Token)
            .or_else(|_| value.parse::<QuotedString>().map(FieldValue::QuotedString))
    }
}

#[cfg(test)]
mod tests {

    mod quoted {
        use super::super::*;

        #[test]
        fn test_is_quoted_string() {
            assert!(is_quoted_string("\"\""));
            assert!(is_quoted_string("\"\\\"\""));
            assert!(is_quoted_string("\"\\t\""));
            assert!(is_quoted_string("\" \""));
            assert!(is_quoted_string("\"\\t \""));

            assert!(!is_quoted_string("\""));
            assert!(!is_quoted_string("\"\\\""));
            assert!(!is_quoted_string("\"\\t"));
        }

        #[test]
        fn parse_quoted_string() {
            assert_eq!("\"\"".parse(), Ok(QuotedString("".to_string())));
            assert_eq!("\"\\\"\"".parse(), Ok(QuotedString("\\\"".to_string())));
            assert_eq!("\"\\t\"".parse(), Ok(QuotedString("\\t".to_string())));
            assert_eq!("\" \"".parse(), Ok(QuotedString(" ".to_string())));
            assert_eq!("\"\\t \"".parse(), Ok(QuotedString("\\t ".to_string())));
        }

        #[test]
        fn consume_quoted_string() {
            assert_eq!(
                QuotedString::consume("\"\""),
                Ok((QuotedString("".to_string()), ""))
            );
            assert_eq!(
                QuotedString::consume("\"\\\"\""),
                Ok((QuotedString("\\\"".to_string()), ""))
            );
            assert_eq!(
                QuotedString::consume("\"\\t\""),
                Ok((QuotedString("\\t".to_string()), ""))
            );
            assert_eq!(
                QuotedString::consume("\" \" blah"),
                Ok((QuotedString(" ".to_string()), " blah"))
            );
            assert_eq!(
                QuotedString::consume("\"\\t \" foo  \""),
                Ok((QuotedString("\\t ".to_string()), " foo  \""))
            );
        }
    }
}
