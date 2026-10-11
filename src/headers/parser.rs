//! Parser for header field values.
//!
//! Header field values are delimiter separated sequences of tokens and quoted strings,
//! defined in [RFC 9110 section 5.6](https://datatracker.ietf.org/doc/html/rfc9110#section-5.6) (formerly RFC 7230).

use bytes::{BufMut, Bytes, BytesMut};
use nom::branch::alt;
use nom::bytes::complete::{escaped, tag, take_while1};
use nom::character::complete::{satisfy, space0};
use nom::combinator::map;
use nom::multi::separated_list0;
use nom::sequence::delimited;
use nom::{Finish, IResult, InputLength};

use super::fields::{Entry, FieldKey, FieldValue, QuotedText, Token};

macro_rules! byte_table {
    ($($c:expr),+ $(,)?) => {
        {
            let mut table = [false; 256];
            $(table[$c as usize] = true;)+
            table
        }

    };
}

const RFC_7230_TOKEN_SPECIAL: [bool; 256] = byte_table![
    b'!', b'#', b'$', b'%', b'&', b'\'', b'*', b'+', b'-', b'.', b'^', b'_', b'`', b'|', b'~'
];

const fn is_token(c: u8) -> bool {
    c.is_ascii_alphanumeric() || RFC_7230_TOKEN_SPECIAL[c as usize]
}

const fn is_valid(c: u8) -> bool {
    c == b' ' || c == b'\t' || (c >= 0x21 && c < 0x7F) || (c > 0x7F)
}

const fn is_visible_ascii(c: u8) -> bool {
    c >= 32 && c < 127 || c == b'\t'
}

const fn is_qd_text(c: u8) -> bool {
    is_valid(c) && c != b'\\' && c != b'"'
}

const fn is_escapable(c: u8) -> bool {
    c == b'\t' || c == b' ' || is_visible_ascii(c)
}

fn byte<'f, F>(cond: F) -> impl Fn(&'f [u8]) -> IResult<&'f [u8], char>
where
    F: Fn(u8) -> bool + Copy,
{
    satisfy(move |c| c.try_into().is_ok_and(cond))
}

fn qd_text(v: &[u8]) -> IResult<&[u8], &[u8]> {
    escaped(take_while1(is_qd_text), '\\', byte(is_escapable))(v)
}

pub(crate) fn quoted_text(v: &[u8]) -> IResult<&[u8], QuotedText> {
    delimited(
        tag(b"\""),
        map(qd_text, |q| QuotedText::new(Bytes::copy_from_slice(q))),
        tag(b"\""),
    )(v)
}

#[cfg(test)]
mod test_quoted {
    use super::*;

    #[test]
    fn escapable_predicates() {
        assert!(!is_qd_text(b'\\'));
        assert!(!is_qd_text(b'"'));

        assert!(is_escapable(b' '));
        assert!(is_escapable(b'"'));
        assert!(is_escapable(b't'));
        assert!(is_escapable(b'\\'));
    }

    #[test]
    fn qd_text_valid() {
        let input = b"abc";
        qd_text(input).no_tail().unwrap();

        let input = b"\tabc";
        qd_text(input).no_tail().unwrap();

        let input = br#"abc\"d"#;
        qd_text(input).no_tail().unwrap();
    }

    #[test]
    fn quoted() {
        let input = b"\"abc\"";
        quoted_text(input).no_tail().unwrap();

        let input = br#""abc\"""#;
        quoted_text(input).no_tail().unwrap();
    }
}

/// Write `value` as an RFC 9110 field value: bare if it is a valid token,
/// otherwise as a quoted-string with `"` and `\` escaped.
pub(crate) fn put_field_value(buf: &mut BytesMut, value: &[u8]) {
    if !value.is_empty() && value.iter().all(|c| is_token(*c)) {
        buf.put(value);
        return;
    }

    buf.put_u8(b'"');
    for &c in value {
        if c == b'"' || c == b'\\' {
            buf.put_u8(b'\\');
        }
        buf.put_u8(c);
    }
    buf.put_u8(b'"');
}

#[cfg(test)]
mod test_put_field_value {
    use super::*;

    fn encode(value: &[u8]) -> Vec<u8> {
        let mut buf = BytesMut::new();
        put_field_value(&mut buf, value);
        buf.to_vec()
    }

    #[test]
    fn token_is_bare() {
        assert_eq!(encode(b"example.com"), b"example.com");
        assert_eq!(encode(b"_hidden"), b"_hidden");
    }

    #[test]
    fn non_token_is_quoted() {
        assert_eq!(encode(b"example.com:8080"), b"\"example.com:8080\"");
        assert_eq!(encode(b"[::1]"), b"\"[::1]\"");
        assert_eq!(encode(b"a, b"), b"\"a, b\"");
        assert_eq!(encode(b""), b"\"\"");
    }

    #[test]
    fn escapes_quote_and_backslash() {
        assert_eq!(encode(br#"a"b\c"#), br#""a\"b\\c""#);
    }

    #[test]
    fn quoted_output_parses_back() {
        for value in [&b"example.com:8080"[..], b"a, b", br#"a"b\c"#] {
            let encoded = encode(value);
            let parsed = quoted_text(&encoded).no_tail().unwrap();
            // Parsed quoted text keeps escapes; compare against the encoded interior.
            assert_eq!(parsed.as_bytes(), &encoded[1..encoded.len() - 1]);
        }
    }
}

pub(crate) fn token<'a>() -> impl FnMut(&'a [u8]) -> IResult<&'a [u8], Token> {
    map(take_while1(is_token), |t: &[u8]| {
        Token::new(Bytes::copy_from_slice(t))
    })
}

pub(crate) fn key<'a>() -> impl FnMut(&'a [u8]) -> IResult<&'a [u8], FieldKey> {
    map(token(), FieldKey::new)
}

#[cfg(test)]
mod test_token {
    use super::*;

    #[test]
    fn token_check() {
        let input = b"abc";
        token()(input).no_tail().unwrap();

        let input = b"abc123";
        token()(input).no_tail().unwrap();

        let input = b"abc!#";
        token()(input).no_tail().unwrap();

        let input = b"";
        assert!(token()(input).no_tail().is_err());
    }
}

pub(crate) fn record<'v>() -> impl FnMut(&'v [u8]) -> IResult<&'v [u8], FieldValue> {
    map(
        alt((
            map(quoted_text, Entry::QuotedText),
            map(token(), Entry::Token),
        )),
        Into::into,
    )
}

pub(crate) fn strip_whitespace<'v, F, O>(parser: F) -> impl FnMut(&'v [u8]) -> IResult<&'v [u8], O>
where
    F: FnMut(&'v [u8]) -> IResult<&'v [u8], O>,
{
    delimited(space0, parser, space0)
}

pub(crate) fn records<'v>(
    delimiter: u8,
) -> impl FnMut(&'v [u8]) -> IResult<&'v [u8], Vec<FieldValue>> {
    let d = [delimiter];
    move |v| {
        let one_record = strip_whitespace(record());
        separated_list0(tag(&d[..]), one_record)(v)
    }
}

#[cfg(test)]
mod test_record {
    use super::*;

    #[test]
    fn record_check() {
        let input = b"abc";
        record()(input).no_tail().unwrap();

        let input = b"\"abc\"";
        record()(input).no_tail().unwrap();
    }

    #[test]
    fn records_check() {
        let input = b"abc, \"def\"";
        records(b',')(input).no_tail().unwrap();

        let input = b"abc, \"def\",";
        records(b',')(input).no_tail().unwrap_err();

        let input = b"abc, \"def\"   ";
        assert_eq!(records(b',')(input).no_tail().unwrap().len(), 2);
    }
}

pub(crate) trait NoTail<O, E> {
    fn no_tail(self) -> Result<O, E>;
}

impl<I, O> NoTail<O, nom::error::Error<I>> for IResult<I, O>
where
    I: InputLength,
{
    fn no_tail(self) -> Result<O, nom::error::Error<I>> {
        match self.finish() {
            Ok((i, o)) if i.input_len() == 0 => Ok(o),
            Ok((i, _)) => Err(nom::error::Error::new(i, nom::error::ErrorKind::Eof)),
            Err(e) => Err(e),
        }
    }
}

impl<I, O> NoTail<O, nom::error::Error<I>> for Result<(I, O), nom::error::Error<I>>
where
    I: InputLength,
{
    fn no_tail(self) -> Result<O, nom::error::Error<I>> {
        match self {
            Ok((i, o)) if i.input_len() == 0 => Ok(o),
            Ok((i, _)) => Err(nom::error::Error::new(i, nom::error::ErrorKind::Eof)),
            Err(e) => Err(e),
        }
    }
}
