//! Parser for header field values.
//!
//! Header field values are delimiter separated sequences of tokens and quoted strings,
//! defined in [RFC 7230](https://tools.ietf.org/html/rfc7230#section-3.2.6).

use bytes::Bytes;
use nom::branch::alt;
use nom::bytes::complete::{escaped, tag, take_while1};
use nom::character::complete::{satisfy, space0};
use nom::combinator::map;
use nom::multi::separated_list0;
use nom::sequence::delimited;
use nom::{Finish, IResult, InputLength};

use super::fields::{Entry, FieldValue, QuotedText, Token};

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

pub(crate) fn token<'a>() -> impl FnMut(&'a [u8]) -> IResult<&'a [u8], Token> {
    map(take_while1(is_token), |t: &[u8]| {
        Token::new(Bytes::copy_from_slice(t))
    })
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
