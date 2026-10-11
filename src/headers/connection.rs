//! Handle connection headers.
//!
//! The `Connection` header lists connection options, and names other headers which apply only
//! to the current connection
//! ([RFC 9110 section 7.6.1](https://datatracker.ietf.org/doc/html/rfc9110#section-7.6.1)).
//!
//! [`ConnectionHeader`] parses the entries of a `Connection` header, for use with a
//! [`HeaderChain`]. To remove connection-scoped headers before
//! forwarding a message, use [`StripHopByHop`](super::hopby::StripHopByHop).

use bytes::Bytes;
use nom::character::complete::{char, space0};
use nom::combinator::{map, opt};
use nom::multi::many0;
use nom::sequence::{delimited, pair, preceded};
use nom::IResult;
use thiserror::Error;

use super::chain::{HeaderChain, HeaderRecordKind, RecordEntry};
use super::parser::NoTail;

/// Close is a pseudo-header that can appear in the CONNECTION header's value,
/// indicating that the other side would like to close the connection after this request.
pub const CLOSE: http::HeaderName = http::HeaderName::from_static("close");

/// The HTTP UPGRADE header.
pub const UPGRADE: http::HeaderName = http::header::UPGRADE;

/// The HTTP CONNECTION header.
pub const CONNECTION: http::HeaderName = http::header::CONNECTION;

/// The `Connection: upgrade` header value.
pub(crate) const CONNECTION_UPGRADE: http::HeaderValue = http::HeaderValue::from_static("upgrade");

/// A header named in `CONNECTION`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ConnectionHeader {
    header: http::HeaderName,
}

impl ConnectionHeader {
    /// Create a new connection header.
    pub fn new(header: http::HeaderName) -> Self {
        Self { header }
    }

    /// The header name.
    pub fn header(&self) -> &http::HeaderName {
        &self.header
    }

    /// Check if the header is a close header.
    pub fn is_close(&self) -> bool {
        self.header == CLOSE
    }

    /// Check if the header is an upgrade header.
    pub fn is_upgrade(&self) -> bool {
        self.header == UPGRADE
    }
}

/// An error occurred while parsing connection headers.
#[derive(Debug, Error)]
#[error("Failed to parse connection header: {0:?}")]
pub struct ConnectionHeaderParseError(nom::error::Error<Bytes>);

impl HeaderRecordKind for ConnectionHeader {
    const HEADER_NAME: http::header::HeaderName = http::header::CONNECTION;

    const DELIMITER: u8 = b',';

    type Error = ConnectionHeaderParseError;

    fn into_bytes(self) -> Vec<u8> {
        self.header.as_str().as_bytes().to_vec()
    }

    fn parse_header_value(
        header: &http::HeaderValue,
    ) -> Result<Vec<super::chain::Record<Self>>, Self::Error> {
        parser(header.as_bytes())
            .no_tail()
            .map(|headers| headers.into_iter().map(Into::into).collect())
            .map_err(|error| {
                ConnectionHeaderParseError(nom::error::Error::new(
                    Bytes::copy_from_slice(error.input),
                    error.code,
                ))
            })
    }
}

/// Parse `Connection = #connection-option`, where `connection-option = token`.
///
/// Empty list elements (`a, , b`) are accepted and ignored, as RFC 9110 section 5.6.1.2
/// requires of recipients.
fn parser(input: &[u8]) -> IResult<&[u8], Vec<ConnectionHeader>> {
    let option = || {
        map(super::parser::token(), |token| {
            http::HeaderName::from_bytes(token.as_bytes())
                .expect("every RFC 9110 token is a valid header name")
                .into()
        })
    };
    let separator = || delimited(space0, char(','), space0);

    map(
        delimited(
            space0,
            pair(opt(option()), many0(preceded(separator(), opt(option())))),
            space0,
        ),
        |(first, rest)| {
            first
                .into_iter()
                .chain(rest.into_iter().flatten())
                .collect()
        },
    )(input)
}

/// All connection options named in every `Connection` header line, as header names (and
/// so compared case-insensitively).
pub(crate) fn connection_options(headers: &http::HeaderMap) -> Vec<http::HeaderName> {
    let mut names = Vec::new();
    for record in HeaderChain::<ConnectionHeader>::from_headers(headers).flat_iter() {
        match record.entry() {
            RecordEntry::Value(option) => names.push(option.header().clone()),
            // Be lenient with lines that don't parse: still use any names they contain.
            RecordEntry::Raw(raw) => names.extend(
                raw.split(|&c| c == b',')
                    .filter_map(|name| http::HeaderName::from_bytes(name.trim_ascii()).ok()),
            ),
        }
    }
    names
}

/// Whether the message requests an upgrade: `Connection` includes `upgrade`, and an
/// `Upgrade` header is present.
pub(crate) fn is_upgrade(headers: &http::HeaderMap) -> bool {
    headers.contains_key(UPGRADE) && connection_options(headers).contains(&UPGRADE)
}

impl From<http::HeaderName> for ConnectionHeader {
    fn from(header: http::HeaderName) -> Self {
        Self { header }
    }
}

impl TryFrom<http::HeaderValue> for ConnectionHeader {
    type Error = http::header::InvalidHeaderName;

    fn try_from(value: http::HeaderValue) -> Result<Self, Self::Error> {
        http::HeaderName::from_bytes(value.as_bytes()).map(Into::into)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::headers::chain::{HeaderChain, IntoRecordValue as _};

    #[test]
    fn parse_connection_headers() {
        let headers = parser(b"close, upgrade").no_tail().unwrap();
        assert_eq!(headers.len(), 2);
        assert_eq!(headers[0].header(), http::HeaderName::from_static("close"));
        assert!(headers[0].is_close());
        assert_eq!(headers[1].header(), http::header::UPGRADE);
        assert!(headers[1].is_upgrade());
    }

    #[test]
    fn parse_connection_headers_case_insensitive() {
        let headers = parser(b"Keep-Alive, UPGRADE").no_tail().unwrap();
        assert_eq!(headers[0].header(), "keep-alive");
        assert!(headers[1].is_upgrade());
    }

    #[test]
    fn parse_connection_headers_empty_elements() {
        for input in [&b""[..], b",", b" a , , b ,", b", a", b"a,,b"] {
            let headers = parser(input)
                .no_tail()
                .unwrap_or_else(|error| panic!("{:?}: {error:?}", String::from_utf8_lossy(input)));
            assert!(headers.len() <= 2, "{:?}", String::from_utf8_lossy(input));
        }
        assert_eq!(parser(b" a , , b ,").no_tail().unwrap().len(), 2);
    }

    #[test]
    fn parse_connection_headers_rejects_non_tokens() {
        for input in [&b"a b"[..], b"a;b", b"\"quoted\""] {
            assert!(
                parser(input).no_tail().is_err(),
                "{:?}",
                String::from_utf8_lossy(input)
            );
        }
    }

    #[test]
    fn parse_connection_headers_all_token_characters() {
        // Every token character must be accepted as a header name, rather than panicking.
        let input = b"abcXYZ019!#$%&'*+-.^_`|~";
        let headers = parser(input).no_tail().unwrap();
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].header(), "abcxyz019!#$%&'*+-.^_`|~");
    }

    #[test]
    fn connection_options_all_lines_case_insensitive() {
        let mut headers = http::HeaderMap::new();
        headers.append(CONNECTION, "keep-alive, Upgrade".parse().unwrap());
        headers.append(CONNECTION, "X-Custom, , close".parse().unwrap());
        headers.append(CONNECTION, "not a token, x-raw".parse().unwrap());

        assert_eq!(
            connection_options(&headers),
            ["keep-alive", "upgrade", "x-custom", "close", "x-raw"]
        );
    }

    #[test]
    fn is_upgrade_detection() {
        let upgrade = |connection: &[&str], upgrade: Option<&str>| {
            let mut headers = http::HeaderMap::new();
            for line in connection {
                headers.append(CONNECTION, line.parse().unwrap());
            }
            if let Some(upgrade) = upgrade {
                headers.insert(UPGRADE, upgrade.parse().unwrap());
            }
            is_upgrade(&headers)
        };

        // Browsers capitalise the option (Firefox also includes keep-alive).
        assert!(upgrade(&["Upgrade"], Some("websocket")));
        assert!(upgrade(&["keep-alive, Upgrade"], Some("websocket")));
        assert!(upgrade(&["keep-alive", "upgrade"], Some("websocket")));

        assert!(!upgrade(&["Upgrade"], None));
        assert!(!upgrade(&["close"], Some("websocket")));
        assert!(!upgrade(&[], Some("websocket")));
    }

    #[test]
    fn connection_header_roundtrip() {
        let mut headers = http::HeaderMap::new();
        headers.append(CONNECTION, "close, upgrade".parse().unwrap());
        headers.append(CONNECTION, "keep-alive".parse().unwrap());

        let chain = HeaderChain::<ConnectionHeader>::try_from_headers(&headers).unwrap();
        let values: Vec<_> = chain
            .into_iter()
            .map(|header| header.into_header_value())
            .collect();
        assert_eq!(values, ["close, upgrade", "keep-alive"]);
    }
}
