//! Support for the Via header.
//!
//! This header is used to identify the proxies that have been involved in the request.

use std::net::SocketAddr;
use std::str::FromStr;

use bytes::BufMut;
use bytes::Bytes;
use bytes::BytesMut;
use nom::branch::alt;
use nom::character::complete::char;
use nom::character::complete::digit1;
use nom::combinator::map;
use nom::combinator::map_res;
use nom::combinator::opt;
use nom::multi::separated_list0;
use nom::sequence::pair;
use thiserror::Error;

use crate::headers::parser::{strip_whitespace, token, NoTail};

use super::chain::Record;
use super::{
    chain::{AppendHeaderRecordMode, HeaderChain, HeaderRecordKind},
    fields::{InvalidValue, Token},
};

/// The `Via` header.
pub const VIA: http::header::HeaderName = http::header::VIA;

/// The `Via` header value, as a chain of proxies.
pub type ViaChain = HeaderChain<Via>;

/// A single `Via` header entry: one proxy which forwarded the message.
///
/// ```text
/// Via = #( received-protocol RWS received-by [ RWS comment ] )
/// ```
///
/// See [RFC 9110 section 7.6.3](https://datatracker.ietf.org/doc/html/rfc9110#section-7.6.3).
///
/// ```
/// use hyproxy::headers::via::{Via, ViaAddress};
///
/// let via = Via::new(http::Version::HTTP_11.into(), ViaAddress::named("proxy").unwrap())
///     .with_comment("hyproxy")
///     .unwrap();
/// assert_eq!(via.to_string(), "1.1 proxy (hyproxy)");
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Via {
    protocol: ViaProtocol,
    address: ViaAddress,
    /// The comment, including the surrounding parentheses, exactly as received.
    comment: Option<Bytes>,
}

/// The maximum nesting depth accepted in a `Via` comment, to bound parsing work on
/// untrusted input.
const MAX_COMMENT_DEPTH: usize = 16;

/// Parse a `comment` (RFC 9110 section 5.6.5), returning it with its parentheses:
///
/// ```text
/// comment = "(" *( ctext / quoted-pair / comment ) ")"
/// ctext   = HTAB / SP / %x21-27 / %x2A-5B / %x5D-7E / obs-text
/// ```
fn comment(input: &[u8]) -> nom::IResult<&[u8], &[u8]> {
    let fail = || nom::Err::Error(nom::error::Error::new(input, nom::error::ErrorKind::Char));
    let is_ctext =
        |c: u8| matches!(c, b'\t' | b' ' | 0x21..=0x27 | 0x2A..=0x5B | 0x5D..=0x7E | 0x80..=0xFF);
    let is_quotable = |c: u8| matches!(c, b'\t' | b' ' | 0x21..=0x7E | 0x80..=0xFF);

    if input.first() != Some(&b'(') {
        return Err(fail());
    }

    let mut depth = 0;
    let mut bytes = input.iter().enumerate();
    while let Some((i, &c)) = bytes.next() {
        match c {
            b'(' => {
                depth += 1;
                if depth > MAX_COMMENT_DEPTH {
                    return Err(fail());
                }
            }
            b')' => {
                depth -= 1;
                if depth == 0 {
                    return Ok((&input[i + 1..], &input[..=i]));
                }
            }
            b'\\' => match bytes.next() {
                Some((_, &escaped)) if is_quotable(escaped) => {}
                _ => return Err(fail()),
            },
            c if is_ctext(c) => {}
            _ => return Err(fail()),
        }
    }

    // Unterminated comment.
    Err(fail())
}

fn via<'v>() -> impl FnMut(&'v [u8]) -> nom::IResult<&'v [u8], Via> {
    use nom::sequence::tuple;

    map(
        tuple((
            protocol(),
            strip_whitespace(address()),
            opt(strip_whitespace(comment)),
        )),
        |(protocol, address, comment)| Via {
            protocol,
            address,
            comment: comment.map(Bytes::copy_from_slice),
        },
    )
}

impl Via {
    /// Create a `Via` entry for a proxy at `address`, which received the message over
    /// `protocol`.
    pub fn new(protocol: ViaProtocol, address: ViaAddress) -> Self {
        Self {
            protocol,
            address,
            comment: None,
        }
    }

    /// Add a comment, typically identifying the proxy software.
    ///
    /// The text is given without parentheses. Returns an error if it contains characters
    /// not permitted in a comment, or unbalanced parentheses.
    pub fn with_comment(self, comment: &str) -> Result<Self, ParseViaError> {
        let comment = format!("({comment})");
        let valid = nom::combinator::all_consuming(self::comment)(comment.as_bytes()).is_ok();
        if !valid {
            return Err(ParseViaError::InvalidComment);
        }

        Ok(Self {
            comment: Some(Bytes::from(comment)),
            ..self
        })
    }

    /// The protocol the proxy received the message over.
    pub fn protocol(&self) -> &ViaProtocol {
        &self.protocol
    }

    /// The name or address of the proxy.
    pub fn address(&self) -> &ViaAddress {
        &self.address
    }

    /// The comment, without its surrounding parentheses, if any.
    ///
    /// Nested comments and escape sequences are returned as received.
    pub fn comment(&self) -> Option<&[u8]> {
        self.comment
            .as_ref()
            .map(|comment| &comment[1..comment.len() - 1])
    }

    /// Convert this entry to its header form, e.g. `1.1 proxy (comment)`.
    pub fn to_bytes(&self) -> Bytes {
        let mut bytes = BytesMut::new();
        if let Some(name) = &self.protocol.name {
            bytes.extend_from_slice(name.as_bytes());
            bytes.put_u8(b'/');
        }
        bytes.extend_from_slice(self.protocol.version.as_bytes());
        bytes.put_u8(b' ');
        bytes.extend_from_slice(&self.address.clone().into_bytes());
        if let Some(comment) = &self.comment {
            bytes.put_u8(b' ');
            bytes.extend_from_slice(comment);
        }
        bytes.freeze()
    }
}

impl std::fmt::Display for Via {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&String::from_utf8_lossy(&self.to_bytes()))
    }
}

impl Via {
    fn parse_bytes(value: &[u8]) -> Result<Vec<Record<Via>>, ParseViaError> {
        let mut parser = separated_list0(char(','), strip_whitespace(via()));

        parser(value)
            .no_tail()
            .map_err(|error| {
                ParseViaError::ParserError(nom::error::Error::new(
                    Bytes::copy_from_slice(error.input),
                    error.code,
                ))
            })
            .map(|r| r.into_iter().map(Into::into).collect())
    }
}

impl HeaderRecordKind for Via {
    const HEADER_NAME: http::header::HeaderName = VIA;

    const DELIMITER: u8 = b',';

    type Error = ParseViaError;

    fn into_bytes(self) -> Vec<u8> {
        self.to_bytes().to_vec()
    }

    fn parse_header_value(
        header: &http::HeaderValue,
    ) -> Result<Vec<super::chain::Record<Self>>, Self::Error> {
        let value = header.as_bytes();
        Via::parse_bytes(value)
    }
}

/// Error for an invalid Via header.
#[derive(Debug, Error)]
pub enum ParseViaError {
    /// A part of the header is not a valid RFC 9110 token.
    #[error(transparent)]
    InvalidToken(#[from] InvalidValue),

    /// An error occurred parsing the header.
    #[error("parsing error: {0:?}")]
    ParserError(nom::error::Error<Bytes>),

    /// The header has only one (space separated) part, missing either the protocol or the address.
    #[error("Missing address, only protocol found")]
    MissingAddress,

    /// The header contains characters in an invalid encoding.
    #[error("Header Encoding")]
    HeaderEncoding,

    /// A comment contains characters which are not permitted, or unbalanced parentheses.
    #[error("invalid comment in Via header")]
    InvalidComment,
}

/// The protocol used by the proxy.
#[derive(Debug, Clone, Eq)]
pub struct ViaProtocol {
    name: Option<Token>,
    version: Token,
}

fn protocol<'v>() -> impl FnMut(&'v [u8]) -> nom::IResult<&'v [u8], ViaProtocol> {
    map(
        pair(opt(pair(strip_whitespace(token()), char('/'))), token()),
        |(name, version)| ViaProtocol {
            name: name.map(|(name, _)| name),
            version,
        },
    )
}

impl ViaProtocol {
    /// Create a protocol from its name and version.
    ///
    /// The name is usually omitted (`None`) for HTTP, as RFC 9110 recommends.
    pub fn new(name: Option<Token>, version: Token) -> Self {
        Self { name, version }
    }

    /// The protocol name, if given. `None` means HTTP.
    pub fn name(&self) -> Option<&Token> {
        self.name.as_ref()
    }

    /// The protocol version.
    pub fn version(&self) -> &Token {
        &self.version
    }

    /// Parse a ViaProtocol from a string.
    pub fn parse_bytes(value: &[u8]) -> Result<Self, ParseViaError> {
        protocol()(value).no_tail().map_err(|error| {
            ParseViaError::ParserError(nom::error::Error::new(
                Bytes::copy_from_slice(error.input),
                error.code,
            ))
        })
    }
}

const HTTP: Token = Token::from_static_unchecked("HTTP");

impl PartialEq for ViaProtocol {
    fn eq(&self, other: &Self) -> bool {
        let http = &HTTP;
        let self_name = self.name.as_ref().unwrap_or(http);
        let other_name = other.name.as_ref().unwrap_or(http);

        self_name.eq_ignore_ascii_case(other_name)
            && self.version.eq_ignore_ascii_case(&other.version)
    }
}

impl From<http::Version> for ViaProtocol {
    /// The protocol name is omitted, since it is HTTP (RFC 9110 section 7.6.3).
    fn from(version: http::Version) -> Self {
        let version = match version {
            http::Version::HTTP_09 => Token::from_static_unchecked("0.9"),
            http::Version::HTTP_10 => Token::from_static_unchecked("1.0"),
            http::Version::HTTP_11 => Token::from_static_unchecked("1.1"),
            http::Version::HTTP_2 => Token::from_static_unchecked("2"),
            http::Version::HTTP_3 => Token::from_static_unchecked("3"),
            // `http::Version` may gain variants; its `Debug` form is `HTTP/<version>`.
            other => {
                let debug = format!("{other:?}");
                Token::parse(debug.strip_prefix("HTTP/").unwrap_or(&debug).as_bytes())
                    .unwrap_or_else(|_| Token::from_static_unchecked("unknown"))
            }
        };

        ViaProtocol {
            name: None,
            version,
        }
    }
}

fn address<'v>() -> impl FnMut(&'v [u8]) -> nom::IResult<&'v [u8], ViaAddress> {
    let port = map_res(pair(char::<&[u8], _>(':'), digit1), |(_, port)| {
        std::str::from_utf8(port)
            .map_err(|_| nom::error::Error::new(port, nom::error::ErrorKind::Digit))
            .and_then(|s| {
                s.parse::<u16>()
                    .map_err(|_| nom::error::Error::new(port, nom::error::ErrorKind::Digit))
            })
    });

    let address = map(pair(token(), port), |(host, port)| {
        ViaAddress::HostAndPort(host, Some(port))
    });
    let pseudonym = map(token(), ViaAddress::Pseudonym);

    strip_whitespace(alt((address, pseudonym)))
}

/// The name or address of the proxy (`received-by` in
/// [RFC 9110 section 7.6.3](https://datatracker.ietf.org/doc/html/rfc9110#section-7.6.3)).
///
/// RFC 9110 defines `received-by = pseudonym [ ":" port ]` with `pseudonym = token`, so a
/// host must be a valid token. Host names and IPv4 addresses are, but IPv6 addresses are not
/// and cannot be represented: use a pseudonym instead.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ViaAddress {
    /// The host and port of the proxy.
    HostAndPort(Token, Option<u16>),

    /// A pseudonym for the proxy.
    Pseudonym(Token),
}

impl ViaAddress {
    /// Convert the ViaAddress to a byte representation suitable for inclusion in a HTTP header.
    pub fn into_bytes(self) -> Bytes {
        match self {
            ViaAddress::HostAndPort(host, Some(port)) => {
                let mut bytes = host
                    .into_bytes()
                    .try_into_mut()
                    .unwrap_or_else(|b| BytesMut::from(b.as_ref()));
                bytes.put_u8(b':');
                bytes.extend_from_slice(port.to_string().as_bytes());
                bytes.freeze()
            }
            ViaAddress::HostAndPort(host, None) => host.into_bytes(),
            ViaAddress::Pseudonym(name) => name.into_bytes(),
        }
    }

    /// Parse a ViaAddress from a sequence of HTTP header bytes.
    pub fn parse_bytes(value: &[u8]) -> Result<Self, ParseViaError> {
        address()(value).no_tail().map_err(|error| {
            ParseViaError::ParserError(nom::error::Error::new(
                Bytes::copy_from_slice(error.input),
                error.code,
            ))
        })
    }

    /// Create a ViaAddress from a name/pseudonym.
    pub fn named(name: impl Into<String>) -> Result<Self, InvalidValue> {
        let name = Token::parse(name.into().as_bytes())?;
        Ok(ViaAddress::Pseudonym(name))
    }

    /// Create a ViaAddress from a URI's host and port.
    ///
    /// Returns `Ok(None)` if the URI has no authority, and an error if the host is not a
    /// valid token (for example, an IPv6 address).
    pub fn from_uri(uri: &http::Uri) -> Result<Option<Self>, InvalidValue> {
        let authority = uri.authority();
        if let Some(authority) = authority {
            let host = authority.host();
            let port = authority.port_u16();
            return Ok(Some(ViaAddress::HostAndPort(
                Token::parse(host.as_bytes())?,
                port,
            )));
        }

        Ok(None)
    }
}

impl FromStr for ViaAddress {
    type Err = ParseViaError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        ViaAddress::parse_bytes(s.as_bytes())
    }
}

impl TryFrom<SocketAddr> for ViaAddress {
    type Error = InvalidValue;

    /// Use the address and port as the `received-by` value.
    ///
    /// IPv4 addresses are valid tokens. IPv6 addresses are not, and return an error.
    fn try_from(addr: SocketAddr) -> Result<Self, Self::Error> {
        Ok(ViaAddress::HostAndPort(
            Token::parse(addr.ip().to_string().as_bytes())?,
            Some(addr.port()),
        ))
    }
}

/// Middleware to add a Via header to requests and responses.
///
/// Apply [`StripHopByHopLayer`](super::StripHopByHopLayer) outside of this layer, so that a
/// client cannot use `Connection` to remove the `Via` header it adds to requests. See
/// [the `hopby` module](super::hopby#ordering).
#[derive(Debug, Clone)]
pub struct SetViaHeaderLayer {
    address: ViaAddress,
    request: AppendHeaderRecordMode,
    response: AppendHeaderRecordMode,
}

impl SetViaHeaderLayer {
    /// Create a new Via header layer.
    pub fn new(address: ViaAddress) -> Self {
        Self {
            address,
            request: Default::default(),
            response: Default::default(),
        }
    }

    /// Set whether to add the Via header to requests.
    pub fn request(mut self, request: AppendHeaderRecordMode) -> Self {
        self.request = request;
        self
    }

    /// Set whether to add the Via header to responses.
    pub fn response(mut self, response: AppendHeaderRecordMode) -> Self {
        self.response = response;
        self
    }
}

impl<S> tower::layer::Layer<S> for SetViaHeaderLayer {
    type Service = SetViaHeader<S>;

    fn layer(&self, inner: S) -> Self::Service {
        SetViaHeader {
            inner,
            address: self.address.clone(),
            request: self.request.clone(),
            response: self.response.clone(),
        }
    }
}

/// Middleware to add a Via header to requests and responses.
#[derive(Debug, Clone)]
pub struct SetViaHeader<S> {
    inner: S,
    address: ViaAddress,
    request: AppendHeaderRecordMode,
    response: AppendHeaderRecordMode,
}

impl<S> SetViaHeader<S> {
    /// Create a new Via header middleware.
    pub fn new(inner: S, address: ViaAddress) -> Self {
        Self {
            inner,
            address,
            request: Default::default(),
            response: Default::default(),
        }
    }

    /// A mutable reference to the request VIA header mode.
    pub fn request(&mut self) -> &mut AppendHeaderRecordMode {
        &mut self.request
    }

    /// A mutable reference to the response VIA header mode.
    pub fn response(&mut self) -> &mut AppendHeaderRecordMode {
        &mut self.response
    }
}

impl<S, BIn, BOut> tower::Service<http::Request<BIn>> for SetViaHeader<S>
where
    S: tower::Service<http::Request<BIn>, Response = http::Response<BOut>>,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = self::future::ViaHeaderFuture<S::Future, BOut, S::Error>;

    fn call(&mut self, mut request: http::Request<BIn>) -> Self::Future {
        let via = Via::new(request.version().into(), self.address.clone());

        ViaChain::append_record(&self.request, via, request.headers_mut());

        self::future::ViaHeaderFuture::new(
            self.inner.call(request),
            self.address.clone(),
            self.response.clone(),
        )
    }

    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }
}

mod future {
    use std::task::ready;

    use pin_project_lite::pin_project;

    use crate::headers::chain::{AppendHeaderRecordMode, HeaderChain};

    use super::{Via, ViaAddress};

    pin_project! {
        #[derive(Debug)]
        pub struct ViaHeaderFuture<F, BOut, E> {
            #[pin]
            inner: F,
            address: ViaAddress,
            mode: AppendHeaderRecordMode,
            marker: std::marker::PhantomData<fn() -> Result<BOut, E>>,
        }
    }

    impl<F, BOut, E> ViaHeaderFuture<F, BOut, E> {
        pub(super) fn new(inner: F, address: ViaAddress, mode: AppendHeaderRecordMode) -> Self {
            Self {
                inner,
                address,
                mode,
                marker: std::marker::PhantomData,
            }
        }
    }

    impl<F, BOut, E> std::future::Future for ViaHeaderFuture<F, BOut, E>
    where
        F: std::future::Future<Output = Result<http::Response<BOut>, E>>,
    {
        type Output = Result<http::Response<BOut>, E>;

        fn poll(
            self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Self::Output> {
            let this = self.project();
            let mut response = ready!(this.inner.poll(cx));

            if let Ok(res) = &mut response {
                let via = Via::new(res.version().into(), this.address.clone());

                HeaderChain::append_record(this.mode, via, res.headers_mut());
            }

            std::task::Poll::Ready(response)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{convert::Infallible, future::Future, pin::Pin};

    use tower::{Layer as _, ServiceExt as _};

    use crate::headers::chain::{Header, IntoRecordValue};

    use super::*;

    fn parse_single(input: &[u8]) -> Via {
        let mut records = Via::parse_bytes(input).unwrap();
        assert_eq!(records.len(), 1);
        records.pop().unwrap().into_value().unwrap()
    }

    #[test]
    fn parse_via_comments() {
        for (input, comment) in [
            (&b"1.1 varnish (Varnish/6.0)"[..], &b"Varnish/6.0"[..]),
            (b"1.1 proxy:8080 (Apache/2.4 (Unix))", b"Apache/2.4 (Unix)"),
            (b"1.1 proxy (escaped \\) paren)", b"escaped \\) paren"),
            (b"1.1 proxy ()", b""),
            (b"1.1 proxy(no space)", b"no space"),
        ] {
            let via = parse_single(input);
            assert_eq!(
                via.comment(),
                Some(comment),
                "{:?}",
                String::from_utf8_lossy(input)
            );
            // Comments are preserved when the header is re-serialized.
            let reparsed = parse_single(&via.to_bytes());
            assert_eq!(reparsed.comment(), Some(comment));
        }

        // A comma inside a comment does not split the list.
        let records = Via::parse_bytes(b"1.1 a (x, y), 1.0 b").unwrap();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].value().unwrap().comment(), Some(&b"x, y"[..]));
    }

    #[test]
    fn parse_via_invalid_comments() {
        let deep = format!(
            "1.1 proxy {}{}",
            "(".repeat(MAX_COMMENT_DEPTH + 1),
            ")".repeat(MAX_COMMENT_DEPTH + 1)
        );
        for input in [
            &b"1.1 proxy (unterminated"[..],
            b"1.1 proxy (unbalanced))",
            b"1.1 proxy (bad escape \\",
            deep.as_bytes(),
        ] {
            assert!(
                Via::parse_bytes(input).is_err(),
                "{:?}",
                String::from_utf8_lossy(input)
            );
        }

        let ok = format!(
            "1.1 proxy {}{}",
            "(".repeat(MAX_COMMENT_DEPTH),
            ")".repeat(MAX_COMMENT_DEPTH)
        );
        assert!(Via::parse_bytes(ok.as_bytes()).is_ok());
    }

    #[test]
    fn via_constructors_and_accessors() {
        let via = Via::new(
            http::Version::HTTP_2.into(),
            ViaAddress::named("proxy").unwrap(),
        );
        assert_eq!(via.protocol().name(), None);
        assert_eq!(via.protocol().version().as_bytes(), b"2");
        assert_eq!(via.address(), &ViaAddress::named("proxy").unwrap());
        assert_eq!(via.comment(), None);
        assert_eq!(via.to_string(), "2 proxy");

        let via = via.with_comment("hyproxy (beta)").unwrap();
        assert_eq!(via.comment(), Some(&b"hyproxy (beta)"[..]));
        assert_eq!(via.to_string(), "2 proxy (hyproxy (beta))");

        for invalid in ["unbalanced (", "unbalanced )", "line\nbreak"] {
            assert!(
                Via::new(
                    http::Version::HTTP_11.into(),
                    ViaAddress::named("p").unwrap()
                )
                .with_comment(invalid)
                .is_err(),
                "{invalid:?}"
            );
        }

        let protocol = ViaProtocol::new(Some(Token::from_static("FOO")), Token::from_static("1"));
        assert_eq!(protocol.name(), Some(&Token::from_static("FOO")));
        assert_eq!(
            Via::new(protocol, ViaAddress::named("p").unwrap()).to_string(),
            "FOO/1 p"
        );
    }

    #[test]
    fn via_protocol_from_version_omits_http() {
        // RFC 9110 section 7.6.3: "the protocol-name is omitted when the received protocol is HTTP".
        for (version, expected) in [
            (http::Version::HTTP_09, "0.9"),
            (http::Version::HTTP_10, "1.0"),
            (http::Version::HTTP_11, "1.1"),
            (http::Version::HTTP_2, "2"),
            (http::Version::HTTP_3, "3"),
        ] {
            let protocol = ViaProtocol::from(version);
            assert_eq!(protocol.name(), None);
            assert_eq!(protocol.version().as_bytes(), expected.as_bytes());
            // Still equal to the explicit `HTTP/<version>` form.
            assert_eq!(
                protocol,
                ViaProtocol::parse_bytes(format!("HTTP/{expected}").as_bytes()).unwrap()
            );
        }
    }

    #[test]
    fn via_address_from_socket_addr() {
        use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

        let v4 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 8080);
        let address = ViaAddress::try_from(v4).unwrap();
        assert_eq!(
            address,
            ViaAddress::HostAndPort(Token::from_static("192.0.2.1"), Some(8080))
        );
        assert_eq!(address.into_bytes().as_ref(), b"192.0.2.1:8080");

        // Previously panicked: IPv6 addresses are not RFC 9110 tokens.
        let v6 = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 8080);
        assert!(ViaAddress::try_from(v6).is_err());
    }

    #[test]
    fn via_address_from_ipv6_uri_is_error() {
        assert!(ViaAddress::from_uri(&"http://[::1]:8080/".parse().unwrap()).is_err());
        assert_eq!(
            ViaAddress::from_uri(&"/path".parse().unwrap()).unwrap(),
            None
        );
    }

    #[test]
    fn via_address_named() {
        assert_eq!(
            ViaAddress::Pseudonym(Token::from_static("proxy")),
            ViaAddress::named("proxy").unwrap()
        );

        assert!(
            ViaAddress::named("😀").is_err(),
            "Invalid characters in pseudonym"
        );
    }

    macro_rules! parse_one {
        ($value:expr) => {
            Via::parse_bytes($value)
                .unwrap()
                .pop()
                .unwrap()
                .into_value()
                .unwrap()
        };
    }

    #[test]
    fn parse_via() {
        let addr = parse_one!(b"http/1.1 localhost:8080");

        assert_eq!(
            addr,
            Via::new(
                http::Version::HTTP_11.into(),
                ViaAddress::HostAndPort(Token::from_static("localhost"), Some(8080))
            )
        );

        let addr = parse_one!(b"http/1.1 proxy");

        assert_eq!(
            addr,
            Via::new(
                http::Version::HTTP_11.into(),
                ViaAddress::named("proxy").unwrap()
            )
        );
    }

    #[test]
    fn parse_via_records() {
        let records = Via::parse_bytes(b"http/1.1 localhost:8080, http/1.1 proxy").unwrap();

        assert_eq!(2, records.len());

        assert_eq!(
            records[0].value().unwrap(),
            &Via::new(
                http::Version::HTTP_11.into(),
                ViaAddress::HostAndPort(Token::from_static("localhost"), Some(8080))
            )
        );

        assert_eq!(
            records[1].value().unwrap(),
            &Via::new(
                http::Version::HTTP_11.into(),
                ViaAddress::named("proxy").unwrap()
            )
        );

        let records = Via::parse_bytes(b"1.1 vegur").unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(
            records[0].value().unwrap(),
            &Via::new(
                http::Version::HTTP_11.into(),
                ViaAddress::named("vegur").unwrap()
            )
        );

        let records = Via::parse_bytes(b"1.0 fred, 1.1 p.example.net").unwrap();
        assert_eq!(records.len(), 2);
        assert_eq!(
            records[0].value().unwrap(),
            &Via::new(
                http::Version::HTTP_10.into(),
                ViaAddress::named("fred").unwrap()
            )
        );

        assert_eq!(
            records[1].value().unwrap(),
            &Via::new(
                http::Version::HTTP_11.into(),
                ViaAddress::named("p.example.net").unwrap()
            )
        );

        let records = Via::parse_bytes(b"HTTP/1.1 GWA").unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(
            records[0].value().unwrap(),
            &Via::new(
                http::Version::HTTP_11.into(),
                ViaAddress::named("GWA").unwrap()
            )
        );
    }

    fn via_fixture() -> Via {
        Via::new(
            http::Version::HTTP_11.into(),
            ViaAddress::HostAndPort(Token::from_static("localhost"), Some(8080)),
        )
    }

    type BoxServiceFuture = Pin<Box<dyn Future<Output = Result<http::Response<()>, Infallible>>>>;

    fn via_service(via: Option<Via>) -> impl FnMut(http::Request<()>) -> BoxServiceFuture {
        move |request: http::Request<()>| {
            let via = via.clone();
            Box::pin(async move {
                let header = if let Some(via) = via {
                    let header = Header::single(via.clone());

                    assert_eq!(
                        header.clone().into_header_value(),
                        request.headers().get(VIA).unwrap()
                    );

                    header
                } else {
                    Header::new()
                };

                Ok(http::Response::builder()
                    .header(VIA, header.into_header_value())
                    .body(())
                    .unwrap())
            })
        }
    }

    #[tokio::test]
    async fn via_header_middleware_defaults() {
        let addr = ViaAddress::from_uri(&"https://localhost:8080".parse().unwrap())
            .unwrap()
            .unwrap();
        let middleware = SetViaHeaderLayer::new(addr.clone());
        let service = middleware.layer(tower::service_fn(via_service(Some(via_fixture()))));

        let request = http::Request::new(());
        let response = service.oneshot(request).await.unwrap();

        let via = Via::new(http::Version::HTTP_11.into(), addr.clone());

        let chain: ViaChain = ViaChain::from_headers(response.headers());

        assert_eq!(2, chain.len());

        assert!(
            chain.flat_iter().all(|v| v.value().unwrap() == &via),
            "All records are the same VIA"
        );
    }

    #[tokio::test]
    async fn via_header_middleware_append() {
        let middleware = SetViaHeaderLayer::new("localhost:8080".parse().unwrap())
            .response(AppendHeaderRecordMode::Append);
        let service = middleware.layer(tower::service_fn(via_service(Some(via_fixture()))));

        let request = http::Request::new(());
        let response = service.oneshot(request).await.unwrap();

        let via = Via::new(
            http::Version::HTTP_11.into(),
            "localhost:8080".parse().unwrap(),
        );

        let chain: ViaChain = ViaChain::from_headers(response.headers());

        assert_eq!(2, chain.len());

        assert!(
            chain.flat_iter().all(|v| v.value() == Some(&via)),
            "All records are the same VIA"
        );

        assert_eq!(2, response.headers().get_all(VIA).iter().count());
    }

    #[tokio::test]
    async fn via_header_middleware_replace() {
        let middleware = SetViaHeaderLayer::new("localhost:8080".parse().unwrap())
            .response(AppendHeaderRecordMode::KeepLast);
        let service = middleware.layer(tower::service_fn(via_service(None)));

        let request = http::Request::get("http://localhost:8080")
            .header(VIA, "1.1 foo")
            .body(())
            .unwrap();
        let response = service.oneshot(request).await.unwrap();

        let via = Via::new(
            http::Version::HTTP_11.into(),
            "localhost:8080".parse().unwrap(),
        );

        let chain: ViaChain = ViaChain::from_headers(response.headers());

        assert_eq!(1, chain.flat_iter().count());

        assert_eq!(
            &via,
            chain.flat_into_iter().next().unwrap().value().unwrap()
        );
    }

    #[tokio::test]
    async fn via_header_middleware_omit() {
        let middleware = SetViaHeaderLayer::new("localhost:8080".parse().unwrap())
            .response(AppendHeaderRecordMode::Omit)
            .request(AppendHeaderRecordMode::Omit);
        let service = middleware.layer(tower::service_fn(via_service(None)));

        let request = http::Request::new(());
        let response = service.oneshot(request).await.unwrap();

        let chain: ViaChain = ViaChain::from_headers(response.headers());

        assert!(chain.is_empty());
    }
}
