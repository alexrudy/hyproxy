//! Typed version of the HTTP `Forwarded` header.
//!
//! See [RFC-7239](https://datatracker.ietf.org/doc/html/rfc7239)
//! for the specification of the `Forwarded` header.

use std::collections::BTreeMap;
use std::fmt;
use std::net::{AddrParseError, IpAddr, Ipv6Addr, SocketAddr};
use std::str::FromStr;

use bytes::{BufMut, Bytes, BytesMut};
use hyperdriver::info::{BraidAddr, ConnectionInfo};
use nom::Finish;
use thiserror::Error;

use super::fields::{FieldKey, FieldValue, Token};

use super::chain::{
    AppendHeaderRecordMode, FromRequest, Header, HeaderChain, HeaderRecordKind, Record,
};
use super::parser::NoTail;

/// The `Forwarded` header, a standard header for identifying the originating IP address of a client connecting to a web server through a proxy server.
///
/// This header is defined in [RFC-7239](https://datatracker.ietf.org/doc/html/rfc7239).
pub const FORWARDED: http::HeaderName = http::header::FORWARDED;

/// The `X-Forwarded-By` header, a de-facto standard header for identifying the originating IP
/// address of a client connecting to a web server through a proxy server. It has been replaced by `Forwarded`.
pub const X_FORWARDED_FOR: http::HeaderName =
    http::header::HeaderName::from_static("x-forwarded-for");

/// The `X-Forwarded-Host` header, a de-facto standard header for identifying the original host requested by the client in the `Host` HTTP request header.
pub const X_FORWARDED_HOST: http::HeaderName =
    http::header::HeaderName::from_static("x-forwarded-host");

/// The `X-Forwarded-Proto` header, a de-facto standard header for identifying the protocol (HTTP or HTTPS) that a client used to connect to your proxy or load balancer.
pub const X_FORWARDED_PROTO: http::HeaderName =
    http::header::HeaderName::from_static("x-forwarded-proto");

/// A collection of values of forwarding information.
///
/// The FORWARDED header can contain multiple comma-separated values, or multiple FORWARDED headers
/// can be present - to parse a requests full chain requires parsing all headers.
pub type ForwardingChain = HeaderChain<Forwarded>;

impl ForwardingChain {
    /// Check if any of the fields are set.
    ///
    /// When no fields are set, the `Forwarded` header should not be included in the request.
    pub fn any(&self) -> bool {
        self.flat_iter().any(ForwardedRecord::any)
    }

    /// Remove the `by` field from the `Forwarded` header.
    pub fn without_by(self) -> Self {
        self.into_iter().map(ForwardedHeader::without_by).collect()
    }

    /// Set the `X-Forwarded-*` headers on a request.
    pub fn set_all_x_forwarded_headers<B>(&self, request: &mut http::Request<B>) {
        for record in self.flat_iter() {
            record.set_x_forwarded_headers(request);
        }
    }
}

/// A single `FORWARDED` header value, which can contain multiple records.
///
/// Records are comma-separated, and contain key-value pairs separated by semicolons.
///
/// This holds `ForwardedRecord` values, which can be parsed or raw, to enable losslessly
/// preserving original values which don't parse as records.
pub type ForwardedHeader = Header<Forwarded>;

impl ForwardedHeader {
    /// Check if any of the fields are set.
    ///
    /// If any raw values are present, and not empty,
    /// this will return `true`.
    pub fn any(&self) -> bool {
        self.iter().any(ForwardedRecord::any)
    }

    /// Remove the `by` field from the parsed `Forwarded` header.
    ///
    /// Leaves the raw values unchanged.
    pub fn without_by(self) -> Self {
        self.into_iter().map(ForwardedRecord::without_by).collect()
    }

    /// Set the `X-Forwarded-*` headers on a request.
    ///
    /// This will skip unparsed raw values.
    pub fn set_all_x_forwarded_headers<B>(&self, request: &mut http::Request<B>) {
        for record in self.iter() {
            record.set_x_forwarded_headers(request);
        }
    }
}

/// A record in a `Forwarded` header.
///
/// This can be a parsed `Forwarded` record, or a raw string that could not be parsed,
/// so that the original value can be preserved.
pub type ForwardedRecord = Record<Forwarded>;

impl ForwardedRecord {
    /// Check if any of the fields are set.
    ///
    /// If the record is raw, this will return `true` if the value is not empty.
    pub fn any(&self) -> bool {
        self.value()
            .map(|v| v.any())
            .or_else(|| self.raw().map(|bytes| bytes.is_empty()))
            .unwrap()
    }

    /// Remove the `by` field from the `Forwarded` record.
    ///
    /// If the record is raw, this will return a new raw record with the same value.
    pub fn without_by(self) -> Self {
        self.map(Forwarded::without_by)
    }

    /// Set the `X-Forwarded-*` headers on a request.
    ///
    /// If the record is raw, this will do nothing.
    pub fn set_x_forwarded_headers<B>(&self, request: &mut http::Request<B>) {
        if let Some(record) = self.value() {
            record.set_x_forwarded_headers(request);
        }
    }
}

/// The contents of one record in a `Forwarded` header.
///
/// A forwarded header can consist of multiple comma-separated records, each containing a set of key-value pairs.
#[derive(Debug, Default, Clone, Eq, PartialEq)]
#[non_exhaustive]
pub struct Forwarded {
    /// The interface where the request came in to the proxy server
    pub by: Option<Forwardee>,

    /// The client that initiated the request and subsequent proxies in a chain of proxies
    pub r#for: Option<Forwardee>,

    /// The original host requested by the client
    pub host: Option<ForwardedHost>,

    /// The protocol used to connect to the proxy server
    pub proto: Option<ForwardedProtocol>,

    /// Additional fields in the `Forwarded` header
    pub extensions: BTreeMap<ForwardedKey, FieldValue>,
}

impl Forwarded {
    /// Create a new `Forwarded` header from a request.
    ///
    /// This should receive the request sent to the proxy server, and will extract the necessary information from it.
    /// It expects that the request has been processed by some middleware that adds the `ConnectionInfo` extension,
    /// which contains the remote and local addresses of the connection.
    pub fn new<B>(request: &http::Request<B>) -> Self {
        let mut by = None;
        let mut r#for = None;
        let mut host = None;
        let mut proto = None;

        if let Some(info) = request.extensions().get::<ConnectionInfo<BraidAddr>>() {
            if let Some(remote) = info.remote_addr.clone().canonical().tcp() {
                r#for = Some(Forwardee::Address(remote.into()));
            }

            if let Some(local) = info.local_addr.clone().canonical().tcp() {
                by = Some(Forwardee::Address(local.into()));
            }
        } else {
            tracing::warn!("No connection info found in request extensions");
        }

        if let Some(host_header) = request
            .headers()
            .get(http::header::HOST)
            .and_then(|h| ForwardedHost::parse_bytes(h.as_bytes()).ok())
        {
            host = Some(host_header);
        }

        if let Some(scheme) = request.uri().scheme() {
            proto = Some(scheme.clone().into());
        }

        Forwarded {
            by,
            r#for,
            host,
            proto,
            extensions: BTreeMap::new(),
        }
    }

    /// Create a new `Forwarded` header from a header value.
    pub fn from_header_value(value: &http::HeaderValue) -> Result<Self, ParseForwardedError> {
        Self::parse_record(value.as_bytes())
    }

    /// Check if any of the fields are set.
    ///
    /// When no fields are set, the `Forwarded` header should not be included in the request.
    pub fn any(&self) -> bool {
        self.by.is_some() || self.r#for.is_some() || self.host.is_some() || self.proto.is_some()
    }

    /// Remove the `by` field from the `Forwarded` header.
    pub fn without_by(self) -> Self {
        Self { by: None, ..self }
    }

    /// Set the `X-Forwarded-*` headers on a request.
    pub fn set_x_forwarded_headers<B>(&self, request: &mut http::Request<B>) {
        if let Some(r#for) = self.r#for.as_ref().and_then(|r#for| r#for.x_forwarded()) {
            request
                .headers_mut()
                .append(X_FORWARDED_FOR, r#for.header_value());
        }

        if let Some(host) = &self.host {
            request
                .headers_mut()
                .append(X_FORWARDED_HOST, host.x_forwarded().as_header_value());
        }

        if let Some(proto) = &self.proto {
            request
                .headers_mut()
                .append(X_FORWARDED_PROTO, proto.x_forwarded().as_header_value());
        }
    }

    /// Convert this `Forwarded` header to a byte string.
    pub fn as_bytes(&self) -> Bytes {
        let mut bytes = BytesMut::new();
        if let Some(forwardee) = &self.by {
            bytes.put(&b"by="[..]);
            bytes.put(forwardee.as_bytes());
            bytes.put_u8(b';');
        }

        if let Some(forwardee) = &self.r#for {
            bytes.put(&b"for="[..]);
            bytes.put(forwardee.as_bytes());
            bytes.put_u8(b';');
        }

        if let Some(host) = &self.host {
            bytes.put(&b"host="[..]);
            bytes.put(host.as_bytes());
            bytes.put_u8(b';');
        }

        if let Some(proto) = &self.proto {
            bytes.put(&b"proto="[..]);
            bytes.put(proto.as_bytes());
            bytes.put_u8(b';');
        }

        for (key, value) in &self.extensions {
            bytes.put(key.as_bytes());
            bytes.put_u8(b'=');
            bytes.put(value.as_bytes());
            bytes.put_u8(b';');
        }

        if !bytes.is_empty() {
            bytes.truncate(bytes.len() - 1);
        }

        bytes.freeze()
    }

    /// Convert this `Forwarded` header to a `http::HeaderValue`.
    pub fn to_header_value(&self) -> http::HeaderValue {
        http::HeaderValue::from_bytes(self.as_bytes().as_ref())
            .expect("valid header from typed Forwarded")
    }

    /// Set the `Forwarded` header on a request.
    pub fn set_header<B>(&self, request: &mut http::Request<B>) {
        if self.any() {
            request
                .headers_mut()
                .append(FORWARDED, self.to_header_value());
        }
    }

    /// Set the `Forwarded` header on a request and the `X-Forwarded-*` headers.
    pub fn set_all_headers<B>(&self, request: &mut http::Request<B>) {
        self.set_x_forwarded_headers(request);
        if self.any() {
            request
                .headers_mut()
                .append("forwarded", self.to_header_value());
        }
    }
}

impl HeaderRecordKind for Forwarded {
    const HEADER_NAME: http::HeaderName = FORWARDED;
    const DELIMITER: u8 = b',';

    type Error = ParseForwardedError;

    fn into_bytes(self) -> Vec<u8> {
        self.as_bytes().to_vec()
    }

    fn parse_header_value(header: &http::HeaderValue) -> Result<Vec<Record<Self>>, Self::Error> {
        Self::parse_bytes(header.as_bytes())
    }
}

mod parse {

    use nom::character::complete::char;
    use nom::multi::separated_list1;
    use nom::sequence::separated_pair;
    use nom::IResult;

    use crate::headers::fields::{FieldKey, FieldValue};
    use crate::headers::parser::{key, record, strip_whitespace};

    fn forwarded_key_value<'a>() -> impl FnMut(&'a [u8]) -> IResult<&'a [u8], (FieldKey, FieldValue)>
    {
        separated_pair(
            strip_whitespace(key()),
            char('='),
            strip_whitespace(record()),
        )
    }

    pub type ForwardedRecord = Vec<(FieldKey, FieldValue)>;

    pub(super) fn forwarded_record<'a>(
    ) -> impl FnMut(&'a [u8]) -> IResult<&'a [u8], ForwardedRecord> {
        separated_list1(char(';'), forwarded_key_value())
    }
}

impl Forwarded {
    fn parse_bytes(value: &[u8]) -> Result<Vec<Record<Self>>, ParseForwardedError> {
        use nom::character::complete::char;
        use nom::multi::separated_list0;

        separated_list0(char(','), self::parse::forwarded_record())(value)
            .finish()
            .no_tail()
            .map_err(|error| ParseForwardedError {
                kind: ParseForwadingErrorKind::MalformedRecord(nom::error::Error::new(
                    Bytes::copy_from_slice(error.input),
                    error.code,
                )),
            })
            .and_then(|records| {
                records
                    .into_iter()
                    .map(Forwarded::parse_items)
                    .collect::<Result<Vec<Forwarded>, ParseForwardedError>>()
            })
            .map(|records| records.into_iter().map(Record::from_value).collect())
    }

    fn parse_items<I>(iter: I) -> Result<Forwarded, ParseForwardedError>
    where
        I: IntoIterator<Item = (FieldKey, FieldValue)>,
    {
        let mut data: BTreeMap<_, _> = BTreeMap::new();

        for (key, value) in iter
            .into_iter()
            .map(|(key, value)| (ForwardedKey(key), value))
        {
            if data.contains_key(&key) {
                return Err(ParseForwardedError {
                    kind: ParseForwadingErrorKind::DuplicateField(key),
                });
            }

            data.insert(key, value);
        }

        let by = data
            .remove(&ForwardedKey::BY)
            .map(Forwardee::try_from)
            .transpose()?;

        let r#for = data
            .remove(&ForwardedKey::FOR)
            .map(Forwardee::try_from)
            .transpose()?;
        let host = data
            .remove(&ForwardedKey::HOST)
            .map(|value| ForwardedHost::parse_bytes(value.as_bytes()))
            .transpose()?;

        let proto = data
            .remove(&ForwardedKey::PROTO)
            .map(|value| {
                let v =
                    std::str::from_utf8(value.as_bytes()).map_err(|error| ParseForwardedError {
                        kind: ParseForwadingErrorKind::NonUtf8Proto { error },
                    })?;

                ForwardedProtocol::from_str(v).map_err(|error| ParseForwardedError {
                    kind: ParseForwadingErrorKind::InvalidScheme {
                        key: "proto".to_string(),
                        error,
                    },
                })
            })
            .transpose()?;

        Ok(Forwarded {
            by,
            r#for,
            host,
            proto,
            extensions: data,
        })
    }

    fn parse_record(value: &[u8]) -> Result<Forwarded, ParseForwardedError>
    where
        Self: Sized,
    {
        let records = parse::forwarded_record()(value)
            .finish()
            .no_tail()
            .map_err(|error| ParseForwardedError {
                kind: ParseForwadingErrorKind::MalformedRecord(nom::error::Error::new(
                    Bytes::copy_from_slice(error.input),
                    error.code,
                )),
            })?;

        Self::parse_items(records)
    }
}

impl FromRequest for Forwarded {
    fn from_request<B>(request: &http::Request<B>) -> Self {
        Self::new(request)
    }
}

impl FromStr for Forwarded {
    type Err = ParseForwardedError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse_record(s.as_bytes())
    }
}

#[derive(Debug, Error)]
enum ParseForwadingErrorKind {
    #[error("invalid key=value pair in FORWARDED: {0:?}")]
    MalformedRecord(nom::error::Error<Bytes>),

    #[error("duplicate field in FORWARDED: {0:?}")]
    DuplicateField(ForwardedKey),

    #[error("invalid forwardee for FORWARDED: {0:?}")]
    InvalidForwardee(Bytes),

    #[error("invalid host for FORWARDED (host): {error}")]
    InvalidHost {
        #[source]
        error: http::uri::InvalidUri,
    },

    #[error("invalid host for FORWARDED (host): {error}")]
    NonUtf8Host {
        #[source]
        error: std::str::Utf8Error,
    },

    #[error("invalid protocol for FORWARDED ({key}): {error}")]
    InvalidScheme {
        key: String,
        error: http::uri::InvalidUri,
    },

    #[error("invalid protocol for FORWARDED (proto): {error}")]
    NonUtf8Proto {
        #[source]
        error: std::str::Utf8Error,
    },
}

/// An error parsing a `Forwarded` header record.
#[derive(Debug, Error)]
#[error("{}", .kind)]
pub struct ParseForwardedError {
    kind: ParseForwadingErrorKind,
}

impl<T> From<T> for ParseForwardedError
where
    ParseForwadingErrorKind: From<T>,
{
    fn from(source: T) -> Self {
        ParseForwardedError {
            kind: source.into(),
        }
    }
}

/// An interface used in a `Forwarded` header chain.
///
/// This can be a secret, a named interface, an IP address, or an unknown interface.
///
/// The `Secret` variant is used to indicate that the request was forwarded without revealing the original interface. It is the default.
/// Most implemenetations should provide either the `Secret` or `Address` variant.
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub enum Forwardee {
    /// The request was forwarded on a named interface.
    Named(Token),

    /// The request was forwarded on an IP address.
    Address(ForwardAddress),

    /// The request was forwarded on an unknown interface.
    Unknown,
}

impl Forwardee {
    /// Create the X-Forwarded header value for the `Forwardee`.
    ///
    /// This will return `None` if the `Forwardee` is not an `Address`.
    pub fn x_forwarded(&self) -> Option<XForwardee> {
        match self {
            Forwardee::Address(addr) => Some(XForwardee(addr.x_forwarded())),
            _ => None,
        }
    }

    /// Convert the `Forwardee` to a byte string.
    pub fn as_bytes(&self) -> Bytes {
        match self {
            Forwardee::Named(token) => {
                let mut bytes = BytesMut::new();
                bytes.put_u8(b'_');
                bytes.put(token.as_bytes());
                bytes.freeze()
            }
            Forwardee::Address(addr) => addr.as_bytes(),
            Forwardee::Unknown => Bytes::from_static(b"unknown"),
        }
    }
}

impl TryFrom<FieldValue> for Forwardee {
    type Error = ParseForwardedError;

    fn try_from(value: FieldValue) -> Result<Self, Self::Error> {
        if let Ok(data) = std::str::from_utf8(value.as_bytes()) {
            if data == "unknown" {
                return Ok(Forwardee::Unknown);
            }

            if let Ok(addr) = ForwardAddress::from_str(data) {
                return Ok(Forwardee::Address(addr));
            }
        }

        if value.token().is_some() && value.as_bytes().first().is_some_and(|b| *b == b'_') {
            let token = value.into_token().unwrap();

            return Ok(Forwardee::Named(Token::new(token.into_bytes().slice(1..))));
        }

        Err(ParseForwardedError {
            kind: ParseForwadingErrorKind::InvalidForwardee(Bytes::copy_from_slice(
                value.as_bytes(),
            )),
        })
    }
}

impl From<SocketAddr> for Forwardee {
    fn from(addr: SocketAddr) -> Self {
        Forwardee::Address(addr.into())
    }
}

/// An interface used in a `X-Forwarded-For` header.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
pub struct XForwardee(XForwardAddress);

impl XForwardee {
    /// The `X-Forwarded-For` header value for the `XForwardee`.
    pub fn header_value(&self) -> http::HeaderValue {
        self.0.to_string().parse().unwrap()
    }
}

/// The original protocol used in a proxied request,
/// reported in the `Forwarded` header.
///
/// Only `http` and `https` are supported by [RFC-2739](https://datatracker.ietf.org/doc/html/rfc7239)
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct ForwardedProtocol(http::uri::Scheme);

impl ForwardedProtocol {
    /// Convert the `ForwardProtocol` to a byte string.
    pub fn as_bytes(&self) -> Bytes {
        Bytes::copy_from_slice(self.0.as_str().as_bytes())
    }

    /// Create the X-Forwarded header value for the `ForwardProtocol`.
    pub fn x_forwarded(&self) -> XForwardedProtocol<'_> {
        XForwardedProtocol(self)
    }
}

/// The X-FORWARDED-PROTO header, a de-facto standard header for identifying the protocol (HTTP or HTTPS)
/// that a client used to connect to a proxy or load balancer.
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct XForwardedProtocol<'a>(&'a ForwardedProtocol);

impl XForwardedProtocol<'_> {
    /// Convert the `ForwardProtocol` to a `http::HeaderValue`.
    pub fn as_header_value(&self) -> http::HeaderValue {
        http::HeaderValue::from_bytes(self.0.as_bytes().as_ref()).unwrap()
    }
}

impl From<http::uri::Scheme> for ForwardedProtocol {
    fn from(scheme: http::uri::Scheme) -> Self {
        ForwardedProtocol(scheme)
    }
}

impl FromStr for ForwardedProtocol {
    type Err = http::uri::InvalidUri;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        http::uri::Scheme::from_str(s).map(ForwardedProtocol)
    }
}

/// An address used in a `Forwarded` header.
///
/// This can be an IP address, or an IP address with a port.
///
/// When included as a header value, the address will be quoted and in square brackets if it is an IPv6 address.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
pub struct ForwardAddress {
    ip: IpAddr,
    port: Option<u16>,
}

impl ForwardAddress {
    /// The IP address of the `ForwardAddress`.
    pub fn ip(&self) -> &IpAddr {
        &self.ip
    }

    /// The port of the `ForwardAddress`.
    pub fn port(&self) -> Option<u16> {
        self.port
    }

    /// Set the port of the `ForwardAddress`.
    pub fn with_port(self, port: u16) -> Self {
        Self {
            port: Some(port),
            ..self
        }
    }

    /// Remove the port from the `ForwardAddress`.
    pub fn without_port(self) -> Self {
        Self { port: None, ..self }
    }

    /// Set the IP address of the `ForwardAddress`.
    pub fn with_ip(self, ip: IpAddr) -> Self {
        Self { ip, ..self }
    }

    /// Create the X-Forwarded header value for the `ForwardAddress`.
    pub fn x_forwarded(&self) -> XForwardAddress {
        XForwardAddress(*self)
    }

    /// Convert the `ForwardAddress` to a byte string.
    pub fn as_bytes(&self) -> Bytes {
        let mut bytes = BytesMut::new();

        match &self.ip {
            IpAddr::V4(ip) => {
                bytes.put(ip.to_string().as_bytes());

                if let Some(port) = &self.port {
                    bytes.put_u8(b':');
                    bytes.put(port.to_string().as_bytes());
                }
            }
            IpAddr::V6(ip) => {
                bytes.put_u8(b'"');
                bytes.put_u8(b'[');
                bytes.put(ip.to_string().as_bytes());
                bytes.put_u8(b']');
                if let Some(port) = &self.port {
                    bytes.put_u8(b':');
                    bytes.put(port.to_string().as_bytes());
                }
                bytes.put_u8(b'"');
            }
        }

        bytes.freeze()
    }

    /// Convert the `ForwardAddress` to a `http::HeaderValue`.
    pub fn as_header_value(&self) -> http::HeaderValue {
        http::HeaderValue::from_bytes(self.as_bytes().as_ref()).unwrap()
    }
}

impl fmt::Display for ForwardAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.ip {
            IpAddr::V4(ip) => write!(f, "{}", ip),
            IpAddr::V6(ip) => write!(f, "\"[{}]", ip),
        }?;

        if let Some(port) = &self.port {
            write!(f, ":{}", port)?;
        }

        if self.ip.is_ipv6() {
            write!(f, "\"")
        } else {
            Ok(())
        }
    }
}

impl From<SocketAddr> for ForwardAddress {
    fn from(addr: SocketAddr) -> Self {
        ForwardAddress {
            ip: addr.ip(),
            port: Some(addr.port()),
        }
    }
}

impl From<IpAddr> for ForwardAddress {
    fn from(ip: IpAddr) -> Self {
        ForwardAddress { ip, port: None }
    }
}

/// An error parsing a `ForwardAddress`.
#[derive(Debug, Error)]
#[error("{}", .kind)]
pub struct ForwardParseError {
    kind: ErrorKind,
}

#[derive(Debug, Error)]
enum ErrorKind {
    #[error(transparent)]
    Address(AddrParseError),

    #[error("invalid IPv6 address")]
    InvalidIpv6Address,

    #[error("invalid port for forwarded address")]
    Port(std::num::ParseIntError),
}

impl FromStr for ForwardAddress {
    type Err = ForwardParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let addr = value
            .strip_prefix("\"")
            .and_then(|s| s.strip_suffix("\""))
            .unwrap_or(value);

        let (ip, port) = if addr.starts_with('[') && addr.contains(']') {
            if !addr.chars().filter(|c| *c == '[' || *c == ']').count() == 2 {
                return Err(ForwardParseError {
                    kind: ErrorKind::InvalidIpv6Address,
                });
            }

            let (addr, port) = addr
                .strip_prefix('[')
                .ok_or(ForwardParseError {
                    kind: ErrorKind::InvalidIpv6Address,
                })?
                .split_once(']')
                .ok_or(ForwardParseError {
                    kind: ErrorKind::InvalidIpv6Address,
                })?;

            let port = if let Some(port) = port.strip_prefix(':') {
                if port.is_empty() {
                    return Err(ForwardParseError {
                        kind: ErrorKind::InvalidIpv6Address,
                    });
                }

                Some(port)
            } else {
                None
            };

            let ip: Ipv6Addr = addr.parse().map_err(|error| ForwardParseError {
                kind: ErrorKind::Address(error),
            })?;

            (IpAddr::V6(ip), port)
        } else {
            let (ip, port) = value
                .rsplit_once(':')
                .map(|(ip, port)| (ip, Some(port)))
                .unwrap_or((addr, None));
            let ip: IpAddr = ip.parse().map_err(|error| ForwardParseError {
                kind: ErrorKind::Address(error),
            })?;
            (ip, port)
        };

        let port = port
            .map(|s| {
                s.parse::<u16>().map_err(|err| ForwardParseError {
                    kind: ErrorKind::Port(err),
                })
            })
            .transpose()?;

        Ok(ForwardAddress { ip, port })
    }
}

/// An address used in a `X-Forwarded-For` header.
///
/// This uses a different format than `ForwardAddress`, and is used to create the `X-Forwarded-For` header value.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
pub struct XForwardAddress(ForwardAddress);

impl fmt::Display for XForwardAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.0.ip {
            IpAddr::V4(ip) => write!(f, "{}", ip),
            IpAddr::V6(ip) => write!(f, "{}", ip),
        }
    }
}

/// The `host` field of a `Forwarded` header,
/// representing the original host requested by the client.
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct ForwardedHost {
    host: String,
    port: Option<u16>,
}

impl ForwardedHost {
    /// Create a new `ForwardedHost`.
    pub fn new(host: String, port: Option<u16>) -> Self {
        Self { host, port }
    }

    /// The host of the `ForwardedHost`.
    pub fn host(&self) -> &str {
        &self.host
    }

    /// The port of the `ForwardedHost`.
    pub fn port(&self) -> Option<u16> {
        self.port
    }

    /// Convert the `ForwardedHost` to a byte string.
    pub fn as_bytes(&self) -> Bytes {
        let mut bytes = BytesMut::new();
        bytes.put(self.host.as_bytes());

        if let Some(port) = self.port {
            bytes.put_u8(b':');
            bytes.put(port.to_string().as_bytes());
        }

        bytes.freeze()
    }

    /// Create the X-Forwarded header value for the `ForwardedHost`.
    pub fn x_forwarded(&self) -> XForwardedHost<'_> {
        XForwardedHost(self)
    }

    /// Parse a `ForwardedHost` from a byte string.
    pub fn parse_bytes(value: &[u8]) -> Result<Self, ParseForwardedError> {
        let value = std::str::from_utf8(value).map_err(|error| ParseForwardedError {
            kind: ParseForwadingErrorKind::NonUtf8Host { error },
        })?;
        Self::from_str(value).map_err(|error| ParseForwardedError {
            kind: ParseForwadingErrorKind::InvalidHost { error },
        })
    }
}

impl FromStr for ForwardedHost {
    type Err = http::uri::InvalidUri;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let authority = http::uri::Authority::from_str(s)?;
        Ok(ForwardedHost {
            host: authority.host().to_string(),
            port: authority.port_u16(),
        })
    }
}

/// An address used in a `X-Forwarded-Host` header.
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct XForwardedHost<'a>(&'a ForwardedHost);

impl XForwardedHost<'_> {
    /// The `X-Forwarded-Host` header value for the `XForwardedHost`.
    pub fn as_header_value(&self) -> http::HeaderValue {
        http::HeaderValue::from_bytes(self.0.as_bytes().as_ref()).unwrap()
    }
}

/// A key used in a `Forwarded` header.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ForwardedKey(FieldKey);

impl ForwardedKey {
    /// The interface where the request came in to the proxy server.
    pub const BY: ForwardedKey = ForwardedKey::new(Token::from_static_unchecked("by"));

    /// The client that initiated the request and subsequent proxies in a chain of proxies.
    pub const FOR: ForwardedKey = ForwardedKey::new(Token::from_static_unchecked("for"));

    /// The `host` request header field as received by the proxy.
    pub const HOST: ForwardedKey = ForwardedKey::new(Token::from_static_unchecked("host"));

    /// Indicates which protocol was used to make the request (typically "http" or "https").
    pub const PROTO: ForwardedKey = ForwardedKey::new(Token::from_static_unchecked("proto"));

    /// Convert the `ForwardedKey` to a byte string.
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }

    /// Create a new `ForwardedKey`.
    pub const fn new(token: Token) -> Self {
        Self(FieldKey::new(token))
    }
}

/// A setting which control how the `Forwarded` address fields are displayed.
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub enum ForwardeeMode {
    /// The interface should be displayed as an IP address.
    Address,

    /// The interface should be displayed as a named interface.
    Named(Token),

    /// The interface should be displayed as an unknown interface.
    Unknown,

    /// The interface should be omitted from the `Forwarded` header.
    Omit,
}

/// Configuration for the `Forwarded` header.
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct ForwardedHeaderConfig {
    /// The mode for the `by` field of the `Forwarded` header.
    pub by: ForwardeeMode,

    /// The mode for the `for` field of the `Forwarded` header.
    pub r#for: ForwardeeMode,

    /// Whether to include the `host` field in the `Forwarded` header.
    pub host: bool,

    /// Whether to include the `proto` field in the `Forwarded` header.
    pub proto: bool,
}

impl Default for ForwardedHeaderConfig {
    fn default() -> Self {
        Self {
            by: ForwardeeMode::Omit,
            r#for: ForwardeeMode::Unknown,
            host: true,
            proto: true,
        }
    }
}

impl ForwardedHeaderConfig {
    /// Build a `Forwarded` header from a request.
    pub fn from_request<B>(&self, request: &http::Request<B>) -> Forwarded {
        let mut forwarded = Forwarded::new(request);

        match self.by {
            ForwardeeMode::Address => {
                if let Some(info) = request.extensions().get::<ConnectionInfo<BraidAddr>>() {
                    if let Some(local) = info.local_addr.clone().canonical().tcp() {
                        forwarded.by = Some(Forwardee::Address(local.into()));
                    }
                }
            }
            ForwardeeMode::Named(ref name) => forwarded.by = Some(Forwardee::Named(name.clone())),
            ForwardeeMode::Unknown => forwarded.by = Some(Forwardee::Unknown),
            ForwardeeMode::Omit => forwarded.by = None,
        }

        match self.r#for {
            ForwardeeMode::Address => {
                if let Some(info) = request.extensions().get::<ConnectionInfo<BraidAddr>>() {
                    if let Some(remote) = info.remote_addr.clone().canonical().tcp() {
                        forwarded.r#for = Some(Forwardee::Address(remote.into()));
                    }
                }
            }
            ForwardeeMode::Named(ref name) => {
                forwarded.r#for = Some(Forwardee::Named(name.clone()))
            }
            ForwardeeMode::Unknown => forwarded.r#for = Some(Forwardee::Unknown),
            ForwardeeMode::Omit => forwarded.r#for = None,
        }

        if !self.host {
            forwarded.host = None;
        }

        if !self.proto {
            forwarded.proto = None;
        }

        forwarded
    }
}

/// A middleware for adding a `Forwarded` header to requests.
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct SetForwardedHeader<S> {
    inner: S,
    config: ForwardedHeaderConfig,
    set_x_headers: bool,
    append: AppendHeaderRecordMode,
}

impl<S> SetForwardedHeader<S> {
    /// Create a new `ForwardedHeader` middleware.
    pub fn new(
        inner: S,
        config: ForwardedHeaderConfig,
        set_x_headers: bool,
        append: AppendHeaderRecordMode,
    ) -> Self {
        Self {
            inner,
            config,
            set_x_headers,
            append,
        }
    }

    /// Set the configuration for the `Forwarded` header.
    pub fn config(mut self, config: ForwardedHeaderConfig) -> Self {
        self.config = config;
        self
    }

    /// Apply the `Forwarded` header configuration to a request.
    pub fn set_forwarded_header<B>(&self, req: &mut http::Request<B>) {
        let forward = self.config.from_request(req);

        if self.set_x_headers {
            forward.set_x_forwarded_headers(req);
        }

        ForwardingChain::append_record(&self.append, forward, req.headers_mut());
    }
}

impl<S, B> tower::Service<http::Request<B>> for SetForwardedHeader<S>
where
    S: tower::Service<http::Request<B>>,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = S::Future;

    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: http::Request<B>) -> Self::Future {
        self.set_forwarded_header(&mut req);
        self.inner.call(req)
    }
}

/// A middleware for adding a `Forwarded` header to requests.
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct SetForwardedHeaderLayer {
    config: ForwardedHeaderConfig,
    set_x_headers: bool,
    append: AppendHeaderRecordMode,
}

impl Default for SetForwardedHeaderLayer {
    /// Create a new `ForwardedHeaderLayer` middleware.
    fn default() -> Self {
        Self {
            config: ForwardedHeaderConfig::default(),
            set_x_headers: false,
            append: AppendHeaderRecordMode::default(),
        }
    }
}

impl SetForwardedHeaderLayer {
    /// Create a new `ForwardedHeaderLayer` middleware.
    pub fn new() -> Self {
        Self {
            config: ForwardedHeaderConfig::default(),
            set_x_headers: false,
            append: AppendHeaderRecordMode::default(),
        }
    }

    /// Set the configuration for the `Forwarded` header.
    pub fn config(mut self, config: ForwardedHeaderConfig) -> Self {
        self.config = config;
        self
    }

    /// Set whether to include the `X-Forwarded-*` headers.
    pub fn set_x_headers(mut self, set_x_headers: bool) -> Self {
        self.set_x_headers = set_x_headers;
        self
    }

    /// Set wether to collect the `Forwarded` headers into a chain.
    pub fn append_forwarded_headers(mut self, append: AppendHeaderRecordMode) -> Self {
        self.append = append;
        self
    }
}

impl<S> tower::layer::Layer<S> for SetForwardedHeaderLayer {
    type Service = SetForwardedHeader<S>;

    fn layer(&self, inner: S) -> Self::Service {
        SetForwardedHeader {
            inner,
            config: self.config.clone(),
            set_x_headers: self.set_x_headers,
            append: self.append.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use hyperdriver::info::BraidAddr;
    use tower::ServiceExt;

    use super::*;

    #[test]
    fn forwardee_display() {
        assert_eq!(
            Forwardee::Address("127.0.0.1".parse().unwrap())
                .as_bytes()
                .as_ref(),
            b"127.0.0.1"
        );
        assert_eq!(
            Forwardee::Address("[::1]:8080".parse().unwrap())
                .as_bytes()
                .as_ref(),
            b"\"[::1]:8080\""
        );
        assert_eq!(Forwardee::Unknown.as_bytes().as_ref(), b"unknown");
        assert_eq!(
            Forwardee::Named(Token::from_static("name"))
                .as_bytes()
                .as_ref(),
            b"_name"
        );
    }

    #[test]
    fn parse_forwarded_address() {
        assert_eq!(
            "192.168.0.1".parse::<ForwardAddress>().unwrap(),
            IpAddr::V4(Ipv4Addr::new(192, 168, 0, 1)).into()
        );

        assert_eq!(
            "192.168.0.2:8888".parse::<ForwardAddress>().unwrap(),
            ForwardAddress::from(IpAddr::V4(Ipv4Addr::new(192, 168, 0, 2))).with_port(8888)
        );

        assert_eq!(
            "\"[2001:db8:cafe::17]\"".parse::<ForwardAddress>().unwrap(),
            IpAddr::V6("2001:db8:cafe::17".parse().unwrap()).into(),
            "IPv6 address without port, but quoted with brackets"
        );

        assert_eq!(
            "\"[2001:db8:cafe::17]:4711\""
                .parse::<ForwardAddress>()
                .unwrap(),
            ForwardAddress::from(IpAddr::V6("2001:db8:cafe::17".parse().unwrap())).with_port(4711)
        );

        assert!("2001:db8:cafe::17".parse::<ForwardAddress>().is_err());
    }

    #[test]
    fn forwarded_bytes() {
        let forwarded = Forwarded {
            r#for: Some(Forwardee::Address(
                "[2001:db8:cafe::17]:4711".parse().unwrap(),
            )),
            ..Default::default()
        };

        assert_eq!(
            forwarded.as_bytes().as_ref(),
            b"for=\"[2001:db8:cafe::17]:4711\""
        );

        let forwarded = Forwarded {
            r#for: Some(Forwardee::Address("192.0.2.60".parse().unwrap())),
            proto: Some(http::uri::Scheme::HTTP.into()),
            by: Some(Forwardee::Address("203.0.113.43".parse().unwrap())),
            ..Default::default()
        };

        assert_eq!(
            forwarded.as_bytes().as_ref(),
            b"by=203.0.113.43;for=192.0.2.60;proto=http"
        );
    }

    fn parse_record_str(record: &str) -> Forwarded {
        let records = Forwarded::parse_bytes(record.as_bytes()).unwrap();
        assert_eq!(records.len(), 1);
        records.into_iter().next().unwrap().into_value().unwrap()
    }

    #[test]
    fn parse_forwarded_record() {
        let forwarded = parse_record_str("For=192.0.2.60; pRoTo=https");

        let expected = Forwarded {
            r#for: Some(Forwardee::Address("192.0.2.60".parse().unwrap())),
            proto: Some(http::uri::Scheme::HTTPS.into()),
            ..Default::default()
        };

        assert_eq!(forwarded, expected);
    }

    #[test]
    fn parse_forwarded_chain() {
        let forwarded = "for=192.0.2.1, for=\"[2001:db8:cafe::18]:8080\";proto=https";
        let mut request = http::Request::new(());
        request
            .headers_mut()
            .insert(FORWARDED, forwarded.parse().unwrap());
        request
            .headers_mut()
            .append(FORWARDED, "for=192.0.2.5".parse().unwrap());

        let chain = ForwardingChain::from_headers(request.headers());
        assert_eq!(chain.len(), 2);

        let mut iter = chain.flat_into_iter();

        assert_eq!(
            iter.next().unwrap().into_value().unwrap(),
            Forwarded {
                r#for: Some(Forwardee::Address("192.0.2.1".parse().unwrap())),
                ..Default::default()
            },
        );

        assert_eq!(
            iter.next().unwrap().into_value().unwrap(),
            Forwarded {
                r#for: Some(Forwardee::Address(
                    "[2001:db8:cafe::18]:8080".parse().unwrap()
                )),
                proto: Some(http::uri::Scheme::HTTPS.into()),
                ..Default::default()
            },
        );

        assert_eq!(
            iter.next().unwrap().into_value().unwrap(),
            Forwarded {
                r#for: Some(Forwardee::Address("192.0.2.5".parse().unwrap())),
                ..Default::default()
            },
            "Third record at 192.0.2.5",
        );

        assert!(iter.next().is_none());
    }

    #[test]
    fn parse_forwarded() {
        let forwarded = "for=192.0.2.60;by=203.0.113.43;proto=http".parse().unwrap();
        assert_eq!(
            Forwarded {
                r#for: Some(Forwardee::Address("192.0.2.60".parse().unwrap())),
                proto: Some(http::uri::Scheme::HTTP.into()),
                by: Some(Forwardee::Address("203.0.113.43".parse().unwrap())),
                ..Default::default()
            },
            forwarded
        );
    }

    #[test]
    fn parse_forwarded_roundtrip() {
        let forwarded = Forwarded {
            r#for: Some(Forwardee::Address(
                "[2001:db8:cafe::17]:4711".parse().unwrap(),
            )),
            ..Default::default()
        };

        let parsed = Forwarded::parse_record(forwarded.as_bytes().as_ref()).unwrap();
        assert_eq!(parsed, forwarded);
    }

    #[test]
    fn forwarded_x_headers() {
        let forwarded = Forwarded {
            r#for: Some(Forwardee::Address(
                "[2001:db8:cafe::17]:4711".parse().unwrap(),
            )),
            ..Default::default()
        };

        let mut request = http::Request::new(());
        forwarded.set_x_forwarded_headers(&mut request);

        assert_eq!(
            request.headers().get("x-forwarded-for").unwrap(),
            "2001:db8:cafe::17"
        );
    }

    #[test]
    fn forwarded_config() {
        let config = ForwardedHeaderConfig {
            by: ForwardeeMode::Omit,
            r#for: ForwardeeMode::Address,
            host: false,
            proto: false,
        };

        let mut request = http::Request::new(());
        request
            .extensions_mut()
            .insert(ConnectionInfo::<BraidAddr> {
                local_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 80).into(),
                remote_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8080).into(),
            });
        let forwarded = config.from_request(&request);

        assert_eq!(forwarded.by, None);
        assert_eq!(
            forwarded.r#for.as_ref(),
            Some(&Forwardee::Address(
                SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8080).into()
            ))
        );
        assert_eq!(forwarded.host, None);
        assert_eq!(forwarded.proto, None);

        let config = ForwardedHeaderConfig {
            by: ForwardeeMode::Named(Token::from_static("proxy")),
            r#for: ForwardeeMode::Named(Token::from_static("client")),
            host: true,
            proto: true,
        };

        let mut request = http::Request::new(());
        request
            .extensions_mut()
            .insert(ConnectionInfo::<BraidAddr> {
                local_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 80).into(),
                remote_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8080).into(),
            });
        let forwarded = config.from_request(&request);

        assert_eq!(
            forwarded.by.as_ref(),
            Some(&Forwardee::Named(Token::from_static("proxy")))
        );
        assert_eq!(
            forwarded.r#for.as_ref(),
            Some(&Forwardee::Named(Token::from_static("client")))
        );
        assert_eq!(forwarded.host, None);
        assert_eq!(forwarded.proto, None);
    }

    fn connection_info() -> ConnectionInfo<BraidAddr> {
        ConnectionInfo {
            local_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 80).into(),
            remote_addr: SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 8080).into(),
        }
    }

    #[test]
    fn forwarded_header_from_request() {
        let mut request = http::Request::new(());
        request.extensions_mut().insert(connection_info());

        let forwarded = Forwarded::new(&request);

        assert_eq!(
            forwarded.r#for.as_ref(),
            Some(&Forwardee::Address(
                SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 8080).into()
            ))
        );
    }

    #[tokio::test]
    async fn forwarded_header_service() {
        let service = SetForwardedHeader::new(
            tower::service_fn(|req: http::Request<()>| async { Ok::<_, ()>(req) }),
            Default::default(),
            false,
            Default::default(),
        );

        let mut request = http::Request::get("http://example.com").body(()).unwrap();
        request.extensions_mut().insert(connection_info());
        request
            .headers_mut()
            .insert(http::header::HOST, "example.com".parse().unwrap());

        let response = service.oneshot(request).await.unwrap();
        let forwarded = response.headers().get(FORWARDED).unwrap();
        assert_eq!(forwarded, "for=unknown;host=example.com;proto=http");
    }

    #[tokio::test]
    async fn forwarded_header_service_ipv6() {
        for mode in [
            AppendHeaderRecordMode::Append,
            AppendHeaderRecordMode::Chain,
            AppendHeaderRecordMode::Expand,
            AppendHeaderRecordMode::KeepFirst,
            AppendHeaderRecordMode::KeepLast,
        ] {
            let service = SetForwardedHeader::new(
                tower::service_fn(|req: http::Request<()>| async { Ok::<_, ()>(req) }),
                Default::default(),
                false,
                mode,
            )
            .config(ForwardedHeaderConfig {
                r#for: ForwardeeMode::Address,
                ..Default::default()
            });

            let mut request = http::Request::get("https://example.com").body(()).unwrap();
            request
                .headers_mut()
                .insert(http::header::HOST, "example.com".parse().unwrap());
            request.extensions_mut().insert(connection_info());

            let response = service.oneshot(request).await.unwrap();
            let forwarded = response.headers().get(FORWARDED).unwrap();
            assert_eq!(forwarded, "for=\"[::1]:8080\";host=example.com;proto=https");
        }
    }

    #[tokio::test]
    async fn xforwarded_header_service() {
        let service = SetForwardedHeader::new(
            tower::service_fn(|req: http::Request<()>| async { Ok::<_, ()>(req) }),
            Default::default(),
            true,
            AppendHeaderRecordMode::KeepLast,
        )
        .config(ForwardedHeaderConfig {
            r#for: ForwardeeMode::Address,
            ..Default::default()
        });

        let mut request = http::Request::get("http://example.com").body(()).unwrap();
        request
            .headers_mut()
            .insert(http::header::HOST, "example.com".parse().unwrap());
        request.extensions_mut().insert(connection_info());

        let response = service.oneshot(request).await.unwrap();
        let forwarded = response.headers().get(FORWARDED).unwrap();
        assert_eq!(forwarded, "for=\"[::1]:8080\";host=example.com;proto=http");

        let x_forwarded_for = response
            .headers()
            .get(X_FORWARDED_FOR)
            .expect("Missing X-Forwarded-For");
        assert_eq!(x_forwarded_for, "::1");

        let x_forwarded_host = response
            .headers()
            .get(X_FORWARDED_HOST)
            .expect("Missing X-Forwarded-Host");
        assert_eq!(x_forwarded_host, "example.com");

        let x_forwarded_proto = response
            .headers()
            .get(X_FORWARDED_PROTO)
            .expect("Missing X-Forwarded-Proto");
        assert_eq!(x_forwarded_proto, "http");
    }

    #[tokio::test]
    async fn xforwarded_header_service_named() {
        let service = SetForwardedHeader::new(
            tower::service_fn(|req: http::Request<()>| async { Ok::<_, ()>(req) }),
            Default::default(),
            true,
            Default::default(),
        )
        .config(ForwardedHeaderConfig {
            r#for: ForwardeeMode::Named(Token::from_static("example-proxy")),
            ..Default::default()
        });

        let mut request = http::Request::get("http://example.com").body(()).unwrap();
        request
            .headers_mut()
            .insert(http::header::HOST, "example.com".parse().unwrap());
        request.extensions_mut().insert(connection_info());

        let response = service.oneshot(request).await.unwrap();
        let forwarded = response.headers().get(FORWARDED).unwrap();
        assert_eq!(forwarded, "for=_example-proxy;host=example.com;proto=http");

        assert!(
            response.headers().get(X_FORWARDED_FOR).is_none(),
            "Named forward address should not result in X-Forwarded-For header"
        );

        let x_forwarded_host = response
            .headers()
            .get(X_FORWARDED_HOST)
            .expect("Missing X-Forwarded-Host");
        assert_eq!(x_forwarded_host, "example.com");

        let x_forwarded_proto = response
            .headers()
            .get(X_FORWARDED_PROTO)
            .expect("Missing X-Forwarded-Proto");
        assert_eq!(x_forwarded_proto, "http");
    }

    #[tokio::test]
    async fn forwarded_header_service_preseves_junk() {
        let service = SetForwardedHeader::new(
            tower::service_fn(|req: http::Request<()>| async { Ok::<_, ()>(req) }),
            Default::default(),
            false,
            AppendHeaderRecordMode::Chain,
        );

        let mut request = http::Request::get("http://example.com").body(()).unwrap();
        request
            .headers_mut()
            .insert(http::header::HOST, "example.com".parse().unwrap());
        request.headers_mut().insert(
            FORWARDED,
            http::HeaderValue::from_bytes(b"not-a-valid value\xaf, for=192.0.2.5;proto=https")
                .unwrap(),
        );
        request.extensions_mut().insert(connection_info());

        let response = service.oneshot(request).await.unwrap();
        let forwarded = response.headers().get(FORWARDED).unwrap();

        assert_eq!(
            forwarded,
            http::HeaderValue::from_bytes(
                b"not-a-valid value\xaf, for=192.0.2.5;proto=https, for=unknown;host=example.com;proto=http"
            )
            .unwrap()
        );
    }

    #[tokio::test]
    async fn forwarded_header_service_append() {
        let service = SetForwardedHeader::new(
            tower::service_fn(|req: http::Request<()>| async { Ok::<_, ()>(req) }),
            Default::default(),
            false,
            AppendHeaderRecordMode::Append,
        );

        let mut request = http::Request::get("http://example.com").body(()).unwrap();
        request
            .headers_mut()
            .insert(http::header::HOST, "example.com".parse().unwrap());
        request.headers_mut().insert(
            FORWARDED,
            http::HeaderValue::from_str(
                "for=192.0.2.5; proto=https, for=\"[2001:db8:cafe::17]:4711\"",
            )
            .unwrap(),
        );

        request.extensions_mut().insert(connection_info());

        let response = service.oneshot(request).await.unwrap();
        let headers = response.headers().get_all(FORWARDED);
        assert_eq!(headers.iter().count(), 2);

        let chain = ForwardingChain::from_headers(response.headers());
        assert_eq!(chain.len(), 2);
        assert_eq!(chain.flat_iter().count(), 3);

        let mut iter = chain.flat_into_iter();
        assert_eq!(
            iter.next().unwrap().into_value().unwrap(),
            Forwarded {
                r#for: Some(Forwardee::Address("192.0.2.5".parse().unwrap())),
                proto: Some(http::uri::Scheme::HTTPS.into()),
                ..Default::default()
            },
        );

        assert_eq!(
            iter.next().unwrap().into_value().unwrap(),
            Forwarded {
                r#for: Some(Forwardee::Address(
                    "[2001:db8:cafe::17]:4711".parse().unwrap()
                )),
                ..Default::default()
            },
        );

        assert_eq!(
            iter.next().unwrap().into_value().unwrap(),
            Forwarded {
                r#for: Some(Forwardee::Unknown),
                host: Some("example.com".parse().unwrap()),
                proto: Some(http::uri::Scheme::HTTP.into()),
                ..Default::default()
            },
        );
    }

    #[tokio::test]
    async fn forwarded_header_service_keepfirst() {
        let service = SetForwardedHeader::new(
            tower::service_fn(|req: http::Request<()>| async { Ok::<_, ()>(req) }),
            Default::default(),
            false,
            AppendHeaderRecordMode::KeepFirst,
        );

        let mut request = http::Request::get("http://example.com").body(()).unwrap();
        request
            .headers_mut()
            .insert(http::header::HOST, "example.com".parse().unwrap());
        request.headers_mut().insert(
            FORWARDED,
            http::HeaderValue::from_str("for=192.0.2.4").unwrap(),
        );

        let response = service.oneshot(request).await.unwrap();
        let headers = response.headers().get_all(FORWARDED);
        assert_eq!(headers.iter().count(), 1);

        let chain = ForwardingChain::from_headers(response.headers());
        assert_eq!(chain.len(), 1);
        assert_eq!(chain.flat_iter().count(), 1);

        let mut iter = chain.flat_into_iter();
        assert_eq!(
            iter.next().unwrap().into_value().unwrap(),
            Forwarded {
                r#for: Some(Forwardee::Address("192.0.2.4".parse().unwrap())),
                ..Default::default()
            }
        );
    }
}
