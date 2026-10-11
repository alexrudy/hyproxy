//! Typed version of the HTTP `Forwarded` header.
//!
//! See [RFC-7239](https://datatracker.ietf.org/doc/html/rfc7239)
//! for the specification of the `Forwarded` header.

use std::collections::BTreeMap;
use std::fmt;
use std::net::{AddrParseError, IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::str::FromStr;

use bytes::{BufMut, Bytes, BytesMut};
use nom::Finish;
use thiserror::Error;

use super::fields::{FieldKey, FieldValue, Token};

use super::chain::{
    AppendHeaderRecordMode, FromRequest, Header, HeaderChain, HeaderRecordKind, Record,
};
use super::parser::{put_field_value, NoTail};

/// The `Forwarded` header, a standard header for identifying the originating IP address of a client connecting to a web server through a proxy server.
///
/// This header is defined in [RFC-7239](https://datatracker.ietf.org/doc/html/rfc7239).
pub const FORWARDED: http::HeaderName = http::header::FORWARDED;

/// The `X-Forwarded-For` header, a de-facto standard header for identifying the originating IP
/// address of a client connecting to a web server through a proxy server. It has been replaced by `Forwarded`.
pub const X_FORWARDED_FOR: http::HeaderName =
    http::header::HeaderName::from_static("x-forwarded-for");

/// The `X-Forwarded-Host` header, a de-facto standard header for identifying the original host requested by the client in the `Host` HTTP request header.
pub const X_FORWARDED_HOST: http::HeaderName =
    http::header::HeaderName::from_static("x-forwarded-host");

/// The `X-Forwarded-Proto` header, a de-facto standard header for identifying the protocol (HTTP or HTTPS) that a client used to connect to your proxy or load balancer.
pub const X_FORWARDED_PROTO: http::HeaderName =
    http::header::HeaderName::from_static("x-forwarded-proto");

/// The `X-Forwarded-Port` header, a de-facto standard header for identifying the port that a
/// client connected to on your proxy or load balancer.
///
/// This is provided for convenience; [`SetForwardedHeader`] does not set it, since `Forwarded`
/// has no equivalent field (the port is part of `host`, if it was present in the `Host` header).
pub const X_FORWARDED_PORT: http::HeaderName =
    http::header::HeaderName::from_static("x-forwarded-port");

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
    ///
    /// Every `for` address in the chain is appended to `X-Forwarded-For`, while
    /// `X-Forwarded-Host` and `X-Forwarded-Proto` are taken from the first record
    /// that has them, unless already present. See [`Forwarded::set_x_forwarded_headers`].
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
    /// This will skip unparsed raw values. See [`ForwardingChain::set_all_x_forwarded_headers`].
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
            .or_else(|| self.raw().map(|bytes| !bytes.is_empty()))
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

/// The remote address for the current connection.
///
/// This is expected to be present in the http::Request extensions
/// when using the connection.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct RemoteAddress(pub ForwardAddress);

/// The local address for the current connection.
///
/// This is expected to be present in the http::Request extensions
/// when using the connection.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct LocalAddress(pub ForwardAddress);

/// The scheme of the connection the request arrived on (`http` or `https`).
///
/// When present in the http::Request extensions, this is used for the
/// `proto` field of the `Forwarded` header. It takes precedence over the
/// request URI's scheme, which describes the request target rather than the
/// connection, and is usually absent for HTTP/1.1 requests.
///
/// [`ConnectionInfoAdapter`] inserts `https` when TLS connection info is
/// available. Servers that only accept plaintext connections should insert
/// `ConnectionScheme(Scheme::HTTP)` themselves.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ConnectionScheme(pub http::uri::Scheme);

#[cfg(feature = "hyperdriver")]
pub use self::info::{ConnectionInfoAdapter, ConnectionInfoAdapterLayer};

#[cfg(feature = "hyperdriver")]
mod info {
    use std::net::SocketAddr;

    use chateau::info::TlsConnectionInfo;
    use hyperdriver::info::ConnectionInfo;

    use super::{ConnectionScheme, LocalAddress, RemoteAddress};

    /// A layer that wraps a service with a [`ConnectionInfoAdapter`].
    ///
    /// This adapts the hyperdriver-specific [`ConnectionInfo`] object
    /// and provides the hyproxy-specific [`RemoteAddress`] and [`LocalAddress`]
    /// for use in the Forward headers.
    #[derive(Debug, Default, Clone, Copy)]
    pub struct ConnectionInfoAdapterLayer;

    impl<S> tower::Layer<S> for ConnectionInfoAdapterLayer {
        type Service = ConnectionInfoAdapter<S>;

        fn layer(&self, inner: S) -> Self::Service {
            ConnectionInfoAdapter::new(inner)
        }
    }

    /// A service to provide the connection info for a request.
    ///
    /// This adapts the hyperdriver-specific [`ConnectionInfo`] object
    /// and provides the hyproxy-specific [`RemoteAddress`] and [`LocalAddress`]
    /// for use in the Forward headers.
    ///
    /// If the request carries [`TlsConnectionInfo`] (see hyperdriver's
    /// `with_tls_connection_info`), this also inserts
    /// [`ConnectionScheme`]`(https)`. Without TLS connection info, the scheme
    /// cannot be determined, and no [`ConnectionScheme`] is inserted.
    #[derive(Debug, Default, Clone)]
    pub struct ConnectionInfoAdapter<S> {
        service: S,
    }

    impl<S> ConnectionInfoAdapter<S> {
        /// Creates a new [`ConnectionInfoAdapter`] with the given service.
        pub fn new(service: S) -> Self {
            Self { service }
        }

        /// Returns a reference to the inner service.
        pub fn inner(&self) -> &S {
            &self.service
        }

        /// Returns the inner service, consuming this adapter.
        pub fn into_inner(self) -> S {
            self.service
        }
    }

    impl<B, S> tower::Service<http::Request<B>> for ConnectionInfoAdapter<S>
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
            self.service.poll_ready(cx)
        }

        fn call(&mut self, mut req: http::Request<B>) -> Self::Future {
            if let Some(info) = req.extensions().get::<ConnectionInfo>().cloned() {
                if let Some(&remote) = info.remote_addr.downcast_ref::<SocketAddr>() {
                    req.extensions_mut().insert(RemoteAddress(remote.into()));
                }

                if let Some(&local) = info.local_addr.downcast_ref::<SocketAddr>() {
                    req.extensions_mut().insert(LocalAddress(local.into()));
                }
            } else {
                // Common for e.g. in-memory transports or tests, so not worth a warning per request.
                tracing::debug!("connection info not found in request extensions");
            }

            if req.extensions().get::<TlsConnectionInfo>().is_some() {
                req.extensions_mut()
                    .insert(ConnectionScheme(http::uri::Scheme::HTTPS));
            }

            self.service.call(req)
        }
    }
}

/// The contents of one record in a `Forwarded` header.
///
/// A forwarded header can consist of multiple comma-separated records, each containing a set of key-value pairs.
///
/// This type is `#[non_exhaustive]`, so construct it with [`Default`] and the `with_*` methods:
///
/// ```
/// use std::net::{IpAddr, Ipv4Addr};
/// use hyproxy::headers::forward::{Forwarded, Forwardee};
///
/// let forwarded = Forwarded::default()
///     .with_for(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 60)))
///     .with_by(Forwardee::unknown())
///     .with_host("example.com".parse().unwrap())
///     .with_proto(http::uri::Scheme::HTTPS);
///
/// assert_eq!(
///     forwarded.to_header_value(),
///     "by=unknown;for=192.0.2.60;host=example.com;proto=https"
/// );
/// ```
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
    /// It expects that the request has been processed by some middleware that adds the `RemoteAddress` extension,
    /// and optionally the local address.
    ///
    /// - `host` is taken from the `Host` header, falling back to the request URI's
    ///   authority (which is where HTTP/2 carries `:authority`).
    /// - `proto` is taken from the [`ConnectionScheme`] extension, falling back to
    ///   the request URI's scheme.
    pub fn new<B>(request: &http::Request<B>) -> Self {
        let mut by = None;
        let mut r#for = None;
        let mut host = None;
        let mut proto = None;

        if let Some(&remote) = request.extensions().get::<RemoteAddress>() {
            r#for = Some(Forwardee::address(remote.0));
        }

        if let Some(&local) = request.extensions().get::<LocalAddress>() {
            by = Some(Forwardee::address(local.0));
        }

        if let Some(header) = request.headers().get(http::header::HOST) {
            host = ForwardedHost::parse_bytes(header.as_bytes()).ok();
        } else if let Some(authority) = request.uri().authority() {
            // Userinfo is not part of the host, so build from the parts rather than parsing.
            host = Some(ForwardedHost::new(
                authority.host().to_string(),
                authority.port_u16(),
            ));
        }

        if let Some(ConnectionScheme(scheme)) = request.extensions().get::<ConnectionScheme>() {
            proto = Some(scheme.clone().into());
        } else if let Some(scheme) = request.uri().scheme() {
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
        self.by.is_some()
            || self.r#for.is_some()
            || self.host.is_some()
            || self.proto.is_some()
            || !self.extensions.is_empty()
    }

    /// Remove the `by` field from the `Forwarded` header.
    pub fn without_by(self) -> Self {
        Self { by: None, ..self }
    }

    /// Set the `by` field: the interface where the request came in to the proxy.
    pub fn with_by(self, by: impl Into<Forwardee>) -> Self {
        Self {
            by: Some(by.into()),
            ..self
        }
    }

    /// Set the `for` field: the client that initiated the request.
    pub fn with_for(self, r#for: impl Into<Forwardee>) -> Self {
        Self {
            r#for: Some(r#for.into()),
            ..self
        }
    }

    /// Set the `host` field: the original `Host` requested by the client.
    pub fn with_host(self, host: ForwardedHost) -> Self {
        Self {
            host: Some(host),
            ..self
        }
    }

    /// Set the `proto` field: the protocol the request arrived on.
    pub fn with_proto(self, proto: impl Into<ForwardedProtocol>) -> Self {
        Self {
            proto: Some(proto.into()),
            ..self
        }
    }

    /// Add an extension parameter, replacing any existing value for `key`.
    ///
    /// `key` must not be one of the standard parameters (`by`, `for`, `host`,
    /// `proto`); use the dedicated methods for those. Otherwise the parameter
    /// would be emitted twice, which RFC 7239 forbids.
    pub fn with_extension(mut self, key: ForwardedKey, value: FieldValue) -> Self {
        debug_assert!(
            ![
                ForwardedKey::BY,
                ForwardedKey::FOR,
                ForwardedKey::HOST,
                ForwardedKey::PROTO
            ]
            .contains(&key),
            "{key:?} is a standard Forwarded parameter, not an extension"
        );
        self.extensions.insert(key, value);
        self
    }

    /// Set the `X-Forwarded-*` headers on a request.
    ///
    /// This is equivalent to [`Forwarded::append_x_forwarded_headers`] with
    /// [`AppendHeaderRecordMode::Append`]: the `for` address is appended to
    /// `X-Forwarded-For`, while `X-Forwarded-Host` and `X-Forwarded-Proto` are
    /// only set if they are not already present.
    pub fn set_x_forwarded_headers<B>(&self, request: &mut http::Request<B>) {
        self.append_x_forwarded_headers(&AppendHeaderRecordMode::Append, request.headers_mut());
    }

    /// Set the `X-Forwarded-*` headers, treating any existing values according to `mode`.
    ///
    /// The mode expresses how much the upstream values are trusted, and is
    /// applied the same way as for the `Forwarded` header chain.
    ///
    /// `X-Forwarded-For` is a list, so each comma-separated entry is treated as a record:
    ///
    /// | Mode        | `X-Forwarded-For`                                     |
    /// |-------------|-------------------------------------------------------|
    /// | `Append`    | Our address is added as a new header line.            |
    /// | `Chain`     | Our address is added to the last header line.         |
    /// | `Flatten`   | All entries, then ours, are combined into one line.   |
    /// | `Expand`    | Each entry, then ours, gets its own header line.      |
    /// | `KeepFirst` | Only the first existing entry is kept, or ours if none. |
    /// | `KeepLast`  | Only our address is kept.                             |
    /// | `Omit`      | The header is removed.                                |
    ///
    /// `X-Forwarded-Host` and `X-Forwarded-Proto` describe the original client
    /// request, and are conventionally single-valued:
    ///
    /// | Mode                                       | `X-Forwarded-Host` / `X-Forwarded-Proto`      |
    /// |--------------------------------------------|-----------------------------------------------|
    /// | `Append`, `Chain`, `Flatten`, `Expand`     | An existing value is kept; otherwise ours is set. |
    /// | `KeepFirst`                                | Only the first existing entry is kept; otherwise ours is set. |
    /// | `KeepLast`                                 | Existing values are replaced by ours.         |
    /// | `Omit`                                     | The header is removed.                        |
    pub fn append_x_forwarded_headers(
        &self,
        mode: &AppendHeaderRecordMode,
        headers: &mut http::HeaderMap,
    ) {
        let r#for = self
            .r#for
            .as_ref()
            .and_then(Forwardee::x_forwarded)
            .map(|r#for| r#for.to_header_value());
        append_x_forwarded_list(mode, X_FORWARDED_FOR, r#for, headers);

        let host = self
            .host
            .as_ref()
            .map(|host| host.x_forwarded().to_header_value());
        append_x_forwarded_single(mode, X_FORWARDED_HOST, host, headers);

        let proto = self
            .proto
            .as_ref()
            .map(|proto| proto.x_forwarded().to_header_value());
        append_x_forwarded_single(mode, X_FORWARDED_PROTO, proto, headers);
    }

    /// Convert this `Forwarded` header to a byte string.
    pub fn to_bytes(&self) -> Bytes {
        let mut bytes = BytesMut::new();
        if let Some(forwardee) = &self.by {
            bytes.put(&b"by="[..]);
            bytes.put(forwardee.to_bytes());
            bytes.put_u8(b';');
        }

        if let Some(forwardee) = &self.r#for {
            bytes.put(&b"for="[..]);
            bytes.put(forwardee.to_bytes());
            bytes.put_u8(b';');
        }

        if let Some(host) = &self.host {
            bytes.put(&b"host="[..]);
            put_field_value(&mut bytes, &host.to_bytes());
            bytes.put_u8(b';');
        }

        if let Some(proto) = &self.proto {
            bytes.put(&b"proto="[..]);
            put_field_value(&mut bytes, &proto.to_bytes());
            bytes.put_u8(b';');
        }

        for (key, value) in &self.extensions {
            bytes.put(key.as_bytes());
            bytes.put_u8(b'=');
            bytes.put(value.to_header_bytes());
            bytes.put_u8(b';');
        }

        if !bytes.is_empty() {
            bytes.truncate(bytes.len() - 1);
        }

        bytes.freeze()
    }

    /// Convert this `Forwarded` header to a `http::HeaderValue`.
    pub fn to_header_value(&self) -> http::HeaderValue {
        http::HeaderValue::from_bytes(self.to_bytes().as_ref())
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
        self.set_header(request);
    }
}

/// Split all values of a comma-separated list header into trimmed, non-empty entries.
fn x_forwarded_entries(headers: &http::HeaderMap, name: &http::HeaderName) -> Vec<Vec<Vec<u8>>> {
    headers
        .get_all(name)
        .iter()
        .map(|value| {
            value
                .as_bytes()
                .split(|&c| c == b',')
                .map(<[u8]>::trim_ascii)
                .filter(|entry| !entry.is_empty())
                .map(<[u8]>::to_vec)
                .collect()
        })
        .collect()
}

fn join_x_forwarded_entries<'a, I>(entries: I) -> Option<http::HeaderValue>
where
    I: IntoIterator<Item = &'a [u8]>,
{
    let joined = entries.into_iter().collect::<Vec<_>>().join(&b", "[..]);
    if joined.is_empty() {
        return None;
    }

    // Entries are sub-slices of valid header values (or our own values), so
    // joining them with ", " always produces a valid header value.
    http::HeaderValue::from_bytes(&joined).ok()
}

/// The first entry of the first value of `name`, if any.
fn first_x_forwarded_entry(
    headers: &http::HeaderMap,
    name: &http::HeaderName,
) -> Option<http::HeaderValue> {
    x_forwarded_entries(headers, name)
        .into_iter()
        .flatten()
        .next()
        .and_then(|entry| http::HeaderValue::from_bytes(&entry).ok())
}

fn append_x_forwarded_list(
    mode: &AppendHeaderRecordMode,
    name: http::HeaderName,
    ours: Option<http::HeaderValue>,
    headers: &mut http::HeaderMap,
) {
    use AppendHeaderRecordMode as Mode;

    match mode {
        Mode::Append => {
            if let Some(ours) = ours {
                headers.append(name, ours);
            }
        }
        Mode::Chain => {
            let Some(ours) = ours else { return };
            let mut values: Vec<_> = headers.get_all(&name).iter().cloned().collect();
            let last = values
                .pop()
                .and_then(|last| join_x_forwarded_entries([last.as_bytes(), ours.as_bytes()]))
                .unwrap_or(ours);

            headers.remove(&name);
            for value in values {
                headers.append(&name, value);
            }
            headers.append(name, last);
        }
        Mode::Flatten => {
            let entries = x_forwarded_entries(headers, &name);
            let joined = join_x_forwarded_entries(
                entries
                    .iter()
                    .flatten()
                    .map(Vec::as_slice)
                    .chain(ours.as_ref().map(http::HeaderValue::as_bytes)),
            );

            headers.remove(&name);
            if let Some(joined) = joined {
                headers.insert(name, joined);
            }
        }
        Mode::Expand => {
            let entries = x_forwarded_entries(headers, &name);

            headers.remove(&name);
            for entry in entries.iter().flatten() {
                if let Ok(value) = http::HeaderValue::from_bytes(entry) {
                    headers.append(&name, value);
                }
            }
            if let Some(ours) = ours {
                headers.append(name, ours);
            }
        }
        Mode::KeepFirst => {
            let value = first_x_forwarded_entry(headers, &name).or(ours);
            headers.remove(&name);
            if let Some(value) = value {
                headers.insert(name, value);
            }
        }
        Mode::KeepLast => {
            headers.remove(&name);
            if let Some(ours) = ours {
                headers.insert(name, ours);
            }
        }
        Mode::Omit => {
            headers.remove(&name);
        }
    }
}

fn append_x_forwarded_single(
    mode: &AppendHeaderRecordMode,
    name: http::HeaderName,
    ours: Option<http::HeaderValue>,
    headers: &mut http::HeaderMap,
) {
    use AppendHeaderRecordMode as Mode;

    match mode {
        Mode::Append | Mode::Chain | Mode::Flatten | Mode::Expand => {
            if let Some(ours) = ours {
                if !headers.contains_key(&name) {
                    headers.insert(name, ours);
                }
            }
        }
        Mode::KeepFirst => {
            let value = first_x_forwarded_entry(headers, &name).or(ours);
            headers.remove(&name);
            if let Some(value) = value {
                headers.insert(name, value);
            }
        }
        Mode::KeepLast => {
            headers.remove(&name);
            if let Some(ours) = ours {
                headers.insert(name, ours);
            }
        }
        Mode::Omit => {
            headers.remove(&name);
        }
    }
}

impl HeaderRecordKind for Forwarded {
    const HEADER_NAME: http::HeaderName = FORWARDED;
    const DELIMITER: u8 = b',';

    type Error = ParseForwardedError;

    fn into_bytes(self) -> Vec<u8> {
        self.to_bytes().to_vec()
    }

    fn parse_header_value(header: &http::HeaderValue) -> Result<Vec<Record<Self>>, Self::Error> {
        Self::parse_bytes(header.as_bytes())
    }
}

/// Parsers for the RFC 7239 section 4 grammar:
///
/// ```text
/// Forwarded         = 1#forwarded-element
/// forwarded-element = [ forwarded-pair ] *( ";" [ forwarded-pair ] )
/// forwarded-pair    = token "=" value
/// value             = token / quoted-string
/// ```
///
/// Optional whitespace is tolerated around `;` and `,` (the RFC's own examples
/// use it), but not around `=`. Empty pairs and empty list elements are accepted
/// and ignored, as RFC 7230 section 7 requires of recipients.
mod parse {

    use nom::character::complete::{char, space0};
    use nom::combinator::{map, opt};
    use nom::multi::many0;
    use nom::sequence::{delimited, pair, preceded, separated_pair};
    use nom::IResult;

    use crate::headers::fields::{FieldKey, FieldValue};
    use crate::headers::parser::{key, record};

    pub type ForwardedRecord = Vec<(FieldKey, FieldValue)>;

    fn forwarded_pair(input: &[u8]) -> IResult<&[u8], (FieldKey, FieldValue)> {
        separated_pair(key(), char('='), record())(input)
    }

    fn separator(c: char) -> impl FnMut(&[u8]) -> IResult<&[u8], char> {
        move |input| delimited(space0, char(c), space0)(input)
    }

    /// A single `forwarded-element`. Always succeeds, possibly with no pairs.
    fn forwarded_element(input: &[u8]) -> IResult<&[u8], ForwardedRecord> {
        map(
            pair(
                opt(forwarded_pair),
                many0(preceded(separator(';'), opt(forwarded_pair))),
            ),
            |(first, rest)| {
                first
                    .into_iter()
                    .chain(rest.into_iter().flatten())
                    .collect()
            },
        )(input)
    }

    /// A single `forwarded-element`, with surrounding whitespace.
    pub(super) fn forwarded_record(input: &[u8]) -> IResult<&[u8], ForwardedRecord> {
        delimited(space0, forwarded_element, space0)(input)
    }

    /// A full `Forwarded` header value. Empty elements are dropped.
    pub(super) fn forwarded_records(input: &[u8]) -> IResult<&[u8], Vec<ForwardedRecord>> {
        map(
            delimited(
                space0,
                pair(
                    forwarded_element,
                    many0(preceded(separator(','), forwarded_element)),
                ),
                space0,
            ),
            |(first, rest)| {
                std::iter::once(first)
                    .chain(rest)
                    .filter(|element| !element.is_empty())
                    .collect()
            },
        )(input)
    }
}

impl Forwarded {
    fn parse_bytes(value: &[u8]) -> Result<Vec<Record<Self>>, ParseForwardedError> {
        parse::forwarded_records(value)
            .finish()
            .no_tail()
            .map_err(|error| ParseForwardedError {
                kind: ParseForwardedErrorKind::MalformedRecord(nom::error::Error::new(
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
                    kind: ParseForwardedErrorKind::DuplicateField(key),
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
            .map(|value| ForwardedHost::parse_bytes(&value.unescaped()))
            .transpose()?;

        let proto = data
            .remove(&ForwardedKey::PROTO)
            .map(|value| {
                let value = value.unescaped();
                let v = std::str::from_utf8(&value).map_err(|error| ParseForwardedError {
                    kind: ParseForwardedErrorKind::NonUtf8Proto { error },
                })?;

                ForwardedProtocol::from_str(v).map_err(|error| ParseForwardedError {
                    kind: ParseForwardedErrorKind::InvalidScheme { error },
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

    fn parse_record(value: &[u8]) -> Result<Forwarded, ParseForwardedError> {
        let records = parse::forwarded_record(value)
            .finish()
            .no_tail()
            .map_err(|error| ParseForwardedError {
                kind: ParseForwardedErrorKind::MalformedRecord(nom::error::Error::new(
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
enum ParseForwardedErrorKind {
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

    #[error("invalid host for FORWARDED (host): userinfo is not permitted")]
    HostWithUserinfo,

    #[error("invalid host for FORWARDED (host): not valid UTF-8: {error}")]
    NonUtf8Host {
        #[source]
        error: std::str::Utf8Error,
    },

    #[error("invalid protocol for FORWARDED (proto): {error}")]
    InvalidScheme {
        #[source]
        error: http::uri::InvalidUri,
    },

    #[error("invalid protocol for FORWARDED (proto): not valid UTF-8: {error}")]
    NonUtf8Proto {
        #[source]
        error: std::str::Utf8Error,
    },
}

/// An error parsing a `Forwarded` header record.
#[derive(Debug, Error)]
#[error(transparent)]
pub struct ParseForwardedError {
    kind: ParseForwardedErrorKind,
}

/// A node in a `Forwarded` header: the value of a `for` or `by` parameter.
///
/// A node is a name, optionally followed by a port, as defined in
/// [RFC 7239 section 6](https://datatracker.ietf.org/doc/html/rfc7239#section-6):
///
/// ```text
/// node      = nodename [ ":" node-port ]
/// nodename  = IPv4address / "[" IPv6address "]" / "unknown" / obfnode
/// node-port = port / obfport
/// ```
///
/// Any kind of name can carry any kind of port, so `unknown:8080`,
/// `_hidden:_port` and `"[::1]:_port"` are all valid nodes.
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct Forwardee {
    name: NodeName,
    port: Option<NodePort>,
}

/// An obfuscated identifier, used in a [`Forwardee`] to identify a node or port
/// without revealing it (`obfnode` and `obfport` in RFC 7239 section 6.3):
///
/// ```text
/// obfnode = "_" 1*( ALPHA / DIGIT / "." / "_" / "-")
/// obfport = "_" 1*(ALPHA / DIGIT / "." / "_" / "-")
/// ```
///
/// The name is stored without the leading `_`, and is validated on construction,
/// so it is always valid in a `Forwarded` header. [`Display`](fmt::Display) and
/// [`FromStr`] use the header form, including the leading `_`.
///
/// ```
/// use hyproxy::headers::forward::ObfuscatedName;
///
/// const PROXY: ObfuscatedName = ObfuscatedName::from_static("proxy-1");
/// assert_eq!(PROXY.as_str(), "proxy-1");
/// assert_eq!(PROXY.to_string(), "_proxy-1");
/// assert_eq!("_proxy-1".parse::<ObfuscatedName>().unwrap(), PROXY);
///
/// assert!(ObfuscatedName::new("not valid!").is_err());
/// ```
///
/// Invalid names in a `const` are rejected at compile time:
///
/// ```compile_fail
/// use hyproxy::headers::forward::ObfuscatedName;
///
/// const INVALID: ObfuscatedName = ObfuscatedName::from_static("not valid!");
/// ```
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ObfuscatedName(Bytes);

impl ObfuscatedName {
    /// Create an obfuscated name, without the leading `_`.
    ///
    /// Returns an error if `name` is empty, or contains characters other than
    /// `ALPHA / DIGIT / "." / "_" / "-"`.
    pub fn new(name: &str) -> Result<Self, ForwardParseError> {
        if Self::is_valid(name.as_bytes()) {
            Ok(Self(Bytes::copy_from_slice(name.as_bytes())))
        } else {
            Err(ForwardParseError {
                kind: ErrorKind::InvalidObfuscatedIdentifier,
            })
        }
    }

    /// Create an obfuscated name from a static string, without the leading `_`.
    ///
    /// # Panics
    /// If `name` is not a valid obfuscated name (see [`ObfuscatedName::new`]).
    /// When used in a `const` context, this is a compile-time error instead.
    pub const fn from_static(name: &'static str) -> Self {
        assert!(
            Self::is_valid(name.as_bytes()),
            "invalid obfuscated name: expected 1 or more of ALPHA / DIGIT / '.' / '_' / '-'"
        );
        Self(Bytes::from_static(name.as_bytes()))
    }

    /// The name, without the leading `_`.
    pub fn as_str(&self) -> &str {
        std::str::from_utf8(&self.0).expect("obfuscated names are validated as ASCII")
    }

    const fn is_valid(name: &[u8]) -> bool {
        if name.is_empty() {
            return false;
        }

        let mut i = 0;
        while i < name.len() {
            if !is_obfuscated_char(name[i]) {
                return false;
            }
            i += 1;
        }
        true
    }
}

impl fmt::Debug for ObfuscatedName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("ObfuscatedName")
            .field(&self.as_str())
            .finish()
    }
}

impl fmt::Display for ObfuscatedName {
    /// Formats the name as it appears in a header, with the leading `_`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "_{}", self.as_str())
    }
}

impl FromStr for ObfuscatedName {
    type Err = ForwardParseError;

    /// Parse an obfuscated name in its header form, with the leading `_`.
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        value
            .strip_prefix('_')
            .ok_or(ForwardParseError {
                kind: ErrorKind::InvalidObfuscatedIdentifier,
            })
            .and_then(Self::new)
    }
}

impl AsRef<str> for ObfuscatedName {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl TryFrom<&str> for ObfuscatedName {
    type Error = ForwardParseError;

    /// Equivalent to [`ObfuscatedName::new`]: `name` is without the leading `_`.
    fn try_from(name: &str) -> Result<Self, Self::Error> {
        Self::new(name)
    }
}

impl TryFrom<Token> for ObfuscatedName {
    type Error = ForwardParseError;

    /// Validate a token as an obfuscated name (without the leading `_`).
    ///
    /// Tokens permit characters (such as `!` or `~`) which obfuscated names do not.
    fn try_from(token: Token) -> Result<Self, Self::Error> {
        if Self::is_valid(token.as_bytes()) {
            Ok(Self(token.into_bytes()))
        } else {
            Err(ForwardParseError {
                kind: ErrorKind::InvalidObfuscatedIdentifier,
            })
        }
    }
}

/// The name portion of a [`Forwardee`] (`nodename` in RFC 7239 section 6).
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub enum NodeName {
    /// An IPv4 or IPv6 address.
    Address(IpAddr),

    /// An obfuscated identifier (`obfnode`), used to identify an interface
    /// without revealing its address.
    Obfuscated(ObfuscatedName),

    /// The `unknown` identifier, used when the node is not known or is
    /// intentionally hidden.
    Unknown,
}

/// The port portion of a [`Forwardee`] (`node-port` in RFC 7239 section 6).
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub enum NodePort {
    /// A numeric port.
    Port(u16),

    /// An obfuscated port (`obfport`).
    Obfuscated(ObfuscatedName),
}

impl Forwardee {
    /// Create a new `Forwardee` from a name and an optional port.
    pub const fn new(name: NodeName, port: Option<NodePort>) -> Self {
        Self { name, port }
    }

    /// A node identified by an IP address, with an optional numeric port.
    pub fn address(addr: ForwardAddress) -> Self {
        Self {
            name: NodeName::Address(addr.ip),
            port: addr.port.map(NodePort::Port),
        }
    }

    /// A node identified by an obfuscated name, with no port.
    pub const fn obfuscated(name: ObfuscatedName) -> Self {
        Self::new(NodeName::Obfuscated(name), None)
    }

    /// The `unknown` node, with no port.
    pub const fn unknown() -> Self {
        Self::new(NodeName::Unknown, None)
    }

    /// The name of this node.
    pub fn name(&self) -> &NodeName {
        &self.name
    }

    /// The port of this node, if any.
    pub fn port(&self) -> Option<&NodePort> {
        self.port.as_ref()
    }

    /// The IP address of this node, if it is identified by one.
    pub fn ip(&self) -> Option<IpAddr> {
        match self.name {
            NodeName::Address(ip) => Some(ip),
            _ => None,
        }
    }

    /// Set the port of this node.
    pub fn with_port(self, port: NodePort) -> Self {
        Self {
            port: Some(port),
            ..self
        }
    }

    /// Remove the port from this node.
    pub fn without_port(self) -> Self {
        Self { port: None, ..self }
    }

    /// Create the X-Forwarded header value for the `Forwardee`.
    ///
    /// This will return `None` if the `Forwardee` is not identified by an IP address.
    pub fn x_forwarded(&self) -> Option<XForwardee> {
        self.ip()
            .map(|ip| XForwardee(ForwardAddress::from(ip).x_forwarded()))
    }

    /// Convert the `Forwardee` to a byte string.
    ///
    /// The result is a valid `Forwarded` field value: it is emitted as a token
    /// where possible, and as a quoted-string otherwise (e.g. for IPv6
    /// addresses, or any node with a port).
    pub fn to_bytes(&self) -> Bytes {
        let node = match &self.port {
            Some(port) => format!("{}:{}", self.name, port),
            None => self.name.to_string(),
        };

        let mut bytes = BytesMut::with_capacity(node.len() + 2);
        put_field_value(&mut bytes, node.as_bytes());
        bytes.freeze()
    }

    /// Parse a node from its unquoted, unescaped text.
    fn parse_node(node: &str) -> Result<Self, ForwardParseError> {
        let invalid = |kind| ForwardParseError { kind };

        let (name, port) = if let Some(rest) = node.strip_prefix('[') {
            let (ip, rest) = rest
                .split_once(']')
                .ok_or(invalid(ErrorKind::InvalidIpv6Address))?;

            let ip: Ipv6Addr = ip
                .parse()
                .map_err(|error| invalid(ErrorKind::Address(error)))?;

            let port = if rest.is_empty() {
                None
            } else {
                Some(
                    rest.strip_prefix(':')
                        .ok_or(invalid(ErrorKind::InvalidIpv6Address))?,
                )
            };

            (NodeName::Address(ip.into()), port)
        } else {
            let (name, port) = match node.split_once(':') {
                Some((name, port)) => (name, Some(port)),
                None => (node, None),
            };

            (name.parse()?, port)
        };

        let port = port.map(str::parse).transpose()?;
        Ok(Self { name, port })
    }
}

impl fmt::Display for Forwardee {
    /// Formats the node as a `Forwarded` field value, quoted if necessary.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // `to_bytes` only ever produces ASCII.
        f.write_str(&String::from_utf8_lossy(&self.to_bytes()))
    }
}

impl FromStr for Forwardee {
    type Err = ForwardParseError;

    /// Parse a node. The value may optionally be wrapped in double quotes.
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let node = value
            .strip_prefix('"')
            .and_then(|s| s.strip_suffix('"'))
            .unwrap_or(value);

        Self::parse_node(node)
    }
}

impl TryFrom<FieldValue> for Forwardee {
    type Error = ParseForwardedError;

    /// Parse a `node` (RFC 7239 section 6). The value may be a token or a
    /// quoted-string; both forms are interpreted identically.
    fn try_from(value: FieldValue) -> Result<Self, Self::Error> {
        let node = value.unescaped();

        std::str::from_utf8(&node)
            .ok()
            .and_then(|node| Forwardee::parse_node(node).ok())
            .ok_or_else(|| ParseForwardedError {
                kind: ParseForwardedErrorKind::InvalidForwardee(Bytes::copy_from_slice(&node)),
            })
    }
}

impl From<ForwardAddress> for Forwardee {
    fn from(addr: ForwardAddress) -> Self {
        Self::address(addr)
    }
}

impl From<SocketAddr> for Forwardee {
    fn from(addr: SocketAddr) -> Self {
        Self::address(addr.into())
    }
}

impl From<IpAddr> for Forwardee {
    fn from(ip: IpAddr) -> Self {
        Self::address(ip.into())
    }
}

impl From<NodeName> for Forwardee {
    fn from(name: NodeName) -> Self {
        Self::new(name, None)
    }
}

/// Characters permitted after the leading `_` of an `obfnode` or `obfport`.
const fn is_obfuscated_char(c: u8) -> bool {
    c.is_ascii_alphanumeric() || c == b'.' || c == b'_' || c == b'-'
}

impl fmt::Display for NodeName {
    /// Formats the name as it appears in a `node`, without any quoting.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NodeName::Address(IpAddr::V4(ip)) => write!(f, "{ip}"),
            NodeName::Address(IpAddr::V6(ip)) => write!(f, "[{ip}]"),
            NodeName::Obfuscated(name) => write!(f, "{name}"),
            NodeName::Unknown => f.write_str("unknown"),
        }
    }
}

impl FromStr for NodeName {
    type Err = ForwardParseError;

    /// Parse a `nodename`. IPv6 addresses must be enclosed in brackets.
    fn from_str(name: &str) -> Result<Self, Self::Err> {
        let invalid = |kind| ForwardParseError { kind };

        // ABNF string literals are case-insensitive (RFC 5234 section 2.3).
        if name.eq_ignore_ascii_case("unknown") {
            return Ok(NodeName::Unknown);
        }

        if name.starts_with('_') {
            return name.parse().map(NodeName::Obfuscated);
        }

        if let Some(ip) = name.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
            let ip: Ipv6Addr = ip
                .parse()
                .map_err(|error| invalid(ErrorKind::Address(error)))?;
            return Ok(NodeName::Address(ip.into()));
        }

        // IPv6 addresses must be bracketed, so anything else must be IPv4.
        let ip: Ipv4Addr = name
            .parse()
            .map_err(|error| invalid(ErrorKind::Address(error)))?;
        Ok(NodeName::Address(ip.into()))
    }
}

impl From<IpAddr> for NodeName {
    fn from(ip: IpAddr) -> Self {
        NodeName::Address(ip)
    }
}

impl fmt::Display for NodePort {
    /// Formats the port as it appears in a `node`, without the leading `:`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NodePort::Port(port) => write!(f, "{port}"),
            NodePort::Obfuscated(port) => write!(f, "{port}"),
        }
    }
}

impl FromStr for NodePort {
    type Err = ForwardParseError;

    /// Parse a `node-port`: either `1*5DIGIT` or an obfuscated `_` identifier.
    fn from_str(port: &str) -> Result<Self, Self::Err> {
        let invalid = |kind| ForwardParseError { kind };

        if port.starts_with('_') {
            return port.parse().map(NodePort::Obfuscated);
        }

        // Checked explicitly because `u16::from_str` also accepts a leading `+`.
        if port.is_empty() || port.len() > 5 || !port.bytes().all(|c| c.is_ascii_digit()) {
            return Err(invalid(ErrorKind::InvalidPort));
        }

        port.parse()
            .map(NodePort::Port)
            .map_err(|error| invalid(ErrorKind::Port(error)))
    }
}

impl From<u16> for NodePort {
    fn from(port: u16) -> Self {
        NodePort::Port(port)
    }
}

/// An interface used in a `X-Forwarded-For` header.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
pub struct XForwardee(XForwardAddress);

impl XForwardee {
    /// The `X-Forwarded-For` header value for the `XForwardee`.
    pub fn to_header_value(&self) -> http::HeaderValue {
        self.0.to_string().parse().unwrap()
    }
}

/// The original protocol used in a proxied request,
/// reported in the `Forwarded` header.
///
/// [RFC 7239 section 5.4](https://datatracker.ietf.org/doc/html/rfc7239#section-5.4) permits any
/// URI scheme name, though `http` and `https` are by far the most common.
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct ForwardedProtocol(http::uri::Scheme);

impl ForwardedProtocol {
    /// The URI scheme of this protocol.
    pub fn scheme(&self) -> &http::uri::Scheme {
        &self.0
    }

    /// Convert into the URI scheme of this protocol.
    pub fn into_scheme(self) -> http::uri::Scheme {
        self.0
    }

    /// Convert the `ForwardedProtocol` to a byte string.
    pub fn to_bytes(&self) -> Bytes {
        Bytes::copy_from_slice(self.0.as_str().as_bytes())
    }

    /// Create the X-Forwarded header value for the `ForwardedProtocol`.
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
    pub fn to_header_value(&self) -> http::HeaderValue {
        http::HeaderValue::from_bytes(self.0.to_bytes().as_ref()).unwrap()
    }
}

impl From<ForwardedProtocol> for http::uri::Scheme {
    fn from(proto: ForwardedProtocol) -> Self {
        proto.into_scheme()
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
    ///
    /// The result is a valid `Forwarded` field value: a bare IPv4 address is
    /// emitted as a token, while anything containing `:` or `[` (IPv6, or any
    /// address with a port) is emitted as a quoted-string, per RFC 7239 section 6.
    pub fn to_bytes(&self) -> Bytes {
        let node = match (&self.ip, self.port) {
            (IpAddr::V4(ip), None) => ip.to_string(),
            (IpAddr::V4(ip), Some(port)) => format!("{ip}:{port}"),
            (IpAddr::V6(ip), None) => format!("[{ip}]"),
            (IpAddr::V6(ip), Some(port)) => format!("[{ip}]:{port}"),
        };

        let mut bytes = BytesMut::with_capacity(node.len() + 2);
        put_field_value(&mut bytes, node.as_bytes());
        bytes.freeze()
    }

    /// Convert the `ForwardAddress` to a `http::HeaderValue`.
    pub fn to_header_value(&self) -> http::HeaderValue {
        http::HeaderValue::from_bytes(self.to_bytes().as_ref()).unwrap()
    }
}

impl fmt::Display for ForwardAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // `to_bytes` only ever produces ASCII.
        f.write_str(&String::from_utf8_lossy(&self.to_bytes()))
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

/// An error parsing a [`Forwardee`], [`ForwardAddress`], [`NodeName`] or [`NodePort`].
#[derive(Debug, Error)]
#[error(transparent)]
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

    #[error("invalid port for forwarded address: expected 1 to 5 digits")]
    InvalidPort,

    #[error(
        "invalid obfuscated identifier: expected '_' followed by ALPHA / DIGIT / '.' / '_' / '-'"
    )]
    InvalidObfuscatedIdentifier,

    #[error("forwarded node is not an IP address")]
    NotAnAddress,

    #[error("forwarded address has an obfuscated port, which cannot be represented numerically")]
    ObfuscatedPort,
}

impl FromStr for ForwardAddress {
    type Err = ForwardParseError;

    /// Parse an IP-address `node` (RFC 7239 section 6) with an optional numeric port.
    ///
    /// The value may optionally be wrapped in double quotes. Nodes which are
    /// valid, but are not IP addresses with numeric ports (e.g. `unknown` or
    /// `"[::1]:_port"`), are rejected; parse a [`Forwardee`] to accept those.
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let invalid = |kind| ForwardParseError { kind };
        let node: Forwardee = value.parse()?;

        let NodeName::Address(ip) = node.name else {
            return Err(invalid(ErrorKind::NotAnAddress));
        };

        let port = match node.port {
            None => None,
            Some(NodePort::Port(port)) => Some(port),
            Some(NodePort::Obfuscated(_)) => return Err(invalid(ErrorKind::ObfuscatedPort)),
        };

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
    pub fn to_bytes(&self) -> Bytes {
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
            kind: ParseForwardedErrorKind::NonUtf8Host { error },
        })?;
        Self::from_str(value)
    }
}

impl FromStr for ForwardedHost {
    type Err = ParseForwardedError;

    /// Parse a `Host` header value: `uri-host [ ":" port ]` (RFC 9110 section 7.2).
    ///
    /// Unlike a URI authority, this does not permit userinfo (`user@host`).
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.contains('@') {
            return Err(ParseForwardedError {
                kind: ParseForwardedErrorKind::HostWithUserinfo,
            });
        }

        let authority = http::uri::Authority::from_str(s).map_err(|error| ParseForwardedError {
            kind: ParseForwardedErrorKind::InvalidHost { error },
        })?;
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
    pub fn to_header_value(&self) -> http::HeaderValue {
        http::HeaderValue::from_bytes(self.0.to_bytes().as_ref()).unwrap()
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

    /// The interface should be displayed as an obfuscated identifier.
    Obfuscated(ObfuscatedName),

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
                if forwarded.by.as_ref().and_then(Forwardee::ip).is_none() {
                    forwarded.by = None;
                }
            }
            ForwardeeMode::Obfuscated(ref name) => {
                forwarded.by = Some(Forwardee::obfuscated(name.clone()))
            }
            ForwardeeMode::Unknown => forwarded.by = Some(Forwardee::unknown()),
            ForwardeeMode::Omit => forwarded.by = None,
        }

        match self.r#for {
            ForwardeeMode::Address => {
                if forwarded.r#for.as_ref().and_then(Forwardee::ip).is_none() {
                    forwarded.r#for = None;
                }
            }
            ForwardeeMode::Obfuscated(ref name) => {
                forwarded.r#for = Some(Forwardee::obfuscated(name.clone()))
            }
            ForwardeeMode::Unknown => forwarded.r#for = Some(Forwardee::unknown()),
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
    /// Create a new `SetForwardedHeader` middleware.
    ///
    /// See [`SetForwardedHeaderLayer::set_x_headers`] and
    /// [`SetForwardedHeaderLayer::append_forwarded_headers`] for the meaning of
    /// `set_x_headers` and `append`.
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

    /// Set whether to include the `X-Forwarded-*` headers.
    ///
    /// See [`SetForwardedHeaderLayer::set_x_headers`].
    pub fn set_x_headers(mut self, set_x_headers: bool) -> Self {
        self.set_x_headers = set_x_headers;
        self
    }

    /// Set how the new `Forwarded` record is combined with existing ones.
    ///
    /// See [`SetForwardedHeaderLayer::append_forwarded_headers`].
    pub fn append_forwarded_headers(mut self, append: AppendHeaderRecordMode) -> Self {
        self.append = append;
        self
    }

    /// Returns a reference to the inner service.
    pub fn inner(&self) -> &S {
        &self.inner
    }

    /// Returns the inner service, consuming this middleware.
    pub fn into_inner(self) -> S {
        self.inner
    }

    /// Apply the `Forwarded` header configuration to a request.
    pub fn set_forwarded_header<B>(&self, req: &mut http::Request<B>) {
        let forward = self.config.from_request(req);

        if self.set_x_headers {
            forward.append_x_forwarded_headers(&self.append, req.headers_mut());
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

/// A layer which wraps services in [`SetForwardedHeader`], adding a `Forwarded`
/// header to requests.
#[derive(Debug, Default, Clone, Eq, PartialEq, Hash)]
pub struct SetForwardedHeaderLayer {
    config: ForwardedHeaderConfig,
    set_x_headers: bool,
    append: AppendHeaderRecordMode,
}

impl SetForwardedHeaderLayer {
    /// Create a new `SetForwardedHeaderLayer` with the default configuration.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the configuration for the `Forwarded` header.
    pub fn config(mut self, config: ForwardedHeaderConfig) -> Self {
        self.config = config;
        self
    }

    /// Set whether to include the `X-Forwarded-*` headers.
    ///
    /// When enabled, existing `X-Forwarded-*` headers are handled according to
    /// the [`AppendHeaderRecordMode`] (see [`Self::append_forwarded_headers`]),
    /// as described in [`Forwarded::append_x_forwarded_headers`]. When disabled,
    /// existing `X-Forwarded-*` headers are left untouched.
    pub fn set_x_headers(mut self, set_x_headers: bool) -> Self {
        self.set_x_headers = set_x_headers;
        self
    }

    /// Set how the new `Forwarded` record is combined with existing ones.
    ///
    /// This also expresses how far upstream proxies are trusted, and so applies
    /// to the `X-Forwarded-*` headers too, when they are enabled. For example,
    /// [`AppendHeaderRecordMode::KeepLast`] discards all upstream values, which
    /// is appropriate for a proxy at the edge of the network.
    pub fn append_forwarded_headers(mut self, append: AppendHeaderRecordMode) -> Self {
        self.append = append;
        self
    }
}

impl<S> tower::layer::Layer<S> for SetForwardedHeaderLayer {
    type Service = SetForwardedHeader<S>;

    fn layer(&self, inner: S) -> Self::Service {
        SetForwardedHeader::new(
            inner,
            self.config.clone(),
            self.set_x_headers,
            self.append.clone(),
        )
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use tower::ServiceExt;

    use super::*;

    fn connection_info<B>(request: &mut http::Request<B>) {
        request.extensions_mut().insert(LocalAddress(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 80).into(),
        ));
        request.extensions_mut().insert(RemoteAddress(
            SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 8080).into(),
        ));
    }

    #[test]
    fn forwardee_display() {
        assert_eq!(
            Forwardee::address("127.0.0.1".parse().unwrap())
                .to_bytes()
                .as_ref(),
            b"127.0.0.1"
        );
        assert_eq!(
            Forwardee::address("[::1]:8080".parse().unwrap())
                .to_bytes()
                .as_ref(),
            b"\"[::1]:8080\""
        );
        assert_eq!(Forwardee::unknown().to_bytes().as_ref(), b"unknown");
        assert_eq!(
            Forwardee::obfuscated(ObfuscatedName::from_static("name"))
                .to_bytes()
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
            r#for: Some(Forwardee::address(
                "[2001:db8:cafe::17]:4711".parse().unwrap(),
            )),
            ..Default::default()
        };

        assert_eq!(
            forwarded.to_bytes().as_ref(),
            b"for=\"[2001:db8:cafe::17]:4711\""
        );

        let forwarded = Forwarded {
            r#for: Some(Forwardee::address("192.0.2.60".parse().unwrap())),
            proto: Some(http::uri::Scheme::HTTP.into()),
            by: Some(Forwardee::address("203.0.113.43".parse().unwrap())),
            ..Default::default()
        };

        assert_eq!(
            forwarded.to_bytes().as_ref(),
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
            r#for: Some(Forwardee::address("192.0.2.60".parse().unwrap())),
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
                r#for: Some(Forwardee::address("192.0.2.1".parse().unwrap())),
                ..Default::default()
            },
        );

        assert_eq!(
            iter.next().unwrap().into_value().unwrap(),
            Forwarded {
                r#for: Some(Forwardee::address(
                    "[2001:db8:cafe::18]:8080".parse().unwrap()
                )),
                proto: Some(http::uri::Scheme::HTTPS.into()),
                ..Default::default()
            },
        );

        assert_eq!(
            iter.next().unwrap().into_value().unwrap(),
            Forwarded {
                r#for: Some(Forwardee::address("192.0.2.5".parse().unwrap())),
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
                r#for: Some(Forwardee::address("192.0.2.60".parse().unwrap())),
                proto: Some(http::uri::Scheme::HTTP.into()),
                by: Some(Forwardee::address("203.0.113.43".parse().unwrap())),
                ..Default::default()
            },
            forwarded
        );
    }

    #[test]
    fn parse_forwarded_roundtrip() {
        let forwarded = Forwarded {
            r#for: Some(Forwardee::address(
                "[2001:db8:cafe::17]:4711".parse().unwrap(),
            )),
            ..Default::default()
        };

        let parsed = Forwarded::parse_record(forwarded.to_bytes().as_ref()).unwrap();
        assert_eq!(parsed, forwarded);
    }

    #[test]
    fn forwarded_x_headers() {
        let forwarded = Forwarded {
            r#for: Some(Forwardee::address(
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
        connection_info(&mut request);
        let forwarded = config.from_request(&request);

        assert_eq!(forwarded.by, None);
        assert_eq!(
            forwarded.r#for.as_ref(),
            Some(&Forwardee::address(
                SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 8080).into()
            ))
        );
        assert_eq!(forwarded.host, None);
        assert_eq!(forwarded.proto, None);

        let config = ForwardedHeaderConfig {
            by: ForwardeeMode::Obfuscated(ObfuscatedName::from_static("proxy")),
            r#for: ForwardeeMode::Obfuscated(ObfuscatedName::from_static("client")),
            host: true,
            proto: true,
        };

        let mut request = http::Request::new(());
        connection_info(&mut request);

        let forwarded = config.from_request(&request);

        assert_eq!(
            forwarded.by.as_ref(),
            Some(&Forwardee::obfuscated(ObfuscatedName::from_static("proxy")))
        );
        assert_eq!(
            forwarded.r#for.as_ref(),
            Some(&Forwardee::obfuscated(ObfuscatedName::from_static(
                "client"
            )))
        );
        assert_eq!(forwarded.host, None);
        assert_eq!(forwarded.proto, None);
    }

    #[test]
    fn forwarded_header_from_request() {
        let mut request = http::Request::new(());
        connection_info(&mut request);

        let forwarded = Forwarded::new(&request);

        assert_eq!(
            forwarded.r#for.as_ref(),
            Some(&Forwardee::address(
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
        connection_info(&mut request);

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
            connection_info(&mut request);

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
        connection_info(&mut request);

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
    async fn xforwarded_header_service_obfuscated() {
        let service = SetForwardedHeader::new(
            tower::service_fn(|req: http::Request<()>| async { Ok::<_, ()>(req) }),
            Default::default(),
            true,
            Default::default(),
        )
        .config(ForwardedHeaderConfig {
            r#for: ForwardeeMode::Obfuscated(ObfuscatedName::from_static("example-proxy")),
            ..Default::default()
        });

        let mut request = http::Request::get("http://example.com").body(()).unwrap();
        request
            .headers_mut()
            .insert(http::header::HOST, "example.com".parse().unwrap());
        connection_info(&mut request);

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
    async fn forwarded_header_service_preserves_junk() {
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
        connection_info(&mut request);

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

        connection_info(&mut request);

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
                r#for: Some(Forwardee::address("192.0.2.5".parse().unwrap())),
                proto: Some(http::uri::Scheme::HTTPS.into()),
                ..Default::default()
            },
        );

        assert_eq!(
            iter.next().unwrap().into_value().unwrap(),
            Forwarded {
                r#for: Some(Forwardee::address(
                    "[2001:db8:cafe::17]:4711".parse().unwrap()
                )),
                ..Default::default()
            },
        );

        assert_eq!(
            iter.next().unwrap().into_value().unwrap(),
            Forwarded {
                r#for: Some(Forwardee::unknown()),
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
                r#for: Some(Forwardee::address("192.0.2.4".parse().unwrap())),
                ..Default::default()
            }
        );
    }

    fn roundtrip(forwarded: &Forwarded) -> Forwarded {
        Forwarded::parse_record(forwarded.to_bytes().as_ref()).unwrap_or_else(|error| {
            panic!(
                "failed to re-parse {:?}: {error}",
                String::from_utf8_lossy(&forwarded.to_bytes())
            )
        })
    }

    #[test]
    fn forward_address_quoting() {
        let v4: IpAddr = Ipv4Addr::new(192, 0, 2, 1).into();
        let v6: IpAddr = "2001:db8::17".parse().unwrap();

        let cases = [
            (ForwardAddress::from(v4), "192.0.2.1"),
            (
                ForwardAddress::from(v4).with_port(8080),
                "\"192.0.2.1:8080\"",
            ),
            (ForwardAddress::from(v6), "\"[2001:db8::17]\""),
            (
                ForwardAddress::from(v6).with_port(8080),
                "\"[2001:db8::17]:8080\"",
            ),
        ];

        for (addr, expected) in cases {
            assert_eq!(addr.to_bytes().as_ref(), expected.as_bytes());
            assert_eq!(addr.to_string(), expected);
        }
    }

    #[test]
    fn forwarded_ipv4_with_port_roundtrip() {
        let forwarded = Forwarded {
            r#for: Some(SocketAddr::new(Ipv4Addr::new(192, 0, 2, 1).into(), 8080).into()),
            by: Some(SocketAddr::new(Ipv4Addr::new(203, 0, 113, 43).into(), 80).into()),
            ..Default::default()
        };

        assert_eq!(
            forwarded.to_bytes().as_ref(),
            b"by=\"203.0.113.43:80\";for=\"192.0.2.1:8080\""
        );
        assert_eq!(roundtrip(&forwarded), forwarded);
    }

    #[test]
    fn forwarded_host_quoting() {
        let cases = [
            ("example.com", "host=example.com"),
            ("example.com:8080", "host=\"example.com:8080\""),
            ("[::1]", "host=\"[::1]\""),
            ("[::1]:8080", "host=\"[::1]:8080\""),
        ];

        for (host, expected) in cases {
            let forwarded = Forwarded {
                host: Some(host.parse().unwrap()),
                ..Default::default()
            };
            assert_eq!(forwarded.to_bytes().as_ref(), expected.as_bytes());
            assert_eq!(roundtrip(&forwarded), forwarded);
        }
    }

    #[test]
    fn x_forwarded_host_is_not_quoted() {
        let forwarded = Forwarded {
            host: Some("example.com:8080".parse().unwrap()),
            ..Default::default()
        };

        let mut request = http::Request::new(());
        forwarded.set_x_forwarded_headers(&mut request);
        assert_eq!(
            request.headers().get(X_FORWARDED_HOST).unwrap(),
            "example.com:8080"
        );
    }

    #[test]
    fn forwarded_quoted_extension_roundtrip() {
        for input in [
            "for=unknown;ext=\"a, b\"",
            "for=unknown;ext=\"a;b=c\"",
            r#"for=unknown;ext="say \"hi\"""#,
            "for=unknown;ext=token",
        ] {
            let forwarded: Forwarded = input.parse().unwrap();
            assert_eq!(forwarded.to_bytes().as_ref(), input.as_bytes());
            assert_eq!(roundtrip(&forwarded), forwarded);
        }
    }

    #[test]
    fn forwarded_record_any_raw() {
        let raw = ForwardedRecord::from(http::HeaderValue::from_static("not a valid record"));
        assert!(raw.raw().is_some());
        assert!(raw.any(), "non-empty raw record should be reported");

        let empty = ForwardedRecord::from(http::HeaderValue::from_static(""));
        assert_eq!(empty.raw(), Some(&b""[..]));
        assert!(!empty.any(), "empty raw record should not be reported");
    }

    #[test]
    fn forwarded_header_any_with_raw() {
        let mut headers = http::HeaderMap::new();
        headers.insert(FORWARDED, "not a valid record".parse().unwrap());
        assert!(ForwardingChain::from_headers(&headers).any());
    }

    #[tokio::test]
    async fn forwarded_header_service_ipv4_remote() {
        let service = SetForwardedHeader::new(
            tower::service_fn(|req: http::Request<()>| async { Ok::<_, ()>(req) }),
            ForwardedHeaderConfig {
                r#for: ForwardeeMode::Address,
                ..Default::default()
            },
            false,
            AppendHeaderRecordMode::Chain,
        );

        let mut request = http::Request::get("http://example.com").body(()).unwrap();
        request
            .headers_mut()
            .insert(http::header::HOST, "example.com:8080".parse().unwrap());
        request.extensions_mut().insert(RemoteAddress(
            SocketAddr::new(Ipv4Addr::new(192, 0, 2, 1).into(), 51234).into(),
        ));

        let response = service.oneshot(request).await.unwrap();
        let forwarded = response.headers().get(FORWARDED).unwrap();
        assert_eq!(
            forwarded,
            "for=\"192.0.2.1:51234\";host=\"example.com:8080\";proto=http"
        );

        let chain = ForwardingChain::from_headers(response.headers());
        assert!(
            chain.flat_iter().all(|record| record.value().is_some()),
            "emitted header should parse cleanly: {chain:?}"
        );
    }

    #[test]
    fn parse_obfuscated_identifier() {
        // `for="_gazonk"` is the example from RFC 7239 section 4.
        for input in ["for=_gazonk", "for=\"_gazonk\"", r#"for="\_gazonk""#] {
            let forwarded: Forwarded = input.parse().unwrap();
            assert_eq!(
                forwarded.r#for,
                Some(Forwardee::obfuscated(ObfuscatedName::from_static("gazonk"))),
                "{input}"
            );
        }

        let forwarded: Forwarded = "for=_hidden.proxy-1_a".parse().unwrap();
        assert_eq!(forwarded.to_bytes().as_ref(), b"for=_hidden.proxy-1_a");
    }

    #[test]
    fn parse_invalid_obfuscated_identifier() {
        // obfnode = "_" 1*( ALPHA / DIGIT / "." / "_" / "-")
        for input in ["for=_", "for=_a!b", "for=_a~b", "for=\"_a b\"", "for=\"_\""] {
            assert!(input.parse::<Forwarded>().is_err(), "{input}");
        }
    }

    #[test]
    fn parse_unknown_case_insensitive() {
        for input in [
            "for=unknown",
            "for=UNKNOWN",
            "for=Unknown",
            "for=\"unknown\"",
        ] {
            let forwarded: Forwarded = input.parse().unwrap();
            assert_eq!(forwarded.r#for, Some(Forwardee::unknown()), "{input}");
        }
    }

    #[test]
    fn parse_forwarded_address_quoted_ipv4() {
        assert_eq!(
            "\"192.0.2.1:8080\"".parse::<ForwardAddress>().unwrap(),
            ForwardAddress::from(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))).with_port(8080)
        );
        assert_eq!(
            "\"192.0.2.1\"".parse::<ForwardAddress>().unwrap(),
            ForwardAddress::from(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)))
        );
    }

    #[test]
    fn parse_forwarded_address_invalid() {
        for input in [
            // Trailing data after the IPv6 bracket.
            "[::1]junk",
            "[::1]]",
            "[::1]:",
            "[[::1]",
            "[::1",
            // IPv6 must be bracketed; IPv4 must not be.
            "::1",
            "2001:db8::17",
            "[192.0.2.1]",
            // port = 1*5DIGIT, and must fit in a u16.
            "192.0.2.1:",
            "192.0.2.1:+80",
            "192.0.2.1:080080",
            "192.0.2.1:65536",
            "192.0.2.1:80:80",
            "[::1]:+80",
            "",
        ] {
            assert!(input.parse::<ForwardAddress>().is_err(), "{input:?}");
        }
    }

    fn obf_name(name: &'static str) -> ObfuscatedName {
        ObfuscatedName::from_static(name)
    }

    #[test]
    fn parse_node_with_any_port() {
        let v4: IpAddr = Ipv4Addr::new(192, 0, 2, 1).into();
        let v6: IpAddr = "2001:db8:cafe::17".parse().unwrap();

        let cases = [
            (
                "unknown:8080",
                Forwardee::new(NodeName::Unknown, Some(NodePort::Port(8080))),
            ),
            (
                "UNKNOWN:_p",
                Forwardee::new(NodeName::Unknown, Some(NodePort::Obfuscated(obf_name("p")))),
            ),
            (
                "_hidden:80",
                Forwardee::obfuscated(obf_name("hidden")).with_port(NodePort::Port(80)),
            ),
            (
                "_hidden:_port",
                Forwardee::obfuscated(obf_name("hidden"))
                    .with_port(NodePort::Obfuscated(obf_name("port"))),
            ),
            (
                "192.0.2.1:_p0rt",
                Forwardee::from(v4).with_port(NodePort::Obfuscated(obf_name("p0rt"))),
            ),
            (
                "[2001:db8:cafe::17]:_p0rt",
                Forwardee::from(v6).with_port(NodePort::Obfuscated(obf_name("p0rt"))),
            ),
            ("[2001:db8:cafe::17]", Forwardee::from(v6)),
        ];

        for (input, expected) in cases {
            assert_eq!(input.parse::<Forwardee>().unwrap(), expected, "{input}");
            assert_eq!(
                format!("\"{input}\"").parse::<Forwardee>().unwrap(),
                expected,
                "quoted {input}"
            );
        }
    }

    #[test]
    fn parse_node_invalid() {
        for input in [
            "",
            "unknown:",
            "unknown:+1",
            "unknown:65536",
            "unknownx",
            "_a:_",
            "_a:_!",
            "_:80",
            "[::1]:_",
            "[::1]_p",
            "::1",
            "_a:80:80",
        ] {
            assert!(input.parse::<Forwardee>().is_err(), "{input:?}");
        }
    }

    #[test]
    fn forwardee_serialization() {
        let cases = [
            (Forwardee::unknown(), "unknown"),
            (
                Forwardee::unknown().with_port(NodePort::Port(8080)),
                "\"unknown:8080\"",
            ),
            (Forwardee::obfuscated(obf_name("hidden")), "_hidden"),
            (
                Forwardee::obfuscated(obf_name("hidden"))
                    .with_port(NodePort::Obfuscated(obf_name("port"))),
                "\"_hidden:_port\"",
            ),
            (
                Forwardee::from(IpAddr::V6(Ipv6Addr::LOCALHOST))
                    .with_port(NodePort::Obfuscated(obf_name("p"))),
                "\"[::1]:_p\"",
            ),
            (
                Forwardee::from(SocketAddr::new(Ipv4Addr::new(192, 0, 2, 1).into(), 80)),
                "\"192.0.2.1:80\"",
            ),
        ];

        for (forwardee, expected) in cases {
            assert_eq!(forwardee.to_bytes().as_ref(), expected.as_bytes());
            assert_eq!(forwardee.to_string(), expected);
            assert_eq!(expected.parse::<Forwardee>().unwrap(), forwardee);

            let forwarded = Forwarded {
                r#for: Some(forwardee),
                ..Default::default()
            };
            assert_eq!(roundtrip(&forwarded), forwarded);
        }
    }

    #[test]
    fn forwardee_accessors() {
        let addr = ForwardAddress::from(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))).with_port(80);
        let forwardee = Forwardee::address(addr);
        assert_eq!(forwardee.ip(), Some(*addr.ip()));
        assert_eq!(forwardee.port(), Some(&NodePort::Port(80)));
        assert_eq!(forwardee.name(), &NodeName::Address(*addr.ip()));
        assert_eq!(forwardee.clone().without_port().port(), None);

        assert_eq!(Forwardee::unknown().ip(), None);
        assert_eq!(Forwardee::obfuscated(obf_name("x")).ip(), None);
    }

    #[test]
    fn forward_address_rejects_non_address_nodes() {
        for input in ["unknown", "_hidden", "192.0.2.1:_p", "\"[::1]:_p\""] {
            assert!(input.parse::<Forwardee>().is_ok(), "{input}");
            assert!(input.parse::<ForwardAddress>().is_err(), "{input}");
        }
    }

    #[test]
    fn parse_forwarded_obfuscated_port() {
        let forwarded: Forwarded = "for=\"[2001:db8:cafe::17]:_p0rt\";by=\"_proxy:_in\""
            .parse()
            .unwrap();

        let r#for = forwarded.r#for.as_ref().unwrap();
        assert_eq!(r#for.ip(), Some("2001:db8:cafe::17".parse().unwrap()));
        assert_eq!(r#for.port(), Some(&NodePort::Obfuscated(obf_name("p0rt"))));
        assert_eq!(
            forwarded.by,
            Some(
                Forwardee::obfuscated(obf_name("proxy"))
                    .with_port(NodePort::Obfuscated(obf_name("in")))
            )
        );
        assert_eq!(roundtrip(&forwarded), forwarded);
    }

    #[test]
    fn x_forwarded_for_obfuscated_port() {
        let forwarded = Forwarded {
            r#for: Some(
                Forwardee::from(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)))
                    .with_port(NodePort::Obfuscated(obf_name("p"))),
            ),
            ..Default::default()
        };

        let mut request = http::Request::new(());
        forwarded.set_x_forwarded_headers(&mut request);
        assert_eq!(request.headers().get(X_FORWARDED_FOR).unwrap(), "192.0.2.1");

        let forwarded = Forwarded {
            r#for: Some(Forwardee::unknown().with_port(NodePort::Port(80))),
            ..Default::default()
        };
        let mut request = http::Request::new(());
        forwarded.set_x_forwarded_headers(&mut request);
        assert!(request.headers().get(X_FORWARDED_FOR).is_none());
    }

    #[test]
    fn forwarded_host_from_uri_authority() {
        // HTTP/2 carries the host in `:authority`, which hyper puts in the URI.
        let request = http::Request::get("https://example.com:8443/path")
            .body(())
            .unwrap();
        let forwarded = Forwarded::new(&request);
        assert_eq!(
            forwarded.host,
            Some(ForwardedHost::new("example.com".into(), Some(8443)))
        );

        let request = http::Request::get("https://user:pw@example.com/")
            .body(())
            .unwrap();
        let forwarded = Forwarded::new(&request);
        assert_eq!(
            forwarded.host,
            Some(ForwardedHost::new("example.com".into(), None)),
            "userinfo is not part of the host"
        );
    }

    #[test]
    fn forwarded_host_header_takes_precedence() {
        let request = http::Request::get("https://authority.example/")
            .header(http::header::HOST, "header.example")
            .body(())
            .unwrap();
        let forwarded = Forwarded::new(&request);
        assert_eq!(
            forwarded.host,
            Some(ForwardedHost::new("header.example".into(), None))
        );
    }

    #[test]
    fn forwarded_proto_from_connection_scheme() {
        // HTTP/1.1 origin-form requests have no scheme in the URI.
        let mut request = http::Request::get("/path").body(()).unwrap();
        assert_eq!(Forwarded::new(&request).proto, None);

        request
            .extensions_mut()
            .insert(ConnectionScheme(http::uri::Scheme::HTTP));
        assert_eq!(
            Forwarded::new(&request).proto,
            Some(http::uri::Scheme::HTTP.into())
        );

        // The connection scheme describes how the request reached us, so it
        // wins over the scheme of an absolute-form target.
        let mut request = http::Request::get("http://example.com/").body(()).unwrap();
        request
            .extensions_mut()
            .insert(ConnectionScheme(http::uri::Scheme::HTTPS));
        assert_eq!(
            Forwarded::new(&request).proto,
            Some(http::uri::Scheme::HTTPS.into())
        );
    }

    #[test]
    fn forwarded_host_rejects_userinfo() {
        for input in [
            "user@example.com",
            "user:pw@example.com:8080",
            "@example.com",
        ] {
            assert!(input.parse::<ForwardedHost>().is_err(), "{input}");
            assert!(
                format!("host=\"{input}\"").parse::<Forwarded>().is_err(),
                "{input}"
            );
        }

        let request = http::Request::get("/")
            .header(http::header::HOST, "user@example.com")
            .body(())
            .unwrap();
        assert_eq!(Forwarded::new(&request).host, None);
    }

    #[test]
    fn forwarded_any_with_extensions() {
        let forwarded: Forwarded = "ext=value".parse().unwrap();
        assert!(forwarded.any());

        let mut request = http::Request::new(());
        forwarded.set_header(&mut request);
        assert_eq!(request.headers().get(FORWARDED).unwrap(), "ext=value");

        assert!(!Forwarded::default().any());
    }

    #[cfg(feature = "hyperdriver")]
    #[tokio::test]
    async fn connection_info_adapter_sets_scheme_for_tls() {
        use chateau::info::TlsConnectionInfo;

        let service =
            ConnectionInfoAdapter::new(tower::service_fn(|req: http::Request<()>| async move {
                Ok::<_, ()>(req.extensions().get::<ConnectionScheme>().cloned())
            }));

        let mut request = http::Request::new(());
        request
            .extensions_mut()
            .insert(TlsConnectionInfo::default());
        assert_eq!(
            service.clone().oneshot(request).await.unwrap(),
            Some(ConnectionScheme(http::uri::Scheme::HTTPS))
        );

        let request = http::Request::new(());
        assert_eq!(service.oneshot(request).await.unwrap(), None);
    }

    fn ours() -> Forwarded {
        Forwarded {
            r#for: Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)).into()),
            host: Some("ours.example".parse().unwrap()),
            proto: Some(http::uri::Scheme::HTTP.into()),
            ..Default::default()
        }
    }

    fn upstream_x_headers() -> http::HeaderMap {
        let mut headers = http::HeaderMap::new();
        headers.append(X_FORWARDED_FOR, "192.0.2.1, 192.0.2.2".parse().unwrap());
        headers.append(X_FORWARDED_FOR, "192.0.2.3".parse().unwrap());
        headers.insert(X_FORWARDED_HOST, "upstream.example".parse().unwrap());
        headers.insert(X_FORWARDED_PROTO, "https".parse().unwrap());
        headers
    }

    fn values(headers: &http::HeaderMap, name: &http::HeaderName) -> Vec<String> {
        headers
            .get_all(name)
            .iter()
            .map(|v| v.to_str().unwrap().to_owned())
            .collect()
    }

    #[test]
    fn x_forwarded_modes_with_upstream_values() {
        use AppendHeaderRecordMode as Mode;

        let upstream = ("upstream.example", "https");
        let replaced = ("ours.example", "http");

        /// Mode, expected `X-Forwarded-For` lines, and expected (host, proto).
        type Case<'a> = (Mode, &'a [&'a str], Option<(&'a str, &'a str)>);

        let cases: [Case<'_>; 7] = [
            (
                Mode::Append,
                &["192.0.2.1, 192.0.2.2", "192.0.2.3", "198.51.100.1"],
                Some(upstream),
            ),
            (
                Mode::Chain,
                &["192.0.2.1, 192.0.2.2", "192.0.2.3, 198.51.100.1"],
                Some(upstream),
            ),
            (
                Mode::Flatten,
                &["192.0.2.1, 192.0.2.2, 192.0.2.3, 198.51.100.1"],
                Some(upstream),
            ),
            (
                Mode::Expand,
                &["192.0.2.1", "192.0.2.2", "192.0.2.3", "198.51.100.1"],
                Some(upstream),
            ),
            (Mode::KeepFirst, &["192.0.2.1"], Some(upstream)),
            (Mode::KeepLast, &["198.51.100.1"], Some(replaced)),
            (Mode::Omit, &[], None),
        ];

        for (mode, expected_for, expected_single) in cases {
            let mut headers = upstream_x_headers();
            ours().append_x_forwarded_headers(&mode, &mut headers);

            assert_eq!(values(&headers, &X_FORWARDED_FOR), expected_for, "{mode:?}");

            let (host, proto) = match expected_single {
                Some((host, proto)) => (vec![host], vec![proto]),
                None => (vec![], vec![]),
            };
            assert_eq!(values(&headers, &X_FORWARDED_HOST), host, "{mode:?}");
            assert_eq!(values(&headers, &X_FORWARDED_PROTO), proto, "{mode:?}");
        }
    }

    #[test]
    fn x_forwarded_modes_without_upstream_values() {
        use AppendHeaderRecordMode as Mode;

        for mode in [
            Mode::Append,
            Mode::Chain,
            Mode::Flatten,
            Mode::Expand,
            Mode::KeepFirst,
            Mode::KeepLast,
        ] {
            let mut headers = http::HeaderMap::new();
            ours().append_x_forwarded_headers(&mode, &mut headers);

            assert_eq!(
                values(&headers, &X_FORWARDED_FOR),
                ["198.51.100.1"],
                "{mode:?}"
            );
            assert_eq!(
                values(&headers, &X_FORWARDED_HOST),
                ["ours.example"],
                "{mode:?}"
            );
            assert_eq!(values(&headers, &X_FORWARDED_PROTO), ["http"], "{mode:?}");
        }

        let mut headers = http::HeaderMap::new();
        ours().append_x_forwarded_headers(&Mode::Omit, &mut headers);
        assert!(headers.is_empty());
    }

    #[test]
    fn x_forwarded_keep_last_without_our_values_removes_upstream() {
        // Upstream values are untrusted under KeepLast, even if we have nothing to replace them with.
        let mut headers = upstream_x_headers();
        Forwarded::default()
            .append_x_forwarded_headers(&AppendHeaderRecordMode::KeepLast, &mut headers);
        assert!(headers.is_empty(), "{headers:?}");
    }

    #[test]
    fn x_forwarded_keep_first_splits_combined_values() {
        let mut headers = http::HeaderMap::new();
        headers.insert(X_FORWARDED_PROTO, " https , http".parse().unwrap());
        headers.insert(X_FORWARDED_HOST, "a.example, b.example".parse().unwrap());

        ours().append_x_forwarded_headers(&AppendHeaderRecordMode::KeepFirst, &mut headers);
        assert_eq!(values(&headers, &X_FORWARDED_PROTO), ["https"]);
        assert_eq!(values(&headers, &X_FORWARDED_HOST), ["a.example"]);
    }

    #[test]
    fn x_forwarded_chain_does_not_duplicate_single_values() {
        let chain: ForwardingChain = [
            "for=192.0.2.1;host=a.example;proto=https"
                .parse::<Forwarded>()
                .unwrap(),
            "for=192.0.2.2;host=b.example;proto=http".parse().unwrap(),
        ]
        .into_iter()
        .collect();

        let mut request = http::Request::new(());
        chain.set_all_x_forwarded_headers(&mut request);
        let headers = request.headers();
        assert_eq!(
            values(headers, &X_FORWARDED_FOR),
            ["192.0.2.1", "192.0.2.2"]
        );
        assert_eq!(values(headers, &X_FORWARDED_HOST), ["a.example"]);
        assert_eq!(values(headers, &X_FORWARDED_PROTO), ["https"]);
    }

    async fn x_forwarded_service_response(
        mode: AppendHeaderRecordMode,
        set_x_headers: bool,
    ) -> http::HeaderMap {
        let service = SetForwardedHeader::new(
            tower::service_fn(|req: http::Request<()>| async { Ok::<_, ()>(req) }),
            ForwardedHeaderConfig {
                r#for: ForwardeeMode::Address,
                ..Default::default()
            },
            set_x_headers,
            mode,
        );

        // A request which reached us over plaintext from a TLS-terminating load balancer.
        let mut request = http::Request::get("/").body(()).unwrap();
        request
            .headers_mut()
            .insert(http::header::HOST, "example.com".parse().unwrap());
        request
            .extensions_mut()
            .insert(ConnectionScheme(http::uri::Scheme::HTTP));
        request.extensions_mut().insert(RemoteAddress(
            SocketAddr::new(Ipv4Addr::new(10, 0, 0, 1).into(), 4000).into(),
        ));
        *request.headers_mut() = {
            let mut headers = upstream_x_headers();
            headers.extend(request.headers().clone());
            headers
        };

        service.oneshot(request).await.unwrap().headers().clone()
    }

    #[tokio::test]
    async fn x_forwarded_service_trusts_upstream_when_chaining() {
        let headers = x_forwarded_service_response(AppendHeaderRecordMode::Append, true).await;
        assert_eq!(
            values(&headers, &X_FORWARDED_FOR),
            ["192.0.2.1, 192.0.2.2", "192.0.2.3", "10.0.0.1"]
        );
        assert_eq!(values(&headers, &X_FORWARDED_HOST), ["upstream.example"]);
        assert_eq!(values(&headers, &X_FORWARDED_PROTO), ["https"]);
    }

    #[tokio::test]
    async fn x_forwarded_service_replaces_upstream_when_keep_last() {
        let headers = x_forwarded_service_response(AppendHeaderRecordMode::KeepLast, true).await;
        assert_eq!(values(&headers, &X_FORWARDED_FOR), ["10.0.0.1"]);
        assert_eq!(values(&headers, &X_FORWARDED_HOST), ["example.com"]);
        assert_eq!(values(&headers, &X_FORWARDED_PROTO), ["http"]);
    }

    #[tokio::test]
    async fn x_forwarded_service_untouched_when_disabled() {
        for mode in [
            AppendHeaderRecordMode::KeepLast,
            AppendHeaderRecordMode::Omit,
        ] {
            let headers = x_forwarded_service_response(mode.clone(), false).await;
            let upstream = upstream_x_headers();
            for name in [&X_FORWARDED_FOR, &X_FORWARDED_HOST, &X_FORWARDED_PROTO] {
                assert_eq!(values(&headers, name), values(&upstream, name), "{mode:?}");
            }
        }
    }

    #[test]
    fn forwarded_builder() {
        let ext = ForwardedKey::new(Token::from_static("ext"));
        let value = crate::headers::fields::parse_field(b"\"a b\"").unwrap();

        let forwarded = Forwarded::default()
            .with_for(SocketAddr::new(Ipv4Addr::new(192, 0, 2, 1).into(), 80))
            .with_by(Forwardee::obfuscated(obf_name("proxy")))
            .with_host("example.com".parse().unwrap())
            .with_proto(http::uri::Scheme::HTTPS)
            .with_extension(ext.clone(), value.clone());

        assert_eq!(
            forwarded,
            Forwarded {
                by: Some(Forwardee::obfuscated(obf_name("proxy"))),
                r#for: Some(SocketAddr::new(Ipv4Addr::new(192, 0, 2, 1).into(), 80).into()),
                host: Some("example.com".parse().unwrap()),
                proto: Some(http::uri::Scheme::HTTPS.into()),
                extensions: [(ext, value)].into_iter().collect(),
            }
        );
        assert_eq!(roundtrip(&forwarded), forwarded);
    }

    #[test]
    #[cfg(debug_assertions)]
    #[should_panic(expected = "standard Forwarded parameter")]
    fn forwarded_builder_rejects_standard_extension_key() {
        let value = crate::headers::fields::parse_field(b"unknown").unwrap();
        let _ = Forwarded::default()
            .with_extension(ForwardedKey::new(Token::from_static("FOR")), value);
    }

    #[test]
    fn set_all_headers_sets_forwarded_and_x_headers() {
        let forwarded = Forwarded::default()
            .with_for(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)))
            .with_proto(http::uri::Scheme::HTTPS);

        let mut request = http::Request::new(());
        forwarded.set_all_headers(&mut request);
        assert_eq!(
            request.headers().get(FORWARDED).unwrap(),
            "for=192.0.2.1;proto=https"
        );
        assert_eq!(request.headers().get(X_FORWARDED_FOR).unwrap(), "192.0.2.1");
        assert_eq!(request.headers().get(X_FORWARDED_PROTO).unwrap(), "https");

        let mut request = http::Request::new(());
        Forwarded::default().set_all_headers(&mut request);
        assert!(request.headers().is_empty());
    }

    #[test]
    fn parse_errors_expose_source() {
        use std::error::Error as _;

        let error = "proto=\"\\ \"".parse::<Forwarded>().unwrap_err();
        assert!(error.to_string().contains("invalid protocol"), "{error}");
        assert!(
            error.source().is_some(),
            "InvalidScheme should expose the underlying InvalidUri"
        );

        let error = "host=\"\\ \"".parse::<Forwarded>().unwrap_err();
        assert!(error.to_string().contains("invalid host"), "{error}");
        assert!(error.source().is_some());

        let error = "[::1]:x".parse::<ForwardAddress>().unwrap_err();
        assert!(error.to_string().contains("port"), "{error}");
    }

    #[test]
    fn obfuscated_name_validation() {
        for valid in ["a", "hidden", "proxy-1", "a.b_c-d", "_leading", "0"] {
            let name = ObfuscatedName::new(valid).unwrap();
            assert_eq!(name.as_str(), valid);
            assert_eq!(name.to_string(), format!("_{valid}"));
            assert_eq!(name.to_string().parse::<ObfuscatedName>().unwrap(), name);
        }

        for invalid in ["", "a b", "a!b", "a~b", "a:b", "caf\u{e9}", "a\"b"] {
            assert!(ObfuscatedName::new(invalid).is_err(), "{invalid:?}");
        }

        // The header form requires the leading `_`.
        assert!("hidden".parse::<ObfuscatedName>().is_err());
        assert!("_".parse::<ObfuscatedName>().is_err());
    }

    #[test]
    fn obfuscated_name_from_token() {
        assert_eq!(
            ObfuscatedName::try_from(Token::from_static("proxy")).unwrap(),
            obf_name("proxy")
        );
        // `!` and `~` are valid token characters, but not valid in an obfuscated name.
        assert!(ObfuscatedName::try_from(Token::from_static("a!b")).is_err());
        assert!(ObfuscatedName::try_from(Token::from_static("a~b")).is_err());
    }

    #[test]
    #[should_panic(expected = "invalid obfuscated name")]
    fn obfuscated_name_from_static_panics() {
        let _ = ObfuscatedName::from_static("not valid!");
    }

    #[test]
    fn obfuscated_name_debug() {
        assert_eq!(
            format!("{:?}", obf_name("proxy")),
            "ObfuscatedName(\"proxy\")"
        );
    }

    #[test]
    fn forwarded_protocol_scheme() {
        let proto: ForwardedProtocol = "https".parse().unwrap();
        assert_eq!(proto.scheme(), &http::uri::Scheme::HTTPS);
        assert_eq!(
            http::uri::Scheme::from(proto.clone()),
            http::uri::Scheme::HTTPS
        );
        assert_eq!(proto.into_scheme(), http::uri::Scheme::HTTPS);
    }

    #[test]
    fn x_forwarded_port_constant() {
        assert_eq!(X_FORWARDED_PORT.as_str(), "x-forwarded-port");
    }

    #[test]
    fn forwarding_chain_try_from_headers() {
        let mut headers = http::HeaderMap::new();
        headers.append(FORWARDED, "for=192.0.2.1, for=192.0.2.2".parse().unwrap());
        headers.append(FORWARDED, "for=192.0.2.3;proto=https".parse().unwrap());

        let chain = ForwardingChain::try_from_headers(&headers).unwrap();
        assert_eq!(chain, ForwardingChain::from_headers(&headers));
        assert!(chain.flat_iter().all(|record| record.value().is_some()));

        headers.append(FORWARDED, "not a valid record".parse().unwrap());
        assert!(ForwardingChain::try_from_headers(&headers).is_err());
        assert!(
            ForwardingChain::from_headers(&headers)
                .last_record()
                .unwrap()
                .raw()
                .is_some(),
            "the lenient constructor preserves the invalid value as a raw record"
        );

        assert!(ForwardingChain::try_from_headers(&http::HeaderMap::new())
            .unwrap()
            .is_empty());
    }

    #[test]
    fn forwarding_chain_first_and_last_record() {
        let mut headers = http::HeaderMap::new();
        headers.append(FORWARDED, "for=192.0.2.1, for=192.0.2.2".parse().unwrap());
        headers.append(FORWARDED, "for=192.0.2.3, for=192.0.2.4".parse().unwrap());
        // An empty header value parses to a header with no records.
        headers.append(FORWARDED, "".parse().unwrap());

        let chain = ForwardingChain::try_from_headers(&headers).unwrap();
        assert_eq!(chain.len(), 3);

        let for_ip = |record: Option<&ForwardedRecord>| {
            record
                .and_then(ForwardedRecord::value)
                .and_then(|forwarded| forwarded.r#for.as_ref())
                .and_then(Forwardee::ip)
        };
        assert_eq!(
            for_ip(chain.first_record()),
            Some(Ipv4Addr::new(192, 0, 2, 1).into())
        );
        assert_eq!(
            for_ip(chain.last_record()),
            Some(Ipv4Addr::new(192, 0, 2, 4).into())
        );
    }

    #[test]
    fn parse_escaped_quoted_values() {
        let forwarded: Forwarded = r#"for="\[::1\]:8080";host="example.com\:8080";proto="\https""#
            .parse()
            .unwrap();

        assert_eq!(
            forwarded.r#for,
            Some(SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 8080).into())
        );
        assert_eq!(
            forwarded.host,
            Some(ForwardedHost::new("example.com".into(), Some(8080)))
        );
        assert_eq!(forwarded.proto, Some(http::uri::Scheme::HTTPS.into()));
    }

    #[test]
    fn parse_empty_pairs() {
        let expected = Forwarded {
            r#for: Some(Forwardee::unknown()),
            proto: Some(http::uri::Scheme::HTTP.into()),
            ..Default::default()
        };

        for input in [
            "for=unknown;;proto=http",
            ";for=unknown;proto=http",
            "for=unknown;proto=http;",
            "for=unknown ; ; proto=http",
        ] {
            assert_eq!(input.parse::<Forwarded>().unwrap(), expected, "{input}");
        }
    }

    #[test]
    fn parse_empty_list_elements() {
        for (input, count) in [
            ("for=_a,,for=_b", 2),
            (", for=_a", 1),
            ("for=_a,", 1),
            ("for=_a , , for=_b ,", 2),
            ("for=_a;, for=_b", 2),
            ("", 0),
            (",", 0),
        ] {
            let records = Forwarded::parse_bytes(input.as_bytes())
                .unwrap_or_else(|error| panic!("{input:?}: {error}"));
            assert_eq!(records.len(), count, "{input:?}");
            assert!(records.iter().all(|r| r.value().is_some()), "{input:?}");
        }
    }

    #[test]
    fn parse_whitespace_around_separators() {
        let records =
            Forwarded::parse_bytes(b" for=_a ; proto=http , for=_b\t;\tby=unknown ").unwrap();
        assert_eq!(records.len(), 2);
    }

    #[test]
    fn parse_rejects_whitespace_around_equals() {
        // forwarded-pair = token "=" value
        for input in ["for =unknown", "for= unknown", "for = unknown"] {
            assert!(input.parse::<Forwarded>().is_err(), "{input}");
            assert!(Forwarded::parse_bytes(input.as_bytes()).is_err(), "{input}");
        }
    }

    #[tokio::test]
    async fn forwarded_header_service_preserves_quoted_values() {
        let service = SetForwardedHeader::new(
            tower::service_fn(|req: http::Request<()>| async { Ok::<_, ()>(req) }),
            Default::default(),
            false,
            AppendHeaderRecordMode::Chain,
        );

        let upstream = "for=\"192.0.2.5:4711\";host=\"example.com:8080\";ext=\"a, b\"";

        let mut request = http::Request::get("http://example.com").body(()).unwrap();
        request
            .headers_mut()
            .insert(http::header::HOST, "example.com".parse().unwrap());
        request
            .headers_mut()
            .insert(FORWARDED, upstream.parse().unwrap());

        let response = service.oneshot(request).await.unwrap();
        let forwarded = response.headers().get(FORWARDED).unwrap();
        assert_eq!(
            forwarded.to_str().unwrap(),
            format!("{upstream}, for=unknown;host=example.com;proto=http")
        );
    }
}
