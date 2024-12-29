//! Typed version of the HTTP `Forwarded` header.

use std::{
    fmt,
    net::{AddrParseError, IpAddr, Ipv6Addr, SocketAddr},
    str::FromStr,
};

use hyperdriver::info::ConnectionInfo;
use thiserror::Error;

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
#[derive(Debug, Default, Clone, Eq, PartialEq, Hash)]
pub struct ForwardingChain {
    records: Vec<Forwarded>,
}

impl ForwardingChain {
    /// Create a new `ForwardingChain` from a request.
    ///
    /// This should receive the request sent to the proxy server, and will extract the necessary information from it.
    /// It expects that the request has been processed by some middleware that adds the `ConnectionInfo` extension,
    /// which contains the remote and local addresses of the connection.
    pub fn new<B>(reqeust: &http::Request<B>) -> Self {
        let forwarded = reqeust.headers().get_all(FORWARDED).iter();
        let mut records = if let Some(length) = forwarded.size_hint().1 {
            Vec::with_capacity(length)
        } else {
            Vec::new()
        };
        for value in forwarded {
            if let Ok(forwarded) = value.to_str() {
                for record in forwarded.split(',') {
                    if let Ok(forwarded) = Forwarded::from_str(record) {
                        records.push(forwarded);
                    }
                }
            }
        }

        Self { records }
    }

    /// Check if any of the fields are set.
    ///
    /// When no fields are set, the `Forwarded` header should not be included in the request.
    pub fn any(&self) -> bool {
        self.records.iter().any(Forwarded::any)
    }

    /// The records in the `Forwarded` header.
    pub fn records(&self) -> &[Forwarded] {
        &self.records
    }

    /// Remove the `by` field from the `Forwarded` header.
    pub fn without_by(self) -> Self {
        Self {
            records: self
                .records
                .into_iter()
                .map(Forwarded::without_by)
                .collect(),
        }
    }

    /// Set the `X-Forwarded-*` headers on a request.
    pub fn set_all_x_forwarded_headers<B>(&self, request: &mut http::Request<B>) {
        for record in &self.records {
            record.set_x_forwarded_headers(request);
        }
    }

    /// Set the `Forwarded` header on a request.
    pub fn set_single_forwarded_header<B>(&self, request: &mut http::Request<B>) {
        if self.any() {
            request.headers_mut().append(
                FORWARDED,
                self.records
                    .iter()
                    .map(|r| r.to_string())
                    .collect::<Vec<_>>()
                    .join(",")
                    .parse()
                    .unwrap(),
            );
        }
    }

    /// Set a sequence of `Forwarded` headers on a request.
    pub fn set_all_forwarded_headers<B>(&self, request: &mut http::Request<B>) {
        for record in &self.records {
            record.set_header(request);
        }
    }

    /// Add a record to the `Forwarded` header.
    pub fn push(&mut self, record: Forwarded) {
        self.records.push(record);
    }
}

/// The contents of one record in a `Forwarded` header.
///
/// A forwarded header can consist of multiple comma-separated records, each containing a set of key-value pairs.
#[derive(Debug, Default, Clone, Eq, PartialEq, Hash)]
pub struct Forwarded {
    by: Option<Forwardee>,
    r#for: Option<Forwardee>,
    host: Option<String>,
    proto: Option<ForwardProtocol>,
}

impl Forwarded {
    /// Create a new `Forwarded` header from a request.
    ///
    /// This should receive the request sent to the proxy server, and will extract the necessary information from it.
    /// It expects that the request has been processed by some middleware that adds the `ConnectionInfo` extension,
    /// which contains the remote and local addresses of the connection.
    pub fn new<B>(reqeust: &http::Request<B>) -> Self {
        let mut by = None;
        let mut r#for = None;
        let mut host = None;
        let mut proto = None;

        if let Some(info) = reqeust.extensions().get::<ConnectionInfo>() {
            if let Some(remote) = info.remote_addr.clone().canonical().tcp() {
                r#for = Some(Forwardee::Address(remote.into()));
            }

            if let Some(local) = info.local_addr.clone().canonical().tcp() {
                by = Some(Forwardee::Address(local.into()));
            }
        } else {
            tracing::warn!("No connection info found in request extensions");
        }

        if let Some(header) = reqeust.headers().get(http::header::HOST) {
            host = header.to_str().ok().map(|s| s.to_string());
        }

        if let Some(scheme) = reqeust.uri().scheme() {
            proto = scheme.try_into().ok();
        }

        Forwarded {
            by,
            r#for,
            host,
            proto,
        }
    }

    /// Check if any of the fields are set.
    ///
    /// When no fields are set, the `Forwarded` header should not be included in the request.
    pub fn any(&self) -> bool {
        self.by.is_some() || self.r#for.is_some() || self.host.is_some() || self.proto.is_some()
    }

    /// The `by` field of the `Forwarded` header, which identifies the interface that received the request.
    pub fn by(&self) -> Option<&Forwardee> {
        self.by.as_ref()
    }

    /// The `for` field of the `Forwarded` header, which identifies the client that initiated the request.
    pub fn r#for(&self) -> Option<&Forwardee> {
        self.r#for.as_ref()
    }

    /// The `host` field of the `Forwarded` header, which identifies the original host requested by the client.
    pub fn host(&self) -> Option<&str> {
        self.host.as_deref()
    }

    /// The `proto` field of the `Forwarded` header, which identifies the protocol used by the client to connect to the proxy.
    pub fn proto(&self) -> Option<&ForwardProtocol> {
        self.proto.as_ref()
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
                .append(X_FORWARDED_HOST, host.parse().unwrap());
        }

        if let Some(proto) = &self.proto {
            request
                .headers_mut()
                .append(X_FORWARDED_PROTO, proto.to_string().parse().unwrap());
        }
    }

    /// Set the `Forwarded` header on a request.
    pub fn set_header<B>(&self, request: &mut http::Request<B>) {
        if self.any() {
            request
                .headers_mut()
                .append(FORWARDED, format!("{}", self).parse().unwrap());
        }
    }

    /// Set the `Forwarded` header on a request and the `X-Forwarded-*` headers.
    pub fn set_all_headers<B>(&self, request: &mut http::Request<B>) {
        self.set_x_forwarded_headers(request);
        if self.any() {
            request
                .headers_mut()
                .append("forwarded", format!("{}", self).parse().unwrap());
        }
    }
}

impl fmt::Display for Forwarded {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut parts = Vec::new();

        if let Some(by) = &self.by {
            parts.push(format!("by={}", by));
        }

        if let Some(r#for) = &self.r#for {
            parts.push(format!("for={}", r#for));
        }

        if let Some(host) = &self.host {
            parts.push(format!("host={}", host));
        }

        if let Some(proto) = &self.proto {
            parts.push(format!("proto={}", proto));
        }

        write!(f, "{}", parts.join(";"))
    }
}

impl From<Forwarded> for http::HeaderValue {
    fn from(forwarded: Forwarded) -> Self {
        let value = format!("{}", forwarded);
        http::HeaderValue::from_str(&value).unwrap()
    }
}

impl FromStr for Forwarded {
    type Err = ParseForwardedError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut by = None;
        let mut r#for = None;
        let mut host = None;
        let mut proto = None;

        for part in s.split(';') {
            let (key, value) = part.split_once('=').ok_or_else(|| ParseForwardedError {
                kind: ParseForwadingErrorKind::MalformedRecord(part.to_string()),
            })?;

            let key = key.trim();
            let value = value.trim();

            fn insert_or_error<T>(
                field: &mut Option<T>,
                value: T,
                key: &str,
            ) -> Result<(), ParseForwardedError> {
                if field.is_some() {
                    return Err(ParseForwardedError {
                        kind: ParseForwadingErrorKind::DuplicateField(key.to_string()),
                    });
                }

                *field = Some(value);
                Ok(())
            }

            match key {
                "by" => insert_or_error(&mut by, value.into(), key)?,
                "for" => insert_or_error(&mut r#for, value.into(), key)?,
                "host" => insert_or_error(&mut host, value.into(), key)?,
                "proto" => {
                    let value = value.parse().map_err(|error| ParseForwardedError {
                        kind: ParseForwadingErrorKind::InvalidScheme {
                            key: key.to_string(),
                            error,
                        },
                    })?;
                    insert_or_error(&mut proto, value, key)?
                }
                _ => {
                    return Err(ParseForwardedError {
                        kind: ParseForwadingErrorKind::InvalidKey(key.to_string()),
                    })
                }
            }
        }

        Ok(Forwarded {
            by,
            r#for,
            host,
            proto,
        })
    }
}

#[derive(Debug, Error)]
enum ParseForwadingErrorKind {
    #[error("invalid key=value pair in FORWARDED: {0}")]
    MalformedRecord(String),

    #[error("duplicate field in FORWARDED: {0}")]
    DuplicateField(String),

    #[error("invalid key for FORWARDED: {0}")]
    InvalidKey(String),

    #[error("invalid protocol for FORWARDED ({key}): {error}")]
    InvalidScheme {
        key: String,
        error: UnsupportedProtocol,
    },
}

/// An error parsing a `Forwarded` header record.
#[derive(Debug, Error)]
#[error("{}", .kind)]
pub struct ParseForwardedError {
    kind: ParseForwadingErrorKind,
}

/// An interface used in a `Forwarded` header chain.
///
/// This can be a secret, a named interface, an IP address, or an unknown interface.
///
/// The `Secret` variant is used to indicate that the request was forwarded without revealing the original interface. It is the default.
/// Most implemenetations should provide either the `Secret` or `Address` variant.
#[derive(Debug, Clone, Eq, PartialEq, Hash, Default)]
pub enum Forwardee {
    /// The request was forwarded without revealing the original interface.
    #[default]
    Secret,

    /// The request was forwarded on a named interface.
    Named(Box<str>),

    /// The request was forwarded on an IP address.
    Address(ForwardAddress),

    /// The request was forwarded on an unknown interface.
    Unkown,
}

impl Forwardee {
    /// Check if the `Forwardee` is a secret.
    pub fn is_secret(&self) -> bool {
        matches!(self, Forwardee::Secret)
    }

    /// Create the X-Forwarded header value for the `Forwardee`.
    ///
    /// This will return `None` if the `Forwardee` is not an `Address`.
    pub fn x_forwarded(&self) -> Option<XForwardee> {
        match self {
            Forwardee::Address(addr) => Some(XForwardee(addr.x_forwarded())),
            _ => None,
        }
    }
}

impl fmt::Display for Forwardee {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Forwardee::Secret => write!(f, "secret"),
            Forwardee::Named(name) => write!(f, "{}", name),
            Forwardee::Address(addr) => write!(f, "{}", addr),
            Forwardee::Unkown => write!(f, "unkown"),
        }
    }
}

impl From<SocketAddr> for Forwardee {
    fn from(addr: SocketAddr) -> Self {
        Forwardee::Address(addr.into())
    }
}

impl From<&str> for Forwardee {
    fn from(name: &str) -> Self {
        if let Ok(addr) = name.parse::<ForwardAddress>() {
            return Forwardee::Address(addr);
        }

        match name {
            "unknown" => Forwardee::Unkown,
            "secret" => Forwardee::Secret,
            name => Forwardee::Named(name.into()),
        }
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
pub enum ForwardProtocol {
    /// The request was forwarded using the HTTP protocol.
    Http,

    /// The request was forwarded using the HTTPS protocol.
    Https,
}

impl fmt::Display for ForwardProtocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ForwardProtocol::Http => write!(f, "http"),
            ForwardProtocol::Https => write!(f, "https"),
        }
    }
}

/// An error indicating that the protocol in a forwarded header is not supported by [RFC-2739](https://datatracker.ietf.org/doc/html/rfc7239).
#[derive(Debug, Error)]
#[error("Unsupported protocol {0} for forwarded header")]
pub struct UnsupportedProtocol(String);

impl TryFrom<&http::uri::Scheme> for ForwardProtocol {
    type Error = UnsupportedProtocol;

    fn try_from(scheme: &http::uri::Scheme) -> Result<Self, Self::Error> {
        match scheme.as_str() {
            "http" => Ok(ForwardProtocol::Http),
            "https" => Ok(ForwardProtocol::Https),
            _ => Err(UnsupportedProtocol(scheme.to_string())),
        }
    }
}

impl FromStr for ForwardProtocol {
    type Err = UnsupportedProtocol;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "http" => Ok(ForwardProtocol::Http),
            "https" => Ok(ForwardProtocol::Https),
            _ => Err(UnsupportedProtocol(s.to_string())),
        }
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
            IpAddr::V6(ip) => write!(f, "[{}]", ip),
        }?;

        match &self.0.port {
            Some(port) => write!(f, ":{}", port),
            None => Ok(()),
        }
    }
}

/// A setting which control how the `Forwarded` address fields are displayed.
#[derive(Debug, Clone, Eq, PartialEq, Hash, Default)]
pub enum ForwardeeMode {
    /// The interface should be masked as a secret.
    #[default]
    Secret,

    /// The interface should be displayed as an IP address.
    Address,

    /// The interface should be displayed as a named interface.
    Named(Box<str>),

    /// The interface should be displayed as an unknown interface.
    Unkown,

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
            r#for: ForwardeeMode::Secret,
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
            ForwardeeMode::Secret => forwarded.by = Some(Forwardee::Secret),
            ForwardeeMode::Address => {
                if let Some(info) = request.extensions().get::<ConnectionInfo>() {
                    if let Some(local) = info.local_addr.clone().canonical().tcp() {
                        forwarded.by = Some(Forwardee::Address(local.into()));
                    }
                }
            }
            ForwardeeMode::Named(ref name) => forwarded.by = Some(Forwardee::Named(name.clone())),
            ForwardeeMode::Unkown => forwarded.by = Some(Forwardee::Unkown),
            ForwardeeMode::Omit => forwarded.by = None,
        }

        match self.r#for {
            ForwardeeMode::Secret => forwarded.r#for = Some(Forwardee::Secret),
            ForwardeeMode::Address => {
                if let Some(info) = request.extensions().get::<ConnectionInfo>() {
                    if let Some(remote) = info.remote_addr.clone().canonical().tcp() {
                        forwarded.r#for = Some(Forwardee::Address(remote.into()));
                    }
                }
            }
            ForwardeeMode::Named(ref name) => {
                forwarded.r#for = Some(Forwardee::Named(name.clone()))
            }
            ForwardeeMode::Unkown => forwarded.r#for = Some(Forwardee::Unkown),
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
    chained: bool,
}

impl<S> SetForwardedHeader<S> {
    /// Create a new `ForwardedHeader` middleware.
    pub fn new(inner: S, set_x_headers: bool, chained: bool) -> Self {
        Self {
            inner,
            config: ForwardedHeaderConfig::default(),
            set_x_headers,
            chained,
        }
    }

    /// Set the configuration for the `Forwarded` header.
    pub fn config(mut self, config: ForwardedHeaderConfig) -> Self {
        self.config = config;
        self
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
        let forward = self.config.from_request(&req);

        if self.set_x_headers {
            forward.set_x_forwarded_headers(&mut req);
        }

        if self.chained {
            let mut chain = ForwardingChain::new(&req);
            chain.push(forward);
            chain.set_single_forwarded_header(&mut req);
        } else {
            forward.set_header(&mut req);
        }

        self.inner.call(req)
    }
}

/// A middleware for adding a `Forwarded` header to requests.
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct SetForwardedHeaderLayer {
    config: ForwardedHeaderConfig,
    set_x_headers: bool,
    chained: bool,
}

impl Default for SetForwardedHeaderLayer {
    /// Create a new `ForwardedHeaderLayer` middleware.
    fn default() -> Self {
        Self {
            config: ForwardedHeaderConfig::default(),
            set_x_headers: false,
            chained: false,
        }
    }
}

impl SetForwardedHeaderLayer {
    /// Create a new `ForwardedHeaderLayer` middleware.
    pub fn new() -> Self {
        Self {
            config: ForwardedHeaderConfig::default(),
            set_x_headers: false,
            chained: false,
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
    pub fn chain_forwarded_headers(mut self, chain: bool) -> Self {
        self.chained = chain;
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
            chained: self.chained,
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
        assert_eq!(format!("{}", Forwardee::Secret), "secret");
        assert_eq!(
            format!("{}", Forwardee::Address("127.0.0.1".parse().unwrap())),
            "127.0.0.1"
        );
        assert_eq!(
            format!("{}", Forwardee::Address("[::1]:8080".parse().unwrap())),
            "\"[::1]:8080\""
        );
        assert_eq!(format!("{}", Forwardee::Unkown), "unkown");
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
    fn forward_protocol_display() {
        assert_eq!(format!("{}", ForwardProtocol::Http), "http");
        assert_eq!(format!("{}", ForwardProtocol::Https), "https");
    }

    #[test]
    fn forward_protocol_try_from() {
        assert_eq!(
            ForwardProtocol::try_from(&http::uri::Scheme::HTTP).unwrap(),
            ForwardProtocol::Http
        );
        assert_eq!(
            ForwardProtocol::try_from(&http::uri::Scheme::HTTPS).unwrap(),
            ForwardProtocol::Https
        );
        assert!(ForwardProtocol::try_from(&http::uri::Scheme::try_from("ftp").unwrap()).is_err());
    }

    #[test]
    fn forwarded_display() {
        let forwarded = Forwarded {
            r#for: Some(Forwardee::Address(
                "[2001:db8:cafe::17]:4711".parse().unwrap(),
            )),
            ..Default::default()
        };

        assert_eq!(format!("{}", forwarded), "for=\"[2001:db8:cafe::17]:4711\"");

        let forwarded = Forwarded {
            r#for: Some("192.0.2.60".into()),
            proto: Some(ForwardProtocol::Http),
            by: Some("203.0.113.43".into()),
            ..Default::default()
        };

        assert_eq!(
            format!("{}", forwarded),
            "by=203.0.113.43;for=192.0.2.60;proto=http"
        );
    }

    #[test]
    fn parse_forwarded_chain() {
        let forwarded = "for=192.168.0.1, for=\"[2001:db8:cafe::18]:8080\"; proto=https";
        let mut request = http::Request::new(());
        request
            .headers_mut()
            .insert(FORWARDED, forwarded.parse().unwrap());

        let chain = ForwardingChain::new(&request);
        assert_eq!(chain.records().len(), 2);
        assert_eq!(
            chain.records()[0],
            Forwarded {
                r#for: Some(Forwardee::Address("192.168.0.1".parse().unwrap())),
                ..Default::default()
            }
        );

        assert_eq!(
            chain.records()[1],
            Forwarded {
                r#for: Some(Forwardee::Address(
                    "[2001:db8:cafe::18]:8080".parse().unwrap()
                )),
                proto: Some(ForwardProtocol::Https),
                ..Default::default()
            }
        );
    }

    #[test]
    fn parse_forwarded() {
        let forwarded = "for=192.0.2.60; by=203.0.113.43; proto=http"
            .parse()
            .unwrap();
        assert_eq!(
            Forwarded {
                r#for: Some("192.0.2.60".into()),
                proto: Some(ForwardProtocol::Http),
                by: Some("203.0.113.43".into()),
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

        let parsed = Forwarded::from_str(&format!("{}", forwarded)).unwrap();
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
            "[2001:db8:cafe::17]:4711"
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

        assert_eq!(forwarded.by(), None);
        assert_eq!(
            forwarded.r#for(),
            Some(&Forwardee::Address(
                SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8080).into()
            ))
        );
        assert_eq!(forwarded.host(), None);
        assert_eq!(forwarded.proto(), None);

        let config = ForwardedHeaderConfig {
            by: ForwardeeMode::Named("proxy".into()),
            r#for: ForwardeeMode::Named("client".into()),
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

        assert_eq!(forwarded.by(), Some(&Forwardee::Named("proxy".into())));
        assert_eq!(forwarded.r#for(), Some(&Forwardee::Named("client".into())));
        assert_eq!(forwarded.host(), None);
        assert_eq!(forwarded.proto(), None);
    }

    fn connection_info() -> ConnectionInfo {
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
            forwarded.r#for(),
            Some(&Forwardee::Address(
                SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 8080).into()
            ))
        );
    }

    #[tokio::test]
    async fn forwarded_header_service() {
        let service = SetForwardedHeader::new(
            tower::service_fn(|req: http::Request<()>| async { Ok::<_, ()>(req) }),
            false,
            false,
        );

        let mut request = http::Request::get("http://example.com").body(()).unwrap();
        request.extensions_mut().insert(connection_info());
        request
            .headers_mut()
            .insert(http::header::HOST, "example.com".parse().unwrap());

        let response = service.oneshot(request).await.unwrap();
        let forwarded = response.headers().get(FORWARDED).unwrap();
        assert_eq!(forwarded, "for=secret;host=example.com;proto=http");
    }

    #[tokio::test]
    async fn forwarded_header_service_ipv6() {
        let service = SetForwardedHeader::new(
            tower::service_fn(|req: http::Request<()>| async { Ok::<_, ()>(req) }),
            false,
            false,
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

    #[tokio::test]
    async fn xforwarded_header_service() {
        let service = SetForwardedHeader::new(
            tower::service_fn(|req: http::Request<()>| async { Ok::<_, ()>(req) }),
            true,
            false,
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
        assert_eq!(x_forwarded_for, "[::1]:8080");

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
    async fn xforwarded_header_service_secret() {
        let service = SetForwardedHeader::new(
            tower::service_fn(|req: http::Request<()>| async { Ok::<_, ()>(req) }),
            true,
            false,
        )
        .config(ForwardedHeaderConfig {
            r#for: ForwardeeMode::Secret,
            ..Default::default()
        });

        let mut request = http::Request::get("http://example.com").body(()).unwrap();
        request
            .headers_mut()
            .insert(http::header::HOST, "example.com".parse().unwrap());
        request.extensions_mut().insert(connection_info());

        let response = service.oneshot(request).await.unwrap();
        let forwarded = response.headers().get(FORWARDED).unwrap();
        assert_eq!(forwarded, "for=secret;host=example.com;proto=http");

        assert!(
            response.headers().get(X_FORWARDED_FOR).is_none(),
            "Secret forward address should not result in X-Forwarded-For header"
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
}
