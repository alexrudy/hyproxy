//! Support for the Via header.
//!
//! This header is used to identify the proxies that have been involved in the request.

use core::fmt;
use std::{net::SocketAddr, str::FromStr};

use http::header::HeaderValue;
use thiserror::Error;

use super::is_rfc7230_token;

/// The `Via` header.
pub const VIA: http::header::HeaderName = http::header::VIA;

/// The `Via` header value, as a chain of proxies.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ViaChain {
    records: Vec<Via>,
}

impl ViaChain {
    /// Create the via header value
    pub fn to_header_value(&self) -> HeaderValue {
        let value = format!("{}", self);
        value.parse().unwrap()
    }

    /// Parse the via header value from headers.
    pub fn from_headers(headers: &http::HeaderMap) -> Result<Self, ViaError> {
        let mut records = Vec::new();

        for header in headers.get_all(VIA) {
            let value = header.to_str().map_err(|_| ViaError::HeaderEncoding)?;
            for record in value.split(',') {
                records.push(record.trim().parse()?);
            }
        }

        Ok(ViaChain { records })
    }

    /// Set the via header value in headers.
    pub fn set_headers(&self, headers: &mut http::HeaderMap) {
        headers.insert(VIA, self.to_header_value());
    }

    /// Get the records in the chain.
    pub fn records(&self) -> &[Via] {
        &self.records
    }

    /// Add a new record to the chain.
    pub fn push(&mut self, via: Via) {
        self.records.push(via);
    }

    /// Compress the chain by removing duplicate protocol records.
    pub fn compress(&mut self) {
        let mut records = Vec::new();
        let mut last: Option<&Via> = None;

        for via in self.records.iter() {
            if let Some(last) = last {
                if last.protocol == via.protocol {
                    continue;
                }
            }

            records.push(via.clone());
            last = Some(via);
        }

        self.records = records;
    }
}

impl fmt::Display for ViaChain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let parts: Vec<String> = self
            .records
            .iter()
            .map(|record| format!("{}", record))
            .collect();

        write!(f, "{}", parts.join(", "))
    }
}

impl FromStr for ViaChain {
    type Err = ViaError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let records: Vec<Via> = s
            .split(',')
            .map(|record| record.trim().parse())
            .collect::<Result<Vec<Via>, ViaError>>()?;

        Ok(ViaChain { records })
    }
}

impl From<Via> for ViaChain {
    fn from(via: Via) -> Self {
        ViaChain { records: vec![via] }
    }
}

/// The `Via` header value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Via {
    protocol: ViaProtocol,
    address: ViaAddress,
}

impl Via {
    /// Create the via header value
    pub fn to_header_value(&self) -> HeaderValue {
        let value = format!("{}", self);
        value.parse().unwrap()
    }
}

impl fmt::Display for Via {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} {}", self.protocol, self.address)
    }
}

/// Error for an invalid Via header.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ViaError {
    /// A part of the header is not a valid RFC 7230 token.
    #[error(transparent)]
    InvalidToken(#[from] InvalidToken),

    /// The header has only one (space separated) part, missing either the protocl or the address.
    #[error("Missing address, only protocol found")]
    MissingAddress,

    /// The header contains characters in an invalid encoding.
    #[error("Header Encoding")]
    HeaderEncoding,
}

impl FromStr for Via {
    type Err = ViaError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (protocol, address) = s.split_once(' ').ok_or(ViaError::MissingAddress)?;

        Ok(Via {
            protocol: protocol.parse()?,
            address: address.parse()?,
        })
    }
}

/// The protocol used by the proxy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ViaProtocol {
    name: Option<String>,
    version: String,
}

impl fmt::Display for ViaProtocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(name) = &self.name {
            write!(f, "{}/{}", name, self.version)
        } else {
            write!(f, "{}", self.version)
        }
    }
}

impl From<http::Version> for ViaProtocol {
    fn from(version: http::Version) -> Self {
        match version {
            http::Version::HTTP_09 => ViaProtocol {
                name: Some("HTTP".to_string()),
                version: "0.9".to_string(),
            },
            http::Version::HTTP_10 => ViaProtocol {
                name: Some("HTTP".to_string()),
                version: "1.0".to_string(),
            },
            http::Version::HTTP_11 => ViaProtocol {
                name: Some("HTTP".to_string()),
                version: "1.1".to_string(),
            },
            http::Version::HTTP_2 => ViaProtocol {
                name: Some("HTTP".to_string()),
                version: "2".to_string(),
            },
            http::Version::HTTP_3 => ViaProtocol {
                name: Some("HTTP".to_string()),
                version: "3".to_string(),
            },
            version if format!("{version:?}").contains('/') => {
                let fmtted = format!("{version:?}");
                let (name, version) = fmtted.split_once('/').unwrap();

                if !is_rfc7230_token(name) {
                    panic!("Invalid protocol");
                }

                if !is_rfc7230_token(version) {
                    panic!("Invalid protocol");
                }

                ViaProtocol {
                    name: Some(name.to_string()),
                    version: version.to_string(),
                }
            }
            version => {
                let fmtted = format!("{version:?}");
                if !is_rfc7230_token(&fmtted) {
                    panic!("Invalid protocol");
                }

                ViaProtocol {
                    name: None,
                    version: fmtted,
                }
            }
        }
    }
}

/// Error for invalid protocol.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("Invalid token: {0}")]
pub struct InvalidToken(String);

impl FromStr for ViaProtocol {
    type Err = InvalidToken;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Some((name, version)) = s.split_once('/') {
            if !is_rfc7230_token(name) {
                return Err(InvalidToken(name.to_string()));
            }

            if !is_rfc7230_token(version) {
                return Err(InvalidToken(version.to_string()));
            }

            Ok(ViaProtocol {
                name: Some(name.to_string()),
                version: version.to_string(),
            })
        } else {
            if !is_rfc7230_token(s) {
                return Err(InvalidToken(s.to_string()));
            }
            Ok(ViaProtocol {
                name: None,
                version: s.to_string(),
            })
        }
    }
}

/// The name or address of the proxy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ViaAddress {
    /// The host and port of the proxy.
    HostAndPort(http::uri::Authority),

    /// A pseudonym for the proxy.
    Pseudonym(Box<str>),
}

impl ViaAddress {
    /// Create a ViaAddress from a name/psuedonym.
    pub fn named(name: impl Into<String>) -> Result<Self, InvalidToken> {
        let value: String = name.into();
        if is_rfc7230_token(&value) {
            Ok(ViaAddress::Pseudonym(value.into()))
        } else {
            Err(InvalidToken(value))
        }
    }

    /// Create a ViaAddress from a URI.
    pub fn from_uri(uri: &http::Uri) -> Option<Self> {
        uri.authority().cloned().map(ViaAddress::HostAndPort)
    }
}

impl fmt::Display for ViaAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ViaAddress::HostAndPort(authority) => write!(f, "{}", authority),
            ViaAddress::Pseudonym(pseudonym) => write!(f, "{}", pseudonym),
        }
    }
}

impl From<SocketAddr> for ViaAddress {
    fn from(addr: SocketAddr) -> Self {
        ViaAddress::HostAndPort(http::uri::Authority::try_from(format!("{}", addr)).unwrap())
    }
}

impl FromStr for ViaAddress {
    type Err = InvalidToken;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.contains(':') {
            if let Ok(addr) = s.parse() {
                return Ok(ViaAddress::HostAndPort(addr));
            }
        }

        if is_rfc7230_token(s) {
            Ok(ViaAddress::Pseudonym(s.into()))
        } else {
            Err(InvalidToken(s.to_string()))
        }
    }
}

/// Middleware modes for the Via header.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum ViaHeaderMode {
    /// Do not set the Via header. Ignore any existing Via header.
    Omit,
    /// Replace the existing Via header.
    Replace,

    /// Chain the value to the existing Via header.
    #[default]
    Chain,

    /// Append the value as a new Via header.
    Append,
}

impl ViaHeaderMode {
    fn is_omit(&self) -> bool {
        matches!(self, ViaHeaderMode::Omit)
    }

    fn apply(&self, headers: &mut http::HeaderMap, via: Via) {
        match self {
            ViaHeaderMode::Replace => {
                headers.insert(VIA, via.to_header_value());
            }
            ViaHeaderMode::Chain => {
                let mut chain = ViaChain::from_headers(headers).unwrap_or_default();
                chain.push(via);
                chain.set_headers(headers);
            }
            ViaHeaderMode::Append => {
                headers.append(VIA, via.to_header_value());
            }
            _ => {}
        }
    }
}

/// Middleware to add a Via header to requests and responses.
#[derive(Debug, Clone)]
pub struct ViaHeaderLayer {
    address: ViaAddress,
    request: ViaHeaderMode,
    response: ViaHeaderMode,
}

impl ViaHeaderLayer {
    /// Create a new Via header layer.
    pub fn new(address: ViaAddress) -> Self {
        Self {
            address,
            request: Default::default(),
            response: Default::default(),
        }
    }

    /// Set whether to add the Via header to requests.
    pub fn request(mut self, request: ViaHeaderMode) -> Self {
        self.request = request;
        self
    }

    /// Set whether to add the Via header to responses.
    pub fn response(mut self, response: ViaHeaderMode) -> Self {
        self.response = response;
        self
    }
}

impl<S> tower::layer::Layer<S> for ViaHeaderLayer {
    type Service = ViaHeaderMiddleware<S>;

    fn layer(&self, inner: S) -> Self::Service {
        ViaHeaderMiddleware {
            inner,
            address: self.address.clone(),
            request: self.request,
            response: self.response,
        }
    }
}

/// Middleware to add a Via header to requests and responses.
#[derive(Debug, Clone)]
pub struct ViaHeaderMiddleware<S> {
    inner: S,
    address: ViaAddress,
    request: ViaHeaderMode,
    response: ViaHeaderMode,
}

impl<S> ViaHeaderMiddleware<S> {
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
    pub fn request(&mut self) -> &mut ViaHeaderMode {
        &mut self.request
    }

    /// A mutable reference to the response VIA header mode.
    pub fn response(&mut self) -> &mut ViaHeaderMode {
        &mut self.response
    }
}

impl<S, BIn, BOut> tower::Service<http::Request<BIn>> for ViaHeaderMiddleware<S>
where
    S: tower::Service<http::Request<BIn>, Response = http::Response<BOut>>,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = self::future::ViaHeaderFuture<S::Future, BOut, S::Error>;

    fn call(&mut self, mut request: http::Request<BIn>) -> Self::Future {
        if !self.request.is_omit() {
            let via = Via {
                protocol: request.version().into(),
                address: self.address.clone(),
            };

            self.request.apply(request.headers_mut(), via);
        }

        self::future::ViaHeaderFuture::new(
            self.inner.call(request),
            self.address.clone(),
            self.response,
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

    use super::{Via, ViaAddress, ViaHeaderMode};

    pin_project! {
        #[derive(Debug)]
        pub struct ViaHeaderFuture<F, BOut, E> {
            #[pin]
            inner: F,
            address: ViaAddress,
            mode: ViaHeaderMode,
            marker: std::marker::PhantomData<fn() -> Result<BOut, E>>,
        }
    }

    impl<F, BOut, E> ViaHeaderFuture<F, BOut, E> {
        pub(super) fn new(inner: F, address: ViaAddress, mode: ViaHeaderMode) -> Self {
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
                if !this.mode.is_omit() {
                    let via = Via {
                        protocol: res.version().into(),
                        address: this.address.clone(),
                    };

                    this.mode.apply(res.headers_mut(), via);
                }
            }

            std::task::Poll::Ready(response)
        }
    }
}

#[cfg(test)]
mod tests {
    use tower::{Layer as _, ServiceExt as _};

    use super::*;

    #[test]
    fn parse_via_protocol() {
        assert_eq!(
            ViaProtocol {
                name: Some("http".into()),
                version: "1.1".into()
            },
            "http/1.1".parse().unwrap()
        );

        assert_eq!(
            ViaProtocol {
                name: None,
                version: "1.1".into()
            },
            "1.1".parse().unwrap()
        );
    }

    #[test]
    fn version_to_protocol() {
        assert_eq!(
            ViaProtocol {
                name: Some("HTTP".into()),
                version: "1.1".into()
            },
            http::Version::HTTP_11.into()
        );

        assert_eq!(
            ViaProtocol {
                name: Some("HTTP".into()),
                version: "2".into()
            },
            http::Version::HTTP_2.into()
        );
    }

    #[test]
    fn invalid_protocol() {
        assert!("http/,1".parse::<ViaProtocol>().is_err());
        assert!("😀".parse::<ViaProtocol>().is_err());
    }

    #[test]
    fn display_protocol() {
        assert_eq!(
            "http/1.1",
            format!("{}", "http/1.1".parse::<ViaProtocol>().unwrap())
        );
        assert_eq!("1.1", format!("{}", "1.1".parse::<ViaProtocol>().unwrap()));
    }

    #[test]
    fn parse_via_address() {
        assert_eq!(
            ViaAddress::HostAndPort("localhost:8080".parse().unwrap()),
            "localhost:8080".parse().unwrap()
        );

        assert_eq!(
            ViaAddress::Pseudonym("proxy".into()),
            "proxy".parse().unwrap()
        );
    }

    #[test]
    fn invalid_address() {
        assert!("😀".parse::<ViaAddress>().is_err());
    }

    #[test]
    fn display_address() {
        assert_eq!(
            "localhost:8080",
            format!("{}", "localhost:8080".parse::<ViaAddress>().unwrap())
        );
        assert_eq!(
            "proxy",
            format!("{}", "proxy".parse::<ViaAddress>().unwrap())
        );
    }

    #[test]
    fn parse_via() {
        assert_eq!(
            Via {
                protocol: "http/1.1".parse().unwrap(),
                address: "localhost:8080".parse().unwrap()
            },
            "http/1.1 localhost:8080".parse().unwrap()
        );

        assert_eq!(
            Via {
                protocol: "http/1.1".parse().unwrap(),
                address: "proxy".parse().unwrap()
            },
            "http/1.1 proxy".parse().unwrap()
        );
    }

    #[test]
    fn invalid_via() {
        assert!("http/1.1, localhost:8080".parse::<Via>().is_err());
        assert!("http/1.1".parse::<Via>().is_err());
        assert!("😀".parse::<Via>().is_err());
    }

    #[test]
    fn display_via() {
        assert_eq!(
            "http/1.1 localhost:8080",
            format!("{}", "http/1.1 localhost:8080".parse::<Via>().unwrap())
        );
        assert_eq!(
            "http/1.1 proxy",
            format!("{}", "http/1.1 proxy".parse::<Via>().unwrap())
        );
    }

    #[test]
    fn parse_via_chain() {
        assert_eq!(
            ViaChain {
                records: vec![
                    "http/1.1 localhost:8080".parse().unwrap(),
                    "http/1.1 proxy".parse().unwrap()
                ]
            },
            "http/1.1 localhost:8080, http/1.1 proxy".parse().unwrap()
        );
    }

    #[tokio::test]
    async fn via_header_middleware_defaults() {
        let middleware = ViaHeaderLayer::new("localhost:8080".parse().unwrap());
        let service = middleware.layer(tower::service_fn(|req: http::Request<()>| async move {
            let via = Via {
                protocol: http::Version::HTTP_11.into(),
                address: "localhost:8080".parse().unwrap(),
            };
            assert_eq!(via.to_header_value(), req.headers().get(VIA).unwrap());
            http::Response::builder()
                .header(VIA, via.to_header_value())
                .body(())
        }));

        let request = http::Request::new(());
        let response = service.oneshot(request).await.unwrap();

        let via = Via {
            protocol: http::Version::HTTP_11.into(),
            address: "localhost:8080".parse().unwrap(),
        };

        let chain: ViaChain = ViaChain::from_headers(response.headers()).unwrap();

        assert_eq!(2, chain.records().len());

        assert!(
            chain.records.iter().all(|v| v == &via),
            "All records are the same VIA"
        )
    }

    #[tokio::test]
    async fn via_header_middleware_append() {
        let middleware =
            ViaHeaderLayer::new("localhost:8080".parse().unwrap()).response(ViaHeaderMode::Append);
        let service = middleware.layer(tower::service_fn(|req: http::Request<()>| async move {
            let via = Via {
                protocol: http::Version::HTTP_11.into(),
                address: "localhost:8080".parse().unwrap(),
            };
            assert_eq!(via.to_header_value(), req.headers().get(VIA).unwrap());
            http::Response::builder()
                .header(VIA, via.to_header_value())
                .body(())
        }));

        let request = http::Request::new(());
        let response = service.oneshot(request).await.unwrap();

        let via = Via {
            protocol: http::Version::HTTP_11.into(),
            address: "localhost:8080".parse().unwrap(),
        };

        let chain: ViaChain = ViaChain::from_headers(response.headers()).unwrap();

        assert_eq!(2, chain.records().len());

        assert!(
            chain.records.iter().all(|v| v == &via),
            "All records are the same VIA"
        );

        assert_eq!(2, response.headers().get_all(VIA).iter().count());
    }

    #[tokio::test]
    async fn via_header_middleware_replace() {
        let middleware =
            ViaHeaderLayer::new("localhost:8080".parse().unwrap()).response(ViaHeaderMode::Replace);
        let service = middleware.layer(tower::service_fn(|req: http::Request<()>| async move {
            let via = Via {
                protocol: http::Version::HTTP_11.into(),
                address: "localhost:8080".parse().unwrap(),
            };
            assert_eq!(via.to_header_value(), req.headers().get(VIA).unwrap());
            http::Response::builder()
                .header(VIA, via.to_header_value())
                .body(())
        }));

        let request = http::Request::new(());
        let response = service.oneshot(request).await.unwrap();

        let via = Via {
            protocol: http::Version::HTTP_11.into(),
            address: "localhost:8080".parse().unwrap(),
        };

        let chain: ViaChain = ViaChain::from_headers(response.headers()).unwrap();

        assert_eq!(1, chain.records().len());

        assert_eq!(via, chain.records()[0]);
    }

    #[tokio::test]
    async fn via_header_middleware_omit() {
        let middleware = ViaHeaderLayer::new("localhost:8080".parse().unwrap())
            .response(ViaHeaderMode::Omit)
            .request(ViaHeaderMode::Omit);
        let service = middleware.layer(tower::service_fn(|req: http::Request<()>| async move {
            let via = Via {
                protocol: http::Version::HTTP_11.into(),
                address: "localhost:8081".parse().unwrap(),
            };
            assert!(req.headers().get(VIA).is_none());
            http::Response::builder()
                .header(VIA, via.to_header_value())
                .body(())
        }));

        let request = http::Request::new(());
        let response = service.oneshot(request).await.unwrap();

        let via = Via {
            protocol: http::Version::HTTP_11.into(),
            address: "localhost:8081".parse().unwrap(),
        };

        let chain: ViaChain = ViaChain::from_headers(response.headers()).unwrap();

        assert_eq!(1, chain.records().len());

        assert_eq!(via, chain.records()[0]);
    }
}
