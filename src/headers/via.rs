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

/// The `Via` header value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Via {
    protocol: ViaProtocol,
    address: ViaAddress,
}

fn via<'v>() -> impl FnMut(&'v [u8]) -> nom::IResult<&'v [u8], Via> {
    use nom::sequence::pair;

    map(
        pair(protocol(), strip_whitespace(address())),
        |(protocol, address)| Via { protocol, address },
    )
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
        let mut bytes = Vec::new();
        if let Some(name) = &self.protocol.name {
            bytes.extend_from_slice(name.as_bytes());
            bytes.push(b'/');
        }
        bytes.extend_from_slice(Token::as_bytes(&self.protocol.version));
        bytes.push(b' ');
        bytes.extend_from_slice(self.address.into_bytes().as_ref());
        bytes
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
    /// A part of the header is not a valid RFC 7230 token.
    #[error(transparent)]
    InvalidToken(#[from] InvalidValue),

    /// An error occured parsing the header.
    #[error("parsing error: {0:?}")]
    ParserError(nom::error::Error<Bytes>),

    /// The header has only one (space separated) part, missing either the protocl or the address.
    #[error("Missing address, only protocol found")]
    MissingAddress,

    /// The header contains characters in an invalid encoding.
    #[error("Header Encoding")]
    HeaderEncoding,
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
    fn from(version: http::Version) -> Self {
        match version {
            http::Version::HTTP_09 => ViaProtocol {
                name: Some(Token::from_static("HTTP")),
                version: Token::from_static("0.9"),
            },
            http::Version::HTTP_10 => ViaProtocol {
                name: Some(Token::from_static("HTTP")),
                version: Token::from_static("1.0"),
            },
            http::Version::HTTP_11 => ViaProtocol {
                name: Some(Token::from_static("HTTP")),
                version: Token::from_static("1.1"),
            },
            http::Version::HTTP_2 => ViaProtocol {
                name: Some(Token::from_static("HTTP")),
                version: Token::from_static("2"),
            },
            http::Version::HTTP_3 => ViaProtocol {
                name: Some(Token::from_static("HTTP")),
                version: Token::from_static("3"),
            },
            _ => panic!("Unexpected protocol: {version:?}"),
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

/// The name or address of the proxy.
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

    /// Create a ViaAddress from a name/psuedonym.
    pub fn named(name: impl Into<String>) -> Result<Self, InvalidValue> {
        let name = Token::parse(name.into().as_bytes())?;
        Ok(ViaAddress::Pseudonym(name))
    }

    /// Create a ViaAddress from a URI.
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

impl From<SocketAddr> for ViaAddress {
    fn from(addr: SocketAddr) -> Self {
        ViaAddress::HostAndPort(
            Token::parse(addr.ip().to_string().as_bytes()).unwrap(),
            Some(addr.port()),
        )
    }
}

/// Middleware to add a Via header to requests and responses.
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
        let via = Via {
            protocol: request.version().into(),
            address: self.address.clone(),
        };

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
                let via = Via {
                    protocol: res.version().into(),
                    address: this.address.clone(),
                };

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
            Via {
                protocol: http::Version::HTTP_11.into(),
                address: ViaAddress::HostAndPort(Token::from_static("localhost"), Some(8080))
            }
        );

        let addr = parse_one!(b"http/1.1 proxy");

        assert_eq!(
            addr,
            Via {
                protocol: http::Version::HTTP_11.into(),
                address: ViaAddress::named("proxy").unwrap(),
            }
        );
    }

    #[test]
    fn parse_via_records() {
        let records = Via::parse_bytes(b"http/1.1 localhost:8080, http/1.1 proxy").unwrap();

        assert_eq!(2, records.len());

        assert_eq!(
            records[0].value().unwrap(),
            &Via {
                protocol: http::Version::HTTP_11.into(),
                address: ViaAddress::HostAndPort(Token::from_static("localhost"), Some(8080))
            }
        );

        assert_eq!(
            records[1].value().unwrap(),
            &Via {
                protocol: http::Version::HTTP_11.into(),
                address: ViaAddress::named("proxy").unwrap(),
            }
        );

        let records = Via::parse_bytes(b"1.1 vegur").unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(
            records[0].value().unwrap(),
            &Via {
                protocol: http::Version::HTTP_11.into(),
                address: ViaAddress::named("vegur").unwrap(),
            }
        );

        let records = Via::parse_bytes(b"1.0 fred, 1.1 p.example.net").unwrap();
        assert_eq!(records.len(), 2);
        assert_eq!(
            records[0].value().unwrap(),
            &Via {
                protocol: http::Version::HTTP_10.into(),
                address: ViaAddress::named("fred").unwrap(),
            }
        );

        assert_eq!(
            records[1].value().unwrap(),
            &Via {
                protocol: http::Version::HTTP_11.into(),
                address: ViaAddress::named("p.example.net").unwrap(),
            }
        );

        let records = Via::parse_bytes(b"HTTP/1.1 GWA").unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(
            records[0].value().unwrap(),
            &Via {
                protocol: http::Version::HTTP_11.into(),
                address: ViaAddress::named("GWA").unwrap(),
            }
        );
    }

    fn via_fixture() -> Via {
        Via {
            protocol: http::Version::HTTP_11.into(),
            address: ViaAddress::HostAndPort(Token::from_static("localhost"), Some(8080)),
        }
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

        let via = Via {
            protocol: http::Version::HTTP_11.into(),
            address: addr.clone(),
        };

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

        let via = Via {
            protocol: http::Version::HTTP_11.into(),
            address: "localhost:8080".parse().unwrap(),
        };

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

        let via = Via {
            protocol: http::Version::HTTP_11.into(),
            address: "localhost:8080".parse().unwrap(),
        };

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
