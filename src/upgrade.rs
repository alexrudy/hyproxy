//! Middleware to facilitate upgrades across reverse proxy boundaries.

use core::fmt;
use std::ops;
use std::str::FromStr;

use bytes::{BufMut, Bytes, BytesMut};
use http::HeaderValue;
use nom::bytes::complete::tag;
use nom::combinator::{map, opt};
use nom::multi::separated_list0;
use nom::sequence::tuple;
use nom::IResult;
use thiserror::Error;

use crate::headers::fields::Token;
use crate::headers::parser::{strip_whitespace, token, NoTail as _};
/// The `Upgrade` header field allows the sender to specify what protocols they would like to upgrade to.
pub const UPGRADE: http::HeaderName = http::header::UPGRADE;

/// Errors that can occur when parsing an upgrade protocol.
#[derive(Debug, Error)]
#[error("upgrade protocol error")]
pub struct UpgradeProtocolError(nom::error::Error<Bytes>);

impl From<nom::error::Error<Bytes>> for UpgradeProtocolError {
    fn from(error: nom::error::Error<Bytes>) -> Self {
        UpgradeProtocolError(error)
    }
}

impl From<nom::error::Error<&[u8]>> for UpgradeProtocolError {
    fn from(error: nom::error::Error<&[u8]>) -> Self {
        UpgradeProtocolError(nom::error::Error::new(
            Bytes::copy_from_slice(error.input),
            error.code,
        ))
    }
}

fn protocol<'v>() -> impl FnMut(&'v [u8]) -> IResult<&'v [u8], UpgradeProtocol> {
    let v = tuple((tag(b"/"), token()));
    let version = opt(map(v, |(_, version)| version));

    map(tuple((token(), version)), |(name, version)| {
        UpgradeProtocol { name, version }
    })
}

fn parse_upgrade_protocols(
    value: &HeaderValue,
) -> Result<Vec<UpgradeProtocol>, UpgradeProtocolError> {
    separated_list0(tag(b","), strip_whitespace(protocol()))(value.as_bytes())
        .no_tail()
        .map_err(Into::into)
}

fn parse_connection_headers(value: &HeaderValue) -> Result<Vec<Token>, UpgradeProtocolError> {
    separated_list0(tag(b","), strip_whitespace(token()))(value.as_bytes())
        .no_tail()
        .map_err(Into::into)
}

// Get upgrade state for the inbound request
fn get_upgrade_request(headers: &http::HeaderMap) -> Result<UpgradeRequest, UpgradeProtocolError> {
    if let Some(connection) = headers.get(http::header::CONNECTION) {
        let connection_headers = parse_connection_headers(connection)?;
        if connection_headers.contains(&Token::from_static("upgrade")) {
            if let Some(upgrade) = headers.get(UPGRADE) {
                tracing::trace!("Found upgrade header: {:?}", upgrade);
                return parse_upgrade_protocols(upgrade)
                    .map(|protocols| UpgradeRequest { protocols });
            }
        }
    }

    Ok(Default::default())
}

fn get_upgrade_response(headers: &http::HeaderMap) -> Option<UpgradeProtocol> {
    match get_upgrade_request(headers) {
        Ok(mut protocols) if protocols.len() == 1 => protocols.pop(),
        _ => None,
    }
}

/// A protocol that can be upgraded.
#[derive(Clone)]
pub struct UpgradeProtocol {
    name: Token,
    version: Option<Token>,
}

impl PartialEq for UpgradeProtocol {
    fn eq(&self, other: &Self) -> bool {
        if let Some((version, other_version)) = self.version().zip(other.version()) {
            self.name.eq_ignore_ascii_case(&other.name)
                && version.eq_ignore_ascii_case(other_version)
        } else {
            self.name.eq_ignore_ascii_case(&other.name)
        }
    }
}

impl fmt::Debug for UpgradeProtocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = String::from_utf8_lossy(self.name.as_bytes());
        write!(f, "UpgradeProtocol(")?;
        match self.version {
            Some(ref version) => write!(
                f,
                "{}/{}",
                name,
                String::from_utf8_lossy(version.as_bytes())
            ),
            None => write!(f, "{}", name),
        }?;
        write!(f, ")")
    }
}

impl UpgradeProtocol {
    /// The name of the protocol.
    pub fn name(&self) -> &Token {
        &self.name
    }

    /// The version of the protocol.
    pub fn version(&self) -> Option<&Token> {
        self.version.as_ref()
    }

    fn extend_buffer(&self, buffer: &mut BytesMut) {
        buffer.extend_from_slice(self.name.as_bytes());
        if let Some(version) = &self.version {
            buffer.put_u8(b'/');
            buffer.extend_from_slice(version.as_bytes());
        }
    }
}

impl FromStr for UpgradeProtocol {
    type Err = UpgradeProtocolError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        protocol()(value.as_bytes()).no_tail().map_err(Into::into)
    }
}

/// A request to upgrade to one or more protocols.
#[derive(Debug, Clone, Default)]
pub struct UpgradeRequest {
    protocols: Vec<UpgradeProtocol>,
}

impl UpgradeRequest {
    /// Check if the request is expecting a particular protocol
    pub fn matching(&self, protocol: &UpgradeProtocol) -> bool {
        self.protocols.contains(protocol)
    }

    /// Add a protocol to the upgrade request
    pub fn push(&mut self, protocol: UpgradeProtocol) {
        self.protocols.push(protocol);
    }

    /// Convert the upgrade request to a header value
    pub fn to_header_value(&self) -> HeaderValue {
        let mut buf = BytesMut::new();

        let mut iter = self.protocols.iter();
        if let Some(protocol) = iter.next() {
            protocol.extend_buffer(&mut buf);
        }

        for protocol in iter {
            buf.put(&b", "[..]);
            protocol.extend_buffer(&mut buf);
        }

        HeaderValue::from_bytes(&buf).unwrap()
    }

    fn pop(&mut self) -> Option<UpgradeProtocol> {
        self.protocols.pop()
    }
}

impl ops::Deref for UpgradeRequest {
    type Target = [UpgradeProtocol];

    fn deref(&self) -> &Self::Target {
        &self.protocols
    }
}

/// Layer to facilitate upgrades across reverse proxy boundaries.
#[derive(Clone, Debug)]
pub struct ProxyUpgradeLayer {
    _priv: (),
}

impl Default for ProxyUpgradeLayer {
    fn default() -> Self {
        Self::new()
    }
}

impl ProxyUpgradeLayer {
    /// Create a new `ProxyUpgradeLayer`.
    pub fn new() -> Self {
        Self { _priv: () }
    }
}

impl<S> tower::layer::Layer<S> for ProxyUpgradeLayer {
    type Service = ProxyUpgrade<S>;

    fn layer(&self, inner: S) -> Self::Service {
        ProxyUpgrade::new(inner)
    }
}

/// Middleware to facilitate upgrades across reverse proxy boundaries.
#[derive(Clone, Debug)]
pub struct ProxyUpgrade<S> {
    inner: S,
}

impl<S> ProxyUpgrade<S> {
    /// Create a new `ProxyUpgrade` middleware.
    pub fn new(inner: S) -> Self {
        Self { inner }
    }
}

impl<S, BIn, BOut> tower::Service<http::Request<BIn>> for ProxyUpgrade<S>
where
    S: tower::Service<http::Request<BIn>, Response = http::Response<BOut>>,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = self::future::UpgradableProxyFuture<S::Future>;

    fn call(&mut self, mut request: http::Request<BIn>) -> Self::Future {
        let upgrade = self::future::Upgrade::new(&mut request);
        let inner = self.inner.call(request);
        self::future::UpgradableProxyFuture::new(inner, upgrade)
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

    use hyperdriver::bridge::io::TokioIo;
    use tokio::io::copy_bidirectional;

    use super::*;

    #[derive(Debug)]
    pub(super) struct Upgrade {
        protocol: Option<UpgradeRequest>,
        on: Option<hyper::upgrade::OnUpgrade>,
    }

    impl Upgrade {
        pub(super) fn new<B>(request: &mut http::Request<B>) -> Self {
            let protocol = get_upgrade_request(request.headers())
                .map(Some)
                .unwrap_or_else(|error| {
                    tracing::error!("Unable to parse upgrade protocols from request: {error}");
                    None
                });

            if let Some(protocol) = &protocol {
                request.extensions_mut().insert(protocol.clone());
            }

            let on = hyper::upgrade::on(request);
            Self {
                protocol,
                on: Some(on),
            }
        }
    }

    pin_project_lite::pin_project! {
        pub struct UpgradableProxyFuture<F> {
            #[pin]
            inner: F,
            request_upgrade: Upgrade,
        }
    }

    impl<F> UpgradableProxyFuture<F> {
        pub(super) fn new(inner: F, upgrade: Upgrade) -> Self {
            Self {
                inner,
                request_upgrade: upgrade,
            }
        }
    }

    impl<F, BOut, E> std::future::Future for UpgradableProxyFuture<F>
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

            if let Ok(response) = &mut response {
                if response.status() == http::StatusCode::SWITCHING_PROTOCOLS {
                    let request_protocol = this.request_upgrade.protocol.as_ref();
                    let response_protocol = get_upgrade_response(response.headers());
                    if request_protocol
                        .zip(response_protocol.as_ref())
                        .is_some_and(|(protocols, response_protocol)| {
                            protocols.matching(response_protocol)
                        })
                    {
                        let response_upgraded = hyper::upgrade::on(response);
                        let request_upgraded = this.request_upgrade.on.take().unwrap();

                        tokio::spawn(async move {
                            let upstream_io = match request_upgraded.await {
                                Ok(upgraded) => {
                                    tracing::debug!("Request upgraded");
                                    upgraded
                                }
                                Err(e) => {
                                    tracing::error!("Request upgrade failed: {:?}", e);
                                    return;
                                }
                            };

                            let downstream_io = match response_upgraded.await {
                                Ok(upgraded) => {
                                    tracing::debug!("Response upgraded");
                                    upgraded
                                }
                                Err(e) => {
                                    tracing::error!("Response upgrade failed: {:?}", e);
                                    return;
                                }
                            };

                            match copy_bidirectional(
                                &mut TokioIo::new(upstream_io),
                                &mut TokioIo::new(downstream_io),
                            )
                            .await
                            {
                                Ok((up, down)) => {
                                    tracing::debug!(
                                        "Upgrade complete: {} bytes upstream, {} bytes downstream",
                                        up,
                                        down
                                    );
                                }
                                Err(error) => {
                                    tracing::debug!("Upgrade IO error: {}", error);
                                }
                            }
                        });
                    } else {
                        let protocol_options = request_protocol
                            .map(|p| {
                                p.iter()
                                    .map(|p| format!("{p:?}"))
                                    .collect::<Vec<_>>()
                                    .join(", ")
                            })
                            .unwrap_or_default();

                        tracing::debug!(
                            requested = %protocol_options,
                            response = %response_protocol.as_ref().map(|p| format!("{p:?}")).unwrap_or_default(),
                            "Proxy Upgrade protocol mismatch, refusing to start upgrade"
                        );
                    }
                }
            }

            std::task::Poll::Ready(response)
        }
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn parse_protocol() {
        let protocol = "websocket".parse::<UpgradeProtocol>().unwrap();
        assert_eq!(protocol.name().as_bytes(), b"websocket");
    }

    #[test]
    fn parse_protocol_with_invalid_characters() {
        let protocol = "websocket/ 2".parse::<UpgradeProtocol>();
        assert!(protocol.is_err());
    }

    #[test]
    fn parse_protocol_requests() {
        let protocols =
            parse_upgrade_protocols(&"websocket, http/2".parse::<http::HeaderValue>().unwrap())
                .unwrap();
        assert_eq!(protocols.len(), 2);

        let request = UpgradeRequest { protocols };

        assert!(request.matching(&"http/2".parse().unwrap()))
    }

    #[test]
    fn parse_headers_without_upgrade_in_connection() {
        let mut headers = http::HeaderMap::new();
        headers.insert(http::header::CONNECTION, "close".parse().unwrap());
        headers.insert(http::header::UPGRADE, "websocket".parse().unwrap());

        let request = get_upgrade_request(&headers).unwrap();
        assert!(request.is_empty());
    }
}
