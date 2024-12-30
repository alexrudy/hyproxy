//! Middleware to facilitate upgrades across reverse proxy boundaries.

use core::fmt;
use std::ops;
use std::str::FromStr;

use http::HeaderValue;
use thiserror::Error;

use crate::token::{is_rfc7230_token, rfc7230_protocol, InvalidToken};

/// The `Upgrade` header field allows the sender to specify what protocols they would like to upgrade to.
pub const UPGRADE: http::HeaderName = http::header::UPGRADE;

/// Errors that can occur when parsing an upgrade protocol.
#[derive(Debug, Error)]
pub enum UpgradeProtocolError {
    /// The protocol contains invalid characters.
    #[error("protocol contains invalid characters: {}", .0.0)]
    InvalidProtocol(#[from] InvalidToken),

    /// The header contains characters in an unknown encoding.
    #[error("header contains characters in unknown encoding")]
    InvalidHeader(#[from] http::header::ToStrError),
}

fn parse_upgrade_protocols(
    value: &HeaderValue,
) -> Result<Vec<UpgradeProtocol>, UpgradeProtocolError> {
    value
        .to_str()?
        .split(',')
        .map(|s| s.trim().parse())
        .collect()
}

// Get upgrade state for the inbound request
fn get_upgrade_request(headers: &http::HeaderMap) -> Result<UpgradeRequest, UpgradeProtocolError> {
    if headers.get(http::header::CONNECTION) == Some(&http::HeaderValue::from_static("upgrade")) {
        if let Some(upgrade) = headers.get(UPGRADE) {
            tracing::trace!("Found upgrade header: {:?}", upgrade);
            return parse_upgrade_protocols(upgrade).map(|protocols| UpgradeRequest { protocols });
        }
    }
    Ok(UpgradeRequest {
        protocols: Vec::new(),
    })
}

fn get_upgrade_response(headers: &http::HeaderMap) -> Option<UpgradeProtocol> {
    match get_upgrade_request(headers) {
        Ok(mut protocols) if protocols.len() == 1 => protocols.pop(),
        _ => None,
    }
}

/// A protocol that can be upgraded.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct UpgradeProtocol {
    protocol: String,
}

impl fmt::Debug for UpgradeProtocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("UpgradeProtocol")
            .field(&self.protocol)
            .finish()
    }
}

impl fmt::Display for UpgradeProtocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.protocol)
    }
}

impl ops::Deref for UpgradeProtocol {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.protocol
    }
}

impl FromStr for UpgradeProtocol {
    type Err = UpgradeProtocolError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self {
            protocol: rfc7230_protocol(s)?.to_string(),
        })
    }
}

impl TryFrom<String> for UpgradeProtocol {
    type Error = UpgradeProtocolError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        if !is_rfc7230_token(&value) {
            return Err(InvalidToken(value).into());
        }
        Ok(Self { protocol: value })
    }
}

/// A request to upgrade to one or more protocols.
#[derive(Debug, Clone)]
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
        let value = self
            .protocols
            .iter()
            .map(|p| &p as &str)
            .collect::<Vec<&str>>()
            .join(", ");
        HeaderValue::from_str(&value).unwrap()
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

impl fmt::Display for UpgradeRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let value = self
            .protocols
            .iter()
            .map(|p| &p as &str)
            .collect::<Vec<&str>>()
            .join(", ");
        f.write_str(&value)
    }
}

impl FromStr for UpgradeRequest {
    type Err = UpgradeProtocolError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let protocols = s
            .split(',')
            .map(|s| s.trim().parse())
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self { protocols })
    }
}

/// Layer to facilitate upgrades across reverse proxy boundaries.
#[derive(Clone, Debug)]
pub struct ProxyUpgradeLayer {
    _priv: (),
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
                            .map(|p| p.iter().map(|p| &p as &str).collect::<Vec<_>>().join(", "))
                            .unwrap_or_default();

                        tracing::debug!(
                            requested = protocol_options,
                            response = %response_protocol.as_ref().map(|p| p.to_string()).unwrap_or_default(),
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
        assert_eq!(
            protocol,
            UpgradeProtocol {
                protocol: "websocket".to_string()
            }
        );
    }

    #[test]
    fn parse_protocol_with_invalid_characters() {
        let protocol = "websocket/ 2".parse::<UpgradeProtocol>();
        assert!(protocol.is_err());
    }

    #[test]
    fn parse_protocol_requests() {
        let request = "websocket, http/2".parse::<UpgradeRequest>().unwrap();
        assert_eq!(request.len(), 2);

        assert!(request.matching(&"http/2".parse().unwrap()))
    }

    #[test]
    fn parse_protocol_requests_with_invalid_characters() {
        let request = "websocket, 😀, http/2, http/3".parse::<UpgradeRequest>();
        assert!(request.is_err());
    }
}
