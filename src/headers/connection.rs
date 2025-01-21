//! Handle connection headers.

use std::{collections::HashSet, sync::Arc};

use bytes::Bytes;
use nom::character::complete::char;
use nom::combinator::map;
use nom::multi::separated_list0;
use nom::IResult;
use thiserror::Error;

use super::chain::HeaderRecordKind;
use super::parser::{strip_whitespace, NoTail};

/// Close is a pseudo-header that can appear in the CONNECTION header's value,
/// indicating that the other side would like to close the connection after this request.
pub const CLOSE: http::HeaderName = http::HeaderName::from_static("close");

/// The HTTP UPGRADE header.
pub const UPGRADE: http::HeaderName = http::header::UPGRADE;

/// The HTTP CONNECTION header.
pub const CONNECTION: http::HeaderName = http::header::CONNECTION;

const CONNECTION_UPGRADE: http::HeaderValue = http::HeaderValue::from_static("upgrade");

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

/// An error occured while parsing connection headers.
#[derive(Debug, Error)]
#[error("Failed to parse connection header: {0:?}")]
pub struct ConnectionHeaderParseError(nom::error::Error<Bytes>);

impl HeaderRecordKind for ConnectionHeader {
    const HEADER_NAME: http::header::HeaderName = http::header::CONNECTION;

    const DELIMITER: u8 = b',';

    type Error = ConnectionHeaderParseError;

    fn into_bytes(self) -> Vec<u8> {
        todo!()
    }

    fn parse_header_value(
        header: &http::HeaderValue,
    ) -> Result<Vec<super::chain::Record<Self>>, Self::Error> {
        parser()(header.as_bytes())
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

fn parser<'v>() -> impl FnMut(&'v [u8]) -> IResult<&'v [u8], Vec<ConnectionHeader>> {
    map(
        separated_list0(char(','), strip_whitespace(super::parser::token())),
        |headers| {
            headers
                .into_iter()
                .map(|header| {
                    http::HeaderName::from_bytes(header.as_bytes())
                        .unwrap()
                        .into()
                })
                .collect()
        },
    )
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

/// Configuration for removing connection headers.
#[derive(Debug, Default, Clone, PartialEq, Eq, Hash)]
pub struct RemoveConnectionHeadersConfig {
    keep_upgrade: bool,
    preserve_if_upgrade: bool,
    preserve_if_close: bool,
}

/// A layer to remove connection headers in requests and responses.
#[derive(Debug, Clone)]
pub struct RemoveConnectionHeadersLayer {
    request: HashSet<http::HeaderName>,
    response: HashSet<http::HeaderName>,
    config: RemoveConnectionHeadersConfig,
}

impl RemoveConnectionHeadersLayer {
    /// Create a new `RemoveConnectionHeadersLayer`.
    pub fn new(config: RemoveConnectionHeadersConfig) -> Self {
        Self {
            request: HashSet::new(),
            response: HashSet::new(),
            config,
        }
    }

    /// Add a header to be removed during requests and responses.
    pub fn add_header(&mut self, header: http::HeaderName) {
        self.request.insert(header.clone());
        self.response.insert(header);
    }

    /// Add the CONNECTION header to be removed during requests and responses.
    pub fn add_connection_header(&mut self) {
        self.request.insert(http::header::CONNECTION);
        self.response.insert(http::header::CONNECTION);
    }

    /// Remove a header from being removed during requests and responses.
    pub fn remove_header(&mut self, header: &http::HeaderName) {
        self.request.remove(header);
        self.response.remove(header);
    }

    /// Configure to keep the UPGRADE header when present.
    pub fn keep_upgrade(&mut self, keep_upgrade: bool) {
        self.config.keep_upgrade = keep_upgrade;
    }

    /// Add a request header to be removed.
    pub fn add_request_header(&mut self, header: http::HeaderName) {
        self.request.insert(header);
    }

    /// Remove a request header from being removed.
    pub fn remove_request_header(&mut self, header: &http::HeaderName) {
        self.request.remove(header);
    }

    /// Add a response header to be removed.
    pub fn add_response_header(&mut self, header: http::HeaderName) {
        self.response.insert(header);
    }

    /// Remove a response header from being removed.
    pub fn remove_response_header(&mut self, header: &http::HeaderName) {
        self.response.remove(header);
    }

    /// Clear the set of request headers to be removed.
    pub fn clear_request_headers(&mut self) {
        self.request.clear();
    }

    /// Clear the set of response headers to be removed.
    pub fn clear_response_headers(&mut self) {
        self.response.clear();
    }
}

impl<S> tower::layer::Layer<S> for RemoveConnectionHeadersLayer {
    type Service = RemoveConnectionHeaders<S>;

    fn layer(&self, inner: S) -> Self::Service {
        RemoveConnectionHeaders {
            inner,
            config: Arc::new(self.config.clone()),
            request: Arc::new(self.request.clone()),
            response: Arc::new(self.response.clone()),
        }
    }
}

/// A service to remove connection headers in requests and responses.
#[derive(Debug, Clone)]
pub struct RemoveConnectionHeaders<S> {
    inner: S,
    config: Arc<RemoveConnectionHeadersConfig>,
    request: Arc<HashSet<http::HeaderName>>,
    response: Arc<HashSet<http::HeaderName>>,
}

impl<S> RemoveConnectionHeaders<S> {
    /// Create a new `RemoveConnectionHeadersLayer`.
    pub fn new(
        inner: S,
        config: RemoveConnectionHeadersConfig,
        headers: HashSet<http::HeaderName>,
    ) -> Self {
        let headers = Arc::new(headers);
        Self {
            inner,
            config: Arc::new(config),
            request: headers.clone(),
            response: headers,
        }
    }

    /// Remove related headers from the request.
    pub fn remove_request_headers(&self, headers: &mut http::HeaderMap) {
        remove_headers(&self.config, &self.request, headers);
    }

    /// Remove related headers from the response.
    pub fn remove_response_headers(&self, headers: &mut http::HeaderMap) {
        remove_headers(&self.config, &self.response, headers);
    }
}

fn remove_headers(
    config: &RemoveConnectionHeadersConfig,
    targets: &HashSet<http::HeaderName>,
    headers: &mut http::HeaderMap,
) {
    for header in targets.iter() {
        process_header(config, header, headers);
    }
}

fn process_header(
    config: &RemoveConnectionHeadersConfig,
    name: &http::HeaderName,
    headers: &mut http::HeaderMap,
) {
    if let Some(original_value) = headers.remove(name) {
        if let Ok(referenced_headers) = ConnectionHeader::parse_header_value(&original_value) {
            if config.preserve_if_upgrade || config.preserve_if_close {
                for header in &referenced_headers {
                    if config.preserve_if_upgrade && header.value().is_some_and(|r| r.is_upgrade())
                    {
                        headers.insert(CONNECTION, original_value);
                        return;
                    }
                    if config.preserve_if_close && header.value().is_some_and(|r| r.is_close()) {
                        headers.insert(CONNECTION, original_value);
                        return;
                    }
                }
            }

            for header in referenced_headers {
                if config.keep_upgrade && header.value().is_some_and(|r| r.is_upgrade()) {
                    headers.insert(CONNECTION, CONNECTION_UPGRADE);
                    continue;
                }

                if header.value().is_some_and(|r| r.is_close()) {
                    continue;
                }

                if let Some(target) = header.into_value() {
                    headers.remove(target.header());
                }
            }
        }
    }
}

impl<S, BIn, BOut> tower::Service<http::Request<BIn>> for RemoveConnectionHeaders<S>
where
    S: tower::Service<http::Request<BIn>, Response = http::Response<BOut>>,
{
    type Response = http::Response<BOut>;
    type Error = S::Error;
    type Future = future::RemoveConnectionHeadersFuture<S::Future, S::Error, BOut>;

    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, request: http::Request<BIn>) -> Self::Future {
        let mut request = request;
        self.remove_request_headers(request.headers_mut());
        future::RemoveConnectionHeadersFuture {
            inner: self.inner.call(request),
            headers: self.request.clone(),
            config: self.config.clone(),
            error: std::marker::PhantomData,
        }
    }
}

mod future {
    use std::{collections::HashSet, future::Future, sync::Arc, task::ready};

    pin_project_lite::pin_project! {
        #[derive(Debug)]
        pub struct RemoveConnectionHeadersFuture<F, E, BOut> {
            #[pin]
            pub(super) inner: F,
            pub(super) headers: Arc<HashSet<http::HeaderName>>,
            pub(super) config: Arc<super::RemoveConnectionHeadersConfig>,
            pub(super) error: std::marker::PhantomData<fn() -> (BOut, E)>
        }
    }

    impl<F, E, BOut> Future for RemoveConnectionHeadersFuture<F, E, BOut>
    where
        F: Future<Output = Result<http::Response<BOut>, E>>,
    {
        type Output = Result<http::Response<BOut>, E>;

        fn poll(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Self::Output> {
            let mut outcome = ready!(self.as_mut().project().inner.poll(cx));

            if let Ok(respoonse) = &mut outcome {
                super::remove_headers(&self.config, &self.headers, respoonse.headers_mut());
            }

            std::task::Poll::Ready(outcome)
        }
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn parse_connection_headers() {
        let headers = b"close, upgrade";
        let headers = parser()(headers).no_tail().unwrap();
        assert_eq!(headers.len(), 2);
        assert_eq!(headers[0].header(), http::HeaderName::from_static("close"));
        assert_eq!(headers[1].header(), http::header::UPGRADE);
    }

    #[test]
    fn remove_connection_headers() {
        let mut headers = http::HeaderMap::new();
        headers.insert(http::header::CONNECTION, "close, upgrade".parse().unwrap());
        headers.insert(http::header::UPGRADE, "websocket".parse().unwrap());

        let config = RemoveConnectionHeadersConfig {
            keep_upgrade: false,
            ..Default::default()
        };
        let mut targets = HashSet::new();
        targets.insert(http::header::CONNECTION);
        remove_headers(&config, &targets, &mut headers);
        assert_eq!(headers.len(), 0);
    }

    #[test]
    fn remove_connection_headers_keep_upgrade() {
        let mut headers = http::HeaderMap::new();
        headers.insert(http::header::CONNECTION, "close, upgrade".parse().unwrap());
        headers.insert(http::header::UPGRADE, "websocket".parse().unwrap());

        let config = RemoveConnectionHeadersConfig {
            keep_upgrade: true,
            ..Default::default()
        };
        let mut targets = HashSet::new();
        targets.insert(http::header::CONNECTION);
        remove_headers(&config, &targets, &mut headers);
        assert_eq!(headers.len(), 2);
        assert_eq!(headers.get(http::header::UPGRADE).unwrap(), "websocket");
    }

    #[test]
    fn preserve_connection_headers() {
        let mut headers = http::HeaderMap::new();
        headers.insert(
            http::header::CONNECTION,
            "keep-alive, upgrade".parse().unwrap(),
        );
        headers.insert(http::header::UPGRADE, "websocket".parse().unwrap());
        headers.insert("keep-alive", "timeout=5, max=200".parse().unwrap());

        let config = RemoveConnectionHeadersConfig {
            preserve_if_upgrade: true,
            ..Default::default()
        };
        let mut targets = HashSet::new();
        targets.insert(http::header::CONNECTION);
        remove_headers(&config, &targets, &mut headers);
        assert_eq!(headers.len(), 3);
        assert_eq!(
            headers.get(http::header::CONNECTION).unwrap(),
            "keep-alive, upgrade"
        );
        assert_eq!(headers.get(http::header::UPGRADE).unwrap(), "websocket");
        assert_eq!(headers.get("keep-alive").unwrap(), "timeout=5, max=200");
    }

    #[test]
    fn preserve_close() {
        let mut headers = http::HeaderMap::new();
        headers.insert(http::header::CONNECTION, "close, upgrade".parse().unwrap());
        headers.insert(http::header::UPGRADE, "websocket".parse().unwrap());

        let config = RemoveConnectionHeadersConfig {
            preserve_if_close: true,
            ..Default::default()
        };
        let mut targets = HashSet::new();
        targets.insert(http::header::CONNECTION);
        remove_headers(&config, &targets, &mut headers);
        assert_eq!(headers.len(), 2);
        assert_eq!(
            headers.get(http::header::CONNECTION).unwrap(),
            "close, upgrade"
        );
        assert_eq!(headers.get(http::header::UPGRADE).unwrap(), "websocket");
    }
}
