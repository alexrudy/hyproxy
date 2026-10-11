//! Middleware to handle the Hop-by-Hop headers.
//!
//! Hop-by-hop headers describe a single connection, and must not be forwarded by a proxy
//! ([RFC 9110 section 7.6.1](https://datatracker.ietf.org/doc/html/rfc9110#section-7.6.1)).
//! [`StripHopByHop`] removes them from requests and responses:
//!
//! - The headers in [`HOPBYHOP`], which are always hop-by-hop.
//! - The connection-scoped headers: `Connection`, every header it names, and the headers in
//!   [`CONNECTION_SCOPED`], which are removed even when `Connection` does not name them, as
//!   older implementations send them without doing so. [`ConnectionHeaders`] controls whether
//!   these are removed, for example to allow an upgrade to be proxied.
//!
//! # Ordering
//!
//! `Connection` can name any header, so a client can send `Connection: x-forwarded-for` to
//! ask for that header to be removed. Apply [`StripHopByHopLayer`] *outside* of middleware
//! which adds headers to the request, such as
//! [`SetForwardedHeaderLayer`](super::SetForwardedHeaderLayer) and
//! [`SetViaHeaderLayer`](super::SetViaHeaderLayer), so that it only strips headers sent by
//! the client:
//!
//! ```
//! use hyproxy::headers::{SetForwardedHeaderLayer, StripHopByHopLayer};
//!
//! let service = tower::ServiceBuilder::new()
//!     // Outermost: runs first on the request.
//!     .layer(StripHopByHopLayer::new())
//!     .layer(SetForwardedHeaderLayer::new())
//!     .service_fn(|req: http::Request<()>| async move {
//!         Ok::<_, std::convert::Infallible>(http::Response::new(()))
//!     });
//! # let _ = service;
//! ```
//!
//! Responses pass through the layers in the opposite order, so the outermost layer sees the
//! response *last*: after inner middleware such as `SetViaHeaderLayer` has added headers to
//! it. An upstream which sends, say, `Connection: via` could then remove those headers.
//! Legitimate upstreams have no reason to do this, as `Via` is an end-to-end header, but if
//! the upstream is not trusted (as for a forward proxy), split stripping into two layers with
//! [`StripDirection`], one next to the client and one next to the upstream:
//!
//! ```
//! use hyproxy::headers::hopby::StripDirection;
//! use hyproxy::headers::via::ViaAddress;
//! use hyproxy::headers::{SetForwardedHeaderLayer, SetViaHeaderLayer, StripHopByHopLayer};
//!
//! let service = tower::ServiceBuilder::new()
//!     // Strips the client's request, before headers are added to it.
//!     .layer(StripHopByHopLayer::new().direction(StripDirection::Request))
//!     .layer(SetViaHeaderLayer::new(ViaAddress::named("proxy").unwrap()))
//!     .layer(SetForwardedHeaderLayer::new())
//!     // Strips the upstream's response, before headers are added to it.
//!     .layer(StripHopByHopLayer::new().direction(StripDirection::Response))
//!     .service_fn(|req: http::Request<()>| async move {
//!         Ok::<_, std::convert::Infallible>(http::Response::new(()))
//!     });
//! # let _ = service;
//! ```
//!
//! When splitting, give both layers the same [`ConnectionHeaders`] policy. The inner layer
//! decides whether a response is an upgrade from the request it receives, after the outer
//! layer has already applied its policy to that request.

use http::header::{HeaderMap, HeaderName};
pub use http::header::{
    CONNECTION, PROXY_AUTHENTICATE, PROXY_AUTHORIZATION, TE, TRANSFER_ENCODING, UPGRADE,
};

use super::chain::{HeaderChain, RecordEntry};
use super::connection::{ConnectionHeader, CONNECTION_UPGRADE};

/// Headers which are always hop-by-hop, and are removed by [`StripHopByHop`]
/// regardless of [`ConnectionHeaders`].
pub const HOPBYHOP: [HeaderName; 4] = [
    PROXY_AUTHENTICATE,
    PROXY_AUTHORIZATION,
    TE,
    TRANSFER_ENCODING,
];

/// The `Keep-Alive` header, an HTTP/1.0 connection option.
pub const KEEP_ALIVE: HeaderName = HeaderName::from_static("keep-alive");

/// The `Proxy-Connection` header, a non-standard predecessor of `Connection`.
pub const PROXY_CONNECTION: HeaderName = HeaderName::from_static("proxy-connection");

/// Headers which are connection-scoped even when `Connection` does not name them
/// (RFC 9110 section 7.6.1). These are handled according to [`ConnectionHeaders`].
pub const CONNECTION_SCOPED: [HeaderName; 4] = [CONNECTION, KEEP_ALIVE, PROXY_CONNECTION, UPGRADE];

/// How [`StripHopByHop`] treats connection-scoped headers: `Connection`, the headers it
/// names, and the headers in [`CONNECTION_SCOPED`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub enum ConnectionHeaders {
    /// Remove all connection-scoped headers.
    #[default]
    Strip,

    /// As [`ConnectionHeaders::Strip`], except for upgrade messages, where `Upgrade` and
    /// `Connection: upgrade` are kept so that the upgrade can be proxied. All other
    /// connection-scoped headers are still removed.
    ///
    /// A request is an upgrade if `Connection` includes `upgrade` and an `Upgrade` header is
    /// present. A response is an upgrade if, in addition, its status is
    /// `101 Switching Protocols` and the request was an upgrade.
    PreserveUpgrade,

    /// Leave all connection-scoped headers in place.
    Preserve,
}

/// Which messages [`StripHopByHop`] removes hop-by-hop headers from.
///
/// See [Ordering](self#ordering) for when to strip only one direction.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub enum StripDirection {
    /// Strip both requests and responses.
    #[default]
    Both,

    /// Strip requests only, leaving responses untouched.
    Request,

    /// Strip responses only, leaving requests untouched.
    Response,
}

impl StripDirection {
    fn requests(self) -> bool {
        matches!(self, StripDirection::Both | StripDirection::Request)
    }

    fn responses(self) -> bool {
        matches!(self, StripDirection::Both | StripDirection::Response)
    }
}

fn strip_hopbyhop_headers(headers: &mut HeaderMap) {
    for header in HOPBYHOP.iter() {
        headers.remove(header);
    }
}

/// All headers named in every `Connection` header line.
fn connection_options(headers: &HeaderMap) -> Vec<HeaderName> {
    let mut names = Vec::new();
    for record in HeaderChain::<ConnectionHeader>::from_headers(headers).flat_iter() {
        match record.entry() {
            RecordEntry::Value(option) => names.push(option.header().clone()),
            // Be lenient with lines that don't parse: still strip anything they name.
            RecordEntry::Raw(raw) => names.extend(
                raw.split(|&c| c == b',')
                    .filter_map(|name| HeaderName::from_bytes(name.trim_ascii()).ok()),
            ),
        }
    }
    names
}

/// Whether the message requests an upgrade: `Connection: upgrade` and an `Upgrade` header.
fn is_upgrade(headers: &HeaderMap) -> bool {
    headers.contains_key(UPGRADE) && connection_options(headers).contains(&UPGRADE)
}

/// Remove connection-scoped headers according to `mode`. `allow_upgrade` is whether this
/// message may be treated as an upgrade (for responses, whether it is a `101` to an
/// upgrade request).
fn strip_connection_headers(mode: ConnectionHeaders, allow_upgrade: bool, headers: &mut HeaderMap) {
    if mode == ConnectionHeaders::Preserve {
        return;
    }

    let names = connection_options(headers);
    let keep_upgrade = mode == ConnectionHeaders::PreserveUpgrade
        && allow_upgrade
        && headers.contains_key(UPGRADE)
        && names.contains(&UPGRADE);

    for name in names.iter().chain(CONNECTION_SCOPED.iter()) {
        if keep_upgrade && name == UPGRADE {
            continue;
        }
        headers.remove(name);
    }

    if keep_upgrade {
        headers.insert(CONNECTION, CONNECTION_UPGRADE);
    }
}

/// Layer to strip hop-by-hop headers. See [`StripHopByHop`].
#[derive(Debug, Clone, Default)]
pub struct StripHopByHopLayer {
    connection: ConnectionHeaders,
    direction: StripDirection,
}

impl StripHopByHopLayer {
    /// Create a new `StripHopByHopLayer`, which strips all hop-by-hop headers from both
    /// requests and responses.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set how connection-scoped headers are treated.
    pub fn connection_headers(mut self, connection: ConnectionHeaders) -> Self {
        self.connection = connection;
        self
    }

    /// Set which messages to strip. Defaults to [`StripDirection::Both`].
    pub fn direction(mut self, direction: StripDirection) -> Self {
        self.direction = direction;
        self
    }
}

impl<S> tower::layer::Layer<S> for StripHopByHopLayer {
    type Service = StripHopByHop<S>;

    fn layer(&self, inner: S) -> Self::Service {
        StripHopByHop::new(inner)
            .connection_headers(self.connection)
            .direction(self.direction)
    }
}

/// Middleware to strip hop-by-hop headers from requests and responses.
///
/// See the [module documentation](self) for which headers are removed, and where to
/// apply this middleware.
#[derive(Debug, Clone)]
pub struct StripHopByHop<S> {
    inner: S,
    connection: ConnectionHeaders,
    direction: StripDirection,
}

impl<S> StripHopByHop<S> {
    /// Create a new `StripHopByHop` middleware, which strips all hop-by-hop headers from
    /// both requests and responses.
    pub fn new(inner: S) -> Self {
        Self {
            inner,
            connection: ConnectionHeaders::default(),
            direction: StripDirection::default(),
        }
    }

    /// Set how connection-scoped headers are treated.
    pub fn connection_headers(mut self, connection: ConnectionHeaders) -> Self {
        self.connection = connection;
        self
    }

    /// Set which messages to strip. Defaults to [`StripDirection::Both`].
    pub fn direction(mut self, direction: StripDirection) -> Self {
        self.direction = direction;
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
}

impl<S, BIn, BOut> tower::Service<http::Request<BIn>> for StripHopByHop<S>
where
    S: tower::Service<http::Request<BIn>, Response = http::Response<BOut>>,
{
    type Response = http::Response<BOut>;
    type Error = S::Error;
    type Future = self::future::StripHopByHopFuture<S::Future>;

    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: http::Request<BIn>) -> Self::Future {
        // Recorded before stripping, as it decides how the response is treated.
        let upgrade = is_upgrade(req.headers());

        if self.direction.requests() {
            strip_connection_headers(self.connection, true, req.headers_mut());
            strip_hopbyhop_headers(req.headers_mut());
        }

        // `None` leaves the response untouched.
        let response = self.direction.responses().then_some(self.connection);
        self::future::StripHopByHopFuture::new(self.inner.call(req), response, upgrade)
    }
}

mod future {
    use std::task::ready;

    use pin_project_lite::pin_project;

    use super::{strip_connection_headers, strip_hopbyhop_headers, ConnectionHeaders};

    pin_project! {
        /// Future returned by [`StripHopByHop`](super::StripHopByHop).
        #[derive(Debug)]
        pub struct StripHopByHopFuture<F> {
            #[pin]
            inner: F,
            connection: Option<ConnectionHeaders>,
            upgrade: bool,
        }
    }

    impl<F> StripHopByHopFuture<F> {
        pub(super) fn new(inner: F, connection: Option<ConnectionHeaders>, upgrade: bool) -> Self {
            Self {
                inner,
                connection,
                upgrade,
            }
        }
    }

    impl<F, BOut, E> std::future::Future for StripHopByHopFuture<F>
    where
        F: std::future::Future<Output = Result<http::Response<BOut>, E>>,
    {
        type Output = Result<http::Response<BOut>, E>;

        fn poll(
            self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Self::Output> {
            let this = self.project();
            let mut res = ready!(this.inner.poll(cx));

            if let (Ok(response), Some(connection)) = (&mut res, *this.connection) {
                let upgrade =
                    *this.upgrade && response.status() == http::StatusCode::SWITCHING_PROTOCOLS;
                strip_connection_headers(connection, upgrade, response.headers_mut());
                strip_hopbyhop_headers(response.headers_mut());
            }

            std::task::Poll::Ready(res)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::convert::Infallible;

    use http::header::{
        HeaderValue, CONTENT_TYPE, PROXY_AUTHENTICATE, TE, TRAILER, TRANSFER_ENCODING, VIA,
    };
    use tower::{Layer as _, ServiceExt as _};

    use super::*;
    use crate::headers::forward::{RemoteAddress, FORWARDED, X_FORWARDED_FOR};
    use crate::headers::via::ViaAddress;
    use crate::headers::{
        ForwardedHeaderConfig, ForwardeeMode, SetForwardedHeaderLayer, SetViaHeaderLayer,
    };

    fn names(headers: &HeaderMap) -> Vec<&str> {
        let mut names: Vec<_> = headers.keys().map(HeaderName::as_str).collect();
        names.sort_unstable();
        names
    }

    fn upgrade_request_headers() -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(CONNECTION, "keep-alive, Upgrade, x-hop".parse().unwrap());
        headers.insert(UPGRADE, "websocket".parse().unwrap());
        headers.insert(KEEP_ALIVE, "timeout=5".parse().unwrap());
        headers.insert("x-hop", "1".parse().unwrap());
        headers.insert(CONTENT_TYPE, "text/plain".parse().unwrap());
        headers
    }

    #[test]
    fn strip_linked_connection_headers() {
        let mut headers = HeaderMap::new();
        headers.insert(CONNECTION, "close, keep-alive, upgrade".parse().unwrap());
        headers.insert(UPGRADE, "websocket".parse().unwrap());

        strip_connection_headers(ConnectionHeaders::Strip, true, &mut headers);
        assert!(headers.is_empty(), "{headers:?}");
    }

    #[test]
    fn strip_all_connection_lines() {
        let mut headers = HeaderMap::new();
        headers.append(CONNECTION, "x-first".parse().unwrap());
        headers.append(CONNECTION, "x-second, , x-third".parse().unwrap());
        for name in ["x-first", "x-second", "x-third", "x-kept"] {
            headers.insert(name, "1".parse().unwrap());
        }

        strip_connection_headers(ConnectionHeaders::Strip, true, &mut headers);
        assert_eq!(names(&headers), ["x-kept"]);
    }

    #[test]
    fn strip_unparseable_connection_line() {
        let mut headers = HeaderMap::new();
        headers.insert(CONNECTION, "x-named, not a token".parse().unwrap());
        headers.insert("x-named", "1".parse().unwrap());

        strip_connection_headers(ConnectionHeaders::Strip, true, &mut headers);
        assert!(headers.is_empty(), "{headers:?}");
    }

    #[test]
    fn strip_implicit_connection_scoped_headers() {
        // Removed even though `Connection` does not name them.
        let mut headers = HeaderMap::new();
        headers.insert(KEEP_ALIVE, "timeout=5".parse().unwrap());
        headers.insert(PROXY_CONNECTION, "keep-alive".parse().unwrap());
        headers.insert(UPGRADE, "websocket".parse().unwrap());
        headers.insert(CONTENT_TYPE, "text/plain".parse().unwrap());

        strip_connection_headers(ConnectionHeaders::Strip, true, &mut headers);
        assert_eq!(names(&headers), ["content-type"]);
    }

    #[test]
    fn strip_hopbyhop_headers() {
        let mut headers = HeaderMap::new();
        headers.insert(PROXY_AUTHENTICATE, "Basic".parse().unwrap());
        headers.insert(TE, "trailers".parse().unwrap());
        headers.insert(TRANSFER_ENCODING, "chunked".parse().unwrap());
        headers.insert(TRAILER, "Expires".parse().unwrap());

        super::strip_hopbyhop_headers(&mut headers);
        // `Trailer` is end-to-end: it announces the fields in the trailer section.
        assert_eq!(names(&headers), ["trailer"]);
    }

    #[test]
    fn preserve_upgrade_keeps_only_upgrade() {
        let mut headers = upgrade_request_headers();
        strip_connection_headers(ConnectionHeaders::PreserveUpgrade, true, &mut headers);

        assert_eq!(names(&headers), ["connection", "content-type", "upgrade"]);
        assert_eq!(headers[CONNECTION], "upgrade");
        assert_eq!(headers[UPGRADE], "websocket");
    }

    #[test]
    fn preserve_upgrade_requires_upgrade_header() {
        let mut headers = upgrade_request_headers();
        headers.remove(UPGRADE);
        strip_connection_headers(ConnectionHeaders::PreserveUpgrade, true, &mut headers);
        assert_eq!(names(&headers), ["content-type"]);
    }

    #[test]
    fn preserve_upgrade_requires_connection_upgrade() {
        let mut headers = upgrade_request_headers();
        headers.insert(CONNECTION, "keep-alive".parse().unwrap());
        strip_connection_headers(ConnectionHeaders::PreserveUpgrade, true, &mut headers);
        assert_eq!(names(&headers), ["content-type", "x-hop"]);
    }

    #[test]
    fn preserve_upgrade_not_allowed() {
        let mut headers = upgrade_request_headers();
        strip_connection_headers(ConnectionHeaders::PreserveUpgrade, false, &mut headers);
        assert_eq!(names(&headers), ["content-type"]);
    }

    #[test]
    fn preserve_leaves_connection_headers() {
        let mut headers = upgrade_request_headers();
        let original = headers.clone();
        strip_connection_headers(ConnectionHeaders::Preserve, true, &mut headers);
        assert_eq!(headers, original);
    }

    /// Run a request through `StripHopByHop`, with an inner service which records the
    /// request headers it received, and responds with `status` and `response_headers`.
    async fn roundtrip(
        layer: StripHopByHopLayer,
        request_headers: HeaderMap,
        status: http::StatusCode,
        response_headers: HeaderMap,
    ) -> (HeaderMap, HeaderMap) {
        let service = layer.layer(tower::service_fn(move |req: http::Request<()>| {
            let response_headers = response_headers.clone();
            async move {
                let mut response = http::Response::new(req.headers().clone());
                *response.status_mut() = status;
                *response.headers_mut() = response_headers;
                Ok::<_, Infallible>(response)
            }
        }));

        let mut request = http::Request::new(());
        *request.headers_mut() = request_headers;
        let response = service.oneshot(request).await.unwrap();
        let (parts, forwarded_request_headers) = response.into_parts();
        (forwarded_request_headers, parts.headers)
    }

    fn upgrade_response_headers() -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(CONNECTION, "upgrade, keep-alive".parse().unwrap());
        headers.insert(UPGRADE, "websocket".parse().unwrap());
        headers.insert(KEEP_ALIVE, "timeout=5".parse().unwrap());
        headers
    }

    #[tokio::test]
    async fn service_preserve_upgrade_on_switching_protocols() {
        let (request, response) = roundtrip(
            StripHopByHopLayer::new().connection_headers(ConnectionHeaders::PreserveUpgrade),
            upgrade_request_headers(),
            http::StatusCode::SWITCHING_PROTOCOLS,
            upgrade_response_headers(),
        )
        .await;

        assert_eq!(names(&request), ["connection", "content-type", "upgrade"]);
        assert_eq!(names(&response), ["connection", "upgrade"]);
        assert_eq!(response[CONNECTION], "upgrade");
    }

    #[tokio::test]
    async fn service_preserve_upgrade_strips_non_101_response() {
        let (_, response) = roundtrip(
            StripHopByHopLayer::new().connection_headers(ConnectionHeaders::PreserveUpgrade),
            upgrade_request_headers(),
            http::StatusCode::OK,
            upgrade_response_headers(),
        )
        .await;
        assert!(response.is_empty(), "{response:?}");
    }

    #[tokio::test]
    async fn service_preserve_upgrade_strips_101_without_upgrade_request() {
        let mut request_headers = upgrade_request_headers();
        request_headers.remove(UPGRADE);

        let (_, response) = roundtrip(
            StripHopByHopLayer::new().connection_headers(ConnectionHeaders::PreserveUpgrade),
            request_headers,
            http::StatusCode::SWITCHING_PROTOCOLS,
            upgrade_response_headers(),
        )
        .await;
        assert!(response.is_empty(), "{response:?}");
    }

    #[tokio::test]
    async fn service_strip_and_preserve() {
        let mut request_headers = upgrade_request_headers();
        request_headers.insert(TE, "trailers".parse().unwrap());

        let (request, response) = roundtrip(
            StripHopByHopLayer::new().connection_headers(ConnectionHeaders::Strip),
            request_headers.clone(),
            http::StatusCode::SWITCHING_PROTOCOLS,
            upgrade_response_headers(),
        )
        .await;
        assert_eq!(names(&request), ["content-type"]);
        assert!(response.is_empty(), "{response:?}");

        // `Preserve` keeps connection-scoped headers, but still strips `HOPBYHOP`.
        let (request, response) = roundtrip(
            StripHopByHopLayer::new().connection_headers(ConnectionHeaders::Preserve),
            request_headers,
            http::StatusCode::SWITCHING_PROTOCOLS,
            upgrade_response_headers(),
        )
        .await;
        assert_eq!(
            names(&request),
            [
                "connection",
                "content-type",
                "keep-alive",
                "upgrade",
                "x-hop"
            ]
        );
        assert_eq!(response, upgrade_response_headers());
    }

    #[tokio::test]
    async fn direction_request_only() {
        let (request, response) = roundtrip(
            StripHopByHopLayer::new().direction(StripDirection::Request),
            upgrade_request_headers(),
            http::StatusCode::OK,
            upgrade_response_headers(),
        )
        .await;
        assert_eq!(names(&request), ["content-type"]);
        assert_eq!(response, upgrade_response_headers());
    }

    #[tokio::test]
    async fn direction_response_only() {
        let (request, response) = roundtrip(
            StripHopByHopLayer::new().direction(StripDirection::Response),
            upgrade_request_headers(),
            http::StatusCode::OK,
            upgrade_response_headers(),
        )
        .await;
        assert_eq!(request, upgrade_request_headers());
        assert!(response.is_empty(), "{response:?}");
    }

    #[tokio::test]
    async fn direction_response_only_detects_upgrade_request() {
        // The request is not stripped, but is still used to decide whether a `101` is an upgrade.
        let (request, response) = roundtrip(
            StripHopByHopLayer::new()
                .connection_headers(ConnectionHeaders::PreserveUpgrade)
                .direction(StripDirection::Response),
            upgrade_request_headers(),
            http::StatusCode::SWITCHING_PROTOCOLS,
            upgrade_response_headers(),
        )
        .await;
        assert_eq!(request, upgrade_request_headers());
        assert_eq!(names(&response), ["connection", "upgrade"]);
    }

    /// A proxy stack with `Via` and the given hop-by-hop layers, in front of an upstream which
    /// tries to remove the response `Via`. Returns the (upstream request, client response) headers.
    async fn via_stack(
        outer: StripHopByHopLayer,
        inner: Option<StripHopByHopLayer>,
    ) -> (HeaderMap, HeaderMap) {
        let service = tower::ServiceBuilder::new()
            .layer(outer)
            .layer(SetViaHeaderLayer::new(ViaAddress::named("proxy").unwrap()))
            .option_layer(inner)
            .service_fn(|req: http::Request<()>| async move {
                let mut response = http::Response::new(req.headers().clone());
                let headers = response.headers_mut();
                headers.insert(CONNECTION, "via, x-upstream-hop".parse().unwrap());
                headers.insert("x-upstream-hop", "1".parse().unwrap());
                Ok::<_, Infallible>(response)
            });

        // A client trying to remove the request `Via`.
        let mut request = http::Request::new(());
        request
            .headers_mut()
            .insert(CONNECTION, "via".parse().unwrap());

        let response = service.oneshot(request).await.unwrap();
        let (parts, upstream_request) = response.into_parts();
        (upstream_request, parts.headers)
    }

    #[tokio::test]
    async fn split_layers_protect_added_headers_in_both_directions() {
        let (request, response) = via_stack(
            StripHopByHopLayer::new().direction(StripDirection::Request),
            Some(StripHopByHopLayer::new().direction(StripDirection::Response)),
        )
        .await;

        assert_eq!(names(&request), ["via"]);
        assert_eq!(names(&response), ["via"]);
        assert!(
            response[VIA].to_str().unwrap().ends_with(" proxy"),
            "{response:?}"
        );
    }

    #[tokio::test]
    async fn single_layer_does_not_protect_response_headers() {
        // This is why the module docs recommend splitting the layer for untrusted upstreams.
        let (request, response) = via_stack(StripHopByHopLayer::new(), None).await;

        assert_eq!(names(&request), ["via"]);
        assert!(response.is_empty(), "{response:?}");
    }

    #[tokio::test]
    async fn ordering_protects_added_headers() {
        let service = tower::ServiceBuilder::new()
            .layer(StripHopByHopLayer::new())
            .layer(SetForwardedHeaderLayer::new().set_x_headers(true).config(
                ForwardedHeaderConfig {
                    r#for: ForwardeeMode::Address,
                    ..Default::default()
                },
            ))
            .service_fn(|req: http::Request<()>| async move {
                Ok::<_, Infallible>(http::Response::new(req.headers().clone()))
            });

        // A client trying to remove the headers this proxy adds.
        let mut request = http::Request::get("/").body(()).unwrap();
        request.headers_mut().insert(
            CONNECTION,
            HeaderValue::from_static("forwarded, x-forwarded-for"),
        );
        request.extensions_mut().insert(RemoteAddress(
            "192.0.2.1:4000"
                .parse::<std::net::SocketAddr>()
                .unwrap()
                .into(),
        ));

        let forwarded = service.oneshot(request).await.unwrap().into_body();
        assert_eq!(forwarded[FORWARDED], "for=\"192.0.2.1:4000\"");
        assert_eq!(forwarded[X_FORWARDED_FOR], "192.0.2.1");
        assert!(forwarded.get(CONNECTION).is_none());
    }
}
