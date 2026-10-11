//! The service which runs a proxied upgrade, and its supporting types.

use std::fmt;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use hyper::upgrade::{OnUpgrade, Upgraded};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tower::BoxError;

#[cfg(not(feature = "hyperdriver"))]
use crate::bridge::TokioIo;
#[cfg(feature = "hyperdriver")]
use hyperdriver::bridge::io::TokioIo;

use super::UpgradeProtocol;

/// An upgraded connection proxied between a client and an upstream server.
///
/// This is the request type for the tunnel service in [`ProxyUpgrade`](super::ProxyUpgrade).
/// It carries both connections and the HTTP exchange which upgraded them, so that tunnel
/// middleware can make decisions based on the protocol, request, or response.
///
/// The connections are generic so that middleware can wrap them, for example to count or
/// limit the bytes passed over the connection, using [`Tunnel::map_io`]. When used with
/// [`ProxyUpgrade`](super::ProxyUpgrade), both start as [`UpgradedIo`].
#[derive(Debug)]
pub struct Tunnel<C, U> {
    client: C,
    upstream: U,
    protocol: UpgradeProtocol,
    request: http::request::Parts,
    response: http::response::Parts,
}

impl<C, U> Tunnel<C, U> {
    /// Create a new tunnel between `client` and `upstream`, which were upgraded to
    /// `protocol` by the given request and response.
    pub fn new(
        client: C,
        upstream: U,
        protocol: UpgradeProtocol,
        request: http::request::Parts,
        response: http::response::Parts,
    ) -> Self {
        Self {
            client,
            upstream,
            protocol,
            request,
            response,
        }
    }

    /// The connection to the client.
    pub fn client(&self) -> &C {
        &self.client
    }

    /// The connection to the client, mutably.
    pub fn client_mut(&mut self) -> &mut C {
        &mut self.client
    }

    /// The connection to the upstream server.
    pub fn upstream(&self) -> &U {
        &self.upstream
    }

    /// The connection to the upstream server, mutably.
    pub fn upstream_mut(&mut self) -> &mut U {
        &mut self.upstream
    }

    /// The protocol both connections were upgraded to, as named by the upstream's response.
    pub fn protocol(&self) -> &UpgradeProtocol {
        &self.protocol
    }

    /// The client's upgrade request, as received by [`ProxyUpgrade`](super::ProxyUpgrade).
    ///
    /// The extensions are cloned from the request, so they include any extensions added by
    /// middleware outside of `ProxyUpgrade` (such as connection information), and the
    /// parsed [`UpgradeRequest`](super::UpgradeRequest).
    pub fn request(&self) -> &http::request::Parts {
        &self.request
    }

    /// The client's upgrade request, mutably.
    pub fn request_mut(&mut self) -> &mut http::request::Parts {
        &mut self.request
    }

    /// The upstream's `101 Switching Protocols` response, as returned by the inner service.
    pub fn response(&self) -> &http::response::Parts {
        &self.response
    }

    /// The upstream's `101 Switching Protocols` response, mutably.
    pub fn response_mut(&mut self) -> &mut http::response::Parts {
        &mut self.response
    }

    /// Consume the tunnel, returning the client and upstream connections.
    pub fn into_io(self) -> (C, U) {
        (self.client, self.upstream)
    }

    /// Replace the connections, keeping the protocol, request and response.
    pub fn map_io<C2, U2, F>(self, f: F) -> Tunnel<C2, U2>
    where
        F: FnOnce(C, U) -> (C2, U2),
    {
        let (client, upstream) = f(self.client, self.upstream);
        Tunnel {
            client,
            upstream,
            protocol: self.protocol,
            request: self.request,
            response: self.response,
        }
    }
}

/// The number of bytes copied in each direction over a [`Tunnel`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TunnelStats {
    client_to_upstream: u64,
    upstream_to_client: u64,
}

impl TunnelStats {
    /// Create stats from the bytes copied in each direction.
    pub fn new(client_to_upstream: u64, upstream_to_client: u64) -> Self {
        Self {
            client_to_upstream,
            upstream_to_client,
        }
    }

    /// Bytes copied from the client to the upstream.
    pub fn client_to_upstream(&self) -> u64 {
        self.client_to_upstream
    }

    /// Bytes copied from the upstream to the client.
    pub fn upstream_to_client(&self) -> u64 {
        self.upstream_to_client
    }
}

/// The default tunnel service: copies data in both directions with
/// [`tokio::io::copy_bidirectional`] until both sides have closed.
///
/// Wrap this with tower middleware to control tunnels. The tunnel service is cloned for every
/// upgrade, so middleware which limits all tunnels together must share its state between
/// clones, as tower's concurrency limit does.
#[derive(Debug, Clone, Default)]
pub struct CopyBidirectional {
    _priv: (),
}

impl CopyBidirectional {
    /// Create a new `CopyBidirectional` service.
    pub fn new() -> Self {
        Self { _priv: () }
    }
}

impl<C, U> tower::Service<Tunnel<C, U>> for CopyBidirectional
where
    C: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    U: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    type Response = TunnelStats;
    type Error = io::Error;
    type Future = CopyBidirectionalFuture;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, tunnel: Tunnel<C, U>) -> Self::Future {
        CopyBidirectionalFuture {
            inner: Box::pin(async move {
                let protocol = tunnel.protocol.clone();
                let (mut client, mut upstream) = tunnel.into_io();
                let (up, down) = tokio::io::copy_bidirectional(&mut client, &mut upstream).await?;
                tracing::debug!(
                    ?protocol,
                    "Upgrade complete: {} bytes upstream, {} bytes downstream",
                    up,
                    down
                );
                Ok(TunnelStats::new(up, down))
            }),
        }
    }
}

/// Future returned by [`CopyBidirectional`].
pub struct CopyBidirectionalFuture {
    inner: Pin<Box<dyn Future<Output = io::Result<TunnelStats>> + Send>>,
}

impl fmt::Debug for CopyBidirectionalFuture {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CopyBidirectionalFuture")
            .finish_non_exhaustive()
    }
}

impl Future for CopyBidirectionalFuture {
    type Output = io::Result<TunnelStats>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.inner.as_mut().poll(cx)
    }
}

pin_project_lite::pin_project! {
    /// An upgraded hyper connection, with Tokio I/O traits.
    pub struct UpgradedIo {
        #[pin]
        inner: TokioIo<Upgraded>,
    }
}

impl UpgradedIo {
    fn new(upgraded: Upgraded) -> Self {
        Self {
            inner: TokioIo::new(upgraded),
        }
    }

    /// Consume the wrapper, returning the hyper connection.
    ///
    /// Use [`Upgraded::downcast`] to recover the underlying I/O type.
    pub fn into_inner(self) -> Upgraded {
        self.inner.into_inner()
    }
}

impl fmt::Debug for UpgradedIo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UpgradedIo").finish_non_exhaustive()
    }
}

impl AsyncRead for UpgradedIo {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.project().inner.poll_read(cx, buf)
    }
}

impl AsyncWrite for UpgradedIo {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.project().inner.poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.project().inner.poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.project().inner.poll_shutdown(cx)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        self.project().inner.poll_write_vectored(cx, bufs)
    }
}

/// The default executor for tunnels, which runs each with [`tokio::spawn`].
#[derive(Debug, Clone, Copy, Default)]
pub struct TokioExecutor {
    _priv: (),
}

impl TokioExecutor {
    /// Create a new `TokioExecutor`.
    pub fn new() -> Self {
        Self { _priv: () }
    }
}

impl<F> hyper::rt::Executor<F> for TokioExecutor
where
    F: Future + Send + 'static,
    F::Output: Send + 'static,
{
    fn execute(&self, fut: F) {
        tokio::spawn(fut);
    }
}

/// A proxied upgrade, to be run by the executor in [`ProxyUpgrade`](super::ProxyUpgrade).
///
/// The task waits for both connections to upgrade, then calls the tunnel service. It
/// completes when the tunnel service does. Errors are logged, and are not returned.
#[must_use = "futures do nothing unless polled"]
pub struct TunnelTask {
    inner: Pin<Box<dyn Future<Output = ()> + Send>>,
}

impl TunnelTask {
    pub(super) fn new<T>(
        service: T,
        client: OnUpgrade,
        upstream: OnUpgrade,
        protocol: UpgradeProtocol,
        request: http::request::Parts,
        response: http::response::Parts,
    ) -> Self
    where
        T: tower::Service<Tunnel<UpgradedIo, UpgradedIo>> + Send + 'static,
        T::Future: Send,
        T::Error: Into<BoxError>,
    {
        Self {
            inner: Box::pin(run(service, client, upstream, protocol, request, response)),
        }
    }
}

impl fmt::Debug for TunnelTask {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TunnelTask").finish_non_exhaustive()
    }
}

impl Future for TunnelTask {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.inner.as_mut().poll(cx)
    }
}

async fn run<T>(
    mut service: T,
    client: OnUpgrade,
    upstream: OnUpgrade,
    protocol: UpgradeProtocol,
    request: http::request::Parts,
    response: http::response::Parts,
) where
    T: tower::Service<Tunnel<UpgradedIo, UpgradedIo>>,
    T::Error: Into<BoxError>,
{
    let client = match client.await {
        Ok(upgraded) => {
            tracing::debug!(?protocol, "Request upgraded");
            upgraded
        }
        Err(error) => {
            // Usually the client disconnecting.
            tracing::debug!(?protocol, "Request upgrade failed: {:?}", error);
            return;
        }
    };

    let upstream = match upstream.await {
        Ok(upgraded) => {
            tracing::debug!(?protocol, "Response upgraded");
            upgraded
        }
        Err(error) => {
            // The upstream agreed to upgrade, so this is unexpected.
            tracing::warn!(?protocol, "Response upgrade failed: {:?}", error);
            return;
        }
    };

    let tunnel = Tunnel::new(
        UpgradedIo::new(client),
        UpgradedIo::new(upstream),
        protocol.clone(),
        request,
        response,
    );

    let result = async {
        std::future::poll_fn(|cx| service.poll_ready(cx))
            .await
            .map_err(Into::into)?;
        service.call(tunnel).await.map_err(Into::into)
    }
    .await;

    if let Err(error) = result {
        tracing::debug!(?protocol, "Upgrade tunnel error: {}", error);
    }
}
