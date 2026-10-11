//! Limit the amount of data passed over a [`Tunnel`].
//!
//! [`DataLimit`] counts the bytes read from the client (sent upstream) and from the upstream
//! (sent to the client). It can limit each direction separately, and the total of both
//! directions. Exactly as many bytes as the limit allows get through; the next read which
//! would pass more data fails with a [`DataLimitExceeded`] I/O error, which ends the tunnel
//! when used with [`CopyBidirectional`](super::CopyBidirectional).
//!
//! ```
//! use hyproxy::upgrade::limit::DataLimitLayer;
//! use hyproxy::upgrade::{CopyBidirectional, ProxyUpgradeLayer};
//!
//! const MIB: u64 = 1024 * 1024;
//!
//! // Allow at most 1 MiB of uploads and 64 MiB of downloads over each upgraded connection.
//! let tunnel = tower::ServiceBuilder::new()
//!     .layer(
//!         DataLimitLayer::default()
//!             .client_to_upstream(MIB)
//!             .upstream_to_client(64 * MIB),
//!     )
//!     .service(CopyBidirectional::new());
//!
//! let layer = ProxyUpgradeLayer::new().tunnel(tunnel);
//! # let _ = layer;
//! ```

use std::fmt;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::task::{ready, Context, Poll};

use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::Tunnel;

/// Which of a tunnel's data limits was exceeded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DataLimitKind {
    /// The limit on data in both directions combined.
    Total,
    /// The limit on data from the client to the upstream (uploads).
    ClientToUpstream,
    /// The limit on data from the upstream to the client (downloads).
    UpstreamToClient,
}

impl fmt::Display for DataLimitKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            DataLimitKind::Total => "total",
            DataLimitKind::ClientToUpstream => "client to upstream",
            DataLimitKind::UpstreamToClient => "upstream to client",
        })
    }
}

/// The error returned by a [`LimitedIo`] read once one of its tunnel's data limits is
/// exceeded.
///
/// This is wrapped in an [`io::Error`] with [`io::ErrorKind::Other`]; use
/// [`io::Error::get_ref`] and downcast to detect it.
#[derive(Debug, Clone, Copy, Error, PartialEq, Eq)]
#[error("tunnel {kind} data limit of {limit} bytes exceeded")]
pub struct DataLimitExceeded {
    kind: DataLimitKind,
    limit: u64,
}

impl DataLimitExceeded {
    /// Which limit was exceeded.
    pub fn kind(&self) -> DataLimitKind {
        self.kind
    }

    /// The limit which was exceeded, in bytes.
    pub fn limit(&self) -> u64 {
        self.limit
    }
}

/// The limits applied to each tunnel; `None` is unlimited.
#[derive(Debug, Clone, Copy, Default)]
struct Limits {
    total: Option<u64>,
    client_to_upstream: Option<u64>,
    upstream_to_client: Option<u64>,
}

/// Layer which limits the amount of data passed over each [`Tunnel`].
///
/// [`DataLimitLayer::new`] limits the total in both directions. The default has no limits;
/// add them with [`total`](Self::total), [`client_to_upstream`](Self::client_to_upstream)
/// and [`upstream_to_client`](Self::upstream_to_client). All the limits that are set apply.
///
/// See the [module documentation](self) for details.
#[derive(Debug, Clone, Copy, Default)]
pub struct DataLimitLayer {
    limits: Limits,
}

impl DataLimitLayer {
    /// Allow at most `limit` bytes in total, in both directions, over each tunnel.
    pub fn new(limit: u64) -> Self {
        Self::default().total(limit)
    }

    /// Allow at most `limit` bytes in total, in both directions, over each tunnel.
    pub fn total(mut self, limit: u64) -> Self {
        self.limits.total = Some(limit);
        self
    }

    /// Allow at most `limit` bytes from the client to the upstream (uploads) over each
    /// tunnel.
    pub fn client_to_upstream(mut self, limit: u64) -> Self {
        self.limits.client_to_upstream = Some(limit);
        self
    }

    /// Allow at most `limit` bytes from the upstream to the client (downloads) over each
    /// tunnel.
    pub fn upstream_to_client(mut self, limit: u64) -> Self {
        self.limits.upstream_to_client = Some(limit);
        self
    }
}

impl<S> tower::layer::Layer<S> for DataLimitLayer {
    type Service = DataLimit<S>;

    fn layer(&self, inner: S) -> Self::Service {
        DataLimit {
            inner,
            limits: self.limits,
        }
    }
}

/// Tunnel middleware which limits the amount of data passed over each [`Tunnel`].
///
/// See [`DataLimitLayer`] and the [module documentation](self) for details.
#[derive(Debug, Clone)]
pub struct DataLimit<S> {
    inner: S,
    limits: Limits,
}

impl<S> DataLimit<S> {
    /// Allow at most `limit` bytes in total, in both directions, over each tunnel passed to
    /// `inner`.
    pub fn new(inner: S, limit: u64) -> Self {
        Self {
            inner,
            limits: Limits::default(),
        }
        .total(limit)
    }

    /// Allow at most `limit` bytes in total, in both directions, over each tunnel.
    pub fn total(mut self, limit: u64) -> Self {
        self.limits.total = Some(limit);
        self
    }

    /// Allow at most `limit` bytes from the client to the upstream (uploads) over each
    /// tunnel.
    pub fn client_to_upstream(mut self, limit: u64) -> Self {
        self.limits.client_to_upstream = Some(limit);
        self
    }

    /// Allow at most `limit` bytes from the upstream to the client (downloads) over each
    /// tunnel.
    pub fn upstream_to_client(mut self, limit: u64) -> Self {
        self.limits.upstream_to_client = Some(limit);
        self
    }
}

impl<S, C, U> tower::Service<Tunnel<C, U>> for DataLimit<S>
where
    S: tower::Service<Tunnel<LimitedIo<C>, LimitedIo<U>>>,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = S::Future;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, tunnel: Tunnel<C, U>) -> Self::Future {
        let total = self.limits.total.map(|limit| {
            Arc::new(SharedBudget {
                limit,
                used: AtomicU64::new(0),
            })
        });
        let client_to_upstream = self
            .limits
            .client_to_upstream
            .map(|limit| Budget::new(DataLimitKind::ClientToUpstream, limit));
        let upstream_to_client = self
            .limits
            .upstream_to_client
            .map(|limit| Budget::new(DataLimitKind::UpstreamToClient, limit));

        let tunnel = tunnel.map_io(|client, upstream| {
            (
                // Bytes read from the client go upstream, and vice versa.
                LimitedIo::new(client, client_to_upstream, total.clone()),
                LimitedIo::new(upstream, upstream_to_client, total),
            )
        });
        self.inner.call(tunnel)
    }
}

/// The limit for one direction of a tunnel.
#[derive(Debug)]
struct Budget {
    kind: DataLimitKind,
    limit: u64,
    used: u64,
}

impl Budget {
    fn new(kind: DataLimitKind, limit: u64) -> Self {
        Self {
            kind,
            limit,
            used: 0,
        }
    }

    /// Record that `n` bytes passed, returning how many of `n` fit within the limit.
    fn consume(&mut self, n: usize) -> usize {
        let allowed = self.limit.saturating_sub(self.used).min(n as u64);
        self.used += allowed;
        // `allowed <= n`, which came from a `usize`.
        allowed as usize
    }

    fn exceeded(&self) -> DataLimitExceeded {
        DataLimitExceeded {
            kind: self.kind,
            limit: self.limit,
        }
    }
}

/// The total limit, shared by both sides of a tunnel.
#[derive(Debug)]
struct SharedBudget {
    limit: u64,
    used: AtomicU64,
}

impl SharedBudget {
    /// Record that `n` bytes passed, returning how many of `n` fit within the limit.
    fn consume(&self, n: usize) -> usize {
        let n = n as u64;
        let before = self.used.fetch_add(n, Ordering::Relaxed);
        // `allowed <= n`, which came from a `usize`.
        self.limit.saturating_sub(before).min(n) as usize
    }

    fn exceeded(&self) -> DataLimitExceeded {
        DataLimitExceeded {
            kind: DataLimitKind::Total,
            limit: self.limit,
        }
    }
}

pin_project_lite::pin_project! {
    /// One side of a tunnel whose data is limited by [`DataLimit`].
    ///
    /// Reads count against the limit for data sent from this side, and the total limit
    /// shared with the other side of the tunnel. Writes pass through unchanged.
    #[derive(Debug)]
    pub struct LimitedIo<T> {
        #[pin]
        inner: T,
        direction: Option<Budget>,
        total: Option<Arc<SharedBudget>>,
        exceeded: Option<DataLimitExceeded>,
    }
}

impl<T> LimitedIo<T> {
    fn new(inner: T, direction: Option<Budget>, total: Option<Arc<SharedBudget>>) -> Self {
        Self {
            inner,
            direction,
            total,
            exceeded: None,
        }
    }

    /// The wrapped I/O object.
    pub fn get_ref(&self) -> &T {
        &self.inner
    }

    /// Consume the wrapper, returning the wrapped I/O object.
    pub fn into_inner(self) -> T {
        self.inner
    }
}

impl<T: AsyncRead> AsyncRead for LimitedIo<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.project();
        if let Some(exceeded) = this.exceeded {
            return Poll::Ready(Err(io::Error::other(*exceeded)));
        }

        let before = buf.filled().len();
        ready!(this.inner.poll_read(cx, buf))?;
        let read = buf.filled().len() - before;
        if read == 0 {
            return Poll::Ready(Ok(()));
        }

        // Only count against the total what this direction's limit lets through.
        let mut allowed = read;
        if let Some(direction) = this.direction.as_mut() {
            allowed = direction.consume(allowed);
            if allowed < read {
                *this.exceeded = Some(direction.exceeded());
            }
        }
        if let Some(total) = this.total.as_ref() {
            let within_total = total.consume(allowed);
            if within_total < allowed {
                allowed = within_total;
                *this.exceeded = Some(total.exceeded());
            }
        }

        if allowed < read {
            // Drop the bytes past the limit, and fail the next read. Reporting the bytes
            // within the limit first means exactly as many bytes as allowed get through.
            buf.set_filled(before + allowed);
            if allowed == 0 {
                let exceeded = this.exceeded.expect("a limit was exceeded");
                return Poll::Ready(Err(io::Error::other(exceeded)));
            }
        }

        Poll::Ready(Ok(()))
    }
}

impl<T: AsyncWrite> AsyncWrite for LimitedIo<T> {
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

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _, DuplexStream};
    use tower::{Layer as _, ServiceExt as _};

    use super::*;
    use crate::upgrade::{CopyBidirectional, TunnelStats};

    type Copy = tokio::task::JoinHandle<io::Result<TunnelStats>>;

    /// Start a tunnel limited by `layer`, returning the client and upstream peers.
    fn start(layer: DataLimitLayer) -> (DuplexStream, DuplexStream, Copy) {
        let (client, client_peer) = tokio::io::duplex(64);
        let (upstream, upstream_peer) = tokio::io::duplex(64);
        let tunnel = Tunnel::new(
            client,
            upstream,
            "echo".parse().unwrap(),
            http::Request::new(()).into_parts().0,
            http::Response::new(()).into_parts().0,
        );
        let service = layer.layer(CopyBidirectional::new());
        let copy = tokio::spawn(service.oneshot(tunnel));
        (client_peer, upstream_peer, copy)
    }

    async fn send(from: &mut DuplexStream, to: &mut DuplexStream, data: &[u8]) {
        from.write_all(data).await.unwrap();
        let mut buf = vec![0u8; data.len()];
        to.read_exact(&mut buf).await.unwrap();
        assert_eq!(buf, data);
    }

    async fn exceeded(copy: Copy) -> DataLimitExceeded {
        let error = copy.await.unwrap().unwrap_err();
        *error
            .get_ref()
            .and_then(|e| e.downcast_ref::<DataLimitExceeded>())
            .expect("data limit error")
    }

    #[tokio::test]
    async fn data_within_limit_passes() {
        let (mut client, mut upstream, copy) = start(DataLimitLayer::new(9));

        send(&mut client, &mut upstream, b"ping").await;
        // Exactly reaching the limit is allowed.
        send(&mut upstream, &mut client, b"pong!").await;

        drop(client);
        drop(upstream);
        let stats = copy.await.unwrap().unwrap();
        assert_eq!(stats, TunnelStats::new(4, 5));
    }

    #[tokio::test]
    async fn data_over_total_limit_is_cut_off() {
        let (mut client, mut upstream, copy) = start(DataLimitLayer::new(8));

        send(&mut client, &mut upstream, b"ping").await;
        // The total limit is shared between directions, so only "pong" fits.
        upstream.write_all(b"pong!").await.unwrap();

        let exceeded = exceeded(copy).await;
        assert_eq!(exceeded.kind(), DataLimitKind::Total);
        assert_eq!(exceeded.limit(), 8);

        // The client gets the bytes within the limit, then the connection closes.
        let mut received = Vec::new();
        client.read_to_end(&mut received).await.unwrap();
        assert_eq!(received, b"pong");
    }

    #[tokio::test]
    async fn directions_are_limited_separately() {
        let layer = DataLimitLayer::default()
            .client_to_upstream(4)
            .upstream_to_client(8);
        let (mut client, mut upstream, copy) = start(layer);

        // The client has used its whole allowance, but the upstream has its own.
        send(&mut client, &mut upstream, b"ping").await;
        send(&mut upstream, &mut client, b"pong").await;
        send(&mut upstream, &mut client, b"pong").await;

        client.write_all(b"!").await.unwrap();
        let exceeded = exceeded(copy).await;
        assert_eq!(exceeded.kind(), DataLimitKind::ClientToUpstream);
        assert_eq!(exceeded.limit(), 4);

        let mut received = Vec::new();
        upstream.read_to_end(&mut received).await.unwrap();
        assert!(received.is_empty());
    }

    #[tokio::test]
    async fn download_over_limit_is_cut_off() {
        let (mut client, mut upstream, copy) =
            start(DataLimitLayer::default().upstream_to_client(3));

        upstream.write_all(b"pong").await.unwrap();
        let exceeded = exceeded(copy).await;
        assert_eq!(exceeded.kind(), DataLimitKind::UpstreamToClient);

        let mut received = Vec::new();
        client.read_to_end(&mut received).await.unwrap();
        assert_eq!(received, b"pon");
    }

    #[tokio::test]
    async fn total_and_direction_limits_both_apply() {
        let layer = DataLimitLayer::new(6).client_to_upstream(100);
        let (mut client, mut upstream, copy) = start(layer);

        send(&mut upstream, &mut client, b"pong").await;
        // Within the client's own limit, but over the total.
        client.write_all(b"ping").await.unwrap();

        let exceeded = exceeded(copy).await;
        assert_eq!(exceeded.kind(), DataLimitKind::Total);

        let mut received = Vec::new();
        upstream.read_to_end(&mut received).await.unwrap();
        assert_eq!(received, b"pi");
    }

    #[test]
    fn data_limit_exceeded_message_names_the_limit() {
        let error = DataLimitExceeded {
            kind: DataLimitKind::ClientToUpstream,
            limit: 4,
        };
        assert_eq!(
            error.to_string(),
            "tunnel client to upstream data limit of 4 bytes exceeded"
        );
    }
}
