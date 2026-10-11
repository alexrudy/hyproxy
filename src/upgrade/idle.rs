//! Close a [`Tunnel`] when no data has moved over it for a while.
//!
//! [`IdleTimeout`] tracks reads and writes on both the client and upstream connections. If
//! neither moves any data for the configured duration, the tunnel service's future is
//! dropped, closing both connections, and the tunnel fails with [`IdleTimeoutElapsed`].
//!
//! A write which is stuck because the receiver isn't reading does not count as activity,
//! so a tunnel which is not making progress also times out.
//!
//! ```
//! use std::time::Duration;
//!
//! use hyproxy::upgrade::idle::IdleTimeoutLayer;
//! use hyproxy::upgrade::{CopyBidirectional, ProxyUpgradeLayer};
//!
//! // Close upgraded connections after 5 minutes without any traffic.
//! let tunnel = tower::ServiceBuilder::new()
//!     .layer(IdleTimeoutLayer::new(Duration::from_secs(5 * 60)))
//!     .service(CopyBidirectional::new());
//!
//! let layer = ProxyUpgradeLayer::new().tunnel(tunnel);
//! # let _ = layer;
//! ```
//!
//! This uses Tokio's timer, so it must run within a Tokio runtime with the time driver
//! enabled.

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::task::{ready, Context, Poll};
use std::time::Duration;

use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::time::{Instant, Sleep};
use tower::BoxError;

use super::Tunnel;

/// The error returned when a tunnel is closed by [`IdleTimeout`].
#[derive(Debug, Clone, Copy, Error, PartialEq, Eq)]
#[error("tunnel idle for {timeout:?}")]
pub struct IdleTimeoutElapsed {
    timeout: Duration,
}

impl IdleTimeoutElapsed {
    /// The idle timeout which elapsed.
    pub fn timeout(&self) -> Duration {
        self.timeout
    }
}

/// Layer which closes each [`Tunnel`] once it has been idle for a duration.
///
/// See the [module documentation](self) for details.
#[derive(Debug, Clone, Copy)]
pub struct IdleTimeoutLayer {
    timeout: Duration,
}

impl IdleTimeoutLayer {
    /// Close each tunnel once no data has moved over it for `timeout`.
    pub fn new(timeout: Duration) -> Self {
        Self { timeout }
    }
}

impl<S> tower::layer::Layer<S> for IdleTimeoutLayer {
    type Service = IdleTimeout<S>;

    fn layer(&self, inner: S) -> Self::Service {
        IdleTimeout::new(inner, self.timeout)
    }
}

/// Tunnel middleware which closes each [`Tunnel`] once it has been idle for a duration.
///
/// See the [module documentation](self) for details.
#[derive(Debug, Clone)]
pub struct IdleTimeout<S> {
    inner: S,
    timeout: Duration,
}

impl<S> IdleTimeout<S> {
    /// Close each tunnel passed to `inner` once no data has moved over it for `timeout`.
    pub fn new(inner: S, timeout: Duration) -> Self {
        Self { inner, timeout }
    }
}

impl<S, C, U> tower::Service<Tunnel<C, U>> for IdleTimeout<S>
where
    S: tower::Service<Tunnel<IdleIo<C>, IdleIo<U>>>,
    S::Error: Into<BoxError>,
{
    type Response = S::Response;
    type Error = BoxError;
    type Future = IdleTimeoutFuture<S::Future>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx).map_err(Into::into)
    }

    fn call(&mut self, tunnel: Tunnel<C, U>) -> Self::Future {
        let activity = Arc::new(Activity::new());
        let tunnel = tunnel.map_io(|client, upstream| {
            (
                IdleIo::new(client, activity.clone()),
                IdleIo::new(upstream, activity.clone()),
            )
        });

        IdleTimeoutFuture {
            inner: self.inner.call(tunnel),
            sleep: tokio::time::sleep_until(activity.deadline(self.timeout)),
            activity,
            timeout: self.timeout,
        }
    }
}

/// When data last moved over either side of a tunnel.
#[derive(Debug)]
struct Activity {
    start: Instant,
    /// Nanoseconds after `start`.
    last: AtomicU64,
}

impl Activity {
    fn new() -> Self {
        Self {
            start: Instant::now(),
            last: AtomicU64::new(0),
        }
    }

    fn touch(&self) {
        // A u64 of nanoseconds lasts for centuries.
        let elapsed = self.start.elapsed().as_nanos() as u64;
        self.last.fetch_max(elapsed, Ordering::Relaxed);
    }

    fn deadline(&self, timeout: Duration) -> Instant {
        self.start + Duration::from_nanos(self.last.load(Ordering::Relaxed)) + timeout
    }
}

pin_project_lite::pin_project! {
    /// Future returned by [`IdleTimeout`].
    #[derive(Debug)]
    pub struct IdleTimeoutFuture<F> {
        #[pin]
        inner: F,
        #[pin]
        sleep: Sleep,
        activity: Arc<Activity>,
        timeout: Duration,
    }
}

impl<F, R, E> Future for IdleTimeoutFuture<F>
where
    F: Future<Output = Result<R, E>>,
    E: Into<BoxError>,
{
    type Output = Result<R, BoxError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut this = self.project();

        if let Poll::Ready(result) = this.inner.poll(cx) {
            return Poll::Ready(result.map_err(Into::into));
        }

        // When the timer fires, only time out if there has been no activity since it was
        // set; otherwise, wait until the idle timeout after the latest activity.
        loop {
            ready!(this.sleep.as_mut().poll(cx));
            let deadline = this.activity.deadline(*this.timeout);
            if deadline <= Instant::now() {
                return Poll::Ready(Err(IdleTimeoutElapsed {
                    timeout: *this.timeout,
                }
                .into()));
            }
            this.sleep.as_mut().reset(deadline);
        }
    }
}

pin_project_lite::pin_project! {
    /// One side of a tunnel watched by [`IdleTimeout`].
    ///
    /// Reads and writes which move data count as activity for the whole tunnel.
    #[derive(Debug)]
    pub struct IdleIo<T> {
        #[pin]
        inner: T,
        activity: Arc<Activity>,
    }
}

impl<T> IdleIo<T> {
    fn new(inner: T, activity: Arc<Activity>) -> Self {
        Self { inner, activity }
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

impl<T: AsyncRead> AsyncRead for IdleIo<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.project();
        let before = buf.filled().len();
        ready!(this.inner.poll_read(cx, buf))?;
        if buf.filled().len() > before {
            this.activity.touch();
        }
        Poll::Ready(Ok(()))
    }
}

impl<T: AsyncWrite> AsyncWrite for IdleIo<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.project();
        let written = ready!(this.inner.poll_write(cx, buf))?;
        if written > 0 {
            this.activity.touch();
        }
        Poll::Ready(Ok(written))
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
        let this = self.project();
        let written = ready!(this.inner.poll_write_vectored(cx, bufs))?;
        if written > 0 {
            this.activity.touch();
        }
        Poll::Ready(Ok(written))
    }
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    use tower::ServiceExt as _;

    use super::*;
    use crate::upgrade::CopyBidirectional;

    fn tunnel<C, U>(client: C, upstream: U) -> Tunnel<C, U> {
        Tunnel::new(
            client,
            upstream,
            "echo".parse().unwrap(),
            http::Request::new(()).into_parts().0,
            http::Response::new(()).into_parts().0,
        )
    }

    const TIMEOUT: Duration = Duration::from_secs(10);

    #[tokio::test(start_paused = true)]
    async fn idle_tunnel_times_out_after_last_activity() {
        let (client, mut client_peer) = tokio::io::duplex(64);
        let (upstream, mut upstream_peer) = tokio::io::duplex(64);
        let service = IdleTimeout::new(CopyBidirectional::new(), TIMEOUT);
        let copy = tokio::spawn(service.oneshot(tunnel(client, upstream)));

        tokio::time::sleep(Duration::from_secs(5)).await;
        client_peer.write_all(b"ping").await.unwrap();
        let mut buf = [0u8; 4];
        upstream_peer.read_exact(&mut buf).await.unwrap();

        // Past the original deadline, but within the timeout of the last activity.
        tokio::time::sleep(Duration::from_secs(7)).await;
        assert!(!copy.is_finished());

        tokio::time::sleep(Duration::from_secs(4)).await;
        assert!(copy.is_finished());
        let error = copy.await.unwrap().unwrap_err();
        let elapsed = error
            .downcast_ref::<IdleTimeoutElapsed>()
            .expect("idle timeout error");
        assert_eq!(elapsed.timeout(), TIMEOUT);

        // Both connections are closed.
        assert_eq!(client_peer.read(&mut buf).await.unwrap(), 0);
        assert_eq!(upstream_peer.read(&mut buf).await.unwrap(), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn tunnel_closing_before_timeout_is_not_an_error() {
        let (client, client_peer) = tokio::io::duplex(64);
        let (upstream, upstream_peer) = tokio::io::duplex(64);
        let service = IdleTimeout::new(CopyBidirectional::new(), TIMEOUT);
        let copy = tokio::spawn(service.oneshot(tunnel(client, upstream)));

        drop(client_peer);
        drop(upstream_peer);
        copy.await.unwrap().unwrap();
    }
}
