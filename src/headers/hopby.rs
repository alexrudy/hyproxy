//! Middleware to handle the Hop-by-Hop headers.

const HOPBYHOP: [http::header::HeaderName; 5] = [
    http::header::PROXY_AUTHENTICATE,
    http::header::PROXY_AUTHORIZATION,
    http::header::TE,
    http::header::TRAILER,
    http::header::TRANSFER_ENCODING,
];

fn strip_hopbyhop_headers(headers: &mut http::HeaderMap) {
    for header in HOPBYHOP.iter() {
        headers.remove(header);
    }
}

fn strip_linked_headers(headers: &mut http::HeaderMap, index: http::HeaderName) {
    let index_header = headers.get(&index).cloned();

    let values = index_header
        .as_ref()
        .map(|v| v.as_bytes().split(|c| *c == b',').collect::<Vec<&[u8]>>())
        .unwrap_or_default();

    for value in values {
        let trimmed = value
            .iter()
            .filter(|c| !c.is_ascii_whitespace())
            .copied()
            .collect::<Vec<_>>();

        if let Ok(name) = http::HeaderName::from_bytes(&trimmed) {
            headers.remove(&name);
        }
    }

    headers.remove(index);
}

/// Layer to strip hop-by-hop headers.
#[derive(Debug, Clone, Default)]
pub struct StripHopByHopLayer {
    preserve_connection: bool,
}

impl StripHopByHopLayer {
    /// Create a new `StripHopByHopLayer`.
    pub fn new(preserve_connection: bool) -> Self {
        Self {
            preserve_connection,
        }
    }
}

impl<S> tower::layer::Layer<S> for StripHopByHopLayer {
    type Service = StripHopByHop<S>;

    fn layer(&self, inner: S) -> Self::Service {
        StripHopByHop::new(inner, self.preserve_connection)
    }
}

/// Middleware to strip Hop-by-Hop headers.
#[derive(Debug, Clone)]
pub struct StripHopByHop<S> {
    inner: S,
    preserve_connection: bool,
}

impl<S> StripHopByHop<S> {
    /// Create a new `StripHopByHop` middleware.
    pub fn new(inner: S, preserve_connection: bool) -> Self {
        Self {
            inner,
            preserve_connection,
        }
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
        if !self.preserve_connection {
            strip_linked_headers(req.headers_mut(), http::header::CONNECTION);
        }
        strip_hopbyhop_headers(req.headers_mut());

        self::future::StripHopByHopFuture::new(self.inner.call(req), self.preserve_connection)
    }
}

mod future {
    use std::task::ready;

    use pin_project_lite::pin_project;

    use super::{strip_hopbyhop_headers, strip_linked_headers};

    pin_project! {
        pub struct StripHopByHopFuture<F> {

            #[pin]
            inner: F,
            preserve_connection: bool,
        }
    }

    impl<F> StripHopByHopFuture<F> {
        pub(super) fn new(inner: F, preserve_connection: bool) -> Self {
            Self {
                inner,
                preserve_connection,
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

            if let Ok(response) = &mut res {
                if !*this.preserve_connection {
                    strip_linked_headers(response.headers_mut(), http::header::CONNECTION);
                }
                strip_hopbyhop_headers(response.headers_mut());
            }

            std::task::Poll::Ready(res)
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn strip_linked_connection_headers() {
        let mut headers = http::HeaderMap::new();
        headers.insert(
            http::header::CONNECTION,
            "close, keep-alive, upgrade".parse().unwrap(),
        );
        headers.insert(http::header::UPGRADE, "websocket".parse().unwrap());

        super::strip_linked_headers(&mut headers, http::header::CONNECTION);

        assert!(headers.get(http::header::CONNECTION).is_none());
        assert!(headers.get("close").is_none());
        assert!(headers.get("keep-alive").is_none());
        assert!(headers.get(http::header::UPGRADE).is_none());
    }

    #[test]
    fn strip_hopbyhop_headers() {
        let mut headers = http::HeaderMap::new();
        headers.insert(http::header::PROXY_AUTHENTICATE, "Basic".parse().unwrap());
        headers.insert(http::header::TE, "trailers".parse().unwrap());
        headers.insert(http::header::TRAILER, "Expires".parse().unwrap());
        headers.insert(http::header::TRANSFER_ENCODING, "chunked".parse().unwrap());

        super::strip_hopbyhop_headers(&mut headers);

        assert!(headers.get(http::header::PROXY_AUTHENTICATE).is_none());
        assert!(headers.get(http::header::TE).is_none());
        assert!(headers.get(http::header::TRAILER).is_none());
        assert!(headers.get(http::header::TRANSFER_ENCODING).is_none());
    }
}
