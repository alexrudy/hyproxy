//! Layer to fix the scheme of the request URI when
//! passing through a proxy.
//!
//! Sometimes, the client may not set the scheme of the URI
//! when sending a request. This can be a problem when the
//! request is being proxied, as the upstream may require
//! the scheme to be set. This layer can be used to set
//! the scheme of the URI to a default value when it is
//! not set.

use hyperdriver::{
    client::{conn::Connection, pool::PoolableConnection},
    service::ExecuteRequest,
};

/// A layer that sets the scheme of the URI to a default.
///
/// Defaults to `http` via the `Default` implementation.
#[derive(Debug, Clone)]
pub struct ProxyUriLayer {
    scheme: http::uri::Scheme,
}

impl ProxyUriLayer {
    /// Create a new `ProxyUriLayer` with the given scheme
    pub fn new(scheme: http::uri::Scheme) -> Self {
        Self { scheme }
    }
}

impl Default for ProxyUriLayer {
    fn default() -> Self {
        Self {
            scheme: http::uri::Scheme::HTTP,
        }
    }
}

impl From<http::uri::Scheme> for ProxyUriLayer {
    fn from(scheme: http::uri::Scheme) -> Self {
        Self::new(scheme)
    }
}

impl<S> tower::layer::Layer<S> for ProxyUriLayer {
    type Service = ProxyUriService<S>;

    fn layer(&self, service: S) -> Self::Service {
        ProxyUriService {
            scheme: self.scheme.clone(),
            service,
        }
    }
}

/// A service that sets the scheme of the URI to a default.
#[derive(Debug, Clone)]
pub struct ProxyUriService<S> {
    scheme: http::uri::Scheme,
    service: S,
}

impl<S> ProxyUriService<S> {
    /// Create a new `ProxyUriService` with the given scheme
    pub fn new(scheme: http::uri::Scheme, service: S) -> Self {
        Self { scheme, service }
    }

    /// Create a new `ProxyUriLayer` with the given scheme
    pub fn layer(scheme: http::uri::Scheme) -> ProxyUriLayer {
        ProxyUriLayer::new(scheme)
    }

    /// The default scheme used by this service.
    pub fn scheme(&self) -> &http::uri::Scheme {
        &self.scheme
    }

    /// Unwrap the inner service
    pub fn into_inner(self) -> S {
        self.service
    }

    fn set_scheme<B>(&self, req: &mut http::Request<B>) {
        let mut uri = req.uri().clone().into_parts();
        if uri.scheme.is_none() {
            uri.scheme = Some(self.scheme.clone());
        }

        *req.uri_mut() = http::Uri::from_parts(uri).expect("valid uri with scheme");
    }
}

impl<S, B> tower::Service<http::Request<B>> for ProxyUriService<S>
where
    S: tower::Service<http::Request<B>>,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = S::Future;

    fn call(&mut self, mut req: http::Request<B>) -> Self::Future {
        self.set_scheme(&mut req);

        self.service.call(req)
    }

    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.service.poll_ready(cx)
    }
}

impl<S, C, B> tower::Service<ExecuteRequest<C, B>> for ProxyUriService<S>
where
    S: tower::Service<ExecuteRequest<C, B>>,
    C: Connection<B> + PoolableConnection<B>,
    B: Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = S::Future;

    fn call(&mut self, mut req: ExecuteRequest<C, B>) -> Self::Future {
        self.set_scheme(req.request_mut());

        self.service.call(req)
    }

    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.service.poll_ready(cx)
    }
}
