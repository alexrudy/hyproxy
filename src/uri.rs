//! Layer to fix the scheme of the request URI when
//! passing through a proxy.
//!
//! Sometimes, the client may not set the scheme of the URI
//! when sending a request. This can be a problem when the
//! request is being proxied, as the upstream may require
//! the scheme to be set. This layer can be used to set
//! the scheme of the URI to a default value when it is
//! not set.

use chateau::client::pool::PoolableConnection;
use hyperdriver::client::conn::Connection;

/// A layer that sets the scheme of the URI to a default,
/// and optionally sets the authority of the URI.
///
/// Defaults to `http` via the `Default` implementation.
#[derive(Debug, Clone)]
pub struct ProxyUriLayer {
    scheme: http::uri::Scheme,
    authority: Option<http::uri::Authority>,
}

impl ProxyUriLayer {
    /// Create a new `ProxyUriLayer` with the given scheme
    pub fn new(scheme: http::uri::Scheme, authority: Option<http::uri::Authority>) -> Self {
        Self { scheme, authority }
    }
}

impl Default for ProxyUriLayer {
    fn default() -> Self {
        Self {
            scheme: http::uri::Scheme::HTTP,
            authority: None,
        }
    }
}

impl From<http::uri::Scheme> for ProxyUriLayer {
    fn from(scheme: http::uri::Scheme) -> Self {
        Self::new(scheme, None)
    }
}

impl<S> tower::layer::Layer<S> for ProxyUriLayer {
    type Service = ProxyUriService<S>;

    fn layer(&self, service: S) -> Self::Service {
        ProxyUriService {
            scheme: self.scheme.clone(),
            authority: self.authority.clone(),
            service,
        }
    }
}

/// A service that sets the scheme of the URI to a default.
#[derive(Debug, Clone)]
pub struct ProxyUriService<S> {
    scheme: http::uri::Scheme,
    authority: Option<http::uri::Authority>,
    service: S,
}

impl<S> ProxyUriService<S> {
    /// Create a new `ProxyUriService` with the given scheme
    pub fn new(
        scheme: http::uri::Scheme,
        authority: Option<http::uri::Authority>,
        service: S,
    ) -> Self {
        Self {
            scheme,
            authority,
            service,
        }
    }

    /// Create a new `ProxyUriLayer` with the given scheme
    pub fn layer(
        scheme: http::uri::Scheme,
        authority: Option<http::uri::Authority>,
    ) -> ProxyUriLayer {
        ProxyUriLayer::new(scheme, authority)
    }

    /// The default scheme used by this service.
    pub fn scheme(&self) -> &http::uri::Scheme {
        &self.scheme
    }

    /// The default authority used by this service.
    pub fn authority(&self) -> Option<&http::uri::Authority> {
        self.authority.as_ref()
    }

    /// Unwrap the inner service
    pub fn into_inner(self) -> S {
        self.service
    }

    fn apply<B>(&self, req: &mut http::Request<B>) {
        let mut uri = req.uri().clone().into_parts();
        let authority = req
            .extensions()
            .get()
            .or(self.authority.as_ref())
            .or(uri.authority.as_ref());

        uri.authority = authority.cloned();
        uri.scheme = Some(self.scheme.clone());

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
        self.apply(&mut req);

        self.service.call(req)
    }

    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.service.poll_ready(cx)
    }
}

impl<S, C, B> tower::Service<(C, http::Request<B>)> for ProxyUriService<S>
where
    S: tower::Service<(C, http::Request<B>)>,
    C: Connection<B> + PoolableConnection<B>,
    B: Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = S::Future;

    fn call(&mut self, mut req: (C, http::Request<B>)) -> Self::Future {
        self.apply(&mut req.1);

        self.service.call(req)
    }

    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.service.poll_ready(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_apply_with_scheme() {
        let mut req = http::Request::builder()
            .method(http::Method::GET)
            .uri("https://example.com")
            .body(())
            .unwrap();
        let uri_service = ProxyUriService::new(http::uri::Scheme::HTTP, None, ());
        uri_service.apply(&mut req);
        assert_eq!(req.uri().scheme(), Some(&http::uri::Scheme::HTTP));
        assert_eq!(
            req.uri().authority(),
            Some(&http::uri::Authority::from_static("example.com"))
        );
    }

    #[test]
    fn test_apply_with_scheme_and_authority() {
        let mut req = http::Request::builder()
            .method(http::Method::GET)
            .uri("https://example.com")
            .body(())
            .unwrap();
        let uri_service = ProxyUriService::new(
            http::uri::Scheme::HTTP,
            Some(http::uri::Authority::from_static("proxy.example.com")),
            (),
        );
        uri_service.apply(&mut req);
        assert_eq!(req.uri().scheme(), Some(&http::uri::Scheme::HTTP));
        assert_eq!(
            req.uri().authority(),
            Some(&http::uri::Authority::from_static("proxy.example.com"))
        );
    }

    #[test]
    fn test_apply_with_extension_authority() {
        let mut req = http::Request::builder()
            .method(http::Method::GET)
            .uri("https://example.com")
            .body(())
            .unwrap();
        req.extensions_mut()
            .insert(http::uri::Authority::from_static("elsewhere.example.com"));
        let uri_service = ProxyUriService::new(
            http::uri::Scheme::HTTP,
            Some(http::uri::Authority::from_static("proxy.example.com")),
            (),
        );
        uri_service.apply(&mut req);
        assert_eq!(req.uri().scheme(), Some(&http::uri::Scheme::HTTP));
        assert_eq!(
            req.uri().authority(),
            Some(&http::uri::Authority::from_static("elsewhere.example.com"))
        );
    }
}
