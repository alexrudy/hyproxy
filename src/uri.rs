//! Layer to set the scheme and authority of the request URI when
//! passing through a proxy.
//!
//! Servers usually receive HTTP/1.1 requests in origin-form (`GET /path`), with the
//! authority in the `Host` header rather than the URI. A client sending the request on to
//! the upstream needs an absolute URI. [`ProxyUriService`] rewrites the request URI to use
//! the configured scheme and an authority, keeping the path and query.
//!
//! The authority is taken from the first of:
//!
//! 1. An [`http::uri::Authority`] in the request extensions.
//! 2. The authority configured on the layer.
//! 3. The request URI's authority.
//! 4. The `Host` header.
//!
//! If no authority is found, or the request has no path (for example, a `CONNECT` request
//! in authority-form), the URI is left unchanged.

/// A layer that sets the scheme of the request URI, and optionally overrides its authority.
///
/// The scheme always replaces any scheme in the request URI. See the
/// [module documentation](self) for how the authority is chosen.
///
/// Defaults to `http`, with no authority override, via the `Default` implementation.
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

/// A service that sets the scheme and authority of the request URI.
///
/// See the [module documentation](self) for details.
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

    /// Returns a reference to the inner service.
    pub fn inner(&self) -> &S {
        &self.service
    }

    /// Returns the inner service, consuming this middleware.
    pub fn into_inner(self) -> S {
        self.service
    }

    fn apply<B>(&self, req: &mut http::Request<B>) {
        let Some(authority) = self.authority_for(req) else {
            tracing::debug!(uri = %req.uri(), "no authority for request, leaving URI unchanged");
            return;
        };

        let mut parts = req.uri().clone().into_parts();
        if parts.path_and_query.is_none() {
            // Authority-form (e.g. `CONNECT example.com:443`) has no path, and cannot have a scheme.
            tracing::debug!(uri = %req.uri(), "no path for request, leaving URI unchanged");
            return;
        }

        parts.scheme = Some(self.scheme.clone());
        parts.authority = Some(authority);

        match http::Uri::from_parts(parts) {
            Ok(uri) => *req.uri_mut() = uri,
            Err(error) => {
                tracing::debug!(uri = %req.uri(), %error, "unable to set scheme and authority");
            }
        }
    }

    fn authority_for<B>(&self, req: &http::Request<B>) -> Option<http::uri::Authority> {
        req.extensions()
            .get::<http::uri::Authority>()
            .or(self.authority.as_ref())
            .or(req.uri().authority())
            .cloned()
            .or_else(|| {
                let host = req.headers().get(http::header::HOST)?.as_bytes();
                // `Host` is `uri-host [ ":" port ]`, which does not permit userinfo.
                if host.contains(&b'@') {
                    return None;
                }
                http::uri::Authority::try_from(host).ok()
            })
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
    fn test_apply_origin_form_uses_host_header() {
        let mut req = http::Request::get("/path?query=1")
            .header(http::header::HOST, "example.com:8080")
            .body(())
            .unwrap();
        let uri_service = ProxyUriService::new(http::uri::Scheme::HTTPS, None, ());
        uri_service.apply(&mut req);
        assert_eq!(req.uri(), "https://example.com:8080/path?query=1");
    }

    #[test]
    fn test_apply_configured_authority_overrides_host_header() {
        let mut req = http::Request::get("/path")
            .header(http::header::HOST, "example.com")
            .body(())
            .unwrap();
        let uri_service = ProxyUriService::new(
            http::uri::Scheme::HTTP,
            Some(http::uri::Authority::from_static("upstream.internal")),
            (),
        );
        uri_service.apply(&mut req);
        assert_eq!(req.uri(), "http://upstream.internal/path");
    }

    #[test]
    fn test_apply_without_authority_leaves_uri_unchanged() {
        for host in [None, Some("user@example.com"), Some("not a host")] {
            let mut req = http::Request::get("/path").body(()).unwrap();
            if let Some(host) = host {
                req.headers_mut()
                    .insert(http::header::HOST, host.parse().unwrap());
            }
            let uri_service = ProxyUriService::new(http::uri::Scheme::HTTP, None, ());
            uri_service.apply(&mut req);
            assert_eq!(req.uri(), "/path", "{host:?}");
        }
    }

    #[test]
    fn test_apply_authority_form_leaves_uri_unchanged() {
        let mut req = http::Request::builder()
            .method(http::Method::CONNECT)
            .uri("example.com:443")
            .body(())
            .unwrap();
        let uri_service = ProxyUriService::new(
            http::uri::Scheme::HTTP,
            Some(http::uri::Authority::from_static("proxy.example.com")),
            (),
        );
        uri_service.apply(&mut req);
        assert_eq!(req.uri(), "example.com:443");
    }

    #[tokio::test]
    async fn test_service_default_layer_origin_form() {
        use tower::{Layer as _, ServiceExt as _};

        // Previously panicked with `AuthorityMissing`.
        let service =
            ProxyUriLayer::default().layer(tower::service_fn(
                |req: http::Request<()>| async move {
                    Ok::<_, std::convert::Infallible>(req.uri().clone())
                },
            ));
        let req = http::Request::get("/path")
            .header(http::header::HOST, "example.com")
            .body(())
            .unwrap();
        assert_eq!(
            service.oneshot(req).await.unwrap(),
            "http://example.com/path"
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
