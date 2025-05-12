//! # Bail out from processing, returning a response early
//!
//! Sometimes, instead of returning an error (see `hyperdriver::service::)

use std::fmt;

use self::future::BailFuture;

/// Extends services to use the BailService directly from a method.
pub trait ServiceBailExt {
    /// Provide a pre-processor which returns either `Ok(req)`
    /// with a moditied request, or `Err(res)` with the desired
    /// immediate response. This pre-processor is synchronous.
    fn bail<F>(self, preprocessor: F) -> BailService<Self, F>
    where
        Self: Sized;
}

impl<S> ServiceBailExt for S {
    fn bail<F>(self, preprocessor: F) -> BailService<S, F> {
        BailService {
            inner: self,
            preprocessor,
        }
    }
}

/// Bail out of processing a request, returning a response immediately.
#[derive(Clone)]
pub struct BailService<S, F> {
    inner: S,
    preprocessor: F,
}

impl<S: fmt::Debug, F> fmt::Debug for BailService<S, F> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BailService")
            .field("inner", &self.inner)
            .finish()
    }
}

impl<S, F> BailService<S, F> {
    /// Helper Service for middleware that might error.
    pub fn new(inner: S, preprocessor: F) -> Self {
        Self {
            inner,
            preprocessor,
        }
    }

    /// Get a reference to the inner service.
    pub fn service(&self) -> &S {
        &self.inner
    }
}

impl<S, F, R> tower::Service<R> for BailService<S, F>
where
    S: tower::Service<R>,
    F: Fn(R) -> Result<R, S::Response>,
{
    type Response = S::Response;

    type Error = S::Error;

    type Future = BailFuture<S::Future, S::Response, S::Error>;

    #[inline]
    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    #[inline]
    fn call(&mut self, req: R) -> Self::Future {
        match (self.preprocessor)(req) {
            Ok(req) => BailFuture::future(self.inner.call(req)),
            Err(error) => BailFuture::bail(error),
        }
    }
}

/// A layer that wraps a service with a preprocessor function.
#[derive(Clone)]
pub struct BailLayer<F> {
    preprocessor: F,
}

impl<F> BailLayer<F> {
    /// Create a new `BailLayer` wrapping the given preprocessor function.
    pub fn new(preprocessor: F) -> Self {
        Self { preprocessor }
    }
}

impl<F> fmt::Debug for BailLayer<F> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BailLayer").finish()
    }
}

impl<S, F: Clone> tower::layer::Layer<S> for BailLayer<F> {
    type Service = BailService<S, F>;

    fn layer(&self, inner: S) -> Self::Service {
        BailService::new(inner, self.preprocessor.clone())
    }
}

mod future {

    use std::{fmt, future::Future, marker::PhantomData, task::Poll};

    pin_project_lite::pin_project! {
        #[project = BailFutureStateProj]
        enum BailFutureState<F, R> {
            Inner {
                #[pin]
                future: F
            },
            Bail {
                response: Option<R>
            },
        }
    }

    impl<F, R: fmt::Debug> fmt::Debug for BailFutureState<F, R> {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                Self::Inner { .. } => f.debug_tuple("Inner").finish(),
                Self::Bail { response } => f.debug_tuple("Bail").field(response).finish(),
            }
        }
    }

    pin_project_lite::pin_project! {

        /// Future for when a service either errors before yielding,
        /// or continues. This is us
        #[derive(Debug)]
        pub struct BailFuture<F, R, E> {
            #[pin]
            state: BailFutureState<F, R>,
            error: PhantomData<fn() -> E>,
        }
    }

    impl<F, R, E> BailFuture<F, R, E> {
        /// Create a future that resolves to the contained service
        pub fn future(inner: F) -> Self {
            Self {
                state: BailFutureState::Inner { future: inner },
                error: PhantomData,
            }
        }

        /// Create a future that immediately resolves to an error.
        pub fn bail(response: R) -> Self {
            Self {
                state: BailFutureState::Bail {
                    response: Some(response),
                },
                error: PhantomData,
            }
        }
    }

    impl<F, R, E> Future for BailFuture<F, R, E>
    where
        F: Future<Output = Result<R, E>>,
    {
        type Output = Result<R, E>;

        fn poll(
            self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> Poll<Self::Output> {
            let mut this = self.project();

            match this.state.as_mut().project() {
                BailFutureStateProj::Inner { future } => future.poll(cx),
                BailFutureStateProj::Bail { response } => {
                    Poll::Ready(Ok(response.take().expect("polled after response")))
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::convert::Infallible;
    use std::future::Future;
    use std::pin::Pin;
    use std::task::{Context, Poll, Waker};
    use tower::layer::Layer;
    use tower::Service;

    // Poll a function once with a no-op waker.
    fn poll_once<F, R>(func: F) -> Poll<R>
    where
        F: FnOnce(&mut Context) -> Poll<R>,
    {
        func(&mut Context::from_waker(Waker::noop()))
    }

    // A test request type
    #[derive(Debug, Clone, PartialEq)]
    struct TestRequest {
        value: u32,
    }

    // A test response type
    #[derive(Debug, Clone, PartialEq)]
    struct TestResponse {
        value: u32,
    }

    // Mock service for testing
    #[derive(Debug, Clone)]
    struct MockService {
        // Controls how poll_ready responds
        ready: bool,
        // Controls what the service returns
        response_value: u32,
    }

    impl MockService {
        fn new(ready: bool, response_value: u32) -> Self {
            Self {
                ready,
                response_value,
            }
        }
    }

    impl Service<TestRequest> for MockService {
        type Response = TestResponse;
        type Error = Infallible;
        type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

        fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            if self.ready {
                Poll::Ready(Ok(()))
            } else {
                Poll::Pending
            }
        }

        fn call(&mut self, req: TestRequest) -> Self::Future {
            let response = TestResponse {
                value: req.value + self.response_value,
            };
            Box::pin(async move { Ok(response) })
        }
    }

    #[tokio::test]
    async fn test_bailout_service_creation() {
        let inner_service = MockService::new(true, 5);
        let preprocessor = |req: TestRequest| Ok::<_, Infallible>(req);

        let bailout_service = BailService::new(inner_service, preprocessor);
        assert!(std::matches!(bailout_service.service(), MockService { .. }));
    }

    #[tokio::test]
    async fn test_bailout_service_pass_through() {
        let inner_service = MockService::new(true, 5);
        let preprocessor = |req: TestRequest| Ok(req);

        let mut bailout_service = BailService::new(inner_service, preprocessor);

        // Test poll_ready
        let poll_result = poll_once(|cx| bailout_service.poll_ready(cx));
        assert_eq!(poll_result, Poll::Ready(Ok(())));

        // Test call with pass-through
        let request = TestRequest { value: 10 };
        let response_future = bailout_service.call(request);

        let response = response_future.await.unwrap();
        assert_eq!(response, TestResponse { value: 15 }); // 10 + 5
    }

    #[tokio::test]
    async fn test_bailout_service_bail_out() {
        let inner_service = MockService::new(true, 5);
        let bailout_response = TestResponse { value: 42 };
        let preprocessor = move |_req: TestRequest| -> Result<TestRequest, TestResponse> {
            Err(bailout_response.clone())
        };

        let mut bailout_service = BailService::new(inner_service, preprocessor);

        // Service should be ready since we'll bail out anyway
        let poll_result = poll_once(|cx| bailout_service.poll_ready(cx));
        assert_eq!(poll_result, Poll::Ready(Ok(())));

        // Test call with bailout
        let request = TestRequest { value: 10 };
        let response_future = bailout_service.call(request);

        let response = response_future.await.unwrap();
        // Should get our bailout response, not the result of inner service
        assert_eq!(response, TestResponse { value: 42 });
    }

    #[tokio::test]
    async fn test_bailout_layer() {
        let inner_service = MockService::new(true, 5);
        let preprocessor = |req: TestRequest| Ok(req);

        // Create a layer and apply it
        let layer = BailLayer::new(preprocessor);
        let mut service = layer.layer(inner_service);

        // Test the service works
        let request = TestRequest { value: 10 };
        let response_future = service.call(request);

        let response = response_future.await.unwrap();
        assert_eq!(response, TestResponse { value: 15 }); // 10 + 5
    }

    #[test]
    fn test_debug_impl() {
        let inner_service = MockService::new(true, 5);
        let preprocessor = |req: TestRequest| Ok::<_, Infallible>(req);

        let bailout_service = BailService::new(inner_service, preprocessor);

        let debug_output = format!("{:?}", bailout_service);
        assert!(debug_output.contains("BailService"));

        let layer = BailLayer::new(preprocessor);
        let debug_layer = format!("{:?}", layer);
        assert!(debug_layer.contains("BailLayer"));
    }

    #[tokio::test]
    async fn test_bailout_future() {
        use super::future::BailFuture;

        // Test the future case
        let inner_future = async { Ok::<_, Infallible>(TestResponse { value: 123 }) };
        let bailout_future = BailFuture::<_, _, Infallible>::future(inner_future);
        let result = bailout_future.await.unwrap();
        assert_eq!(result, TestResponse { value: 123 });

        // Test the bail case
        let response = TestResponse { value: 456 };
        let bailout_future = BailFuture::<
            Pin<Box<dyn Future<Output = Result<TestResponse, Infallible>>>>,
            _,
            Infallible,
        >::bail(response);
        let result = bailout_future.await.unwrap();
        assert_eq!(result, TestResponse { value: 456 });
    }

    #[test]
    fn test_service_not_ready() {
        let inner_service = MockService::new(false, 5); // Not ready
        let preprocessor = |req: TestRequest| Ok(req);

        let mut bailout_service = BailService::new(inner_service, preprocessor);

        // Test poll_ready should be pending
        let poll_result =
            bailout_service.poll_ready(&mut Context::from_waker(std::task::Waker::noop()));

        assert!(matches!(poll_result, Poll::Pending));
    }

    #[tokio::test]
    async fn test_complex_preprocessor() {
        let inner_service = MockService::new(true, 5);

        // A preprocessor that conditionally bails or modifies the request
        let preprocessor = |req: TestRequest| -> Result<TestRequest, TestResponse> {
            if req.value > 100 {
                // Bail out with custom response
                Err(TestResponse { value: 999 })
            } else if req.value > 50 {
                // Modify the request
                Ok(TestRequest { value: 42 })
            } else {
                // Pass through unchanged
                Ok(req)
            }
        };

        let mut bailout_service = BailService::new(inner_service, preprocessor);

        // Test case 1: value <= 50, should pass through unchanged
        let request = TestRequest { value: 30 };
        let response = bailout_service.call(request).await.unwrap();
        assert_eq!(response, TestResponse { value: 35 }); // 30 + 5

        // Test case 2: 50 < value <= 100, should modify request
        let request = TestRequest { value: 60 };
        let response = bailout_service.call(request).await.unwrap();
        assert_eq!(response, TestResponse { value: 47 }); // 42 + 5

        // Test case 3: value > 100, should bail out
        let request = TestRequest { value: 150 };
        let response = bailout_service.call(request).await.unwrap();
        assert_eq!(response, TestResponse { value: 999 }); // Bailout response
    }
}
