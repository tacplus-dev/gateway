//! Edge request limits for the gateway router.
//!
//! Before this existed the router accepted an unbounded number of concurrent
//! requests, at an unbounded rate, with an unbounded request body. All three
//! are reachable by an unauthenticated caller, so all three are capped here,
//! at the outermost layer of the stack.

use std::time::Duration;

use axum::error_handling::HandleErrorLayer;
use axum::http::{Request, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Router;
use tower::util::BoxCloneService;
use tower::{BoxError, ServiceBuilder};
use tower_http::body::Limited;
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::map_request_body::MapRequestBodyLayer;

/// Concurrent in-flight requests admitted by the router. Beyond this, requests
/// are shed with 503 rather than queued, so an overload sheds load instead of
/// growing an unbounded queue of tasks.
const DEFAULT_MAX_CONCURRENT_REQUESTS: usize = 1024;

/// Requests per second admitted by the router.
const DEFAULT_MAX_REQUESTS_PER_SECOND: u64 = 2000;

/// Requests waiting on the rate limiter before the limiter itself stops being
/// ready and the concurrency/load-shed layer above it starts shedding.
const DEFAULT_RATE_LIMIT_QUEUE: usize = 1024;

/// Largest REST request body the gateway will read. Matches the 10MB gRPC
/// message ceiling the proxy already enforces per message.
const DEFAULT_MAX_REQUEST_BODY_BYTES: usize = 10 * 1024 * 1024;

#[derive(Debug, Clone, Copy)]
pub struct EdgeLimits {
    pub max_concurrent_requests: usize,
    pub max_requests_per_second: u64,
    pub rate_limit_queue: usize,
    pub max_request_body_bytes: usize,
}

impl Default for EdgeLimits {
    fn default() -> Self {
        Self {
            max_concurrent_requests: DEFAULT_MAX_CONCURRENT_REQUESTS,
            max_requests_per_second: DEFAULT_MAX_REQUESTS_PER_SECOND,
            rate_limit_queue: DEFAULT_RATE_LIMIT_QUEUE,
            max_request_body_bytes: DEFAULT_MAX_REQUEST_BODY_BYTES,
        }
    }
}

impl EdgeLimits {
    /// Defaults, with each limit overridable by env var. The limits are a
    /// blunt instrument on a shared edge: an operator who has to raise or
    /// lower one during an incident needs to do it without a rebuild.
    pub fn from_env() -> Self {
        let d = Self::default();
        Self {
            max_concurrent_requests: env_usize(
                "GATEWAY_MAX_CONCURRENT_REQUESTS",
                d.max_concurrent_requests,
            ),
            max_requests_per_second: env_usize(
                "GATEWAY_MAX_REQUESTS_PER_SECOND",
                d.max_requests_per_second as usize,
            ) as u64,
            rate_limit_queue: env_usize("GATEWAY_RATE_LIMIT_QUEUE", d.rate_limit_queue),
            max_request_body_bytes: env_usize(
                "GATEWAY_MAX_REQUEST_BODY_BYTES",
                d.max_request_body_bytes,
            ),
        }
    }
}

fn env_usize(name: &str, default: usize) -> usize {
    match std::env::var(name) {
        Ok(v) => match v.parse::<usize>() {
            Ok(n) if n > 0 => n,
            _ => {
                tracing::warn!(var = name, value = %v, default, "ignoring unparsable limit override");
                default
            }
        },
        Err(_) => default,
    }
}

/// The router with the edge limits wrapped around it, ready to be served.
pub type EdgeService<B> = BoxCloneService<Request<B>, Response, std::convert::Infallible>;

/// Rate + concurrency limiting for the whole router, including the raw gRPC
/// proxy path.
///
/// `load_shed` sits above `concurrency_limit` so an over-limit request is
/// answered 503 immediately instead of waiting for a permit. The rate limiter
/// is `!Clone` and therefore has to sit behind a `Buffer`, which is also what
/// gives it one shared quota across every cloned copy of the service.
///
/// The limits wrap the router from OUTSIDE rather than going through
/// `Router::layer`. `Router::layer` applies the layer once per route — which
/// would make each limit per-route rather than per-gateway — and for a route
/// that is still a bare handler it re-runs the layer on every request, which
/// would hand each request its own semaphore and its own rate quota. Neither
/// is a limit.
pub fn with_edge_limits<B>(router: Router, limits: &EdgeLimits) -> EdgeService<B>
where
    B: http_body::Body<Data = bytes::Bytes> + Send + 'static,
    B::Error: Into<BoxError>,
{
    BoxCloneService::new(
        ServiceBuilder::new()
            .layer(HandleErrorLayer::new(handle_edge_error))
            .load_shed()
            .concurrency_limit(limits.max_concurrent_requests)
            .buffer(limits.rate_limit_queue)
            .rate_limit(limits.max_requests_per_second, Duration::from_secs(1))
            .service(router.into_service::<B>()),
    )
}

/// Cap the request body size.
///
/// Applied to the REST/SPA half of the stack only: gRPC client-streaming
/// bodies are long-lived and legitimately exceed any single-message ceiling,
/// and they are already bounded per message inside `proxy_grpc`.
///
/// `MapRequestBodyLayer` converts the `Limited<Body>` back to `axum::body::Body`
/// because a `Router` is only a `Service<Request<Body>>`.
pub fn with_request_body_limit(router: Router, max_bytes: usize) -> Router {
    router.layer(
        ServiceBuilder::new()
            .layer(RequestBodyLimitLayer::new(max_bytes))
            .layer(MapRequestBodyLayer::new(
                axum::body::Body::new::<Limited<axum::body::Body>>,
            )),
    )
}

fn handle_edge_error(err: BoxError) -> std::future::Ready<Response> {
    let response = if err.is::<tower::load_shed::error::Overloaded>() {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            "{\"error\":\"gateway overloaded\"}",
        )
            .into_response()
    } else {
        tracing::error!(error = %err, "edge limit layer error");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "{\"error\":\"internal error\"}",
        )
            .into_response()
    };
    std::future::ready(response)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::routing::{get, post};
    use std::time::Instant;
    use tower::ServiceExt;

    fn test_limits() -> EdgeLimits {
        EdgeLimits {
            max_concurrent_requests: 1024,
            max_requests_per_second: 10_000,
            rate_limit_queue: 1024,
            max_request_body_bytes: 1024,
        }
    }

    fn get_request(path: &str) -> axum::http::Request<axum::body::Body> {
        axum::http::Request::builder()
            .uri(path)
            .body(axum::body::Body::empty())
            .unwrap()
    }

    /// N in flight is served, N+1 is shed with 503 rather than queued.
    #[tokio::test]
    async fn concurrency_limit_sheds_the_request_over_the_limit() {
        let service: EdgeService<axum::body::Body> = with_edge_limits(
            Router::new().route(
                "/slow",
                get(|| async {
                    tokio::time::sleep(Duration::from_millis(300)).await;
                    "ok"
                }),
            ),
            &EdgeLimits {
                max_concurrent_requests: 1,
                ..test_limits()
            },
        );

        let first = tokio::spawn({
            let service = service.clone();
            async move { service.oneshot(get_request("/slow")).await.unwrap() }
        });
        // Let the first request take the only permit.
        tokio::time::sleep(Duration::from_millis(50)).await;

        let second = service.clone().oneshot(get_request("/slow")).await.unwrap();
        assert_eq!(
            second.status(),
            StatusCode::SERVICE_UNAVAILABLE,
            "the request over the concurrency limit must be shed"
        );

        assert_eq!(
            first.await.unwrap().status(),
            StatusCode::OK,
            "the in-flight request must still be served"
        );
    }

    /// The rate limiter actually paces requests: six requests at 2/s cannot
    /// all complete inside the first window.
    #[tokio::test]
    async fn rate_limit_paces_requests() {
        let service: EdgeService<axum::body::Body> = with_edge_limits(
            Router::new().route("/fast", get(|| async { "ok" })),
            &EdgeLimits {
                max_requests_per_second: 2,
                ..test_limits()
            },
        );

        let start = Instant::now();
        for _ in 0..6 {
            let response = service.clone().oneshot(get_request("/fast")).await.unwrap();
            assert_eq!(response.status(), StatusCode::OK);
        }
        let elapsed = start.elapsed();

        assert!(
            elapsed >= Duration::from_millis(1500),
            "6 requests at 2/s must take at least two window resets, took {elapsed:?}"
        );
    }

    /// A body over the cap is rejected; one under it is served.
    #[tokio::test]
    async fn request_body_limit_rejects_oversized_bodies() {
        let router = with_request_body_limit(
            Router::new().route(
                "/echo",
                post(|body: bytes::Bytes| async move { body.len().to_string() }),
            ),
            16,
        );

        let request = |len: usize| {
            axum::http::Request::builder()
                .method("POST")
                .uri("/echo")
                .header("content-length", len.to_string())
                .body(axum::body::Body::from(vec![b'x'; len]))
                .unwrap()
        };

        let ok = router.clone().oneshot(request(8)).await.unwrap();
        assert_eq!(ok.status(), StatusCode::OK, "a body under the cap is served");

        let too_big = router.clone().oneshot(request(64)).await.unwrap();
        assert_eq!(
            too_big.status(),
            StatusCode::PAYLOAD_TOO_LARGE,
            "a body over the cap is rejected"
        );
    }
}
