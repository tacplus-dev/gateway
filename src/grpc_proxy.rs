use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use axum::body::Body;
use axum::response::{IntoResponse, Response};
use http::{Request, StatusCode};
use http_body::Frame;
use tower::{Service, ServiceExt};

use crate::auth::GatewayAuth;
use crate::resolver::Resolver;

/// Body wrapper that overrides `is_end_stream()` to always return `false`.
/// This prevents `tonic::body::Body::new()` from short-circuiting to an empty
/// body when the underlying HTTP/2 stream has received all data + END_STREAM
/// but the data hasn't been polled/consumed yet.
struct StreamingBody(Body);

impl http_body::Body for StreamingBody {
    type Data = bytes::Bytes;
    type Error = axum::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        // Safety: Body is Unpin (axum::body::Body is Unpin).
        let inner = Pin::new(&mut self.get_mut().0);
        inner.poll_frame(cx)
    }

    fn is_end_stream(&self) -> bool {
        false // Never short-circuit — always let poll_frame determine EOF.
    }

    fn size_hint(&self) -> http_body::SizeHint {
        self.0.size_hint()
    }
}

/// Extract the proto package name (service_id) from a gRPC method path.
/// "/herald.HeraldService/PublishEvents" -> "herald"
fn extract_service_id(path: &str) -> Option<&str> {
    path.trim_start_matches('/')
        .split('.')
        .next()
        .filter(|s| !s.is_empty())
}

/// Proxy state shared across gRPC proxy handlers.
pub struct ProxyState {
    pub resolver: Arc<Resolver>,
    pub auth: Arc<GatewayAuth>,
}

/// Handle a gRPC request by forwarding raw bytes to the backend service.
/// Determines the target service from the gRPC method path, enforces
/// per-route C2S auth using the ROUTES table, and forwards the raw HTTP/2
/// frames through a tonic Channel without deserializing the protobuf body.
pub async fn handle(
    proxy: &ProxyState,
    req: Request<Body>,
) -> Response {
    let path = req.uri().path().to_string();

    let service_id = match extract_service_id(&path) {
        Some(id) => id,
        None => {
            return (
                StatusCode::NOT_FOUND,
                "unknown gRPC service",
            )
                .into_response();
        }
    };

    // Gateway's own services (Mint) are handled by tonic routes, not the proxy.
    if service_id == "gateway" {
        return StatusCode::NOT_FOUND.into_response();
    }

    // Look up per-route auth policy from the generated ROUTES table.
    // Default to Entitled (most restrictive) for routes not in the table.
    let auth_policy = gateway_tacplus::s2sm::rest_dispatch::ROUTES
        .iter()
        .find(|r| r.grpc_path == path)
        .map(|r| r.auth_policy)
        .unwrap_or(gateway_tacplus::s2sm::rest_dispatch::AuthPolicy::Entitled);

    let auth_header = req
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok());

    if let Err((code, msg)) = proxy
        .auth
        .validate_c2s(auth_policy, service_id, &path, auth_header)
        .await
    {
        tracing::warn!(path = %path, error = %msg, "gRPC auth rejected");
        // Map HTTP status to gRPC status code.
        let grpc_code = match code {
            StatusCode::FORBIDDEN => tonic::Code::PermissionDenied,
            _ => tonic::Code::Unauthenticated,
        };
        return tonic_status_to_response(tonic::Status::new(grpc_code, msg));
    }

    // Convert axum Body to tonic Body for Channel compatibility.
    // Wrap in StreamingBody to prevent tonic::body::Body::new() from
    // short-circuiting on is_end_stream() for bodies that have received
    // all data but haven't been polled yet (client-streaming gRPC).
    let (parts, body) = req.into_parts();
    let streaming_body = StreamingBody(body);
    let tonic_body = tonic::body::Body::new(streaming_body);
    let tonic_req = Request::from_parts(parts, tonic_body);

    // Forward raw HTTP/2 request through the Channel.
    // Must call ready() before call() — tower's buffer layer panics otherwise.
    let mut channel = proxy.resolver.dial(service_id);
    if let Err(e) = channel.ready().await {
        tracing::error!(error = %e, service = service_id, path = %path, "gRPC proxy channel not ready");
        return tonic_status_to_response(tonic::Status::unavailable(format!(
            "backend not ready: {}",
            e
        )));
    }
    match channel.call(tonic_req).await {
        Ok(response) => {
            let (parts, body) = response.into_parts();
            Response::from_parts(parts, Body::new(body))
        }
        Err(e) => {
            tracing::error!(error = %e, service = service_id, path = %path, "gRPC proxy error");
            tonic_status_to_response(tonic::Status::unavailable(format!(
                "backend unavailable: {}",
                e
            )))
        }
    }
}

/// Convert a tonic Status to an HTTP response with gRPC trailers.
fn tonic_status_to_response(status: tonic::Status) -> Response {
    let grpc_status = status.code() as i32;
    let message = status.message().to_string();

    let http_status = match status.code() {
        tonic::Code::Unauthenticated => StatusCode::UNAUTHORIZED,
        tonic::Code::PermissionDenied => StatusCode::FORBIDDEN,
        tonic::Code::NotFound => StatusCode::NOT_FOUND,
        _ => StatusCode::OK, // gRPC errors use HTTP 200 with grpc-status trailer
    };

    Response::builder()
        .status(http_status)
        .header("content-type", "application/grpc")
        .header("grpc-status", grpc_status.to_string())
        .header("grpc-message", message)
        .body(Body::empty())
        .unwrap()
}

/// Returns true if the request has a gRPC content-type.
pub fn is_grpc(req: &Request<Body>) -> bool {
    req.headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .map(|ct| ct.starts_with("application/grpc"))
        .unwrap_or(false)
}
