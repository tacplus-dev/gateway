use std::sync::Arc;

use axum::body::Body;
use axum::response::{IntoResponse, Response};
use http::{Request, StatusCode};
use tower::Service;

use crate::auth::GatewayAuth;
use crate::resolver::Resolver;

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
/// Determines the target service from the gRPC method path, authenticates
/// via metadata headers, and forwards the raw HTTP/2 frames through a
/// tonic Channel without deserializing the protobuf body.
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

    // Gateway's own services (MintService) are handled by tonic routes, not the proxy.
    if service_id == "gateway" {
        return StatusCode::NOT_FOUND.into_response();
    }

    // Auth: validate using gRPC metadata (HTTP/2 headers).
    let metadata = tonic::metadata::MetadataMap::from_headers(req.headers().clone());
    if let Err(status) = proxy.auth.validate(&path, &metadata) {
        return tonic_status_to_response(status);
    }

    // Convert axum Body to tonic Body for Channel compatibility.
    let (parts, body) = req.into_parts();
    let tonic_body = tonic::body::Body::new(body);
    let tonic_req = Request::from_parts(parts, tonic_body);

    // Forward raw HTTP/2 request through the Channel.
    let mut channel = proxy.resolver.dial(service_id);
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
