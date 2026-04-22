use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use axum::body::Body;
use axum::response::Response;
use http::{Request, StatusCode};
use http_body::Frame;
use tower::{Service, ServiceExt};

use crate::auth::GatewayAuth;
use crate::resolver::Resolver;

use gateway_tacplus::types::libs::trace::{TraceEvent, TraceRound};

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
        let inner = Pin::new(&mut self.get_mut().0);
        inner.poll_frame(cx)
    }

    fn is_end_stream(&self) -> bool {
        false
    }

    fn size_hint(&self) -> http_body::SizeHint {
        self.0.size_hint()
    }
}

/// Extract the proto package name (service_id) from a gRPC method path.
/// "/eventbus.Trace/WatchTrace" -> "eventbus"
fn extract_service_id(path: &str) -> Option<&str> {
    path.trim_start_matches('/')
        .split('.')
        .next()
        .filter(|s| !s.is_empty())
}

/// Minimal prost message to extract trace_id (field 200) from any protobuf
/// message without full deserialization. prost skips unknown fields,
/// so this works on any message type that has trace_id at field 200.
#[derive(prost::Message)]
struct TraceProbe {
    #[prost(string, tag = "200")]
    trace_id: String,
}

/// Proxy state shared across gRPC proxy handlers.
pub struct ProxyState {
    pub resolver: Arc<Resolver>,
    pub auth: Arc<GatewayAuth>,
    pub trace_publisher: Arc<dyn Fn(TraceEvent) + Send + Sync>,
    pub trace_round: Box<dyn Fn() -> TraceRound + Send + Sync>,
}

/// Frame proto bytes as a gRPC message: [0u8 (no compression), 4-byte BE length, payload].
pub fn frame_grpc(proto_bytes: &[u8]) -> Vec<u8> {
    let len = proto_bytes.len() as u32;
    let mut buf = Vec::with_capacity(5 + proto_bytes.len());
    buf.push(0u8); // no compression
    buf.extend_from_slice(&len.to_be_bytes());
    buf.extend_from_slice(proto_bytes);
    buf
}

/// Extract proto payload from a gRPC frame. Returns the payload bytes after
/// the 5-byte header, or an error if the frame is malformed.
fn unframe_grpc(grpc_bytes: &[u8]) -> Result<&[u8], tonic::Status> {
    if grpc_bytes.len() < 5 {
        return Err(tonic::Status::internal("gRPC frame too short"));
    }
    let msg_len = u32::from_be_bytes([
        grpc_bytes[1], grpc_bytes[2], grpc_bytes[3], grpc_bytes[4],
    ]) as usize;
    let proto_end = (5 + msg_len).min(grpc_bytes.len());
    Ok(&grpc_bytes[5..proto_end])
}

/// Handle a gRPC request: extract frame, validate, authenticate, and forward.
///
/// Per-message processing (from ARCHITECTURE.md):
/// 1. Extract gRPC frame (5-byte header + protobuf payload)
/// 2. Deserialize and validate via proxy_dispatch::validate_request()
/// 3. Authenticate via GatewayAuth::validate_c2s()
/// 4. Extract trace_id (field 200) and publish TraceEvent if present
/// 5. Forward original bytes to backend service
pub async fn handle(
    proxy: &ProxyState,
    req: Request<Body>,
) -> Response {
    let path = req.uri().path().to_string();

    let service_id = match extract_service_id(&path) {
        Some(id) => id,
        None => {
            return tonic_status_to_response(tonic::Status::not_found("unknown gRPC service"));
        }
    };

    // Gateway's own services (Mint) are handled by tonic routes, not the proxy.
    if service_id == "gateway" {
        return tonic_status_to_response(tonic::Status::not_found("gateway service not proxied"));
    }

    // Look up route info from the generated ROUTES table.
    // Default to Entitled (most restrictive) for routes not in the table.
    let route_info = gateway_tacplus::s2sm::rest_dispatch::ROUTES
        .iter()
        .find(|r| r.grpc_path == path);
    let auth_policy = route_info
        .map(|r| r.auth_policy)
        .unwrap_or(gateway_tacplus::s2sm::rest_dispatch::AuthPolicy::Entitled);

    // Extract auth header before consuming the request.
    let auth_header = req
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    // Check if this is a streaming RPC.
    let is_streaming = route_info
        .map(|r| r.server_streaming)
        .unwrap_or(false);

    let (parts, body) = req.into_parts();

    // active_trace_id is set when a unary request carries a trace_id (field 200).
    // It's used to publish a response trace event after the backend call completes.
    let mut active_trace_id = String::new();

    let tonic_req = if is_streaming {
        // Streaming: validate auth on the initial request, then forward body directly.
        // Per-frame validation of subsequent messages is deferred (TODO).
        if let Err((code, msg)) = proxy
            .auth
            .validate_c2s(auth_policy, service_id, &path, auth_header.as_deref())
            .await
        {
            tracing::warn!(path = %path, error = %msg, "gRPC auth rejected");
            let grpc_code = match code {
                StatusCode::FORBIDDEN => tonic::Code::PermissionDenied,
                _ => tonic::Code::Unauthenticated,
            };
            return tonic_status_to_response(tonic::Status::new(grpc_code, msg));
        }

        let streaming_body = StreamingBody(body);
        let tonic_body = tonic::body::Body::new(streaming_body);
        Request::from_parts(parts, tonic_body)
    } else {
        // Unary: buffer body, extract frame, validate, auth, trace, then forward.
        let body_bytes = match axum::body::to_bytes(body, 10 * 1024 * 1024).await {
            Ok(b) => b,
            Err(e) => {
                return tonic_status_to_response(tonic::Status::internal(
                    format!("failed to read request body: {}", e),
                ));
            }
        };

        // Extract and validate the protobuf payload from the gRPC frame.
        if body_bytes.len() > 5 {
            match unframe_grpc(&body_bytes) {
                Ok(proto_bytes) => {
                    // Validate: deserialize into typed message and run validation.
                    if let Err(status) = gateway_tacplus::s2sm::proxy_dispatch::validate_request(&path, proto_bytes) {
                        tracing::warn!(path = %path, error = %status.message(), "request validation failed");
                        return tonic_status_to_response(status);
                    }

                    // Trace: extract trace_id from proto field 200.
                    match <TraceProbe as prost::Message>::decode(proto_bytes) {
                        Ok(probe) if !probe.trace_id.is_empty() => {
                            active_trace_id = probe.trace_id.clone();
                            let round = (proxy.trace_round)();
                            (proxy.trace_publisher)(TraceEvent {
                                trace_id: probe.trace_id.clone(),
                                round: Some(round),
                                message_type: path.clone(),
                                ..Default::default()
                            });
                        }
                        Ok(_) => {}
                        Err(e) => {
                            tracing::debug!(error = %e, grpc_path = %path, "TraceProbe decode skipped");
                        }
                    }
                }
                Err(status) => {
                    return tonic_status_to_response(status);
                }
            }
        }

        // Auth: validate after body extraction so we reject malformed messages first.
        if let Err((code, msg)) = proxy
            .auth
            .validate_c2s(auth_policy, service_id, &path, auth_header.as_deref())
            .await
        {
            tracing::warn!(path = %path, error = %msg, "gRPC auth rejected");
            let grpc_code = match code {
                StatusCode::FORBIDDEN => tonic::Code::PermissionDenied,
                _ => tonic::Code::Unauthenticated,
            };
            return tonic_status_to_response(tonic::Status::new(grpc_code, msg));
        }

        // Forward original buffered bytes (not re-serialized).
        let new_body = Body::from(body_bytes);
        let streaming_body = StreamingBody(new_body);
        let tonic_body = tonic::body::Body::new(streaming_body);
        Request::from_parts(parts, tonic_body)
    };

    // Forward to backend service.
    // Try service_id first, fall back to SPIFFE path routing.
    let mut channel = {
        let endpoints = proxy.resolver.health().get_endpoints(service_id);
        if endpoints.is_empty() {
            proxy.resolver.dial_spiffe(service_id)
        } else {
            proxy.resolver.dial(service_id)
        }
    };

    if let Err(e) = channel.ready().await {
        tracing::error!(error = %e, service = service_id, path = %path, "gRPC proxy channel not ready");
        return tonic_status_to_response(tonic::Status::unavailable(format!(
            "backend not ready: {}",
            e
        )));
    }
    match channel.call(tonic_req).await {
        Ok(response) => {
            // Publish response trace if the request was traced.
            if !active_trace_id.is_empty() {
                let round = (proxy.trace_round)();
                (proxy.trace_publisher)(TraceEvent {
                    trace_id: active_trace_id,
                    round: Some(round),
                    message_type: format!("{} response", path),
                    ..Default::default()
                });
            }
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

/// Convert a tonic Status to an HTTP response with gRPC status headers.
pub fn tonic_status_to_response(status: tonic::Status) -> Response {
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
