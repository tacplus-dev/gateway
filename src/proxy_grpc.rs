use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use axum::body::Body;
use axum::response::Response;
use http::{Request, StatusCode};
use http_body::Frame;
use http_body_util::BodyExt;
use tokio_stream::wrappers::ReceiverStream;
use tower::{Service, ServiceExt};

use crate::auth::GatewayAuth;
use crate::resolver::Resolver;

use gateway_model::types::sys::trace::{TraceEvent, TraceEventKind, TraceRound};

const MAX_GRPC_MESSAGE_BYTES: usize = 10 * 1024 * 1024;

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

pub(crate) fn route_identity(
    route_info: &gateway_model::s2sm::rest_dispatch::RouteInfo,
) -> (&str, &str) {
    let service_id = route_info.service_id;
    let entitlement_service = route_info.entitlement_service.unwrap_or(service_id);
    (service_id, entitlement_service)
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
        return Err(tonic::Status::invalid_argument("gRPC frame too short"));
    }
    if grpc_bytes[0] != 0 {
        return Err(tonic::Status::unimplemented(
            "compressed gRPC frames are not supported by gateway validation",
        ));
    }
    let msg_len =
        u32::from_be_bytes([grpc_bytes[1], grpc_bytes[2], grpc_bytes[3], grpc_bytes[4]]) as usize;
    if msg_len > MAX_GRPC_MESSAGE_BYTES {
        return Err(tonic::Status::resource_exhausted(
            "gRPC message exceeds gateway validation limit",
        ));
    }
    let proto_end = 5 + msg_len;
    if grpc_bytes.len() != proto_end {
        return Err(tonic::Status::invalid_argument(
            "gRPC frame length mismatch",
        ));
    }
    Ok(&grpc_bytes[5..proto_end])
}

fn status_code_to_tonic(code: StatusCode) -> tonic::Code {
    match code {
        StatusCode::FORBIDDEN => tonic::Code::PermissionDenied,
        StatusCode::BAD_REQUEST => tonic::Code::InvalidArgument,
        StatusCode::TOO_MANY_REQUESTS => tonic::Code::ResourceExhausted,
        StatusCode::SERVICE_UNAVAILABLE => tonic::Code::Unavailable,
        StatusCode::GATEWAY_TIMEOUT => tonic::Code::DeadlineExceeded,
        _ => tonic::Code::Unauthenticated,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StreamingValidation {
    RequestHeader,
    AlreadyValidated,
}

/// Wrap a streaming gRPC request body with per-frame validation and auth.
///
/// Each inbound gRPC data frame is decoded enough to extract one or more gRPC
/// message frames. Every message is validated through generated tacplus
/// constraints and authorized against the bearer token before the original frame
/// bytes are forwarded to the backend service.
fn validated_streaming_body(
    mut body: Body,
    proxy: &ProxyState,
    path: String,
    service_id: String,
    entitlement_service: String,
    auth_policy: gateway_model::s2sm::rest_dispatch::AuthPolicy,
    auth_header: Option<String>,
) -> Body {
    let auth = Arc::clone(&proxy.auth);
    let (tx, rx) = tokio::sync::mpsc::channel::<Result<bytes::Bytes, std::io::Error>>(16);

    tokio::spawn(async move {
        let mut buffer = bytes::BytesMut::new();

        while let Some(frame_result) = body.frame().await {
            let frame = match frame_result {
                Ok(frame) => frame,
                Err(e) => {
                    let _ = tx
                        .send(Err(std::io::Error::new(
                            std::io::ErrorKind::Other,
                            format!("request body read error: {e}"),
                        )))
                        .await;
                    return;
                }
            };

            let Some(data) = frame.data_ref() else {
                continue;
            };
            buffer.extend_from_slice(data);

            loop {
                if buffer.len() < 5 {
                    break;
                }
                let msg_len =
                    u32::from_be_bytes([buffer[1], buffer[2], buffer[3], buffer[4]]) as usize;
                if buffer[0] != 0 {
                    let _ = tx
                        .send(Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "compressed gRPC frames are not supported by gateway validation",
                        )))
                        .await;
                    return;
                }
                if msg_len > MAX_GRPC_MESSAGE_BYTES {
                    let _ = tx
                        .send(Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "gRPC message exceeds gateway validation limit",
                        )))
                        .await;
                    return;
                }
                let frame_len = 5 + msg_len;
                if buffer.len() < frame_len {
                    if buffer.len() > 5 + MAX_GRPC_MESSAGE_BYTES {
                        let _ = tx
                            .send(Err(std::io::Error::new(
                                std::io::ErrorKind::InvalidData,
                                "incomplete gRPC frame exceeds gateway validation limit",
                            )))
                            .await;
                        return;
                    }
                    break;
                }

                let grpc_frame = buffer.split_to(frame_len).freeze();
                let proto_bytes = &grpc_frame[5..];

                if let Err(status) =
                    gateway_model::s2sm::proxy_dispatch::validate_request(&path, proto_bytes)
                {
                    tracing::warn!(
                        path = %path,
                        error = %status.message(),
                        "streaming request frame validation failed"
                    );
                    let _ = tx
                        .send(Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            status.to_string(),
                        )))
                        .await;
                    return;
                }

                let target_namespace =
                    match gateway_model::s2sm::proxy_dispatch::request_target_namespace(
                        &path,
                        proto_bytes,
                    ) {
                        Ok(ns) => ns,
                        Err(status) => {
                            tracing::warn!(
                                path = %path,
                                error = %status.message(),
                                "streaming request frame namespace extraction failed"
                            );
                            let _ = tx
                                .send(Err(std::io::Error::new(
                                    std::io::ErrorKind::InvalidData,
                                    status.to_string(),
                                )))
                                .await;
                            return;
                        }
                    };

                if let Err((code, msg)) = auth
                    .validate_c2s_with_target_namespace(
                        auth_policy,
                        &service_id,
                        &entitlement_service,
                        &path,
                        auth_header.as_deref(),
                        target_namespace.as_deref(),
                    )
                    .await
                {
                    let grpc_code = status_code_to_tonic(code);
                    tracing::warn!(
                        path = %path,
                        code = ?grpc_code,
                        error = %msg,
                        "streaming request frame auth rejected"
                    );
                    let _ = tx
                        .send(Err(std::io::Error::new(
                            std::io::ErrorKind::PermissionDenied,
                            tonic::Status::new(grpc_code, msg).to_string(),
                        )))
                        .await;
                    return;
                }

                if tx.send(Ok(grpc_frame)).await.is_err() {
                    return;
                }
            }
        }

        if !buffer.is_empty() {
            let _ = tx
                .send(Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "incomplete trailing gRPC frame",
                )))
                .await;
        }
    });

    Body::from_stream(ReceiverStream::new(rx))
}

/// Handle a gRPC request: extract frame, validate, authenticate, and forward.
///
/// Per-message processing (from ARCHITECTURE.md):
/// 1. Extract gRPC frame (5-byte header + protobuf payload)
/// 2. Deserialize and validate via proxy_dispatch::validate_request()
/// 3. Authenticate via GatewayAuth::validate_c2s()
/// 4. Extract trace_id (field 200) and publish TraceEvent if present
/// 5. Forward original bytes to backend service
pub async fn handle(proxy: &ProxyState, req: Request<Body>) -> Response {
    handle_inner(proxy, req, StreamingValidation::RequestHeader).await
}

/// Handle an internally constructed streaming request whose inbound frames have
/// already been validated and authorized before entering the gRPC body stream.
pub async fn handle_prevalidated_stream(proxy: &ProxyState, req: Request<Body>) -> Response {
    handle_inner(proxy, req, StreamingValidation::AlreadyValidated).await
}

async fn handle_inner(
    proxy: &ProxyState,
    req: Request<Body>,
    streaming_validation: StreamingValidation,
) -> Response {
    let path = req.uri().path().to_string();

    let package_service_id = match extract_service_id(&path) {
        Some(id) => id,
        None => {
            return tonic_status_to_response(tonic::Status::not_found("unknown gRPC service"));
        }
    };

    // Gateway's own services (Mint) are handled by tonic routes, not the proxy.
    if package_service_id == "gateway" {
        return tonic_status_to_response(tonic::Status::not_found("gateway service not proxied"));
    }

    // Look up route info from the generated ROUTES table. ROUTES is the complete
    // set of C2S-reachable methods; a path that is not in it is not a method the
    // gateway proxies, so it is REJECTED. Falling through to Entitled would be an
    // allow-by-default: every S2S-only method (which carries no ROUTES entry, and
    // whose own service authorizes by peer identity, not by user entitlement)
    // would become reachable from outside by anything the entitlement check
    // happens to admit. Deny, not "most restrictive policy".
    let route_info = match gateway_model::s2sm::rest_dispatch::ROUTES
        .iter()
        .find(|r| r.grpc_path == path)
    {
        Some(r) => r,
        None => {
            tracing::warn!(path = %path, "gRPC path not in generated ROUTES table; rejected");
            return tonic_status_to_response(tonic::Status::not_found(
                "unknown gRPC method",
            ));
        }
    };
    let auth_policy = route_info.auth_policy;
    let (service_id, entitlement_service) = route_identity(route_info);

    // Extract auth header before consuming the request.
    let auth_header = req
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    // Check if this is a streaming RPC. Either direction of streaming must be
    // treated as streaming so each incoming frame is validated and authorized
    // before forwarding.
    let is_streaming = route_info.server_streaming || route_info.client_streaming;

    let (parts, body) = req.into_parts();

    // active_trace_id is set when a unary request carries a trace_id (field 200).
    // It's used to publish a response trace event after the backend call completes.
    let mut active_trace_id = String::new();

    let tonic_req = if is_streaming {
        if streaming_validation == StreamingValidation::RequestHeader {
            if let Err((code, msg)) = proxy
                .auth
                .validate_c2s(
                    auth_policy,
                    service_id,
                    entitlement_service,
                    &path,
                    auth_header.as_deref(),
                )
                .await
            {
                tracing::warn!(path = %path, error = %msg, "gRPC stream auth rejected");
                let grpc_code = status_code_to_tonic(code);
                return tonic_status_to_response(tonic::Status::new(grpc_code, msg));
            }
        }

        let body = match streaming_validation {
            StreamingValidation::RequestHeader => validated_streaming_body(
                body,
                proxy,
                path.clone(),
                service_id.to_string(),
                entitlement_service.to_string(),
                auth_policy,
                auth_header.clone(),
            ),
            StreamingValidation::AlreadyValidated => body,
        };
        let streaming_body = StreamingBody(body);
        let tonic_body = tonic::body::Body::new(streaming_body);
        Request::from_parts(parts, tonic_body)
    } else {
        // Token check FIRST, on headers alone — the same ordering the streaming
        // branch above already uses. Buffering and decoding up to 10MB is work
        // an unauthenticated caller must not be able to make the gateway do.
        // The namespace-aware half of the check needs the decoded message and
        // still runs below, once the body has been read and validated.
        if let Err((code, msg)) = proxy
            .auth
            .validate_c2s(
                auth_policy,
                service_id,
                entitlement_service,
                &path,
                auth_header.as_deref(),
            )
            .await
        {
            tracing::warn!(path = %path, error = %msg, "gRPC auth rejected before body read");
            let grpc_code = status_code_to_tonic(code);
            return tonic_status_to_response(tonic::Status::new(grpc_code, msg));
        }

        // Unary: buffer body, extract frame, validate, trace, then forward.
        let body_bytes = match axum::body::to_bytes(body, 5 + MAX_GRPC_MESSAGE_BYTES).await {
            Ok(b) => b,
            Err(e) => {
                return tonic_status_to_response(tonic::Status::internal(format!(
                    "failed to read request body: {}",
                    e
                )));
            }
        };

        // Extract and validate the protobuf payload from the gRPC frame.
        let target_namespace = match unframe_grpc(&body_bytes) {
            Ok(proto_bytes) => {
                // Validate: deserialize into typed message and run validation.
                if let Err(status) =
                    gateway_model::s2sm::proxy_dispatch::validate_request(&path, proto_bytes)
                {
                    tracing::warn!(path = %path, error = %status.message(), "request validation failed");
                    return tonic_status_to_response(status);
                }

                let target_namespace =
                    match gateway_model::s2sm::proxy_dispatch::request_target_namespace(
                        &path,
                        proto_bytes,
                    ) {
                        Ok(ns) => ns,
                        Err(status) => {
                            tracing::warn!(path = %path, error = %status.message(), "request namespace extraction failed");
                            return tonic_status_to_response(status);
                        }
                    };

                // Trace: extract trace_id from proto field 200.
                match <TraceProbe as prost::Message>::decode(proto_bytes) {
                    Ok(probe) if !probe.trace_id.is_empty() => {
                        active_trace_id = probe.trace_id.clone();
                        let round = (proxy.trace_round)();
                        // TODO: set typed rpc field using AccountingMethod lookup by path.
                        (proxy.trace_publisher)(TraceEvent {
                            trace_id: probe.trace_id.clone(),
                            round: Some(round),
                            kind: TraceEventKind::ExternalRequest.into(),
                            ..Default::default()
                        });
                    }
                    Ok(_) => {}
                    Err(e) => {
                        tracing::debug!(error = %e, grpc_path = %path, "TraceProbe decode skipped");
                    }
                }

                target_namespace
            }
            Err(status) => {
                return tonic_status_to_response(status);
            }
        };

        // The target-namespace half of the check: it needs the decoded message,
        // so it can only run now. The token itself was already verified above.
        if let Err((code, msg)) = proxy
            .auth
            .validate_c2s_with_target_namespace(
                auth_policy,
                service_id,
                entitlement_service,
                &path,
                auth_header.as_deref(),
                target_namespace.as_deref(),
            )
            .await
        {
            tracing::warn!(path = %path, error = %msg, "gRPC auth rejected");
            if !active_trace_id.is_empty() {
                let round = (proxy.trace_round)();
                (proxy.trace_publisher)(TraceEvent {
                    trace_id: active_trace_id,
                    round: Some(round),
                    kind: TraceEventKind::ExternalResponse.into(),
                    error: msg.clone(),
                    ..Default::default()
                });
            }
            let grpc_code = status_code_to_tonic(code);
            return tonic_status_to_response(tonic::Status::new(grpc_code, msg));
        }

        // Forward original buffered bytes (not re-serialized).
        let new_body = Body::from(body_bytes);
        let streaming_body = StreamingBody(new_body);
        let tonic_body = tonic::body::Body::new(streaming_body);
        Request::from_parts(parts, tonic_body)
    };

    // Forward to backend service.
    // Probe endpoints to find a live one — stale health entries (pods that were
    // removed from the cluster but not yet expired from Hazelcast) cause transport
    // errors without probing. dial_ready_any() skips unreachable endpoints.
    // Try service_id first, fall back to SPIFFE path routing.
    let mut channel = {
        let endpoints = proxy.resolver.health().get_endpoints(service_id);
        if endpoints.is_empty() {
            proxy.resolver.dial_spiffe(service_id).await
        } else {
            proxy.resolver.dial_ready_any(service_id).await
        }
    };

    if let Err(e) = channel.ready().await {
        tracing::error!(error = %e, service = service_id, path = %path, "gRPC proxy channel not ready");
        if !active_trace_id.is_empty() {
            let round = (proxy.trace_round)();
            (proxy.trace_publisher)(TraceEvent {
                trace_id: active_trace_id,
                round: Some(round),
                kind: TraceEventKind::ExternalResponse.into(),
                error: format!("backend not ready: {}", e),
                ..Default::default()
            });
        }
        return tonic_status_to_response(tonic::Status::unavailable(format!(
            "backend not ready: {}",
            e
        )));
    }
    match channel.call(tonic_req).await {
        Ok(response) => {
            if !active_trace_id.is_empty() {
                let round = (proxy.trace_round)();
                (proxy.trace_publisher)(TraceEvent {
                    trace_id: active_trace_id,
                    round: Some(round),
                    kind: TraceEventKind::ExternalResponse.into(),
                    ..Default::default()
                });
            }
            let (parts, body) = response.into_parts();
            Response::from_parts(parts, Body::new(body))
        }
        Err(e) => {
            tracing::error!(error = %e, service = service_id, path = %path, "gRPC proxy error");
            if !active_trace_id.is_empty() {
                let round = (proxy.trace_round)();
                (proxy.trace_publisher)(TraceEvent {
                    trace_id: active_trace_id,
                    round: Some(round),
                    kind: TraceEventKind::ExternalResponse.into(),
                    error: format!("backend unavailable: {}", e),
                    ..Default::default()
                });
            }
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use gateway_grpcserver::authorizer::JwkCache;
    use gateway_key::keys;
    use gateway_model::s2sm::rest_dispatch::{AuthPolicy, RouteInfo};
    use gateway_servicemanager::SpiffeServerCertVerifier;
    use gateway_x509::x509::{ImmutableCertChain, X509KeyUsage};

    use crate::health::HealthWatcher;

    /// A request body that records every poll. Nothing may read it before the
    /// token check has passed.
    struct CountingBody {
        polls: Arc<AtomicUsize>,
        data: Option<bytes::Bytes>,
    }

    impl http_body::Body for CountingBody {
        type Data = bytes::Bytes;
        type Error = std::io::Error;

        fn poll_frame(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
            let this = self.get_mut();
            this.polls.fetch_add(1, Ordering::SeqCst);
            Poll::Ready(this.data.take().map(|d| Ok(Frame::data(d))))
        }
    }

    /// A verifier nothing in this test consults; `Resolver` just holds one, and
    /// `WebPkiServerVerifier` refuses to build with no anchors at all.
    fn unused_verifier() -> Arc<SpiffeServerCertVerifier> {
        let key = keys::generate_ec_p256_key().expect("throwaway key");
        let expiry = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_secs() as i64
            + 3600;
        let cert = ImmutableCertChain::for_self_signing(key)
            .self_sign("unused", expiry, X509KeyUsage::CertSign, &[])
            .expect("throwaway cert");
        let mut roots = rustls::RootCertStore::empty();
        for der in rustls_pemfile::certs(&mut cert.pem_bytes()) {
            roots.add(der.expect("der")).expect("add root");
        }
        SpiffeServerCertVerifier::new("proxy.test", roots).expect("verifier")
    }

    /// The first unary, non-gateway route in the generated table that requires
    /// a token. Picked from ROUTES so the test follows regeneration.
    fn unary_authenticated_route() -> &'static RouteInfo {
        gateway_model::s2sm::rest_dispatch::ROUTES
            .iter()
            .find(|r| {
                !r.server_streaming
                    && !r.client_streaming
                    && r.auth_policy != AuthPolicy::NoAuth
                    && !r.grpc_path.starts_with("/gateway.")
            })
            .expect("the generated ROUTES table must contain a unary authenticated route")
    }

    /// The finding: an unauthenticated caller could make the gateway buffer and
    /// decode up to 10MB before the token was ever looked at. The body here is
    /// garbage that cannot be unframed, so before the fix the caller got an
    /// InvalidArgument frame error — proof the parse ran. It must now be
    /// Unauthenticated, with the body never polled at all.
    #[tokio::test]
    async fn unary_rejects_unauthenticated_caller_before_reading_the_body() {
        let _ = rustls::crypto::ring::default_provider().install_default();

        let proxy = ProxyState {
            resolver: Arc::new(Resolver::plaintext_backends(
                HealthWatcher::seeded(HashMap::new()),
                unused_verifier(),
            )),
            auth: Arc::new(GatewayAuth::new(Arc::new(JwkCache::seeded(vec![])), false)),
            trace_publisher: Arc::new(|_| {}),
            trace_round: Box::new(Default::default),
        };

        let polls = Arc::new(AtomicUsize::new(0));
        let body = Body::new(CountingBody {
            polls: Arc::clone(&polls),
            // A malformed gRPC frame: length prefix claims 4GB, payload is 3
            // bytes. unframe_grpc rejects this the moment it is reached.
            data: Some(bytes::Bytes::from_static(b"\x00\xff\xff\xff\xffnot")),
        });

        let route = unary_authenticated_route();
        let request = Request::builder()
            .method("POST")
            .uri(route.grpc_path)
            .header("content-type", "application/grpc+proto")
            .body(body)
            .expect("request");

        let response = handle(&proxy, request).await;

        assert_eq!(
            response
                .headers()
                .get("grpc-status")
                .and_then(|v| v.to_str().ok()),
            Some("16"),
            "no token must be Unauthenticated (16), not a body-parse error: {:?}",
            response.headers().get("grpc-message")
        );
        assert_eq!(
            polls.load(Ordering::SeqCst),
            0,
            "the request body must not be polled before the token check"
        );
    }

    #[test]
    fn route_identity_separates_physical_service_from_entitlement_contract() {
        let route = RouteInfo {
            http_path: "/api/v1/tasks/DelegationProbeBusStateService/PublishToStream",
            grpc_path: "/tasks.DelegationProbeBusStateService/PublishToStream",
            service_id: "eventbus",
            entitlement_service: Some("tasks"),
            http_methods: &["POST"],
            auth_policy: AuthPolicy::Entitled,
            entitlement_scopes: &["WRITE"],
            capability_scope: Some("WRITE"),
            server_streaming: true,
            client_streaming: true,
            target_namespace_field: None,
        };

        let (physical_service, entitlement_service) = route_identity(&route);

        assert_eq!(physical_service, "eventbus");
        assert_eq!(entitlement_service, "tasks");
    }
}
