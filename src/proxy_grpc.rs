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

pub(crate) const MAX_GRPC_MESSAGE_BYTES: usize = 10 * 1024 * 1024;

/// Body wrapper that overrides `is_end_stream()` to always return `false`.
/// This prevents `tonic::body::Body::new()` from short-circuiting to an empty
/// body when the underlying HTTP/2 stream has received all data + END_STREAM
/// but the data hasn't been polled/consumed yet.
pub(crate) struct StreamingBody(pub(crate) Body);

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

/// Whether `route` is a service's MCP session carrier: the method tacplus
/// generates as `Broker<Service>McpSession`, a bidi stream of `mcp.McpRequest`.
pub(crate) fn is_mcp_carrier(route: &gateway_model::s2sm::rest_dispatch::RouteInfo) -> bool {
    let method = route.grpc_path.rsplit('/').next().unwrap_or("");
    route.client_streaming
        && route.server_streaming
        && method.starts_with("Broker")
        && method.ends_with("McpSession")
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
    /// The rotating streams' sessions this gateway carries, each bound to the
    /// backend instance that issued it and its opening token's subject (#26).
    pub sessions: Arc<crate::rotation::Sessions>,
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

/// Splits the next complete gRPC message frame (5-byte header and payload) off
/// the front of `buffer`. `Ok(None)` when it does not hold one yet; an error
/// for a frame the gateway will not forward (compressed, or over its limit).
fn next_grpc_frame(buffer: &mut bytes::BytesMut) -> Result<Option<bytes::Bytes>, &'static str> {
    if buffer.len() < 5 {
        return Ok(None);
    }
    if buffer[0] != 0 {
        return Err("compressed gRPC frames are not supported by gateway validation");
    }
    let msg_len = u32::from_be_bytes([buffer[1], buffer[2], buffer[3], buffer[4]]) as usize;
    if msg_len > MAX_GRPC_MESSAGE_BYTES {
        return Err("gRPC message exceeds gateway validation limit");
    }
    let frame_len = 5 + msg_len;
    if buffer.len() < frame_len {
        return Ok(None);
    }
    Ok(Some(buffer.split_to(frame_len).freeze()))
}

type StreamOpened = tokio::sync::oneshot::Sender<Result<String, tonic::Status>>;

/// Ends a tenant-routed stream with `status`. Before its first message the
/// refusal goes to the opener, which answers it without dialling; after it,
/// down the forwarded body.
async fn refuse(
    opened_tx: &mut Option<StreamOpened>,
    tx: &tokio::sync::mpsc::Sender<Result<bytes::Bytes, std::io::Error>>,
    status: tonic::Status,
) {
    match opened_tx.take() {
        Some(opened) => {
            let _ = opened.send(Err(status));
        }
        None => {
            let kind = if status.code() == tonic::Code::PermissionDenied {
                std::io::ErrorKind::PermissionDenied
            } else {
                std::io::ErrorKind::InvalidData
            };
            let _ = tx
                .send(Err(std::io::Error::new(kind, status.to_string())))
                .await;
        }
    }
}

/// Opens a tenant-routed stream: reads the request body up to its first
/// message, whose route field (a tid, see `rest_dispatch::route_tenant_from_wire`)
/// names the tenant the stream is for, and returns that tenant with the body
/// to forward. Every later message must name the same tenant: the stream is
/// opened for one tenant, so a message naming another, or none, ends it with
/// INVALID_ARGUMENT and is not forwarded. A first message naming no valid
/// tenant (or a stream with no message at all) is refused here, before
/// anything is dialled.
///
/// `stamp` is the tenant of an MCP session of a tenant-owned service, the
/// caller token's (#15): each message is stamped with it (`stamp_mcp_tenant`)
/// before its route field is read, so the session is opened for that tenant
/// and a message naming another is refused, PERMISSION_DENIED.
async fn route_stream(
    mut body: Body,
    route: &'static gateway_model::s2sm::rest_dispatch::RouteInfo,
    stamp: Option<String>,
) -> Result<(String, Body), tonic::Status> {
    let (tx, rx) = tokio::sync::mpsc::channel::<Result<bytes::Bytes, std::io::Error>>(16);
    let (opened_tx, opened_rx) = tokio::sync::oneshot::channel();

    tokio::spawn(async move {
        let mut opened_tx = Some(opened_tx);
        let mut tenant: Option<String> = None;
        let mut buffer = bytes::BytesMut::new();

        loop {
            loop {
                let frame = match next_grpc_frame(&mut buffer) {
                    Ok(Some(frame)) => frame,
                    Ok(None) => break,
                    Err(why) => {
                        let status = tonic::Status::invalid_argument(why);
                        return refuse(&mut opened_tx, &tx, status).await;
                    }
                };
                let frame = match &stamp {
                    Some(stamp) => match stamp_mcp_tenant(&frame[5..], stamp) {
                        Ok(message) => bytes::Bytes::from(frame_grpc(&message)),
                        Err(status) => return refuse(&mut opened_tx, &tx, status).await,
                    },
                    None => frame,
                };
                let named = match gateway_model::s2sm::rest_dispatch::route_tenant_from_wire(
                    &frame[5..],
                    route,
                ) {
                    Ok(named) => named,
                    Err(status) => return refuse(&mut opened_tx, &tx, status).await,
                };
                if let Some(open) = &tenant {
                    if *open != named {
                        let status = tonic::Status::invalid_argument(format!(
                            "this stream is opened for tenant {open}; a message names tenant {named}"
                        ));
                        return refuse(&mut opened_tx, &tx, status).await;
                    }
                } else {
                    // The first message: the stream is opened for its tenant.
                    if let Some(opened) = opened_tx.take() {
                        if opened.send(Ok(named.clone())).is_err() {
                            return;
                        }
                    }
                    tenant = Some(named);
                }
                if tx.send(Ok(frame)).await.is_err() {
                    return;
                }
            }

            match body.frame().await {
                Some(Ok(frame)) => {
                    if let Some(data) = frame.data_ref() {
                        buffer.extend_from_slice(data);
                    }
                }
                Some(Err(e)) => {
                    let status = tonic::Status::invalid_argument(format!("request body read error: {e}"));
                    return refuse(&mut opened_tx, &tx, status).await;
                }
                None => break,
            }
        }

        if !buffer.is_empty() {
            let status = tonic::Status::invalid_argument("incomplete trailing gRPC frame");
            return refuse(&mut opened_tx, &tx, status).await;
        }
        // A stream that ended before its first message names no tenant.
        if opened_tx.is_some() {
            if let Err(status) = gateway_model::s2sm::rest_dispatch::route_tenant_from_wire(&[], route) {
                refuse(&mut opened_tx, &tx, status).await;
            }
        }
    });

    let tenant = opened_rx
        .await
        .map_err(|_| tonic::Status::internal("tenant-routed stream ended before it was opened"))??;
    Ok((tenant, Body::from_stream(ReceiverStream::new(rx))))
}

pub(crate) fn status_code_to_tonic(code: StatusCode) -> tonic::Code {
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
                let grpc_frame = match next_grpc_frame(&mut buffer) {
                    Ok(Some(frame)) => frame,
                    Ok(None) => break,
                    Err(why) => {
                        let _ = tx
                            .send(Err(std::io::Error::new(std::io::ErrorKind::InvalidData, why)))
                            .await;
                        return;
                    }
                };
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

/// One `mcp.McpRequest` as it goes on to a tenant-owned service's MCP carrier:
/// in the session's `tenant`, the caller token's (tacplus#170). A frame with no
/// tenant is stamped by appending the field (protobuf's last value wins), so the
/// rest of the message goes on byte for byte; a frame already naming the
/// session's tenant goes on as it is; a frame naming any other tenant is
/// refused. The client, and the model behind it, never choose the tenant.
pub(crate) fn stamp_mcp_tenant(message: &[u8], tenant: &str) -> Result<Vec<u8>, tonic::Status> {
    use gateway_model::types::sys::mcp::McpRequest;

    let request = <McpRequest as prost::Message>::decode(message)
        .map_err(|e| tonic::Status::invalid_argument(format!("decode: {e}")))?;
    if request.tenant == tenant {
        return Ok(message.to_vec());
    }
    if !request.tenant.is_empty() {
        // The client's value is not echoed: it is not ours to repeat.
        return Err(tonic::Status::permission_denied(format!(
            "MCP frame names a tenant other than this session's ({tenant}); the session's tenant is the caller token's"
        )));
    }
    let mut stamped = message.to_vec();
    stamped.extend(prost::Message::encode_to_vec(&McpRequest {
        tenant: tenant.to_string(),
        ..Default::default()
    }));
    Ok(stamped)
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
        // `/<pkg>.<Svc>Rotating/<Method>`, a streaming method's rotating
        // sibling (tacplus#322), carries no ROUTES entry of its own: it is
        // the plain method's route, its frames rotation Envelopes.
        None if streaming_validation == StreamingValidation::RequestHeader
            && crate::rotation::plain_route(&path).is_some() =>
        {
            let (plain_path, route) = crate::rotation::plain_route(&path).expect("matched");
            return crate::rotation::handle(proxy, req, route, plain_path).await;
        }
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

    // `tenant` is the call's target tenant, read off the request's route field
    // (`(spec.rpc).route_field`, a tid) for a route of a tenant-owned service,
    // and empty for a platform route, which is never addressed by tenant. It
    // is never taken from the caller's token: who is asking is the token's,
    // whether they may is the target's policy, and neither moves the call.
    // (An MCP session's route field is the one the gateway fills in, from the
    // token, before it is read: #15, `mcp_session_tenant`.)
    let (tonic_req, tenant) = if is_streaming {
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

        // An MCP session of a tenant-owned service is in the caller token's
        // tenant, never one the client or the model names (#15): its frames
        // are stamped with the token's tid, and routed by it.
        let stamp = match mcp_session_tenant(proxy, route_info, &path, auth_header.as_deref()) {
            Ok(stamp) => stamp,
            Err(status) => return tonic_status_to_response(status),
        };

        // A tenant-routed stream is opened for the tenant its first message
        // names, so that message is read before anything is dialled.
        let (tenant, body) = if route_info.route_field_number != 0 {
            match route_stream(body, route_info, stamp).await {
                Ok(opened) => opened,
                Err(status) => {
                    tracing::warn!(path = %path, error = %status.message(), "tenant-routed stream refused");
                    return tonic_status_to_response(status);
                }
            }
        } else {
            (String::new(), body)
        };

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
        (Request::from_parts(parts, tonic_body), tenant)
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
        let (target_namespace, tenant) = match unframe_grpc(&body_bytes) {
            Ok(proto_bytes) => {
                // Validate: deserialize into typed message and run validation.
                if let Err(status) =
                    gateway_model::s2sm::proxy_dispatch::validate_request(&path, proto_bytes)
                {
                    tracing::warn!(path = %path, error = %status.message(), "request validation failed");
                    return tonic_status_to_response(status);
                }

                // The target tenant: an empty or malformed one is refused
                // here, INVALID_ARGUMENT, before anything is dialled.
                let tenant = match gateway_model::s2sm::rest_dispatch::route_tenant_from_wire(
                    proto_bytes,
                    route_info,
                ) {
                    Ok(tenant) => tenant,
                    Err(status) => {
                        tracing::warn!(path = %path, error = %status.message(), "tenant-routed request refused");
                        return tonic_status_to_response(status);
                    }
                };

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

                (target_namespace, tenant)
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
        (Request::from_parts(parts, tonic_body), tenant)
    };

    let route_key = proxy.resolver.resolve_target(service_id, &tenant);

    // Forward to backend service.
    // Probe endpoints to find a live one — stale health entries (pods that were
    // removed from the cluster but not yet expired from Hazelcast) cause transport
    // errors without probing. dial_ready_any() skips unreachable endpoints.
    // Try route_key first, fall back to SPIFFE path routing. The TLS identity is
    // always `service_id`: a tenant instance's certificate names the bare
    // service, under a `/tenants/<tid>` namespace. A tenant with no healthy
    // instance gets no channel, so the call is UNAVAILABLE: never another
    // tenant's instance.
    let mut channel = {
        let endpoints = proxy.resolver.health().get_endpoints(&route_key);
        if endpoints.is_empty() {
            proxy.resolver.dial_spiffe(&route_key, service_id).await
        } else {
            proxy.resolver.dial_ready_any(&route_key, service_id).await
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

/// The tenant of an MCP session of a tenant-owned service (#15): `None` for
/// every other route, which is never stamped; for the carrier
/// (`Broker<Service>McpSession`) of a service routed by a target-tenant field,
/// the caller token's tid (`GatewayAuth::caller_tid`), and a caller in no
/// tenant is refused. The carrier is then routed by that tid like any
/// tenant-routed stream, by its (stamped) first message.
pub(crate) fn mcp_session_tenant(
    proxy: &ProxyState,
    route_info: &'static gateway_model::s2sm::rest_dispatch::RouteInfo,
    path: &str,
    auth_header: Option<&str>,
) -> Result<Option<String>, tonic::Status> {
    if route_info.route_field_number == 0 || !is_mcp_carrier(route_info) {
        return Ok(None);
    }
    let (service_id, entitlement_service) = route_identity(route_info);
    match proxy.auth.caller_tid(
        route_info.auth_policy,
        service_id,
        entitlement_service,
        path,
        auth_header,
    ) {
        Ok(tid) => Ok(Some(tid)),
        Err((code, msg)) => {
            tracing::warn!(path = %path, service = service_id, error = %msg, "MCP session tenant refused");
            Err(tonic::Status::new(status_code_to_tonic(code), msg))
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

    use rustls::pki_types::pem::PemObject;
    use rustls::pki_types::CertificateDer;

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
        for der in CertificateDer::pem_slice_iter(cert.pem_bytes()) {
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
            sessions: Default::default(),
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
            http_path: "/tasks/DelegationProbeBusStateService/PublishToStream",
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
            form_body: false,
            redirect_field: None,
            route_field: None,
            route_field_json: None,
            route_field_number: 0,
        };

        let (physical_service, entitlement_service) = route_identity(&route);

        assert_eq!(physical_service, "eventbus");
        assert_eq!(entitlement_service, "tasks");
    }

    /// A client-streaming route of a tenant-owned service, routed by its
    /// request's field 2, `tenant`.
    static ROUTED_STREAM: RouteInfo = CREW_CHAT;
    const CREW_CHAT: RouteInfo = RouteInfo {
        http_path: "",
        grpc_path: "/crew.Crew/Chat",
        service_id: "crew",
        entitlement_service: None,
        http_methods: &[],
        auth_policy: AuthPolicy::AnyUser,
        entitlement_scopes: &[],
        capability_scope: None,
        server_streaming: true,
        client_streaming: true,
        target_namespace_field: None,
        form_body: false,
        redirect_field: None,
        route_field: Some("tenant"),
        route_field_json: Some("tenant"),
        route_field_number: 2,
    };

    /// A gRPC frame of a message whose field 2 is `tenant` (absent when empty).
    fn naming(tenant: &str) -> Vec<u8> {
        let mut message = vec![0x0a, 2, b'h', b'i'];
        if !tenant.is_empty() {
            message.extend_from_slice(&[0x12, tenant.len() as u8]);
            message.extend_from_slice(tenant.as_bytes());
        }
        frame_grpc(&message)
    }

    /// A request body delivered in exactly these chunks.
    fn chunked(chunks: Vec<Vec<u8>>) -> Body {
        Body::from_stream(futures::stream::iter(
            chunks
                .into_iter()
                .map(|c| Ok::<_, std::io::Error>(bytes::Bytes::from(c))),
        ))
    }

    /// Everything the opened body forwards, and the error that ends it, if any.
    async fn drain(mut body: Body) -> (Vec<u8>, Option<String>) {
        let mut forwarded = Vec::new();
        while let Some(frame) = body.frame().await {
            match frame {
                Ok(frame) => forwarded.extend_from_slice(frame.data_ref().expect("data")),
                Err(e) => return (forwarded, Some(e.to_string())),
            }
        }
        (forwarded, None)
    }

    /// A stream is opened for the tenant its first message names, even when
    /// that message arrives split across body chunks, and every message naming
    /// it is forwarded unchanged.
    #[tokio::test]
    async fn a_routed_stream_opens_for_its_first_message_and_forwards_its_messages() {
        let first = naming("acme0001");
        let (head, tail) = first.split_at(3);
        let mut rest = tail.to_vec();
        rest.extend(naming("acme0001"));

        let (tenant, body) = route_stream(chunked(vec![head.to_vec(), rest]), &ROUTED_STREAM, None)
            .await
            .expect("a first message naming a tid opens the stream");
        assert_eq!(tenant, "acme0001");

        let (forwarded, error) = drain(body).await;
        assert_eq!(error, None);
        assert_eq!(forwarded, [naming("acme0001"), naming("acme0001")].concat());
    }

    /// The stream is opened for one tenant: a later message naming another, or
    /// none, ends it there, and that message is not forwarded.
    #[tokio::test]
    async fn a_routed_stream_ends_at_a_message_naming_another_tenant() {
        for stray in ["beta0002", ""] {
            let (tenant, body) = route_stream(
                chunked(vec![naming("acme0001"), naming(stray), naming("acme0001")]),
                &ROUTED_STREAM,
                None,
            )
            .await
            .expect("opens");
            assert_eq!(tenant, "acme0001");

            let (forwarded, error) = drain(body).await;
            assert_eq!(forwarded, naming("acme0001"), "only the message before {stray:?} is forwarded");
            let error = error.unwrap_or_else(|| panic!("a message naming {stray:?} must end the stream"));
            assert!(error.contains("tenant"), "{error}");
        }
    }

    /// A stream whose first message names no valid tenant, or that has no
    /// message at all, is refused before it is opened: the caller dials nothing.
    #[tokio::test]
    async fn a_routed_stream_naming_no_tenant_is_refused_before_it_opens() {
        for (case, chunks) in [
            ("no tenant", vec![naming("")]),
            ("a name, not a tid", vec![naming("acme")]),
            ("no message", vec![]),
            ("a truncated message", vec![naming("acme0001")[..7].to_vec()]),
        ] {
            let status = route_stream(chunked(chunks), &ROUTED_STREAM, None)
                .await
                .err()
                .unwrap_or_else(|| panic!("{case} must be refused"));
            assert_eq!(status.code(), tonic::Code::InvalidArgument, "{case}: {status:?}");
        }
    }

    /// An MCP session's stream (#15) is stamped before it is routed: a first
    /// message naming no tenant opens the stream for the stamp, and is
    /// forwarded naming it; a message naming another tenant is refused,
    /// PERMISSION_DENIED, before the stream opens or wherever it comes later.
    #[tokio::test]
    async fn a_stamped_stream_opens_for_its_stamp_and_refuses_another_tenant() {
        let stamp = || Some("acme0001".to_string());
        let (tenant, body) =
            route_stream(chunked(vec![naming(""), naming("acme0001")]), &ROUTED_STREAM, stamp())
                .await
                .expect("an unnamed first message opens for the stamp");
        assert_eq!(tenant, "acme0001");
        let (forwarded, error) = drain(body).await;
        assert_eq!(error, None);
        assert_eq!(forwarded, [naming("acme0001"), naming("acme0001")].concat(), "stamped");

        let status = route_stream(chunked(vec![naming("beta0002")]), &ROUTED_STREAM, stamp())
            .await
            .err()
            .expect("a first message naming another tenant is refused");
        assert_eq!(status.code(), tonic::Code::PermissionDenied, "{status:?}");

        let (_, body) = route_stream(
            chunked(vec![naming(""), naming("beta0002"), naming("")]),
            &ROUTED_STREAM,
            stamp(),
        )
        .await
        .expect("opens");
        let (forwarded, error) = drain(body).await;
        assert_eq!(forwarded, naming("acme0001"), "nothing at or after the refused message");
        assert!(error.is_some(), "a message naming another tenant ends the stream");
    }

    fn empty_proxy() -> ProxyState {
        let _ = rustls::crypto::ring::default_provider().install_default();
        ProxyState {
            resolver: Arc::new(Resolver::plaintext_backends(
                HealthWatcher::seeded(HashMap::new()),
                unused_verifier(),
            )),
            auth: Arc::new(GatewayAuth::new(Arc::new(JwkCache::seeded(vec![])), false)),
            trace_publisher: Arc::new(|_| {}),
            trace_round: Box::new(Default::default),
            sessions: Default::default(),
        }
    }

    /// `ROUTED_STREAM` as a service's MCP session carrier, with or without a
    /// route field.
    static ROUTED_CARRIER: RouteInfo = RouteInfo {
        grpc_path: "/crew.Crew/BrokerCrewMcpSession",
        ..CREW_CHAT
    };
    static PLATFORM_CARRIER: RouteInfo = RouteInfo {
        grpc_path: "/crew.Crew/BrokerCrewMcpSession",
        route_field: None,
        route_field_json: None,
        route_field_number: 0,
        ..CREW_CHAT
    };

    /// Only the carrier of a tenant-routed service has a session tenant, and
    /// only a caller whose token names one gets it; a platform carrier and
    /// every other stream are never stamped, and no token is read for them.
    #[test]
    fn only_a_tenant_routed_carrier_has_a_session_tenant() {
        let proxy = empty_proxy();
        for route in [&PLATFORM_CARRIER, &ROUTED_STREAM] {
            assert!(
                matches!(mcp_session_tenant(&proxy, route, route.grpc_path, None), Ok(None)),
                "{} is not stamped",
                route.grpc_path
            );
        }
        let status = mcp_session_tenant(&proxy, &ROUTED_CARRIER, ROUTED_CARRIER.grpc_path, None)
            .expect_err("a caller with no token has no tenant");
        assert_ne!(status.code(), tonic::Code::Ok);
    }

    /// The rotating sibling (#26) of a tenant-routed stream that is not an MCP
    /// carrier opens with an envelope that carries no request, so names no
    /// tenant to route by, and the token is never one: UNIMPLEMENTED, and the
    /// client falls back to the plain method, routed by its first message.
    #[tokio::test]
    async fn a_tenant_routed_streams_rotating_sibling_is_unimplemented() {
        let proxy = empty_proxy();
        let opening = crate::rotation::Envelope::default();
        let request = Request::builder()
            .method("POST")
            .uri("/crew.CrewRotating/Chat")
            .header("content-type", "application/grpc+proto")
            .body(Body::from(frame_grpc(&prost::Message::encode_to_vec(&opening))))
            .expect("request");
        let response = crate::rotation::handle(
            &proxy,
            request,
            &ROUTED_STREAM,
            ROUTED_STREAM.grpc_path.to_string(),
        )
        .await;
        assert_eq!(
            response.headers().get("grpc-status").and_then(|v| v.to_str().ok()),
            Some("12"),
            "a tenant-routed stream's sibling must be Unimplemented (12)"
        );
    }

    fn route_for(grpc_path: &str) -> Option<&'static RouteInfo> {
        gateway_model::s2sm::rest_dispatch::ROUTES
            .iter()
            .find(|r| r.grpc_path == grpc_path)
    }

    /// Token-management item 7: the user half of the delegate-bound Offline
    /// Token mint must be reachable through gateway's ORDINARY client-facing
    /// path — no hand-written `Mint` front entry, no proxy special case. The
    /// entry exists only because `kernel.proto` declares
    /// `kernel.UserMint` `(spec.service_c2s)`; `kernel.Mint` is
    /// `(spec.service_s2s)` and a service carries exactly one caller surface,
    /// so moving the RPC to its own C2S service is what generates the route.
    ///
    /// AnyUser, not Entitled: any authenticated person may connect an agent of
    /// their own, and the handler mints against that caller's own OPA
    /// entitlements. Asserted on the generated table so a regeneration that
    /// drops or re-gates the route fails here.
    #[test]
    fn kernel_user_mint_delegate_offline_token_is_a_generic_c2s_route() {
        let path = "/kernel.UserMint/MintDelegateOfflineToken";
        let route = route_for(path)
            .unwrap_or_else(|| panic!("{path} must be in the generated ROUTES table"));

        assert_eq!(
            route.service_id, "kernel",
            "the gateway must dial kernel directly for this RPC"
        );
        assert_eq!(
            route.auth_policy,
            AuthPolicy::AnyUser,
            "{path} must admit any authenticated user: {:?}",
            route.auth_policy
        );
        assert_eq!(
            route.http_path, "/kernel/UserMint/MintDelegateOfflineToken",
            "the convention REST path is the client-facing way in"
        );
        assert!(
            !route.client_streaming && !route.server_streaming,
            "a unary mint must dispatch through the unary arm"
        );

        // The delegate half stays S2S: it is redeemed by the delegate's own
        // service identity, never from a browser, so it must NOT be routable.
        assert!(
            route_for("/kernel.Mint/BrokerDelegateOfflineToken").is_none(),
            "BrokerDelegateOfflineToken is S2S-only and must have no gateway route"
        );

        // And nothing re-declared the RPC on gateway's own hand-written front.
        assert!(
            route_for("/gateway.Mint/MintDelegateOfflineToken").is_none(),
            "this RPC must flow through generic C2S routing, not a gateway front"
        );
    }

    /// The tripwire for decision-goalB-q1 §6. `CreatePersonalPrincipal` used to
    /// carry `RPC_FLAG_SELF_AUTHENTICATES`, which made tacplus emit a NoAuth
    /// proxy route for it — kernel itself, gateway-fronted, unauthenticated, in
    /// the user-facing path, which is exactly what the ruling forbids. Unit 5
    /// swapped the flag for `auth_services: ["*"]` so the route is no longer
    /// generated and `resolve`'s deny-by-default answers `NOT_FOUND`.
    ///
    /// Re-adding the flag would silently restore the route, so the assertion is
    /// on the generated table rather than on the proto: this fails on the next
    /// regeneration after such a change, not on a review nobody runs.
    #[test]
    fn kernel_create_personal_principal_has_no_proxy_route() {
        assert!(
            route_for("/kernel.Mint/CreatePersonalPrincipal").is_none(),
            "kernel.Mint.CreatePersonalPrincipal is externally routable again — a no-auth flag \
             was re-added to it in kernel.proto. Registration must only be reachable through \
             a device-broker delegate (decision-goalB-q1-broker-service-design.md §6)."
        );
    }

    fn mcp_request(payload: &str, tenant: &str) -> Vec<u8> {
        prost::Message::encode_to_vec(&gateway_model::types::sys::mcp::McpRequest {
            payload: payload.to_string(),
            tenant: tenant.to_string(),
        })
    }

    fn decoded(message: &[u8]) -> gateway_model::types::sys::mcp::McpRequest {
        prost::Message::decode(message).expect("an McpRequest")
    }

    /// An MCP frame with no tenant is stamped with the session's, and nothing
    /// else in it changes: the original bytes are a prefix of what goes on.
    #[test]
    fn an_mcp_frame_with_no_tenant_is_stamped_with_the_session_tenant() {
        let message = mcp_request(r#"{"jsonrpc":"2.0","id":1}"#, "");
        let stamped = stamp_mcp_tenant(&message, "acme0001").expect("stamped");
        assert!(stamped.starts_with(&message), "the client's bytes go on as they were");
        let request = decoded(&stamped);
        assert_eq!(request.tenant, "acme0001");
        assert_eq!(request.payload, r#"{"jsonrpc":"2.0","id":1}"#);

        // An explicitly encoded empty tenant is no tenant: the stamp, appended
        // after it, is the value that wins.
        let mut explicit = mcp_request("{}", "");
        explicit.extend([0x12, 0x00]);
        let request = decoded(&stamp_mcp_tenant(&explicit, "acme0001").expect("stamped"));
        assert_eq!(request.tenant, "acme0001");
    }

    #[test]
    fn an_mcp_frame_naming_the_session_tenant_goes_on_unchanged() {
        let message = mcp_request("{}", "acme0001");
        assert_eq!(stamp_mcp_tenant(&message, "acme0001").expect("forwarded"), message);
    }

    /// Another tenant is refused, also when it is the last of two values (the
    /// one protobuf keeps) behind the session's own.
    #[test]
    fn an_mcp_frame_naming_another_tenant_is_refused() {
        let status = stamp_mcp_tenant(&mcp_request("{}", "beta0002"), "acme0001")
            .expect_err("another tenant");
        assert_eq!(status.code(), tonic::Code::PermissionDenied);
        assert!(
            !status.message().contains("beta0002"),
            "the client's value is not echoed: {}",
            status.message()
        );

        let mut smuggled = mcp_request("{}", "acme0001");
        smuggled.extend(mcp_request("", "beta0002"));
        assert_eq!(
            stamp_mcp_tenant(&smuggled, "acme0001").expect_err("last value wins").code(),
            tonic::Code::PermissionDenied
        );
    }

    #[test]
    fn a_frame_that_is_not_an_mcp_request_is_refused() {
        assert_eq!(
            stamp_mcp_tenant(&[0xff, 0xff], "acme0001").expect_err("malformed").code(),
            tonic::Code::InvalidArgument
        );
    }
}
