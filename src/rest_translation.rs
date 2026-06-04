use std::sync::Arc;

use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{FromRequestParts, State};
use axum::http::StatusCode;
use axum::response::sse::{Event, Sse};
use axum::response::IntoResponse;
use axum::routing::any;
use axum::Router;
use futures::{SinkExt, StreamExt};
use tokio::sync::RwLock;
use tokio::time::{timeout, Duration};
use tokio_stream::wrappers::ReceiverStream;
use uuid::Uuid;

use gateway_tacplus::s2sm::rest_dispatch::{self, AuthPolicy, RouteInfo, REST_ROOT_PATH, ROUTES};
use gateway_tacplus::s2sm::ServiceManager;
use gateway_tacplus::types::libs::jwk::jwk::Jwk as ProtoJwk;
use gateway_tacplus::types::libs::jwk::jwk::JwkUseType;
use gateway_tacplus::types::libs::key::key::KeyType;
use gateway_tacplus::types::libs::x509::x509::X509Cert;

use crate::auth::GatewayAuth;
use crate::proxy_grpc::{self, ProxyState};

const MAX_JSON_BODY_BYTES: usize = 10 * 1024 * 1024;

/// Application state for REST translation.
pub struct RestState {
    pub proxy: Arc<ProxyState>,
    pub sm: Arc<ServiceManager>,
    pub auth: Arc<GatewayAuth>,
    pub ca_certs: Arc<RwLock<Vec<X509Cert>>>,
    /// Public base URL (scheme + host) used as the OIDC `iss` claim and the
    /// base for jwks_uri / token_endpoint. Sourced from gateway config's
    /// external_hostnames at startup.
    pub issuer_url: String,
}

/// OIDC Discovery 1.0 document, hand-written with snake_case field names.
/// The generated `OpenIdConfiguration` proto-JSON serializer emits camelCase
/// (proto3 canonical JSON convention) which is not what the OIDC spec
/// requires. Until tacplus emits an RFC-compliant override for this type,
/// we hand-roll the discovery doc locally.
#[derive(serde::Serialize)]
struct OidcDiscoveryDoc<'a> {
    issuer: &'a str,
    jwks_uri: String,
    token_endpoint: String,
    response_types_supported: &'static [&'static str],
    grant_types_supported: &'static [&'static str],
    subject_types_supported: &'static [&'static str],
    id_token_signing_alg_values_supported: &'static [&'static str],
}

/// RFC 7517 / RFC 8037 compliant JWK. Hand-written because tacplus's
/// `jwks_to_api_json` helper has a bug: its `stringify_jwks_enums` only
/// converts INT enum values to strings, but tacplus's serde impl emits
/// enums as proto-name strings ("KEY_TYPE_OKP"), so the rewrite never
/// fires. Until that helper is fixed, we map manually here.
#[derive(serde::Serialize)]
struct PublicJwk {
    kty: &'static str,
    #[serde(rename = "use", skip_serializing_if = "Option::is_none")]
    use_: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    alg: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    kid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    crv: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    x: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    y: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    n: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    e: Option<String>,
}

#[derive(serde::Serialize)]
struct PublicJwks {
    keys: Vec<PublicJwk>,
}

fn proto_jwk_to_public(j: &ProtoJwk) -> Option<PublicJwk> {
    let kty = match KeyType::try_from(j.kty).ok()? {
        KeyType::Rsa => "RSA",
        KeyType::Ec => "EC",
        KeyType::Okp => "OKP",
        KeyType::Undefined => return None,
    };
    let use_ = match JwkUseType::try_from(j.r#use).ok()? {
        JwkUseType::Sig => Some("sig"),
        JwkUseType::Enc => Some("enc"),
        JwkUseType::Undefined => None,
    };
    let opt = |s: &str| {
        if s.is_empty() {
            None
        } else {
            Some(s.to_string())
        }
    };
    Some(PublicJwk {
        kty,
        use_,
        alg: opt(&j.alg),
        kid: opt(&j.kid),
        crv: opt(&j.crv),
        x: opt(&j.x),
        y: opt(&j.y),
        n: opt(&j.n),
        e: opt(&j.e),
    })
}

/// Build the REST router.
/// No auth middleware — all auth is handled by proxy_grpc.
pub fn router(state: Arc<RestState>) -> Router {
    let rest_route = format!("{}/{{*rest}}", REST_ROOT_PATH);
    Router::new()
        .route(&rest_route, any(rest_handler))
        .with_state(state)
}

/// REST→gRPC handler. Converts JSON to proto, delegates to proxy_grpc,
/// converts response back to JSON.
async fn rest_handler(
    State(state): State<Arc<RestState>>,
    request: axum::http::Request<axum::body::Body>,
) -> axum::response::Response {
    let (mut parts, body) = request.into_parts();
    let path = parts.uri.path().to_string();
    let req_method = parts.method.clone();

    tracing::debug!(path = %path, method = %req_method, "REST request");

    let auth_header_value = parts
        .headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    let request_id = parts
        .headers
        .get("x-request-id")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .unwrap_or_else(|| Uuid::new_v4().to_string());

    // Look up route.
    let route = ROUTES.iter().find(|r| r.http_path == path);
    let route = match route {
        Some(r) => r,
        None => {
            // Try SPIFFE path routing.
            let spiffe_path = path
                .strip_prefix(REST_ROOT_PATH)
                .and_then(|p| p.strip_prefix('/'))
                .unwrap_or("");
            if !spiffe_path.is_empty() {
                let endpoints = state
                    .proxy
                    .resolver
                    .health()
                    .get_endpoints_by_spiffe_path(spiffe_path);
                if !endpoints.is_empty() {
                    tracing::info!(path = %path, spiffe_path = %spiffe_path, request_id = %request_id, "SPIFFE path routing");
                    let body_bytes = match read_body_for_method(&req_method, body).await {
                        Ok(bytes) => bytes,
                        Err(response) => return response,
                    };
                    return dispatch_via_proxy(
                        &state,
                        &path,
                        &body_bytes,
                        auth_header_value.as_deref(),
                        false,
                    )
                    .await;
                }
            }
            tracing::warn!(path = %path, "no route found");
            return (
                StatusCode::NOT_FOUND,
                format!("{{\"error\":\"unknown route: {}\"}}", path),
            )
                .into_response();
        }
    };

    if route.client_streaming {
        if let Ok(ws) = WebSocketUpgrade::from_request_parts(&mut parts, &state).await {
            let state = Arc::clone(&state);
            let route = route;
            let auth_header = auth_header_value.clone();
            return ws
                .on_upgrade(move |socket| {
                    handle_websocket_stream(socket, state, route, auth_header, request_id)
                })
                .into_response();
        }
    }

    // Check HTTP method.
    if !route
        .http_methods
        .iter()
        .any(|m| m.eq_ignore_ascii_case(req_method.as_str()))
    {
        return (
            StatusCode::METHOD_NOT_ALLOWED,
            format!(
                "{{\"error\":\"method {} not allowed for {}\"}}",
                req_method, path
            ),
        )
            .into_response();
    }

    // Read body after WebSocket upgrade handling; upgrade requests do not carry
    // a JSON request body.
    let body_bytes = match read_body_for_method(&req_method, body).await {
        Ok(bytes) => bytes,
        Err(response) => return response,
    };

    // Gateway Mint special cases — served locally or proxied to kernel directly.
    if route.grpc_path.starts_with("/gateway.Mint/") {
        return handle_mint(
            route,
            &state,
            &body_bytes,
            auth_header_value.as_deref(),
            &request_id,
        )
        .await;
    }

    if route.server_streaming {
        dispatch_stream_via_proxy(
            &state,
            route.grpc_path,
            &body_bytes,
            auth_header_value.as_deref(),
        )
        .await
    } else {
        dispatch_via_proxy(
            &state,
            route.grpc_path,
            &body_bytes,
            auth_header_value.as_deref(),
            false,
        )
        .await
    }
}

async fn read_body_for_method(
    method: &axum::http::Method,
    body: axum::body::Body,
) -> Result<Vec<u8>, axum::response::Response> {
    if *method == axum::http::Method::GET {
        return Ok(b"{}".to_vec());
    }

    axum::body::to_bytes(body, MAX_JSON_BODY_BYTES)
        .await
        .map(|b| b.to_vec())
        .map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                format!("{{\"error\":\"failed to read request body: {}\"}}", e),
            )
                .into_response()
        })
}

/// Convert JSON to proto, frame as gRPC, delegate to proxy_grpc, convert response to JSON.
async fn dispatch_via_proxy(
    state: &RestState,
    grpc_path: &str,
    json_body: &[u8],
    auth_header: Option<&str>,
    _is_streaming: bool,
) -> axum::response::Response {
    // 1. Convert JSON to proto bytes.
    let proto_bytes =
        match gateway_tacplus::s2sm::proxy_dispatch::request_json_to_proto(grpc_path, json_body) {
            Ok(b) => b,
            Err(e) => {
                return (
                    StatusCode::BAD_REQUEST,
                    format!("{{\"error\":\"invalid request body: {}\"}}", e),
                )
                    .into_response();
            }
        };

    // 2. Frame as gRPC.
    let grpc_body = proxy_grpc::frame_grpc(&proto_bytes);

    // 3. Build gRPC request.
    let mut builder = http::Request::builder()
        .method(http::Method::POST)
        .uri(grpc_path)
        .header("content-type", "application/grpc+proto")
        .header("te", "trailers");

    if let Some(auth) = auth_header {
        builder = builder.header("authorization", auth);
    }

    let grpc_request = match builder.body(axum::body::Body::from(grpc_body)) {
        Ok(r) => r,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("{{\"error\":\"failed to build gRPC request: {}\"}}", e),
            )
                .into_response();
        }
    };

    // 4. Delegate to proxy_grpc.
    let response = proxy_grpc::handle(&state.proxy, grpc_request).await;

    // 5. Check for gRPC error.
    let grpc_status = response
        .headers()
        .get("grpc-status")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<i32>().ok())
        .unwrap_or(-1);

    if grpc_status > 0 {
        let grpc_message = response
            .headers()
            .get("grpc-message")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("unknown error")
            .to_string();
        let http_status = grpc_status_to_http(grpc_status);
        return (http_status, format!("{{\"error\":\"{}\"}}", grpc_message)).into_response();
    }

    // 6. Read response body, unframe gRPC, convert to JSON.
    let response_bytes = match axum::body::to_bytes(response.into_body(), MAX_JSON_BODY_BYTES).await
    {
        Ok(b) => b,
        Err(e) => {
            return (
                StatusCode::BAD_GATEWAY,
                format!("{{\"error\":\"failed to read backend response: {}\"}}", e),
            )
                .into_response();
        }
    };

    if response_bytes.len() < 5 {
        // Empty response (e.g., google.protobuf.Empty).
        return (
            StatusCode::OK,
            [(
                axum::http::header::CONTENT_TYPE,
                "application/json".to_string(),
            )],
            "{}".to_string(),
        )
            .into_response();
    }

    // Unframe gRPC: skip 5-byte header.
    if response_bytes[0] != 0 {
        return (
            StatusCode::BAD_GATEWAY,
            "{\"error\":\"compressed gRPC response frames are not supported by REST translation\"}"
                .to_string(),
        )
            .into_response();
    }
    let msg_len = u32::from_be_bytes([
        response_bytes[1],
        response_bytes[2],
        response_bytes[3],
        response_bytes[4],
    ]) as usize;
    if msg_len > MAX_JSON_BODY_BYTES || response_bytes.len() != 5 + msg_len {
        return (
            StatusCode::BAD_GATEWAY,
            "{\"error\":\"malformed gRPC response frame\"}".to_string(),
        )
            .into_response();
    }
    let proto_end = 5 + msg_len;
    let response_proto = &response_bytes[5..proto_end];

    match gateway_tacplus::s2sm::proxy_dispatch::response_to_json(grpc_path, response_proto) {
        Ok(json) => (
            StatusCode::OK,
            [(
                axum::http::header::CONTENT_TYPE,
                "application/json".to_string(),
            )],
            json,
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("{{\"error\":\"failed to serialize response: {}\"}}", e),
        )
            .into_response(),
    }
}

/// SSE streaming: delegate to proxy_grpc, read response frames as SSE events.
async fn dispatch_stream_via_proxy(
    state: &RestState,
    grpc_path: &str,
    json_body: &[u8],
    auth_header: Option<&str>,
) -> axum::response::Response {
    // Convert JSON to proto, frame as gRPC, build request.
    let proto_bytes =
        match gateway_tacplus::s2sm::proxy_dispatch::request_json_to_proto(grpc_path, json_body) {
            Ok(b) => b,
            Err(e) => {
                return (
                    StatusCode::BAD_REQUEST,
                    format!("{{\"error\":\"invalid request body: {}\"}}", e),
                )
                    .into_response();
            }
        };

    let grpc_body = proxy_grpc::frame_grpc(&proto_bytes);

    let mut builder = http::Request::builder()
        .method(http::Method::POST)
        .uri(grpc_path)
        .header("content-type", "application/grpc+proto")
        .header("te", "trailers");

    if let Some(auth) = auth_header {
        builder = builder.header("authorization", auth);
    }

    let grpc_request = match builder.body(axum::body::Body::from(grpc_body)) {
        Ok(r) => r,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("{{\"error\":\"failed to build gRPC request: {}\"}}", e),
            )
                .into_response();
        }
    };

    // Delegate to proxy_grpc.
    let response = proxy_grpc::handle(&state.proxy, grpc_request).await;

    // Check for gRPC error before streaming.
    let grpc_status = response
        .headers()
        .get("grpc-status")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<i32>().ok())
        .unwrap_or(-1);

    if grpc_status > 0 {
        let grpc_message = response
            .headers()
            .get("grpc-message")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("unknown error")
            .to_string();
        let http_status = grpc_status_to_http(grpc_status);
        return (http_status, format!("{{\"error\":\"{}\"}}", grpc_message)).into_response();
    }

    // Stream response frames as SSE events.
    let grpc_path_owned = grpc_path.to_string();
    let body = response.into_body();

    let sse_stream = GrpcFrameStream::new(body).map(move |frame_result| match frame_result {
        Ok(proto_bytes) => {
            let json = gateway_tacplus::s2sm::proxy_dispatch::response_to_json(
                &grpc_path_owned,
                &proto_bytes,
            )
            .unwrap_or_else(|e| format!("{{\"error\":\"{}\"}}", e));
            Ok::<_, std::convert::Infallible>(Event::default().data(json))
        }
        Err(e) => Ok(Event::default()
            .event("error")
            .data(format!("{{\"error\":\"{}\"}}", e))),
    });

    Sse::new(sse_stream).into_response()
}

async fn handle_websocket_stream(
    socket: WebSocket,
    state: Arc<RestState>,
    route: &'static RouteInfo,
    header_auth: Option<String>,
    fallback_request_id: String,
) {
    let (mut ws_sender, mut ws_receiver) = socket.split();

    let first = match timeout(Duration::from_secs(10), ws_receiver.next()).await {
        Ok(Some(Ok(Message::Text(text)))) => text,
        Ok(Some(Ok(Message::Close(_)))) | Ok(None) => return,
        Ok(Some(Ok(_))) => {
            let _ = ws_sender
                .send(ws_error("first WebSocket message must be text"))
                .await;
            return;
        }
        Ok(Some(Err(e))) => {
            tracing::warn!(error = %e, "WebSocket receive failed before start");
            return;
        }
        Err(_) => {
            let _ = ws_sender
                .send(ws_error("timed out waiting for WebSocket start"))
                .await;
            return;
        }
    };

    let mut backend_auth_header = header_auth;
    let mut request_id = fallback_request_id;
    let mut initial_frame: Option<WsDataFrame> = None;

    match serde_json::from_str::<serde_json::Value>(first.as_str()) {
        Ok(value) if value.get("type").and_then(|v| v.as_str()) == Some("start") => {
            if let Some(auth) = value.get("authorization").and_then(|v| v.as_str()) {
                backend_auth_header = Some(auth.to_string());
            }
            if let Some(id) = value.get("requestId").and_then(|v| v.as_str()) {
                request_id = id.to_string();
            }
        }
        _ => match parse_ws_data_frame(route, first.as_str()) {
            Ok(frame) => {
                if backend_auth_header.is_none() {
                    backend_auth_header = frame.auth_header.clone();
                }
                initial_frame = Some(frame);
            }
            Err(e) => {
                let _ = ws_sender.send(ws_error(e)).await;
                let _ = ws_sender.close().await;
                return;
            }
        },
    }

    if !matches!(route.auth_policy, AuthPolicy::NoAuth) && backend_auth_header.is_none() {
        let _ = ws_sender
            .send(ws_error(
                "authenticated WebSocket streams require start.authorization or first message authorization",
            ))
            .await;
        let _ = ws_sender.close().await;
        return;
    }

    let mut builder = http::Request::builder()
        .method(http::Method::POST)
        .uri(route.grpc_path)
        .header("content-type", "application/grpc+proto")
        .header("te", "trailers");

    if let Some(auth) = backend_auth_header.as_deref() {
        builder = builder.header("authorization", auth);
    }
    if let Ok(id) = request_id.parse::<http::HeaderValue>() {
        builder = builder.header("x-request-id", id);
    }

    let (body_tx, body_rx) = tokio::sync::mpsc::channel::<Result<bytes::Bytes, std::io::Error>>(16);
    let reader_state = Arc::clone(&state);

    tokio::spawn(async move {
        if let Some(frame) = initial_frame {
            if send_ws_json_frame(&body_tx, &reader_state, route, frame)
                .await
                .is_err()
            {
                return;
            }
        }

        while let Some(msg) = ws_receiver.next().await {
            match msg {
                Ok(Message::Text(text)) => {
                    if is_ws_complete(text.as_str()) {
                        break;
                    }
                    let frame = match parse_ws_data_frame(route, text.as_str()) {
                        Ok(frame) => frame,
                        Err(e) => {
                            let _ = send_ws_body_error(&body_tx, e).await;
                            return;
                        }
                    };
                    if send_ws_json_frame(&body_tx, &reader_state, route, frame)
                        .await
                        .is_err()
                    {
                        return;
                    };
                }
                Ok(Message::Close(_)) | Err(_) => break,
                Ok(Message::Ping(_)) | Ok(Message::Pong(_)) => {}
                Ok(Message::Binary(_)) => {
                    let _ =
                        send_ws_body_error(&body_tx, "binary WebSocket messages are not supported")
                            .await;
                    return;
                }
            }
        }
    });

    let grpc_request =
        match builder.body(axum::body::Body::from_stream(ReceiverStream::new(body_rx))) {
            Ok(r) => r,
            Err(e) => {
                let _ = ws_sender
                    .send(ws_error(format!("failed to build gRPC request: {}", e)))
                    .await;
                return;
            }
        };

    let response = proxy_grpc::handle_prevalidated_stream(&state.proxy, grpc_request).await;
    let grpc_status = response
        .headers()
        .get("grpc-status")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<i32>().ok())
        .unwrap_or(-1);

    if grpc_status > 0 {
        let grpc_message = response
            .headers()
            .get("grpc-message")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("unknown error");
        let _ = ws_sender.send(ws_error(grpc_message)).await;
        let _ = ws_sender.close().await;
        return;
    }

    let grpc_path = route.grpc_path.to_string();
    let mut frames = GrpcFrameStream::new(response.into_body());
    while let Some(frame) = frames.next().await {
        match frame {
            Ok(proto_bytes) => {
                let json = gateway_tacplus::s2sm::proxy_dispatch::response_to_json(
                    &grpc_path,
                    &proto_bytes,
                )
                .unwrap_or_else(|e| format!("{{\"error\":\"{}\"}}", e));
                if ws_sender.send(Message::Text(json.into())).await.is_err() {
                    return;
                }
            }
            Err(e) => {
                let _ = ws_sender.send(ws_error(e)).await;
                let _ = ws_sender.close().await;
                return;
            }
        }
    }

    let _ = ws_sender.close().await;
}

struct WsDataFrame {
    json_bytes: Vec<u8>,
    auth_header: Option<String>,
}

fn parse_ws_data_frame(route: &RouteInfo, text: &str) -> Result<WsDataFrame, String> {
    let value = serde_json::from_str::<serde_json::Value>(text)
        .map_err(|e| format!("invalid WebSocket JSON frame: {e}"))?;

    if let Some(frame_type) = value.get("type").and_then(|v| v.as_str()) {
        return match frame_type {
            "message" => {
                let payload = value
                    .get("message")
                    .or_else(|| value.get("payload"))
                    .or_else(|| value.get("body"))
                    .ok_or_else(|| {
                        "WebSocket message frame requires message, payload, or body".to_string()
                    })?;
                let json_bytes = serde_json::to_vec(payload)
                    .map_err(|e| format!("failed to encode WebSocket message payload: {e}"))?;
                let auth_header = value
                    .get("authorization")
                    .and_then(|v| v.as_str())
                    .map(str::to_string);
                Ok(WsDataFrame {
                    json_bytes,
                    auth_header,
                })
            }
            "start" => Err("start frame is only valid as the first WebSocket message".to_string()),
            "complete" => Err("complete frame must not carry a request payload".to_string()),
            other => Err(format!("unknown WebSocket frame type: {other}")),
        };
    }

    if matches!(route.auth_policy, AuthPolicy::NoAuth) {
        Ok(WsDataFrame {
            json_bytes: text.as_bytes().to_vec(),
            auth_header: None,
        })
    } else {
        Err(
            "authenticated WebSocket data messages must use a type=message envelope with authorization"
                .to_string(),
        )
    }
}

fn is_ws_complete(text: &str) -> bool {
    serde_json::from_str::<serde_json::Value>(text)
        .ok()
        .and_then(|v| v.get("type").and_then(|t| t.as_str()).map(str::to_string))
        .as_deref()
        == Some("complete")
}

async fn send_ws_json_frame(
    tx: &tokio::sync::mpsc::Sender<Result<bytes::Bytes, std::io::Error>>,
    state: &RestState,
    route: &RouteInfo,
    frame: WsDataFrame,
) -> Result<(), ()> {
    let proto_bytes = match gateway_tacplus::s2sm::proxy_dispatch::request_json_to_proto(
        route.grpc_path,
        &frame.json_bytes,
    ) {
        Ok(bytes) => bytes,
        Err(e) => {
            let _ = send_ws_body_error(tx, format!("invalid WebSocket request body: {e}")).await;
            return Err(());
        }
    };

    if let Err(status) =
        gateway_tacplus::s2sm::proxy_dispatch::validate_request(route.grpc_path, &proto_bytes)
    {
        let _ = send_ws_body_error(tx, status.to_string()).await;
        return Err(());
    }

    let target_namespace = match gateway_tacplus::s2sm::proxy_dispatch::request_target_namespace(
        route.grpc_path,
        &proto_bytes,
    ) {
        Ok(ns) => ns,
        Err(status) => {
            let _ = send_ws_body_error(tx, status.to_string()).await;
            return Err(());
        }
    };

    let entitlement_service = route.entitlement_service.unwrap_or(route.service_id);
    if let Err((_, msg)) = state
        .auth
        .validate_c2s_with_target_namespace(
            route.auth_policy,
            route.service_id,
            entitlement_service,
            route.grpc_path,
            frame.auth_header.as_deref(),
            target_namespace.as_deref(),
        )
        .await
    {
        let _ = send_ws_body_error(tx, msg).await;
        return Err(());
    }

    tx.send(Ok(bytes::Bytes::from(proxy_grpc::frame_grpc(&proto_bytes))))
        .await
        .map_err(|_| ())
}

async fn send_ws_body_error(
    tx: &tokio::sync::mpsc::Sender<Result<bytes::Bytes, std::io::Error>>,
    message: impl Into<String>,
) -> Result<(), ()> {
    tx.send(Err(std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        message.into(),
    )))
    .await
    .map_err(|_| ())
}

fn ws_error(message: impl AsRef<str>) -> Message {
    Message::Text(
        serde_json::json!({ "error": message.as_ref() })
            .to_string()
            .into(),
    )
}

/// Stream that reads gRPC frames from an HTTP body and yields proto payloads.
struct GrpcFrameStream {
    body: axum::body::Body,
    buffer: bytes::BytesMut,
}

impl GrpcFrameStream {
    fn new(body: axum::body::Body) -> Self {
        Self {
            body,
            buffer: bytes::BytesMut::new(),
        }
    }
}

impl futures::Stream for GrpcFrameStream {
    type Item = Result<Vec<u8>, String>;

    fn poll_next(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        use http_body::Body as HttpBody;
        let this = self.get_mut();

        loop {
            // Try to extract a complete frame from the buffer.
            if this.buffer.len() >= 5 {
                if this.buffer[0] != 0 {
                    return std::task::Poll::Ready(Some(Err(
                        "compressed gRPC response frames are not supported by REST translation"
                            .to_string(),
                    )));
                }
                let msg_len = u32::from_be_bytes([
                    this.buffer[1],
                    this.buffer[2],
                    this.buffer[3],
                    this.buffer[4],
                ]) as usize;
                if msg_len > MAX_JSON_BODY_BYTES {
                    return std::task::Poll::Ready(Some(Err(
                        "gRPC response message exceeds REST translation limit".to_string(),
                    )));
                }
                let frame_len = 5 + msg_len;
                if this.buffer.len() >= frame_len {
                    let frame = this.buffer.split_to(frame_len);
                    let proto = frame[5..].to_vec();
                    return std::task::Poll::Ready(Some(Ok(proto)));
                }
            }

            // Need more data from the body.
            let pinned = std::pin::Pin::new(&mut this.body);
            match pinned.poll_frame(cx) {
                std::task::Poll::Ready(Some(Ok(frame))) => {
                    if let Some(data) = frame.data_ref() {
                        this.buffer.extend_from_slice(data);
                        if this.buffer.len() > 5 + MAX_JSON_BODY_BYTES {
                            return std::task::Poll::Ready(Some(Err(
                                "incomplete gRPC response frame exceeds REST translation limit"
                                    .to_string(),
                            )));
                        }
                    }
                }
                std::task::Poll::Ready(Some(Err(e))) => {
                    return std::task::Poll::Ready(Some(Err(format!("body read error: {}", e))));
                }
                std::task::Poll::Ready(None) => {
                    if !this.buffer.is_empty() {
                        let remaining = this.buffer.len();
                        this.buffer.clear();
                        return std::task::Poll::Ready(Some(Err(format!(
                            "incomplete trailing gRPC response frame: {} bytes",
                            remaining
                        ))));
                    }
                    return std::task::Poll::Ready(None);
                }
                std::task::Poll::Pending => {
                    return std::task::Poll::Pending;
                }
            }
        }
    }
}

/// Handle Mint RPCs: OpenIdConfig/Jwks/PublicCa locally, TokenMint/X509Mint via kernel.
async fn handle_mint(
    route: &RouteInfo,
    state: &RestState,
    body: &[u8],
    auth_header: Option<&str>,
    request_id: &str,
) -> axum::response::Response {
    match route.grpc_path {
        "/gateway.Mint/OpenIdConfig" => {
            // issuer is the gateway's configured public URL (not the Host header,
            // which can be lost across HTTP/2 / TLS termination boundaries).
            let base = &state.issuer_url;
            let config = OidcDiscoveryDoc {
                issuer: base,
                jwks_uri: format!("{}{}/.well-known/jwks.json", base, REST_ROOT_PATH),
                token_endpoint: format!("{}{}/gateway/TokenMint", base, REST_ROOT_PATH),
                response_types_supported: &["token"],
                grant_types_supported: &["urn:ietf:params:oauth:grant-type:token-exchange"],
                subject_types_supported: &["public"],
                id_token_signing_alg_values_supported: &["EdDSA"],
            };
            json_response(&config)
        }
        "/gateway.Mint/Jwks" => {
            let keys: Vec<PublicJwk> = state
                .auth
                .get_raw_jwks()
                .iter()
                .filter_map(proto_jwk_to_public)
                .collect();
            json_response(&PublicJwks { keys })
        }
        "/gateway.Mint/TokenMint" => {
            tracing::info!(request_id = %request_id, "routing TokenMint to mint");
            let req =
                match gateway_tacplus::types::common::tokenrequest::token_mint_request_from_json(
                    body,
                ) {
                    Ok(r) => r,
                    Err(e) => {
                        return (
                            StatusCode::BAD_REQUEST,
                            format!("{{\"error\":\"invalid request body: {}\"}}", e),
                        )
                            .into_response()
                    }
                };
            let grpc_req = rest_dispatch::with_metadata(req, auth_header, request_id);
            // TokenMint is proxied to kernel.Mint (the sole token authority).
            match state
                .sm
                .s2s()
                .kernel()
                .mint_client()
                .token_mint(grpc_req)
                .await
            {
                Ok(resp) => json_response(&resp.into_inner()),
                Err(status) => {
                    tracing::warn!(request_id = %request_id, status = %status, "mint token error");
                    let (code, msg) = rest_dispatch::grpc_err(status);
                    (code, msg).into_response()
                }
            }
        }
        "/gateway.Mint/X509Mint" => {
            let req =
                match gateway_tacplus::types::common::tokenrequest::x509_mint_request_from_json(
                    body,
                ) {
                    Ok(r) => r,
                    Err(e) => {
                        return (
                            StatusCode::BAD_REQUEST,
                            format!("{{\"error\":\"invalid request body: {}\"}}", e),
                        )
                            .into_response()
                    }
                };
            let grpc_req = rest_dispatch::with_metadata(req, auth_header, request_id);
            // X509Mint is proxied to kernel.Mint (the sole cert signing authority).
            match state
                .sm
                .s2s()
                .kernel()
                .mint_client()
                .x509_mint(grpc_req)
                .await
            {
                Ok(resp) => json_response(&resp.into_inner()),
                Err(status) => {
                    tracing::warn!(request_id = %request_id, status = %status, "kernel x509 mint error");
                    let (code, msg) = rest_dispatch::grpc_err(status);
                    (code, msg).into_response()
                }
            }
        }
        "/gateway.Mint/PublicCa" => {
            let certs = state.ca_certs.read().await;
            let items: Vec<serde_json::Value> = certs
                .iter()
                .map(|c| serde_json::json!({"id": c.id, "base64": c.base64}))
                .collect();
            let resp = serde_json::json!({"certs": items});
            (
                StatusCode::OK,
                [(
                    axum::http::header::CONTENT_TYPE,
                    "application/json".to_string(),
                )],
                resp.to_string(),
            )
                .into_response()
        }
        _ => (
            StatusCode::NOT_FOUND,
            format!("{{\"error\":\"unknown mint route: {}\"}}", route.grpc_path),
        )
            .into_response(),
    }
}

/// Serialize a value to a JSON HTTP response.
fn json_response<T: serde::Serialize>(value: &T) -> axum::response::Response {
    match serde_json::to_string(value) {
        Ok(json) => (
            StatusCode::OK,
            [(
                axum::http::header::CONTENT_TYPE,
                "application/json".to_string(),
            )],
            json,
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("{{\"error\":\"failed to serialize response: {}\"}}", e),
        )
            .into_response(),
    }
}

/// Map gRPC status code to HTTP status code for REST error responses.
fn grpc_status_to_http(grpc_status: i32) -> StatusCode {
    match grpc_status {
        3 => StatusCode::BAD_REQUEST,          // INVALID_ARGUMENT
        5 => StatusCode::NOT_FOUND,            // NOT_FOUND
        7 => StatusCode::FORBIDDEN,            // PERMISSION_DENIED
        12 => StatusCode::NOT_IMPLEMENTED,     // UNIMPLEMENTED
        14 => StatusCode::SERVICE_UNAVAILABLE, // UNAVAILABLE
        16 => StatusCode::UNAUTHORIZED,        // UNAUTHENTICATED
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    }
}
