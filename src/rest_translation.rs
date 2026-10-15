use std::sync::Arc;

use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{FromRequestParts, State};
use axum::http::StatusCode;
use axum::response::sse::{Event, Sse};
use axum::response::IntoResponse;
use axum::routing::{any, MethodRouter};
use axum::Router;
use futures::{SinkExt, StreamExt};
use tokio::sync::mpsc;
use tokio::time::{timeout, Duration};
use tokio_stream::wrappers::ReceiverStream;
use uuid::Uuid;

use gateway_model::s2sm::rest_dispatch::{self, AuthPolicy, RouteInfo, ROUTES};
use gateway_model::s2sm::ServiceManager;
use gateway_model::types::sys::jwk::jwk::Jwk as ProtoJwk;
use gateway_model::types::sys::jwk::jwk::JwkUseType;
use gateway_model::types::sys::key::key::KeyType;
use gateway_model::types::sys::x509::x509::X509Cert;

use crate::auth::GatewayAuth;
use crate::proxy_grpc::{self, ProxyState};

const MAX_JSON_BODY_BYTES: usize = 10 * 1024 * 1024;
const ID_TOKEN_SIGNING_ALGS_SUPPORTED: &[&str] = &["EdDSA", "ES256"];

fn is_mint_token_grpc_path(path: &str) -> bool {
    matches!(path, "/gateway.Mint/MintToken" | "/gateway.Mint/TokenMint")
}

fn is_mint_x509_grpc_path(path: &str) -> bool {
    matches!(
        path,
        "/gateway.Mint/MintX509Cert" | "/gateway.Mint/X509Mint"
    )
}

/// Application state for REST translation.
pub struct RestState {
    pub proxy: Arc<ProxyState>,
    pub sm: Arc<ServiceManager>,
    pub auth: Arc<GatewayAuth>,
    /// The CA that signed gateway's external TLS cert, from gateway config —
    /// exactly what `mint::GatewayMintService` serves on the native gRPC
    /// `ListPublicCa`. The REST path used to serve kernel's `CaState` signing
    /// CAs here instead: internal cluster trust material, on a `NoAuth` route,
    /// and the wrong answer to the question `ListPublicCa` asks. Both paths
    /// now answer from the same config value.
    pub root_ca: Vec<X509Cert>,
    /// Public OIDC issuer URL used as the JWT `iss` claim and discovery
    /// issuer. Sourced from gateway config's external_hostnames at startup.
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
///
/// REST paths sit at the origin root, beside the SPA, so there is no prefix to
/// mount a catch-all under: every generated path is registered exactly, and
/// anything unclaimed reaches `fallback`.
pub fn router(state: Arc<RestState>) -> Router {
    rest_routes(Router::new(), any(rest_handler))
        .fallback(fallback)
        .with_state(state)
}

/// One exact route per generated `http_path`. A `rest_path` alias is its own
/// ROUTES entry, so it is registered here too. Empty paths are RPCs with no
/// REST surface.
fn rest_routes<S: Clone + Send + Sync + 'static>(
    router: Router<S>,
    handler: MethodRouter<S>,
) -> Router<S> {
    ROUTES
        .iter()
        .map(|r| r.http_path)
        .filter(|p| !p.is_empty())
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .fold(router, |router, path| router.route(path, handler.clone()))
}

/// Requests no REST route claimed: SPIFFE-path routing first, then the SPA.
async fn fallback(
    State(state): State<Arc<RestState>>,
    request: axum::http::Request<axum::body::Body>,
) -> axum::response::Response {
    let (parts, body) = request.into_parts();
    let path = parts.uri.path();
    let spiffe_path = path.trim_start_matches('/');
    if !spiffe_path.is_empty() {
        let endpoints = state
            .proxy
            .resolver
            .health()
            .get_endpoints_by_spiffe_path(spiffe_path);
        if !endpoints.is_empty() {
            let auth_header_value = parts
                .headers
                .get("authorization")
                .and_then(|v| v.to_str().ok());
            let request_id = parts
                .headers
                .get("x-request-id")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string())
                .unwrap_or_else(|| Uuid::new_v4().to_string());
            tracing::info!(path = %path, spiffe_path = %spiffe_path, request_id = %request_id, "SPIFFE path routing");
            let body_bytes = match read_body_for_method(&parts.method, body).await {
                Ok(bytes) => bytes,
                Err(response) => return response,
            };
            return dispatch_via_proxy(
                &state.proxy,
                path,
                &body_bytes,
                auth_header_value,
                &request_id,
                false,
            )
            .await;
        }
    }
    spa_or_not_found(&parts.method, parts.uri, &parts.headers).await
}

/// The SPA answers browser navigation (`GET`/`HEAD`). Any other method on an
/// unknown path is an API call that missed, and gets a JSON 404 rather than
/// `index.html`.
async fn spa_or_not_found(
    method: &axum::http::Method,
    uri: axum::http::Uri,
    headers: &axum::http::HeaderMap,
) -> axum::response::Response {
    if method == axum::http::Method::GET || method == axum::http::Method::HEAD {
        return crate::spa::spa_handler(uri, headers).await;
    }
    tracing::warn!(path = %uri.path(), "no route found");
    (
        StatusCode::NOT_FOUND,
        format!("{{\"error\":\"unknown route: {}\"}}", uri.path()),
    )
        .into_response()
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

    // Look up route. Only registered paths reach this handler (`rest_routes`).
    let Some(route) = ROUTES.iter().find(|r| r.http_path == path) else {
        tracing::warn!(path = %path, "no route found");
        return (
            StatusCode::NOT_FOUND,
            format!("{{\"error\":\"unknown route: {}\"}}", path),
        )
            .into_response();
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
    let body_bytes = match authorize_then_read_body(
        &state.auth,
        route,
        auth_header_value.as_deref(),
        &req_method,
        body,
    )
    .await
    {
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
        dispatch_unary(
            &state.proxy,
            route,
            parts.headers.get(axum::http::header::CONTENT_TYPE),
            body_bytes,
            auth_header_value.as_deref(),
            &request_id,
        )
        .await
    }
}

/// One unary REST call. A `form_body` route's form-encoded body is decoded to
/// JSON first, and a `redirect_field` route's answer becomes its 303; both by
/// the generated `rest_dispatch` seams, so every other route is served exactly
/// as the JSON path always served it.
pub(crate) async fn dispatch_unary(
    proxy: &ProxyState,
    route: &RouteInfo,
    content_type: Option<&axum::http::HeaderValue>,
    body: Vec<u8>,
    auth_header: Option<&str>,
    request_id: &str,
) -> axum::response::Response {
    let json_body = match rest_dispatch::form_body_to_json(route, content_type, body).await {
        Ok(json) => json,
        Err((status, error_body)) => {
            return (
                status,
                [(
                    axum::http::header::CONTENT_TYPE,
                    "application/json".to_string(),
                )],
                error_body,
            )
                .into_response();
        }
    };
    let response = dispatch_via_proxy(
        proxy,
        route.grpc_path,
        &json_body,
        auth_header,
        request_id,
        false,
    )
    .await;
    // An error stays the JSON error it already is: there is no URL to send the
    // browser to.
    if route.redirect_field.is_none() || response.status() != StatusCode::OK {
        return response;
    }
    let response_json = match axum::body::to_bytes(response.into_body(), MAX_JSON_BODY_BYTES).await {
        Ok(bytes) => bytes,
        Err(e) => {
            return json_error_response(
                StatusCode::BAD_GATEWAY,
                format!("failed to read response body: {e}"),
            );
        }
    };
    rest_dispatch::redirect_response(route, &String::from_utf8_lossy(&response_json))
        .expect("redirect_response answers every route with a redirect_field")
}

/// Verify the caller's token on headers alone, then read the request body.
///
/// The token check has to come first: reading the body buffers up to
/// `MAX_JSON_BODY_BYTES` and the JSON→proto conversion that follows decodes all
/// of it, and neither is work an unauthenticated caller may make the gateway
/// do. This mirrors the ordering `proxy_grpc` uses on both of its paths; the
/// namespace-aware half of the check still runs there, once the message is
/// decoded.
async fn authorize_then_read_body(
    auth: &GatewayAuth,
    route: &RouteInfo,
    auth_header: Option<&str>,
    method: &axum::http::Method,
    body: axum::body::Body,
) -> Result<Vec<u8>, axum::response::Response> {
    let (service_id, entitlement_service) = proxy_grpc::route_identity(route);
    if let Err((code, msg)) = auth
        .validate_c2s(
            route.auth_policy,
            service_id,
            entitlement_service,
            route.grpc_path,
            auth_header,
        )
        .await
    {
        tracing::warn!(path = %route.http_path, error = %msg, "REST auth rejected before body read");
        return Err(json_error_response(code, msg));
    }

    read_body_for_method(method, body).await
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

#[derive(Debug)]
struct GrpcBodyError {
    grpc_status: Option<i32>,
    message: String,
}

impl GrpcBodyError {
    fn transport(message: impl Into<String>) -> Self {
        Self {
            grpc_status: None,
            message: message.into(),
        }
    }

    fn grpc(grpc_status: i32, message: impl Into<String>) -> Self {
        Self {
            grpc_status: Some(grpc_status),
            message: message.into(),
        }
    }
}

fn json_error_body(message: impl AsRef<str>) -> String {
    serde_json::json!({ "error": message.as_ref() }).to_string()
}

fn json_error_response(status: StatusCode, message: impl AsRef<str>) -> axum::response::Response {
    (
        status,
        [(
            axum::http::header::CONTENT_TYPE,
            "application/json".to_string(),
        )],
        json_error_body(message),
    )
        .into_response()
}

fn grpc_message_from_headers(headers: &http::HeaderMap) -> String {
    headers
        .get("grpc-message")
        .and_then(|v| v.to_str().ok())
        .filter(|s| !s.is_empty())
        .unwrap_or("unknown gRPC error")
        .to_string()
}

fn grpc_error_from_headers(headers: &http::HeaderMap) -> Option<GrpcBodyError> {
    let status_value = headers.get("grpc-status")?;
    let grpc_status = status_value
        .to_str()
        .ok()
        .and_then(|v| v.parse::<i32>().ok());
    let Some(grpc_status) = grpc_status else {
        return Some(GrpcBodyError::transport("malformed grpc-status header"));
    };
    if grpc_status <= 0 {
        return None;
    }
    Some(GrpcBodyError::grpc(
        grpc_status,
        grpc_message_from_headers(headers),
    ))
}

fn grpc_error_response_from_headers(headers: &http::HeaderMap) -> Option<axum::response::Response> {
    grpc_error_from_headers(headers).map(grpc_body_error_response)
}

fn grpc_body_error_response(error: GrpcBodyError) -> axum::response::Response {
    let status = error
        .grpc_status
        .map(grpc_status_to_http)
        .unwrap_or(StatusCode::BAD_GATEWAY);
    json_error_response(status, error.message)
}

async fn read_grpc_response_body(mut body: axum::body::Body) -> Result<Vec<u8>, GrpcBodyError> {
    use http_body_util::BodyExt as _;

    let mut bytes = Vec::new();
    while let Some(frame_result) = body.frame().await {
        let frame =
            frame_result.map_err(|e| GrpcBodyError::transport(format!("body read error: {e}")))?;
        if let Some(data) = frame.data_ref() {
            if bytes.len().saturating_add(data.len()) > 5 + MAX_JSON_BODY_BYTES {
                return Err(GrpcBodyError::transport(
                    "gRPC response exceeds REST translation limit",
                ));
            }
            bytes.extend_from_slice(data);
        }
        if let Some(trailers) = frame.trailers_ref() {
            if let Some(error) = grpc_error_from_headers(trailers) {
                return Err(error);
            }
        }
    }
    Ok(bytes)
}

/// Convert JSON to proto, frame as gRPC, delegate to proxy_grpc, convert response to JSON.
async fn dispatch_via_proxy(
    proxy: &ProxyState,
    grpc_path: &str,
    json_body: &[u8],
    auth_header: Option<&str>,
    request_id: &str,
    _is_streaming: bool,
) -> axum::response::Response {
    // 1. Convert JSON to proto bytes.
    let proto_bytes =
        match gateway_model::s2sm::proxy_dispatch::request_json_to_proto(grpc_path, json_body) {
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

    // Forward the caller's x-request-id so downstream handlers (accounting,
    // tracing) can join back to this call. Without this the backend never
    // sees the header at all and every accounting/trace record is emitted
    // with an empty request_id — see the accounting join design.
    if let Ok(id) = http::HeaderValue::from_str(request_id) {
        builder = builder.header("x-request-id", id);
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
    let response = proxy_grpc::handle(proxy, grpc_request).await;

    // 5. Check for headers-only gRPC errors before reading the body.
    if let Some(error_response) = grpc_error_response_from_headers(response.headers()) {
        return error_response;
    }

    // 6. Read response body and trailers, unframe gRPC, convert to JSON.
    let response_bytes = match read_grpc_response_body(response.into_body()).await {
        Ok(b) => b,
        Err(e) => return grpc_body_error_response(e),
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

    match gateway_model::s2sm::proxy_dispatch::response_to_json(grpc_path, response_proto) {
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
        match gateway_model::s2sm::proxy_dispatch::request_json_to_proto(grpc_path, json_body) {
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

    // Check for headers-only gRPC errors before streaming.
    if let Some(error_response) = grpc_error_response_from_headers(response.headers()) {
        return error_response;
    }

    // Stream response frames as SSE events.
    let grpc_path_owned = grpc_path.to_string();
    let body = response.into_body();

    let sse_stream = futures::stream::unfold(
        (GrpcFrameStream::new(body), grpc_path_owned, false),
        |(mut frames, grpc_path, done)| async move {
            if done {
                return None;
            }
            match frames.next().await {
                Some(Ok(proto_bytes)) => {
                    match gateway_model::s2sm::proxy_dispatch::response_to_json(
                        &grpc_path,
                        &proto_bytes,
                    ) {
                        Ok(json) => Some((
                            Ok::<_, std::convert::Infallible>(Event::default().data(json)),
                            (frames, grpc_path, false),
                        )),
                        Err(e) => Some((
                            Ok(Event::default()
                                .event("error")
                                .data(json_error_body(format!(
                                    "failed to serialize response: {e}"
                                )))),
                            (frames, grpc_path, true),
                        )),
                    }
                }
                Some(Err(e)) => Some((
                    Ok(Event::default().event("error").data(json_error_body(e))),
                    (frames, grpc_path, true),
                )),
                None => None,
            }
        },
    );

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
            if let Some(auth) = value
                .get("authorization")
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty())
            {
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

    if let Err(message) =
        authorize_ws_stream(&state.auth, route, backend_auth_header.as_deref()).await
    {
        let _ = ws_sender.send(ws_error(message)).await;
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

    let (body_tx, body_rx) = mpsc::channel::<Result<bytes::Bytes, std::io::Error>>(16);
    let (reader_error_tx, mut reader_error_rx) = mpsc::channel::<String>(1);
    let reader_state = Arc::clone(&state);

    let reader_task = tokio::spawn(async move {
        if let Some(frame) = initial_frame {
            if forward_ws_json_frame(&body_tx, &reader_error_tx, &reader_state, route, frame)
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
                            let _ = send_ws_reader_error(&reader_error_tx, e).await;
                            return;
                        }
                    };
                    if forward_ws_json_frame(
                        &body_tx,
                        &reader_error_tx,
                        &reader_state,
                        route,
                        frame,
                    )
                    .await
                    .is_err()
                    {
                        return;
                    };
                }
                Ok(Message::Close(_)) | Err(_) => break,
                Ok(Message::Ping(_)) | Ok(Message::Pong(_)) => {}
                Ok(Message::Binary(_)) => {
                    let _ = send_ws_reader_error(
                        &reader_error_tx,
                        "binary WebSocket messages are not supported",
                    )
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
                reader_task.abort();
                return;
            }
        };

    let response = {
        let proxy_response = proxy_grpc::handle_prevalidated_stream(&state.proxy, grpc_request);
        tokio::pin!(proxy_response);
        tokio::select! {
            Some(error) = reader_error_rx.recv() => {
                let _ = ws_sender.send(ws_error(error)).await;
                let _ = ws_sender.close().await;
                reader_task.abort();
                return;
            }
            response = &mut proxy_response => response,
        }
    };

    if let Some(error) = grpc_error_from_headers(response.headers()) {
        let _ = ws_sender.send(ws_error(error.message)).await;
        let _ = ws_sender.close().await;
        reader_task.abort();
        return;
    }

    let grpc_path = route.grpc_path.to_string();
    let mut frames = GrpcFrameStream::new(response.into_body());
    loop {
        tokio::select! {
            Some(error) = reader_error_rx.recv() => {
                let _ = ws_sender.send(ws_error(error)).await;
                let _ = ws_sender.close().await;
                reader_task.abort();
                return;
            }
            frame = frames.next() => {
                let Some(frame) = frame else {
                    break;
                };
                match frame {
                    Ok(proto_bytes) => {
                        let json = match gateway_model::s2sm::proxy_dispatch::response_to_json(
                            &grpc_path,
                            &proto_bytes,
                        ) {
                            Ok(json) => json,
                            Err(e) => {
                                let _ = ws_sender
                                    .send(ws_error(format!("failed to serialize response: {e}")))
                                    .await;
                                let _ = ws_sender.close().await;
                                reader_task.abort();
                                return;
                            }
                        };
                        if ws_sender.send(Message::Text(json.into())).await.is_err() {
                            reader_task.abort();
                            return;
                        }
                    }
                    Err(e) => {
                        let _ = ws_sender.send(ws_error(e)).await;
                        let _ = ws_sender.close().await;
                        reader_task.abort();
                        return;
                    }
                }
            }
        }
    }

    if let Ok(error) = reader_error_rx.try_recv() {
        let _ = ws_sender.send(ws_error(error)).await;
        let _ = ws_sender.close().await;
        reader_task.abort();
        return;
    }

    let _ = ws_sender.close().await;
    reader_task.abort();
}

#[derive(Debug)]
struct WsDataFrame {
    json_bytes: Vec<u8>,
    auth_header: Option<String>,
}

/// Verify the token a WebSocket stream is about to carry into the backend,
/// before the backend stream is opened.
///
/// This is the header-only half of the check `authorize_then_read_body` runs on
/// the unary path; the namespace-aware half still runs per data frame in
/// `ws_frame_to_proto`. It cannot move up into `rest_handler` ahead of the
/// upgrade: W2S streams are message-tokened, so the token legitimately first
/// appears in the `start` frame. This is the earliest point at which the token
/// that will actually be forwarded is known, and it is still before the dial.
///
/// Before this existed the caller only had to supply *some* non-empty string:
/// presence was checked, validity was not, and the gateway opened a real
/// backend gRPC stream with that unverified value as `authorization`.
async fn authorize_ws_stream(
    auth: &GatewayAuth,
    route: &RouteInfo,
    auth_header: Option<&str>,
) -> Result<(), String> {
    if !matches!(route.auth_policy, AuthPolicy::NoAuth) && auth_header.is_none() {
        return Err(
            "authenticated WebSocket streams require an authorization token before backend stream open; every data message must include authorization"
                .to_string(),
        );
    }

    let (service_id, entitlement_service) = proxy_grpc::route_identity(route);
    auth.validate_c2s(
        route.auth_policy,
        service_id,
        entitlement_service,
        route.grpc_path,
        auth_header,
    )
    .await
    .map_err(|(_, message)| {
        tracing::warn!(path = %route.http_path, error = %message, "WebSocket auth rejected before backend stream open");
        message
    })
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
                    .filter(|s| !s.is_empty())
                    .map(str::to_string);
                if !matches!(route.auth_policy, AuthPolicy::NoAuth) && auth_header.is_none() {
                    return Err(
                        "authenticated WebSocket message frames require authorization".to_string(),
                    );
                }
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

async fn forward_ws_json_frame(
    tx: &mpsc::Sender<Result<bytes::Bytes, std::io::Error>>,
    error_tx: &mpsc::Sender<String>,
    state: &RestState,
    route: &RouteInfo,
    frame: WsDataFrame,
) -> Result<(), ()> {
    let proto_bytes = match ws_frame_to_proto(state, route, frame).await {
        Ok(bytes) => bytes,
        Err(e) => {
            let _ = send_ws_reader_error(error_tx, e).await;
            return Err(());
        }
    };

    tx.send(Ok(bytes::Bytes::from(proxy_grpc::frame_grpc(&proto_bytes))))
        .await
        .map_err(|_| ())
}

async fn ws_frame_to_proto(
    state: &RestState,
    route: &RouteInfo,
    frame: WsDataFrame,
) -> Result<Vec<u8>, String> {
    let proto_bytes = gateway_model::s2sm::proxy_dispatch::request_json_to_proto(
        route.grpc_path,
        &frame.json_bytes,
    )
    .map_err(|e| format!("invalid WebSocket request body: {e}"))?;

    gateway_model::s2sm::proxy_dispatch::validate_request(route.grpc_path, &proto_bytes)
        .map_err(|status| status.to_string())?;

    let target_namespace = gateway_model::s2sm::proxy_dispatch::request_target_namespace(
        route.grpc_path,
        &proto_bytes,
    )
    .map_err(|status| status.to_string())?;

    let entitlement_service = route.entitlement_service.unwrap_or(route.service_id);
    state
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
        .map_err(|(_, msg)| msg)?;

    Ok(proto_bytes)
}

async fn send_ws_reader_error(
    tx: &mpsc::Sender<String>,
    message: impl Into<String>,
) -> Result<(), ()> {
    tx.send(message.into()).await.map_err(|_| ())
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
    done: bool,
}

impl GrpcFrameStream {
    fn new(body: axum::body::Body) -> Self {
        Self {
            body,
            buffer: bytes::BytesMut::new(),
            done: false,
        }
    }

    fn fail(
        &mut self,
        message: impl Into<String>,
    ) -> std::task::Poll<Option<Result<Vec<u8>, String>>> {
        self.done = true;
        self.buffer.clear();
        std::task::Poll::Ready(Some(Err(message.into())))
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

        if this.done {
            return std::task::Poll::Ready(None);
        }

        loop {
            // Try to extract a complete frame from the buffer.
            if this.buffer.len() >= 5 {
                if this.buffer[0] != 0 {
                    return this.fail(
                        "compressed gRPC response frames are not supported by REST translation",
                    );
                }
                let msg_len = u32::from_be_bytes([
                    this.buffer[1],
                    this.buffer[2],
                    this.buffer[3],
                    this.buffer[4],
                ]) as usize;
                if msg_len > MAX_JSON_BODY_BYTES {
                    return this.fail("gRPC response message exceeds REST translation limit");
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
                            return this.fail(
                                "incomplete gRPC response frame exceeds REST translation limit",
                            );
                        }
                    }
                    if let Some(trailers) = frame.trailers_ref() {
                        if let Some(error) = grpc_error_from_headers(trailers) {
                            return this.fail(error.message);
                        }
                    }
                }
                std::task::Poll::Ready(Some(Err(e))) => {
                    return this.fail(format!("body read error: {}", e));
                }
                std::task::Poll::Ready(None) => {
                    if !this.buffer.is_empty() {
                        let remaining = this.buffer.len();
                        this.buffer.clear();
                        return this.fail(format!(
                            "incomplete trailing gRPC response frame: {} bytes",
                            remaining
                        ));
                    }
                    this.done = true;
                    return std::task::Poll::Ready(None);
                }
                std::task::Poll::Pending => {
                    return std::task::Poll::Pending;
                }
            }
        }
    }
}

/// The public OIDC issuer for an external hostname: the bare origin, which is
/// also what kernel signs as `iss`.
pub fn issuer_url(host: &str) -> String {
    format!("https://{}", host)
}

fn openid_config(issuer: &str) -> OidcDiscoveryDoc<'_> {
    OidcDiscoveryDoc {
        issuer,
        jwks_uri: format!("{}/.well-known/jwks.json", issuer),
        token_endpoint: format!("{}/gateway/TokenMint", issuer),
        response_types_supported: &["token"],
        grant_types_supported: &["urn:ietf:params:oauth:grant-type:token-exchange"],
        subject_types_supported: &["public"],
        id_token_signing_alg_values_supported: ID_TOKEN_SIGNING_ALGS_SUPPORTED,
    }
}

/// Handle Mint RPCs: GetOpenIdConfig/ListJwks/ListPublicCa locally, MintToken/MintX509Cert via kernel.
async fn handle_mint(
    route: &RouteInfo,
    state: &RestState,
    body: &[u8],
    auth_header: Option<&str>,
    request_id: &str,
) -> axum::response::Response {
    match route.grpc_path {
        "/gateway.Mint/GetOpenIdConfig" => {
            // issuer is the configured public OIDC issuer URL, not the Host
            // header, which can be lost across HTTP/2 / TLS termination.
            json_response(&openid_config(&state.issuer_url))
        }
        "/gateway.Mint/ListJwks" => {
            let keys: Vec<PublicJwk> = state
                .auth
                .get_raw_jwks()
                .iter()
                .filter_map(proto_jwk_to_public)
                .collect();
            json_response(&PublicJwks { keys })
        }
        path if is_mint_token_grpc_path(path) => {
            tracing::info!(request_id = %request_id, "routing MintToken to kernel mint");
            let req = match gateway_model::types::sys::tokenrequest::token_mint_request_from_json(
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
                .mint_token(grpc_req)
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
        path if is_mint_x509_grpc_path(path) => {
            let req =
                match gateway_model::types::sys::tokenrequest::x509_mint_request_from_json(body)
                {
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
                .mint_x509_cert(grpc_req)
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
        "/gateway.Mint/ListPublicCa" => list_public_ca_response(&state.root_ca),
        _ => (
            StatusCode::NOT_FOUND,
            format!("{{\"error\":\"unknown mint route: {}\"}}", route.grpc_path),
        )
            .into_response(),
    }
}

/// REST translation of `ListPublicCa`, over the same `PublicCaResponse` the
/// native gRPC handler returns — see `mint::public_ca_response` for why the two
/// share one source. The JSON shape is unchanged.
fn list_public_ca_response(root_ca: &[X509Cert]) -> axum::response::Response {
    let items: Vec<serde_json::Value> = crate::mint::public_ca_response(root_ca)
        .certs
        .iter()
        .map(|c| serde_json::json!({"id": c.id, "base64": c.base64}))
        .collect();
    (
        StatusCode::OK,
        [(
            axum::http::header::CONTENT_TYPE,
            "application/json".to_string(),
        )],
        serde_json::json!({"certs": items}).to_string(),
    )
        .into_response()
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
        4 => StatusCode::GATEWAY_TIMEOUT,      // DEADLINE_EXCEEDED
        5 => StatusCode::NOT_FOUND,            // NOT_FOUND
        7 => StatusCode::FORBIDDEN,            // PERMISSION_DENIED
        8 => StatusCode::TOO_MANY_REQUESTS,    // RESOURCE_EXHAUSTED
        12 => StatusCode::NOT_IMPLEMENTED,     // UNIMPLEMENTED
        14 => StatusCode::SERVICE_UNAVAILABLE, // UNAVAILABLE
        16 => StatusCode::UNAUTHORIZED,        // UNAUTHENTICATED
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

#[cfg(test)]
mod tests {
    use std::pin::Pin;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::task::{Context, Poll};

    use gateway_grpcserver::authorizer::JwkCache;
    use http_body::Frame;

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

    /// The first unary, non-gateway route in the generated table that requires
    /// a token. Picked from ROUTES so the test follows regeneration.
    fn unary_authenticated_route() -> &'static RouteInfo {
        ROUTES
            .iter()
            .find(|r| {
                !r.server_streaming
                    && !r.client_streaming
                    && r.auth_policy != AuthPolicy::NoAuth
                    && !r.grpc_path.starts_with("/gateway.")
            })
            .expect("the generated ROUTES table must contain a unary authenticated route")
    }

    /// The finding on the REST path: the handler buffered up to
    /// MAX_JSON_BODY_BYTES and handed it to the JSON→proto decoder before any
    /// token was checked. An unauthenticated caller must now be turned away
    /// with the body untouched.
    #[tokio::test]
    async fn rest_rejects_unauthenticated_caller_before_reading_the_body() {
        let auth = GatewayAuth::new(Arc::new(JwkCache::seeded(vec![])), false);
        let polls = Arc::new(AtomicUsize::new(0));
        let body = axum::body::Body::new(CountingBody {
            polls: Arc::clone(&polls),
            // Not JSON — before the fix this reached request_json_to_proto and
            // came back as a 400 parse error, proving the parse ran.
            data: Some(bytes::Bytes::from_static(b"not json at all")),
        });

        let response = super::authorize_then_read_body(
            &auth,
            unary_authenticated_route(),
            None,
            &axum::http::Method::POST,
            body,
        )
        .await
        .expect_err("a caller with no token must be rejected");

        assert_eq!(
            response.status(),
            StatusCode::UNAUTHORIZED,
            "no token must be 401, not a body-parse error"
        );
        assert_eq!(
            polls.load(Ordering::SeqCst),
            0,
            "the request body must not be polled before the token check"
        );
    }

    use super::*;

    fn route(auth_policy: AuthPolicy) -> RouteInfo {
        RouteInfo {
            http_path: "/api/test",
            grpc_path: "/test.Service/Method",
            service_id: "test",
            entitlement_service: None,
            http_methods: &["POST"],
            auth_policy,
            entitlement_scopes: &[],
            capability_scope: None,
            server_streaming: true,
            client_streaming: true,
            target_namespace_field: None,
            form_body: false,
            redirect_field: None,
        }
    }

    /// The REST route table and the SPA/404 fallback, with a stub in place of
    /// `rest_handler` so no backend state is needed.
    fn root_router() -> Router {
        rest_routes(Router::new(), any(|| async { "rest" })).fallback(
            |method: axum::http::Method, uri: axum::http::Uri, headers: axum::http::HeaderMap| async move {
                spa_or_not_found(&method, uri, &headers).await
            },
        )
    }

    async fn send(method: &str, path: &str) -> axum::response::Response {
        use tower::ServiceExt;
        let request = axum::http::Request::builder()
            .method(method)
            .uri(path)
            .body(axum::body::Body::empty())
            .expect("request");
        root_router().oneshot(request).await.expect("response")
    }

    async fn body_text(response: axum::response::Response) -> String {
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body");
        String::from_utf8(bytes.to_vec()).expect("utf-8 body")
    }

    #[test]
    fn generated_rest_paths_sit_at_the_origin_root() {
        for r in ROUTES.iter().filter(|r| !r.http_path.is_empty()) {
            assert!(
                !r.http_path.starts_with("/api/"),
                "{} still carries the removed REST root prefix",
                r.http_path
            );
        }
    }

    #[tokio::test]
    async fn well_known_paths_reach_rest_not_the_spa() {
        for path in ["/.well-known/openid-configuration", "/.well-known/jwks.json"] {
            let response = send("GET", path).await;
            assert_eq!(response.status(), StatusCode::OK, "{path}");
            assert_eq!(body_text(response).await, "rest", "{path} must be a REST route");
        }
    }

    #[tokio::test]
    async fn spa_routes_still_serve_the_spa() {
        for path in ["/", "/scotty", "/sentinel", "/login", "/scotty/tickets/42"] {
            let response = send("GET", path).await;
            assert_eq!(response.status(), StatusCode::OK, "{path}");
            let content_type = response
                .headers()
                .get(axum::http::header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .unwrap_or_default()
                .to_string();
            assert!(content_type.starts_with("text/html"), "{path} served {content_type}");
        }
    }

    #[tokio::test]
    async fn non_get_on_an_unknown_path_is_a_json_404() {
        let response = send("POST", "/nope").await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert_eq!(body_text(response).await, r#"{"error":"unknown route: /nope"}"#);
    }

    /// The request's Host has to survive the REST fallback for the SPA to pick
    /// the bundle configured for it, and a bundle that arrives in a config
    /// update after startup has to be served without a restart. The only test
    /// that sets the process-wide bundles, under a hostname no other test sends.
    #[tokio::test]
    async fn a_bundle_added_after_startup_is_served_through_the_fallback() {
        use tower::ServiceExt;
        let dir = std::env::temp_dir().join(format!("gateway-bundle-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).expect("bundle dir");
        std::fs::write(dir.join("index.html"), "<html><head></head>web app</html>").expect("index");
        let request = || {
            axum::http::Request::builder()
                .uri("/projects/7")
                .header(axum::http::header::HOST, "app.fallback.test:8443")
                .body(axum::body::Body::empty())
                .expect("request")
        };

        // Startup config: no bundle for this host.
        crate::spa::set_web_bundles(&[]);
        let before = body_text(root_router().oneshot(request()).await.expect("response")).await;
        assert!(!before.ends_with("web app</html>"));

        // A later config update adds it.
        let bundles = [gateway_model::types::services::gateway::gateway::WebBundle {
            hostname: "app.fallback.test".into(),
            dir: dir.display().to_string(),
            ..Default::default()
        }];
        assert!(crate::spa::set_web_bundles(&bundles));
        assert!(!crate::spa::set_web_bundles(&bundles), "an unchanged update is not a change");
        let response = root_router().oneshot(request()).await.expect("response");
        let _ = std::fs::remove_dir_all(&dir);

        assert_eq!(response.status(), StatusCode::OK);
        assert!(body_text(response).await.ends_with("web app</html>"));
    }

    #[test]
    fn discovery_advertises_the_bare_origin_as_issuer() {
        let issuer = issuer_url("dev.seabeam.net");
        let doc = serde_json::to_value(openid_config(&issuer)).expect("json");
        assert_eq!(doc["issuer"], "https://dev.seabeam.net");
        assert_eq!(doc["jwks_uri"], "https://dev.seabeam.net/.well-known/jwks.json");
    }

    #[test]
    fn mint_gateway_accepts_generated_and_legacy_method_names() {
        assert!(is_mint_token_grpc_path("/gateway.Mint/MintToken"));
        assert!(is_mint_token_grpc_path("/gateway.Mint/TokenMint"));
        assert!(is_mint_x509_grpc_path("/gateway.Mint/MintX509Cert"));
        assert!(is_mint_x509_grpc_path("/gateway.Mint/X509Mint"));
    }

    #[test]
    fn authenticated_message_frame_requires_authorization() {
        let err = parse_ws_data_frame(
            &route(AuthPolicy::Entitled),
            r#"{"type":"message","message":{"id":"1"}}"#,
        )
        .expect_err("authenticated frames without authorization must fail");

        assert!(err.contains("authorization"));
    }

    #[test]
    fn authenticated_message_frame_rejects_empty_authorization() {
        let err = parse_ws_data_frame(
            &route(AuthPolicy::AnyUser),
            r#"{"type":"message","authorization":"","message":{"id":"1"}}"#,
        )
        .expect_err("empty authorization is not a token");

        assert!(err.contains("authorization"));
    }

    #[test]
    fn authenticated_message_frame_accepts_authorization() {
        let frame = parse_ws_data_frame(
            &route(AuthPolicy::Entitled),
            r#"{"type":"message","authorization":"Bearer token","message":{"id":"1"}}"#,
        )
        .expect("authorized message frame should parse");

        assert_eq!(frame.auth_header.as_deref(), Some("Bearer token"));
        assert_eq!(frame.json_bytes, br#"{"id":"1"}"#);
    }

    #[test]
    fn auth_disabled_route_allows_raw_json_payload() {
        let frame = parse_ws_data_frame(&route(AuthPolicy::NoAuth), r#"{"id":"1"}"#)
            .expect("auth-disabled routes can use raw JSON payloads");

        assert!(frame.auth_header.is_none());
        assert_eq!(frame.json_bytes, br#"{"id":"1"}"#);
    }

    #[test]
    fn complete_frame_never_becomes_a_payload() {
        let err = parse_ws_data_frame(&route(AuthPolicy::NoAuth), r#"{"type":"complete"}"#)
            .expect_err("complete is a control frame");

        assert!(err.contains("complete"));
    }

    // ── WebSocket streams must not reach the backend on an unverified token ──
    //
    // The finding: `handle_websocket_stream` checked only that SOME non-empty
    // authorization string had been supplied, then opened a real backend gRPC
    // stream and forwarded that string verbatim as `authorization`. Presence is
    // not validity. `authorize_ws_stream` now runs the same header-only check
    // the unary path runs, at the last point before the dial — the first point
    // at which the token that will actually be forwarded is known — and
    // `handle_websocket_stream` returns on its error without ever building the
    // backend request.

    use gateway_jwk::jwk::{ImmutableJwk, Jwk};
    use gateway_key::{base64_utils, keys};
    use gateway_token::token::Token;

    /// Publish a throwaway signing key as the JWK the cache verifies against.
    fn jwk_for(key: &keys::ImmutableKey) -> ImmutableJwk {
        let keys::PublicKey::EcP256(ec) = key.public_key() else {
            panic!("these tests sign with P-256");
        };
        let point = ec.to_encoded_point(false);
        ImmutableJwk::new(Jwk {
            kty: "EC".to_string(),
            alg: Some(key.alg().to_string()),
            kid: key.id().to_string(),
            key_use: Some("sig".to_string()),
            n: None,
            e: None,
            crv: Some("P-256".to_string()),
            x: Some(base64_utils::encode_base64_url(point.x().expect("x"))),
            y: Some(base64_utils::encode_base64_url(point.y().expect("y"))),
            exp: None,
            created: None,
        })
        .expect("jwk")
    }

    /// A live user token audienced at `service`, entitled to everything.
    /// `{"all": true}` is the admin bypass, used so an entitlement failure can
    /// never be mistaken for the authentication failure under test.
    fn ws_token(key: &keys::ImmutableKey, service: &str) -> String {
        let mut token = Token::new();
        token.set_kid(key.id()).expect("kid");
        token.set_alg(key.alg()).expect("alg");
        token.set_issuer("ws-stream-auth-test").expect("iss");
        token.set_subject("alice@example.com").expect("sub");
        token.set_audience(service).expect("aud");
        token.set_namespace("/tenants/acme").expect("namespace");
        token.set_sub_type("user").expect("sub_type");
        token
            .set_expiration(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .expect("clock")
                    .as_secs() as i64
                    + 3600,
            )
            .expect("exp");
        token
            .set_service_entitlements(serde_json::json!({ "all": true }))
            .expect("service_entitlements");
        token.sign(key).expect("sign");
        format!("Bearer {}", token.base64().expect("base64"))
    }

    /// The first `client_streaming` route in the generated table that requires
    /// a token and entitles against itself. Picked from ROUTES so the test
    /// follows regeneration rather than pinning a path a proto change can move.
    fn ws_authenticated_route() -> &'static RouteInfo {
        ROUTES
            .iter()
            .find(|r| {
                r.client_streaming
                    && r.auth_policy != AuthPolicy::NoAuth
                    && r.entitlement_service.is_none()
                    && !r.grpc_path.starts_with("/gateway.")
            })
            .expect("the generated ROUTES table must contain an authenticated W2S route")
    }

    fn ws_noauth_route() -> &'static RouteInfo {
        ROUTES
            .iter()
            .find(|r| r.client_streaming && r.auth_policy == AuthPolicy::NoAuth)
            .expect("the generated ROUTES table must contain a NoAuth W2S route")
    }

    /// The bypass as reported: any non-empty string satisfied the old presence
    /// check, so a caller with no credential at all got a backend stream.
    #[tokio::test]
    async fn websocket_stream_rejects_a_token_that_is_not_a_token() {
        let key = keys::generate_ec_p256_key().expect("signing key");
        let auth = GatewayAuth::new(Arc::new(JwkCache::seeded(vec![jwk_for(&key)])), false);

        authorize_ws_stream(&auth, ws_authenticated_route(), Some("Bearer not-a-token"))
            .await
            .expect_err("an unverifiable string must not open a backend stream");
    }

    /// The same bypass with more effort behind it: a well-formed, unexpired,
    /// correctly-audienced token that gateway simply cannot verify, because it
    /// was signed by a key the JWK cache does not trust.
    #[tokio::test]
    async fn websocket_stream_rejects_a_token_signed_by_an_untrusted_key() {
        let route = ws_authenticated_route();
        let trusted = keys::generate_ec_p256_key().expect("trusted key");
        let forged = keys::generate_ec_p256_key().expect("attacker key");
        let auth = GatewayAuth::new(Arc::new(JwkCache::seeded(vec![jwk_for(&trusted)])), false);

        authorize_ws_stream(&auth, route, Some(&ws_token(&forged, route.service_id)))
            .await
            .expect_err("a token signed by an untrusted key must not open a backend stream");
    }

    #[tokio::test]
    async fn websocket_stream_rejects_a_missing_token() {
        let key = keys::generate_ec_p256_key().expect("signing key");
        let auth = GatewayAuth::new(Arc::new(JwkCache::seeded(vec![jwk_for(&key)])), false);

        let message = authorize_ws_stream(&auth, ws_authenticated_route(), None)
            .await
            .expect_err("no token must not open a backend stream");

        assert!(
            message.contains("authorization"),
            "the rejection must say what is missing, got {message:?}"
        );
    }

    /// The other half: the gate is defense in depth, not a new wall. A caller
    /// who really is authenticated and entitled still gets their stream.
    #[tokio::test]
    async fn websocket_stream_accepts_a_valid_token() {
        let route = ws_authenticated_route();
        let key = keys::generate_ec_p256_key().expect("signing key");
        let auth = GatewayAuth::new(Arc::new(JwkCache::seeded(vec![jwk_for(&key)])), false);

        authorize_ws_stream(&auth, route, Some(&ws_token(&key, route.service_id)))
            .await
            .expect("a valid, entitled token must still open the backend stream");
    }

    /// And a `NoAuth` W2S route still opens with no token at all, exactly as
    /// `parse_ws_data_frame` already allows for its data frames.
    #[tokio::test]
    async fn a_noauth_websocket_stream_still_opens_without_a_token() {
        let auth = GatewayAuth::new(Arc::new(JwkCache::seeded(vec![])), false);

        authorize_ws_stream(&auth, ws_noauth_route(), None)
            .await
            .expect("a NoAuth W2S route must not start requiring a token");
    }

    // ── ListPublicCa answers the same on REST and on gRPC ───────────────────

    fn ca(id: &str) -> X509Cert {
        X509Cert {
            id: id.to_string(),
            base64: format!("base64-of-{id}"),
            ..Default::default()
        }
    }

    /// The REST path used to serve kernel's `CaState` internal cluster signing
    /// CAs while the native gRPC path served the external root CA from config.
    /// Both now answer from one function over one input, so the same root_ca
    /// yields the same cert set on either path.
    #[test]
    fn rest_and_grpc_list_public_ca_return_the_same_cert_set() {
        let root_ca = vec![ca("external-root"), ca("external-root-next")];

        let grpc: Vec<(String, String)> = crate::mint::public_ca_response(&root_ca)
            .certs
            .into_iter()
            .map(|c| (c.id, c.base64))
            .collect();

        let response = list_public_ca_response(&root_ca);
        assert_eq!(response.status(), StatusCode::OK);
        let body = futures::executor::block_on(axum::body::to_bytes(
            response.into_body(),
            MAX_JSON_BODY_BYTES,
        ))
        .expect("body");
        let json: serde_json::Value = serde_json::from_slice(&body).expect("json");
        let rest: Vec<(String, String)> = json["certs"]
            .as_array()
            .expect("certs array")
            .iter()
            .map(|c| {
                (
                    c["id"].as_str().expect("id").to_string(),
                    c["base64"].as_str().expect("base64").to_string(),
                )
            })
            .collect();

        assert_eq!(
            rest, grpc,
            "REST ListPublicCa must return exactly what the gRPC handler returns"
        );
    }
}
