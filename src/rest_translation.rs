use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::sse::{Event, Sse};
use axum::response::IntoResponse;
use axum::routing::any;
use axum::Router;
use futures::StreamExt;
use tokio::sync::RwLock;
use tonic::transport::Channel;
use uuid::Uuid;

use gateway_tacplus::s2sm::rest_dispatch::{self, RouteInfo, ROUTES, REST_ROOT_PATH};
use gateway_tacplus::types::libs::jwk::jwk::Jwk as ProtoJwk;
use gateway_tacplus::types::libs::jwk::jwk::JwkUseType;
use gateway_tacplus::types::libs::key::key::KeyType;
use gateway_tacplus::types::libs::x509::x509::X509Cert;
use gateway_tacplus::types::services::kernel::kernel::mint_client::MintClient as KernelMintClient;

use crate::auth::GatewayAuth;
use crate::proxy_grpc::{self, ProxyState};

/// Application state for REST translation.
pub struct RestState {
    pub proxy: Arc<ProxyState>,
    pub kernel_channel: Channel,
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
    let opt = |s: &str| if s.is_empty() { None } else { Some(s.to_string()) };
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
    headers: axum::http::HeaderMap,
    request: axum::http::Request<axum::body::Body>,
) -> axum::response::Response {
    let path = request.uri().path().to_string();
    let req_method = request.method().clone();

    tracing::debug!(path = %path, method = %req_method, "REST request");

    let auth_header_value = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    let request_id = headers
        .get("x-request-id")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .unwrap_or_else(|| Uuid::new_v4().to_string());

    // Read body.
    let body_bytes = if req_method == axum::http::Method::GET {
        b"{}".to_vec()
    } else {
        match axum::body::to_bytes(request.into_body(), 10 * 1024 * 1024).await {
            Ok(b) => b.to_vec(),
            Err(e) => {
                return (
                    StatusCode::BAD_REQUEST,
                    format!("{{\"error\":\"failed to read request body: {}\"}}", e),
                )
                    .into_response();
            }
        }
    };

    // Look up route.
    let route = ROUTES.iter().find(|r| r.http_path == path);
    let route = match route {
        Some(r) => r,
        None => {
            // Try SPIFFE path routing.
            let spiffe_path = path.strip_prefix(REST_ROOT_PATH)
                .and_then(|p| p.strip_prefix('/'))
                .unwrap_or("");
            if !spiffe_path.is_empty() {
                let endpoints = state.proxy.resolver.health().get_endpoints_by_spiffe_path(spiffe_path);
                if !endpoints.is_empty() {
                    tracing::info!(path = %path, spiffe_path = %spiffe_path, request_id = %request_id, "SPIFFE path routing");
                    return dispatch_via_proxy(
                        &state, &path, &body_bytes, auth_header_value.as_deref(), false,
                    ).await;
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

    // Check HTTP method.
    if !route.http_methods.iter().any(|m| m.eq_ignore_ascii_case(req_method.as_str())) {
        return (
            StatusCode::METHOD_NOT_ALLOWED,
            format!("{{\"error\":\"method {} not allowed for {}\"}}", req_method, path),
        )
            .into_response();
    }

    // Gateway Mint special cases — served locally or proxied to kernel directly.
    if route.grpc_path.starts_with("/gateway.Mint/") {
        return handle_mint(
            route, &state, &body_bytes, auth_header_value.as_deref(), &request_id,
        ).await;
    }

    if route.server_streaming {
        dispatch_stream_via_proxy(
            &state, route.grpc_path, &body_bytes, auth_header_value.as_deref(),
        ).await
    } else {
        dispatch_via_proxy(
            &state, route.grpc_path, &body_bytes, auth_header_value.as_deref(), false,
        ).await
    }
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
    let proto_bytes = match gateway_tacplus::s2sm::proxy_dispatch::request_json_to_proto(grpc_path, json_body) {
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
    let grpc_status = response.headers()
        .get("grpc-status")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<i32>().ok())
        .unwrap_or(-1);

    if grpc_status > 0 {
        let grpc_message = response.headers()
            .get("grpc-message")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("unknown error")
            .to_string();
        let http_status = grpc_status_to_http(grpc_status);
        return (http_status, format!("{{\"error\":\"{}\"}}", grpc_message)).into_response();
    }

    // 6. Read response body, unframe gRPC, convert to JSON.
    let response_bytes = match axum::body::to_bytes(response.into_body(), 10 * 1024 * 1024).await {
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
            [(axum::http::header::CONTENT_TYPE, "application/json".to_string())],
            "{}".to_string(),
        )
            .into_response();
    }

    // Unframe gRPC: skip 5-byte header.
    let msg_len = u32::from_be_bytes([
        response_bytes[1], response_bytes[2], response_bytes[3], response_bytes[4],
    ]) as usize;
    let proto_end = (5 + msg_len).min(response_bytes.len());
    let response_proto = &response_bytes[5..proto_end];

    match gateway_tacplus::s2sm::proxy_dispatch::response_to_json(grpc_path, response_proto) {
        Ok(json) => (
            StatusCode::OK,
            [(axum::http::header::CONTENT_TYPE, "application/json".to_string())],
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
    let proto_bytes = match gateway_tacplus::s2sm::proxy_dispatch::request_json_to_proto(grpc_path, json_body) {
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
    let grpc_status = response.headers()
        .get("grpc-status")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<i32>().ok())
        .unwrap_or(-1);

    if grpc_status > 0 {
        let grpc_message = response.headers()
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

    let sse_stream = GrpcFrameStream::new(body).map(move |frame_result| {
        match frame_result {
            Ok(proto_bytes) => {
                let json = gateway_tacplus::s2sm::proxy_dispatch::response_to_json(
                    &grpc_path_owned, &proto_bytes,
                ).unwrap_or_else(|e| format!("{{\"error\":\"{}\"}}", e));
                Ok::<_, std::convert::Infallible>(Event::default().data(json))
            }
            Err(e) => {
                Ok(Event::default().event("error").data(format!("{{\"error\":\"{}\"}}", e)))
            }
        }
    });

    Sse::new(sse_stream).into_response()
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
                let msg_len = u32::from_be_bytes([
                    this.buffer[1], this.buffer[2], this.buffer[3], this.buffer[4],
                ]) as usize;
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
                    }
                }
                std::task::Poll::Ready(Some(Err(e))) => {
                    return std::task::Poll::Ready(Some(Err(format!("body read error: {}", e))));
                }
                std::task::Poll::Ready(None) => {
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
            tracing::info!(request_id = %request_id, "routing TokenMint to kernel");
            let req =
                match gateway_tacplus::types::common::tokenrequest::token_mint_request_from_json(body) {
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
            let mut client = KernelMintClient::new(state.kernel_channel.clone());
            match client.token_mint(grpc_req).await {
                Ok(resp) => json_response(&resp.into_inner()),
                Err(status) => {
                    tracing::warn!(request_id = %request_id, status = %status, "kernel mint error");
                    let (code, msg) = rest_dispatch::grpc_err(status);
                    (code, msg).into_response()
                }
            }
        }
        "/gateway.Mint/X509Mint" => {
            let req =
                match gateway_tacplus::types::common::tokenrequest::x509_mint_request_from_json(body) {
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
            let mut client = KernelMintClient::new(state.kernel_channel.clone());
            match client.x509_mint(grpc_req).await {
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
            let items: Vec<serde_json::Value> = certs.iter().map(|c| {
                serde_json::json!({"id": c.id, "base64": c.base64})
            }).collect();
            let resp = serde_json::json!({"certs": items});
            (
                StatusCode::OK,
                [(axum::http::header::CONTENT_TYPE, "application/json".to_string())],
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
            [(axum::http::header::CONTENT_TYPE, "application/json".to_string())],
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
