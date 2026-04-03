use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::middleware;
use axum::response::IntoResponse;
use axum::routing::any;
use axum::Router;
use tonic::transport::Channel;
use uuid::Uuid;

use gateway_tacplus::s2sm::rest_dispatch::{self, RouteInfo, ROUTES, REST_ROOT_PATH};
use gateway_tacplus::types::libs::jwk::jwk::{Jwks, OpenIdConfiguration};
use gateway_tacplus::types::services::kernel::kernel::mint_client::MintClient as KernelMintClient;

use crate::auth::GatewayAuth;
use crate::resolver::Resolver;

/// Application state shared across REST handlers.
pub struct AppState {
    pub resolver: Arc<Resolver>,
    pub auth: Arc<GatewayAuth>,
    pub kernel_channel: Channel,
}

/// Build the REST router.
/// Auth middleware runs before the handler, using the ROUTES table
/// to look up per-route AuthPolicy and enforcing C2S auth.
pub fn router(state: Arc<AppState>) -> Router {
    let rest_route = format!("{}/{{*rest}}", REST_ROOT_PATH);
    Router::new()
        .route(&rest_route, any(rest_handler))
        .layer(middleware::from_fn_with_state(state.clone(), auth_middleware))
        .with_state(state)
}

/// REST→gRPC handler. Dispatches incoming HTTP requests to backend gRPC services
/// using the tacplus-generated dispatch functions. Mint RPCs are handled specially:
/// OpenIdConfig and Jwks are served locally, TokenMint and X509Mint are proxied to kernel.
async fn rest_handler(
    State(state): State<Arc<AppState>>,
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

    // Read body: empty for GET, up to 10MB for others.
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
            tracing::warn!(path = %path, "no route found");
            return (
                StatusCode::NOT_FOUND,
                format!("{{\"error\":\"unknown route: {}\"}}", path),
            )
                .into_response();
        }
    };

    // Check HTTP method is allowed.
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

    // Gateway Mint special cases — these RPCs are not in the dispatch table.
    // OpenIdConfig and Jwks are served locally; TokenMint and X509Mint proxy to kernel.
    if route.grpc_path.starts_with("/gateway.Mint/") {
        return handle_mint(
            route,
            &state,
            &body_bytes,
            auth_header_value.as_deref(),
            &request_id,
            &headers,
        )
        .await;
    }

    // Resolve channel: kernel for gateway service, resolver for others.
    let channel = if route.service_id == "gateway" {
        state.kernel_channel.clone()
    } else {
        state.resolver.dial(route.service_id)
    };

    tracing::debug!(
        grpc_path = %route.grpc_path,
        service = %route.service_id,
        request_id = %request_id,
        streaming = route.server_streaming,
        has_auth = auth_header_value.is_some(),
        "dispatching to backend"
    );

    if route.server_streaming {
        return rest_dispatch::dispatch_stream(
            route.grpc_path,
            &body_bytes,
            channel,
            auth_header_value.as_deref(),
            &request_id,
        )
        .await;
    }

    match rest_dispatch::dispatch(
        route.grpc_path,
        &body_bytes,
        channel,
        auth_header_value.as_deref(),
        &request_id,
    )
    .await
    {
        Ok(json) => (
            StatusCode::OK,
            [(
                axum::http::header::CONTENT_TYPE,
                "application/json".to_string(),
            )],
            json,
        )
            .into_response(),
        Err((status, body)) => {
            tracing::warn!(
                grpc_path = %route.grpc_path,
                request_id = %request_id,
                status = %status,
                "backend dispatch error"
            );
            (status, body).into_response()
        }
    }
}

/// Handle Mint RPCs: OpenIdConfig/Jwks locally, TokenMint/X509Mint via kernel.
async fn handle_mint(
    route: &RouteInfo,
    state: &AppState,
    body: &[u8],
    auth_header: Option<&str>,
    request_id: &str,
    headers: &axum::http::HeaderMap,
) -> axum::response::Response {
    match route.grpc_path {
        "/gateway.Mint/OpenIdConfig" => {
            let host = headers
                .get("host")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("localhost");
            let base = format!("https://{}", host);
            let config = OpenIdConfiguration {
                issuer: base.clone(),
                jwks_uri: format!("{}{}/.well-known/jwks.json", base, REST_ROOT_PATH),
                token_endpoint: format!("{}{}/gateway/TokenMint", base, REST_ROOT_PATH),
                subject_types_supported: vec!["public".to_string()],
                id_token_signing_alg_values_supported: vec!["EdDSA".to_string()],
                response_types_supported: vec!["token".to_string()],
                grant_types_supported: vec![
                    "urn:ietf:params:oauth:grant-type:token-exchange".to_string(),
                ],
                ..Default::default()
            };
            json_response(&config)
        }
        "/gateway.Mint/Jwks" => {
            let jwks = Jwks {
                keys: state.auth.get_raw_jwks(),
            };
            json_response(&jwks)
        }
        "/gateway.Mint/TokenMint" => {
            tracing::info!(request_id = %request_id, "routing TokenMint to kernel");
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
            let grpc_req =
                rest_dispatch::with_metadata(req, auth_header, request_id);
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
            let grpc_req =
                rest_dispatch::with_metadata(req, auth_header, request_id);
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

/// Axum middleware: look up route from ROUTES table, enforce auth policy.
async fn auth_middleware(
    State(state): State<Arc<AppState>>,
    request: axum::http::Request<axum::body::Body>,
    next: middleware::Next,
) -> axum::response::Response {
    let path = request.uri().path();

    let route = ROUTES.iter().find(|r| r.http_path == path);

    if let Some(route) = route {
        if let Err((code, msg)) = state
            .auth
            .validate_c2s(
                route.auth_policy,
                route.service_id,
                route.grpc_path,
                request
                    .headers()
                    .get("authorization")
                    .and_then(|v| v.to_str().ok()),
            )
            .await
        {
            tracing::warn!(path = %path, error = %msg, "auth rejected");
            return (code, format!("{{\"error\":\"{}\"}}", msg)).into_response();
        }
    }

    next.run(request).await
}
