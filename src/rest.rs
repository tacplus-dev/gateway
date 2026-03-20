use std::sync::Arc;

use axum::body::Body;
use axum::extract::State;
use axum::http::{HeaderMap, Request, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::any;
use axum::Router;
use tonic::transport::Channel;

use gateway_tacplus::types::libs::jwk::jwk::{Jwks, OpenIdConfiguration};

use crate::auth::GatewayAuth;
use crate::grpc_dispatch;
use crate::registry::Registry;
use crate::resolver::Resolver;

/// Application state shared across REST handlers.
pub struct AppState {
    pub resolver: Arc<Resolver>,
    pub auth: Arc<GatewayAuth>,
    pub registry: Arc<Registry>,
    pub kernel_channel: Channel,
}

/// Build the REST router.
/// Routes /api/* to the registry-driven REST handler.
pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/api/*rest", any(rest_handler))
        .with_state(state)
}

/// Registry-driven REST handler.
/// Looks up the request path in the registry route table, authenticates,
/// resolves the backend, and dispatches the request as a gRPC call.
async fn rest_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    request: Request<Body>,
) -> Response {
    let path = request.uri().path().to_string();
    let req_method = request.method().clone();

    // Look up route in registry
    let route = match state.registry.lookup(&path) {
        Some(r) => r,
        None => {
            return (
                StatusCode::NOT_FOUND,
                format!("{{\"error\":\"unknown route: {}\"}}", path),
            )
                .into_response();
        }
    };

    // Check HTTP method matches
    if !route.allows_method(req_method.as_str()) {
        return (
            StatusCode::METHOD_NOT_ALLOWED,
            format!("{{\"error\":\"method {} not allowed for {}\"}}", req_method, path),
        )
            .into_response();
    }

    // Authenticate (skip for no-auth routes)
    if !route.no_auth {
        let auth_header = headers
            .get("authorization")
            .and_then(|v| v.to_str().ok());

        if let Err(status) = state.auth.validate_rest(&path, auth_header) {
            return (
                StatusCode::UNAUTHORIZED,
                format!("{{\"error\":\"{}\"}}", status.message()),
            )
                .into_response();
        }
    }

    // Handle gateway-local OIDC/JWKS endpoints directly (no backend needed).
    if route.grpc_path == "/gateway.MintService/OpenIdConfig" {
        let host = headers
            .get("host")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("localhost");
        let base = format!("https://{}", host);
        let config = OpenIdConfiguration {
            issuer: base.clone(),
            jwks_uri: format!("{}/api/v1/.well-known/jwks.json", base),
            token_endpoint: format!("{}/api/v1/Mint/TokenMint", base),
            subject_types_supported: vec!["public".to_string()],
            id_token_signing_alg_values_supported: vec!["EdDSA".to_string()],
            response_types_supported: vec!["token".to_string()],
            grant_types_supported: vec![
                "urn:ietf:params:oauth:grant-type:token-exchange".to_string(),
            ],
            ..Default::default()
        };
        return json_response(&config);
    }
    if route.grpc_path == "/gateway.MintService/Jwks" {
        let jwks = Jwks {
            keys: state.auth.get_raw_jwks(),
        };
        return json_response(&jwks);
    }

    // Resolve a gRPC channel to the backend service.
    // Gateway-local routes (TokenMint, X509Mint) use the direct kernel channel.
    let channel = if route.service_id == "gateway" {
        state.kernel_channel.clone()
    } else {
        state.resolver.dial(&route.service_id)
    };

    // Read request body (empty for GET)
    let body_bytes = if req_method == axum::http::Method::GET {
        Vec::new()
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

    // Dispatch REST→gRPC
    match grpc_dispatch::dispatch(&route.grpc_path, &body_bytes, channel).await {
        Ok(json) => (
            StatusCode::OK,
            [(axum::http::header::CONTENT_TYPE, "application/json".to_string())],
            json,
        )
            .into_response(),
        Err((status, body)) => (status, body).into_response(),
    }
}

/// Serialize a value to a JSON response.
fn json_response<T: serde::Serialize>(value: &T) -> Response {
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
