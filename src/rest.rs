use std::sync::Arc;

use axum::body::Body;
use axum::extract::State;
use axum::http::{HeaderMap, Request, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::any;
use axum::Router;

use crate::auth::GatewayAuth;
use crate::registry::Registry;
use crate::resolver::Resolver;

/// Application state shared across REST handlers.
pub struct AppState {
    pub resolver: Arc<Resolver>,
    pub auth: Arc<GatewayAuth>,
    pub registry: Arc<Registry>,
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
/// resolves the backend, and forwards the request.
async fn rest_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    request: Request<Body>,
) -> Response {
    let path = request.uri().path().to_string();
    let query = request.uri().query().map(|q| q.to_string());
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

    // Resolve backend
    let backend = match state.resolver.resolve_addr(&route.service_id) {
        Some(addr) => addr,
        None => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                format!(
                    "{{\"error\":\"no healthy backend for service: {}\"}}",
                    route.service_id
                ),
            )
                .into_response();
        }
    };

    // Build target URL — forward to backend using the same http_path
    let target_url = if let Some(ref q) = query {
        format!("http://{}{}?{}", backend, path, q)
    } else {
        format!("http://{}{}", backend, path)
    };

    let client = reqwest::Client::new();

    if req_method == axum::http::Method::GET {
        // GET: no body, forward query params
        let mut req_builder = client.get(&target_url);
        for (name, value) in headers.iter() {
            if let Ok(v) = value.to_str() {
                match name.as_str() {
                    "authorization" | "accept" | "x-request-id" => {
                        req_builder = req_builder.header(name.as_str(), v);
                    }
                    _ => {}
                }
            }
        }
        forward_response(req_builder.send().await).await
    } else {
        // POST: forward body
        let mut req_builder = client.post(&target_url);
        for (name, value) in headers.iter() {
            if let Ok(v) = value.to_str() {
                match name.as_str() {
                    "authorization" | "content-type" | "accept" | "x-request-id" => {
                        req_builder = req_builder.header(name.as_str(), v);
                    }
                    _ => {}
                }
            }
        }
        let body_bytes = match axum::body::to_bytes(request.into_body(), 10 * 1024 * 1024).await {
            Ok(b) => b,
            Err(e) => {
                return (
                    StatusCode::BAD_REQUEST,
                    format!("{{\"error\":\"failed to read request body: {}\"}}", e),
                )
                    .into_response();
            }
        };
        req_builder = req_builder.body(body_bytes.to_vec());
        forward_response(req_builder.send().await).await
    }
}

/// Forward a backend response back to the client.
async fn forward_response(result: Result<reqwest::Response, reqwest::Error>) -> Response {
    match result {
        Ok(resp) => {
            let status = StatusCode::from_u16(resp.status().as_u16())
                .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
            let content_type = resp
                .headers()
                .get("content-type")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("application/json")
                .to_string();

            match resp.bytes().await {
                Ok(body) => (
                    status,
                    [(axum::http::header::CONTENT_TYPE, content_type)],
                    body.to_vec(),
                )
                    .into_response(),
                Err(e) => (
                    StatusCode::BAD_GATEWAY,
                    format!("{{\"error\":\"failed to read backend response: {}\"}}", e),
                )
                    .into_response(),
            }
        }
        Err(e) => (
            StatusCode::BAD_GATEWAY,
            format!("{{\"error\":\"backend request failed: {}\"}}", e),
        )
            .into_response(),
    }
}
