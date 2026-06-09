use std::sync::Arc;

use axum::extract::Path;
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};

use crate::auth::GatewayAuth;

/// Directory containing cavalier client binaries (baked into the container).
const CLIENT_DIR: &str = "/opt/cavalier/clients";

/// Valid os/arch combinations.
const VALID_TARGETS: &[(&str, &str)] = &[
    ("linux", "arm64"),
    ("linux", "amd64"),
    ("darwin", "arm64"),
    ("windows", "amd64"),
];

/// Serve cavalier client binary downloads.
/// Route: GET /api/v1/client/:os/:arch
/// Auth: AnyUser (valid token required, no entitlement check).
pub async fn handler(
    Path((os, arch)): Path<(String, String)>,
    req: axum::extract::Request,
    auth: Arc<GatewayAuth>,
) -> Response {
    let auth_header = req
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok());

    if let Err((status, msg)) = auth.validate_c2s(
        gateway_model::s2sm::rest_dispatch::AuthPolicy::AnyUser,
        "gateway",
        "gateway",
        "/gateway/ClientDownload",
        auth_header,
    ).await {
        return (status, msg).into_response();
    }

    if !VALID_TARGETS.iter().any(|(o, a)| *o == os && *a == arch) {
        return (
            StatusCode::NOT_FOUND,
            format!("unknown target: {os}/{arch}"),
        ).into_response();
    }

    let filename = if os == "windows" {
        format!("cavalier-{os}-{arch}.exe")
    } else {
        format!("cavalier-{os}-{arch}")
    };
    let file_path = format!("{CLIENT_DIR}/{filename}");

    match tokio::fs::read(&file_path).await {
        Ok(data) => (
            StatusCode::OK,
            [
                (header::CONTENT_TYPE, "application/octet-stream".to_string()),
                (header::CONTENT_DISPOSITION, format!("attachment; filename=\"{filename}\"")),
                (header::CACHE_CONTROL, "public, max-age=86400".to_string()),
            ],
            data,
        ).into_response(),
        Err(_) => (
            StatusCode::NOT_FOUND,
            format!("client binary not available for {os}/{arch}"),
        ).into_response(),
    }
}
