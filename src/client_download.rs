use std::path::Path as FsPath;
use std::sync::Arc;

use axum::extract::Path;
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};

use crate::auth::GatewayAuth;

/// Directory containing client binaries (baked into the container): the
/// gateway's own at its root, each contributed client under
/// `<service>/<client>/` (see `contributions`).
pub const CLIENT_DIR: &str = "/opt/tacplus/clients";

/// Valid os/arch combinations. macOS means Apple silicon: there is no
/// darwin/amd64 build (tacplus docs/USER.md, "Contributing to the gateway").
const VALID_TARGETS: &[(&str, &str)] = &[
    ("linux", "arm64"),
    ("linux", "amd64"),
    ("darwin", "arm64"),
    ("windows", "amd64"),
];

/// Serve the gateway's own client binary downloads.
/// Route: GET /client/:os/:arch
/// Auth: AnyUser (valid token required, no entitlement check).
pub async fn handler(
    Path((os, arch)): Path<(String, String)>,
    req: axum::extract::Request,
    auth: Arc<GatewayAuth>,
) -> Response {
    serve_client(&auth, req.headers(), FsPath::new(CLIENT_DIR), "gateway", &os, &arch).await
}

/// The one download rule, for the gateway's own client and every contributed
/// one: a signed-in user (AnyUser) of any of the fixed targets gets
/// `<dir>/<stem>-<os>-<arch>[.exe]`, under that name.
pub(crate) async fn serve_client(
    auth: &GatewayAuth,
    headers: &HeaderMap,
    dir: &FsPath,
    stem: &str,
    os: &str,
    arch: &str,
) -> Response {
    let auth_header = headers
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
        format!("{stem}-{os}-{arch}.exe")
    } else {
        format!("{stem}-{os}-{arch}")
    };

    match tokio::fs::read(dir.join(&filename)).await {
        Ok(data) => (
            StatusCode::OK,
            [
                (header::CONTENT_TYPE, "application/octet-stream".to_string()),
                (header::CONTENT_DISPOSITION, format!("attachment; filename=\"{filename}\"")),
                (header::CACHE_CONTROL, "private, max-age=86400".to_string()),
            ],
            data,
        ).into_response(),
        Err(_) => (
            StatusCode::NOT_FOUND,
            format!("client binary not available for {os}/{arch}"),
        ).into_response(),
    }
}
