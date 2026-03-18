use std::path::PathBuf;
use std::sync::OnceLock;

use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};

use crate::registry::Registry;

/// Embedded web assets from dist/ directory.
/// In development, this may be empty — SPA will return a placeholder.
#[derive(rust_embed::Embed)]
#[folder = "dist/"]
#[allow(dead_code)]
struct WebAssets;

/// WEB_ROOT env var: when set, serve SPA files from disk instead of embedded assets.
/// This enables frontend development without rebuilding the gateway binary.
static WEB_ROOT: OnceLock<Option<PathBuf>> = OnceLock::new();

pub fn web_root() -> &'static Option<PathBuf> {
    WEB_ROOT.get_or_init(|| std::env::var("WEB_ROOT").ok().map(PathBuf::from))
}

/// Serve static files — from WEB_ROOT on disk if set, otherwise from embedded dist/.
/// Falls back to index.html for SPA client-side routing.
pub async fn spa_handler(uri: axum::http::Uri) -> Response {
    let path = uri.path().trim_start_matches('/');

    if let Some(root) = web_root() {
        return serve_from_disk(root, path).await;
    }

    serve_from_embedded(path)
}

async fn serve_from_disk(root: &PathBuf, path: &str) -> Response {
    // Try exact file from disk
    let file_path = root.join(path);
    if let Ok(data) = tokio::fs::read(&file_path).await {
        let mime = mime_guess::from_path(path).first_or_octet_stream();
        return (
            StatusCode::OK,
            [
                (header::CONTENT_TYPE, mime.as_ref().to_string()),
                (header::CACHE_CONTROL, "no-cache".to_string()),
            ],
            data,
        )
            .into_response();
    }

    // SPA fallback: serve index.html
    let index_path = root.join("index.html");
    if let Ok(data) = tokio::fs::read(&index_path).await {
        return (
            StatusCode::OK,
            [
                (header::CONTENT_TYPE, "text/html; charset=utf-8".to_string()),
                (header::CACHE_CONTROL, "no-cache".to_string()),
            ],
            data,
        )
            .into_response();
    }

    placeholder_response()
}

fn serve_from_embedded(path: &str) -> Response {
    // Try to serve the exact file
    if let Some(content) = WebAssets::get(path) {
        let mime = mime_guess::from_path(path).first_or_octet_stream();
        return (
            StatusCode::OK,
            [
                (header::CONTENT_TYPE, mime.as_ref().to_string()),
                (header::CACHE_CONTROL, "public, max-age=3600".to_string()),
            ],
            content.data.to_vec(),
        )
            .into_response();
    }

    // SPA fallback: serve index.html for all unmatched routes
    if let Some(index) = WebAssets::get("index.html") {
        return (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "text/html; charset=utf-8".to_string())],
            index.data.to_vec(),
        )
            .into_response();
    }

    placeholder_response()
}

fn placeholder_response() -> Response {
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/html; charset=utf-8".to_string())],
        "<!DOCTYPE html><html><head><title>Gateway</title></head><body><h1>Gateway</h1><p>Web UI not built. Run the frontend build to populate dist/.</p></body></html>".to_string(),
    )
        .into_response()
}

/// Serve embedded registry files: registry.json, registry.schema.json, AGENT.md.
pub async fn registry_handler(uri: axum::http::Uri) -> Response {
    let name = uri.path().trim_start_matches("/registry/");

    match name {
        "registry.json" => (
            StatusCode::OK,
            [
                (header::CONTENT_TYPE, "application/json".to_string()),
                (header::CACHE_CONTROL, "public, max-age=3600".to_string()),
            ],
            Registry::registry_json().to_string(),
        )
            .into_response(),
        "registry.schema.json" => (
            StatusCode::OK,
            [
                (header::CONTENT_TYPE, "application/json".to_string()),
                (header::CACHE_CONTROL, "public, max-age=3600".to_string()),
            ],
            Registry::registry_schema_json().to_string(),
        )
            .into_response(),
        "AGENT.md" => (
            StatusCode::OK,
            [
                (header::CONTENT_TYPE, "text/markdown; charset=utf-8".to_string()),
                (header::CACHE_CONTROL, "public, max-age=3600".to_string()),
            ],
            Registry::agent_md().to_string(),
        )
            .into_response(),
        _ => (StatusCode::NOT_FOUND, "not found").into_response(),
    }
}
