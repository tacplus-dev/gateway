use std::path::{Component, Path, PathBuf};
use std::sync::OnceLock;

use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};

use crate::registry::Registry;

/// Bootstrap config injected into index.html as `window.__SCHEMATIC__`.
/// Web clients (w2sm) read this to discover the gateway URL for gRPC-over-REST.
static BOOTSTRAP_SCRIPT: OnceLock<String> = OnceLock::new();

// TODO: Support dynamic gateway URL discovery for load balancer/proxy scenarios.

/// Initialize the bootstrap config script tag. Call once at startup.
pub fn init_bootstrap(gateway_url: &str) {
    let json = serde_json::json!({
        "gatewayUrl": gateway_url,
    });
    let script = format!(
        "<script>window.__SCHEMATIC__={}</script>",
        serde_json::to_string(&json).unwrap()
    );
    BOOTSTRAP_SCRIPT.set(script).ok();
}

/// Inject bootstrap config into HTML by inserting before </head>.
fn inject_bootstrap(html: &[u8]) -> Vec<u8> {
    let script = match BOOTSTRAP_SCRIPT.get() {
        Some(s) => s,
        None => return html.to_vec(),
    };
    let html_str = String::from_utf8_lossy(html);
    match html_str.find("</head>") {
        Some(pos) => {
            let mut out = String::with_capacity(html_str.len() + script.len());
            out.push_str(&html_str[..pos]);
            out.push_str(script);
            out.push_str(&html_str[pos..]);
            out.into_bytes()
        }
        None => html.to_vec(),
    }
}

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

/// Where a request path lands inside the web root, once `..`, absolute paths
/// and symlinks have been resolved.
enum Resolved {
    /// A real path, canonicalized and confirmed to be under the root.
    UnderRoot(PathBuf),
    /// Nothing readable there. The SPA fallback applies, as before.
    Missing,
    /// The path pointed outside the root. Serve nothing.
    Escaped,
}

/// Resolve a request path against the web root, refusing anything that leaves it.
///
/// `root.join(path)` on a raw request path let `../` walk out of the web root
/// and serve any file the gateway process can read. Both checks are needed:
/// the component scan rejects the escapes that are visible in the request, and
/// canonicalizing catches the ones that only appear once a symlink inside the
/// root is followed. Nothing percent-decodes the path on the way here, so an
/// encoded `%2e%2e` stays a literal file name and cannot smuggle a `..` past
/// the component scan.
async fn resolve_under_root(root: &Path, path: &str) -> Resolved {
    if Path::new(path)
        .components()
        .any(|c| !matches!(c, Component::Normal(_) | Component::CurDir))
    {
        return Resolved::Escaped;
    }

    let Ok(root) = tokio::fs::canonicalize(root).await else {
        return Resolved::Missing;
    };
    let Ok(resolved) = tokio::fs::canonicalize(root.join(path)).await else {
        return Resolved::Missing;
    };
    if resolved.starts_with(&root) {
        Resolved::UnderRoot(resolved)
    } else {
        Resolved::Escaped
    }
}

async fn serve_from_disk(root: &PathBuf, path: &str) -> Response {
    // Try exact file from disk
    let file_path = match resolve_under_root(root, path).await {
        Resolved::UnderRoot(file_path) => Some(file_path),
        Resolved::Missing => None,
        Resolved::Escaped => {
            tracing::warn!(path = %path, "static file request outside WEB_ROOT rejected");
            return (StatusCode::BAD_REQUEST, "invalid path").into_response();
        }
    };
    if let Some(file_path) = file_path {
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
    }

    // SPA fallback: serve index.html with injected bootstrap config
    let index_path = root.join("index.html");
    if let Ok(data) = tokio::fs::read(&index_path).await {
        return (
            StatusCode::OK,
            [
                (header::CONTENT_TYPE, "text/html; charset=utf-8".to_string()),
                (header::CACHE_CONTROL, "no-cache".to_string()),
            ],
            inject_bootstrap(&data),
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

    // SPA fallback: serve index.html for all unmatched routes, with bootstrap config
    if let Some(index) = WebAssets::get("index.html") {
        return (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "text/html; charset=utf-8".to_string())],
            inject_bootstrap(&index.data),
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

#[cfg(test)]
mod tests {
    use super::*;

    /// A throwaway web root with one real asset in it, plus a secret sitting
    /// next to the root that a `../` must never reach.
    struct Fixture {
        dir: PathBuf,
    }

    impl Fixture {
        fn new() -> Self {
            let dir = std::env::temp_dir().join(format!("gateway-spa-{}", uuid::Uuid::new_v4()));
            std::fs::create_dir_all(dir.join("root")).expect("root");
            std::fs::write(dir.join("root/app.js"), b"console.log(1)").expect("asset");
            std::fs::write(dir.join("root/index.html"), b"<html><head></head></html>")
                .expect("index");
            std::fs::write(dir.join("secret.txt"), b"SECRET").expect("secret");
            Self { dir }
        }

        fn root(&self) -> PathBuf {
            self.dir.join("root")
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    async fn body_of(response: Response) -> Vec<u8> {
        axum::body::to_bytes(response.into_body(), 64 * 1024)
            .await
            .expect("body")
            .to_vec()
    }

    /// The finding: `root.join(path)` on the raw request path let `..` walk out
    /// of WEB_ROOT and serve any file the gateway process could read.
    #[tokio::test]
    async fn a_path_that_escapes_the_web_root_is_rejected() {
        let fixture = Fixture::new();

        for path in [
            "../secret.txt",
            "../../etc/passwd",
            "assets/../../secret.txt",
            "/etc/passwd",
        ] {
            let response = serve_from_disk(&fixture.root(), path).await;
            assert_eq!(
                response.status(),
                StatusCode::BAD_REQUEST,
                "{path} must be rejected outright, not resolved"
            );
            let body = body_of(response).await;
            assert!(
                !body.windows(6).any(|w| w == b"SECRET"),
                "{path} must not serve anything from outside the root"
            );
        }
    }

    #[tokio::test]
    async fn a_normal_in_root_path_is_still_served() {
        let fixture = Fixture::new();

        let response = serve_from_disk(&fixture.root(), "app.js").await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(body_of(response).await, b"console.log(1)");
    }

    /// A path inside the root that simply is not there still falls back to
    /// index.html — that is SPA client-side routing, not an escape.
    #[tokio::test]
    async fn a_missing_in_root_path_still_falls_back_to_index() {
        let fixture = Fixture::new();

        let response = serve_from_disk(&fixture.root(), "dashboard/settings").await;
        assert_eq!(response.status(), StatusCode::OK);
        assert!(body_of(response).await.starts_with(b"<html>"));
    }

    /// A symlink inside the root pointing out of it is the escape the component
    /// scan alone cannot see; only the canonicalized comparison catches it.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_symlink_out_of_the_web_root_is_rejected() {
        let fixture = Fixture::new();
        std::os::unix::fs::symlink(fixture.dir.join("secret.txt"), fixture.root().join("escape"))
            .expect("symlink");

        let response = serve_from_disk(&fixture.root(), "escape").await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_ne!(body_of(response).await, b"SECRET");
    }

    /// The registry is mounted at `/registry/{file}`, which is the prefix
    /// `registry_handler` strips. Under the old prefixed mount it never
    /// matched and every file 404'd.
    #[tokio::test]
    async fn registry_files_resolve_under_the_root_mount() {
        let ok = registry_handler("/registry/registry.json".parse().unwrap()).await;
        assert_eq!(ok.status(), StatusCode::OK);
        let missing = registry_handler("/registry/nope.json".parse().unwrap()).await;
        assert_eq!(missing.status(), StatusCode::NOT_FOUND);
    }
}
