//! What the fleet's services contribute to their gateway, served under `/-/`
//! (#21; tacplus docs/USER.md, "Contributing to the gateway"). The fleet
//! builder writes them beside the gateway's own webapp:
//!
//! | Path | Serves | From |
//! |---|---|---|
//! | `/-/apps/<service>/` | the service's webapp module, with its own SPA fallback | `WEB_ROOT/-/apps/<service>/` |
//! | `/-/apps.json` | the index, `[{service, title, version, path}]` sorted by service | `WEB_ROOT/-/apps.json` |
//! | `/-/clients/<service>/<client>/<os>/<arch>` | a client binary, to a signed-in user (AnyUser) | `CLIENT_DIR/<service>/<client>/<client>-<os>-<arch>[.exe]` |
//!
//! No proto route can take a path under `/-/`: routes are
//! `/{package}/{Service}/{Rpc}` and no proto identifier starts with `-`. Every
//! other path under `/-/` is a 404, never the gateway's SPA or SPIFFE routing.

use std::path::PathBuf;
use std::sync::Arc;

use axum::Router;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode, Uri, header};
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::{any, get};

use crate::auth::GatewayAuth;
use crate::client_download;

pub struct Contributions {
    /// The merged webapp's root (WEB_ROOT); none means nothing is contributed.
    pub web_root: Option<PathBuf>,
    /// The client binaries' root (`client_download::CLIENT_DIR`).
    pub client_dir: PathBuf,
    pub auth: Arc<GatewayAuth>,
}

pub fn router(contributions: Arc<Contributions>) -> Router {
    Router::new()
        .route("/-/apps.json", get(apps_index))
        .route("/-/apps/{service}", get(module_without_slash))
        .route("/-/apps/{service}/", get(module_index))
        .route("/-/apps/{service}/{*path}", get(module_file))
        .route("/-/clients/{service}/{client}/{os}/{arch}", get(client))
        .route("/-", any(not_found))
        .route("/-/", any(not_found))
        .route("/-/{*rest}", any(not_found))
        .with_state(contributions)
}

/// A registry or client name as a single path segment: what the fleet's
/// registries allow, and nothing that could be `.`, `..` or a separator.
fn is_name(s: &str) -> bool {
    !s.is_empty()
        && !s.starts_with('.')
        && s.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
}

fn not_found_response() -> Response {
    (StatusCode::NOT_FOUND, "not found").into_response()
}

async fn not_found() -> Response {
    not_found_response()
}

/// The index of modules. A fleet with none has no file: that is an empty list.
async fn apps_index(State(c): State<Arc<Contributions>>) -> Response {
    let body = match &c.web_root {
        Some(root) => tokio::fs::read(root.join("-/apps.json")).await.unwrap_or_else(|_| b"[]".to_vec()),
        None => b"[]".to_vec(),
    };
    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "application/json".to_string()),
            (header::CACHE_CONTROL, "no-cache".to_string()),
        ],
        body,
    )
        .into_response()
}

/// A module is built with `/-/apps/<service>/` as its base: its relative
/// asset paths only resolve under the slash.
async fn module_without_slash(Path(service): Path<String>, uri: Uri) -> Response {
    if !is_name(&service) {
        return not_found_response();
    }
    let query = uri.query().map(|q| format!("?{q}")).unwrap_or_default();
    Redirect::permanent(&format!("/-/apps/{service}/{query}")).into_response()
}

async fn module_index(State(c): State<Arc<Contributions>>, Path(service): Path<String>) -> Response {
    serve_module(&c, &service, "").await
}

async fn module_file(
    State(c): State<Arc<Contributions>>,
    Path((service, path)): Path<(String, String)>,
) -> Response {
    serve_module(&c, &service, &path).await
}

/// A module's file, else its own index.html; a service without a module is a
/// 404, never the gateway's index.html.
async fn serve_module(c: &Contributions, service: &str, path: &str) -> Response {
    let Some(web_root) = &c.web_root else {
        return not_found_response();
    };
    if !is_name(service) {
        return not_found_response();
    }
    let root = web_root.join("-/apps").join(service);
    crate::spa::serve_dir(&root, path).await.unwrap_or_else(not_found_response)
}

async fn client(
    State(c): State<Arc<Contributions>>,
    Path((service, client, os, arch)): Path<(String, String, String, String)>,
    headers: HeaderMap,
) -> Response {
    if !is_name(&service) || !is_name(&client) {
        return not_found_response();
    }
    let dir = c.client_dir.join(&service).join(&client);
    client_download::serve_client(&c.auth, &headers, &dir, &client, &os, &arch).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::tests::{jwk_for, user_header};
    use axum::body::Body;
    use axum::http::Request;
    use gateway_grpcserver::authorizer::JwkCache;
    use gateway_key::keys;
    use tower::ServiceExt;

    /// A merged webapp as the fleet builder writes it: the gateway's own
    /// index.html, one module (tenantecho) with an asset, the index, and one
    /// contributed client for two targets.
    struct Fleet {
        dir: PathBuf,
        key: keys::ImmutableKey,
    }

    impl Fleet {
        fn new() -> Self {
            let dir = std::env::temp_dir().join(format!("gateway-contrib-{}", uuid::Uuid::new_v4()));
            let web = dir.join("web");
            std::fs::create_dir_all(web.join("-/apps/tenantecho/assets")).expect("module dir");
            std::fs::write(web.join("index.html"), b"<html><head></head>gateway</html>").expect("gateway index");
            std::fs::write(web.join("-/apps/tenantecho/index.html"), b"<html><head></head>echo</html>")
                .expect("module index");
            std::fs::write(web.join("-/apps/tenantecho/assets/app.js"), b"echo bundle").expect("module asset");
            std::fs::write(
                web.join("-/apps.json"),
                br#"[{"service":"tenantecho","title":"Echo","version":"1.2.0","path":"/-/apps/tenantecho/"}]"#,
            )
            .expect("index");
            let clients = dir.join("clients/tenantecho/echo");
            std::fs::create_dir_all(&clients).expect("clients dir");
            std::fs::write(clients.join("echo-linux-amd64"), b"ELF echo").expect("linux client");
            std::fs::write(clients.join("echo-windows-amd64.exe"), b"MZ echo").expect("windows client");
            std::fs::write(dir.join("secret.txt"), b"SECRET").expect("secret");
            Self { dir, key: keys::generate_ec_p256_key().expect("signing key") }
        }

        fn router(&self) -> Router {
            self.router_with(Some(self.dir.join("web")))
        }

        fn router_with(&self, web_root: Option<PathBuf>) -> Router {
            router(Arc::new(Contributions {
                web_root,
                client_dir: self.dir.join("clients"),
                auth: Arc::new(GatewayAuth::new(Arc::new(JwkCache::seeded(vec![jwk_for(&self.key)])), false)),
            }))
        }

        fn user(&self) -> String {
            user_header(&self.key, "gateway")
        }
    }

    impl Drop for Fleet {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    async fn get(router: &Router, uri: &str, authorization: Option<&str>) -> (StatusCode, HeaderMap, Vec<u8>) {
        let mut request = Request::get(uri);
        if let Some(value) = authorization {
            request = request.header(header::AUTHORIZATION, value);
        }
        let response = router.clone().oneshot(request.body(Body::empty()).unwrap()).await.unwrap();
        let (parts, body) = response.into_parts();
        let body = axum::body::to_bytes(body, 1 << 20).await.expect("body").to_vec();
        (parts.status, parts.headers, body)
    }

    fn text(body: &[u8]) -> String {
        String::from_utf8_lossy(body).into_owned()
    }

    #[tokio::test]
    async fn a_module_is_served_from_its_own_directory() {
        let fleet = Fleet::new();
        let router = fleet.router();

        let (status, headers, body) = get(&router, "/-/apps/tenantecho/assets/app.js", None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, b"echo bundle");
        assert_eq!(headers[header::CONTENT_TYPE], "text/javascript");

        let (status, _, body) = get(&router, "/-/apps/tenantecho/", None).await;
        assert_eq!(status, StatusCode::OK);
        assert!(text(&body).ends_with("echo</html>"), "{}", text(&body));
    }

    /// The module shares the session through the origin and the bootstrap
    /// object, under its tacplus-dev name.
    #[tokio::test]
    async fn a_module_index_carries_the_bootstrap_object() {
        crate::spa::init_bootstrap("");
        let fleet = Fleet::new();

        let (_, _, body) = get(&fleet.router(), "/-/apps/tenantecho/", None).await;
        let body = text(&body);
        assert!(body.contains("<script>window.__TACPLUS__={"), "{body}");
        assert!(!body.contains("SCHEMATIC"), "{body}");
    }

    /// An unknown path under a module is that module's client-side route: its
    /// own index.html, never the gateway's.
    #[tokio::test]
    async fn the_spa_fallback_is_the_modules_own() {
        let fleet = Fleet::new();

        for uri in ["/-/apps/tenantecho/pings/42", "/-/apps/tenantecho/assets/missing.js"] {
            let (status, headers, body) = get(&fleet.router(), uri, None).await;
            assert_eq!(status, StatusCode::OK, "{uri}");
            assert_eq!(headers[header::CONTENT_TYPE], "text/html; charset=utf-8", "{uri}");
            assert!(text(&body).ends_with("echo</html>"), "{uri}: {}", text(&body));
        }
    }

    #[tokio::test]
    async fn a_service_without_a_module_is_not_found() {
        let fleet = Fleet::new();

        for uri in ["/-/apps/nosuch/", "/-/apps/nosuch/anything"] {
            let (status, _, body) = get(&fleet.router(), uri, None).await;
            assert_eq!(status, StatusCode::NOT_FOUND, "{uri}");
            assert!(!text(&body).contains("gateway</html>"), "{uri}");
        }
        // A gateway with no WEB_ROOT has no modules either.
        let (status, _, _) = get(&fleet.router_with(None), "/-/apps/tenantecho/", None).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn a_module_root_without_its_slash_redirects_to_it() {
        let fleet = Fleet::new();

        let (status, headers, _) = get(&fleet.router(), "/-/apps/tenantecho?x=1", None).await;
        assert_eq!(status, StatusCode::PERMANENT_REDIRECT);
        assert_eq!(headers[header::LOCATION], "/-/apps/tenantecho/?x=1");
    }

    /// Nothing under a module reaches outside it: not the gateway's files, not
    /// another module's, not the host's.
    #[tokio::test]
    async fn a_path_out_of_a_module_is_refused() {
        let fleet = Fleet::new();
        let router = fleet.router();

        for uri in [
            "/-/apps/tenantecho/../../index.html",
            "/-/apps/tenantecho/%2e%2e/%2e%2e/index.html",
            "/-/apps/../../secret.txt",
            "/-/apps/..%2f..%2fsecret.txt/",
        ] {
            let (status, _, body) = get(&router, uri, None).await;
            assert_ne!(status, StatusCode::OK, "{uri}: {}", text(&body));
            assert!(!text(&body).contains("SECRET") && !text(&body).contains("gateway</html>"), "{uri}");
        }

        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(
                fleet.dir.join("secret.txt"),
                fleet.dir.join("web/-/apps/tenantecho/escape"),
            )
            .expect("symlink");
            let (status, _, body) = get(&router, "/-/apps/tenantecho/escape", None).await;
            assert_eq!(status, StatusCode::BAD_REQUEST);
            assert!(!text(&body).contains("SECRET"));
        }
    }

    #[tokio::test]
    async fn the_index_is_served_as_written() {
        let fleet = Fleet::new();

        let (status, headers, body) = get(&fleet.router(), "/-/apps.json", None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(headers[header::CONTENT_TYPE], "application/json");
        let index: serde_json::Value = serde_json::from_slice(&body).expect("json");
        assert_eq!(
            index,
            serde_json::json!([{"service": "tenantecho", "title": "Echo", "version": "1.2.0", "path": "/-/apps/tenantecho/"}])
        );
    }

    /// A fleet that contributes nothing has no index file: an empty list.
    #[tokio::test]
    async fn no_index_is_an_empty_list() {
        let fleet = Fleet::new();
        std::fs::remove_file(fleet.dir.join("web/-/apps.json")).expect("remove index");

        for router in [fleet.router(), fleet.router_with(None)] {
            let (status, _, body) = get(&router, "/-/apps.json", None).await;
            assert_eq!(status, StatusCode::OK);
            assert_eq!(body, b"[]");
        }
    }

    #[tokio::test]
    async fn a_contributed_client_is_served_to_a_signed_in_user() {
        let fleet = Fleet::new();
        let user = fleet.user();

        let (status, headers, body) =
            get(&fleet.router(), "/-/clients/tenantecho/echo/linux/amd64", Some(&user)).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, b"ELF echo");
        assert_eq!(headers[header::CONTENT_DISPOSITION], "attachment; filename=\"echo-linux-amd64\"");
        assert_eq!(headers[header::CACHE_CONTROL], "private, max-age=86400");

        let (status, headers, body) =
            get(&fleet.router(), "/-/clients/tenantecho/echo/windows/amd64", Some(&user)).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, b"MZ echo");
        assert_eq!(headers[header::CONTENT_DISPOSITION], "attachment; filename=\"echo-windows-amd64.exe\"");
    }

    /// The same sign-in rule as /client/{os}/{arch}: no token, a token the
    /// gateway cannot verify, or one for another audience gets nothing.
    #[tokio::test]
    async fn a_contributed_client_needs_a_signed_in_user() {
        let fleet = Fleet::new();
        let stranger = user_header(&keys::generate_ec_p256_key().expect("key"), "gateway");
        let other_audience = user_header(&fleet.key, "echo");

        for authorization in [None, Some("Bearer not-a-token"), Some(stranger.as_str()), Some(other_audience.as_str())] {
            let (status, _, body) =
                get(&fleet.router(), "/-/clients/tenantecho/echo/linux/amd64", authorization).await;
            assert_eq!(status, StatusCode::UNAUTHORIZED, "{authorization:?}");
            assert_ne!(body, b"ELF echo");
        }
    }

    /// The fixed targets only: no darwin/amd64, nothing that is not a target,
    /// and a target the fleet did not build is a 404.
    #[tokio::test]
    async fn only_the_fixed_targets_are_served() {
        let fleet = Fleet::new();
        let user = fleet.user();

        for uri in [
            "/-/clients/tenantecho/echo/darwin/amd64",
            "/-/clients/tenantecho/echo/linux/riscv64",
            "/-/clients/tenantecho/echo/linux/arm64",
            "/-/clients/tenantecho/nosuch/linux/amd64",
            "/-/clients/nosuch/echo/linux/amd64",
            "/-/clients/tenantecho/..%2f..%2fsecret.txt/linux/amd64",
        ] {
            let (status, _, body) = get(&fleet.router(), uri, Some(&user)).await;
            assert_eq!(status, StatusCode::NOT_FOUND, "{uri}: {}", text(&body));
        }
    }

    /// Any other path under /-/ is this module's 404, not the gateway's SPA.
    #[tokio::test]
    async fn the_rest_of_the_prefix_is_not_found() {
        let fleet = Fleet::new();

        for uri in ["/-", "/-/", "/-/apps", "/-/apps/", "/-/other", "/-/clients/tenantecho/echo"] {
            let (status, _, _) = get(&fleet.router(), uri, None).await;
            assert_eq!(status, StatusCode::NOT_FOUND, "{uri}");
        }
    }

    /// Merged with the generated routes, as main.rs does, nothing collides
    /// and the REST router's fallback (SPIFFE paths, then the gateway's SPA)
    /// never sees a path under /-/.
    #[tokio::test]
    async fn the_prefix_merges_beside_the_generated_routes() {
        let fleet = Fleet::new();
        let router = crate::rest_translation::rest_routes(Router::new(), any(|| async { "rest" }))
            .fallback(|| async { "fallback" })
            .merge(fleet.router());

        let (_, _, body) = get(&router, "/-/other", None).await;
        assert_eq!(text(&body), "not found");
        let (_, _, body) = get(&router, "/-/apps/tenantecho/x", None).await;
        assert!(text(&body).ends_with("echo</html>"));
        let (_, _, body) = get(&router, "/somewhere/else", None).await;
        assert_eq!(text(&body), "fallback");
        let route = gateway_model::s2sm::rest_dispatch::ROUTES
            .iter()
            .find(|r| !r.http_path.is_empty())
            .expect("a REST route");
        let (_, _, body) = get(&router, route.http_path, None).await;
        assert_eq!(text(&body), "rest", "{}", route.http_path);
    }

    /// The prefix is the gateway's because no proto route can be under it:
    /// every generated REST path and gRPC method is `/{package}/...` or
    /// `/{package}.{Service}/...`, and no proto identifier starts with `-`.
    #[test]
    fn no_proto_route_is_under_the_prefix() {
        use gateway_model::s2sm::rest_dispatch::ROUTES;

        assert!(!ROUTES.is_empty());
        for route in ROUTES {
            assert!(!route.http_path.starts_with("/-"), "{}", route.http_path);
            assert!(!route.grpc_path.starts_with("/-"), "{}", route.grpc_path);
        }
    }
}
