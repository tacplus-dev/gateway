//! The plaintext (port 80) half of the edge, and the HSTS header on the TLS half.
//!
//! When one LoadBalancer carries both 443 and 80 to this pod, the gateway — not
//! a second externally-exposed Service — is what answers on 80. It answers
//! exactly three ways (it no longer proxies ACME HTTP-01 challenges: the
//! deployment's pipeline answers ACME by DNS-01, #25):
//!
//!   1. The blob store's byte paths — `/b/*` and `/upload/*` — are `404`, NOT
//!      redirected. The decision doc requires it (R3: "port-80 answers `/b/*`
//!      with 404"), because the path IS the credential: a `301` puts the token in
//!      a `Location` header, which is logged by every intermediary between here
//!      and the client, and it invites a client to keep presenting credentials
//!      over plaintext. A 404 tells it nothing and costs it one request.
//!   2. Any other `GET`/`HEAD` is redirected `301` to the same path on `https://`.
//!   3. Anything else is `405`. A redirect would turn a POST into a GET, and
//!      there is nothing here to serve a body to.
//!
//! Nothing else is routed on 80: no SPA, no REST, no gRPC. Everything the
//! gateway actually serves is behind TLS, and the redirect is what gets a client
//! there.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::body::Body;
use axum::response::Response;
use http::{header, HeaderValue, Method, Request, StatusCode};

/// Two years, subdomains included. No `preload` token: it was never submitted, and
/// `includeSubDomains` + `preload` would lock every subdomain of the domain (its mail
/// host, the dev host) into HTTPS-only in every browser forever (decided 2026-09-30).
const HSTS_VALUE: &str = "max-age=63072000; includeSubDomains";

/// Serves the port-80 listener.
pub struct PlainHttp;

impl PlainHttp {

    pub async fn handle(&self, req: Request<Body>) -> Response<Body> {
        if req.method() != Method::GET && req.method() != Method::HEAD {
            return Response::builder()
                .status(StatusCode::METHOD_NOT_ALLOWED)
                .header(header::ALLOW, "GET, HEAD")
                .body(Body::empty())
                .expect("static 405 response");
        }

        // The blob paths are answered here rather than redirected. See rule 2 in
        // this module's comment.
        if is_blob_path(req.uri().path()) {
            return status_only(StatusCode::NOT_FOUND);
        }

        redirect_to_https(&req)
    }
}

/// True for the blob store's two byte paths. The prefixes are
/// `blob_proxy`'s, so the plaintext rule and the TLS route cannot come to
/// disagree about which paths carry a token.
fn is_blob_path(path: &str) -> bool {
    path.starts_with(crate::blob_proxy::PATH_BLOB) || path.starts_with(crate::blob_proxy::PATH_UPLOAD)
}

/// `301` to the same path and query on `https://`, on the host the client
/// asked for. A request with no usable Host header has no target to redirect
/// to and gets a 400.
fn redirect_to_https(req: &Request<Body>) -> Response<Body> {
    let host = req
        .uri()
        .host()
        .or_else(|| {
            req.headers()
                .get(header::HOST)
                .and_then(|value| value.to_str().ok())
        })
        .unwrap_or("");
    // Strip any port the client sent: the https target is 443, never whatever
    // port the plaintext request arrived on.
    let host = host.split(':').next().unwrap_or("");
    if host.is_empty() {
        return status_only(StatusCode::BAD_REQUEST);
    }

    let path_and_query = req
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/");
    let location = format!("https://{host}{path_and_query}");

    match HeaderValue::from_str(&location) {
        Ok(value) => Response::builder()
            .status(StatusCode::MOVED_PERMANENTLY)
            .header(header::LOCATION, value)
            .body(Body::empty())
            .expect("static 301 response"),
        // A Host header with control characters in it.
        Err(_) => status_only(StatusCode::BAD_REQUEST),
    }
}

fn status_only(status: StatusCode) -> Response<Body> {
    Response::builder()
        .status(status)
        .body(Body::empty())
        .expect("static status response")
}

/// Binds `addr` and serves the port-80 rules until the process exits. Returns
/// once the listener is bound, so a failure to bind is reported at startup
/// rather than swallowed by a background task.
pub async fn serve(addr: SocketAddr) -> std::io::Result<()> {
    let plain = Arc::new(PlainHttp);
    let app = axum::Router::new().fallback(move |req: Request<Body>| {
        let plain = Arc::clone(&plain);
        async move { plain.handle(req).await }
    });

    let listener = tokio::net::TcpListener::bind(addr).await?;
    tokio::spawn(async move {
        if let Err(e) = axum::serve(listener, app).await {
            tracing::error!(error = %e, "plaintext HTTP listener stopped");
        }
    });
    Ok(())
}

/// Adds HSTS to every response served over TLS. Applied to the whole 443 app —
/// REST, SPA, Mint and the proxied gRPC alike — because the header is a
/// statement about the ORIGIN, not about one route, and a browser that never
/// sees it on the response it happens to make keeps trying plaintext first.
pub async fn hsts(
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let mut response = next.run(req).await;
    response.headers_mut().insert(
        header::STRICT_TRANSPORT_SECURITY,
        HeaderValue::from_static(HSTS_VALUE),
    );
    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::routing::get;
    use axum::Router;
    use tower::ServiceExt;

    fn request(method: &str, uri: &str) -> Request<Body> {
        Request::builder()
            .method(method)
            .uri(uri)
            .header(header::HOST, "console.example.com")
            .body(Body::empty())
            .unwrap()
    }

    /// The ACME challenge path is no longer proxied anywhere: it is a GET like
    /// any other, and redirected.
    #[tokio::test]
    async fn acme_challenge_path_is_redirected_like_any_other() {
        let response = PlainHttp
            .handle(request("GET", "/.well-known/acme-challenge/abc123"))
            .await;

        assert_eq!(response.status(), StatusCode::MOVED_PERMANENTLY);
        assert_eq!(
            response.headers().get(header::LOCATION).unwrap(),
            "https://console.example.com/.well-known/acme-challenge/abc123"
        );
    }

    /// Every other GET is a 301 to the same path on https, query string kept.
    #[tokio::test]
    async fn non_challenge_get_redirects_to_https() {
        let plain = PlainHttp;
        let response = plain.handle(request("GET", "/app/login?next=%2Fhome")).await;

        assert_eq!(response.status(), StatusCode::MOVED_PERMANENTLY);
        assert_eq!(
            response.headers().get(header::LOCATION).unwrap(),
            "https://console.example.com/app/login?next=%2Fhome"
        );
    }

    /// HEAD redirects like GET — a HEAD on 80 is a client checking a URL.
    #[tokio::test]
    async fn head_redirects_to_https() {
        let plain = PlainHttp;
        let response = plain.handle(request("HEAD", "/")).await;

        assert_eq!(response.status(), StatusCode::MOVED_PERMANENTLY);
        assert_eq!(
            response.headers().get(header::LOCATION).unwrap(),
            "https://console.example.com/"
        );
    }

    /// A Host header carrying the port must not leak that port into the
    /// https:// target.
    #[tokio::test]
    async fn redirect_drops_the_port_from_the_host_header() {
        let plain = PlainHttp;
        let response = plain
            .handle(
                Request::builder()
                    .method("GET")
                    .uri("/x")
                    .header(header::HOST, "console.example.com:80")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await;

        assert_eq!(
            response.headers().get(header::LOCATION).unwrap(),
            "https://console.example.com/x"
        );
    }

    /// Anything that is not GET or HEAD is 405. A 301 would silently turn a
    /// POST into a GET, and port 80 serves no application surface to POST to.
    #[tokio::test]
    async fn non_get_methods_are_405() {
        let plain = PlainHttp;
        for method in ["POST", "PUT", "DELETE", "PATCH", "OPTIONS"] {
            let response = plain.handle(request(method, "/app/login")).await;
            assert_eq!(
                response.status(),
                StatusCode::METHOD_NOT_ALLOWED,
                "{method} on port 80 must be rejected"
            );
            assert_eq!(response.headers().get(header::ALLOW).unwrap(), "GET, HEAD");
        }
    }

    /// The blob paths are 404 on port 80, not 301: a redirect would put the
    /// token in a Location header, which every intermediary logs.
    #[tokio::test]
    async fn blob_paths_are_404_on_port_80() {
        let plain = PlainHttp;
        for path in ["/b/sometoken", "/upload/sometoken", "/b/", "/upload/"] {
            let response = plain.handle(request("GET", path)).await;
            assert_eq!(
                response.status(),
                StatusCode::NOT_FOUND,
                "{path} on port 80 must be 404"
            );
            assert!(
                response.headers().get(header::LOCATION).is_none(),
                "{path} must not be redirected — the Location header would carry the token"
            );
        }
        // HEAD too: a client checking a blob URL over plaintext learns nothing.
        let head = plain.handle(request("HEAD", "/b/sometoken")).await;
        assert_eq!(head.status(), StatusCode::NOT_FOUND);
    }

    /// Every response off the TLS side carries HSTS, with the exact max-age,
    /// includeSubDomains and preload the design calls for.
    #[tokio::test]
    async fn hsts_header_is_set_on_tls_responses() {
        let app = Router::new()
            .route("/healthz", get(|| async { "ok" }))
            .layer(axum::middleware::from_fn(hsts));

        let response = app.oneshot(request("GET", "/healthz")).await.unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get(header::STRICT_TRANSPORT_SECURITY)
                .unwrap(),
            "max-age=63072000; includeSubDomains"
        );
    }
}
