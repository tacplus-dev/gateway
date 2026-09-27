//! The plaintext (port 80) half of the edge, and the HSTS header on the TLS half.
//!
//! One LoadBalancer carries both 443 and 80 to this pod, so the gateway — not a
//! second externally-exposed Service — is what answers on 80. It answers exactly
//! three ways:
//!
//!   1. `GET`/`HEAD` under `/.well-known/acme-challenge/` is proxied, in-cluster
//!      and in plaintext, to the letsencrypt service's HTTP-01 responder. That
//!      responder (certmagic's `AltHTTPPort` solver) is no longer reachable from
//!      outside the cluster at all; this hop is its only path from the internet.
//!   2. The blob store's byte paths — `/b/*` and `/upload/*` — are `404`, NOT
//!      redirected. The decision doc requires it (R3: "port-80 answers `/b/*`
//!      with 404"), because the path IS the credential: a `301` puts the token in
//!      a `Location` header, which is logged by every intermediary between here
//!      and the client, and it invites a client to keep presenting credentials
//!      over plaintext. A 404 tells it nothing and costs it one request.
//!   3. Any other `GET`/`HEAD` is redirected `301` to the same path on `https://`.
//!   4. Anything else is `405`. A redirect would turn a POST into a GET, and
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
use http_body_util::BodyExt;
use hyper_util::rt::TokioIo;
use tokio::net::TcpStream;

/// The ACME HTTP-01 challenge path prefix, fixed by RFC 8555 §8.3.
const ACME_CHALLENGE_PREFIX: &str = "/.well-known/acme-challenge/";

/// Two years, subdomains included, and the `preload` token. The token only
/// makes the domain ELIGIBLE for the browser preload list — it is not a
/// submission, and submitting is a separate, deliberate step.
const HSTS_VALUE: &str = "max-age=63072000; includeSubDomains; preload";

/// Serves the port-80 listener. `acme_backend` is the in-cluster `host:port` of
/// the letsencrypt service's HTTP-01 responder; `None` means no backend was
/// configured, and challenge requests are answered 503 rather than proxied.
pub struct PlainHttp {
    acme_backend: Option<String>,
}

impl PlainHttp {
    pub fn new(acme_backend: Option<String>) -> Self {
        Self { acme_backend }
    }

    pub async fn handle(&self, req: Request<Body>) -> Response<Body> {
        if req.method() != Method::GET && req.method() != Method::HEAD {
            return Response::builder()
                .status(StatusCode::METHOD_NOT_ALLOWED)
                .header(header::ALLOW, "GET, HEAD")
                .body(Body::empty())
                .expect("static 405 response");
        }

        if req.uri().path().starts_with(ACME_CHALLENGE_PREFIX) {
            return self.proxy_challenge(req).await;
        }

        // The blob paths are answered here rather than redirected. See rule 2 in
        // this module's comment.
        if is_blob_path(req.uri().path()) {
            return status_only(StatusCode::NOT_FOUND);
        }

        redirect_to_https(&req)
    }

    async fn proxy_challenge(&self, req: Request<Body>) -> Response<Body> {
        let Some(backend) = self.acme_backend.as_deref() else {
            tracing::warn!(
                path = %req.uri().path(),
                "acme challenge request but no acme_backend configured"
            );
            return status_only(StatusCode::SERVICE_UNAVAILABLE);
        };

        match proxy_plaintext(req, backend).await {
            Ok(resp) => resp,
            Err(e) => {
                // Expected whenever no issuance is in flight: certmagic binds
                // the solver only while it is solving a challenge.
                tracing::warn!(error = %e, backend = %backend, "acme challenge proxy failed");
                status_only(StatusCode::BAD_GATEWAY)
            }
        }
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

/// Forwards one request over a plaintext HTTP/1.1 connection to `backend`
/// (`host:port`) and returns its response. The same shape as `idp_proxy`, minus
/// the TLS: the ACME responder is in-cluster, plaintext, and serves a challenge
/// token that is public by construction.
async fn proxy_plaintext(
    req: Request<Body>,
    backend: &str,
) -> Result<Response<Body>, Box<dyn std::error::Error + Send + Sync>> {
    let (parts, body) = req.into_parts();
    let body_bytes = body.collect().await?.to_bytes();

    let tcp = TcpStream::connect(backend).await?;
    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tcp)).await?;
    tokio::spawn(async move {
        if let Err(e) = conn.await {
            tracing::debug!(error = %e, "acme proxy: backend connection closed");
        }
    });

    let path_and_query = parts
        .uri
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/");
    // Origin-form (`/path?q`), not absolute-form: this is a direct HTTP/1.1
    // request to the responder, not a request through a forward proxy.
    let backend_uri: http::Uri = path_and_query.parse()?;

    // Preserve the client's original Host header rather than rewriting it to
    // the backend address: certmagic's HTTP-01 solver keys its challenge
    // lookup by the identifier in the request's Host header, so a rewritten
    // Host (e.g. the in-cluster service DNS name) makes it 404 a challenge it
    // is actually holding for the real hostname.
    let mut backend_req = Request::builder()
        .method(parts.method.clone())
        .uri(backend_uri)
        .version(http::Version::HTTP_11);
    for (name, value) in &parts.headers {
        backend_req = backend_req.header(name, value);
    }

    let backend_req = backend_req.body(http_body_util::Full::new(body_bytes).boxed())?;
    let backend_resp = sender.send_request(backend_req).await?;

    let (resp_parts, resp_body) = backend_resp.into_parts();
    let mut resp = Response::builder().status(resp_parts.status);
    for (name, value) in &resp_parts.headers {
        resp = resp.header(name, value);
    }
    Ok(resp.body(Body::new(resp_body.map_err(axum::Error::new).boxed_unsync()))?)
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
pub async fn serve(addr: SocketAddr, acme_backend: Option<String>) -> std::io::Result<()> {
    let plain = Arc::new(PlainHttp::new(acme_backend));
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
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tower::ServiceExt;

    fn request(method: &str, uri: &str) -> Request<Body> {
        Request::builder()
            .method(method)
            .uri(uri)
            .header(header::HOST, "console.seabeam.net")
            .body(Body::empty())
            .unwrap()
    }

    /// A one-shot plaintext HTTP/1.1 server standing in for certmagic's HTTP-01
    /// solver. Returns the address it bound and the request line it received.
    async fn fake_acme_responder(
        body: &'static str,
    ) -> (SocketAddr, tokio::task::JoinHandle<String>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 4096];
            let n = stream.read(&mut buf).await.unwrap();
            let received = String::from_utf8_lossy(&buf[..n]).to_string();
            let response = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\ncontent-length: {}\r\n\r\n{}",
                body.len(),
                body
            );
            stream.write_all(response.as_bytes()).await.unwrap();
            stream.flush().await.unwrap();
            received
        });
        (addr, handle)
    }

    /// The challenge path is proxied to the letsencrypt responder verbatim —
    /// this hop is the only route from the internet to it now that the -acme
    /// LoadBalancer is gone, so a token that does not come back intact means no
    /// certificate.
    #[tokio::test]
    async fn acme_challenge_is_proxied_to_the_letsencrypt_responder() {
        let (addr, received) = fake_acme_responder("token-value.key-authz").await;
        let plain = PlainHttp::new(Some(addr.to_string()));

        let response = plain
            .handle(request("GET", "/.well-known/acme-challenge/abc123"))
            .await;

        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(&body[..], b"token-value.key-authz");

        let request_line = received.await.unwrap();
        assert!(
            request_line.starts_with("GET /.well-known/acme-challenge/abc123 HTTP/1.1"),
            "the backend must see the original path:\n{request_line}"
        );
        // certmagic's HTTP-01 solver keys its challenge lookup by the Host
        // header, not the connection it arrived on — rewriting Host to the
        // backend's own address makes it 404 a challenge it is actually
        // holding for the real hostname (observed live: console.seabeam.net
        // proxied to letsencrypt0.schematic.svc.cluster.local:8080 came back
        // "no information found to solve challenge for identifier:
        // letsencrypt0.schematic.svc.cluster.local").
        assert!(
            request_line.contains("host: console.seabeam.net")
                || request_line.contains("Host: console.seabeam.net"),
            "the backend must see the client's original Host header, not the backend address:\n{request_line}"
        );
    }

    /// No backend configured is a misconfiguration, not a redirect: sending the
    /// ACME validator to https:// would fail the challenge in a way that looks
    /// like a DNS or firewall problem.
    #[tokio::test]
    async fn acme_challenge_without_a_backend_is_503() {
        let plain = PlainHttp::new(None);
        let response = plain
            .handle(request("GET", "/.well-known/acme-challenge/abc123"))
            .await;
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    /// Every other GET is a 301 to the same path on https, query string kept.
    #[tokio::test]
    async fn non_challenge_get_redirects_to_https() {
        let plain = PlainHttp::new(None);
        let response = plain.handle(request("GET", "/app/login?next=%2Fhome")).await;

        assert_eq!(response.status(), StatusCode::MOVED_PERMANENTLY);
        assert_eq!(
            response.headers().get(header::LOCATION).unwrap(),
            "https://console.seabeam.net/app/login?next=%2Fhome"
        );
    }

    /// HEAD redirects like GET — a HEAD on 80 is a client checking a URL.
    #[tokio::test]
    async fn head_redirects_to_https() {
        let plain = PlainHttp::new(None);
        let response = plain.handle(request("HEAD", "/")).await;

        assert_eq!(response.status(), StatusCode::MOVED_PERMANENTLY);
        assert_eq!(
            response.headers().get(header::LOCATION).unwrap(),
            "https://console.seabeam.net/"
        );
    }

    /// A Host header carrying the port must not leak that port into the
    /// https:// target.
    #[tokio::test]
    async fn redirect_drops_the_port_from_the_host_header() {
        let plain = PlainHttp::new(None);
        let response = plain
            .handle(
                Request::builder()
                    .method("GET")
                    .uri("/x")
                    .header(header::HOST, "console.seabeam.net:80")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await;

        assert_eq!(
            response.headers().get(header::LOCATION).unwrap(),
            "https://console.seabeam.net/x"
        );
    }

    /// Anything that is not GET or HEAD is 405. A 301 would silently turn a
    /// POST into a GET, and port 80 serves no application surface to POST to.
    #[tokio::test]
    async fn non_get_methods_are_405() {
        let plain = PlainHttp::new(None);
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
        let plain = PlainHttp::new(None);
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

    /// A POST to the challenge path is still 405: the method check runs first,
    /// and the HTTP-01 responder only ever answers GET.
    #[tokio::test]
    async fn post_to_the_challenge_path_is_405() {
        let plain = PlainHttp::new(Some("127.0.0.1:1".to_string()));
        let response = plain
            .handle(request("POST", "/.well-known/acme-challenge/abc123"))
            .await;
        assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
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
            "max-age=63072000; includeSubDomains; preload"
        );
    }
}
