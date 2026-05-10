use std::sync::atomic::{AtomicUsize, Ordering};

use axum::body::Body;
use axum::response::Response;
use http::{Request, StatusCode};
use http_body_util::BodyExt;
use hyper_util::rt::TokioIo;
use tokio::net::TcpStream;

use gateway_tacplus::types::services::keycloak::{GATEWAY_PROXY_PATH_ADMIN, GATEWAY_PROXY_PATH_REALMS};

use crate::health::HealthWatcher;

/// IdpProxy HTTP-proxies requests to the Keycloak IDP service.
///
/// Keycloak is accessed over plain HTTP on port 8080 (its internal HTTP listener).
/// The connection is intra-cluster so TLS is not required on this leg — the
/// external-facing HTTPS is terminated by the gateway itself.
///
/// Gateway routes /realms/* and /admin/* through this proxy instead of the
/// gRPC path. This is the only HTTP (non-gRPC) backend in the gateway.
pub struct IdpProxy {
    health: HealthWatcher,
    counter: AtomicUsize,
}

impl IdpProxy {
    /// Creates an IdpProxy backed by the given HealthWatcher.
    /// HealthWatcher is cheaply cloneable — all internal state is Arc-wrapped.
    pub fn new(health: HealthWatcher) -> Self {
        Self {
            health,
            counter: AtomicUsize::new(0),
        }
    }

    /// Returns true if the request path starts with an IDP proxy prefix.
    /// Path prefixes are defined as constants in the keycloak proto.
    pub fn is_idp_request(path: &str) -> bool {
        path == GATEWAY_PROXY_PATH_REALMS || path.starts_with(&format!("{}/", GATEWAY_PROXY_PATH_REALMS))
            || path == GATEWAY_PROXY_PATH_ADMIN || path.starts_with(&format!("{}/", GATEWAY_PROXY_PATH_ADMIN))
    }

    /// Forwards an incoming HTTP request to the Keycloak backend.
    pub async fn handle(&self, req: Request<Body>) -> Response<Body> {
        // health.get_endpoints("keycloak") returns the gRPC port (8443).
        // Keycloak's internal HTTP listener is on port 8080 — same host, different port.
        let endpoints: Vec<String> = self.health.get_endpoints("keycloak")
            .into_iter()
            .filter_map(|ep| ep.split(':').next().map(|host| format!("{}:8080", host)))
            .collect();
        if endpoints.is_empty() {
            tracing::warn!("idp_proxy: no healthy keycloak endpoints");
            return error_response(StatusCode::SERVICE_UNAVAILABLE, "IDP service unavailable");
        }

        // Round-robin across healthy endpoints (using Keycloak HTTP port 8080).
        let idx = self.counter.fetch_add(1, Ordering::Relaxed) % endpoints.len();
        let endpoint = &endpoints[idx];

        match self.proxy_request(req, endpoint).await {
            Ok(resp) => resp,
            Err(e) => {
                tracing::error!(error = %e, endpoint = %endpoint, "idp_proxy: request failed");
                error_response(StatusCode::BAD_GATEWAY, "IDP request failed")
            }
        }
    }

    async fn proxy_request(
        &self,
        req: Request<Body>,
        endpoint: &str,
    ) -> Result<Response<Body>, Box<dyn std::error::Error + Send + Sync>> {
        let (parts, body) = req.into_parts();

        // Collect the incoming body.
        let body_bytes = body.collect().await?.to_bytes();

        // Connect to the Keycloak endpoint over plain TCP (HTTP, not HTTPS).
        let tcp = TcpStream::connect(endpoint).await?;
        let io = TokioIo::new(tcp);

        // Build an HTTP/1.1 connection.
        let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await?;
        tokio::spawn(async move {
            if let Err(e) = conn.await {
                tracing::debug!(error = %e, "idp_proxy: backend connection closed");
            }
        });

        // Reconstruct the request for the backend.
        let uri_str = format!("http://{}{}", endpoint, parts.uri.path_and_query()
            .map(|pq| pq.as_str())
            .unwrap_or(""));
        let backend_uri: http::Uri = uri_str.parse()?;

        let mut backend_req = Request::builder()
            .method(parts.method.clone())
            .uri(backend_uri)
            .version(http::Version::HTTP_11);

        // Extract the original Host header (external FQDN) for X-Forwarded-Host.
        let original_host = parts.headers.get(http::header::HOST)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();

        // Copy request headers, replacing Host with the backend endpoint.
        for (name, value) in &parts.headers {
            if name == http::header::HOST {
                continue;
            }
            backend_req = backend_req.header(name, value);
        }
        backend_req = backend_req.header(http::header::HOST, endpoint);

        // Inject X-Forwarded-* headers so Keycloak constructs correct external URLs.
        if !original_host.is_empty() {
            backend_req = backend_req.header("X-Forwarded-Host", original_host.as_str());
        }
        backend_req = backend_req.header("X-Forwarded-Proto", "https");
        backend_req = backend_req.header("X-Forwarded-Port", "443");

        let backend_req = backend_req.body(
            http_body_util::Full::new(body_bytes).boxed()
        )?;

        let backend_resp = sender.send_request(backend_req).await?;

        // Stream the response back.
        let (resp_parts, resp_body) = backend_resp.into_parts();
        let response_body = resp_body
            .map_err(|e| axum::Error::new(e))
            .boxed_unsync();

        let mut resp = Response::builder().status(resp_parts.status);
        for (name, value) in &resp_parts.headers {
            resp = resp.header(name, value);
        }

        Ok(resp.body(Body::new(response_body))?)
    }
}

fn error_response(status: StatusCode, msg: &'static str) -> Response<Body> {
    Response::builder()
        .status(status)
        .body(Body::from(msg))
        .unwrap()
}
