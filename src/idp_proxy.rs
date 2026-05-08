use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::convert::Infallible;

use axum::body::Body;
use axum::response::Response;
use http::{Request, StatusCode};
use http_body_util::BodyExt;
use hyper_util::rt::TokioIo;
use rustls::RootCertStore;
use rustls::pki_types::ServerName;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

use crate::health::HealthWatcher;

/// IdpProxy HTTP-proxies requests to the Keycloak IDP service.
///
/// Keycloak is accessed over HTTPS using a kernel-issued certificate. All
/// service certs have SAN DNS:kernel, so TLS verification uses "kernel" as
/// the server name — the same approach as the gRPC resolver's domain_name("kernel").
///
/// Gateway routes /realms/* and /admin/* through this proxy instead of the
/// gRPC path. This is the only HTTP (non-gRPC) backend in the gateway.
pub struct IdpProxy {
    health: HealthWatcher,
    tls_connector: TlsConnector,
    counter: AtomicUsize,
}

impl IdpProxy {
    /// Creates an IdpProxy from the kernel CA PEM bundle.
    /// HealthWatcher is cheaply cloneable — all internal state is Arc-wrapped.
    pub fn new(health: HealthWatcher, ca_pem_bundle: &str) -> Result<Self, String> {
        let connector = build_tls_connector(ca_pem_bundle)
            .map_err(|e| format!("IdpProxy: failed to build TLS connector: {e}"))?;
        Ok(Self {
            health,
            tls_connector: connector,
            counter: AtomicUsize::new(0),
        })
    }

    /// Returns true if the request path starts with an IDP proxy prefix.
    pub fn is_idp_request(path: &str) -> bool {
        path.starts_with("/realms/") || path == "/realms"
            || path.starts_with("/admin/") || path == "/admin"
    }

    /// Forwards an incoming HTTP request to the Keycloak backend.
    pub async fn handle(&self, req: Request<Body>) -> Response<Body> {
        let endpoints = self.health.get_endpoints("keycloak");
        if endpoints.is_empty() {
            tracing::warn!("idp_proxy: no healthy keycloak endpoints");
            return error_response(StatusCode::SERVICE_UNAVAILABLE, "IDP service unavailable");
        }

        // Round-robin across healthy endpoints.
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

        // Connect to the Keycloak endpoint over TLS, using "kernel" as SNI.
        // All kernel-issued service certs have SAN DNS:kernel.
        let server_name = ServerName::try_from("kernel")
            .map_err(|e| format!("invalid server name: {e}"))?;
        let tcp = TcpStream::connect(endpoint).await?;
        let tls_stream = self.tls_connector.connect(server_name, tcp).await?;
        let io = TokioIo::new(tls_stream);

        // Build an HTTP/1.1 connection (Keycloak supports HTTP/1.1 and HTTP/2).
        let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await?;
        tokio::spawn(async move {
            if let Err(e) = conn.await {
                tracing::debug!(error = %e, "idp_proxy: backend connection closed");
            }
        });

        // Reconstruct the request for the backend.
        let uri_str = format!("https://{}{}", endpoint, parts.uri.path_and_query()
            .map(|pq| pq.as_str())
            .unwrap_or(""));
        let backend_uri: http::Uri = uri_str.parse()?;

        let mut backend_req = Request::builder()
            .method(parts.method.clone())
            .uri(backend_uri)
            .version(http::Version::HTTP_11);

        // Copy request headers, replacing Host with the backend endpoint.
        for (name, value) in &parts.headers {
            if name == http::header::HOST {
                continue;
            }
            backend_req = backend_req.header(name, value);
        }
        backend_req = backend_req.header(http::header::HOST, endpoint);

        let backend_req = backend_req.body(
            http_body_util::Full::new(body_bytes)
                .map_err(|e| match e {})
                .boxed()
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

/// Build a TlsConnector from a PEM CA bundle.
fn build_tls_connector(ca_pem_bundle: &str) -> Result<TlsConnector, Box<dyn std::error::Error>> {
    let mut root_store = RootCertStore::empty();

    // Parse the PEM bundle and add each certificate to the root store.
    for cert in rustls_pemfile::certs(&mut ca_pem_bundle.as_bytes()) {
        root_store.add(cert?)?;
    }

    let config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    Ok(TlsConnector::from(Arc::new(config)))
}

fn error_response(status: StatusCode, msg: &'static str) -> Response<Body> {
    Response::builder()
        .status(status)
        .body(Body::from(msg))
        .unwrap()
}
