//! The blob store's two byte paths at the edge: `PUT /upload/<token>` and
//! `GET|HEAD /b/<token>`.
//!
//! Design: `looper/schematic/decisions/blob-store-2026-09-25.md` (v3). The
//! requirements this module implements are R3's carried-over [review] items:
//! registered on the TLS router BEFORE the SPA fallback; streaming, with no body
//! buffered; `HEAD` answered; other methods 405; per-source-IP and per-token rate
//! limits on top of the global edge limiter; and nothing of either path in a log
//! line.
//!
//! WHY IT IS NOT THE gRPC PROXY. A blob is up to the volume group's
//! `max_blob_bytes` and moves as a body, not as a message — the same reason the
//! ACME challenge goes through `plain_http` rather than through a gRPC method.
//!
//! WHY IT IS NOT UNDER THE REST BODY CAP. `limits::with_request_body_limit` caps
//! a REST body at 10 MB. This module is reached from the same interception layer
//! the gRPC proxy is reached from, which sits OUTSIDE that cap, so an upload is
//! bounded by the volume group's own ceiling — enforced on the wire by blobstore,
//! which is the only place that knows which group the token names.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::Instant;

use axum::body::Body;
use axum::response::Response;
use http::{header, HeaderMap, Method, Request, StatusCode};
use hyper_util::rt::TokioIo;
use http_body_util::BodyExt;
use tokio::net::TcpStream;

use crate::health::HealthWatcher;

/// The two public byte paths. They are the same constants blobstore serves, and
/// the token is the whole remainder of the path after the prefix.
pub const PATH_UPLOAD: &str = "/upload/";
pub const PATH_BLOB: &str = "/b/";

/// blobstore's byte listener port — `Config.http_listener`'s default in
/// `blobstore.proto`. The health plane advertises a service's gRPC port (8443),
/// so the byte port is named here and the host comes from there, exactly as
/// `idp_proxy` does for Keycloak's 9443.
const BLOBSTORE_BYTES_PORT: u16 = 8080;

/// The service label the health plane knows blobstore by.
const BLOBSTORE_SERVICE: &str = "blobstore";

/// Per-source-IP request rate for the blob paths, and the burst it allows.
///
/// These are ON TOP of the global edge limiter, not instead of it: the global one
/// bounds the gateway, and these bound one caller's share of the blob paths. A
/// download of a large PDF is one request, so a legitimate client is nowhere near
/// these; a caller walking tokens is.
const DEFAULT_MAX_RPS_PER_IP: f64 = 20.0;
const DEFAULT_BURST_PER_IP: f64 = 40.0;

/// Per-token request rate. Lower than the per-IP rate because one token is one
/// blob: a PDF viewer issuing Range requests is the busiest legitimate pattern,
/// and it is well under this.
const DEFAULT_MAX_RPS_PER_TOKEN: f64 = 10.0;
const DEFAULT_BURST_PER_TOKEN: f64 = 20.0;

/// Buckets kept before the limiter prunes idle ones. A bound is required: the key
/// space is "every token anyone presents", which an attacker chooses.
const MAX_TRACKED_KEYS: usize = 20_000;

/// How long a bucket may go untouched before a prune may drop it. Dropping a
/// bucket forgives its accumulated debt, so it has to be comfortably longer than
/// the time it takes a full bucket to refill.
const BUCKET_IDLE_SECS: f64 = 60.0;

/// PeerAddr is the client's socket address, inserted per connection by
/// [`with_peer_addr`].
///
/// It exists because the per-source-IP limit has to key on something a client
/// cannot choose. `X-Forwarded-For` is a request header — any client can send one
/// — so keying on it would let an attacker both evade its own limit and exhaust
/// somebody else's. The peer address is what the socket says.
#[derive(Clone, Copy, Debug)]
pub struct PeerAddr(pub SocketAddr);

/// Wraps a finished edge service so every request carries its connection's
/// [`PeerAddr`].
///
/// `axum_server::serve` takes a `MakeService<SocketAddr, _>`, which is any
/// `Service<SocketAddr>` returning the per-connection service — so this is the
/// documented seam rather than a hook prised open. The gateway serves its router
/// through `tower::make::Shared`, which discards the address; this keeps
/// everything else about that wiring identical and only stops discarding it.
pub fn with_peer_addr<S>(service: S) -> impl tower::Service<SocketAddr, Response = PeerAddrService<S>, Error = std::convert::Infallible, Future = std::future::Ready<Result<PeerAddrService<S>, std::convert::Infallible>>> + Clone
where
    S: Clone,
{
    tower::service_fn(move |peer: SocketAddr| {
        std::future::ready(Ok(PeerAddrService { inner: service.clone(), peer }))
    })
}

/// The per-connection service [`with_peer_addr`] produces: it stamps `PeerAddr`
/// into the request's extensions and delegates.
#[derive(Clone)]
pub struct PeerAddrService<S> {
    inner: S,
    peer: SocketAddr,
}

impl<S, B> tower::Service<Request<B>> for PeerAddrService<S>
where
    S: tower::Service<Request<B>>,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = S::Future;

    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: Request<B>) -> Self::Future {
        req.extensions_mut().insert(PeerAddr(self.peer));
        self.inner.call(req)
    }
}

/// BlobProxy streams the two byte paths to a healthy blobstore pod.
pub struct BlobProxy {
    health: HealthWatcher,
    counter: AtomicUsize,
    per_ip: RateLimiter,
    per_token: RateLimiter,
}

impl BlobProxy {
    pub fn new(health: HealthWatcher) -> Self {
        Self {
            health,
            counter: AtomicUsize::new(0),
            per_ip: RateLimiter::from_env("GATEWAY_BLOB_MAX_RPS_PER_IP", DEFAULT_MAX_RPS_PER_IP, DEFAULT_BURST_PER_IP),
            per_token: RateLimiter::from_env(
                "GATEWAY_BLOB_MAX_RPS_PER_TOKEN",
                DEFAULT_MAX_RPS_PER_TOKEN,
                DEFAULT_BURST_PER_TOKEN,
            ),
        }
    }

    /// True for the two byte paths, and only for a request that actually names a
    /// token: `/b/` and `/upload/` with nothing after them are not blob requests
    /// and fall through to the SPA like any other unknown path.
    pub fn is_blob_request(path: &str) -> bool {
        token_of(path).is_some()
    }

    pub async fn handle(&self, req: Request<Body>) -> Response<Body> {
        let path = req.uri().path().to_string();
        let Some((prefix, token)) = token_of(&path) else {
            return status_only(StatusCode::NOT_FOUND);
        };

        // Method first, so a POST to a valid token is 405 rather than counted
        // against the token's rate.
        let allowed: &[Method] = if prefix == PATH_UPLOAD {
            &[Method::PUT]
        } else {
            &[Method::GET, Method::HEAD]
        };
        if !allowed.contains(req.method()) {
            let allow = allowed.iter().map(Method::as_str).collect::<Vec<_>>().join(", ");
            return Response::builder()
                .status(StatusCode::METHOD_NOT_ALLOWED)
                .header(header::ALLOW, allow)
                .body(Body::empty())
                .expect("static 405 response");
        }

        // Per-source-IP, then per-token. Per-IP first: a caller walking many
        // tokens must be stopped by its own limit rather than by each token's.
        if let Some(PeerAddr(peer)) = req.extensions().get::<PeerAddr>().copied() {
            if !self.per_ip.allow(&ip_key(peer.ip())) {
                return too_many_requests();
            }
        }
        // Keyed by a HASH of the token, never the token: this map is long-lived
        // process memory and a heap dump of it must not be a list of live
        // credentials.
        if !self.per_token.allow(&token_key(token)) {
            return too_many_requests();
        }

        let Some(backend) = self.pick_backend() else {
            tracing::warn!("blob_proxy: no healthy blobstore endpoints");
            return status_only(StatusCode::SERVICE_UNAVAILABLE);
        };

        forward(req, prefix, &backend).await
    }

    /// Round-robin over the healthy blobstore pods, on the byte port.
    ///
    /// EITHER POD WILL DO FOR EITHER PATH. Both hold every blob, so a read is
    /// served by whichever answers; an upload is accepted by whichever receives it
    /// and mirrored by that pod to its peer. So there is nothing for the gateway
    /// to pin or to be clever about.
    fn pick_backend(&self) -> Option<String> {
        let endpoints: Vec<String> = self
            .health
            .get_endpoints(BLOBSTORE_SERVICE)
            .into_iter()
            .filter_map(|ep| ep.split(':').next().map(|host| format!("{host}:{BLOBSTORE_BYTES_PORT}")))
            .collect();
        if endpoints.is_empty() {
            return None;
        }
        let idx = self.counter.fetch_add(1, Ordering::Relaxed) % endpoints.len();
        Some(endpoints[idx].clone())
    }
}

/// Splits a path into its prefix and token, or None if it is neither byte path.
fn token_of(path: &str) -> Option<(&'static str, &str)> {
    for prefix in [PATH_UPLOAD, PATH_BLOB] {
        if let Some(rest) = path.strip_prefix(prefix) {
            // A token is one path segment. Anything with a further `/` in it is
            // not a token this gateway forwards — and refusing it here is what
            // keeps `/b/../something` from being a blob request at all.
            if !rest.is_empty() && !rest.contains('/') {
                return Some((prefix, rest));
            }
        }
    }
    None
}

/// Proxies one request to `backend` and answers the backend's response, or the
/// status a failed hop maps to.
///
/// A failed hop is a pod that is dead or unreachable — refused, reset mid-body,
/// gone before it answered. For an upload that is 503: the decision (R1) says
/// uploads fail with 503 while a pod is down, and blobstore promotes nothing it
/// did not fully receive, so the upload was refused rather than half-accepted.
/// A read keeps 502.
async fn forward(req: Request<Body>, prefix: &str, backend: &str) -> Response<Body> {
    match proxy_streaming(req, backend).await {
        Ok(resp) => resp,
        Err(e) => {
            // The error is logged; the PATH is not, because the path is the
            // credential.
            tracing::warn!(error = %e, backend = %backend, prefix = %prefix, "blob_proxy: request failed");
            if prefix == PATH_UPLOAD {
                status_only(StatusCode::SERVICE_UNAVAILABLE)
            } else {
                status_only(StatusCode::BAD_GATEWAY)
            }
        }
    }
}

/// Forwards one request to the backend WITHOUT buffering either body.
///
/// The request body is handed to hyper as-is, so bytes move from the client's
/// connection to the backend's as they arrive; the response body is handed back to
/// axum the same way. This is the difference from `idp_proxy`, which collects its
/// bodies because a Keycloak page is small — an upload is not.
///
/// The hop is PLAINTEXT and in-cluster, like `plain_http`'s hop to the ACME
/// responder: blobstore's byte listener has no route from outside the cluster, the
/// client's TLS is terminated here, and the token in the path is the whole
/// authorization.
async fn proxy_streaming(
    req: Request<Body>,
    backend: &str,
) -> Result<Response<Body>, Box<dyn std::error::Error + Send + Sync>> {
    let (parts, body) = req.into_parts();

    let tcp = TcpStream::connect(backend).await?;
    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tcp)).await?;
    tokio::spawn(async move {
        if let Err(e) = conn.await {
            tracing::debug!(error = %e, "blob_proxy: backend connection closed");
        }
    });

    // Origin-form: a direct HTTP/1.1 request to the pod, not a request through a
    // forward proxy.
    let path_and_query = parts
        .uri
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/");
    let backend_uri: http::Uri = path_and_query.parse()?;

    let mut backend_req = Request::builder()
        .method(parts.method.clone())
        .uri(backend_uri)
        .version(http::Version::HTTP_11);
    for (name, value) in forwardable(&parts.headers) {
        backend_req = backend_req.header(name, value);
    }
    // The pod's own address, not the client's Host: nothing on the byte paths is
    // keyed by hostname, and forwarding the external name would be forwarding
    // something the backend must not act on.
    backend_req = backend_req.header(header::HOST, backend);

    let backend_resp = sender.send_request(backend_req.body(body)?).await?;

    let (resp_parts, resp_body) = backend_resp.into_parts();
    let mut resp = Response::builder().status(resp_parts.status);
    for (name, value) in forwardable(&resp_parts.headers) {
        resp = resp.header(name, value);
    }
    Ok(resp.body(Body::new(resp_body.map_err(axum::Error::new).boxed_unsync()))?)
}

/// The headers that may cross the hop: everything except the hop-by-hop ones and
/// Host.
///
/// Hop-by-hop headers describe THIS connection, not the message, and forwarding
/// them is how a proxy ends up advertising a framing or a keep-alive the next hop
/// did not agree to. `Content-Length` is deliberately NOT in this list — it is
/// end-to-end and an upload's length has to reach blobstore.
fn forwardable(headers: &HeaderMap) -> impl Iterator<Item = (&http::HeaderName, &http::HeaderValue)> {
    headers.iter().filter(|(name, _)| {
        !matches!(
            name.as_str(),
            "connection"
                | "keep-alive"
                | "proxy-authenticate"
                | "proxy-authorization"
                | "te"
                | "trailer"
                | "transfer-encoding"
                | "upgrade"
                | "host"
        )
    })
}

/// ip_key is the per-IP bucket key. The whole address, v4 or v6: a /64's worth of
/// v6 addresses is one host's, but narrowing that is a policy decision the edge
/// limiter does not make either.
fn ip_key(ip: IpAddr) -> String {
    ip.to_string()
}

/// token_key is a short, stable fingerprint of a token — enough to separate
/// tokens, not enough to be one. It is what the limiter's map holds instead of the
/// credential itself.
fn token_key(token: &str) -> String {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    token.hash(&mut h);
    format!("{:x}", h.finish())
}

fn too_many_requests() -> Response<Body> {
    Response::builder()
        .status(StatusCode::TOO_MANY_REQUESTS)
        .body(Body::empty())
        .expect("static 429 response")
}

fn status_only(status: StatusCode) -> Response<Body> {
    Response::builder()
        .status(status)
        .body(Body::empty())
        .expect("static status response")
}

/// A token-bucket limiter over string keys.
///
/// A bucket rather than a fixed window because a fixed window lets twice the rate
/// through across a boundary, and because a PDF viewer's Range requests arrive in
/// a clump that a burst allowance should absorb rather than refuse.
struct RateLimiter {
    rate_per_sec: f64,
    burst: f64,
    buckets: Mutex<HashMap<String, Bucket>>,
}

struct Bucket {
    tokens: f64,
    last: Instant,
}

impl RateLimiter {
    fn new(rate_per_sec: f64, burst: f64) -> Self {
        Self {
            rate_per_sec,
            burst,
            buckets: Mutex::new(HashMap::new()),
        }
    }

    /// Defaults, overridable by env var, like `limits::EdgeLimits`: an operator
    /// raising or lowering a limit during an incident must not need a rebuild. The
    /// burst scales with the rate so one knob moves both.
    fn from_env(var: &str, default_rate: f64, default_burst: f64) -> Self {
        let rate = match std::env::var(var) {
            Ok(v) => match v.parse::<f64>() {
                Ok(n) if n > 0.0 => n,
                _ => {
                    tracing::warn!(var, value = %v, default_rate, "ignoring unparsable blob rate limit");
                    default_rate
                }
            },
            Err(_) => default_rate,
        };
        Self::new(rate, default_burst * (rate / default_rate))
    }

    /// Takes one token, or refuses.
    fn allow(&self, key: &str) -> bool {
        let now = Instant::now();
        let mut buckets = self.buckets.lock().expect("blob rate limiter mutex poisoned");
        if buckets.len() >= MAX_TRACKED_KEYS && !buckets.contains_key(key) {
            prune(&mut buckets, now);
            if buckets.len() >= MAX_TRACKED_KEYS {
                // The table is full of live buckets. Refusing is the safe answer:
                // the alternative is letting the key space grow without bound,
                // which is the thing being defended against.
                return false;
            }
        }
        let bucket = buckets.entry(key.to_string()).or_insert(Bucket {
            tokens: self.burst,
            last: now,
        });
        let elapsed = now.duration_since(bucket.last).as_secs_f64();
        bucket.last = now;
        bucket.tokens = (bucket.tokens + elapsed * self.rate_per_sec).min(self.burst);
        if bucket.tokens < 1.0 {
            return false;
        }
        bucket.tokens -= 1.0;
        true
    }
}

/// Drops buckets that have been idle long enough that dropping them forgives no
/// real debt (an idle bucket has refilled to full anyway).
fn prune(buckets: &mut HashMap<String, Bucket>, now: Instant) {
    buckets.retain(|_, b| now.duration_since(b.last).as_secs_f64() < BUCKET_IDLE_SECS);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_two_byte_paths_with_a_token_are_blob_requests() {
        for path in ["/b/abc", "/upload/abc", "/b/AbC-_123"] {
            assert!(BlobProxy::is_blob_request(path), "{path} must be a blob request");
        }
        for path in [
            "/b/", "/upload/", "/b", "/upload", "/", "/app/b/abc", "/scotty/Scotty/GetTicket",
            // A token is one segment, so nothing that looks like a path is one.
            "/b/../etc/passwd", "/b/a/b", "/upload/a/b",
        ] {
            assert!(!BlobProxy::is_blob_request(path), "{path} must not be a blob request");
        }
    }

    #[test]
    fn the_token_is_the_whole_remainder_of_the_path() {
        assert_eq!(token_of("/b/tok123"), Some((PATH_BLOB, "tok123")));
        assert_eq!(token_of("/upload/tok123"), Some((PATH_UPLOAD, "tok123")));
        assert_eq!(token_of("/b/"), None);
    }

    /// The limiter's map must never hold the credential it is limiting.
    #[test]
    fn the_limiter_key_is_not_the_token() {
        let token = "a-very-secret-bearer-token";
        let key = token_key(token);
        assert!(!key.contains(token));
        assert_eq!(key, token_key(token), "the key must be stable");
        assert_ne!(key, token_key("a-different-token"));
    }

    #[test]
    fn a_bucket_allows_its_burst_then_refuses() {
        let limiter = RateLimiter::new(1.0, 3.0);
        for i in 0..3 {
            assert!(limiter.allow("k"), "request {i} is inside the burst");
        }
        assert!(!limiter.allow("k"), "the request past the burst must be refused");
        // A different key has its own bucket.
        assert!(limiter.allow("other"));
    }

    #[test]
    fn a_bucket_refills_over_time() {
        let limiter = RateLimiter::new(1000.0, 1.0);
        assert!(limiter.allow("k"));
        assert!(!limiter.allow("k"));
        std::thread::sleep(std::time::Duration::from_millis(20));
        assert!(limiter.allow("k"), "20ms at 1000/s must have refilled the bucket");
    }

    #[test]
    fn idle_buckets_are_pruned() {
        let mut buckets = HashMap::new();
        let now = Instant::now();
        buckets.insert("fresh".to_string(), Bucket { tokens: 0.0, last: now });
        buckets.insert(
            "stale".to_string(),
            Bucket {
                tokens: 0.0,
                last: now - std::time::Duration::from_secs_f64(BUCKET_IDLE_SECS + 1.0),
            },
        );
        prune(&mut buckets, now);
        assert!(buckets.contains_key("fresh"));
        assert!(!buckets.contains_key("stale"), "an idle bucket must be dropped");
    }

    /// The whole point of this module: the body is not buffered, and the headers
    /// an upload and a Range download depend on survive the hop.
    ///
    /// A real plaintext HTTP/1.1 backend stands in for a blobstore pod, so what is
    /// asserted is what actually went over the wire rather than what the code
    /// intended to send.
    #[tokio::test]
    async fn a_request_is_proxied_with_its_body_and_headers_intact() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        // A body large enough that nothing could have "just fit" in one read.
        let upload = vec![b'x'; 256 * 1024];
        let expected_len = upload.len();

        let backend = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut received = Vec::new();
            let mut buf = vec![0u8; 64 * 1024];
            // Read until the whole request (headers + body) has arrived.
            loop {
                let n = stream.read(&mut buf).await.unwrap();
                if n == 0 {
                    break;
                }
                received.extend_from_slice(&buf[..n]);
                if let Some(i) = find_headers_end(&received) {
                    if received.len() - i >= expected_len {
                        break;
                    }
                }
            }
            let response = b"HTTP/1.1 201 Created\r\ncontent-type: application/json\r\ncontent-length: 2\r\n\r\n{}";
            stream.write_all(response).await.unwrap();
            stream.flush().await.unwrap();
            received
        });

        let req = Request::builder()
            .method(Method::PUT)
            .uri("/upload/sometoken")
            .header(header::HOST, "console.example.com")
            .header(header::CONTENT_LENGTH, upload.len().to_string())
            .header(header::CONNECTION, "keep-alive")
            .body(Body::from(upload.clone()))
            .unwrap();

        let resp = proxy_streaming(req, &addr.to_string()).await.expect("proxy");
        assert_eq!(resp.status(), StatusCode::CREATED);
        assert_eq!(resp.headers().get(header::CONTENT_TYPE).unwrap(), "application/json");
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(&body[..], b"{}");

        let received = backend.await.unwrap();
        let text = String::from_utf8_lossy(&received);
        assert!(
            text.starts_with("PUT /upload/sometoken HTTP/1.1"),
            "the backend must see the original method and path:\n{}",
            &text[..text.len().min(120)]
        );
        assert!(
            text.to_lowercase().contains(&format!("host: {addr}")),
            "Host must be rewritten to the pod's address"
        );
        assert!(
            !text.to_lowercase().contains("connection: keep-alive"),
            "a hop-by-hop header must not be forwarded"
        );
        let body_start = find_headers_end(&received).expect("the request had no header terminator");
        assert_eq!(
            received.len() - body_start,
            expected_len,
            "the whole body must reach the backend"
        );
    }

    /// A blobstore pod killed while an upload is streaming to it: the backend
    /// reads the headers and part of the body, then drops the connection. The
    /// decision (R1: "if a pod is down, uploads fail (503)") makes that a 503.
    #[tokio::test]
    async fn an_upload_whose_backend_dies_mid_body_is_503() {
        use tokio::io::AsyncReadExt;

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let backend = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 64 * 1024];
            let mut received = 0;
            while received < 128 * 1024 {
                let n = stream.read(&mut buf).await.unwrap();
                assert!(n > 0, "the proxy closed before sending the body");
                received += n;
            }
            // The pod dies: the connection goes away with the body unfinished.
        });

        // Bigger than the backend reads before dying, so the body is mid-flight.
        let upload = vec![b'x'; 8 * 1024 * 1024];
        let req = Request::builder()
            .method(Method::PUT)
            .uri("/upload/sometoken")
            .header(header::CONTENT_LENGTH, upload.len().to_string())
            .body(Body::from(upload))
            .unwrap();

        let resp = forward(req, PATH_UPLOAD, &addr.to_string()).await;
        backend.await.unwrap();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    /// A backend that is not there at all: an upload is refused with 503, and a
    /// read keeps its 502.
    #[tokio::test]
    async fn an_unreachable_backend_is_503_for_an_upload_and_502_for_a_read() {
        // A port that was just bound and released has nothing listening on it.
        let addr = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap()
            .local_addr()
            .unwrap()
            .to_string();

        let upload = Request::builder()
            .method(Method::PUT)
            .uri("/upload/sometoken")
            .header(header::CONTENT_LENGTH, "2")
            .body(Body::from("{}"))
            .unwrap();
        assert_eq!(forward(upload, PATH_UPLOAD, &addr).await.status(), StatusCode::SERVICE_UNAVAILABLE);

        let read = Request::builder().method(Method::GET).uri("/b/sometoken").body(Body::empty()).unwrap();
        assert_eq!(forward(read, PATH_BLOB, &addr).await.status(), StatusCode::BAD_GATEWAY);
    }

    fn find_headers_end(buf: &[u8]) -> Option<usize> {
        buf.windows(4).position(|w| w == b"\r\n\r\n").map(|i| i + 4)
    }

    #[test]
    fn hop_by_hop_headers_do_not_cross_the_hop() {
        let mut headers = HeaderMap::new();
        headers.insert(header::HOST, "console.example.com".parse().unwrap());
        headers.insert(header::CONNECTION, "keep-alive".parse().unwrap());
        headers.insert(header::TRANSFER_ENCODING, "chunked".parse().unwrap());
        headers.insert(header::CONTENT_LENGTH, "1234".parse().unwrap());
        headers.insert(header::RANGE, "bytes=0-99".parse().unwrap());

        let forwarded: Vec<String> = forwardable(&headers).map(|(n, _)| n.to_string()).collect();
        assert!(forwarded.contains(&"content-length".to_string()), "an upload's length is end-to-end");
        assert!(forwarded.contains(&"range".to_string()), "a PDF viewer's Range must reach the backend");
        for dropped in ["host", "connection", "transfer-encoding"] {
            assert!(!forwarded.contains(&dropped.to_string()), "{dropped} must not be forwarded");
        }
    }
}
