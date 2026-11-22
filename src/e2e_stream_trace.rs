// End-to-end proof, over real sockets, that the gateway's streaming paths carry
// the caller's `trace_id` (field 200) to the backend: gRPC server-streaming
// through `proxy_grpc::handle`, REST server-streaming (SSE) through
// `rest_translation::dispatch_stream_via_proxy`, and client-streaming over a
// WebSocket through `rest_translation::handle_websocket_stream`. The standing
// rule (tacplus-dev/looper#51): each handler that makes causal downstream calls
// has a test asserting that the `trace_id` it received arrives on them. The
// unary paths are covered in `e2e_user_mint`.
//
// What is real here:
//
//   * the real `proxy_grpc::handle` and the real REST router, resolving against
//     the real generated `ROUTES` table;
//   * real tonic gRPC servers — the GENERATED `eventbus.TraceSession` and
//     `oauth.Session` servers — on a real TCP port, recording the `trace_id` of
//     each request they decoded.
//
// What is stood in for: eventbus and oauth themselves. Both routes are NoAuth,
// so no token is minted, and the gateway→backend hop is plaintext h2c
// (`Resolver::plaintext_backends`).

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use futures::{SinkExt, StreamExt};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::CertificateDer;
use tokio::net::TcpListener;
use tokio::time::{timeout, Duration};
use tokio_stream::wrappers::TcpListenerStream;
use tokio_tungstenite::tungstenite::Message;
use tower::ServiceExt;

use gateway_grpcserver::authorizer::JwkCache;
use gateway_key::keys;
use gateway_model::types::services::eventbus::eventbus::trace_session_client::TraceSessionClient;
use gateway_model::types::services::eventbus::eventbus::trace_session_server::{
    TraceSession, TraceSessionServer,
};
use gateway_model::types::services::oauth::oauth as oauth_pb;
use gateway_model::types::sys::tokenrequest::{TokenMintRequest, TokenMintResponse, X509MintRequest};
use gateway_model::types::sys::trace::trace::{TraceEvent, TraceRequest};
use gateway_model::types::sys::x509::x509::X509CertChain;
use gateway_servicemanager::SpiffeServerCertVerifier;
use gateway_x509::x509::{ImmutableCertChain, X509KeyUsage};
use oauth_pb::session_server::{Session, SessionServer};

use crate::auth::GatewayAuth;
use crate::health::{HealthWatcher, ServiceEndpoint};
use crate::mint::KernelMinter;
use crate::proxy_grpc::{self, ProxyState};
use crate::resolver::Resolver;
use crate::rest_translation::{self, RestState};

const TRUST_DOMAIN: &str = "stream-trace-e2e.test";
const TRACE_ID: &str = "4bf92f3577b34da6a3ce929d0e0e4736";
/// `SessionRequest.session_id`: 32 random bytes, hex-encoded.
const SESSION_ID: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

// ── the backends ────────────────────────────────────────────────────────────

/// Stands in for eventbus's `TraceSession` and oauth's `Session`. Each records
/// the `trace_id` of the (first) request it decoded and answers with one
/// message, then ends its stream.
#[derive(Default)]
struct StandIn {
    subscribe_trace: Mutex<Vec<String>>,
    broker_session: Mutex<Vec<String>>,
}

#[tonic::async_trait]
impl TraceSession for StandIn {
    type SubscribeTraceStream = tokio_stream::Once<Result<TraceEvent, tonic::Status>>;

    async fn subscribe_trace(
        &self,
        request: tonic::Request<TraceRequest>,
    ) -> Result<tonic::Response<Self::SubscribeTraceStream>, tonic::Status> {
        let trace_id = request.into_inner().trace_id;
        self.subscribe_trace.lock().expect("seen").push(trace_id.clone());
        Ok(tonic::Response::new(tokio_stream::once(Ok(TraceEvent {
            trace_id,
            ..Default::default()
        }))))
    }
}

#[tonic::async_trait]
impl Session for StandIn {
    type BrokerSessionStream = tokio_stream::Once<Result<oauth_pb::SessionResponse, tonic::Status>>;

    async fn broker_session(
        &self,
        request: tonic::Request<tonic::Streaming<oauth_pb::SessionRequest>>,
    ) -> Result<tonic::Response<Self::BrokerSessionStream>, tonic::Status> {
        let first = request
            .into_inner()
            .message()
            .await?
            .ok_or_else(|| tonic::Status::invalid_argument("no SessionRequest"))?;
        self.broker_session.lock().expect("seen").push(first.trace_id.clone());
        Ok(tonic::Response::new(tokio_stream::once(Ok(
            oauth_pb::SessionResponse {
                trace_id: first.trace_id,
                ..Default::default()
            },
        ))))
    }
}

// ── wiring ──────────────────────────────────────────────────────────────────

/// A verifier the plaintext test path never consults; `Resolver` just holds
/// one, and `WebPkiServerVerifier` refuses to build with no anchors at all.
fn unused_verifier() -> Arc<SpiffeServerCertVerifier> {
    let key = keys::generate_ec_p256_key().expect("throwaway key");
    let not_after = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_secs() as i64
        + 3600;
    let cert = ImmutableCertChain::for_self_signing(key)
        .self_sign("unused", not_after, X509KeyUsage::CertSign, &[])
        .expect("throwaway cert");
    let mut roots = rustls::RootCertStore::empty();
    for der in CertificateDer::pem_slice_iter(cert.pem_bytes()) {
        roots.add(der.expect("der")).expect("add root");
    }
    SpiffeServerCertVerifier::new(TRUST_DOMAIN, roots).expect("verifier")
}

/// Serves both stand-ins on one real port, and returns a proxy whose endpoint
/// table sends `eventbus` and `oauth` there.
async fn spawn_backends(backend: Arc<StandIn>) -> Arc<ProxyState> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind backend");
    let addr = listener.local_addr().expect("backend addr");
    let session = Arc::clone(&backend);
    tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(TraceSessionServer::from_arc(backend))
            .add_service(SessionServer::from_arc(session))
            .serve_with_incoming(TcpListenerStream::new(listener))
            .await
            .expect("backend serve");
    });
    let endpoint = ServiceEndpoint {
        host: addr.ip().to_string(),
        port: addr.port() as i32,
    };
    let mut endpoints = HashMap::new();
    endpoints.insert("eventbus".to_string(), vec![endpoint.clone()]);
    endpoints.insert("oauth".to_string(), vec![endpoint]);
    Arc::new(ProxyState {
        resolver: Arc::new(Resolver::plaintext_backends(
            HealthWatcher::seeded(endpoints),
            unused_verifier(),
        )),
        // Both routes are NoAuth: the JWK cache is empty.
        auth: Arc::new(GatewayAuth::new(Arc::new(JwkCache::seeded(vec![])), false)),
        tenant_owned: Arc::new(Default::default()),
        trace_publisher: Arc::new(|_| {}),
        trace_round: Box::new(Default::default),
    })
}

/// The REST router, in front of the proxy. Neither route is a gateway.Mint
/// route, so the minter is never consulted.
fn rest_router(proxy: Arc<ProxyState>) -> axum::Router {
    struct NoMinter;

    #[tonic::async_trait]
    impl KernelMinter for NoMinter {
        async fn mint_token(
            &self,
            _: tonic::Request<TokenMintRequest>,
        ) -> Result<tonic::Response<TokenMintResponse>, tonic::Status> {
            Err(tonic::Status::unimplemented("not part of this test"))
        }

        async fn mint_x509_cert(
            &self,
            _: tonic::Request<X509MintRequest>,
        ) -> Result<tonic::Response<X509CertChain>, tonic::Status> {
            Err(tonic::Status::unimplemented("not part of this test"))
        }
    }

    let auth = Arc::clone(&proxy.auth);
    rest_translation::router(Arc::new(RestState {
        proxy,
        minter: Arc::new(NoMinter),
        auth,
        root_ca: vec![],
        issuer_url: "https://gateway.example".to_string(),
    }))
}

/// Serves `app` on a real port and returns its address.
async fn serve(app: axum::Router) -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind gateway");
    let addr = listener.local_addr().expect("gateway addr");
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("gateway serve");
    });
    addr
}

// ── the runs ────────────────────────────────────────────────────────────────

/// `proxy_grpc::handle`'s streaming path (`validated_streaming_body`).
#[tokio::test]
async fn the_grpc_proxy_carries_the_trace_id_on_a_server_stream() {
    let backend = Arc::new(StandIn::default());
    let proxy = spawn_backends(backend.clone()).await;
    let addr = serve(axum::Router::new().fallback(axum::routing::any(
        move |req: axum::http::Request<axum::body::Body>| {
            let proxy = proxy.clone();
            async move { proxy_grpc::handle(&proxy, req).await }
        },
    )))
    .await;

    let channel = tonic::transport::Endpoint::from_shared(format!("http://{addr}"))
        .expect("endpoint")
        .connect()
        .await
        .expect("connect to gateway");
    let mut events = TraceSessionClient::new(channel)
        .subscribe_trace(TraceRequest {
            trace_id: TRACE_ID.to_string(),
            ..Default::default()
        })
        .await
        .expect("SubscribeTrace must reach eventbus through the gateway")
        .into_inner();
    let event = events
        .message()
        .await
        .expect("stream")
        .expect("the stand-in's one event");

    assert_eq!(event.trace_id, TRACE_ID, "the response must be the backend's");
    assert_eq!(
        *backend.subscribe_trace.lock().expect("seen"),
        vec![TRACE_ID.to_string()],
        "eventbus must receive the trace_id the gRPC caller sent"
    );
}

/// REST server-streaming translation (`rest_handler` →
/// `dispatch_stream_via_proxy` → `proxy_grpc::handle`): the JSON body's
/// `traceId` reaches the backend, and its answer comes back as SSE.
#[tokio::test]
async fn rest_server_streaming_translation_carries_the_trace_id_to_the_backend() {
    let backend = Arc::new(StandIn::default());
    let router = rest_router(spawn_backends(backend.clone()).await);

    let response = router
        .oneshot(
            axum::http::Request::post("/eventbus/TraceSession/SubscribeTrace")
                .header(axum::http::header::CONTENT_TYPE, "application/json")
                .body(axum::body::Body::from(
                    serde_json::json!({"traceId": TRACE_ID}).to_string(),
                ))
                .expect("request"),
        )
        .await
        .expect("router answers");
    assert_eq!(
        response.status(),
        axum::http::StatusCode::OK,
        "REST SubscribeTrace must reach eventbus"
    );
    let sse = timeout(
        Duration::from_secs(10),
        axum::body::to_bytes(response.into_body(), 1 << 20),
    )
    .await
    .expect("the SSE stream ends with the backend's")
    .expect("SSE body");

    assert!(
        String::from_utf8_lossy(&sse).contains(TRACE_ID),
        "the SSE stream must carry the backend's event: {}",
        String::from_utf8_lossy(&sse)
    );
    assert_eq!(
        *backend.subscribe_trace.lock().expect("seen"),
        vec![TRACE_ID.to_string()],
        "eventbus must receive the trace_id of the REST body"
    );
}

/// Client-streaming over a WebSocket (`rest_handler` →
/// `handle_websocket_stream` → `proxy_grpc::handle_prevalidated_stream`): the
/// frame's `traceId` reaches the backend.
#[tokio::test]
async fn websocket_stream_translation_carries_the_trace_id_to_the_backend() {
    let backend = Arc::new(StandIn::default());
    let addr = serve(rest_router(spawn_backends(backend.clone()).await)).await;

    let (mut ws, _) =
        tokio_tungstenite::connect_async(format!("ws://{addr}/oauth/Session/BrokerSession"))
            .await
            .expect("WebSocket upgrade");
    ws.send(Message::Text(
        serde_json::json!({"sessionId": SESSION_ID, "traceId": TRACE_ID})
            .to_string()
            .into(),
    ))
    .await
    .expect("send the first frame");

    let answer = timeout(Duration::from_secs(10), ws.next())
        .await
        .expect("the backend answers")
        .expect("a message")
        .expect("a frame");
    assert!(
        matches!(&answer, Message::Text(text) if text.contains(TRACE_ID)),
        "the WebSocket must carry the backend's answer: {answer:?}"
    );
    assert_eq!(
        *backend.broker_session.lock().expect("seen"),
        vec![TRACE_ID.to_string()],
        "oauth must receive the trace_id of the WebSocket frame"
    );
}
