// End-to-end proof, over a real socket, that gateway.Mint's two kernel-bound
// RPCs carry the caller's `trace_id` (field 200) to kernel: `MintToken` and
// `MintX509Cert`, on both the native gRPC handlers (`mint::GatewayMintService`)
// and their REST translations (`rest_translation::handle_mint`, entered through
// the REST router). The standing rule (tacplus-dev/looper#51): each handler
// that makes causal downstream calls has a test asserting that the `trace_id`
// it received arrives on them.
//
// What is real here:
//
//   * the gateway's Mint handlers and the REST router, unchanged;
//   * a real tonic gRPC server — the GENERATED `sys.minter.Minter` server, the
//     contract kernel hosts and the gateway's `minter_client()` speaks — on a
//     real TCP port, which records the `trace_id` of each request it decoded.
//
// What is stood in for: kernel, and the gateway's generated outbound client.
// A `ServiceManager` cannot be built without bootstrapping against a live
// kernel, so the handlers are given the `mint::KernelMinter` seam over the
// generated raw `MinterClient` instead of `sm.s2s().kernel().minter_client()`;
// the running gateway's implementation of that seam forwards the request it is
// handed, unchanged, to the generated client.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use axum::http::{header, Request, StatusCode};
use tokio::net::TcpListener;
use tokio_stream::wrappers::TcpListenerStream;
use tower::ServiceExt;

use gateway_grpcserver::authorizer::JwkCache;
use gateway_key::keys;
use gateway_model::types::services::gateway::gateway::mint_server::Mint;
use gateway_model::types::sys::minter::minter_client::MinterClient;
use gateway_model::types::sys::minter::minter_server::{Minter, MinterServer};
use gateway_model::types::sys::tokenrequest::{
    MintExternalServiceTokenRequest, MintServiceTokenRequest, TokenMintRequest, TokenMintResponse,
    X509MintRequest,
};
use gateway_model::types::sys::x509::x509::X509CertChain;
use gateway_servicemanager::SpiffeServerCertVerifier;
use gateway_x509::x509::{ImmutableCertChain, X509KeyUsage};

use crate::auth::GatewayAuth;
use crate::health::HealthWatcher;
use crate::mint::{GatewayMintService, KernelMinter};
use crate::proxy_grpc::ProxyState;
use crate::rest_translation::{self, RestState};

const TRUST_DOMAIN: &str = "mint-trace-e2e.test";
const TRACE_ID: &str = "4bf92f3577b34da6a3ce929d0e0e4736";

// ── the backend ─────────────────────────────────────────────────────────────

fn unused() -> tonic::Status {
    tonic::Status::unimplemented("not part of this test")
}

/// Stands in for kernel's `Minter` surface. It records, per RPC, the
/// `trace_id` of each request it received, and answers with an empty message.
#[derive(Default)]
struct KernelStandIn {
    mint_token: Mutex<Vec<String>>,
    mint_x509_cert: Mutex<Vec<String>>,
}

#[tonic::async_trait]
impl Minter for KernelStandIn {
    async fn mint_service_token(
        &self,
        _: tonic::Request<MintServiceTokenRequest>,
    ) -> Result<tonic::Response<TokenMintResponse>, tonic::Status> {
        Err(unused())
    }

    async fn mint_external_service_token(
        &self,
        _: tonic::Request<MintExternalServiceTokenRequest>,
    ) -> Result<tonic::Response<TokenMintResponse>, tonic::Status> {
        Err(unused())
    }

    async fn mint_token(
        &self,
        request: tonic::Request<TokenMintRequest>,
    ) -> Result<tonic::Response<TokenMintResponse>, tonic::Status> {
        self.mint_token.lock().expect("seen").push(request.into_inner().trace_id);
        Ok(tonic::Response::new(TokenMintResponse::default()))
    }

    async fn mint_x509_cert(
        &self,
        request: tonic::Request<X509MintRequest>,
    ) -> Result<tonic::Response<X509CertChain>, tonic::Status> {
        self.mint_x509_cert.lock().expect("seen").push(request.into_inner().trace_id);
        Ok(tonic::Response::new(X509CertChain::default()))
    }
}

/// The handlers' kernel, reached over the wire with the generated client.
struct KernelOverTheWire(MinterClient<tonic::transport::Channel>);

#[tonic::async_trait]
impl KernelMinter for KernelOverTheWire {
    async fn mint_token(
        &self,
        request: tonic::Request<TokenMintRequest>,
    ) -> Result<tonic::Response<TokenMintResponse>, tonic::Status> {
        self.0.clone().mint_token(request).await
    }

    async fn mint_x509_cert(
        &self,
        request: tonic::Request<X509MintRequest>,
    ) -> Result<tonic::Response<X509CertChain>, tonic::Status> {
        self.0.clone().mint_x509_cert(request).await
    }
}

// ── wiring ──────────────────────────────────────────────────────────────────

/// A verifier the REST router's proxy never consults here (the Mint routes do
/// not go through it); `Resolver` just holds one, and `WebPkiServerVerifier`
/// refuses to build with no anchors at all.
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
    for der in rustls_pemfile::certs(&mut cert.pem_bytes()) {
        roots.add(der.expect("der")).expect("add root");
    }
    SpiffeServerCertVerifier::new(TRUST_DOMAIN, roots).expect("verifier")
}

/// Serves the stand-in on a real port and returns the seam over a client
/// connected to it.
async fn spawn_kernel(backend: Arc<KernelStandIn>) -> Arc<dyn KernelMinter> {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind kernel");
    let addr = listener.local_addr().expect("kernel addr");
    tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(MinterServer::from_arc(backend))
            .serve_with_incoming(TcpListenerStream::new(listener))
            .await
            .expect("kernel serve");
    });
    let client = MinterClient::connect(format!("http://{addr}"))
        .await
        .expect("connect to kernel");
    Arc::new(KernelOverTheWire(client))
}

/// The JWK cache is empty: both Mint routes are NoAuth and present no token.
fn auth() -> Arc<GatewayAuth> {
    Arc::new(GatewayAuth::new(Arc::new(JwkCache::seeded(vec![])), false))
}

fn rest_router(minter: Arc<dyn KernelMinter>) -> axum::Router {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let auth = auth();
    let proxy = Arc::new(ProxyState {
        resolver: Arc::new(crate::resolver::Resolver::plaintext_backends(
            HealthWatcher::seeded(HashMap::new()),
            unused_verifier(),
        )),
        auth: Arc::clone(&auth),
        tenant_owned: Arc::new(Default::default()),
        trace_publisher: Arc::new(|_| {}),
        trace_round: Box::new(Default::default),
    });
    rest_translation::router(Arc::new(RestState {
        proxy,
        minter,
        auth,
        root_ca: vec![],
        issuer_url: "https://gateway.example".to_string(),
    }))
}

async fn post_json(router: axum::Router, path: &str, body: serde_json::Value) -> StatusCode {
    router
        .oneshot(
            Request::post(path)
                .header(header::CONTENT_TYPE, "application/json")
                .body(axum::body::Body::from(body.to_string()))
                .expect("request"),
        )
        .await
        .expect("router answers")
        .status()
}

// ── the runs ────────────────────────────────────────────────────────────────

#[tokio::test]
async fn grpc_mint_token_carries_the_trace_id_to_kernel() {
    let backend = Arc::new(KernelStandIn::default());
    let service = GatewayMintService::new(
        spawn_kernel(backend.clone()).await,
        auth(),
        "https://gateway.example".to_string(),
        vec![],
    );

    service
        .mint_token(tonic::Request::new(TokenMintRequest {
            aud: "kernel".to_string(),
            trace_id: TRACE_ID.to_string(),
            ..Default::default()
        }))
        .await
        .expect("MintToken must reach kernel");

    assert_eq!(
        *backend.mint_token.lock().expect("seen"),
        vec![TRACE_ID.to_string()],
        "kernel's MintToken must receive the trace_id the caller sent"
    );
}

#[tokio::test]
async fn grpc_mint_x509_cert_carries_the_trace_id_to_kernel() {
    let backend = Arc::new(KernelStandIn::default());
    let service = GatewayMintService::new(
        spawn_kernel(backend.clone()).await,
        auth(),
        "https://gateway.example".to_string(),
        vec![],
    );

    service
        .mint_x509_cert(tonic::Request::new(X509MintRequest {
            aud: "kernel".to_string(),
            trace_id: TRACE_ID.to_string(),
            ..Default::default()
        }))
        .await
        .expect("MintX509Cert must reach kernel");

    assert_eq!(
        *backend.mint_x509_cert.lock().expect("seen"),
        vec![TRACE_ID.to_string()],
        "kernel's MintX509Cert must receive the trace_id the caller sent"
    );
}

/// `handle_mint`'s MintToken arm builds kernel's request from the JSON body:
/// the body's `traceId` is the trace_id kernel must see.
#[tokio::test]
async fn rest_mint_token_carries_the_trace_id_to_kernel() {
    let backend = Arc::new(KernelStandIn::default());
    let router = rest_router(spawn_kernel(backend.clone()).await);

    let status = post_json(
        router,
        "/gateway/Mint/MintToken",
        serde_json::json!({"aud": "kernel", "traceId": TRACE_ID}),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "REST MintToken must reach kernel");
    assert_eq!(
        *backend.mint_token.lock().expect("seen"),
        vec![TRACE_ID.to_string()],
        "kernel's MintToken must receive the trace_id of the REST body"
    );
}

/// The same for `handle_mint`'s MintX509Cert arm.
#[tokio::test]
async fn rest_mint_x509_cert_carries_the_trace_id_to_kernel() {
    let backend = Arc::new(KernelStandIn::default());
    let router = rest_router(spawn_kernel(backend.clone()).await);

    let status = post_json(
        router,
        "/gateway/Mint/MintX509Cert",
        serde_json::json!({"aud": "kernel", "traceId": TRACE_ID}),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "REST MintX509Cert must reach kernel");
    assert_eq!(
        *backend.mint_x509_cert.lock().expect("seen"),
        vec![TRACE_ID.to_string()],
        "kernel's MintX509Cert must receive the trace_id of the REST body"
    );
}
