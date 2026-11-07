// End-to-end proof, over real sockets, that the gateway sets the tenant of an
// MCP session of a tenant-owned service from the caller's token, and never from
// the client (#15, tacplus-dev/tacplus#170): the session reaches the instance
// of the token's tenant, every `mcp.McpRequest` frame arrives with `tenant`
// stamped to that tenant, and a frame naming any other tenant is refused and
// never forwarded. A caller in no tenant is refused, and a carrier of a service
// that is not tenant-owned is forwarded as it was.
//
// What is real here:
//
//   * the real `proxy_grpc::handle`, and the real REST router's WebSocket
//     bridge (`proxy_grpc::handle_prevalidated_stream`), resolving against the
//     real generated `ROUTES` entry of tenantecho's carrier,
//     `BrokerTenantEchoMcpSession`;
//   * the real `GatewayAuth` over a real `JwkCache`, verifying real
//     ECDSA-signed JWTs;
//   * real tonic servers, the GENERATED `TenantEchoServer`, one per instance,
//     each recording every `McpRequest` its carrier decoded.
//
// What is stood in for: tenantecho itself, on plaintext h2c
// (`Resolver::plaintext_backends`). The `tenant_owned` set handed to
// `ProxyState` is a fixture, as in `e2e_tenant_routing`.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use futures::{SinkExt, StreamExt};
use tokio::net::TcpListener;
use tokio::time::{timeout, Duration};
use tokio_stream::wrappers::{ReceiverStream, TcpListenerStream};
use tokio_tungstenite::tungstenite::Message;

use gateway_grpcserver::authorizer::JwkCache;
use gateway_jwk::jwk::{ImmutableJwk, Jwk};
use gateway_key::{base64_utils, keys};
use gateway_model::s2sm::rest_dispatch::ROUTES;
use gateway_model::types::services::tenantecho::tenantecho::tenant_echo_client::TenantEchoClient;
use gateway_model::types::services::tenantecho::tenantecho::tenant_echo_server::{
    TenantEcho, TenantEchoServer,
};
use gateway_model::types::services::tenantecho::tenantecho::{
    PingPigeonRequest, PingPigeonResponse, PingRequest, PingResponse,
};
use gateway_model::types::sys::mcp::{McpRequest, McpResponse};
use gateway_model::types::sys::tokenrequest::{TokenMintRequest, TokenMintResponse, X509MintRequest};
use gateway_model::types::sys::x509::x509::X509CertChain;
use gateway_servicemanager::SpiffeServerCertVerifier;
use gateway_token::token::Token;
use gateway_x509::x509::{ImmutableCertChain, X509KeyUsage};

use crate::auth::GatewayAuth;
use crate::health::{HealthWatcher, ServiceEndpoint};
use crate::mint::KernelMinter;
use crate::proxy_grpc::{self, ProxyState};
use crate::resolver::Resolver;
use crate::rest_translation::{self, RestState};

const TRUST_DOMAIN: &str = "mcp-tenant-e2e.test";
const SERVICE: &str = "tenantecho";
const CARRIER: &str = "/tenantecho.TenantEcho/BrokerTenantEchoMcpSession";
/// Two tids (exactly 8 characters of `[0-9a-z]`).
const ACME: &str = "acme0001";
const BETA: &str = "beta0002";

// ── the backend ─────────────────────────────────────────────────────────────

/// Stands in for one tenantecho instance. Records every `McpRequest` its
/// carrier decoded, and answers each with the `tenant` it arrived with.
#[derive(Default)]
struct Instance {
    frames: Arc<Mutex<Vec<McpRequest>>>,
}

impl Instance {
    fn frames(&self) -> Vec<McpRequest> {
        self.frames.lock().expect("frames").clone()
    }
}

#[tonic::async_trait]
impl TenantEcho for Instance {
    async fn ping(
        &self,
        _: tonic::Request<PingRequest>,
    ) -> Result<tonic::Response<PingResponse>, tonic::Status> {
        Err(tonic::Status::unimplemented("not part of this test"))
    }

    async fn ping_pigeon(
        &self,
        _: tonic::Request<PingPigeonRequest>,
    ) -> Result<tonic::Response<PingPigeonResponse>, tonic::Status> {
        Err(tonic::Status::unimplemented("not part of this test"))
    }

    type BrokerTenantEchoMcpSessionStream = ReceiverStream<Result<McpResponse, tonic::Status>>;

    async fn broker_tenant_echo_mcp_session(
        &self,
        request: tonic::Request<tonic::Streaming<McpRequest>>,
    ) -> Result<tonic::Response<Self::BrokerTenantEchoMcpSessionStream>, tonic::Status> {
        let mut inbound = request.into_inner();
        let frames = Arc::clone(&self.frames);
        let (tx, rx) = tokio::sync::mpsc::channel(16);
        tokio::spawn(async move {
            while let Ok(Some(frame)) = inbound.message().await {
                let tenant = frame.tenant.clone();
                frames.lock().expect("frames").push(frame);
                if tx.send(Ok(McpResponse { payload: tenant })).await.is_err() {
                    return;
                }
            }
        });
        Ok(tonic::Response::new(ReceiverStream::new(rx)))
    }
}

/// Serves a fresh `Instance` on a real port.
async fn spawn_instance() -> (Arc<Instance>, ServiceEndpoint) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind instance");
    let addr = listener.local_addr().expect("instance addr");
    let instance = Arc::new(Instance::default());
    let served = Arc::clone(&instance);
    tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(TenantEchoServer::from_arc(served))
            .serve_with_incoming(TcpListenerStream::new(listener))
            .await
            .expect("instance serve");
    });
    let endpoint = ServiceEndpoint {
        host: addr.ip().to_string(),
        port: addr.port() as i32,
    };
    (instance, endpoint)
}

/// tenantecho's two tenant instances and a bare-named one, which a
/// tenant-owned service must never reach.
struct Fleet {
    acme: Arc<Instance>,
    beta: Arc<Instance>,
    shared: Arc<Instance>,
    endpoints: HashMap<String, Vec<ServiceEndpoint>>,
}

async fn fleet() -> Fleet {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let (acme, acme_ep) = spawn_instance().await;
    let (beta, beta_ep) = spawn_instance().await;
    let (shared, shared_ep) = spawn_instance().await;
    let mut endpoints = HashMap::new();
    endpoints.insert(format!("{SERVICE}-{ACME}"), vec![acme_ep]);
    endpoints.insert(format!("{SERVICE}-{BETA}"), vec![beta_ep]);
    endpoints.insert(SERVICE.to_string(), vec![shared_ep]);
    Fleet {
        acme,
        beta,
        shared,
        endpoints,
    }
}

// ── tokens ──────────────────────────────────────────────────────────────────

fn jwk_for(key: &keys::ImmutableKey) -> ImmutableJwk {
    let (x, y) = match key.public_key() {
        keys::PublicKey::EcP256(ec) => (
            base64_utils::encode_base64_url(ec.x()),
            base64_utils::encode_base64_url(ec.y()),
        ),
        _ => panic!("this test signs with P-256"),
    };
    ImmutableJwk::new(Jwk {
        kty: "EC".to_string(),
        alg: Some(key.alg().to_string()),
        kid: key.id().to_string(),
        key_use: Some("sig".to_string()),
        n: None,
        e: None,
        crv: Some("P-256".to_string()),
        x: Some(x),
        y: Some(y),
        exp: None,
        created: None,
    })
    .expect("jwk")
}

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_secs() as i64
}

/// A user token for tenantecho in `namespace`, entitled to everything (the
/// admin bypass), so a refusal here can only be the tenant's.
fn user_token(key: &keys::ImmutableKey, namespace: &str) -> String {
    let mut token = Token::new();
    token.set_kid(key.id()).expect("kid");
    token.set_alg(key.alg()).expect("alg");
    token.set_issuer("mcp-tenant-test").expect("iss");
    token.set_subject("alice@example.com").expect("sub");
    token.set_audience(SERVICE).expect("aud");
    token.set_namespace(namespace).expect("namespace");
    token.set_expiration(unix_now() + 3600).expect("exp");
    token.set_sub_type("user").expect("sub_type");
    token
        .set_service_entitlements(serde_json::json!({ "all": true }))
        .expect("service_entitlements");
    token.sign(key).expect("sign");
    format!("Bearer {}", token.base64().expect("base64"))
}

// ── wiring ──────────────────────────────────────────────────────────────────

/// A verifier the plaintext test path never consults; `Resolver` just holds
/// one, and `WebPkiServerVerifier` refuses to build with no anchors at all.
fn unused_verifier() -> Arc<SpiffeServerCertVerifier> {
    let key = keys::generate_ec_p256_key().expect("throwaway key");
    let cert = ImmutableCertChain::for_self_signing(key)
        .self_sign("unused", unix_now() + 3600, X509KeyUsage::CertSign, &[])
        .expect("throwaway cert");
    let mut roots = rustls::RootCertStore::empty();
    for der in rustls_pemfile::certs(&mut cert.pem_bytes()) {
        roots.add(der.expect("der")).expect("add root");
    }
    SpiffeServerCertVerifier::new(TRUST_DOMAIN, roots).expect("verifier")
}

fn proxy_state(
    endpoints: HashMap<String, Vec<ServiceEndpoint>>,
    tenant_owned: &[&str],
    signing_key: &keys::ImmutableKey,
) -> Arc<ProxyState> {
    Arc::new(ProxyState {
        resolver: Arc::new(Resolver::plaintext_backends(
            HealthWatcher::seeded(endpoints),
            unused_verifier(),
        )),
        auth: Arc::new(GatewayAuth::new(
            Arc::new(JwkCache::seeded(vec![jwk_for(signing_key)])),
            false,
        )),
        tenant_owned: Arc::new(tenant_owned.iter().map(|s| s.to_string()).collect()),
        trace_publisher: Arc::new(|_| {}),
        trace_round: Box::new(Default::default),
    })
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

/// The gateway's gRPC listener: every request to `proxy_grpc::handle`.
async fn grpc_gateway(proxy: Arc<ProxyState>) -> std::net::SocketAddr {
    serve(axum::Router::new().fallback(axum::routing::any(
        move |req: axum::http::Request<axum::body::Body>| {
            let proxy = proxy.clone();
            async move { proxy_grpc::handle(&proxy, req).await }
        },
    )))
    .await
}

/// The REST router in front of the proxy, for the WebSocket bridge.
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

fn frame(payload: &str, tenant: &str) -> McpRequest {
    McpRequest {
        payload: payload.to_string(),
        tenant: tenant.to_string(),
    }
}

/// An open MCP session through the gateway: `send` a frame, `answer` reads the
/// next one back (the tenant the instance saw), `end` the stream's outcome.
struct Session {
    tx: tokio::sync::mpsc::Sender<McpRequest>,
    result: Result<tonic::Streaming<McpResponse>, tonic::Status>,
}

impl Session {
    async fn open(gateway: std::net::SocketAddr, bearer: &str) -> Self {
        let channel = tonic::transport::Endpoint::from_shared(format!("http://{gateway}"))
            .expect("endpoint")
            .connect()
            .await
            .expect("connect to gateway");
        let (tx, rx) = tokio::sync::mpsc::channel(16);
        let mut request = tonic::Request::new(ReceiverStream::new(rx));
        request
            .metadata_mut()
            .insert("authorization", bearer.parse().expect("bearer"));
        // The first frame goes out before the call returns its headers.
        let call = tokio::spawn(async move {
            TenantEchoClient::new(channel)
                .broker_tenant_echo_mcp_session(request)
                .await
                .map(tonic::Response::into_inner)
        });
        let session = Self {
            tx,
            result: Err(tonic::Status::unknown("not yet opened")),
        };
        session
            .tx
            .send(frame(r#"{"jsonrpc":"2.0","id":0,"method":"initialize"}"#, ""))
            .await
            .expect("send the opening frame");
        let result = timeout(Duration::from_secs(10), call)
            .await
            .expect("the gateway answers the session")
            .expect("call task");
        Self { result, ..session }
    }

    async fn send(&self, tenant: &str) {
        let _ = self
            .tx
            .send(frame(r#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#, tenant))
            .await;
    }

    /// The next answer's payload, `Err` when the stream failed or ended.
    async fn answer(&mut self) -> Result<String, String> {
        let stream = self.result.as_mut().map_err(|s| s.to_string())?;
        match timeout(Duration::from_secs(10), stream.message()).await {
            Ok(Ok(Some(response))) => Ok(response.payload),
            Ok(Ok(None)) => Err("stream ended".to_string()),
            Ok(Err(status)) => Err(status.to_string()),
            Err(_) => Err("timed out".to_string()),
        }
    }
}

fn tenants(frames: &[McpRequest]) -> Vec<&str> {
    frames.iter().map(|f| f.tenant.as_str()).collect()
}

// ── the runs ────────────────────────────────────────────────────────────────

/// The registry contract this rests on: the carrier of every tenant-owned
/// service declares `route_field: "tenant"`, which is `McpRequest.tenant`
/// (field 2), and no platform carrier declares one.
#[test]
fn every_tenant_owned_carrier_declares_mcp_request_tenant_as_its_route_field() {
    let owned = crate::registry::tenant_owned_services();
    let carriers: Vec<_> = ROUTES
        .iter()
        .filter(|r| proxy_grpc::is_mcp_carrier(r))
        .collect();
    assert!(
        carriers.iter().any(|r| r.grpc_path == CARRIER),
        "tenantecho's carrier must be recognised: {:?}",
        carriers.iter().map(|r| r.grpc_path).collect::<Vec<_>>()
    );
    for route in carriers {
        if owned.contains(route.service_id) {
            assert_eq!(
                (route.route_field, route.route_field_number),
                (Some("tenant"), 2),
                "{} must route by McpRequest.tenant",
                route.grpc_path
            );
        } else {
            assert_eq!(
                route.route_field, None,
                "{} is a platform carrier and declares no route field",
                route.grpc_path
            );
        }
    }
}

/// Two callers, two tenants, the same carrier: each session reaches its own
/// tenant's instance, and every frame (one sent with no tenant, one naming the
/// caller's own) arrives stamped with the token's tenant.
#[tokio::test]
async fn an_mcp_session_reaches_the_token_tenant_and_every_frame_is_stamped() {
    let fleet = fleet().await;
    let key = keys::generate_ec_p256_key().expect("signing key");
    let gateway = grpc_gateway(proxy_state(fleet.endpoints.clone(), &[SERVICE], &key)).await;

    let mut session = Session::open(gateway, &user_token(&key, &format!("/tenants/{ACME}"))).await;
    assert_eq!(session.answer().await, Ok(ACME.to_string()), "the opening frame");
    session.send(ACME).await;
    assert_eq!(session.answer().await, Ok(ACME.to_string()), "a frame naming its own tenant");
    session.send("").await;
    assert_eq!(session.answer().await, Ok(ACME.to_string()), "a later empty frame");
    assert_eq!(tenants(&fleet.acme.frames()), vec![ACME, ACME, ACME]);

    // A caller below a tenant (a workspace) belongs to it.
    let mut session = Session::open(
        gateway,
        &user_token(&key, &format!("/tenants/{BETA}/workspaces/eu")),
    )
    .await;
    assert_eq!(session.answer().await, Ok(BETA.to_string()));
    assert_eq!(tenants(&fleet.beta.frames()), vec![BETA]);

    assert_eq!(tenants(&fleet.acme.frames()).len(), 3, "acme saw only its own session");
    assert!(fleet.shared.frames().is_empty(), "no shared instance is ever reached");
}

/// A frame naming another tenant is refused and never forwarded, whether it
/// opens the session or comes after frames that were.
#[tokio::test]
async fn a_frame_naming_another_tenant_is_refused_and_not_forwarded() {
    let fleet = fleet().await;
    let key = keys::generate_ec_p256_key().expect("signing key");
    let gateway = grpc_gateway(proxy_state(fleet.endpoints.clone(), &[SERVICE], &key)).await;
    let bearer = user_token(&key, &format!("/tenants/{ACME}"));

    // Mid-session.
    let mut session = Session::open(gateway, &bearer).await;
    assert_eq!(session.answer().await, Ok(ACME.to_string()));
    session.send(BETA).await;
    session.send(ACME).await;
    assert!(
        session.answer().await.is_err(),
        "the session must fail at the frame naming {BETA}"
    );
    assert_eq!(
        tenants(&fleet.acme.frames()),
        vec![ACME],
        "nothing at or after the refused frame reaches the instance"
    );

    // As the opening frame.
    let channel = tonic::transport::Endpoint::from_shared(format!("http://{gateway}"))
        .expect("endpoint")
        .connect()
        .await
        .expect("connect");
    let mut request = tonic::Request::new(tokio_stream::iter(vec![frame("{}", BETA)]));
    request
        .metadata_mut()
        .insert("authorization", bearer.parse().expect("bearer"));
    let outcome = timeout(
        Duration::from_secs(10),
        TenantEchoClient::new(channel).broker_tenant_echo_mcp_session(request),
    )
    .await
    .expect("the gateway answers");
    if let Ok(response) = outcome {
        let mut stream = response.into_inner();
        let next = timeout(Duration::from_secs(10), stream.message())
            .await
            .expect("the stream ends");
        assert!(
            !matches!(next, Ok(Some(_))),
            "a session opened naming {BETA} must not be answered: {next:?}"
        );
    }
    assert_eq!(tenants(&fleet.acme.frames()), vec![ACME], "acme saw nothing more");
    assert!(fleet.beta.frames().is_empty(), "the named tenant is never reached");
    assert!(fleet.shared.frames().is_empty());
}

/// A caller whose namespace names no tenant has no instance and no tenant to
/// stamp: PERMISSION_DENIED, and nothing is reached.
#[tokio::test]
async fn a_caller_in_no_tenant_is_refused() {
    let fleet = fleet().await;
    let key = keys::generate_ec_p256_key().expect("signing key");
    let gateway = grpc_gateway(proxy_state(fleet.endpoints.clone(), &[SERVICE], &key)).await;

    let session = Session::open(gateway, &user_token(&key, "/system/us-east")).await;
    let status = session.result.expect_err("a /system caller must be refused");
    assert_eq!(status.code(), tonic::Code::PermissionDenied, "{status:?}");
    assert!(
        fleet.acme.frames().is_empty()
            && fleet.beta.frames().is_empty()
            && fleet.shared.frames().is_empty(),
        "a refused caller reaches no instance"
    );
}

/// The carrier of a service that is not tenant-owned routes by name and is
/// forwarded as it was: no tenant is stamped, and the caller's namespace plays
/// no part.
#[tokio::test]
async fn a_platform_carrier_is_routed_and_forwarded_as_before() {
    let fleet = fleet().await;
    let key = keys::generate_ec_p256_key().expect("signing key");
    let gateway = grpc_gateway(proxy_state(fleet.endpoints.clone(), &[], &key)).await;

    for namespace in [format!("/tenants/{ACME}"), "/system/us-east".to_string()] {
        let mut session = Session::open(gateway, &user_token(&key, &namespace)).await;
        assert_eq!(session.answer().await, Ok(String::new()), "{namespace}: not stamped");
    }
    assert_eq!(tenants(&fleet.shared.frames()), vec!["", ""]);
    assert!(fleet.acme.frames().is_empty() && fleet.beta.frames().is_empty());
}

/// The WebSocket bridge (`handle_websocket_stream` →
/// `proxy_grpc::handle_prevalidated_stream`) stamps and refuses the same way.
#[tokio::test]
async fn the_websocket_bridge_stamps_and_refuses_the_same_way() {
    let fleet = fleet().await;
    let key = keys::generate_ec_p256_key().expect("signing key");
    let bearer = user_token(&key, &format!("/tenants/{ACME}"));
    let addr = serve(rest_router(proxy_state(
        fleet.endpoints.clone(),
        &[SERVICE],
        &key,
    )))
    .await;

    let (mut ws, _) = tokio_tungstenite::connect_async(format!(
        "ws://{addr}/tenantecho/TenantEcho/BrokerTenantEchoMcpSession"
    ))
    .await
    .expect("WebSocket upgrade");
    let message = |tenant: &str| {
        Message::Text(
            serde_json::json!({
                "type": "message",
                "authorization": bearer,
                "message": {"payload": "{}", "tenant": tenant},
            })
            .to_string()
            .into(),
        )
    };
    ws.send(message("")).await.expect("send");
    let answer = timeout(Duration::from_secs(10), ws.next())
        .await
        .expect("the instance answers")
        .expect("a message")
        .expect("a frame");
    assert!(
        matches!(&answer, Message::Text(text) if text.contains(ACME)),
        "the frame must arrive stamped with {ACME}: {answer:?}"
    );

    ws.send(message(BETA)).await.expect("send");
    ws.send(message(ACME)).await.expect("send");
    let next = timeout(Duration::from_secs(10), ws.next())
        .await
        .expect("the gateway answers");
    assert!(
        !matches!(&next, Some(Ok(Message::Text(text))) if text.contains(ACME) && !text.contains("error")),
        "the session must fail at the frame naming {BETA}: {next:?}"
    );
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(tenants(&fleet.acme.frames()), vec![ACME]);
    assert!(fleet.beta.frames().is_empty() && fleet.shared.frames().is_empty());
}
