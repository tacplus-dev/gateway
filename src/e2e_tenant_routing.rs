// End-to-end proof, over real sockets, that the gateway sends a call to a
// tenant-owned service to the instance of the tenant its request NAMES (the
// rpc's `(spec.rpc).route_field`, a tid), whatever tenant the caller's token is
// in; that a call naming no tenant is refused before anything is dialled; and
// that a platform service routes by name as before (#3, tacplus#170,
// tacplus-dev/roadmap decisions/tenant-routing-2026-10-26.md).
//
// What is real here:
//
//   * the real `proxy_grpc::handle`, entered with a real gRPC-framed request;
//   * the real generated `ROUTES` table: the route under test is tenantecho's
//     `Ping`, whose route field is `PingRequest.tenant`, and its MCP session
//     carrier, whose route field is `McpRequest.tenant`;
//   * the real `GatewayAuth` over a real `JwkCache`, verifying real
//     ECDSA-signed JWTs;
//   * the real `Resolver` and the real `HealthWatcher` endpoint table;
//   * real TCP listeners, one per tenant instance, each counting the
//     connections it receives.
//
// The observable is the DIAL, not a response body: each listener accepts and
// immediately drops the socket, so the call ends in Unavailable either way and
// the only thing that distinguishes one tenant from the other is which listener
// the gateway connected to. That is precisely the decision under test. Whether
// the caller may reach that tenant is the target's policy (its tenant door),
// not the gateway's routing, so it is not asserted here.

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use axum::body::Body;
use http::Request;
use tokio::net::TcpListener;
use tower::ServiceExt;

use gateway_grpcserver::authorizer::JwkCache;
use gateway_jwk::jwk::{ImmutableJwk, Jwk};
use gateway_key::{base64_utils, keys};
use gateway_model::s2sm::rest_dispatch::{AuthPolicy, RouteInfo, ROUTES};
use gateway_model::types::services::tenantecho::tenantecho::PingRequest;
use gateway_model::types::sys::mcp::mcp::McpRequest;
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

const TRUST_DOMAIN: &str = "tenant-routing.test";

/// Two tenants' tids: exactly 8 characters of `[0-9a-z]`.
const ACME: &str = "acme0001";
const BETA: &str = "beta0002";

// ── a backend that only records that it was dialed ──────────────────────────

/// A TCP listener that counts inbound connections and drops each one at once.
/// Dropping is deliberate: a live socket that never speaks HTTP/2 would hold
/// the gateway's eager connect open until its keep-alive timeout.
struct DialCounter {
    endpoint: ServiceEndpoint,
    dials: Arc<AtomicUsize>,
}

impl DialCounter {
    async fn spawn() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let dials = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&dials);
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                counter.fetch_add(1, Ordering::SeqCst);
                drop(stream);
            }
        });
        Self {
            endpoint: ServiceEndpoint {
                host: addr.ip().to_string(),
                port: addr.port() as i32,
            },
            dials,
        }
    }

    /// Whether this instance has been dialed at all. The COUNT is deliberately
    /// not asserted on: one logical dial is several connections (a TCP
    /// reachability probe, then the real connect, then `Resolver`'s round-robin
    /// fallback when the eager connect fails), and that is `Resolver` internals,
    /// not routing. Which instance was contacted, and which was not, is the
    /// property under test.
    fn dialed(&self) -> bool {
        self.dials.load(Ordering::SeqCst) > 0
    }

    /// Forgets earlier dials, so a second call in the same test asserts on its
    /// own traffic.
    fn reset(&self) {
        self.dials.store(0, Ordering::SeqCst);
    }
}

// ── tokens ──────────────────────────────────────────────────────────────────

fn jwk_for(key: &keys::ImmutableKey) -> ImmutableJwk {
    let (x, y) = match key.public_key() {
        keys::PublicKey::EcP256(ec) => {
            (
                base64_utils::encode_base64_url(ec.x()),
                base64_utils::encode_base64_url(ec.y()),
            )
        }
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

/// A user token in `namespace`, entitled to everything.
///
/// `{"all": true}` is the admin bypass, and using it here is the point: it takes
/// the entitlement catalog out of the picture so a routing failure cannot be
/// mistaken for an entitlement failure. Entitlements are already proven by
/// `e2e_entitlement`; what is under test here is which backend gets dialed.
fn user_token(key: &keys::ImmutableKey, audience: &str, namespace: &str) -> String {
    let mut token = Token::new();
    token.set_kid(key.id()).expect("kid");
    token.set_alg(key.alg()).expect("alg");
    token.set_issuer("tenant-routing-test").expect("iss");
    token.set_subject("alice@example.com").expect("sub");
    token.set_audience(audience).expect("aud");
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

/// A verifier the plaintext test path never consults; `Resolver` just holds one,
/// and `WebPkiServerVerifier` refuses to build with no anchors at all.
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

/// tenantecho's `Ping`: the fleet's tenant-routed proof rpc, routed by
/// `PingRequest.tenant` (field 2). Asserted off the generated table, so a
/// regeneration that drops or moves its route field fails here first.
fn routed_route() -> &'static RouteInfo {
    let route = ROUTES
        .iter()
        .find(|r| r.grpc_path == "/tenantecho.TenantEcho/Ping")
        .expect("the generated ROUTES table must carry tenantecho's Ping");
    assert_eq!(route.service_id, "tenantecho");
    assert_eq!(route.route_field, Some("tenant"), "Ping is routed by PingRequest.tenant");
    assert_eq!(route.route_field_number, 2, "PingRequest.tenant is field 2");
    assert!(!route.client_streaming && !route.server_streaming, "Ping is unary");
    route
}

/// tenantecho's MCP session carrier: a client-streaming route of a
/// tenant-owned service, routed by `McpRequest.tenant` (field 2).
fn routed_stream_route() -> &'static RouteInfo {
    let route = ROUTES
        .iter()
        .find(|r| r.service_id == "tenantecho" && r.client_streaming)
        .expect("the generated ROUTES table must carry tenantecho's MCP session carrier");
    assert_eq!(route.route_field, Some("tenant"), "the carrier is routed by McpRequest.tenant");
    assert_eq!(route.route_field_number, 2, "McpRequest.tenant is field 2");
    route
}

/// The first unary user-authenticated route of a platform service (no route
/// field) whose request an empty message satisfies, picked from ROUTES so the
/// test follows regeneration rather than pinning a path that a proto change
/// can move.
fn platform_route() -> &'static RouteInfo {
    ROUTES
        .iter()
        .find(|r| {
            r.route_field.is_none()
                && !r.server_streaming
                && !r.client_streaming
                && matches!(r.auth_policy, AuthPolicy::Entitled | AuthPolicy::AnyUser)
                && r.target_namespace_field.is_none()
                && !r.grpc_path.starts_with("/gateway.")
                && gateway_model::s2sm::proxy_dispatch::validate_request(r.grpc_path, &[]).is_ok()
        })
        .expect("the generated ROUTES table must contain a unary user-authenticated platform route")
}

fn proxy_state(
    endpoints: HashMap<String, Vec<ServiceEndpoint>>,
    signing_key: &keys::ImmutableKey,
) -> ProxyState {
    ProxyState {
        resolver: Arc::new(Resolver::plaintext_backends(
            HealthWatcher::seeded(endpoints),
            unused_verifier(),
        )),
        auth: Arc::new(GatewayAuth::new(
            Arc::new(JwkCache::seeded(vec![jwk_for(signing_key)])),
            false,
        )),
        trace_publisher: Arc::new(|_| {}),
        trace_round: Box::new(Default::default),
    }
}

/// A `Ping` naming `tenant` as its target, in a well-formed gRPC frame.
fn ping(tenant: &str) -> Vec<u8> {
    let request = PingRequest {
        message: "hello".to_string(),
        tenant: tenant.to_string(),
        ..Default::default()
    };
    proxy_grpc::frame_grpc(&prost::Message::encode_to_vec(&request))
}

/// One MCP session frame naming `tenant`, in a well-formed gRPC frame.
fn mcp_frame(tenant: &str) -> Vec<u8> {
    let request = McpRequest {
        payload: r#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#.to_string(),
        tenant: tenant.to_string(),
        ..Default::default()
    };
    proxy_grpc::frame_grpc(&prost::Message::encode_to_vec(&request))
}

/// The REST router in front of `proxy`. Ping is not a gateway.Mint route, so
/// the minter is never consulted.
fn rest_router(proxy: ProxyState) -> axum::Router {
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
        proxy: Arc::new(proxy),
        minter: Arc::new(NoMinter),
        auth,
        root_ca: vec![],
        issuer_url: "https://gateway.example".to_string(),
    }))
}

async fn call(
    proxy: &ProxyState,
    route: &RouteInfo,
    bearer: &str,
    body: Vec<u8>,
) -> axum::response::Response {
    let request = Request::builder()
        .method("POST")
        .uri(route.grpc_path)
        .header("content-type", "application/grpc+proto")
        .header("authorization", bearer)
        .body(Body::from(body))
        .expect("request");
    proxy_grpc::handle(proxy, request).await
}

fn grpc_status(response: &axum::response::Response) -> Option<&str> {
    response
        .headers()
        .get("grpc-status")
        .and_then(|v| v.to_str().ok())
}

fn grpc_message(response: &axum::response::Response) -> &str {
    response
        .headers()
        .get("grpc-message")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
}

/// One listener per tenant instance, registered under its route key, plus one
/// under the bare service name that a tenant-routed call must never reach: a
/// tenant-owned service has no shared instance, so dialing it would be a
/// routing bug an "endpoints exist" assertion alone would miss.
struct Instances {
    acme: DialCounter,
    beta: DialCounter,
    shared: DialCounter,
}

impl Instances {
    async fn spawn(service: &str) -> (Self, HashMap<String, Vec<ServiceEndpoint>>) {
        let instances = Self {
            acme: DialCounter::spawn().await,
            beta: DialCounter::spawn().await,
            shared: DialCounter::spawn().await,
        };
        let mut endpoints = HashMap::new();
        endpoints.insert(format!("{service}-{ACME}"), vec![instances.acme.endpoint.clone()]);
        endpoints.insert(format!("{service}-{BETA}"), vec![instances.beta.endpoint.clone()]);
        endpoints.insert(service.to_string(), vec![instances.shared.endpoint.clone()]);
        (instances, endpoints)
    }

    fn dialed(&self) -> (bool, bool, bool) {
        (self.acme.dialed(), self.beta.dialed(), self.shared.dialed())
    }

    fn reset(&self) {
        self.acme.reset();
        self.beta.reset();
        self.shared.reset();
    }
}

// ── the runs ────────────────────────────────────────────────────────────────

/// Two tenants' calls to the same method reach their own instances by the
/// field, whatever tenant the caller's token names: the same acme caller
/// reaches beta's instance when it names beta, and a beta caller reaches
/// acme's when it names acme. One run, one set of sockets, so neither half
/// can be quietly true alone.
#[tokio::test]
async fn a_tenant_owned_call_routes_by_its_target_tenant_field_not_the_token() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let route = routed_route();
    let service = route.service_id;
    let (instances, endpoints) = Instances::spawn(service).await;
    let signing_key = keys::generate_ec_p256_key().expect("signing key");
    let proxy = proxy_state(endpoints, &signing_key);

    for (caller, target, expected) in [
        ("/tenants/acme", ACME, (true, false, false)),
        ("/tenants/acme", BETA, (false, true, false)),
        ("/tenants/beta", ACME, (true, false, false)),
        ("/tenants/beta", BETA, (false, true, false)),
        ("/system/us-east", BETA, (false, true, false)),
    ] {
        instances.reset();
        call(&proxy, route, &user_token(&signing_key, service, caller), ping(target)).await;
        assert_eq!(
            instances.dialed(),
            expected,
            "a {caller} caller naming tenant {target} must reach {service}-{target} alone"
        );
    }
}

/// A call naming no valid target tenant is refused, INVALID_ARGUMENT, before
/// anything is dialled: the tenant is never filled in from the caller's token,
/// and there is no shared instance to fall back to.
#[tokio::test]
async fn a_call_with_no_valid_target_tenant_is_refused_and_dials_nothing() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let route = routed_route();
    let service = route.service_id;
    let (instances, endpoints) = Instances::spawn(service).await;
    let signing_key = keys::generate_ec_p256_key().expect("signing key");
    let proxy = proxy_state(endpoints, &signing_key);

    // "acme" is the tenant's NAME, which is what its token's namespace says:
    // a name is not a tid, and must not route.
    for target in ["", "acme", "ACME0001", "acme00011"] {
        let response = call(
            &proxy,
            route,
            &user_token(&signing_key, service, "/tenants/acme"),
            ping(target),
        )
        .await;
        assert_eq!(
            grpc_status(&response),
            Some("3"),
            "a target tenant of {target:?} must be InvalidArgument (3), got message {:?}",
            grpc_message(&response)
        );
        assert!(
            grpc_message(&response).contains("\"tenant\""),
            "the refusal must name the route field, got {:?}",
            grpc_message(&response)
        );
        assert_eq!(
            instances.dialed(),
            (false, false, false),
            "a refused call ({target:?}) must not reach any backend"
        );
    }
}

/// A tenant with no healthy instance is Unavailable, never another tenant's
/// instance nor the bare service name.
#[tokio::test]
async fn a_tenant_with_no_instance_is_unavailable_and_reaches_no_other() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let route = routed_route();
    let service = route.service_id;
    let (instances, endpoints) = Instances::spawn(service).await;
    let signing_key = keys::generate_ec_p256_key().expect("signing key");
    let proxy = proxy_state(endpoints, &signing_key);

    let response = call(
        &proxy,
        route,
        &user_token(&signing_key, service, "/tenants/acme"),
        ping("gone0003"),
    )
    .await;

    assert_eq!(
        grpc_status(&response),
        Some("14"),
        "a tenant with no instance must be Unavailable (14), got message {:?}",
        grpc_message(&response)
    );
    assert_eq!(instances.dialed(), (false, false, false));
}

/// A stream is opened for the tenant its first message names, whatever tenant
/// the caller's token is in; a stream whose first message names none is
/// refused before anything is dialled.
#[tokio::test]
async fn a_tenant_owned_stream_routes_by_its_first_message() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let route = routed_stream_route();
    let service = route.service_id;
    let (instances, endpoints) = Instances::spawn(service).await;
    let signing_key = keys::generate_ec_p256_key().expect("signing key");
    let proxy = proxy_state(endpoints, &signing_key);
    let bearer = user_token(&signing_key, service, "/tenants/acme");

    call(&proxy, route, &bearer, mcp_frame(BETA)).await;
    assert_eq!(
        instances.dialed(),
        (false, true, false),
        "a stream opened for {BETA} must reach {service}-{BETA} alone"
    );

    instances.reset();
    let response = call(&proxy, route, &bearer, mcp_frame("")).await;
    assert_eq!(
        grpc_status(&response),
        Some("3"),
        "a stream naming no tenant must be InvalidArgument (3), got message {:?}",
        grpc_message(&response)
    );
    assert_eq!(instances.dialed(), (false, false, false), "a refused stream must dial nothing");
}

/// A platform service routes by name, as before: no route field is read, and
/// the caller's namespace is not consulted at all, so every caller lands on
/// the one shared instance and `<svc>-<tid>` is never chosen.
#[tokio::test]
async fn a_platform_service_routes_by_name_whatever_the_caller() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let route = platform_route();
    let service = route.service_id;
    let (instances, endpoints) = Instances::spawn(service).await;
    let signing_key = keys::generate_ec_p256_key().expect("signing key");
    let proxy = proxy_state(endpoints, &signing_key);

    for namespace in ["/tenants/acme", "/tenants/beta", "/system/us-east"] {
        instances.reset();
        call(
            &proxy,
            route,
            &user_token(&signing_key, service, namespace),
            proxy_grpc::frame_grpc(&[]),
        )
        .await;
        assert_eq!(
            instances.dialed(),
            (false, false, true),
            "a {namespace} caller must reach the shared {service} instance alone"
        );
    }
}

/// The REST translation routes the same way: its JSON body's route field
/// (`tenant`) picks the instance whatever tenant the token names, and a body
/// naming none is refused with 400 before anything is dialled.
#[tokio::test]
async fn the_rest_translation_routes_by_the_same_field() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let route = routed_route();
    let service = route.service_id;
    let (instances, endpoints) = Instances::spawn(service).await;
    let signing_key = keys::generate_ec_p256_key().expect("signing key");
    let router = rest_router(proxy_state(endpoints, &signing_key));
    let bearer = user_token(&signing_key, service, "/tenants/acme");

    let post = |body: serde_json::Value| {
        axum::http::Request::post(route.http_path)
            .header(axum::http::header::CONTENT_TYPE, "application/json")
            .header(axum::http::header::AUTHORIZATION, bearer.as_str())
            .body(Body::from(body.to_string()))
            .expect("request")
    };

    router
        .clone()
        .oneshot(post(serde_json::json!({"message": "hello", "tenant": BETA})))
        .await
        .expect("router answers");
    assert_eq!(
        instances.dialed(),
        (false, true, false),
        "a REST call naming {BETA} must reach {service}-{BETA} alone"
    );

    instances.reset();
    let response = router
        .oneshot(post(serde_json::json!({"message": "hello"})))
        .await
        .expect("router answers");
    assert_eq!(
        response.status(),
        axum::http::StatusCode::BAD_REQUEST,
        "a REST call naming no tenant must be 400"
    );
    assert_eq!(instances.dialed(), (false, false, false), "a refused call must dial nothing");
}
