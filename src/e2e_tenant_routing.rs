// End-to-end proof, over real sockets, that the gateway sends a caller to THEIR
// tenant's instance of a tenant-owned service — and that nothing else changes.
//
// What is real here:
//
//   * the real `proxy_grpc::handle`, entered with a real gRPC-framed request;
//   * the real `GatewayAuth` over a real `JwkCache`, verifying real
//     ECDSA-signed JWTs — the namespace this routes on is read off the SAME
//     `VerifiedClaims` the entitlement check uses, so an unverified token can
//     never reach the routing decision;
//   * the real `Resolver` and the real `HealthWatcher` endpoint table;
//   * real TCP listeners, one per tenant instance, each counting the
//     connections it receives.
//
// The observable is the DIAL, not a response body: each listener accepts and
// immediately drops the socket, so the call ends in Unavailable either way and
// the only thing that distinguishes acme from beta is which listener the
// gateway connected to. That is precisely the decision under test.
//
// The registry fixture is the `tenant_owned` set handed to `ProxyState` — no
// service in the live registry declares `(spec.service).tenant_owned` yet
// (registry.rs asserts this, and item 4 §1.2 explains why), so the tenant-owned
// path can only be exercised against a fixture.

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use axum::body::Body;
use http::Request;
use tokio::net::TcpListener;

use gateway_grpcserver::authorizer::JwkCache;
use gateway_jwk::jwk::{ImmutableJwk, Jwk};
use gateway_key::{base64_utils, keys};
use gateway_model::s2sm::rest_dispatch::{AuthPolicy, RouteInfo};
use gateway_servicemanager::SpiffeServerCertVerifier;
use gateway_token::token::Token;
use gateway_x509::x509::{ImmutableCertChain, X509KeyUsage};

use crate::auth::GatewayAuth;
use crate::health::{HealthWatcher, ServiceEndpoint};
use crate::proxy_grpc::{self, ProxyState};
use crate::resolver::Resolver;

const TRUST_DOMAIN: &str = "tenant-routing.test";

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
            let point = ec.to_encoded_point(false);
            (
                base64_utils::encode_base64_url(point.x().expect("x")),
                base64_utils::encode_base64_url(point.y().expect("y")),
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

/// The first unary `Entitled` route in the generated table with no target
/// namespace field, picked from ROUTES so the test follows regeneration rather
/// than pinning a path that a proto change can move.
fn route_under_test() -> &'static RouteInfo {
    gateway_model::s2sm::rest_dispatch::ROUTES
        .iter()
        .find(|r| {
            !r.server_streaming
                && !r.client_streaming
                && r.auth_policy == AuthPolicy::Entitled
                && r.target_namespace_field.is_none()
                && !r.grpc_path.starts_with("/gateway.")
        })
        .expect("the generated ROUTES table must contain a unary entitled route")
}

fn proxy_state(
    endpoints: HashMap<String, Vec<ServiceEndpoint>>,
    tenant_owned: &[&str],
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
        tenant_owned: Arc::new(tenant_owned.iter().map(|s| s.to_string()).collect()),
        trace_publisher: Arc::new(|_| {}),
        trace_round: Box::new(Default::default),
    }
}

/// An empty protobuf message in a well-formed gRPC frame. Every request message
/// on the route under test has no required field, so an empty body reaches the
/// routing decision — which is where this test looks.
fn empty_grpc_body() -> Body {
    Body::from(proxy_grpc::frame_grpc(&[]))
}

async fn call(proxy: &ProxyState, bearer: &str) -> axum::response::Response {
    let request = Request::builder()
        .method("POST")
        .uri(route_under_test().grpc_path)
        .header("content-type", "application/grpc+proto")
        .header("authorization", bearer)
        .body(empty_grpc_body())
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

// ── the runs ────────────────────────────────────────────────────────────────

/// (a) and (b) in one run, on one set of sockets, so neither can be quietly
/// true alone: the same method, the same gateway, two callers, two tenants,
/// two different backends.
#[tokio::test]
async fn a_tenant_owned_service_routes_each_caller_to_their_own_instance() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let route = route_under_test();
    let service = route.service_id;

    let acme = DialCounter::spawn().await;
    let beta = DialCounter::spawn().await;
    let shared = DialCounter::spawn().await;

    let mut endpoints = HashMap::new();
    endpoints.insert(format!("{service}-acme"), vec![acme.endpoint.clone()]);
    endpoints.insert(format!("{service}-beta"), vec![beta.endpoint.clone()]);
    // The bare name is registered too, and must stay untouched: a tenant-owned
    // service has no shared instance, so dialing it would be a routing bug that
    // an "endpoints exist" assertion alone would miss.
    endpoints.insert(service.to_string(), vec![shared.endpoint.clone()]);

    let signing_key = keys::generate_ec_p256_key().expect("signing key");
    let proxy = proxy_state(endpoints, &[service], &signing_key);

    // (a) /tenants/acme
    call(&proxy, &user_token(&signing_key, service, "/tenants/acme")).await;
    assert_eq!(
        (acme.dialed(), beta.dialed(), shared.dialed()),
        (true, false, false),
        "an /tenants/acme caller must reach {service}-acme alone"
    );

    // (b) /tenants/beta, same service, same gateway
    acme.reset();
    call(&proxy, &user_token(&signing_key, service, "/tenants/beta")).await;
    assert_eq!(
        (acme.dialed(), beta.dialed(), shared.dialed()),
        (false, true, false),
        "a /tenants/beta caller must reach {service}-beta, and acme must not be dialed at all"
    );
}

/// (c) A service the registry does NOT mark tenant-owned routes by name, and the
/// caller's namespace is not consulted at all — the same two tokens that split
/// in the test above land on the same backend here.
#[tokio::test]
async fn a_shared_service_ignores_the_caller_namespace_entirely() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let route = route_under_test();
    let service = route.service_id;

    let shared = DialCounter::spawn().await;
    let acme = DialCounter::spawn().await;

    let mut endpoints = HashMap::new();
    endpoints.insert(service.to_string(), vec![shared.endpoint.clone()]);
    // Present, and must never be chosen: nothing may route to `<svc>-acme` for a
    // service the registry does not mark.
    endpoints.insert(format!("{service}-acme"), vec![acme.endpoint.clone()]);

    let signing_key = keys::generate_ec_p256_key().expect("signing key");
    let proxy = proxy_state(endpoints, &[], &signing_key);

    for namespace in ["/tenants/acme", "/tenants/beta", "/system/us-east"] {
        shared.reset();
        call(&proxy, &user_token(&signing_key, service, namespace)).await;
        assert!(
            shared.dialed(),
            "a {namespace} caller must still reach the shared instance"
        );
    }

    assert_eq!(
        (shared.dialed(), acme.dialed()),
        (true, false),
        "every caller must reach the one shared instance, whatever their namespace"
    );
}

/// (d) The case item 4's doc called "the failure mode nobody has decided yet":
/// a /system caller against a tenant-owned service. There is no tenant to route
/// to, so the gateway rejects rather than picking one — and dials nothing.
/// See the decision doc's Open question 2.
#[tokio::test]
async fn a_system_caller_is_rejected_by_a_tenant_owned_service() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let route = route_under_test();
    let service = route.service_id;

    let acme = DialCounter::spawn().await;
    let shared = DialCounter::spawn().await;

    let mut endpoints = HashMap::new();
    endpoints.insert(format!("{service}-acme"), vec![acme.endpoint.clone()]);
    endpoints.insert(service.to_string(), vec![shared.endpoint.clone()]);

    let signing_key = keys::generate_ec_p256_key().expect("signing key");
    let proxy = proxy_state(endpoints, &[service], &signing_key);

    let response = call(
        &proxy,
        &user_token(&signing_key, service, "/system/us-east"),
    )
    .await;

    assert_eq!(
        grpc_status(&response),
        Some("7"),
        "a non-tenant caller must be PermissionDenied (7), got message {:?}",
        grpc_message(&response)
    );
    assert!(
        grpc_message(&response).contains("not tenant-scoped"),
        "the rejection must say why, got {:?}",
        grpc_message(&response)
    );
    assert_eq!(
        (acme.dialed(), shared.dialed()),
        (false, false),
        "a rejected caller must not reach any backend"
    );
}

/// A caller whose namespace names a workspace inside a tenant still belongs to
/// that tenant, and routes there. Nothing deploys per workspace.
#[tokio::test]
async fn a_workspace_scoped_caller_routes_to_its_tenant() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let route = route_under_test();
    let service = route.service_id;

    let acme = DialCounter::spawn().await;
    let mut endpoints = HashMap::new();
    endpoints.insert(format!("{service}-acme"), vec![acme.endpoint.clone()]);

    let signing_key = keys::generate_ec_p256_key().expect("signing key");
    let proxy = proxy_state(endpoints, &[service], &signing_key);

    call(
        &proxy,
        &user_token(&signing_key, service, "/tenants/acme/workspaces/eu"),
    )
    .await;

    assert!(
        acme.dialed(),
        "a /tenants/acme/workspaces/eu caller belongs to tenant acme"
    );
}
