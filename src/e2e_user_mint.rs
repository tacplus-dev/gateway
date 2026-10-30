// End-to-end proof, over real sockets, that the user half of the
// delegate-bound Offline Token mint reaches kernel through the gateway's
// ORDINARY client-facing path — and that the delegate half does not.
// (token-management decision item 7, `kernel.UserMint`.)
//
// What is real here:
//
//   * a real tonic gRPC server — the GENERATED `kernel.UserMint` server, the
//     same trait kernel's `IdentityServiceImpl` implements on the Java side —
//     on a real TCP port;
//   * the real `proxy_grpc::handle` on a second real TCP port, entered by the
//     real generated `UserMintClient` speaking HTTP/2, resolving against the
//     real generated `ROUTES` table;
//   * the real `GatewayAuth` over a real `JwkCache`, verifying a real
//     ECDSA-signed user JWT;
//   * the real `Resolver`, dialing kernel from its endpoint table.
//
// Nothing in `gateway.proto` or `mint.rs` names this RPC. The route exists only
// because `kernel.proto` declares `service UserMint` `(spec.service_c2s)`, so a
// call arriving here proves the generic C2S path carries it with no
// hand-written gateway front.
//
// What is stood in for, none of it on the decision path: kernel itself (a JVM
// service needing state and opa) is a stand-in that returns a fixed code — the
// mint's own behaviour is pinned by kernel's `DelegateOfflineTokenTest`, and
// the hop under test here is client → gateway → the `kernel.UserMint` wire
// contract. The endpoint table and JWK set are seeded rather than streamed from
// kernel, and the gateway→backend hop is plaintext h2c rather than
// SPIFFE-pinned TLS (`Resolver::plaintext_backends`): the routing and auth
// decisions are both made before any dial and do not depend on the transport.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use tokio::net::TcpListener;
use tokio_stream::wrappers::TcpListenerStream;

use gateway_grpcserver::authorizer::JwkCache;
use gateway_jwk::jwk::{ImmutableJwk, Jwk};
use gateway_key::{base64_utils, keys};
use gateway_servicemanager::SpiffeServerCertVerifier;
use gateway_token::token::Token;
use gateway_x509::x509::{ImmutableCertChain, X509KeyUsage};

use gateway_model::types::services::kernel::kernel as kernel_pb;
use gateway_model::types::sys::mcp::mcp::{McpRequest, McpResponse};
use gateway_model::types::sys::tokenrequest::tokenrequest as tokenrequest_pb;
use kernel_pb::mint_client::MintClient;
use kernel_pb::user_mint_client::UserMintClient;
use kernel_pb::user_mint_server::{UserMint, UserMintServer};

use crate::auth::GatewayAuth;
use crate::health::{HealthWatcher, ServiceEndpoint};
use crate::proxy_grpc::{self, ProxyState};
use crate::resolver::Resolver;

const TRUST_DOMAIN: &str = "user-mint-e2e.test";
/// The `service_id` the generated route for `/kernel.UserMint/*` names, and
/// therefore the key the gateway looks up in its endpoint table.
const KERNEL_SERVICE: &str = "kernel";
/// The one-time code the stand-in hands back. The real one is 64 base64url
/// chars of `SecureRandom`; this only has to be recognisable.
const CODE: &str = "the-code-the-user-hands-the-delegate";

// ── the backend ─────────────────────────────────────────────────────────────

fn unused() -> tonic::Status {
    tonic::Status::unimplemented("not part of this test")
}

/// Stands in for kernel's `UserMint` surface. It records the delegate it was
/// asked about and whether the caller's bearer token arrived with the call, so
/// the test can assert the gateway forwards the credential the handler mints
/// against rather than swallowing it.
#[derive(Default)]
struct KernelStandIn {
    seen: Mutex<Vec<(String, String, bool)>>,
}

#[tonic::async_trait]
impl UserMint for KernelStandIn {
    async fn mint_delegate_offline_token(
        &self,
        request: tonic::Request<tokenrequest_pb::MintDelegateOfflineTokenRequest>,
    ) -> Result<tonic::Response<tokenrequest_pb::MintDelegateOfflineTokenResponse>, tonic::Status>
    {
        let had_auth = request.metadata().get("authorization").is_some();
        let req = request.into_inner();
        self.seen
            .lock()
            .expect("seen")
            .push((req.delegate_name, req.delegate_namespace, had_auth));
        Ok(tonic::Response::new(
            tokenrequest_pb::MintDelegateOfflineTokenResponse {
                code: CODE.to_string(),
                expires_at_ms: unix_now() * 1000 + 300_000,
            },
        ))
    }

    async fn merge_credentials(
        &self,
        _: tonic::Request<kernel_pb::MergeCredentialsRequest>,
    ) -> Result<tonic::Response<kernel_pb::MergeCredentialsResponse>, tonic::Status> {
        Err(unused())
    }

    async fn merge_people(
        &self,
        _: tonic::Request<kernel_pb::MergePeopleRequest>,
    ) -> Result<tonic::Response<kernel_pb::MergePeopleResponse>, tonic::Status> {
        Err(unused())
    }

    async fn get_linked_accounts(
        &self,
        _: tonic::Request<kernel_pb::GetLinkedAccountsRequest>,
    ) -> Result<tonic::Response<kernel_pb::GetLinkedAccountsResponse>, tonic::Status> {
        Err(unused())
    }

    async fn delete_identity_link(
        &self,
        _: tonic::Request<kernel_pb::DeleteIdentityLinkRequest>,
    ) -> Result<tonic::Response<kernel_pb::DeleteIdentityLinkResponse>, tonic::Status> {
        Err(unused())
    }

    async fn delete_account(
        &self,
        _: tonic::Request<kernel_pb::DeleteAccountRequest>,
    ) -> Result<tonic::Response<kernel_pb::DeleteAccountResponse>, tonic::Status> {
        Err(unused())
    }

    async fn revoke_sessions(
        &self,
        _: tonic::Request<kernel_pb::RevokeSessionsRequest>,
    ) -> Result<tonic::Response<kernel_pb::RevokeSessionsResponse>, tonic::Status> {
        Err(unused())
    }

    async fn revoke_credential_proof(
        &self,
        _: tonic::Request<kernel_pb::RevokeCredentialProofRequest>,
    ) -> Result<tonic::Response<kernel_pb::RevokeCredentialProofResponse>, tonic::Status> {
        Err(unused())
    }

    async fn revoke_device_credential(
        &self,
        _: tonic::Request<kernel_pb::RevokeDeviceCredentialRequest>,
    ) -> Result<tonic::Response<kernel_pb::RevokeDeviceCredentialResponse>, tonic::Status> {
        Err(unused())
    }

    type BrokerUserMintMcpSessionStream =
        tokio_stream::Empty<Result<McpResponse, tonic::Status>>;

    async fn broker_user_mint_mcp_session(
        &self,
        _: tonic::Request<tonic::Streaming<McpRequest>>,
    ) -> Result<tonic::Response<Self::BrokerUserMintMcpSessionStream>, tonic::Status> {
        Err(unused())
    }
}

// ── credentials ─────────────────────────────────────────────────────────────

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_secs() as i64
}

fn jwk_for(key: &keys::ImmutableKey) -> ImmutableJwk {
    let (x, y) = match key.public_key() {
        keys::PublicKey::EcP256(ec) => {
            (
                base64_utils::encode_base64_url(ec.x()),
                base64_utils::encode_base64_url(ec.y()),
            )
        }
        _ => panic!("this test signs with a P-256 key"),
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

/// An ordinary person's token: `sub_type: user`, audience `kernel`, and NO
/// `service_entitlements` at all. That absence is deliberate — the route is
/// `AnyUser`, so a token carrying no grant whatsoever must still be admitted;
/// a token with grants would pass even if the policy were `Entitled` and would
/// prove nothing about which policy the generated route actually carries.
fn user_token(key: &keys::ImmutableKey) -> String {
    let mut token = Token::new();
    token.set_kid(key.id()).expect("kid");
    token.set_alg(key.alg()).expect("alg");
    token.set_issuer("user-mint-e2e").expect("iss");
    token.set_subject("alice@example.com").expect("sub");
    token.set_audience(KERNEL_SERVICE).expect("aud");
    token.set_namespace("acme").expect("ns");
    token.set_expiration(unix_now() + 3600).expect("exp");
    token.set_sub_type("user").expect("sub_type");
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

async fn spawn_kernel(backend: Arc<KernelStandIn>) -> ServiceEndpoint {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind kernel");
    let addr = listener.local_addr().expect("kernel addr");
    tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(UserMintServer::from_arc(backend))
            .serve_with_incoming(TcpListenerStream::new(listener))
            .await
            .expect("kernel serve");
    });
    ServiceEndpoint {
        host: addr.ip().to_string(),
        port: addr.port() as i32,
    }
}

async fn spawn_gateway(proxy: Arc<ProxyState>) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind gateway");
    let addr = listener.local_addr().expect("gateway addr");
    let app = axum::Router::new().fallback(axum::routing::any(
        move |req: axum::http::Request<axum::body::Body>| {
            let proxy = proxy.clone();
            async move { proxy_grpc::handle(&proxy, req).await }
        },
    ));
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("gateway serve");
    });
    format!("http://{}", addr)
}

async fn channel(gateway_uri: &str) -> tonic::transport::Channel {
    tonic::transport::Endpoint::from_shared(gateway_uri.to_string())
        .expect("endpoint")
        .connect()
        .await
        .expect("connect to gateway")
}

fn proxy_state(kernel: ServiceEndpoint, jwk: ImmutableJwk) -> Arc<ProxyState> {
    let mut endpoints = HashMap::new();
    endpoints.insert(KERNEL_SERVICE.to_string(), vec![kernel]);
    Arc::new(ProxyState {
        resolver: Arc::new(Resolver::plaintext_backends(
            HealthWatcher::seeded(endpoints),
            unused_verifier(),
        )),
        auth: Arc::new(GatewayAuth::new(Arc::new(JwkCache::seeded(vec![jwk])), false)),
        tenant_owned: Arc::new(Default::default()),
        trace_publisher: Arc::new(|_| {}),
        trace_round: Box::new(Default::default),
    })
}

/// Builds the request with a bearer header, since the generated client takes
/// the metadata rather than a channel interceptor here.
fn request_with(
    auth: Option<&str>,
    req: tokenrequest_pb::MintDelegateOfflineTokenRequest,
) -> tonic::Request<tokenrequest_pb::MintDelegateOfflineTokenRequest> {
    let mut request = tonic::Request::new(req);
    if let Some(header) = auth {
        request.metadata_mut().insert(
            "authorization",
            header.parse().expect("authorization header"),
        );
    }
    request
}

fn mint_request() -> tokenrequest_pb::MintDelegateOfflineTokenRequest {
    tokenrequest_pb::MintDelegateOfflineTokenRequest {
        delegate_name: "ticketbot".to_string(),
        delegate_namespace: "/acme".to_string(),
        ..Default::default()
    }
}

// ── the runs ────────────────────────────────────────────────────────────────

/// Item 7's invariant: a person calling `MintDelegateOfflineToken` with their
/// own bearer token reaches kernel through the gateway, and gets the one-time
/// code back. Both halves are asserted in one run — the authenticated caller
/// SUCCEEDS, the caller with no token is REFUSED — so a gateway that let
/// everything through could not pass.
#[tokio::test]
async fn a_user_mints_a_delegate_offline_token_through_the_gateway() {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let signing_key = keys::generate_ec_p256_key().expect("signing key");
    let backend = Arc::new(KernelStandIn::default());
    let kernel = spawn_kernel(backend.clone()).await;
    let gateway_uri = spawn_gateway(proxy_state(kernel, jwk_for(&signing_key))).await;

    let minted = UserMintClient::new(channel(&gateway_uri).await)
        .mint_delegate_offline_token(request_with(
            Some(&user_token(&signing_key)),
            mint_request(),
        ))
        .await
        .unwrap_or_else(|e| panic!("a user's mint must reach kernel through the gateway: {e:?}"))
        .into_inner();

    assert_eq!(
        minted.code, CODE,
        "the response must be the backend's, not something the gateway synthesised"
    );

    let seen = backend.seen.lock().expect("seen").clone();
    assert_eq!(
        seen,
        vec![("ticketbot".to_string(), "/acme".to_string(), true)],
        "kernel must see the delegate pair the client sent, with the caller's bearer token \
         forwarded — the handler mints against that token's subject"
    );

    // No token at all. The route is AnyUser, not NoAuth: the generic path has
    // to refuse this before the dial.
    let refused = UserMintClient::new(channel(&gateway_uri).await)
        .mint_delegate_offline_token(request_with(None, mint_request()))
        .await
        .expect_err("an unauthenticated caller must not mint a delegation");
    assert_eq!(
        refused.code(),
        tonic::Code::Unauthenticated,
        "the refusal must be the auth gate, not the backend: {refused:?}"
    );
    assert_eq!(
        backend.seen.lock().expect("seen").len(),
        1,
        "the refused call must never have reached kernel"
    );
}

/// The other half of item 7's shape: only the USER half moved to C2S.
/// `BrokerDelegateOfflineToken` stays on the S2S `kernel.Mint` service — the
/// delegate redeems the code as itself, over the service plane — so it must not
/// be reachable through the gateway at all.
///
/// The control below is what keeps that from being vacuous: this gateway DOES
/// have a kernel endpoint, and `/kernel.Mint/MintClientToken` is a sibling
/// method on the SAME service that is deliberately routed. It reaches the dial;
/// the broker half does not get that far.
#[tokio::test]
async fn the_delegate_half_stays_off_the_client_path() {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let signing_key = keys::generate_ec_p256_key().expect("signing key");
    let backend = Arc::new(KernelStandIn::default());
    let kernel = spawn_kernel(backend).await;
    let gateway_uri = spawn_gateway(proxy_state(kernel, jwk_for(&signing_key))).await;

    let refused = MintClient::new(channel(&gateway_uri).await)
        .broker_delegate_offline_token(tokenrequest_pb::RedeemDelegateOfflineTokenRequest {
            code: CODE.to_string(),
            ..Default::default()
        })
        .await
        .expect_err("the delegate half must not be reachable from a client");
    assert_eq!(
        refused.code(),
        tonic::Code::NotFound,
        "an S2S-only RPC must be refused by the route table: {refused:?}"
    );
    assert_eq!(
        refused.message(),
        "unknown gRPC method",
        "the refusal must come from deny-by-default, not from a dial failure"
    );

    // The control: a routed sibling on the same S2S service gets past the table
    // and fails at the backend instead (the stand-in serves UserMint only).
    let sibling = MintClient::new(channel(&gateway_uri).await)
        .mint_client_token(tokenrequest_pb::MintClientTokenRequest::default())
        .await
        .expect_err("the stand-in serves no kernel.Mint methods");
    assert_ne!(
        sibling.code(),
        tonic::Code::NotFound,
        "a routed kernel.Mint method must get past the route table, proving the NOT_FOUND \
         above is the table refusing the path rather than kernel being absent: {sibling:?}"
    );
}
