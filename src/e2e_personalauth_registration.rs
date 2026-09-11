// End-to-end proof, over real sockets, of the device-login path the
// personalauth broker exists to create — and of the kernel route that was
// closed so the broker is not optional.
// (`decision-goalB-q1-broker-service-design.md` §4.3 and §6, build unit 7.)
//
// What is real here:
//
//   * a real gateway on a real TCP port — `spawn_gateway` over the real
//     `proxy_grpc::handle`, entered by a real generated tonic client speaking
//     HTTP/2, resolving against the real generated `ROUTES` table;
//   * a real, never-before-seen EC P-256 device key generated per run, and a
//     real self-signed proof JWT signed by it with the real token chassis;
//   * a real `personalauth.Device` tonic server — the GENERATED `DeviceServer`,
//     the same trait `platform/services/personalauth` implements — on its own
//     real port, reached by the gateway through the real `Resolver`;
//   * real signature verification of the device proof inside that backend,
//     against the JWK the registration request carried, and real ECDSA signing
//     and verification of the minted token.
//
// Every call below is made with NO `authorization` header of any kind. That is
// the property under test: `personalauth.Device`'s two RPCs are `NoAuth` routes
// (unit 6 pins that in the generated table), and a device on first launch has
// no token to present.
//
// WHAT IS STOOD IN FOR, AND WHY IT IS NOT THE GATEWAY HOP. `PersonalauthStandIn`
// plays personalauth AND the kernel behind it, collapsed into one backend: it
// stores the registered credential and mints the `/people/<pid>` token itself.
// Neither service can run in this test — personalauth is a separate crate that
// gateway must not depend on, and kernel is a JVM service needing state and opa
// — and `optional_services.personalauth: true` is not schedulable in the mock
// cluster until personalauth's image is published, so there is no live pod to
// drive either. The hop this file exists to prove is the one it does not stand
// in for: device → gateway → the `personalauth.Device` wire contract. The two
// hops beyond it are covered where they are real — `personalauth/src/device.rs`
// pins the broker's forward to `kernel.Mint`, and kernel's `DevicePrincipalTest`
// pins register-then-mint against the real mint arm.
//
// ONE CONSEQUENCE, STATED RATHER THAN ASSERTED PAST. Unit 7's spec asks for
// `azp = spiffe://<td>/system/services/personalauth`, and so does
// `personalauth.proto`'s file header. That is not what this stack stamps.
// Kernel sets `azp` to the Delegate's NAME and nothing else
// (`IdentityServiceImpl.java:783`, `newToken.setAzp(delegate.getName())`), and
// the operator names a service's delegate after the service
// (`operator/pkg/bootstrap/example.go:668`, `Name: svc`), which the mock's
// generated `services/kernel.yaml:94` shows as the literal `personalauth`.
// `DELEGATE_NAME` below is therefore the bare name, and the decision doc for
// this unit records the mismatch. No SPIFFE-shaped `azp` exists anywhere in the
// tree to assert.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use tokio::net::TcpListener;
use tokio_stream::wrappers::TcpListenerStream;

use gateway_grpcserver::authorizer::JwkCache;
use gateway_jwk::jwk::ImmutableJwk;
use gateway_key::{base64_utils, keys};
use gateway_servicemanager::auth::proto_jwk_to_lib;
use gateway_servicemanager::SpiffeServerCertVerifier;
use gateway_token::token::Token;
use gateway_x509::x509::{ImmutableCertChain, X509KeyUsage};

use gateway_model::types::services::kernel::kernel as kernel_pb;
use gateway_model::types::services::personalauth::personalauth as personalauth_pb;
use gateway_model::types::sys::jwk::jwk::{Jwk as ProtoJwk, JwkUseType};
use gateway_model::types::sys::key::key::KeyType;
use gateway_model::types::sys::token::token::Token as TokenProto;
use gateway_model::types::sys::tokenrequest::tokenrequest::TokenMintResponse;
use kernel_pb::mint_client::MintClient;
use personalauth_pb::device_client::DeviceClient;
use personalauth_pb::device_server::{Device, DeviceServer};

use crate::auth::GatewayAuth;
use crate::health::{HealthWatcher, ServiceEndpoint};
use crate::proxy_grpc::{self, ProxyState};
use crate::resolver::Resolver;

const TRUST_DOMAIN: &str = "personalauth-e2e.test";
/// The `service_id` the generated route for `/personalauth.Device/*` names, and
/// therefore the key the gateway looks up in its endpoint table.
const BROKER_SERVICE: &str = "personalauth";
/// The Delegate name kernel stamps into `azp` — see the file header.
const DELEGATE_NAME: &str = "personalauth";

// ── the backend ─────────────────────────────────────────────────────────────

/// A registered device credential: kernel's `PersonalPrincipal` + the one
/// `PersonalCredential` on it, reduced to what the login path reads.
struct Credential {
    principal_id: String,
    public_key: ProtoJwk,
}

/// Stands in for a deployed `personalauth` with kernel behind it.
///
/// The credential lookup follows kernel's `verifyDeviceProof`
/// (`IdentityServiceImpl.java:687`) exactly, because that is what makes the
/// register-then-mint ordering real rather than decorative: the proof's `kid` is
/// the only pre-verification handle, it selects the stored credential, and the
/// signature is checked against the key on THAT row.
struct PersonalauthStandIn {
    /// The key "kernel" signs minted tokens with.
    signing_key: keys::ImmutableKey,
    /// kid → credential, keyed exactly as kernel keys it.
    credentials: Mutex<HashMap<String, Credential>>,
}

impl PersonalauthStandIn {
    fn new(signing_key: keys::ImmutableKey) -> Self {
        Self {
            signing_key,
            credentials: Mutex::new(HashMap::new()),
        }
    }

    /// Kernel's single refusal for every device-proof failure — malformed,
    /// unknown kid, bad signature. One message, so the path is not an oracle
    /// for which credentials exist.
    fn proof_refused() -> tonic::Status {
        tonic::Status::permission_denied("device proof refused")
    }

    fn verify_proof(proof_token: &str, public_key: &ProtoJwk) -> Result<(), tonic::Status> {
        let parsed = Token::parse(proof_token).map_err(|_| Self::proof_refused())?;
        let jwk = ImmutableJwk::new(proto_jwk_to_lib(public_key)).map_err(|_| Self::proof_refused())?;
        parsed.verify(&jwk).map_err(|_| Self::proof_refused())
    }

    /// The `/people/<pid>` token kernel's DEVICE arm mints
    /// (`IdentityServiceImpl.java:655-666`, then `mintUserTokenInternal`).
    fn mint(&self, principal_id: &str, token_use: &str, lifetime: i64) -> TokenProto {
        let namespace = format!("/people/{principal_id}");
        let subject = gateway_spiffe::spiffe::user_spiffe_id(TRUST_DOMAIN, &namespace, principal_id)
            .expect("user spiffe id");

        let mut token = Token::new();
        token.set_kid(self.signing_key.id()).expect("kid");
        token.set_alg(self.signing_key.alg()).expect("alg");
        token.set_issuer("kernel").expect("iss");
        token.set_subject(subject).expect("sub");
        token.set_audience("kernel").expect("aud");
        token.set_namespace(&namespace).expect("namespace");
        token.set_issued_at(unix_now()).expect("iat");
        token.set_expiration(unix_now() + lifetime).expect("exp");
        token.set_sub_type("user").expect("sub_type");
        token.set_token_use(token_use).expect("token_use");
        // The one claim the DEVICE arm synthesizes rather than relaying.
        token
            .set_custom_field("principal_id", serde_json::Value::String(principal_id.to_string()))
            .expect("principal_id");
        // The provenance the broker exists to create.
        token.set_azp(DELEGATE_NAME).expect("azp");
        token.sign(&self.signing_key).expect("sign");

        // Only the compact serialization is filled: it IS the whole token, and
        // the assertions parse and verify it rather than reading a map the
        // backend could have written anything into.
        TokenProto {
            base64: token.base64().expect("base64").to_string(),
            signature: token.signature().expect("signature").to_string(),
            ..Default::default()
        }
    }
}

#[tonic::async_trait]
impl Device for PersonalauthStandIn {
    async fn create_device_principal(
        &self,
        request: tonic::Request<personalauth_pb::CreateDevicePrincipalRequest>,
    ) -> Result<tonic::Response<personalauth_pb::CreateDevicePrincipalResponse>, tonic::Status> {
        let req = request.into_inner();
        let public_key = req
            .public_key
            .ok_or_else(|| tonic::Status::invalid_argument("public_key is required"))?;
        if public_key.kid.is_empty() {
            return Err(tonic::Status::invalid_argument("public_key.kid is required"));
        }

        // Registration is self-attesting about the KEY: the proof must verify
        // against the public key in the same request. A proxy hop that mangled
        // either field fails here rather than silently registering something
        // the device does not hold.
        Self::verify_proof(&req.proof_token, &public_key)?;

        let principal_id = uuid::Uuid::new_v4().to_string();
        self.credentials.lock().expect("credentials").insert(
            public_key.kid.clone(),
            Credential {
                principal_id: principal_id.clone(),
                public_key,
            },
        );

        Ok(tonic::Response::new(
            personalauth_pb::CreateDevicePrincipalResponse {
                principal_id,
                trace_id: req.trace_id,
                ..Default::default()
            },
        ))
    }

    async fn mint_device_tokens(
        &self,
        request: tonic::Request<personalauth_pb::DeviceLoginRequest>,
    ) -> Result<tonic::Response<TokenMintResponse>, tonic::Status> {
        let req = request.into_inner();

        let parsed = Token::parse(&req.proof_token).map_err(|_| Self::proof_refused())?;
        let kid = parsed.kid().ok_or_else(Self::proof_refused)?.to_string();

        let principal_id = {
            let credentials = self.credentials.lock().expect("credentials");
            let credential = credentials.get(&kid).ok_or_else(Self::proof_refused)?;
            Self::verify_proof(&req.proof_token, &credential.public_key)?;
            credential.principal_id.clone()
        };

        Ok(tonic::Response::new(TokenMintResponse {
            access_token: Some(self.mint(&principal_id, "access", 300)),
            refresh_token: Some(self.mint(&principal_id, "refresh", 3600)),
            trace_id: req.trace_id,
            ..Default::default()
        }))
    }
}

// ── the device side ─────────────────────────────────────────────────────────

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_secs() as i64
}

/// The public half of a device key, in the proto shape the registration request
/// carries. `kid` is what kernel stores the credential under and what the
/// proof's header names.
fn proto_jwk_for(key: &keys::ImmutableKey) -> ProtoJwk {
    let (x, y) = match key.public_key() {
        keys::PublicKey::EcP256(ec) => {
            let point = ec.to_encoded_point(false);
            (
                base64_utils::encode_base64_url(point.x().expect("x")),
                base64_utils::encode_base64_url(point.y().expect("y")),
            )
        }
        _ => panic!("this test registers a P-256 device key"),
    };
    ProtoJwk {
        kty: KeyType::Ec as i32,
        alg: key.alg().to_string(),
        kid: key.id().to_string(),
        r#use: JwkUseType::Sig as i32,
        crv: "P-256".to_string(),
        x,
        y,
        // Required by the generated validation on `Jwk` (`created` must be a
        // real epoch second), which the generated server wrapper runs before
        // the handler sees the request.
        created: unix_now(),
        ..Default::default()
    }
}

/// The device's proof of possession: a JWT signed by the device key itself,
/// naming that key in `kid`. It asserts nothing about who the holder is — that
/// is the point of the design (`personalauth.proto` header).
///
/// Assembled by hand rather than through the token chassis, for the two reasons
/// kernel's own `DevicePrincipalTest.DeviceKey.proof()` records: a device is an
/// iOS/Android app emitting whatever a normal JWT library emits, and the chassis
/// cannot produce this token at all — `Token::sign` refuses a token with no
/// `namespace` claim (`chassis/token/src/token.rs:640-643`), and a first-launch
/// device has no namespace and never will. `Token::verify`, which is what the
/// backend runs on it, requires only `iss`, `kid`, `exp` and a signature.
fn device_proof(key: &keys::ImmutableKey) -> String {
    let now = unix_now();
    let header = format!(
        r#"{{"alg":"{}","typ":"JWT","kid":"{}"}}"#,
        key.alg(),
        key.id()
    );
    let payload = format!(
        r#"{{"iss":"{kid}","sub":"{kid}","aud":"kernel","iat":{now},"exp":{exp},"jti":"{jti}"}}"#,
        kid = key.id(),
        now = now,
        exp = now + 300,
        jti = uuid::Uuid::new_v4(),
    );
    let signing_input = format!(
        "{}.{}",
        base64_utils::encode_base64_url(header.as_bytes()),
        base64_utils::encode_base64_url(payload.as_bytes())
    );
    let signature = key.sign(signing_input.as_bytes()).expect("sign proof");
    format!(
        "{}.{}",
        signing_input,
        base64_utils::encode_base64_url(&signature)
    )
}

/// The verifying half of the minted token's signing key, so the test checks the
/// signature rather than trusting the bytes that came back.
fn jwk_for(key: &keys::ImmutableKey) -> ImmutableJwk {
    ImmutableJwk::new(proto_jwk_to_lib(&proto_jwk_for(key))).expect("jwk")
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

async fn spawn_broker(backend: PersonalauthStandIn) -> ServiceEndpoint {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind broker");
    let addr = listener.local_addr().expect("broker addr");
    tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(DeviceServer::new(backend))
            .serve_with_incoming(TcpListenerStream::new(listener))
            .await
            .expect("broker serve");
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

/// A gateway with `personalauth` in its endpoint table and nothing else. The
/// JWK cache is empty on purpose: nothing on this path presents a token, so a
/// call that somehow reached the auth check would fail loudly rather than pass
/// by accident.
fn proxy_state(broker: ServiceEndpoint) -> Arc<ProxyState> {
    let mut endpoints = HashMap::new();
    endpoints.insert(BROKER_SERVICE.to_string(), vec![broker]);
    Arc::new(ProxyState {
        resolver: Arc::new(Resolver::plaintext_backends(
            HealthWatcher::seeded(endpoints),
            unused_verifier(),
        )),
        auth: Arc::new(GatewayAuth::new(Arc::new(JwkCache::seeded(vec![])), false)),
        tenant_owned: Arc::new(Default::default()),
        trace_publisher: Arc::new(|_| {}),
        trace_round: Box::new(Default::default),
    })
}

// ── the runs ────────────────────────────────────────────────────────────────

/// Unit 7's first invariant: a fresh key registers and logs in through the
/// gateway, with no token at any point, and the token that comes back is a
/// `/people/<pid>` token carrying the broker's `azp`.
///
/// The mint half is asserted in BOTH directions in one run — the key that
/// registered mints, a second fresh key that did not is refused — so a backend
/// that answered every login identically could not pass.
#[tokio::test]
async fn a_fresh_device_key_registers_and_mints_through_the_gateway() {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let kernel_signing_key = keys::generate_ec_p256_key().expect("kernel signing key");
    let kernel_jwk = jwk_for(&kernel_signing_key);
    let broker = spawn_broker(PersonalauthStandIn::new(kernel_signing_key)).await;
    let gateway_uri = spawn_gateway(proxy_state(broker)).await;

    // A key that has never existed before this line.
    let device_key = keys::generate_ec_p256_key().expect("device key");

    // ── register ── no authorization header, by construction: the device has
    // no token, and `/personalauth.Device/CreateDevicePrincipal` is a NoAuth
    // route in the generated table.
    let mut client = DeviceClient::new(channel(&gateway_uri).await);
    let registered = client
        .create_device_principal(personalauth_pb::CreateDevicePrincipalRequest {
            proof_token: device_proof(&device_key),
            public_key: Some(proto_jwk_for(&device_key)),
            label: "e2e-device".to_string(),
            platform_synced: false,
            ..Default::default()
        })
        .await
        .unwrap_or_else(|e| panic!("registration must reach personalauth unauthenticated: {e:?}"))
        .into_inner();

    assert!(
        !registered.principal_id.is_empty(),
        "registration must return the principal id kernel allocated"
    );

    // ── log in ── same device key, same absence of a token.
    let minted = client
        .mint_device_tokens(personalauth_pb::DeviceLoginRequest {
            proof_token: device_proof(&device_key),
            offline_access: true,
            ..Default::default()
        })
        .await
        .unwrap_or_else(|e| panic!("device login must reach personalauth unauthenticated: {e:?}"))
        .into_inner();

    let access = Token::parse(
        &minted
            .access_token
            .as_ref()
            .expect("a device login must return an access token")
            .base64,
    )
    .expect("the minted access token must parse");
    access
        .verify(&kernel_jwk)
        .expect("the minted access token must verify against the minting key");

    let namespace = format!("/people/{}", registered.principal_id);
    assert_eq!(
        access.namespace(),
        Some(namespace.as_str()),
        "the login must mint into the principal registration just created, not some other subtree"
    );
    assert_eq!(
        access.subject(),
        Some(
            gateway_spiffe::spiffe::user_spiffe_id(
                TRUST_DOMAIN,
                &namespace,
                &registered.principal_id
            )
            .expect("user spiffe id")
            .as_str()
        ),
        "the token must name the person the fresh key registered as"
    );
    assert_eq!(access.sub_type(), Some("user"));

    // Unit 7's second invariant. See the file header for what `azp` actually
    // carries in this stack, and what it does not.
    assert_eq!(
        access.azp(),
        Some(DELEGATE_NAME),
        "a device login must be attributable to the personalauth broker"
    );

    // A second fresh key, never registered, presenting a well-formed proof of
    // its own. Registration is a precondition, not a formality.
    let stranger = keys::generate_ec_p256_key().expect("stranger key");
    let refused = client
        .mint_device_tokens(personalauth_pb::DeviceLoginRequest {
            proof_token: device_proof(&stranger),
            ..Default::default()
        })
        .await
        .expect_err("an unregistered device key must not mint");
    assert_eq!(
        refused.code(),
        tonic::Code::PermissionDenied,
        "an unregistered key must be refused, not minted for: {refused:?}"
    );
}

/// Unit 7's third invariant, and the reason the broker is not decorative
/// (`decision-goalB-q1-broker-service-design.md` §6): registration is reachable
/// ONLY through personalauth. `/kernel.Mint/CreatePersonalPrincipal` used to be
/// a NoAuth proxy route; unit 5 removed the no-auth flag so tacplus emits no
/// route, and `proxy_grpc`'s deny-by-default then answers `NOT_FOUND`.
///
/// `proxy_grpc::tests::kernel_create_personal_principal_has_no_proxy_route`
/// asserts the route's absence from the table; this asserts what a real client
/// on a real socket actually gets, which is the thing that matters to a device.
/// The `grpc-message` is asserted too: `NOT_FOUND` from the route table and a
/// backend that happens to be unreachable are different failures, and only the
/// first is the ruling being enforced.
#[tokio::test]
async fn a_direct_kernel_registration_is_not_found_through_the_gateway() {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let kernel_signing_key = keys::generate_ec_p256_key().expect("kernel signing key");
    let broker = spawn_broker(PersonalauthStandIn::new(kernel_signing_key)).await;
    let gateway_uri = spawn_gateway(proxy_state(broker)).await;

    let device_key = keys::generate_ec_p256_key().expect("device key");
    let request = kernel_pb::CreatePersonalPrincipalRequest {
        proof_token: device_proof(&device_key),
        public_key: Some(proto_jwk_for(&device_key)),
        label: "e2e-device".to_string(),
        ..Default::default()
    };

    let mut kernel = MintClient::new(channel(&gateway_uri).await);
    let refused = kernel
        .create_personal_principal(request)
        .await
        .expect_err("kernel registration must not be reachable through the gateway");

    assert_eq!(
        refused.code(),
        tonic::Code::NotFound,
        "a device must not be able to skip the broker: {refused:?}"
    );
    assert_eq!(
        refused.message(),
        "unknown gRPC method",
        "the refusal must come from the route table's deny-by-default, not from a dial failure"
    );

    // The control, and what keeps the assertion above from being vacuous. This
    // gateway has no `kernel` endpoint at all, so "kernel is unreachable" and
    // "this kernel method is not routed" would look alike if only the code were
    // read. `/kernel.Mint/MintClientToken` is a sibling method on the SAME
    // service that §6 deliberately left externally routed (QUESTION B: it
    // carries its credential in the body, has no bearer to present, and
    // schematicctl and CI depend on it). It gets as far as the dial and fails
    // there — a different failure, from a later stage.
    let sibling = MintClient::new(channel(&gateway_uri).await)
        .mint_client_token(gateway_model::types::sys::tokenrequest::tokenrequest::MintClientTokenRequest::default())
        .await
        .expect_err("no kernel backend is registered, so the dial must fail");
    assert_eq!(
        sibling.code(),
        tonic::Code::Unavailable,
        "a routed kernel method must reach the dial and fail there, proving the NOT_FOUND above \
         is the route table refusing the path rather than kernel being absent: {sibling:?}"
    );
}
