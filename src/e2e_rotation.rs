// End-to-end proof, over real sockets, that a C2S stream rotated through the
// gateway (#26, tacplus#322's make-before-break) stays on the backend instance
// that issued its session, across several token lifetimes, with nothing lost,
// duplicated or reordered; and that only the session's own subject may rotate
// it.
//
// What is real here:
//
//   * the real `proxy_grpc::handle`, resolving the sibling path
//     `/oauth.SessionRotating/BrokerSession` to the generated route of
//     `oauth.Session/BrokerSession`, and validating each payload as its
//     request type with the generated validators. The one thing changed is
//     the route's policy: the generated route is auth-disabled (as every C2S
//     stream of the fleet is today), and nothing rotates onto one of those,
//     so the test makes it AnyUser;
//   * the real `GatewayAuth` over a real `JwkCache`, verifying real
//     ECDSA-signed JWTs that expire within seconds;
//   * the real `Resolver` and `HealthWatcher`, with two instances of the
//     route's service; between the opening leg and the rotations the table is
//     reordered, so a fresh pick would land on the other instance;
//   * a real tonic gRPC client on one HTTP/2 connection to the gateway, which
//     carries the session across legs as the generated client does: open a
//     new leg with a new token, wait for its echo, send `last` on the old one
//     and drain it to the server's `last`.
//
// What is stood in for: the backend's generated `Rotating` sibling. Each
// instance issues ids of its own and refuses a leg that names an id it did not
// issue, so a misrouted rotation fails loudly; it records each payload it
// receives and echoes it. The gateway→backend hop is plaintext h2c
// (`Resolver::plaintext_backends`).

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

use axum::body::Body;
use bytes::Bytes;
use http_body::Frame;
use prost::Message;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::CertificateDer;
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio::time::{sleep, timeout, Duration};
use tokio_stream::wrappers::ReceiverStream;

use gateway_grpcserver::authorizer::JwkCache;
use gateway_jwk::jwk::{ImmutableJwk, Jwk};
use gateway_key::{base64_utils, keys};
use gateway_model::s2sm::rest_dispatch::{AuthPolicy, RouteInfo};
use gateway_model::types::services::oauth::oauth as oauth_pb;
use gateway_servicemanager::SpiffeServerCertVerifier;
use gateway_token::token::Token;
use gateway_x509::x509::{ImmutableCertChain, X509KeyUsage};

use crate::auth::GatewayAuth;
use crate::health::{HealthWatcher, ServiceEndpoint};
use crate::proxy_grpc::{self, ProxyState};
use crate::resolver::Resolver;
use crate::rotation::{Envelope, Frames};

const TRUST_DOMAIN: &str = "rotation-e2e.test";

/// oauth's `Session.BrokerSession`, the fleet's client-streaming C2S method.
const PLAIN_PATH: &str = "/oauth.Session/BrokerSession";
/// `SessionRequest.session_id`: 32 random bytes, hex-encoded.
const BROKER_SESSION_ID: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

/// The n-th message of the stream: distinct by its trace_id, which is what
/// the backend must receive (looper#51).
fn payload(n: usize) -> Vec<u8> {
    oauth_pb::SessionRequest {
        msg: Some(oauth_pb::session_request::Msg::SessionId(
            BROKER_SESSION_ID.to_string(),
        )),
        trace_id: format!("{:032x}", n + 1),
        ..Default::default()
    }
    .encode_to_vec()
}

// ── the route ───────────────────────────────────────────────────────────────

/// `BrokerSession`'s generated route, as an authenticated method: the
/// generated one is auth-disabled, and nothing rotates onto those (no token,
/// no subject). Everything else, the payload's validation included, is the
/// generated route's.
fn route_under_test() -> &'static RouteInfo {
    let generated = gateway_model::s2sm::rest_dispatch::ROUTES
        .iter()
        .find(|r| r.grpc_path == PLAIN_PATH)
        .expect("the generated ROUTES table must route oauth.Session/BrokerSession");
    assert!(generated.client_streaming, "BrokerSession is a client stream");
    gateway_model::s2sm::proxy_dispatch::validate_request(PLAIN_PATH, &payload(0))
        .expect("the test's payloads are valid SessionRequests");
    crate::rotation::stand_in(RouteInfo {
        auth_policy: AuthPolicy::AnyUser,
        ..*generated
    })
}

fn sibling_path(route: &RouteInfo) -> String {
    let (service, method) = route.grpc_path[1..].split_once('/').expect("a gRPC path");
    format!("/{service}Rotating/{method}")
}

// ── tokens ──────────────────────────────────────────────────────────────────

fn jwk_for(key: &keys::ImmutableKey) -> ImmutableJwk {
    let keys::PublicKey::EcP256(ec) = key.public_key() else {
        panic!("this test signs with P-256");
    };
    ImmutableJwk::new(Jwk {
        kty: "EC".to_string(),
        alg: Some(key.alg().to_string()),
        kid: key.id().to_string(),
        key_use: Some("sig".to_string()),
        n: None,
        e: None,
        crv: Some("P-256".to_string()),
        x: Some(base64_utils::encode_base64_url(ec.x())),
        y: Some(base64_utils::encode_base64_url(ec.y())),
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

/// A user token for `audience` naming `sub`, expiring `lifetime` seconds from
/// now.
fn user_token(key: &keys::ImmutableKey, audience: &str, sub: &str, lifetime: i64) -> String {
    let mut token = Token::new();
    token.set_kid(key.id()).expect("kid");
    token.set_alg(key.alg()).expect("alg");
    token.set_issuer("rotation-test").expect("iss");
    token.set_subject(sub).expect("sub");
    token.set_sub_type("user").expect("sub_type");
    token.set_audience(audience).expect("aud");
    token.set_namespace("/tenants/acme").expect("namespace");
    token
        .set_custom_field("tid", serde_json::json!("t-acme"))
        .expect("tid");
    token.set_expiration(unix_now() + lifetime).expect("exp");
    token.sign(key).expect("sign");
    format!("Bearer {}", token.base64().expect("base64"))
}

// ── the backend instances ───────────────────────────────────────────────────

/// What every instance saw, in the order it saw it.
#[derive(Default)]
pub(crate) struct Log {
    /// (instance, payload) of every message envelope received.
    pub(crate) received: Mutex<Vec<(&'static str, Vec<u8>)>>,
    /// (instance, session id) of every leg admitted.
    legs: Mutex<Vec<(&'static str, String)>>,
}

/// One instance of the backend's `Rotating` sibling, as far as the gateway
/// can tell: it issues session ids of its own, admits a rotation only onto
/// one of them, echoes each message, and answers `last` with its own `last`.
#[derive(Clone)]
pub(crate) struct Instance {
    name: &'static str,
    serves_sibling: bool,
    issued: Arc<Mutex<HashSet<String>>>,
    log: Arc<Log>,
}

fn data(envelope: Envelope) -> Result<Frame<Bytes>, std::convert::Infallible> {
    Ok(Frame::data(Bytes::from(proxy_grpc::frame_grpc(
        &envelope.encode_to_vec(),
    ))))
}

fn trailers(code: tonic::Code) -> Result<Frame<Bytes>, std::convert::Infallible> {
    let mut trailers = http::HeaderMap::new();
    trailers.insert("grpc-status", http::HeaderValue::from(code as i32));
    Ok(Frame::trailers(trailers))
}

impl Instance {
    pub(crate) async fn spawn(name: &'static str, serves_sibling: bool, log: Arc<Log>) -> ServiceEndpoint {
        let instance = Instance {
            name,
            serves_sibling,
            issued: Default::default(),
            log,
        };
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind backend");
        let addr = listener.local_addr().expect("backend addr");
        let app = axum::Router::new().fallback(axum::routing::any(
            move |req: http::Request<Body>| {
                let instance = instance.clone();
                async move { instance.leg(req) }
            },
        ));
        tokio::spawn(async move {
            axum::serve(listener, app).await.expect("backend serve");
        });
        ServiceEndpoint {
            host: addr.ip().to_string(),
            port: addr.port() as i32,
        }
    }

    fn leg(self, req: http::Request<Body>) -> http::Response<Body> {
        if !self.serves_sibling {
            // A server generated without the sibling: tonic's answer to an
            // unknown service.
            return http::Response::builder()
                .header("content-type", "application/grpc")
                .header("grpc-status", (tonic::Code::Unimplemented as i32).to_string())
                .body(Body::empty())
                .expect("response");
        }
        let (tx, rx) = mpsc::channel(16);
        tokio::spawn(self.run(Frames::new(req.into_body()), tx));
        http::Response::builder()
            .header("content-type", "application/grpc")
            .body(Body::new(http_body_util::StreamBody::new(ReceiverStream::new(rx))))
            .expect("response")
    }

    async fn run(
        self,
        mut frames: Frames,
        tx: mpsc::Sender<Result<Frame<Bytes>, std::convert::Infallible>>,
    ) {
        let decode = |frame: Bytes| Envelope::decode(&frame[5..]).expect("an envelope");
        let Ok(Some(first)) = frames.next().await else {
            return;
        };
        let first = decode(first);
        let id = if first.session_id.is_empty() {
            let mut issued = self.issued.lock().unwrap();
            let id = format!("{}-session-{}", self.name, issued.len() + 1);
            issued.insert(id.clone());
            id
        } else if self.issued.lock().unwrap().contains(&first.session_id) {
            first.session_id
        } else {
            let _ = tx.send(trailers(tonic::Code::PermissionDenied)).await;
            return;
        };
        self.log.legs.lock().unwrap().push((self.name, id.clone()));
        let _ = tx
            .send(data(Envelope {
                session_id: id,
                ..Default::default()
            }))
            .await;
        while let Ok(Some(frame)) = frames.next().await {
            let envelope = decode(frame);
            if envelope.last {
                let _ = tx
                    .send(data(Envelope {
                        last: true,
                        ..Default::default()
                    }))
                    .await;
                let _ = tx.send(trailers(tonic::Code::Ok)).await;
                return;
            }
            if envelope.fin {
                let _ = tx.send(trailers(tonic::Code::Ok)).await;
                return;
            }
            self.log
                .received
                .lock()
                .unwrap()
                .push((self.name, envelope.payload.clone()));
            let _ = tx
                .send(data(Envelope {
                    payload: envelope.payload,
                    ..Default::default()
                }))
                .await;
        }
    }
}

// ── the client ──────────────────────────────────────────────────────────────

/// `rotation.Envelope` both ways, for a raw tonic client.
#[derive(Clone, Default)]
struct EnvelopeCodec;

impl tonic::codec::Codec for EnvelopeCodec {
    type Encode = Envelope;
    type Decode = Envelope;
    type Encoder = EnvelopeCodec;
    type Decoder = EnvelopeCodec;

    fn encoder(&mut self) -> Self::Encoder {
        EnvelopeCodec
    }

    fn decoder(&mut self) -> Self::Decoder {
        EnvelopeCodec
    }
}

impl tonic::codec::Encoder for EnvelopeCodec {
    type Item = Envelope;
    type Error = tonic::Status;

    fn encode(
        &mut self,
        item: Envelope,
        dst: &mut tonic::codec::EncodeBuf<'_>,
    ) -> Result<(), tonic::Status> {
        item.encode(dst)
            .map_err(|e| tonic::Status::internal(e.to_string()))
    }
}

impl tonic::codec::Decoder for EnvelopeCodec {
    type Item = Envelope;
    type Error = tonic::Status;

    fn decode(
        &mut self,
        src: &mut tonic::codec::DecodeBuf<'_>,
    ) -> Result<Option<Envelope>, tonic::Status> {
        Envelope::decode(src)
            .map(Some)
            .map_err(|e| tonic::Status::internal(e.to_string()))
    }
}

/// One leg: what the client sends on it, and what it receives.
pub(crate) struct ClientLeg {
    tx: mpsc::Sender<Envelope>,
    rx: tonic::Streaming<Envelope>,
}

/// Opens a leg of `path` with `token` whose first envelope names `session_id`
/// (empty for a new session).
pub(crate) async fn open_leg(
    channel: &tonic::transport::Channel,
    path: &str,
    token: Option<&str>,
    session_id: &str,
) -> Result<ClientLeg, tonic::Status> {
    let (tx, rx) = mpsc::channel(16);
    tx.send(Envelope {
        session_id: session_id.to_string(),
        ..Default::default()
    })
    .await
    .expect("queue the first envelope");
    let mut request = tonic::Request::new(ReceiverStream::new(rx));
    if let Some(token) = token {
        request
            .metadata_mut()
            .insert("authorization", token.parse().expect("metadata"));
    }
    let mut grpc = tonic::client::Grpc::new(channel.clone());
    grpc.ready().await.expect("the gateway connection is ready");
    let rx = grpc
        .streaming(
            request,
            http::uri::PathAndQuery::try_from(path).expect("path"),
            EnvelopeCodec,
        )
        .await?
        .into_inner();
    Ok(ClientLeg { tx, rx })
}

impl ClientLeg {
    pub(crate) async fn send(&self, envelope: Envelope) {
        self.tx.send(envelope).await.expect("the leg takes it");
    }

    pub(crate) async fn next(&mut self) -> Result<Option<Envelope>, tonic::Status> {
        timeout(Duration::from_secs(10), self.rx.message())
            .await
            .expect("the leg answers in time")
    }

    /// The leg's first envelope from the server: the session id.
    pub(crate) async fn session_id(&mut self) -> String {
        let first = self
            .next()
            .await
            .expect("the leg is admitted")
            .expect("the server's first envelope");
        assert!(first.payload.is_empty() && !first.last, "{first:?}");
        assert!(!first.session_id.is_empty(), "the server names the session");
        first.session_id
    }
}

// ── wiring ──────────────────────────────────────────────────────────────────

fn unused_verifier() -> Arc<SpiffeServerCertVerifier> {
    let key = keys::generate_ec_p256_key().expect("throwaway key");
    let cert = ImmutableCertChain::for_self_signing(key)
        .self_sign("unused", unix_now() + 3600, X509KeyUsage::CertSign, &[])
        .expect("throwaway cert");
    let mut roots = rustls::RootCertStore::empty();
    for der in CertificateDer::pem_slice_iter(cert.pem_bytes()) {
        roots.add(der.expect("der")).expect("add root");
    }
    SpiffeServerCertVerifier::new(TRUST_DOMAIN, roots).expect("verifier")
}

struct Fixture {
    proxy: Arc<ProxyState>,
    channel: tonic::transport::Channel,
    key: keys::ImmutableKey,
    route: &'static RouteInfo,
    path: String,
    log: Arc<Log>,
    a: ServiceEndpoint,
    b: ServiceEndpoint,
}

/// Two instances of the route's service, A then B in the endpoint table, and
/// a gateway in front of them.
async fn fixture(serves_sibling: bool) -> Fixture {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let route = route_under_test();
    let key = keys::generate_ec_p256_key().expect("signing key");
    let log = Arc::new(Log::default());
    let a = Instance::spawn("A", serves_sibling, Arc::clone(&log)).await;
    let b = Instance::spawn("B", serves_sibling, Arc::clone(&log)).await;
    let mut endpoints = HashMap::new();
    endpoints.insert(route.service_id.to_string(), vec![a.clone(), b.clone()]);
    let proxy = Arc::new(ProxyState {
        resolver: Arc::new(Resolver::plaintext_backends(
            HealthWatcher::seeded(endpoints),
            unused_verifier(),
        )),
        auth: Arc::new(GatewayAuth::new(
            Arc::new(JwkCache::seeded(vec![jwk_for(&key)])),
            false,
        )),
        trace_publisher: Arc::new(|_| {}),
        trace_round: Box::new(Default::default),
        sessions: Default::default(),
    });

    let gateway = Arc::clone(&proxy);
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind gateway");
    let addr = listener.local_addr().expect("gateway addr");
    let app = axum::Router::new().fallback(axum::routing::any(
        move |req: http::Request<Body>| {
            let gateway = Arc::clone(&gateway);
            async move { proxy_grpc::handle(&gateway, req).await }
        },
    ));
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("gateway serve");
    });
    let channel = tonic::transport::Endpoint::from_shared(format!("http://{addr}"))
        .expect("endpoint")
        .connect()
        .await
        .expect("connect to the gateway");

    Fixture {
        proxy,
        channel,
        key,
        route,
        path: sibling_path(route),
        log,
        a,
        b,
    }
}

impl Fixture {
    fn token(&self, sub: &str, lifetime: i64) -> String {
        user_token(&self.key, self.route.service_id, sub, lifetime)
    }

    /// From now on a fresh pick lands on B.
    fn prefer_b(&self) {
        self.proxy.resolver.health().set_endpoints(
            self.route.service_id,
            vec![self.b.clone(), self.a.clone()],
        );
    }

    async fn sessions_drain(&self) {
        for _ in 0..50 {
            if self.proxy.sessions.len() == 0 {
                return;
            }
            sleep(Duration::from_millis(100)).await;
        }
        panic!("the gateway still holds {} session(s)", self.proxy.sessions.len());
    }
}

fn message(n: usize) -> Envelope {
    Envelope {
        payload: payload(n),
        ..Default::default()
    }
}

// ── the runs ────────────────────────────────────────────────────────────────

/// The acceptance run: one logical stream over four legs, each opened with a
/// token living at most 3 s, rotated every 1.5 s, so it outlives its first
/// tokens. Every leg reaches instance A, which issued the session, though a
/// fresh pick lands on B from the first rotation on; every message arrives
/// once, in order, carrying its trace_id, and every echo comes back the same.
#[tokio::test]
async fn a_rotated_stream_stays_on_its_instance_across_token_lifetimes() {
    const LEGS: usize = 4;
    const PER_LEG: usize = 5;
    let f = fixture(true).await;
    eprintln!("rotating {} as {}", f.route.grpc_path, f.path);

    let first_token = f.token("alice", 3);
    let first_exp = unix_now() + 3;
    let mut leg = open_leg(&f.channel, &f.path, Some(&first_token), "")
        .await
        .expect("the opening leg is admitted");
    let session = leg.session_id().await;
    f.prefer_b();

    let mut sent = 0;
    let mut echoed = Vec::new();
    for rotation in 0..LEGS {
        for _ in 0..PER_LEG {
            leg.send(message(sent)).await;
            sent += 1;
        }
        if rotation + 1 == LEGS {
            break;
        }
        sleep(Duration::from_millis(1500)).await;

        // Make before break: the new leg is admitted and echoes the session
        // before the old one is cut over.
        let mut next = open_leg(&f.channel, &f.path, Some(&f.token("alice", 3)), &session)
            .await
            .expect("the rotation is admitted");
        assert_eq!(next.session_id().await, session, "the new leg joins the session");
        leg.send(Envelope {
            last: true,
            ..Default::default()
        })
        .await;
        loop {
            match leg.next().await.expect("the old leg ends OK") {
                Some(e) if e.last => break,
                Some(e) => echoed.push(e.payload),
                None => panic!("the old leg ended without the server's last"),
            }
        }
        assert!(
            leg.next().await.expect("the old leg ends OK").is_none(),
            "nothing follows the server's last"
        );
        leg = next;
    }
    leg.send(Envelope {
        fin: true,
        ..Default::default()
    })
    .await;
    while let Some(e) = leg.next().await.expect("the stream ends OK") {
        echoed.push(e.payload);
    }

    assert!(
        unix_now() >= first_exp,
        "the stream must outlive its first token"
    );
    let expected: Vec<Vec<u8>> = (0..sent).map(payload).collect();
    let received = f.log.received.lock().unwrap().clone();
    assert_eq!(
        received.iter().map(|(_, p)| p.clone()).collect::<Vec<_>>(),
        expected,
        "every message (and its trace_id) reaches the backend once, in order"
    );
    assert!(
        received.iter().all(|(instance, _)| *instance == "A"),
        "every message reaches the instance that issued the session: {received:?}"
    );
    assert_eq!(
        *f.log.legs.lock().unwrap(),
        vec![("A", session.clone()); LEGS],
        "every leg reaches instance A"
    );
    assert_eq!(echoed, expected, "every echo comes back once, in order");
    f.sessions_drain().await;
}

/// The id alone authorizes nothing: another subject's token with a valid id
/// is refused with PERMISSION_DENIED and no description, and the backend never
/// sees the leg. A missing or expired token, or an unknown id, fail fast with
/// UNAUTHENTICATED. The session's own subject still rotates it after all that.
#[tokio::test]
async fn a_rotation_is_admitted_only_for_its_sessions_subject() {
    let f = fixture(true).await;
    let mut leg = open_leg(&f.channel, &f.path, Some(&f.token("alice", 60)), "")
        .await
        .expect("the opening leg is admitted");
    let session = leg.session_id().await;

    let refused = |result: Result<ClientLeg, tonic::Status>| match result {
        Ok(_) => panic!("the leg must be refused"),
        Err(status) => status,
    };

    let status = refused(open_leg(&f.channel, &f.path, Some(&f.token("bob", 60)), &session).await);
    assert_eq!(status.code(), tonic::Code::PermissionDenied, "{status:?}");
    assert_eq!(status.message(), "", "no reason text");

    for (what, token, id) in [
        ("no token", None, session.as_str()),
        ("an expired token", Some(f.token("alice", -10)), session.as_str()),
        ("an unknown session", Some(f.token("alice", 60)), "A-session-404"),
    ] {
        let status = timeout(
            Duration::from_secs(5),
            open_leg(&f.channel, &f.path, token.as_deref(), id),
        )
        .await
        .unwrap_or_else(|_| panic!("{what}: refused at once, never left to time out"));
        let status = refused(status);
        assert_eq!(status.code(), tonic::Code::Unauthenticated, "{what}: {status:?}");
    }
    assert_eq!(
        f.log.legs.lock().unwrap().len(),
        1,
        "no refused leg reaches the backend"
    );

    let mut next = open_leg(&f.channel, &f.path, Some(&f.token("alice", 60)), &session)
        .await
        .expect("the session's own subject rotates it");
    assert_eq!(next.session_id().await, session);
    drop(leg);
    drop(next);
}

/// A leg ends with UNAUTHENTICATED at its token's exp, at once, even with
/// nothing sent on it.
#[tokio::test]
async fn a_leg_ends_at_its_tokens_exp() {
    let f = fixture(true).await;
    let mut leg = open_leg(&f.channel, &f.path, Some(&f.token("alice", 2)), "")
        .await
        .expect("the opening leg is admitted");
    leg.session_id().await;

    let ended = timeout(Duration::from_secs(4), leg.rx.message())
        .await
        .expect("the leg ends by its token's exp");
    let status = ended.expect_err("an expired leg ends in an error");
    assert_eq!(status.code(), tonic::Code::Unauthenticated, "{status:?}");
    f.sessions_drain().await;
}

/// A backend generated without the sibling answers UNIMPLEMENTED, and the
/// client gets it as is: it falls back to the plain method.
#[tokio::test]
async fn unimplemented_from_a_backend_without_the_sibling_reaches_the_client() {
    let f = fixture(false).await;
    let status = match open_leg(&f.channel, &f.path, Some(&f.token("alice", 60)), "").await {
        Ok(_) => panic!("a backend without the sibling cannot serve it"),
        Err(status) => status,
    };
    assert_eq!(status.code(), tonic::Code::Unimplemented, "{status:?}");
    assert_eq!(f.proxy.sessions.len(), 0, "no session was issued");
}
