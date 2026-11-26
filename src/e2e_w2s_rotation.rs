// End-to-end proof, over real sockets to the backends, that a W2S stream
// rotates through the gateway on the backend's rotating sibling (#67,
// tacplus#323): an SSE server-stream by a new request per leg
// (`x-tacplus-session`), a WebSocket bidi in place on its one socket (a
// `rotate` frame). Each runs across several token lifetimes on the backend
// instance that issued its session, with nothing lost, duplicated or
// reordered; another subject's rotation is refused, and so is an unknown
// session; a backend without the sibling serves the plain method.
//
// What is real here:
//
//   * the real REST router (`rest_translation::router`), its SSE and
//     WebSocket translation, and the real `rotation::handle` behind it,
//     validating each payload as the plain method's request type with the
//     generated validators. The one thing changed is the routes' policy: the
//     generated `eventbus.TraceSession/SubscribeTrace` and
//     `oauth.Session/BrokerSession` are auth-disabled, and nothing rotates
//     onto those (no token, no subject), so the test serves AnyUser copies of
//     them at REST paths of their own;
//   * the real `GatewayAuth` over a real `JwkCache`, verifying real
//     ECDSA-signed JWTs that expire within seconds;
//   * the real `Resolver` and `HealthWatcher`, with two instances of each
//     service; once the session is open the table is reordered, so a fresh
//     pick would land on the other instance.
//
// What is stood in for: the backends' generated `Rotating` siblings. Each
// instance issues ids of its own and keeps its sessions across legs as the
// generated server does: a rotation's leg is attached, the old leg is read to
// the client's `last`, the server answers with its own `last` there and sends
// on the new leg from then on. `SubscribeTrace` sends a numbered event every
// 100 ms; `BrokerSession` echoes each message. The gateway→backend hop is
// plaintext h2c (`Resolver::plaintext_backends`).

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use axum::body::Body;
use bytes::Bytes;
use futures::{SinkExt, StreamExt};
use http_body::Frame;
use http_body_util::BodyExt;
use prost::Message as _;
use tokio::net::TcpListener;
use tokio::sync::{mpsc, oneshot};
use tokio::time::{sleep, timeout, timeout_at, Duration, Instant};
use tokio_stream::wrappers::ReceiverStream;
use tokio_tungstenite::tungstenite::Message;
use tower::ServiceExt;

use gateway_grpcserver::authorizer::JwkCache;
use gateway_key::keys;
use gateway_model::s2sm::rest_dispatch::{AuthPolicy, RouteInfo};
use gateway_model::types::services::oauth::oauth as oauth_pb;
use gateway_model::types::sys::trace::trace::{TraceEvent, TraceRequest};

use crate::auth::GatewayAuth;
use crate::e2e_rotation::{jwk_for, unix_now, unused_verifier, user_token};
use crate::e2e_stream_trace::{rest_router, serve};
use crate::health::{HealthWatcher, ServiceEndpoint};
use crate::proxy_grpc::{self, ProxyState};
use crate::resolver::Resolver;
use crate::rotation::{Envelope, Frames};

/// eventbus's `TraceSession.SubscribeTrace`, a server stream: SSE.
const STREAM_PATH: &str = "/eventbus.TraceSession/SubscribeTrace";
/// oauth's `Session.BrokerSession`, a bidi stream: WebSocket.
const BIDI_PATH: &str = "/oauth.Session/BrokerSession";
const TRACE_ID: &str = "4bf92f3577b34da6a3ce929d0e0e4736";
/// `SessionRequest.session_id`: 32 random bytes, hex-encoded.
const BROKER_SESSION_ID: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
/// The events of a `SubscribeTrace` stream, one every `EVERY`.
const EVENTS: usize = 50;
const EVERY: Duration = Duration::from_millis(100);

// ── the routes ──────────────────────────────────────────────────────────────

/// The generated route of `grpc_path` as an authenticated method, at a REST
/// path no generated route has. Everything else, the payload's validation
/// included, is the generated route's.
fn route_under_test(grpc_path: &str) -> &'static RouteInfo {
    let generated = gateway_model::s2sm::rest_dispatch::ROUTES
        .iter()
        .find(|r| r.grpc_path == grpc_path)
        .unwrap_or_else(|| panic!("the generated ROUTES table must route {grpc_path}"));
    assert!(generated.server_streaming, "{grpc_path} is a server stream");
    let http_path: &'static str =
        Box::leak(format!("/w2s-rotation-test{}", generated.http_path).into_boxed_str());
    crate::rotation::stand_in(RouteInfo {
        auth_policy: AuthPolicy::AnyUser,
        http_path,
        ..*generated
    })
}

// ── the backend instances ───────────────────────────────────────────────────

type Tx = mpsc::Sender<Result<Frame<Bytes>, std::convert::Infallible>>;

/// What every instance saw, in the order it saw it.
#[derive(Default)]
struct Log {
    /// (instance, trace_id) of every request message received.
    received: Mutex<Vec<(&'static str, String)>>,
    /// (instance, session id) of every rotating leg admitted.
    legs: Mutex<Vec<(&'static str, String)>>,
}

/// One live session: the leg it sends on, and a rotation's leg before the
/// client's `last` on the old one, with the signal that starts its reading.
struct Live {
    send: Tx,
    next: Option<(Tx, oneshot::Sender<()>)>,
}

#[derive(Clone)]
struct Instance {
    name: &'static str,
    serves_sibling: bool,
    issued: Arc<AtomicUsize>,
    sessions: Arc<tokio::sync::Mutex<HashMap<String, Live>>>,
    log: Arc<Log>,
}

fn grpc_data(message: &[u8]) -> Result<Frame<Bytes>, std::convert::Infallible> {
    Ok(Frame::data(Bytes::from(proxy_grpc::frame_grpc(message))))
}

fn envelope(envelope: Envelope) -> Result<Frame<Bytes>, std::convert::Infallible> {
    grpc_data(&envelope.encode_to_vec())
}

fn trailers(code: tonic::Code) -> Result<Frame<Bytes>, std::convert::Infallible> {
    let mut trailers = http::HeaderMap::new();
    trailers.insert("grpc-status", http::HeaderValue::from(code as i32));
    Ok(Frame::trailers(trailers))
}

fn is_stream(path: &str) -> bool {
    path.ends_with("/SubscribeTrace")
}

/// `SubscribeTrace`'s n-th event: numbered in a field the stand-in is free to
/// fill, and carrying the request's trace_id.
fn event(trace_id: &str, n: usize) -> Vec<u8> {
    TraceEvent {
        trace_id: trace_id.to_string(),
        error: n.to_string(),
        ..Default::default()
    }
    .encode_to_vec()
}

fn echo(trace_id: &str) -> Vec<u8> {
    oauth_pb::SessionResponse {
        trace_id: trace_id.to_string(),
        ..Default::default()
    }
    .encode_to_vec()
}

impl Instance {
    async fn spawn(name: &'static str, serves_sibling: bool, log: Arc<Log>) -> ServiceEndpoint {
        let instance = Instance {
            name,
            serves_sibling,
            issued: Default::default(),
            sessions: Default::default(),
            log,
        };
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind backend");
        let addr = listener.local_addr().expect("backend addr");
        let app = axum::Router::new().fallback(axum::routing::any(
            move |req: http::Request<Body>| {
                let instance = instance.clone();
                async move { instance.call(req) }
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

    fn call(self, req: http::Request<Body>) -> http::Response<Body> {
        let path = req.uri().path().to_string();
        let rotating = path.contains("Rotating/");
        if rotating && !self.serves_sibling {
            // A server generated without the sibling: tonic's answer to an
            // unknown service.
            return http::Response::builder()
                .header("content-type", "application/grpc")
                .header("grpc-status", (tonic::Code::Unimplemented as i32).to_string())
                .body(Body::empty())
                .expect("response");
        }
        let (tx, rx) = mpsc::channel(16);
        let frames = Frames::new(req.into_body());
        if rotating {
            tokio::spawn(self.leg(path, frames, tx));
        } else {
            tokio::spawn(self.plain(path, frames, tx));
        }
        http::Response::builder()
            .header("content-type", "application/grpc")
            .body(Body::new(http_body_util::StreamBody::new(ReceiverStream::new(rx))))
            .expect("response")
    }

    /// Records a request message, and returns its trace_id.
    fn receive(&self, path: &str, payload: &[u8]) -> String {
        let trace_id = if is_stream(path) {
            TraceRequest::decode(payload).expect("a TraceRequest").trace_id
        } else {
            oauth_pb::SessionRequest::decode(payload)
                .expect("a SessionRequest")
                .trace_id
        };
        self.log
            .received
            .lock()
            .unwrap()
            .push((self.name, trace_id.clone()));
        trace_id
    }

    /// The plain method: three events for `SubscribeTrace`'s one request, an
    /// echo of each of `BrokerSession`'s.
    async fn plain(self, path: String, mut frames: Frames, tx: Tx) {
        while let Ok(Some(frame)) = frames.next().await {
            let trace_id = self.receive(&path, &frame[5..]);
            if is_stream(&path) {
                for n in 0..3 {
                    let _ = tx.send(grpc_data(&event(&trace_id, n))).await;
                }
                break;
            }
            let _ = tx.send(grpc_data(&echo(&trace_id))).await;
        }
        let _ = tx.send(trailers(tonic::Code::Ok)).await;
    }

    /// One leg of the sibling.
    async fn leg(self, path: String, mut frames: Frames, tx: Tx) {
        let Ok(Some(first)) = frames.next().await else {
            return;
        };
        let first = Envelope::decode(&first[5..]).expect("an envelope");
        let (id, turn) = if first.session_id.is_empty() {
            let id = format!(
                "{}-session-{}",
                self.name,
                self.issued.fetch_add(1, Ordering::SeqCst) + 1
            );
            self.sessions.lock().await.insert(
                id.clone(),
                Live {
                    send: tx.clone(),
                    next: None,
                },
            );
            (id, None)
        } else {
            let (go, turn) = oneshot::channel();
            let mut sessions = self.sessions.lock().await;
            match sessions.get_mut(&first.session_id) {
                Some(live) if live.next.is_none() => live.next = Some((tx.clone(), go)),
                _ => {
                    let _ = tx.send(trailers(tonic::Code::PermissionDenied)).await;
                    return;
                }
            }
            (first.session_id, Some(turn))
        };
        self.log.legs.lock().unwrap().push((self.name, id.clone()));
        let _ = tx
            .send(envelope(Envelope {
                session_id: id.clone(),
                ..Default::default()
            }))
            .await;
        // A rotation's leg is read once the old one is read to its last.
        if let Some(turn) = turn {
            if turn.await.is_err() {
                return;
            }
        }
        self.read(&path, &id, frames).await;
    }

    async fn read(&self, path: &str, id: &str, mut frames: Frames) {
        while let Ok(Some(frame)) = frames.next().await {
            let received = Envelope::decode(&frame[5..]).expect("an envelope");
            if received.last {
                // The cut-over: the server's last on the old leg, which ends
                // OK, and every send on the new one from now on.
                let mut sessions = self.sessions.lock().await;
                let Some(live) = sessions.get_mut(id) else {
                    return;
                };
                let (next, go) = live.next.take().expect("a last with a leg to cut over to");
                let old = std::mem::replace(&mut live.send, next);
                let _ = old
                    .send(envelope(Envelope {
                        last: true,
                        ..Default::default()
                    }))
                    .await;
                let _ = old.send(trailers(tonic::Code::Ok)).await;
                let _ = go.send(());
                return;
            }
            if received.fin {
                // A server stream ends when its handler does.
                if !is_stream(path) {
                    self.end(id).await;
                }
                continue;
            }
            let trace_id = self.receive(path, &received.payload);
            if is_stream(path) {
                tokio::spawn(self.clone().produce(id.to_string(), trace_id));
            } else {
                self.send(id, echo(&trace_id)).await;
            }
        }
    }

    /// Sends a message on the session's current leg; false once it is over.
    async fn send(&self, id: &str, payload: Vec<u8>) -> bool {
        let sessions = self.sessions.lock().await;
        let Some(live) = sessions.get(id) else {
            return false;
        };
        let _ = live
            .send
            .send(envelope(Envelope {
                payload,
                ..Default::default()
            }))
            .await;
        true
    }

    /// The handler's end: OK on the current leg, and the session is over.
    async fn end(&self, id: &str) {
        if let Some(live) = self.sessions.lock().await.remove(id) {
            let _ = live.send.send(trailers(tonic::Code::Ok)).await;
        }
    }

    async fn produce(self, id: String, trace_id: String) {
        for n in 0..EVENTS {
            sleep(EVERY).await;
            if !self.send(&id, event(&trace_id, n)).await {
                return;
            }
        }
        self.end(&id).await;
    }
}

// ── wiring ──────────────────────────────────────────────────────────────────

struct Fixture {
    proxy: Arc<ProxyState>,
    router: axum::Router,
    key: keys::ImmutableKey,
    stream: &'static RouteInfo,
    bidi: &'static RouteInfo,
    log: Arc<Log>,
    a: ServiceEndpoint,
    b: ServiceEndpoint,
}

/// Two instances of each service, A then B in the endpoint table, and the
/// gateway's REST router in front of them.
async fn fixture(serves_sibling: bool) -> Fixture {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let stream = route_under_test(STREAM_PATH);
    let bidi = route_under_test(BIDI_PATH);
    let key = keys::generate_ec_p256_key().expect("signing key");
    let log = Arc::new(Log::default());
    let a = Instance::spawn("A", serves_sibling, Arc::clone(&log)).await;
    let b = Instance::spawn("B", serves_sibling, Arc::clone(&log)).await;
    let mut endpoints = HashMap::new();
    for route in [stream, bidi] {
        endpoints.insert(route.service_id.to_string(), vec![a.clone(), b.clone()]);
    }
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
    Fixture {
        router: rest_router(Arc::clone(&proxy)),
        proxy,
        key,
        stream,
        bidi,
        log,
        a,
        b,
    }
}

impl Fixture {
    fn token(&self, route: &RouteInfo, sub: &str, lifetime: i64) -> String {
        user_token(&self.key, route.service_id, sub, lifetime)
    }

    /// From now on a fresh pick lands on B.
    fn prefer_b(&self) {
        for route in [self.stream, self.bidi] {
            self.proxy
                .resolver
                .health()
                .set_endpoints(route.service_id, vec![self.b.clone(), self.a.clone()]);
        }
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

    async fn legs_opened(&self, n: usize) {
        for _ in 0..50 {
            if self.log.legs.lock().unwrap().len() >= n {
                return;
            }
            sleep(Duration::from_millis(100)).await;
        }
        panic!("the backend never saw {n} leg(s)");
    }

    /// A `SubscribeTrace` request over SSE with `x-tacplus-session: session`.
    async fn sse(&self, session: &str, token: &str) -> axum::response::Response {
        self.router
            .clone()
            .oneshot(
                axum::http::Request::post(self.stream.http_path)
                    .header(axum::http::header::CONTENT_TYPE, "application/json")
                    .header("authorization", token)
                    .header("x-tacplus-session", session)
                    .body(Body::from(
                        serde_json::json!({ "traceId": TRACE_ID }).to_string(),
                    ))
                    .expect("request"),
            )
            .await
            .expect("the router answers")
    }
}

// ── the SSE client ──────────────────────────────────────────────────────────

/// The events of an SSE response: (event, data), "message" for a data event.
struct Events {
    body: Body,
    buffer: String,
}

impl Events {
    fn of(response: axum::response::Response) -> Self {
        assert_eq!(response.status(), axum::http::StatusCode::OK);
        Self {
            body: response.into_body(),
            buffer: String::new(),
        }
    }

    /// The next event, `None` at the stream's end. Cancel-safe: what it has
    /// read stays in the buffer.
    async fn next(&mut self) -> Option<(String, String)> {
        loop {
            if let Some(end) = self.buffer.find("\n\n") {
                let block: String = self.buffer.drain(..end + 2).collect();
                let mut event = "message".to_string();
                let mut data = Vec::new();
                for line in block.lines() {
                    if let Some(value) = line.strip_prefix("event:") {
                        event = value.trim_start().to_string();
                    } else if let Some(value) = line.strip_prefix("data:") {
                        data.push(value.strip_prefix(' ').unwrap_or(value).to_string());
                    }
                }
                if data.is_empty() {
                    continue;
                }
                return Some((event, data.join("\n")));
            }
            match self.body.frame().await {
                Some(Ok(frame)) => {
                    if let Ok(data) = frame.into_data() {
                        self.buffer.push_str(&String::from_utf8_lossy(&data));
                    }
                }
                _ => return None,
            }
        }
    }

    async fn next_in_time(&mut self) -> Option<(String, String)> {
        timeout(Duration::from_secs(10), self.next())
            .await
            .expect("the stream answers in time")
    }
}

/// A data event's number; it must carry the request's trace_id.
fn numbered(data: &str) -> usize {
    let event: serde_json::Value = serde_json::from_str(data).expect("a JSON event");
    assert_eq!(event["traceId"], TRACE_ID, "{data}");
    event["error"]
        .as_str()
        .and_then(|n| n.parse().ok())
        .unwrap_or_else(|| panic!("a numbered event: {data}"))
}

// ── the SSE runs ────────────────────────────────────────────────────────────

/// The acceptance run for SSE: one logical stream of `EVENTS` events (5 s)
/// over four requests, each with a token living 3 s, rotated every second.
/// Each old stream ends with `event: last` after its leg's final event; read
/// in order, the streams carry every event once, in order. Every leg reaches
/// instance A, which issued the session, though a fresh pick lands on B, and
/// the request (with its trace_id) reaches it once.
#[tokio::test]
async fn an_sse_stream_rotates_across_token_lifetimes_with_nothing_lost() {
    const LEGS: usize = 4;
    let f = fixture(true).await;
    let first_exp = unix_now() + 3;
    let mut stream = Events::of(f.sse("new", &f.token(f.stream, "alice", 3)).await);
    let (event, session) = stream.next_in_time().await.expect("the session first");
    assert_eq!(event, "session", "the stream names its session first");
    f.prefer_b();

    let mut seen = Vec::new();
    for _ in 1..LEGS {
        let deadline = Instant::now() + Duration::from_secs(1);
        while let Ok(next) = timeout_at(deadline, stream.next()).await {
            let (event, data) = next.expect("the stream outlives this leg");
            assert_eq!(event, "message", "{event}: {data}");
            seen.push(numbered(&data));
        }

        // Make before break: the new request is admitted and names the
        // session before the old one is cut over.
        let mut next = Events::of(f.sse(&session, &f.token(f.stream, "alice", 3)).await);
        assert_eq!(
            next.next_in_time().await,
            Some(("session".to_string(), session.clone())),
            "the new stream carries the session on"
        );
        loop {
            match stream.next_in_time().await {
                Some((event, data)) if event == "last" => {
                    assert_eq!(data, session);
                    break;
                }
                Some((event, data)) => {
                    assert_eq!(event, "message", "{event}: {data}");
                    seen.push(numbered(&data));
                }
                None => panic!("the old stream ended without its last"),
            }
        }
        assert_eq!(stream.next_in_time().await, None, "nothing follows last");
        stream = next;
    }
    while let Some((event, data)) = stream.next_in_time().await {
        assert_eq!(event, "message", "{event}: {data}");
        seen.push(numbered(&data));
    }

    assert!(unix_now() >= first_exp, "the stream must outlive its first token");
    assert_eq!(
        seen,
        (0..EVENTS).collect::<Vec<_>>(),
        "every event comes once, in order"
    );
    assert_eq!(
        *f.log.received.lock().unwrap(),
        vec![("A", TRACE_ID.to_string())],
        "the request, and its trace_id, reaches the backend once"
    );
    assert_eq!(
        *f.log.legs.lock().unwrap(),
        vec![("A", session.clone()); LEGS],
        "every leg reaches instance A"
    );
    f.sessions_drain().await;
}

/// The id alone authorizes nothing: another subject's token with a valid id
/// is refused with PERMISSION_DENIED (403), an unknown session with
/// UNAUTHENTICATED (401), neither with a description, before any event and
/// before the backend sees a leg. The stream goes on.
#[tokio::test]
async fn an_sse_rotation_is_refused_for_another_subject_or_an_unknown_session() {
    let f = fixture(true).await;
    let mut stream = Events::of(f.sse("new", &f.token(f.stream, "alice", 60)).await);
    let (_, session) = stream.next_in_time().await.expect("the session first");

    for (what, session, token, status, code) in [
        (
            "another subject",
            session.as_str(),
            f.token(f.stream, "bob", 60),
            axum::http::StatusCode::FORBIDDEN,
            tonic::Code::PermissionDenied,
        ),
        (
            "an unknown session",
            "A-session-404",
            f.token(f.stream, "alice", 60),
            axum::http::StatusCode::UNAUTHORIZED,
            tonic::Code::Unauthenticated,
        ),
    ] {
        let response = f.sse(session, &token).await;
        assert_eq!(response.status(), status, "{what}");
        assert_eq!(
            response.headers()["grpc-status"],
            (code as i32).to_string().as_str(),
            "{what}"
        );
        let body = axum::body::to_bytes(response.into_body(), 1 << 16)
            .await
            .expect("body");
        let body: serde_json::Value = serde_json::from_slice(&body).expect("a JSON error");
        assert_eq!(body["error"], "", "{what}: no reason text");
        assert_eq!(body["code"], code as i32, "{what}");
    }
    assert_eq!(f.log.legs.lock().unwrap().len(), 1, "no refused leg reaches the backend");

    let (event, data) = stream.next_in_time().await.expect("the stream goes on");
    assert_eq!(event, "message", "{event}: {data}");
}

/// A backend without the sibling: the plain method serves the stream, with
/// no `event: session` (it does not rotate).
#[tokio::test]
async fn an_sse_stream_falls_back_to_the_plain_method_without_the_sibling() {
    let f = fixture(false).await;
    let mut stream = Events::of(f.sse("new", &f.token(f.stream, "alice", 60)).await);
    let mut seen = Vec::new();
    while let Some((event, data)) = stream.next_in_time().await {
        assert_eq!(event, "message", "no session event: {event}: {data}");
        seen.push(numbered(&data));
    }
    assert_eq!(seen, vec![0, 1, 2]);
    assert_eq!(f.log.received.lock().unwrap().len(), 1);
    assert_eq!(f.proxy.sessions.len(), 0, "no session was issued");
}

// ── the WebSocket client ────────────────────────────────────────────────────

type Socket =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

async fn connect(f: &Fixture) -> Socket {
    let addr = serve(f.router.clone()).await;
    let (socket, _) = tokio_tungstenite::connect_async(format!("ws://{addr}{}", f.bidi.http_path))
        .await
        .expect("WebSocket upgrade");
    socket
}

async fn send(socket: &mut Socket, frame: serde_json::Value) {
    socket
        .send(Message::Text(frame.to_string().into()))
        .await
        .expect("send a frame");
}

fn trace_id(n: usize) -> String {
    format!("{:032x}", n + 1)
}

fn message(n: usize, token: &str) -> serde_json::Value {
    serde_json::json!({
        "type": "message",
        "authorization": token,
        "message": { "sessionId": BROKER_SESSION_ID, "traceId": trace_id(n) },
    })
}

/// The next frame, as JSON; `None` once the socket closes.
async fn next_frame(socket: &mut Socket) -> Option<serde_json::Value> {
    loop {
        match timeout(Duration::from_secs(10), socket.next())
            .await
            .expect("the socket answers in time")
        {
            Some(Ok(Message::Text(text))) => {
                return Some(serde_json::from_str(text.as_str()).expect("a JSON frame"))
            }
            Some(Ok(Message::Close(_))) | None => return None,
            Some(Ok(_)) => continue,
            Some(Err(e)) => panic!("the socket failed: {e}"),
        }
    }
}

// ── the WebSocket runs ──────────────────────────────────────────────────────

/// The acceptance run for a WebSocket: one bidi stream over four legs on one
/// socket, each leg's token living 3 s, rotated every second by a `rotate`
/// frame, the data frames carrying the token in force. Every message reaches
/// instance A once, in order, with its trace_id; every echo comes back once,
/// in order; each rotation is acknowledged.
#[tokio::test]
async fn a_websocket_stream_rotates_in_place_across_token_lifetimes() {
    const LEGS: usize = 4;
    const PER_LEG: usize = 5;
    let f = fixture(true).await;
    let mut socket = connect(&f).await;
    let first_exp = unix_now() + 3;
    let mut token = f.token(f.bidi, "alice", 3);
    send(&mut socket, serde_json::json!({ "type": "start", "authorization": token })).await;
    f.legs_opened(1).await;
    f.prefer_b();

    let mut sent = 0;
    for rotation in 0..LEGS {
        for _ in 0..PER_LEG {
            send(&mut socket, message(sent, &token)).await;
            sent += 1;
        }
        if rotation + 1 == LEGS {
            break;
        }
        sleep(Duration::from_secs(1)).await;
        token = f.token(f.bidi, "alice", 3);
        send(&mut socket, serde_json::json!({ "type": "rotate", "authorization": token })).await;
    }
    send(&mut socket, serde_json::json!({ "type": "complete" })).await;

    let mut echoed = Vec::new();
    let mut rotated = 0;
    while let Some(frame) = next_frame(&mut socket).await {
        if frame == serde_json::json!({ "type": "rotated" }) {
            rotated += 1;
        } else if let Some(trace_id) = frame["traceId"].as_str() {
            echoed.push(trace_id.to_string());
        } else {
            panic!("an unexpected frame: {frame}");
        }
    }

    assert!(unix_now() >= first_exp, "the stream must outlive its first token");
    let expected: Vec<String> = (0..sent).map(trace_id).collect();
    assert_eq!(echoed, expected, "every echo comes back once, in order");
    assert_eq!(rotated, LEGS - 1, "every rotation is acknowledged");
    let received = f.log.received.lock().unwrap().clone();
    assert_eq!(
        received.iter().map(|(_, t)| t.clone()).collect::<Vec<_>>(),
        expected,
        "every message (and its trace_id) reaches the backend once, in order"
    );
    assert!(
        received.iter().all(|(instance, _)| *instance == "A"),
        "every message reaches the instance that issued the session: {received:?}"
    );
    let legs = f.log.legs.lock().unwrap().clone();
    assert_eq!(legs.len(), LEGS, "{legs:?}");
    assert!(
        legs.iter().all(|leg| *leg == legs[0] && leg.0 == "A"),
        "every leg carries the one session on instance A: {legs:?}"
    );
    f.sessions_drain().await;
}

/// Another subject's token, an expired one, or none: the rotation is refused
/// with its code, the backend never sees the leg, and the stream goes on. (A
/// WebSocket's session id never leaves the gateway, so its client cannot name
/// an unknown one.)
#[tokio::test]
async fn a_websocket_rotation_is_refused_for_another_subject() {
    let f = fixture(true).await;
    let mut socket = connect(&f).await;
    let token = f.token(f.bidi, "alice", 60);
    send(&mut socket, serde_json::json!({ "type": "start", "authorization": token })).await;
    f.legs_opened(1).await;

    for (what, rotate, code) in [
        (
            "another subject",
            serde_json::json!({ "type": "rotate", "authorization": f.token(f.bidi, "bob", 60) }),
            tonic::Code::PermissionDenied,
        ),
        (
            "an expired token",
            serde_json::json!({ "type": "rotate", "authorization": f.token(f.bidi, "alice", -10) }),
            tonic::Code::Unauthenticated,
        ),
        (
            "no token",
            serde_json::json!({ "type": "rotate" }),
            tonic::Code::Unauthenticated,
        ),
    ] {
        send(&mut socket, rotate).await;
        let refused = next_frame(&mut socket).await.expect("an answer");
        assert_eq!(refused["type"], "rotated", "{what}: {refused}");
        assert_eq!(refused["code"], code as i32, "{what}: {refused}");
    }
    assert_eq!(f.log.legs.lock().unwrap().len(), 1, "no refused leg reaches the backend");

    send(&mut socket, message(0, &token)).await;
    let answer = next_frame(&mut socket).await.expect("the stream goes on");
    assert_eq!(answer["traceId"], trace_id(0), "{answer}");
}

/// A backend without the sibling: the plain method serves the socket, and a
/// `rotate` is refused UNIMPLEMENTED without ending it.
#[tokio::test]
async fn a_websocket_stream_falls_back_to_the_plain_method_without_the_sibling() {
    let f = fixture(false).await;
    let mut socket = connect(&f).await;
    let token = f.token(f.bidi, "alice", 60);
    send(&mut socket, serde_json::json!({ "type": "start", "authorization": token })).await;
    send(&mut socket, message(0, &token)).await;
    let answer = next_frame(&mut socket).await.expect("the plain method answers");
    assert_eq!(answer["traceId"], trace_id(0), "{answer}");

    send(&mut socket, serde_json::json!({ "type": "rotate", "authorization": token })).await;
    let refused = next_frame(&mut socket).await.expect("an answer");
    assert_eq!(refused["type"], "rotated", "{refused}");
    assert_eq!(refused["code"], tonic::Code::Unimplemented as i32, "{refused}");

    send(&mut socket, message(1, &token)).await;
    let answer = next_frame(&mut socket).await.expect("the stream goes on");
    assert_eq!(answer["traceId"], trace_id(1), "{answer}");
    assert_eq!(f.proxy.sessions.len(), 0, "no session was issued");
}
