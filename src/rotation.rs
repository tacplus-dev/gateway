//! Make-before-break rotation of a C2S stream through the gateway (#26).
//!
//! A generated server serves, beside each service `<pkg>.<Svc>` with streaming
//! rpcs, the sibling `<pkg>.<Svc>Rotating` (tacplus#322, `sys/rotation.proto`):
//! the same method names, every one bidi of `rotation.Envelope`. A logical
//! stream is a session carried by one stream (a leg) at a time; each leg opens
//! with its own token, and the first envelope of each leg names the session.
//! The session lives in one backend instance, so every leg of it must reach
//! that instance, and only its subject may carry it on:
//!
//!   - An opening leg (its first envelope has no session id) is routed like
//!     any call. The backend's first envelope carries the new session id: the
//!     gateway records it, bound to the instance it dialed and the subject of
//!     the opening token, before the client sees it.
//!   - A rotation (its first envelope names a session) goes to that instance,
//!     never to a fresh pick, and only when its token names the same subject.
//!     The id alone authorizes nothing: another subject's token is refused
//!     with `PERMISSION_DENIED`, an unknown or ended session with
//!     `UNAUTHENTICATED`, both with no description.
//!   - Every envelope is checked as the plain method's frames are: the token
//!     again, and a payload as the plain method's request type. A leg ends
//!     with `UNAUTHENTICATED` at its token's `exp`, at once.
//!   - Everything else passes through unchanged, both ways, including
//!     `UNIMPLEMENTED` from a backend that serves no sibling (the client falls
//!     back to the plain method).
//!
//! A session is forgotten when its last leg ends. A rotation opens on the same
//! connection as the leg it replaces (tacplus#322), so on the same gateway:
//! the table is this process's own.
//!
//! A W2S stream (SSE, WebSocket) rotates on the same legs, which the gateway
//! itself opens on the client's behalf (#67, `W2sLeg`): it is the sibling's
//! client, so it sends the leg's `last` once the next leg is admitted, and
//! translates the backend's `last` into the W2S carrier's own end of a leg.

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use axum::body::Body;
use axum::response::Response;
use http::Request;
use http_body::Frame;
use http_body_util::BodyExt;
use tokio_stream::wrappers::ReceiverStream;
use tower::{Service, ServiceExt};

use gateway_model::s2sm::rest_dispatch::{AuthPolicy, RouteInfo};

use crate::auth::Subject;
use crate::proxy_grpc::{
    frame_grpc, is_mcp_carrier, mcp_session_tenant, route_identity, stamp_mcp_tenant,
    status_code_to_tonic, tonic_status_to_response, ProxyState, StreamingBody,
    MAX_GRPC_MESSAGE_BYTES,
};

/// The suffix of a rotating sibling's service name.
const SIBLING_SUFFIX: &str = "Rotating";

/// How long a leg may take to send its first envelope. Parity with the
/// generated server's `OPEN_TIMEOUT`.
const OPEN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// The most of a backend's first message read to find its session id: the
/// envelope carries the id and nothing else.
const MAX_FIRST_ENVELOPE_BYTES: usize = 64 * 1024;

/// `rotation.Envelope` (tacplus `sys/rotation.proto`, field numbers frozen).
/// Declared here, as `TraceProbe` is, because the pinned tacplus generates no
/// `sys/rotation` types into the gateway's model.
#[derive(Clone, PartialEq, prost::Message)]
pub(crate) struct Envelope {
    #[prost(bytes = "vec", tag = "1")]
    pub payload: Vec<u8>,
    #[prost(bool, tag = "2")]
    pub last: bool,
    #[prost(string, tag = "3")]
    pub session_id: String,
    #[prost(bytes = "vec", tag = "4")]
    pub cursor: Vec<u8>,
    #[prost(bool, tag = "5")]
    pub fin: bool,
}

impl Envelope {
    /// One message of the plain rpc: an envelope with neither last, fin nor
    /// a session id.
    fn is_message(&self) -> bool {
        !self.last && !self.fin && self.session_id.is_empty()
    }

    /// After a leg's first envelope none carries a session id or a cursor,
    /// and a control envelope carries no payload.
    fn malformed(&self) -> bool {
        !self.session_id.is_empty()
            || !self.cursor.is_empty()
            || (!self.is_message() && !self.payload.is_empty())
    }

    /// A leg's first envelope carries a session id (or none) and nothing else.
    fn opens_a_leg(&self) -> bool {
        self.payload.is_empty() && !self.last && !self.fin && self.cursor.is_empty()
    }
}

/// The plain method a rotating sibling's path stands for, and its route:
/// `/<pkg>.<Svc>Rotating/<Method>` is `/<pkg>.<Svc>/<Method>` when that is a
/// streaming method in ROUTES (only streaming methods have a sibling).
pub(crate) fn plain_route(path: &str) -> Option<(String, &'static RouteInfo)> {
    let (service, method) = path.strip_prefix('/')?.split_once('/')?;
    let plain = service.strip_suffix(SIBLING_SUFFIX)?;
    if plain.is_empty() || method.is_empty() || method.contains('/') {
        return None;
    }
    let plain_path = format!("/{plain}/{method}");
    let route = stand_in_route(&plain_path).or_else(|| {
        gateway_model::s2sm::rest_dispatch::ROUTES
            .iter()
            .find(|r| r.grpc_path == plain_path)
    })?;
    (route.client_streaming || route.server_streaming).then_some((plain_path, route))
}

/// Test-only: routes that stand in for generated ones of the same path. The
/// fleet's C2S streaming methods are all auth-disabled today, and nothing
/// rotates onto one of those, so the end-to-end test rotates an
/// authenticated copy of a real streaming route (its payloads still validate
/// as that route's request type).
#[cfg(test)]
static STAND_IN_ROUTES: Mutex<Vec<&'static RouteInfo>> = Mutex::new(Vec::new());

#[cfg(test)]
pub(crate) fn stand_in(route: RouteInfo) -> &'static RouteInfo {
    let mut routes = STAND_IN_ROUTES.lock().unwrap();
    if let Some(existing) = routes
        .iter()
        .find(|r| r.grpc_path == route.grpc_path && r.http_path == route.http_path)
    {
        return *existing;
    }
    let route: &'static RouteInfo = Box::leak(Box::new(route));
    routes.push(route);
    route
}

#[cfg(test)]
fn stand_in_route(path: &str) -> Option<&'static RouteInfo> {
    STAND_IN_ROUTES
        .lock()
        .unwrap()
        .iter()
        .find(|r| r.grpc_path == path)
        .copied()
}

#[cfg(not(test))]
fn stand_in_route(_path: &str) -> Option<&'static RouteInfo> {
    None
}

/// Test-only: the stand-ins with REST paths of their own (no generated route
/// has them), so that the REST layer can carry a W2S stream on one (#67)
/// while the generated route of the same gRPC path stays as it is.
#[cfg(test)]
pub(crate) fn stand_in_rest_route(http_path: &str) -> Option<&'static RouteInfo> {
    STAND_IN_ROUTES
        .lock()
        .unwrap()
        .iter()
        .find(|r| r.http_path == http_path)
        .copied()
}

#[cfg(test)]
pub(crate) fn stand_in_rest_paths() -> Vec<&'static str> {
    STAND_IN_ROUTES
        .lock()
        .unwrap()
        .iter()
        .map(|r| r.http_path)
        .collect()
}

/// The rotating sessions this gateway carries.
#[derive(Default)]
pub struct Sessions {
    sessions: Mutex<HashMap<String, Session>>,
    /// The SSE stream carrying each session's current leg (#67), by serial:
    /// told to cut over when the session's next leg is admitted.
    carriers: Mutex<HashMap<String, (u64, tokio::sync::oneshot::Sender<()>)>>,
    serial: AtomicU64,
}

struct Session {
    plain_path: String,
    subject: Option<Subject>,
    /// The backend instance (`host:port`) that issued the session.
    endpoint: String,
    /// The legs of it this gateway carries; at none the session is over.
    legs: usize,
}

/// One leg of a session this gateway carries; dropping it ends the leg.
pub(crate) struct Leg {
    sessions: Arc<Sessions>,
    id: String,
}

impl Drop for Leg {
    fn drop(&mut self) {
        let mut sessions = self.sessions.sessions.lock().unwrap();
        if let Some(session) = sessions.get_mut(&self.id) {
            session.legs -= 1;
            if session.legs == 0 {
                sessions.remove(&self.id);
            }
        }
    }
}

impl Sessions {
    /// Records a session a backend instance has just issued, with its first
    /// leg. `None` if the id is already taken: the session is not recorded,
    /// so nothing can rotate onto it.
    fn open(
        self: &Arc<Self>,
        id: &str,
        plain_path: &str,
        subject: Option<Subject>,
        endpoint: &str,
    ) -> Option<Leg> {
        let mut sessions = self.sessions.lock().unwrap();
        if sessions.contains_key(id) {
            return None;
        }
        sessions.insert(
            id.to_string(),
            Session {
                plain_path: plain_path.to_string(),
                subject,
                endpoint: endpoint.to_string(),
                legs: 1,
            },
        );
        Some(Leg {
            sessions: Arc::clone(self),
            id: id.to_string(),
        })
    }

    /// Admits a rotation onto session `id`: the instance to dial, and the new
    /// leg. An unknown (or ended) session is `UNAUTHENTICATED`; another
    /// method's session, or another subject's, `PERMISSION_DENIED`.
    fn join(
        self: &Arc<Self>,
        id: &str,
        plain_path: &str,
        subject: &Option<Subject>,
    ) -> Result<(String, Leg), tonic::Code> {
        let mut sessions = self.sessions.lock().unwrap();
        let session = sessions.get_mut(id).ok_or(tonic::Code::Unauthenticated)?;
        if session.plain_path != plain_path || session.subject != *subject {
            return Err(tonic::Code::PermissionDenied);
        }
        session.legs += 1;
        Ok((
            session.endpoint.clone(),
            Leg {
                sessions: Arc::clone(self),
                id: id.to_string(),
            },
        ))
    }

    /// The SSE stream now carrying session `id` (#67): the stream that carried
    /// it before is told to cut over, and this one will be when the next is.
    /// Called only once this stream's leg has been admitted.
    pub(crate) fn carry(self: &Arc<Self>, id: &str) -> Carrier {
        let serial = self.serial.fetch_add(1, Ordering::Relaxed);
        let (tx, cut_over) = tokio::sync::oneshot::channel();
        let previous = self
            .carriers
            .lock()
            .unwrap()
            .insert(id.to_string(), (serial, tx));
        if let Some((_, previous)) = previous {
            let _ = previous.send(());
        }
        Carrier {
            sessions: Arc::clone(self),
            id: id.to_string(),
            serial,
            cut_over,
        }
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.sessions.lock().unwrap().len()
    }
}

/// An SSE stream's hold on its session (`Sessions::carry`); dropping it lets
/// go, unless a newer stream already carries the session.
pub(crate) struct Carrier {
    sessions: Arc<Sessions>,
    id: String,
    serial: u64,
    /// Fires when the session's next leg is admitted: this stream's leg is to
    /// send its `last`.
    pub(crate) cut_over: tokio::sync::oneshot::Receiver<()>,
}

impl Drop for Carrier {
    fn drop(&mut self) {
        let mut carriers = self.sessions.carriers.lock().unwrap();
        if carriers.get(&self.id).is_some_and(|(serial, _)| *serial == self.serial) {
            carriers.remove(&self.id);
        }
    }
}

/// A refused leg: the code, no description (tacplus#322).
fn refuse(code: tonic::Code) -> Response {
    tonic_status_to_response(tonic::Status::new(code, ""))
}

/// The gRPC messages of a request body, one frame (header and payload) at a
/// time.
pub(crate) struct Frames {
    body: Body,
    buffer: bytes::BytesMut,
    /// A response's status, once its trailers are in.
    status: Option<tonic::Status>,
}

impl Frames {
    pub(crate) fn new(body: Body) -> Self {
        Self {
            body,
            buffer: bytes::BytesMut::new(),
            status: None,
        }
    }

    /// The status a response body's trailers carried, if it is not OK.
    fn failed(&self) -> Option<tonic::Status> {
        self.status
            .clone()
            .filter(|status| status.code() != tonic::Code::Ok)
    }

    pub(crate) async fn next(&mut self) -> Result<Option<bytes::Bytes>, tonic::Status> {
        loop {
            if self.buffer.len() >= 5 {
                if self.buffer[0] != 0 {
                    return Err(tonic::Status::unimplemented(
                        "compressed gRPC frames are not supported by gateway validation",
                    ));
                }
                let len = u32::from_be_bytes([
                    self.buffer[1],
                    self.buffer[2],
                    self.buffer[3],
                    self.buffer[4],
                ]) as usize;
                if len > MAX_GRPC_MESSAGE_BYTES {
                    return Err(tonic::Status::resource_exhausted(
                        "gRPC message exceeds gateway validation limit",
                    ));
                }
                if self.buffer.len() >= 5 + len {
                    return Ok(Some(self.buffer.split_to(5 + len).freeze()));
                }
            }
            match self.body.frame().await {
                None if self.buffer.is_empty() => return Ok(None),
                None => {
                    return Err(tonic::Status::invalid_argument(
                        "incomplete trailing gRPC frame",
                    ))
                }
                Some(Err(e)) => {
                    return Err(tonic::Status::cancelled(format!(
                        "request body read error: {e}"
                    )))
                }
                Some(Ok(frame)) => {
                    if let Some(data) = frame.data_ref() {
                        self.buffer.extend_from_slice(data);
                    } else if let Some(trailers) = frame.trailers_ref() {
                        self.status = tonic::Status::from_header_map(trailers);
                    }
                }
            }
        }
    }
}

fn decode(frame: &[u8]) -> Result<Envelope, tonic::Status> {
    <Envelope as prost::Message>::decode(&frame[5..])
        .map_err(|_| tonic::Status::invalid_argument("malformed rotation envelope"))
}

/// Proxies one leg of `/<pkg>.<Svc>Rotating/<Method>`, the rotating sibling
/// of `plain_path`, whose route is `route`.
pub(crate) async fn handle(
    proxy: &ProxyState,
    req: Request<Body>,
    route: &'static RouteInfo,
    plain_path: String,
) -> Response {
    let path = req.uri().path().to_string();
    let (service_id, entitlement_service) = route_identity(route);

    // A tenant-owned method is routed by its request's target-tenant field
    // (#3), but an opening leg is dialled on its first envelope, which carries
    // no request: there is no tenant to route it to, and the gateway never
    // takes one from the token. Such a method has no rotating sibling through
    // the gateway, so the client falls back to the plain method, which is
    // routed by its first message. The one exception is an MCP session
    // carrier, whose tenant is the caller token's (#15): its leg is routed
    // to, and its messages stamped with, that tenant.
    if route.route_field_number != 0 && !is_mcp_carrier(route) {
        tracing::warn!(path = %path, "rotation of a tenant-routed method refused");
        return refuse(tonic::Code::Unimplemented);
    }
    let auth_header = req
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    // The token first, on headers alone, by the plain method's policy.
    let admitted = match proxy.auth.admit_leg(
        route.auth_policy,
        service_id,
        entitlement_service,
        &plain_path,
        auth_header.as_deref(),
    ) {
        Ok(admitted) => admitted,
        Err((code, msg)) => {
            tracing::warn!(path = %path, error = %msg, "rotating leg refused");
            return refuse(status_code_to_tonic(code));
        }
    };
    let (subject, exp) = match admitted {
        Some((subject, exp)) => (Some(subject), Some(exp)),
        None => (None, None),
    };

    // The rotating sibling of a tenant-owned service's MCP carrier stamps
    // each payload with the caller token's tenant, as the plain carrier does
    // (#15).
    let mcp_tenant = match mcp_session_tenant(proxy, route, &plain_path, auth_header.as_deref()) {
        Ok(tenant) => tenant,
        Err(status) => return refuse(status.code()),
    };

    let (parts, body) = req.into_parts();
    let mut frames = Frames::new(body);
    let first_frame = match tokio::time::timeout(OPEN_TIMEOUT, frames.next()).await {
        Ok(Ok(Some(frame))) => frame,
        Ok(Ok(None)) => return refuse(tonic::Code::Cancelled),
        Ok(Err(status)) => return tonic_status_to_response(status),
        Err(_) => {
            tracing::warn!(path = %path, "rotating leg sent no first envelope in time");
            return refuse(tonic::Code::DeadlineExceeded);
        }
    };
    let first = match decode(&first_frame) {
        Ok(first) if first.opens_a_leg() => first,
        Ok(_) => {
            return tonic_status_to_response(tonic::Status::invalid_argument(
                "a rotating leg opens with a session id and nothing else",
            ))
        }
        Err(status) => return tonic_status_to_response(status),
    };

    // Where the leg goes: a fresh pick for a new session, the session's own
    // instance for a rotation.
    let (endpoint, mut channel, leg, opening) = if first.session_id.is_empty() {
        // A platform service is routed by name, as any call to it; an MCP
        // session of a tenant-owned one to the caller token's tenant.
        let route_key =
            proxy.resolver.resolve_target(service_id, mcp_tenant.as_deref().unwrap_or(""));
        match proxy
            .resolver
            .dial_ready_instance(&route_key, service_id)
            .await
        {
            Some((endpoint, channel)) => (endpoint, channel, None, true),
            None => {
                return tonic_status_to_response(tonic::Status::unavailable(
                    "backend not ready",
                ))
            }
        }
    } else {
        // An auth-disabled method carries no token, so no subject to bind a
        // rotation to: nothing rotates onto it (as the generated server).
        if route.auth_policy == AuthPolicy::NoAuth {
            tracing::warn!(path = %path, "rotation of an auth-disabled method refused");
            return refuse(tonic::Code::PermissionDenied);
        }
        let (endpoint, leg) = match proxy.sessions.join(&first.session_id, &plain_path, &subject) {
            Ok(joined) => joined,
            Err(code) => {
                tracing::warn!(path = %path, code = ?code, "rotation refused");
                return refuse(code);
            }
        };
        match proxy.resolver.dial_instance(&endpoint, service_id).await {
            Ok(channel) => (endpoint, channel, Some(leg), false),
            Err(e) => {
                tracing::warn!(path = %path, endpoint = %endpoint, error = %e, "the session's instance is gone");
                return tonic_status_to_response(tonic::Status::unavailable(
                    "the session's backend instance is gone",
                ));
            }
        }
    };

    // The leg's end, if the gateway ends it first: a refused envelope, or
    // the token's exp.
    let (abort_tx, abort_rx) = tokio::sync::oneshot::channel::<tonic::Status>();
    let ended = Box::pin(async move {
        let expiry = async {
            match exp {
                Some(exp) => {
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs() as i64;
                    tokio::time::sleep(std::time::Duration::from_secs((exp - now).max(0) as u64))
                        .await
                }
                None => std::future::pending().await,
            }
        };
        tokio::select! {
            Ok(status) = abort_rx => status,
            _ = expiry => tonic::Status::unauthenticated(""),
        }
    });

    let (tx, rx) = tokio::sync::mpsc::channel::<Result<bytes::Bytes, std::io::Error>>(16);
    let auth = Arc::clone(&proxy.auth);
    let checked_path = path.clone();
    let plain = plain_path.clone();
    tokio::spawn(async move {
        if tx.send(Ok(first_frame)).await.is_err() {
            return;
        }
        loop {
            let frame = match frames.next().await {
                Ok(Some(frame)) => frame,
                Ok(None) => return,
                Err(status) => {
                    let _ = abort_tx.send(status);
                    let _ = tx
                        .send(Err(std::io::Error::other("request body refused")))
                        .await;
                    return;
                }
            };
            let checked = match check(&auth, route, &plain, &frame, auth_header.as_deref()).await {
                Ok(()) => match &mcp_tenant {
                    Some(tenant) => stamped(frame, tenant),
                    None => Ok(frame),
                },
                Err(status) => Err(status),
            };
            let frame = match checked {
                Ok(frame) => frame,
                Err(status) => {
                    tracing::warn!(path = %checked_path, code = ?status.code(), error = %status.message(), "rotating leg envelope refused");
                    let _ = abort_tx.send(status);
                    let _ = tx
                        .send(Err(std::io::Error::other("request body refused")))
                        .await;
                    return;
                }
            };
            if tx.send(Ok(frame)).await.is_err() {
                return;
            }
        }
    });

    let body = StreamingBody(Body::from_stream(ReceiverStream::new(rx)));
    let backend_req = Request::from_parts(parts, tonic::body::Body::new(body));

    if let Err(e) = channel.ready().await {
        tracing::error!(error = %e, service = service_id, path = %path, "gRPC proxy channel not ready");
        return tonic_status_to_response(tonic::Status::unavailable("backend not ready"));
    }
    match channel.call(backend_req).await {
        Ok(response) => {
            let (parts, body) = response.into_parts();
            let first = opening.then(|| FirstEnvelope {
                buffer: bytes::BytesMut::new(),
                sessions: Arc::clone(&proxy.sessions),
                plain_path,
                subject,
                endpoint,
            });
            Response::from_parts(
                parts,
                Body::new(LegBody {
                    inner: Body::new(body),
                    ended,
                    done: false,
                    first,
                    _leg: leg,
                }),
            )
        }
        Err(e) => {
            tracing::error!(error = %e, service = service_id, path = %path, "gRPC proxy error");
            tonic_status_to_response(tonic::Status::unavailable("backend unavailable"))
        }
    }
}

/// One envelope after a leg's first, checked as the plain method's frames
/// are: well formed, the token still good, a payload valid as the plain
/// method's request.
async fn check(
    auth: &crate::auth::GatewayAuth,
    route: &'static RouteInfo,
    plain_path: &str,
    frame: &[u8],
    auth_header: Option<&str>,
) -> Result<(), tonic::Status> {
    let envelope = decode(frame)?;
    if envelope.malformed() {
        return Err(tonic::Status::invalid_argument("malformed rotation envelope"));
    }
    let target_namespace = if envelope.is_message() {
        gateway_model::s2sm::proxy_dispatch::validate_request(plain_path, &envelope.payload)?;
        gateway_model::s2sm::proxy_dispatch::request_target_namespace(
            plain_path,
            &envelope.payload,
        )?
    } else {
        None
    };
    let (service_id, entitlement_service) = route_identity(route);
    let checked = match target_namespace.as_deref() {
        Some(namespace) => {
            auth.validate_c2s_with_target_namespace(
                route.auth_policy,
                service_id,
                entitlement_service,
                plain_path,
                auth_header,
                Some(namespace),
            )
            .await
        }
        None => {
            auth.validate_c2s(
                route.auth_policy,
                service_id,
                entitlement_service,
                plain_path,
                auth_header,
            )
            .await
        }
    };
    checked.map_err(|(code, _)| tonic::Status::new(status_code_to_tonic(code), ""))
}

/// One envelope after a leg's first, on the rotating sibling of a
/// tenant-owned service's MCP carrier: a message's payload stamped with the
/// session's `tenant` (`proxy_grpc::stamp_mcp_tenant`), or refused.
fn stamped(frame: bytes::Bytes, tenant: &str) -> Result<bytes::Bytes, tonic::Status> {
    let mut envelope = decode(&frame)?;
    if !envelope.is_message() {
        return Ok(frame);
    }
    envelope.payload = stamp_mcp_tenant(&envelope.payload, tenant)?;
    Ok(bytes::Bytes::from(frame_grpc(&prost::Message::encode_to_vec(
        &envelope,
    ))))
}

/// Reads a new session's id off the backend's first envelope.
struct FirstEnvelope {
    buffer: bytes::BytesMut,
    sessions: Arc<Sessions>,
    plain_path: String,
    subject: Option<Subject>,
    endpoint: String,
}

impl FirstEnvelope {
    /// Feeds the response's next bytes. `Some` once the first message is in
    /// (with its leg if it named a session), or it is not one this can read.
    fn feed(&mut self, data: &[u8]) -> Option<Option<Leg>> {
        self.buffer.extend_from_slice(data);
        if self.buffer.len() < 5 {
            return None;
        }
        let len = u32::from_be_bytes([self.buffer[1], self.buffer[2], self.buffer[3], self.buffer[4]])
            as usize;
        if self.buffer[0] != 0 || len > MAX_FIRST_ENVELOPE_BYTES {
            return Some(None);
        }
        if self.buffer.len() < 5 + len {
            return None;
        }
        let leg = match decode(&self.buffer[..5 + len]) {
            Ok(first) if !first.session_id.is_empty() => {
                let leg = self.sessions.open(
                    &first.session_id,
                    &self.plain_path,
                    self.subject.take(),
                    &self.endpoint,
                );
                if leg.is_none() {
                    tracing::warn!(path = %self.plain_path, "a backend issued a session id already in use; not recorded");
                }
                leg
            }
            _ => None,
        };
        Some(leg)
    }
}

/// A leg's response body: the backend's, passed through unchanged, until the
/// gateway ends the leg itself (the trailers of `ended`). Holds the leg, so
/// the session is forgotten when its last leg's response ends.
struct LegBody {
    inner: Body,
    ended: Pin<Box<dyn Future<Output = tonic::Status> + Send>>,
    done: bool,
    first: Option<FirstEnvelope>,
    _leg: Option<Leg>,
}

impl http_body::Body for LegBody {
    type Data = bytes::Bytes;
    type Error = axum::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = self.get_mut();
        if this.done {
            return Poll::Ready(None);
        }
        if let Poll::Ready(status) = this.ended.as_mut().poll(cx) {
            this.done = true;
            let mut trailers = http::HeaderMap::new();
            trailers.insert(
                "grpc-status",
                http::HeaderValue::from(status.code() as i32),
            );
            if !status.message().is_empty() {
                if let Ok(message) = http::HeaderValue::from_str(status.message()) {
                    trailers.insert("grpc-message", message);
                }
            }
            return Poll::Ready(Some(Ok(Frame::trailers(trailers))));
        }
        match Pin::new(&mut this.inner).poll_frame(cx) {
            Poll::Ready(Some(Ok(frame))) => {
                if let (Some(data), Some(first)) = (frame.data_ref(), this.first.as_mut()) {
                    if let Some(leg) = first.feed(data) {
                        this.first = None;
                        this._leg = leg;
                    }
                }
                Poll::Ready(Some(Ok(frame)))
            }
            Poll::Ready(None) => {
                this.done = true;
                Poll::Ready(None)
            }
            other => other,
        }
    }
}

// ── W2S legs (#67) ──────────────────────────────────────────────────────────

/// What a W2S leg receives from the backend.
pub(crate) enum Received {
    /// One message of the plain method's response type.
    Message(Vec<u8>),
    /// The backend's `last`: it has moved to the session's next leg, and
    /// nothing more comes on this one.
    Last,
}

/// One leg of a rotating session that the gateway opens itself, as the
/// sibling's client, for a W2S stream (#67). It goes through `handle` as any
/// leg does, so the same token check, routing by session id, same-subject
/// admission and per-envelope validation apply; the payloads, and the
/// `trace_id` in them, reach the backend unchanged.
///
/// The request body stays open as long as the leg is held: the sibling's
/// client half-closes the logical stream with `fin`, never by ending a leg's
/// body (a leg that ends without its `last` ends the logical stream).
pub(crate) struct W2sLeg {
    tx: tokio::sync::mpsc::Sender<Result<bytes::Bytes, std::io::Error>>,
    frames: Frames,
    session_id: String,
}

fn envelope_frame(envelope: &Envelope) -> bytes::Bytes {
    bytes::Bytes::from(frame_grpc(&prost::Message::encode_to_vec(envelope)))
}

impl W2sLeg {
    /// Opens a leg of the sibling of `route` (a plain streaming method) with
    /// `auth_header`: of a new session when `session_id` is empty, else a
    /// rotation onto it. `Ok` once the backend's first envelope has named the
    /// session; a refusal is the leg's status (`UNIMPLEMENTED` from a backend
    /// without the sibling, or for a method with none through the gateway).
    pub(crate) async fn open(
        proxy: &ProxyState,
        route: &'static RouteInfo,
        auth_header: Option<&str>,
        request_id: &str,
        session_id: &str,
    ) -> Result<Self, tonic::Status> {
        let (service, method) = route
            .grpc_path
            .strip_prefix('/')
            .and_then(|path| path.split_once('/'))
            .ok_or_else(|| tonic::Status::unimplemented(""))?;
        let sibling = format!("/{service}{SIBLING_SUFFIX}/{method}");

        let (tx, rx) = tokio::sync::mpsc::channel(16);
        let opening = Envelope {
            session_id: session_id.to_string(),
            ..Default::default()
        };
        tx.send(Ok(envelope_frame(&opening)))
            .await
            .map_err(|_| tonic::Status::internal("the leg's body is gone"))?;
        let mut builder = Request::builder()
            .method(http::Method::POST)
            .uri(sibling)
            .header("content-type", "application/grpc+proto")
            .header("te", "trailers");
        if let Some(auth) = auth_header {
            builder = builder.header("authorization", auth);
        }
        if let Ok(id) = http::HeaderValue::from_str(request_id) {
            builder = builder.header("x-request-id", id);
        }
        let request = builder
            .body(Body::from_stream(ReceiverStream::new(rx)))
            .map_err(|e| tonic::Status::internal(format!("failed to build the leg: {e}")))?;

        let response = handle(proxy, request, route, route.grpc_path.to_string()).await;
        if let Some(status) = tonic::Status::from_header_map(response.headers()) {
            if status.code() != tonic::Code::Ok {
                return Err(status);
            }
        }
        let mut frames = Frames::new(response.into_body());
        let first = match tokio::time::timeout(OPEN_TIMEOUT, frames.next()).await {
            Ok(Ok(Some(frame))) => decode(&frame)?,
            Ok(Ok(None)) => {
                return Err(frames
                    .failed()
                    .unwrap_or_else(|| tonic::Status::unavailable("the leg ended before it opened")))
            }
            Ok(Err(status)) => return Err(status),
            Err(_) => return Err(tonic::Status::deadline_exceeded("the leg did not open in time")),
        };
        if first.session_id.is_empty()
            || !first.opens_a_leg()
            || (!session_id.is_empty() && first.session_id != session_id)
        {
            return Err(tonic::Status::internal(
                "the backend's first envelope names no session",
            ));
        }
        Ok(Self {
            tx,
            frames,
            session_id: first.session_id,
        })
    }

    /// The session this leg carries.
    pub(crate) fn session_id(&self) -> &str {
        &self.session_id
    }

    /// Sends one message of the plain method's request type. A leg the
    /// backend or the gateway has ended takes nothing; `next` says how it
    /// ended.
    pub(crate) fn send_message(
        &self,
        payload: Vec<u8>,
    ) -> impl Future<Output = ()> + Send + 'static {
        self.send(Envelope {
            payload,
            ..Default::default()
        })
    }

    /// The client's half-close of the logical stream.
    pub(crate) fn send_fin(&self) -> impl Future<Output = ()> + Send + 'static {
        self.send(Envelope {
            fin: true,
            ..Default::default()
        })
    }

    /// The client's cut-over: the session's next leg is admitted, and nothing
    /// more is sent on this one.
    pub(crate) fn send_last(&self) -> impl Future<Output = ()> + Send + 'static {
        self.send(Envelope {
            last: true,
            ..Default::default()
        })
    }

    /// The future holds a sender of its own, not the leg: a leg is not
    /// `Sync` (its response body), and the carriers' futures must be `Send`.
    fn send(&self, envelope: Envelope) -> impl Future<Output = ()> + Send + 'static {
        let tx = self.tx.clone();
        let frame = envelope_frame(&envelope);
        async move {
            let _ = tx.send(Ok(frame)).await;
        }
    }

    /// The backend's next envelope; `None` once the leg has ended OK (the
    /// logical stream's end), the leg's status if it ended in an error.
    pub(crate) async fn next(&mut self) -> Result<Option<Received>, tonic::Status> {
        let Some(frame) = self.frames.next().await? else {
            return match self.frames.failed() {
                Some(status) => Err(status),
                None => Ok(None),
            };
        };
        let envelope = decode(&frame)?;
        if envelope.is_message() {
            Ok(Some(Received::Message(envelope.payload)))
        } else if envelope.last && !envelope.malformed() {
            Ok(Some(Received::Last))
        } else {
            Err(tonic::Status::internal(
                "malformed rotation envelope from the backend",
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Subjects come off verified claims; auth.rs pins what makes two
    /// distinct, and two distinct ones are all this needs.
    fn subject_of(who: &str) -> Option<Subject> {
        Some(Subject::named(who))
    }

    #[test]
    fn a_sibling_path_names_its_plain_method() {
        assert!(plain_route("/pkg.SvcRotating").is_none());
        assert!(plain_route("/pkg.Rotating/").is_none());
        assert!(plain_route("/pkg.Svc/Method").is_none(), "not a sibling");
        // A unary method has no sibling: its Rotating path is unknown.
        let unary = gateway_model::s2sm::rest_dispatch::ROUTES
            .iter()
            .find(|r| !r.client_streaming && !r.server_streaming)
            .expect("a unary route");
        let (pkg_svc, method) = unary.grpc_path[1..].split_once('/').expect("path");
        assert!(plain_route(&format!("/{pkg_svc}Rotating/{method}")).is_none());
        // A streaming method's does.
        let streaming = gateway_model::s2sm::rest_dispatch::ROUTES
            .iter()
            .find(|r| r.client_streaming || r.server_streaming)
            .expect("a streaming route");
        let (pkg_svc, method) = streaming.grpc_path[1..].split_once('/').expect("path");
        let (plain, route) =
            plain_route(&format!("/{pkg_svc}Rotating/{method}")).expect("a sibling");
        assert_eq!(plain, streaming.grpc_path);
        assert_eq!(route.grpc_path, streaming.grpc_path);
    }

    #[test]
    fn a_session_is_forgotten_with_its_last_leg() {
        let sessions = Arc::new(Sessions::default());
        let opening = sessions
            .open("s-1", "/p.S/M", subject_of("alice"), "10.0.0.1:443")
            .expect("a new id");
        assert!(
            sessions.open("s-1", "/p.S/M", None, "10.0.0.2:443").is_none(),
            "an id in use is never rebound to another instance"
        );
        let (endpoint, rotated) = sessions
            .join("s-1", "/p.S/M", &subject_of("alice"))
            .expect("the same subject rotates");
        assert_eq!(endpoint, "10.0.0.1:443", "the instance that issued it");
        assert_eq!(
            sessions.join("s-1", "/p.S/M", &subject_of("bob")).err(),
            Some(tonic::Code::PermissionDenied),
            "another subject's token with a valid id"
        );
        assert_eq!(
            sessions.join("s-1", "/p.S/M", &None).err(),
            Some(tonic::Code::PermissionDenied),
            "no subject is not the session's subject"
        );
        assert_eq!(
            sessions.join("s-1", "/p.S/Other", &subject_of("alice")).err(),
            Some(tonic::Code::PermissionDenied),
            "another method's session"
        );
        drop(opening);
        assert_eq!(sessions.len(), 1, "the rotated leg still carries it");
        drop(rotated);
        assert_eq!(sessions.len(), 0);
        assert_eq!(
            sessions.join("s-1", "/p.S/M", &subject_of("alice")).err(),
            Some(tonic::Code::Unauthenticated),
            "an ended session is unknown"
        );
    }

    #[test]
    fn a_new_carrier_cuts_the_one_before_over() {
        let sessions = Arc::new(Sessions::default());
        let mut first = sessions.carry("s-1");
        assert!(first.cut_over.try_recv().is_err(), "nothing to cut over yet");
        let mut second = sessions.carry("s-1");
        assert!(first.cut_over.try_recv().is_ok(), "the next leg is admitted");
        drop(first);
        assert_eq!(
            sessions.carriers.lock().unwrap().len(),
            1,
            "the carrier before lets go of nothing the next one holds"
        );
        assert!(second.cut_over.try_recv().is_err());
        drop(second);
        assert!(sessions.carriers.lock().unwrap().is_empty());
    }

    #[test]
    fn envelopes_are_well_formed_or_refused() {
        assert!(Envelope::default().opens_a_leg());
        assert!(Envelope { session_id: "s".into(), ..Default::default() }.opens_a_leg());
        assert!(!Envelope { payload: vec![1], ..Default::default() }.opens_a_leg());
        assert!(!Envelope { last: true, ..Default::default() }.opens_a_leg());

        assert!(!Envelope { payload: vec![1], ..Default::default() }.malformed());
        assert!(!Envelope { last: true, ..Default::default() }.malformed());
        assert!(!Envelope { fin: true, ..Default::default() }.malformed());
        assert!(Envelope { session_id: "s".into(), ..Default::default() }.malformed());
        assert!(Envelope { cursor: vec![1], ..Default::default() }.malformed());
        assert!(Envelope { last: true, payload: vec![1], ..Default::default() }.malformed());
    }
}
