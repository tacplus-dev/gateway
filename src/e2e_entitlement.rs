// End-to-end proof, over real sockets, that a caller's entitlements decide
// whether a proxied gRPC call reaches the backend.
//
// What is real here:
//
//   * a real tonic gRPC server — the GENERATED stratum RecordQuery server, the
//     c2s half of the record query plane — listening on a real TCP port;
//   * the real `proxy_grpc::handle` on a second real TCP port, reached over
//     HTTP/2 by a real generated tonic client;
//   * the real `GatewayAuth` over a real `JwkCache`, verifying real ECDSA-signed
//     JWTs, resolving grants through the real generated `grants` catalog;
//   * the real `Resolver`, dialing the backend from its endpoint table.
//
// What is stood in for, none of it on the decision path: the endpoint table and
// the JWK set (both normally streamed from kernel), and the gateway→backend hop
// is plaintext h2c rather than SPIFFE-pinned TLS (`Resolver::plaintext_backends`)
// — the authorization decision is made before any dial and does not depend on
// the transport.
//
// Both halves are asserted in ONE run so neither can be quietly true alone: the
// entitled caller SUCCEEDS through the gateway, the unentitled caller is DENIED.
// Both tokens are non-admin — `service_entitlements` carries a `grants` list and
// never `{"all": true}`, because the admin bypass in auth.rs is checked ahead of
// everything under test and would prove nothing.

use std::collections::HashMap;
use std::sync::Arc;

use tokio::net::TcpListener;
use tokio_stream::wrappers::{ReceiverStream, TcpListenerStream};

use gateway_grpcserver::authorizer::JwkCache;
use gateway_jwk::jwk::{ImmutableJwk, Jwk};
use gateway_key::{base64_utils, keys};
use gateway_servicemanager::SpiffeServerCertVerifier;
use gateway_token::token::Token;
use gateway_x509::x509::{ImmutableCertChain, X509KeyUsage};

use gateway_model::types::vservices::query::query as stratum_pb;
use stratum_pb::record_map_client::RecordMapClient;
use stratum_pb::record_query_client::RecordQueryClient;
use stratum_pb::record_query_server::{RecordQuery, RecordQueryServer};

use crate::auth::GatewayAuth;
use crate::health::{HealthWatcher, ServiceEndpoint};
use crate::proxy_grpc::{self, ProxyState};
use crate::resolver::Resolver;

const TRUST_DOMAIN: &str = "e2e.test";
const BACKEND_SERVICE: &str = "stratum";
const HANDLE_ID: &str = "handle-from-the-real-backend";

// ── the backend ─────────────────────────────────────────────────────────────

/// The generated stratum RecordQuery service. Only the method under test does
/// anything; every other method answers `unimplemented` so a mistaken route
/// shows up as a distinct failure rather than a silent success.
struct RecordQueryBackend;

type CountStream = ReceiverStream<Result<stratum_pb::RecordCount, tonic::Status>>;

#[tonic::async_trait]
impl RecordQuery for RecordQueryBackend {
    /// The method under test: the c2s entry point of the record query plane.
    async fn create_task_activity_query(
        &self,
        _request: tonic::Request<stratum_pb::OpenTaskActivityQueryRequest>,
    ) -> Result<tonic::Response<stratum_pb::QueryHandle>, tonic::Status> {
        Ok(tonic::Response::new(stratum_pb::QueryHandle {
            query_id: HANDLE_ID.to_string(),
            ..Default::default()
        }))
    }

    async fn create_agent_event_query(
        &self,
        _request: tonic::Request<stratum_pb::OpenAgentEventQueryRequest>,
    ) -> Result<tonic::Response<stratum_pb::QueryHandle>, tonic::Status> {
        Err(tonic::Status::unimplemented("create_agent_event_query"))
    }

    async fn get_agent_event_count(
        &self,
        _request: tonic::Request<stratum_pb::QueryHandle>,
    ) -> Result<tonic::Response<stratum_pb::RecordCount>, tonic::Status> {
        Err(tonic::Status::unimplemented("get_agent_event_count"))
    }

    async fn get_agent_event_sample(
        &self,
        _request: tonic::Request<stratum_pb::SampleAgentEventRequest>,
    ) -> Result<tonic::Response<stratum_pb::SampleAgentEventResponse>, tonic::Status> {
        Err(tonic::Status::unimplemented("get_agent_event_sample"))
    }

    async fn list_agent_event(
        &self,
        _request: tonic::Request<stratum_pb::PullAgentEventRequest>,
    ) -> Result<tonic::Response<stratum_pb::PullAgentEventResponse>, tonic::Status> {
        Err(tonic::Status::unimplemented("list_agent_event"))
    }

    async fn delete_agent_event_query(
        &self,
        _request: tonic::Request<stratum_pb::QueryHandle>,
    ) -> Result<tonic::Response<stratum_pb::QueryStats>, tonic::Status> {
        Err(tonic::Status::unimplemented("delete_agent_event_query"))
    }

    async fn update_agent_event_query(
        &self,
        _request: tonic::Request<stratum_pb::RefineAgentEventRequest>,
    ) -> Result<tonic::Response<stratum_pb::QueryStats>, tonic::Status> {
        Err(tonic::Status::unimplemented("update_agent_event_query"))
    }

    async fn get_task_activity_count(
        &self,
        _request: tonic::Request<stratum_pb::QueryHandle>,
    ) -> Result<tonic::Response<stratum_pb::RecordCount>, tonic::Status> {
        Err(tonic::Status::unimplemented("get_task_activity_count"))
    }

    async fn get_task_activity_sample(
        &self,
        _request: tonic::Request<stratum_pb::SampleTaskActivityRequest>,
    ) -> Result<tonic::Response<stratum_pb::SampleTaskActivityResponse>, tonic::Status> {
        Err(tonic::Status::unimplemented("get_task_activity_sample"))
    }

    async fn list_task_activity(
        &self,
        _request: tonic::Request<stratum_pb::PullTaskActivityRequest>,
    ) -> Result<tonic::Response<stratum_pb::PullTaskActivityResponse>, tonic::Status> {
        Err(tonic::Status::unimplemented("list_task_activity"))
    }

    async fn delete_task_activity_query(
        &self,
        _request: tonic::Request<stratum_pb::QueryHandle>,
    ) -> Result<tonic::Response<stratum_pb::QueryStats>, tonic::Status> {
        Err(tonic::Status::unimplemented("delete_task_activity_query"))
    }

    async fn update_task_activity_query(
        &self,
        _request: tonic::Request<stratum_pb::RefineTaskActivityRequest>,
    ) -> Result<tonic::Response<stratum_pb::QueryStats>, tonic::Status> {
        Err(tonic::Status::unimplemented("update_task_activity_query"))
    }

    type WatchAgentEventStream =
        ReceiverStream<Result<stratum_pb::AgentEventWatchEvent, tonic::Status>>;
    async fn watch_agent_event(
        &self,
        _request: tonic::Request<stratum_pb::QueryHandle>,
    ) -> Result<tonic::Response<Self::WatchAgentEventStream>, tonic::Status> {
        Err(tonic::Status::unimplemented("watch_agent_event"))
    }

    type SubscribeAgentEventCountStream = CountStream;
    async fn subscribe_agent_event_count(
        &self,
        _request: tonic::Request<stratum_pb::QueryHandle>,
    ) -> Result<tonic::Response<Self::SubscribeAgentEventCountStream>, tonic::Status> {
        Err(tonic::Status::unimplemented("subscribe_agent_event_count"))
    }

    type WatchTaskActivityStream =
        ReceiverStream<Result<stratum_pb::TaskActivityWatchEvent, tonic::Status>>;
    async fn watch_task_activity(
        &self,
        _request: tonic::Request<stratum_pb::QueryHandle>,
    ) -> Result<tonic::Response<Self::WatchTaskActivityStream>, tonic::Status> {
        Err(tonic::Status::unimplemented("watch_task_activity"))
    }

    type SubscribeTaskActivityCountStream = CountStream;
    async fn subscribe_task_activity_count(
        &self,
        _request: tonic::Request<stratum_pb::QueryHandle>,
    ) -> Result<tonic::Response<Self::SubscribeTaskActivityCountStream>, tonic::Status> {
        Err(tonic::Status::unimplemented("subscribe_task_activity_count"))
    }

    async fn create_accounting_record_query(
        &self,
        _request: tonic::Request<stratum_pb::OpenAccountingRecordQueryRequest>,
    ) -> Result<tonic::Response<stratum_pb::QueryHandle>, tonic::Status> {
        Err(tonic::Status::unimplemented("create_accounting_record_query"))
    }

    async fn get_accounting_record_count(
        &self,
        _request: tonic::Request<stratum_pb::QueryHandle>,
    ) -> Result<tonic::Response<stratum_pb::RecordCount>, tonic::Status> {
        Err(tonic::Status::unimplemented("get_accounting_record_count"))
    }

    async fn get_accounting_record_sample(
        &self,
        _request: tonic::Request<stratum_pb::SampleAccountingRecordRequest>,
    ) -> Result<tonic::Response<stratum_pb::SampleAccountingRecordResponse>, tonic::Status> {
        Err(tonic::Status::unimplemented("get_accounting_record_sample"))
    }

    async fn list_accounting_record(
        &self,
        _request: tonic::Request<stratum_pb::PullAccountingRecordRequest>,
    ) -> Result<tonic::Response<stratum_pb::PullAccountingRecordResponse>, tonic::Status> {
        Err(tonic::Status::unimplemented("list_accounting_record"))
    }

    async fn delete_accounting_record_query(
        &self,
        _request: tonic::Request<stratum_pb::QueryHandle>,
    ) -> Result<tonic::Response<stratum_pb::QueryStats>, tonic::Status> {
        Err(tonic::Status::unimplemented("delete_accounting_record_query"))
    }

    async fn update_accounting_record_query(
        &self,
        _request: tonic::Request<stratum_pb::RefineAccountingRecordRequest>,
    ) -> Result<tonic::Response<stratum_pb::QueryStats>, tonic::Status> {
        Err(tonic::Status::unimplemented("update_accounting_record_query"))
    }

    type WatchAccountingRecordStream =
        ReceiverStream<Result<stratum_pb::AccountingRecordWatchEvent, tonic::Status>>;
    async fn watch_accounting_record(
        &self,
        _request: tonic::Request<stratum_pb::QueryHandle>,
    ) -> Result<tonic::Response<Self::WatchAccountingRecordStream>, tonic::Status> {
        Err(tonic::Status::unimplemented("watch_accounting_record"))
    }

    type SubscribeAccountingRecordCountStream = CountStream;
    async fn subscribe_accounting_record_count(
        &self,
        _request: tonic::Request<stratum_pb::QueryHandle>,
    ) -> Result<tonic::Response<Self::SubscribeAccountingRecordCountStream>, tonic::Status> {
        Err(tonic::Status::unimplemented("subscribe_accounting_record_count"))
    }

    async fn create_agent_session_state_query(
        &self,
        _request: tonic::Request<stratum_pb::OpenAgentSessionStateQueryRequest>,
    ) -> Result<tonic::Response<stratum_pb::QueryHandle>, tonic::Status> {
        Err(tonic::Status::unimplemented("create_agent_session_state_query"))
    }

    async fn get_agent_session_state_count(
        &self,
        _request: tonic::Request<stratum_pb::QueryHandle>,
    ) -> Result<tonic::Response<stratum_pb::RecordCount>, tonic::Status> {
        Err(tonic::Status::unimplemented("get_agent_session_state_count"))
    }

    async fn get_agent_session_state_sample(
        &self,
        _request: tonic::Request<stratum_pb::SampleAgentSessionStateRequest>,
    ) -> Result<tonic::Response<stratum_pb::SampleAgentSessionStateResponse>, tonic::Status> {
        Err(tonic::Status::unimplemented("get_agent_session_state_sample"))
    }

    async fn list_agent_session_state(
        &self,
        _request: tonic::Request<stratum_pb::PullAgentSessionStateRequest>,
    ) -> Result<tonic::Response<stratum_pb::PullAgentSessionStateResponse>, tonic::Status> {
        Err(tonic::Status::unimplemented("list_agent_session_state"))
    }

    async fn delete_agent_session_state_query(
        &self,
        _request: tonic::Request<stratum_pb::QueryHandle>,
    ) -> Result<tonic::Response<stratum_pb::QueryStats>, tonic::Status> {
        Err(tonic::Status::unimplemented("delete_agent_session_state_query"))
    }

    async fn update_agent_session_state_query(
        &self,
        _request: tonic::Request<stratum_pb::RefineAgentSessionStateRequest>,
    ) -> Result<tonic::Response<stratum_pb::QueryStats>, tonic::Status> {
        Err(tonic::Status::unimplemented("update_agent_session_state_query"))
    }

    type WatchAgentSessionStateStream =
        ReceiverStream<Result<stratum_pb::AgentSessionStateWatchEvent, tonic::Status>>;
    async fn watch_agent_session_state(
        &self,
        _request: tonic::Request<stratum_pb::QueryHandle>,
    ) -> Result<tonic::Response<Self::WatchAgentSessionStateStream>, tonic::Status> {
        Err(tonic::Status::unimplemented("watch_agent_session_state"))
    }

    type SubscribeAgentSessionStateCountStream = CountStream;
    async fn subscribe_agent_session_state_count(
        &self,
        _request: tonic::Request<stratum_pb::QueryHandle>,
    ) -> Result<tonic::Response<Self::SubscribeAgentSessionStateCountStream>, tonic::Status> {
        Err(tonic::Status::unimplemented("subscribe_agent_session_state_count"))
    }

    async fn create_mailbox_entry_query(
        &self,
        _request: tonic::Request<stratum_pb::OpenMailboxEntryQueryRequest>,
    ) -> Result<tonic::Response<stratum_pb::QueryHandle>, tonic::Status> {
        Err(tonic::Status::unimplemented("create_mailbox_entry_query"))
    }

    async fn get_mailbox_entry_count(
        &self,
        _request: tonic::Request<stratum_pb::QueryHandle>,
    ) -> Result<tonic::Response<stratum_pb::RecordCount>, tonic::Status> {
        Err(tonic::Status::unimplemented("get_mailbox_entry_count"))
    }

    async fn get_mailbox_entry_sample(
        &self,
        _request: tonic::Request<stratum_pb::SampleMailboxEntryRequest>,
    ) -> Result<tonic::Response<stratum_pb::SampleMailboxEntryResponse>, tonic::Status> {
        Err(tonic::Status::unimplemented("get_mailbox_entry_sample"))
    }

    async fn list_mailbox_entry(
        &self,
        _request: tonic::Request<stratum_pb::PullMailboxEntryRequest>,
    ) -> Result<tonic::Response<stratum_pb::PullMailboxEntryResponse>, tonic::Status> {
        Err(tonic::Status::unimplemented("list_mailbox_entry"))
    }

    async fn delete_mailbox_entry_query(
        &self,
        _request: tonic::Request<stratum_pb::QueryHandle>,
    ) -> Result<tonic::Response<stratum_pb::QueryStats>, tonic::Status> {
        Err(tonic::Status::unimplemented("delete_mailbox_entry_query"))
    }

    async fn update_mailbox_entry_query(
        &self,
        _request: tonic::Request<stratum_pb::RefineMailboxEntryRequest>,
    ) -> Result<tonic::Response<stratum_pb::QueryStats>, tonic::Status> {
        Err(tonic::Status::unimplemented("update_mailbox_entry_query"))
    }

    type WatchMailboxEntryStream =
        ReceiverStream<Result<stratum_pb::MailboxEntryWatchEvent, tonic::Status>>;
    async fn watch_mailbox_entry(
        &self,
        _request: tonic::Request<stratum_pb::QueryHandle>,
    ) -> Result<tonic::Response<Self::WatchMailboxEntryStream>, tonic::Status> {
        Err(tonic::Status::unimplemented("watch_mailbox_entry"))
    }

    type SubscribeMailboxEntryCountStream = CountStream;
    async fn subscribe_mailbox_entry_count(
        &self,
        _request: tonic::Request<stratum_pb::QueryHandle>,
    ) -> Result<tonic::Response<Self::SubscribeMailboxEntryCountStream>, tonic::Status> {
        Err(tonic::Status::unimplemented("subscribe_mailbox_entry_count"))
    }

    async fn create_message_query(
        &self,
        _request: tonic::Request<stratum_pb::OpenMessageQueryRequest>,
    ) -> Result<tonic::Response<stratum_pb::QueryHandle>, tonic::Status> {
        Err(tonic::Status::unimplemented("create_message_query"))
    }

    async fn get_message_count(
        &self,
        _request: tonic::Request<stratum_pb::QueryHandle>,
    ) -> Result<tonic::Response<stratum_pb::RecordCount>, tonic::Status> {
        Err(tonic::Status::unimplemented("get_message_count"))
    }

    async fn get_message_sample(
        &self,
        _request: tonic::Request<stratum_pb::SampleMessageRequest>,
    ) -> Result<tonic::Response<stratum_pb::SampleMessageResponse>, tonic::Status> {
        Err(tonic::Status::unimplemented("get_message_sample"))
    }

    async fn list_message(
        &self,
        _request: tonic::Request<stratum_pb::PullMessageRequest>,
    ) -> Result<tonic::Response<stratum_pb::PullMessageResponse>, tonic::Status> {
        Err(tonic::Status::unimplemented("list_message"))
    }

    async fn delete_message_query(
        &self,
        _request: tonic::Request<stratum_pb::QueryHandle>,
    ) -> Result<tonic::Response<stratum_pb::QueryStats>, tonic::Status> {
        Err(tonic::Status::unimplemented("delete_message_query"))
    }

    async fn update_message_query(
        &self,
        _request: tonic::Request<stratum_pb::RefineMessageRequest>,
    ) -> Result<tonic::Response<stratum_pb::QueryStats>, tonic::Status> {
        Err(tonic::Status::unimplemented("update_message_query"))
    }

    type WatchMessageStream =
        ReceiverStream<Result<stratum_pb::MessageWatchEvent, tonic::Status>>;
    async fn watch_message(
        &self,
        _request: tonic::Request<stratum_pb::QueryHandle>,
    ) -> Result<tonic::Response<Self::WatchMessageStream>, tonic::Status> {
        Err(tonic::Status::unimplemented("watch_message"))
    }

    type SubscribeMessageCountStream = CountStream;
    async fn subscribe_message_count(
        &self,
        _request: tonic::Request<stratum_pb::QueryHandle>,
    ) -> Result<tonic::Response<Self::SubscribeMessageCountStream>, tonic::Status> {
        Err(tonic::Status::unimplemented("subscribe_message_count"))
    }

    async fn create_delegation_probe_query(
        &self,
        _request: tonic::Request<stratum_pb::OpenDelegationProbeQueryRequest>,
    ) -> Result<tonic::Response<stratum_pb::QueryHandle>, tonic::Status> {
        Err(tonic::Status::unimplemented("create_delegation_probe_query"))
    }

    async fn get_delegation_probe_count(
        &self,
        _request: tonic::Request<stratum_pb::QueryHandle>,
    ) -> Result<tonic::Response<stratum_pb::RecordCount>, tonic::Status> {
        Err(tonic::Status::unimplemented("get_delegation_probe_count"))
    }

    async fn get_delegation_probe_sample(
        &self,
        _request: tonic::Request<stratum_pb::SampleDelegationProbeRequest>,
    ) -> Result<tonic::Response<stratum_pb::SampleDelegationProbeResponse>, tonic::Status> {
        Err(tonic::Status::unimplemented("get_delegation_probe_sample"))
    }

    async fn list_delegation_probe(
        &self,
        _request: tonic::Request<stratum_pb::PullDelegationProbeRequest>,
    ) -> Result<tonic::Response<stratum_pb::PullDelegationProbeResponse>, tonic::Status> {
        Err(tonic::Status::unimplemented("list_delegation_probe"))
    }

    async fn delete_delegation_probe_query(
        &self,
        _request: tonic::Request<stratum_pb::QueryHandle>,
    ) -> Result<tonic::Response<stratum_pb::QueryStats>, tonic::Status> {
        Err(tonic::Status::unimplemented("delete_delegation_probe_query"))
    }

    async fn update_delegation_probe_query(
        &self,
        _request: tonic::Request<stratum_pb::RefineDelegationProbeRequest>,
    ) -> Result<tonic::Response<stratum_pb::QueryStats>, tonic::Status> {
        Err(tonic::Status::unimplemented("update_delegation_probe_query"))
    }

    type WatchDelegationProbeStream =
        ReceiverStream<Result<stratum_pb::DelegationProbeWatchEvent, tonic::Status>>;
    async fn watch_delegation_probe(
        &self,
        _request: tonic::Request<stratum_pb::QueryHandle>,
    ) -> Result<tonic::Response<Self::WatchDelegationProbeStream>, tonic::Status> {
        Err(tonic::Status::unimplemented("watch_delegation_probe"))
    }

    type SubscribeDelegationProbeCountStream = CountStream;
    async fn subscribe_delegation_probe_count(
        &self,
        _request: tonic::Request<stratum_pb::QueryHandle>,
    ) -> Result<tonic::Response<Self::SubscribeDelegationProbeCountStream>, tonic::Status> {
        Err(tonic::Status::unimplemented("subscribe_delegation_probe_count"))
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

/// A non-admin user token: entitlements are a flat `grants` list, never
/// `{"all": true}` — the admin bypass sits ahead of everything under test.
fn user_token(key: &keys::ImmutableKey, grants: &[&str]) -> String {
    let mut token = Token::new();
    token.set_kid(key.id()).expect("kid");
    token.set_alg(key.alg()).expect("alg");
    token.set_issuer("e2e-test").expect("iss");
    token.set_subject("alice@example.com").expect("sub");
    token.set_audience(BACKEND_SERVICE).expect("aud");
    token.set_namespace("acme").expect("ns");
    token.set_expiration(unix_now() + 3600).expect("exp");
    token.set_sub_type("user").expect("sub_type");
    token
        .set_service_entitlements(serde_json::json!({ "grants": grants }))
        .expect("service_entitlements");
    token.sign(key).expect("sign");
    format!("Bearer {}", token.base64().expect("base64"))
}

// ── wiring ──────────────────────────────────────────────────────────────────

async fn spawn_backend() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind backend");
    let addr = listener.local_addr().expect("backend addr");
    tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(RecordQueryServer::new(RecordQueryBackend))
            .serve_with_incoming(TcpListenerStream::new(listener))
            .await
            .expect("backend serve");
    });
    addr.to_string()
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

/// A verifier the plaintext test path never consults; it exists only because
/// Resolver holds one. Its root is a throwaway self-signed cert, since
/// WebPkiServerVerifier refuses to build with no anchors at all.
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

async fn call_through_gateway(
    gateway_uri: &str,
    bearer: &str,
) -> Result<stratum_pb::QueryHandle, tonic::Status> {
    let channel = tonic::transport::Endpoint::from_shared(gateway_uri.to_string())
        .expect("endpoint")
        .connect()
        .await
        .expect("connect to gateway");
    let mut client = RecordQueryClient::new(channel);
    let mut request = tonic::Request::new(stratum_pb::OpenTaskActivityQueryRequest::default());
    request.metadata_mut().insert(
        "authorization",
        bearer.parse().expect("authorization metadata"),
    );
    client
        .create_task_activity_query(request)
        .await
        .map(|r| r.into_inner())
}

// ── the run ─────────────────────────────────────────────────────────────────

/// Both halves, one run, one socket pair.
#[tokio::test]
async fn stratum_c2s_query_is_allowed_with_entitlement_and_denied_without() {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let backend_addr = spawn_backend().await;
    let (host, port) = backend_addr.rsplit_once(':').expect("host:port");
    let mut endpoints = HashMap::new();
    endpoints.insert(
        BACKEND_SERVICE.to_string(),
        vec![ServiceEndpoint {
            host: host.to_string(),
            port: port.parse().expect("port"),
        }],
    );
    let resolver = Arc::new(Resolver::plaintext_backends(
        HealthWatcher::seeded(endpoints),
        unused_verifier(),
    ));

    let signing_key = keys::generate_ec_p256_key().expect("signing key");
    let auth = Arc::new(GatewayAuth::new(
        Arc::new(JwkCache::seeded(vec![jwk_for(&signing_key)])),
        false,
    ));

    let proxy = Arc::new(ProxyState {
        resolver,
        auth,
        // stratum is not tenant-owned; this test routes by name, as before.
        tenant_owned: Arc::new(Default::default()),
        trace_publisher: Arc::new(|_| {}),
        trace_round: Box::new(Default::default),
    });
    let gateway_uri = spawn_gateway(proxy).await;

    // Half 1 — entitled caller. QUERY_ANY is the wildcard opa mints today; it
    // is a real grant only because the c2s sibling put query in the catalog.
    // The token names the route's entitlement_service ("query"), not its
    // service_id ("stratum") — those are separate identities.
    let entitled = user_token(&signing_key, &["QUERY_ANY"]);
    let handle = call_through_gateway(&gateway_uri, &entitled)
        .await
        .unwrap_or_else(|e| panic!("entitled caller must reach the backend, got {e:?}"));
    assert_eq!(
        handle.query_id, HANDLE_ID,
        "the response must have come from the real backend, not from the gateway"
    );

    // Half 2 — same method, same sockets, a caller entitled to something else.
    let unentitled = user_token(&signing_key, &["TASKS_ANY"]);
    let denied = call_through_gateway(&gateway_uri, &unentitled)
        .await
        .expect_err("unentitled caller must be denied");
    assert_eq!(
        denied.code(),
        tonic::Code::PermissionDenied,
        "unentitled caller must be denied at the gateway: {denied:?}"
    );

    // The s2s twin of the same query, with the SAME token that just succeeded on
    // the c2s half. RecordMap is not in the generated ROUTES table, so the
    // gateway must refuse to proxy it rather than fall through to an entitlement
    // check — the fix in proxy_grpc. This is what keeps the split meaningful:
    // STRATUM_ANY being a real grant must not open the peer-only surface.
    let channel = tonic::transport::Endpoint::from_shared(gateway_uri.clone())
        .expect("endpoint")
        .connect()
        .await
        .expect("connect to gateway");
    let mut map_client = RecordMapClient::new(channel);
    let mut request = tonic::Request::new(stratum_pb::OpenTaskActivityQueryRequest::default());
    request.metadata_mut().insert(
        "authorization",
        entitled.parse().expect("authorization metadata"),
    );
    let unrouted = map_client
        .create_task_activity_query(request)
        .await
        .expect_err("an unrouted gRPC path must not be proxied");
    assert_eq!(
        unrouted.code(),
        tonic::Code::NotFound,
        "unrouted path must be rejected, not entitlement-checked: {unrouted:?}"
    );
}
