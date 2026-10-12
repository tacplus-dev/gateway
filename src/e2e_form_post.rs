// End-to-end proof, over real sockets, that an identity provider's form_post
// callback gets through the gateway: Sign in with Apple POSTs
// application/x-www-form-urlencoded to /oauth/Auth/BrokerFormPostCallback and
// the browser must be sent on with a 303, not answered JSON.
//
// What is real here:
//
//   * the gateway's unary REST leg, `rest_translation::dispatch_unary`, entered
//     with the generated ROUTES entry for the route, so the `form_body` and
//     `redirect_field` it acts on are the ones tacplus emitted from
//     `(spec.rest_browser)`;
//   * the real `proxy_grpc::handle` and `Resolver` behind it;
//   * a real `oauth.Auth` tonic server, the GENERATED `AuthServer`, on its own
//     real port, which records the request it decoded.
//
// What is not: the oauth service itself. `AuthStandIn` answers the callback
// with a fixed redirect; oauth's own tests cover what the redirect is.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use axum::http::{header, HeaderValue, StatusCode};
use tokio::net::TcpListener;
use tokio_stream::wrappers::TcpListenerStream;

use gateway_grpcserver::authorizer::JwkCache;
use gateway_key::keys;
use gateway_model::s2sm::rest_dispatch::{RouteInfo, ROUTES};
use gateway_model::types::services::oauth::oauth as oauth_pb;
use gateway_model::types::sys::mcp::mcp::{McpRequest, McpResponse};
use gateway_model::types::sys::trace::trace::TraceRequest;
use gateway_servicemanager::SpiffeServerCertVerifier;
use gateway_x509::x509::{ImmutableCertChain, X509KeyUsage};
use oauth_pb::auth_server::{Auth, AuthServer};

use crate::auth::GatewayAuth;
use crate::health::{HealthWatcher, ServiceEndpoint};
use crate::proxy_grpc::ProxyState;
use crate::rest_translation::dispatch_unary;

const TRUST_DOMAIN: &str = "form-post-e2e.test";
const CALLBACK_GRPC_PATH: &str = "/oauth.Auth/BrokerFormPostCallback";
const FORM: &str = "application/x-www-form-urlencoded";
const REDIRECT_URL: &str = "https://console.example/signin/callback?code=c1&state=s2";

// ── the backend ─────────────────────────────────────────────────────────────

/// Answers the form_post callback with REDIRECT_URL and keeps the request it
/// received; a state of "refuse" is answered INVALID_ARGUMENT instead. Every
/// other Auth method is unimplemented: nothing here calls one.
#[derive(Clone, Default)]
struct AuthStandIn {
    last: Arc<Mutex<Option<oauth_pb::FormPostCallbackRequest>>>,
}

fn unused() -> tonic::Status {
    tonic::Status::unimplemented("not part of this test")
}

#[tonic::async_trait]
impl Auth for AuthStandIn {
    async fn list_providers(
        &self,
        _: tonic::Request<TraceRequest>,
    ) -> Result<tonic::Response<oauth_pb::ListProvidersResponse>, tonic::Status> {
        Err(unused())
    }

    async fn authorize(
        &self,
        _: tonic::Request<oauth_pb::AuthorizeRequest>,
    ) -> Result<tonic::Response<oauth_pb::AuthorizeResponse>, tonic::Status> {
        Err(unused())
    }

    async fn classify_sign_in_email(
        &self,
        _: tonic::Request<oauth_pb::ClassifySignInEmailRequest>,
    ) -> Result<tonic::Response<oauth_pb::ClassifySignInEmailResponse>, tonic::Status> {
        Err(unused())
    }

    async fn mint_callback_tokens(
        &self,
        _: tonic::Request<oauth_pb::CallbackRequest>,
    ) -> Result<tonic::Response<oauth_pb::CallbackResponse>, tonic::Status> {
        Err(unused())
    }

    async fn revoke_session(
        &self,
        _: tonic::Request<oauth_pb::LogoutRequest>,
    ) -> Result<tonic::Response<oauth_pb::LogoutResponse>, tonic::Status> {
        Err(unused())
    }

    async fn broker_cli_auth(
        &self,
        _: tonic::Request<oauth_pb::CompleteCliAuthRequest>,
    ) -> Result<tonic::Response<oauth_pb::CompleteCliAuthResponse>, tonic::Status> {
        Err(unused())
    }

    async fn broker_form_post_callback(
        &self,
        request: tonic::Request<oauth_pb::FormPostCallbackRequest>,
    ) -> Result<tonic::Response<oauth_pb::FormPostCallbackResponse>, tonic::Status> {
        let request = request.into_inner();
        let refuse = request.state == "refuse";
        *self.last.lock().unwrap() = Some(request);
        if refuse {
            return Err(tonic::Status::invalid_argument("refused by the test backend"));
        }
        Ok(tonic::Response::new(oauth_pb::FormPostCallbackResponse {
            redirect_url: REDIRECT_URL.to_string(),
            ..Default::default()
        }))
    }

    type BrokerAuthMcpSessionStream =
        tokio_stream::Empty<Result<McpResponse, tonic::Status>>;

    async fn broker_auth_mcp_session(
        &self,
        _: tonic::Request<tonic::Streaming<McpRequest>>,
    ) -> Result<tonic::Response<Self::BrokerAuthMcpSessionStream>, tonic::Status> {
        Err(unused())
    }
}

// ── wiring ──────────────────────────────────────────────────────────────────

/// A verifier the plaintext test path never consults; `Resolver` just holds one,
/// and `WebPkiServerVerifier` refuses to build with no anchors at all.
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

async fn spawn_oauth(backend: AuthStandIn) -> ServiceEndpoint {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind oauth");
    let addr = listener.local_addr().expect("oauth addr");
    tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(AuthServer::new(backend))
            .serve_with_incoming(TcpListenerStream::new(listener))
            .await
            .expect("oauth serve");
    });
    ServiceEndpoint {
        host: addr.ip().to_string(),
        port: addr.port() as i32,
    }
}

/// A gateway with `oauth` in its endpoint table and nothing else. The JWK cache
/// is empty: the callback is a NoAuth route and presents no token.
async fn proxy_with_oauth() -> (ProxyState, AuthStandIn) {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let backend = AuthStandIn::default();
    let mut endpoints = HashMap::new();
    endpoints.insert("oauth".to_string(), vec![spawn_oauth(backend.clone()).await]);
    let proxy = ProxyState {
        resolver: Arc::new(crate::resolver::Resolver::plaintext_backends(
            HealthWatcher::seeded(endpoints),
            unused_verifier(),
        )),
        auth: Arc::new(GatewayAuth::new(Arc::new(JwkCache::seeded(vec![])), false)),
        tenant_owned: Arc::new(Default::default()),
        trace_publisher: Arc::new(|_| {}),
        trace_round: Box::new(Default::default),
    };
    (proxy, backend)
}

fn callback_route() -> &'static RouteInfo {
    ROUTES
        .iter()
        .find(|r| r.grpc_path == CALLBACK_GRPC_PATH)
        .expect("the generated ROUTES table must carry the form_post callback")
}

async fn call(proxy: &ProxyState, content_type: &str, body: &[u8]) -> axum::response::Response {
    dispatch_unary(
        proxy,
        callback_route(),
        Some(&HeaderValue::from_str(content_type).unwrap()),
        body.to_vec(),
        None,
        "req-form-post",
    )
    .await
}

// ── the runs ────────────────────────────────────────────────────────────────

#[test]
fn the_callback_route_is_a_browser_form_target() {
    let route = callback_route();
    assert_eq!(route.http_path, "/oauth/Auth/BrokerFormPostCallback");
    assert!(route.form_body, "(spec.rest_browser).form_body not in ROUTES");
    assert_eq!(route.redirect_field, Some("redirectUrl"));
}

/// Apple's POST: a form body, decoded into the request message, answered with
/// a 303 to the response's redirect_url.
#[tokio::test]
async fn a_form_post_is_answered_with_a_303_to_the_redirect_url() {
    let (proxy, backend) = proxy_with_oauth().await;

    let response = call(
        &proxy,
        "application/x-www-form-urlencoded; charset=UTF-8",
        b"code=c%2Fd&state=st%2Bate&id_token=eyJ.a.b&user=%7B%22name%22%3A%7B%22firstName%22%3A%22Ada%22%7D%7D",
    )
    .await;

    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        response.headers().get(header::LOCATION).map(|v| v.to_str().unwrap()),
        Some(REDIRECT_URL)
    );
    assert_eq!(
        response.headers().get(header::CACHE_CONTROL).map(|v| v.to_str().unwrap()),
        Some("no-store")
    );

    let got = backend.last.lock().unwrap().clone().expect("the form post never reached oauth");
    assert_eq!(got.code, "c/d");
    assert_eq!(got.state, "st+ate");
    assert_eq!(got.id_token, "eyJ.a.b");
    assert_eq!(got.user, r#"{"name":{"firstName":"Ada"}}"#);
}

/// Apple posts `error=` when the person cancels; that must reach oauth too.
#[tokio::test]
async fn a_cancelled_sign_in_still_reaches_oauth_and_redirects() {
    let (proxy, backend) = proxy_with_oauth().await;

    let response = call(&proxy, FORM, b"state=s&error=user_cancelled_authorize").await;

    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let got = backend.last.lock().unwrap().clone().expect("the form post never reached oauth");
    assert_eq!(got.error, "user_cancelled_authorize");
}

/// A JSON body to the same route is served as JSON always was, and still
/// redirects: the route's answer is a redirect whatever the request encoding.
#[tokio::test]
async fn a_json_body_to_the_callback_still_works() {
    let (proxy, backend) = proxy_with_oauth().await;

    let response = call(&proxy, "application/json", br#"{"code":"c","state":"s"}"#).await;

    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let got = backend.last.lock().unwrap().clone().expect("the JSON post never reached oauth");
    assert_eq!((got.code.as_str(), got.state.as_str()), ("c", "s"));
}

/// A field sent twice is refused before oauth is called.
#[tokio::test]
async fn a_repeated_form_field_is_refused_before_oauth() {
    let (proxy, backend) = proxy_with_oauth().await;

    let response = call(&proxy, FORM, b"code=one&code=two&state=s").await;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert!(backend.last.lock().unwrap().is_none(), "a refused form post reached oauth");
}

/// An error from oauth stays the JSON error it was: there is no URL to send
/// the browser to.
#[tokio::test]
async fn an_oauth_error_is_not_turned_into_a_redirect() {
    let (proxy, _backend) = proxy_with_oauth().await;

    let response = call(&proxy, FORM, b"state=refuse").await;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert!(response.headers().get(header::LOCATION).is_none());
}
