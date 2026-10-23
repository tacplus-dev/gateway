// `dev-bypass` enables the GATEWAY_AUTH_PASSTHROUGH env var, a total C2S auth
// bypass meant for local testing. It must never reach a shipped binary, and CI
// packages `cargo build --release`, so make that combination a build failure
// rather than something a stray `--features` flag can slip past review.
#[cfg(all(feature = "dev-bypass", not(debug_assertions)))]
compile_error!(
    "the dev-bypass feature disables all C2S authentication and cannot be enabled in a release build"
);

mod auth;
mod blob_proxy;
mod client_download;
mod idp_proxy;
mod limits;
mod proxy_grpc;
mod health;
mod mint;
mod registry;
mod resolver;
mod rest_translation;
mod plain_http;
mod spa;
mod tls;

/// End-to-end proof that a caller's entitlements decide whether a proxied gRPC
/// call reaches the backend. Lives in the binary crate because that is the only
/// place `proxy_grpc::handle` is reachable from — a `tests/` integration test
/// cannot link a bin target.
#[cfg(test)]
mod e2e_entitlement;

/// End-to-end proof that a tenant-owned service is routed to the caller's own
/// tenant instance, and that every other service is routed exactly as before.
#[cfg(test)]
mod e2e_tenant_routing;

/// End-to-end proof that a fresh device key registers and logs in through the
/// gateway's NoAuth `personalauth.Device` routes, and that the kernel
/// registration RPC those routes replaced is no longer reachable at all.
#[cfg(test)]
mod e2e_personalauth_registration;

/// End-to-end proof that kernel's C2S `UserMint` surface — the user half of the
/// delegate-bound Offline Token mint — is reachable through the gateway's
/// generic routing with no hand-written front, and that the S2S delegate half
/// is not reachable from a client at all.
#[cfg(test)]
mod e2e_user_mint;

/// End-to-end proof that an identity provider's form_post callback (Sign in
/// with Apple) is decoded from its form body and answered with a 303 through
/// the gateway's REST leg.
#[cfg(test)]
mod e2e_form_post;

use std::net::SocketAddr;
use std::sync::Arc;

use axum::http::StatusCode;
use axum::routing::get;
use tokio::time::{timeout, Duration};
use tokio_stream::StreamExt;
use tracing_subscriber::EnvFilter;

use gateway_model::s2sm::ServiceManager;
use gateway_model::types::sys::host::host::Host;
use gateway_model::types::services::gateway::gateway::Config as GatewayConfig;
use gateway_model::types::services::gateway::gateway::ExternalTlsMode;
use gateway_model::types::services::letsencrypt::letsencrypt::lets_encrypt_state_service_client::LetsEncryptStateServiceClient;
use crate::health::TokenProvider;

#[tokio::main]
async fn main() {
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install rustls crypto provider");

    // The chassis logger, installed through its reload layer.
    //
    // NOT `tracing_subscriber::fmt()`: `tracing` allows exactly ONE global
    // subscriber per process, so a service that builds its own wins permanently
    // and the chassis's config-driven install can only fail. That is what
    // happened here — the failure was discarded by grpcconfig's loader, and the
    // redacting layer was linked into this binary and never received a line.
    // Runtime proof at the time: this service emitted the default console format
    // with ANSI escapes, while the java services emitted chassis JSON.
    //
    // install_bootstrap redacts from the first line and leaves the layer
    // swappable, so load_config can still apply the typed logger config. The
    // per-crate `<svc>=info` directive is dropped: the level now comes from the
    // typed logger config, which is the point of routing through the chassis.
    if let Err(e) = gateway_logger::install_bootstrap() {
        eprintln!("FATAL: could not install the redacting logger: {e}");
        std::process::exit(1);
    }

    if let Err(e) = run().await {
        tracing::error!(error = %e, "gateway failed");
        std::process::exit(1);
    }
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Connect to kernel via ServiceManager.
    // SM loads bootstrap config, creates connection pool, StateClients, GrpcClients.
    let sm = Arc::new(ServiceManager::new().await?);
    let kernel_channel = sm.conn().await
        .ok_or("no active kernel connection")?;

    tracing::info!("ServiceManager connected to kernel");

    // 2. Fetch gateway config from kernel state (delivered by operator via bootstrap).
    let mut cfg = sm
        .state_clients()
        .services()
        .gateway_config_state()
        .config()
        .fetch()
        .await
        .map_err(|e| format!("failed to fetch gateway config from kernel: {e}"))?;
    // A raw fetch returns exactly what kernel holds; the proto's declared
    // defaults (tcp_listener = 0.0.0.0:8443 among them) are only applied by the
    // generated delivery path in s2sm/mod.rs, which this startup read bypasses.
    // On 2026-09-19 kernel served a config without tcp_listener while its
    // members were churning, and every fresh gateway start died on the check
    // below. Apply the same defaults the chassis applies.
    gateway_model::types::services::gateway::helpers::config_defaults(&mut cfg);

    let tcp_addr = host_to_socket_addr(
        cfg.tcp_listener.as_ref().ok_or("tcp_listener must be set in gateway config")?,
    );
    tracing::info!(
        tcp_addr = %tcp_addr,
        http = cfg.enable_http,
        grpc = cfg.enable_grpc,
        http3 = cfg.enable_http3,
        tls_mode = ?cfg.external_tls_mode(),
        "gateway config received from kernel"
    );

    // Log SPA serving mode.
    match spa::web_root() {
        Some(root) => tracing::info!(web_root = %root.display(), "SPA: serving from disk (WEB_ROOT)"),
        None => tracing::info!("SPA: serving from embedded assets"),
    }

    // Initialize bootstrap config for SPA — webapp reads window.__SCHEMATIC__ for gateway URL.
    // Empty string = same origin (webapp is served by the gateway itself).
    spa::init_bootstrap("");

    // Hostnames that get their own bundle instead of the one above. Applied
    // again on every gateway config update, not only from the config this pod
    // first received: a pod that starts mid-roll reads the previous config, and
    // reading web_bundles once at startup left it serving the console bundle on
    // every host until it was restarted.
    apply_web_bundles(&cfg);
    sm.state_clients()
        .services()
        .gateway_config_state()
        .config()
        .on_change(Arc::new(apply_web_bundles));

    if !cfg.enable_http && !cfg.enable_http3 && !cfg.enable_grpc {
        return Err("at least one of enable_http, enable_http3, or enable_grpc must be true".into());
    }

    // Use the generated token provider from ServiceManager.
    let token_provider = sm.token_provider();

    // 3. Build external TLS config based on external_tls_mode.
    // Use the generated token provider from ServiceManager.
    let tls_config = match cfg.external_tls_mode() {
        ExternalTlsMode::CertChain => {
            tracing::info!("external TLS mode: cert_chain");
            tls::build_server_config_from_pem(&cfg.external_cert_pem, &cfg.external_key_pem)?
        }
        ExternalTlsMode::Letsencrypt => {
            tracing::info!("external TLS mode: letsencrypt");
            // Start on the cluster-CA edge chain -- the same material cert_chain
            // mode serves -- and never block startup on a public certificate.
            // Gateway owns port 80, which is what answers letsencrypt's HTTP-01
            // challenge, so waiting here for a cert deadlocked its own issuance:
            // no listener -> no challenge -> no cert -> no listener. The watcher
            // spawned below hot-swaps the real certificate in the moment
            // LetsEncryptState delivers one.
            tls::build_server_config_from_pem(&cfg.external_cert_pem, &cfg.external_key_pem)?
        }
        ExternalTlsMode::Unspecified => {
            return Err("external_tls_mode must be set in gateway config (cert_chain or letsencrypt)".into());
        }
    };
    let tls_acceptor = axum_server::tls_rustls::RustlsConfig::from_config(tls_config);

    // Spawn cert hot-reload watchers. BOTH external TLS modes need one.
    //
    // cert_chain was previously treated as static config, read once by the fetch()
    // above and never looked at again. But a supplied certificate expires just as
    // a letsencrypt one does -- a public CA cert is typically 90 days, a private
    // CA cert whatever the issuer sets -- and the renewed PEM is delivered through
    // GatewayConfigState like any other runtime config. With no watcher, gateway
    // kept serving the superseded certificate until someone restarted the pod, and
    // then served an EXPIRED one once the old cert ran out. Nothing logged, and
    // updating the config appeared to succeed.
    //
    // The generated state client already maintains the watch and exposes
    // on_change; only the call site was missing.
    if cfg.external_tls_mode() == ExternalTlsMode::Letsencrypt {
        spawn_cert_watcher(kernel_channel.clone(), token_provider.clone(), tls_acceptor.clone());
    } else if cfg.external_tls_mode() == ExternalTlsMode::CertChain {
        spawn_cert_chain_reloader(sm.clone(), tls_acceptor.clone(), &cfg);
    }

    // 4. Log the compile-time route table.
    registry::Registry::load();

    // 5. Start HealthWatcher (watches ServiceHealthState.instances from kernel).
    let health_watcher = health::HealthWatcher::new(kernel_channel.clone(), token_provider.clone());

    // Wait for initial health data so gRPC proxy channels connect to real endpoints.
    match timeout(Duration::from_secs(30), health_watcher.wait_ready()).await {
        Ok(()) => tracing::info!("initial health data received"),
        Err(_) => tracing::warn!("timed out waiting for health data, proceeding with available endpoints"),
    }

    // 6. Fetch dynamic CAs from kernel's CaState and build backend TLS verifier.
    // CaState.ca_certs contains the runtime CA(s) that sign per-service intermediate CAs
    // via X509Mint. Without these, the resolver can't verify backend service TLS certs.
    let initial_cas = wait_for_ca_certs(kernel_channel.clone(), &token_provider).await?;
    let ca_pem_bundle = build_ca_pem_bundle(sm.config(), &initial_cas);
    let backend_tls =
        build_backend_tls_verifier_from_pem(&ca_pem_bundle, &sm.config().spiffe_trust_domain)?;
    let resolver = Arc::new(resolver::Resolver::new(health_watcher.clone(), backend_tls));

    // Keep kernel's CaState CAs in a shared RwLock, refreshed by the watcher below.
    // These are the INTERNAL cluster signing CAs. They are not what ListPublicCa
    // answers with — that is `cfg.root_ca`, the CA behind gateway's external TLS
    // cert — and nothing else reads this store today; see the 2026-09-12 audit-fix
    // decision doc.
    let ca_certs_store = Arc::new(tokio::sync::RwLock::new(initial_cas));
    spawn_ca_cert_watcher(kernel_channel.clone(), token_provider.clone(), Arc::clone(&ca_certs_store));


    // 7. Create gateway auth using the SM's authorizer's JWK cache.
    // Entitlements are read from the service_entitlements JWT claim — no profile cache needed.
    let authorizer = sm.authorizer();
    let auth_passthrough = std::env::var("GATEWAY_AUTH_PASSTHROUGH")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    if auth_passthrough {
        if cfg!(feature = "dev-bypass") {
            tracing::warn!("GATEWAY_AUTH_PASSTHROUGH is enabled — all C2S auth checks are bypassed");
        } else {
            tracing::error!(
                "GATEWAY_AUTH_PASSTHROUGH is set but this binary was not built with the \
                 dev-bypass feature — ignoring it, C2S auth stays enforced"
            );
        }
    }
    let gateway_auth = Arc::new(auth::GatewayAuth::new(
        authorizer.jwk_cache().clone(),
        auth_passthrough,
    ));

    // Derive the public OIDC issuer URL from configured external_hostnames.
    // Kernel signs JWTs with `https://<host>` as `iss`; discovery must
    // advertise that exact value for external verifiers such as Anthropic WIF.
    let issuer_url = cfg
        .external_hostnames
        .first()
        .map(|h| rest_translation::issuer_url(h))
        .ok_or("gateway config has no external_hostnames; cannot build issuer URL")?;
    tracing::info!(issuer_url = %issuer_url, "OIDC issuer URL derived from external_hostnames");

    // 8. Build gateway Mint service (local OIDC/JWKS, delegates TokenMint/X509Mint to kernel).
    // root_ca comes from config — the CA that signed the external TLS cert.
    // Clients call ListPublicCa to retrieve it for TLS trust configuration.
    let mint_service = mint::GatewayMintService::new(
        Arc::clone(&sm),
        Arc::clone(&gateway_auth),
        issuer_url.clone(),
        cfg.root_ca.clone(),
    );

    // 9. Trace publisher (shared between gRPC proxy and REST handler). The
    // topic it published to belonged to agentsensor, a long-dead service; the
    // proto no longer declares the publish, so traces are dropped until a live
    // sink exists.
    let trace_publisher: Arc<
        dyn Fn(gateway_model::types::sys::trace::TraceEvent) + Send + Sync,
    > = Arc::new(|_event| {});

    // 10. Build gRPC router: Mint (native tonic) + raw proxy for all other services.
    let sm_for_grpc_trace = Arc::clone(&sm);
    // Read once: the set of tenant-owned services is a property of the compiled
    // registry, so it cannot change while the process runs.
    let tenant_owned = Arc::new(registry::tenant_owned_services());
    if !tenant_owned.is_empty() {
        tracing::info!(services = ?tenant_owned, "tenant-owned services route per caller tenant");
    }
    let proxy_state = Arc::new(proxy_grpc::ProxyState {
        resolver: Arc::clone(&resolver),
        auth: Arc::clone(&gateway_auth),
        tenant_owned: Arc::clone(&tenant_owned),
        trace_publisher: Arc::clone(&trace_publisher),
        trace_round: Box::new(move || sm_for_grpc_trace.trace_round()),
    });

    let grpc_router = {
        use gateway_model::types::services::gateway::gateway::mint_server::MintServer;
        let (health_reporter, health_service) = tonic_health::server::health_reporter();
        health_reporter
            .set_service_status("", tonic_health::ServingStatus::Serving)
            .await;
        tonic::service::Routes::new(MintServer::new(mint_service))
            .add_service(health_service)
            .into_axum_router()
    };

    // 11. Build REST state (shares ProxyState — all auth is in proxy_grpc).
    let rest_state = Arc::new(rest_translation::RestState {
        proxy: Arc::clone(&proxy_state),
        sm: Arc::clone(&sm),
        auth: Arc::clone(&gateway_auth),
        root_ca: cfg.root_ca.clone(),
        issuer_url: issuer_url.clone(),
    });

    // 12. Build IDP proxy for /realms/* and /admin/* → Keycloak.
    // Keycloak subprocess listens on HTTPS/9443 with a kernel-issued cert (SAN DNS:kernel).
    // Gateway trusts it via the kernel root chain already in ca_pem_bundle.
    let idp_proxy = Arc::new(
        idp_proxy::IdpProxy::new(health_watcher.clone(), &ca_pem_bundle)
            .map_err(|e| format!("failed to build IDP proxy: {e}"))?,
    );

    // 13. Layer the routers: Mint (tonic) → gRPC proxy → IDP proxy → REST/SPA.
    // Mint is a native tonic service; all other gRPC requests are proxied
    // as raw HTTP/2 through the resolver to backend services.
    // The REST router carries the fallback: unclaimed GET/HEAD serve the SPA.
    let client_auth = Arc::clone(&gateway_auth);
    let spa_and_rest = rest_translation::router(rest_state)
        .route("/healthz", get(healthz))
        .route("/readyz", get(healthz))
        .route("/registry/{file}", get(spa::registry_handler))
        .route("/client/{os}/{arch}", get(move |path, req| client_download::handler(path, req, client_auth.clone())));

    // Intercept gRPC requests before they reach REST/SPA routing.
    // Native gRPC clients (operator, service-to-service) send content-type: application/grpc.
    // These are proxied as raw HTTP/2 to backend services. Non-gRPC requests pass through
    // to the IDP proxy check, then REST routes and SPA handler.
    let proxy_state_clone = Arc::clone(&proxy_state);
    let idp_proxy_clone = Arc::clone(&idp_proxy);
    // The blob store's byte paths. Intercepted HERE, alongside the gRPC proxy and
    // the IDP proxy, for two reasons the decision doc's R3 asks for: this layer
    // sits BEFORE the SPA fallback, so `/b/<token>` is never answered with the
    // web app's index.html; and it sits OUTSIDE the REST body cap applied below,
    // so an upload is bounded by its volume group's max_blob_bytes rather than by
    // the 10 MB REST ceiling.
    let blob_proxy = Arc::new(blob_proxy::BlobProxy::new(health_watcher.clone()));
    let blob_proxy_clone = Arc::clone(&blob_proxy);
    // The per-IP limit on oauth's public sign-in routes. Checked HERE, first, so
    // it covers the REST and the native gRPC spelling of a route alike, and
    // refuses before any body is read.
    let sign_in_limit = Arc::new(limits::SignInLimit::from_env());
    let grpc_and_idp_intercept = axum::middleware::from_fn(
        move |req: axum::extract::Request, next: axum::middleware::Next| {
            let proxy = Arc::clone(&proxy_state_clone);
            let idp = Arc::clone(&idp_proxy_clone);
            let blob = Arc::clone(&blob_proxy_clone);
            let sign_in_limit = Arc::clone(&sign_in_limit);
            async move {
                if let Some(refusal) = sign_in_limit.refusal(&req) {
                    refusal
                } else if proxy_grpc::is_grpc(&req) {
                    proxy_grpc::handle(&proxy, req).await
                } else if idp_proxy::IdpProxy::is_idp_request(req.uri().path()) {
                    idp.handle(req).await
                } else if blob_proxy::BlobProxy::is_blob_request(req.uri().path()) {
                    blob.handle(req).await
                } else {
                    next.run(req).await
                }
            }
        },
    );

    // Edge limits. The body cap sits INSIDE the gRPC/IDP intercept so it only
    // applies to the REST/SPA half — raw gRPC client streams are long-lived and
    // already bounded per message in proxy_grpc. The concurrency/rate cap wraps
    // the finished router, so it covers Mint, the gRPC proxy and REST alike.
    let edge_limits = limits::EdgeLimits::from_env();
    tracing::info!(
        max_concurrent_requests = edge_limits.max_concurrent_requests,
        max_requests_per_second = edge_limits.max_requests_per_second,
        max_request_body_bytes = edge_limits.max_request_body_bytes,
        "edge limits"
    );
    let spa_and_rest =
        limits::with_request_body_limit(spa_and_rest, edge_limits.max_request_body_bytes);

    // Mint (tonic) handles /gateway.Mint/* methods.
    // Everything else hits the intercept layer: gRPC → IDP proxy → REST/SPA.
    let app = grpc_router
        .fallback_service(spa_and_rest.layer(grpc_and_idp_intercept))
        // HSTS on everything served over TLS. Outermost on purpose: the header
        // is a statement about the origin, so it has to be on the response the
        // browser actually gets, whichever half of the router produced it.
        .layer(axum::middleware::from_fn(plain_http::hsts));
    let app: limits::EdgeService<hyper::body::Incoming> =
        limits::with_edge_limits(app, &edge_limits);

    // 13. Start the plaintext listener, when configured. The gateway owns the
    // edge's port 80 as well as 443 — one LoadBalancer carries both — so this
    // is what proxies ACME HTTP-01 challenges to the letsencrypt service and
    // redirects everything else to https. Bound before the TLS listener so a
    // bind failure kills startup instead of being lost in a background task.
    if let Some(http_listener) = cfg.http_listener.as_ref() {
        let http_addr = host_to_socket_addr(http_listener);
        let acme_backend = cfg
            .acme_backend
            .as_ref()
            .map(|host| format!("{}:{}", host.host, host.port));
        if acme_backend.is_none() {
            tracing::warn!(
                "http_listener is set but acme_backend is not — ACME HTTP-01 challenges \
                 will be answered 503 and no certificate can be issued or renewed"
            );
        }
        plain_http::serve(http_addr, acme_backend.clone()).await?;
        tracing::info!(
            addr = %http_addr,
            acme_backend = acme_backend.as_deref().unwrap_or(""),
            "listening (plaintext, ACME challenge + https redirect)"
        );
    }

    // 14. Start TLS listener — serves both HTTP and gRPC on the same port.
    tracing::info!(addr = %tcp_addr, "listening (TLS, HTTP+gRPC)");

    // Gateway builds the ServiceManager with new() but never calls run(), because
    // it serves external TLS (LetsEncrypt / CertChain) rather than the SM's
    // auto-TLS. The SM sets grpc_health to NOT_SERVING in new() and flips it to
    // SERVING inside run() — so without this call the plaintext health listener on
    // 8444 stays NOT_SERVING forever and k8s startup probes fail indefinitely
    // ("service unhealthy (responded with NOT_SERVING)", observed 114 times).
    //
    // set_serving drives the SAME handle that serves 8444. Do NOT substitute a
    // locally-created tonic health reporter: that is a different health service
    // from the one being probed, and it silently does nothing for k8s.
    //
    // Placed here because bootstrap is complete — identity, state clients, TLS
    // material and the full router are all built — and the listener is about to
    // accept. Reporting SERVING any earlier would be a lie.
    sm.set_serving(true).await;

    // `with_peer_addr` rather than `tower::make::Shared`: Shared discards the
    // connection's peer address, and the blob paths' per-source-IP rate limit has
    // to key on something the client cannot choose (see blob_proxy::PeerAddr).
    // Everything else about this wiring is unchanged — it is the same finished
    // service, served per connection with its address attached.
    axum_server::bind_rustls(tcp_addr, tls_acceptor)
        .serve(blob_proxy::with_peer_addr(app))
        .await?;

    // Graceful shutdown.
    sm.close();

    Ok(())
}

/// Hot-reload the external TLS certificate in cert_chain mode when a renewed
/// cert/key is written to GatewayConfigState.
///
/// Registers a change callback on the generated state client, which already
/// maintains the watch -- no hand-rolled stream, per the tacplus rule that
/// generated capabilities are used rather than duplicated.
///
/// The callback fires on ANY gateway config change, so it compares the PEMs
/// against the ones currently being served and does nothing unless they actually
/// differ. Without that, toggling an unrelated field would rebuild and swap the
/// TLS config for no reason.
///
/// A rejected certificate is logged and DISCARDED: the previously loaded, working
/// certificate keeps serving. Swapping in a broken cert because someone pasted a
/// malformed PEM would take the public endpoint down, which is strictly worse than
/// continuing on the old one until it is corrected.
fn spawn_cert_chain_reloader(
    sm: Arc<ServiceManager>,
    tls_config: axum_server::tls_rustls::RustlsConfig,
    initial: &GatewayConfig,
) {
    let serving = Arc::new(std::sync::Mutex::new((
        initial.external_cert_pem.clone(),
        initial.external_key_pem.clone(),
    )));

    sm.state_clients()
        .services()
        .gateway_config_state()
        .config()
        .on_change(Arc::new(move |new_cfg: &GatewayConfig| {
            if new_cfg.external_tls_mode() != ExternalTlsMode::CertChain {
                return;
            }
            {
                let current = serving.lock().unwrap();
                if current.0 == new_cfg.external_cert_pem && current.1 == new_cfg.external_key_pem {
                    return;
                }
            }
            match tls::build_server_config_from_pem(
                &new_cfg.external_cert_pem,
                &new_cfg.external_key_pem,
            ) {
                Ok(new_config) => {
                    tls_config.reload_from_config(new_config);
                    let mut current = serving.lock().unwrap();
                    *current = (
                        new_cfg.external_cert_pem.clone(),
                        new_cfg.external_key_pem.clone(),
                    );
                    tracing::info!("external TLS certificate hot-reloaded from gateway config");
                }
                Err(e) => tracing::error!(
                    error = %e,
                    "renewed external_cert_pem/external_key_pem rejected; \
                     continuing to serve the previous certificate"
                ),
            }
        }));

    tracing::info!("cert_chain hot-reload watcher registered");
}

/// Serve cfg.web_bundles, logging the bundle set whenever it changes.
fn apply_web_bundles(cfg: &GatewayConfig) {
    if spa::set_web_bundles(&cfg.web_bundles) {
        for bundle in &cfg.web_bundles {
            tracing::info!(hostname = %bundle.hostname, dir = %bundle.dir, "SPA: web bundle for hostname");
        }
    }
}

/// Spawn a background task that watches LetsEncryptState.cert_data and
/// hot-reloads the TLS config when the certificate is renewed.
fn spawn_cert_watcher(
    channel: tonic::transport::Channel,
    token_provider: TokenProvider,
    tls_config: axum_server::tls_rustls::RustlsConfig,
) {
    tokio::spawn(async move {
        loop {
            match watch_cert_updates(channel.clone(), &token_provider, &tls_config).await {
                Ok(()) => tracing::warn!("WatchCertData stream ended, reconnecting"),
                Err(e) => {
                    tracing::error!(error = %e, "WatchCertData cert watcher failed, retrying in 5s");
                    tokio::time::sleep(Duration::from_secs(5)).await;
                }
            }
        }
    });
}

async fn watch_cert_updates(
    channel: tonic::transport::Channel,
    token_provider: &TokenProvider,
    tls_config: &axum_server::tls_rustls::RustlsConfig,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut client = LetsEncryptStateServiceClient::new(channel);

    let mut request = tonic::Request::new(Default::default());
    if let Ok(token) = (token_provider)().await {
        let val: tonic::metadata::MetadataValue<tonic::metadata::Ascii> =
            format!("Bearer {}", token).parse()
                .map_err(|e| format!("invalid token metadata: {e}"))?;
        request.metadata_mut().insert("authorization", val);
    }

    let response = client.watch_cert_data(request).await?;
    let mut stream = response.into_inner();

    tracing::info!("TLS cert watcher stream started");

    while let Some(msg) = stream.next().await {
        match msg {
            Ok(cert_data) => tls::apply_cert_data(tls_config, &cert_data),
            Err(e) => {
                tracing::warn!(error = %e, "WatchCertData stream error");
                return Err(e.into());
            }
        }
    }

    Ok(())
}

async fn healthz() -> StatusCode {
    StatusCode::OK
}

/// Spawn a background task that watches kernel's CaState and updates the shared CA cert store.
fn spawn_ca_cert_watcher(
    channel: tonic::transport::Channel,
    token_provider: TokenProvider,
    ca_certs_store: Arc<tokio::sync::RwLock<Vec<gateway_model::types::sys::x509::x509::X509Cert>>>,
) {
    tokio::spawn(async move {
        loop {
            match watch_ca_cert_updates(channel.clone(), &token_provider, &ca_certs_store).await {
                Ok(()) => tracing::warn!("WatchCaCerts stream ended, reconnecting"),
                Err(e) => {
                    tracing::error!(error = %e, "CA cert watcher failed, retrying in 5s");
                    tokio::time::sleep(Duration::from_secs(5)).await;
                }
            }
        }
    });
}

async fn watch_ca_cert_updates(
    channel: tonic::transport::Channel,
    token_provider: &TokenProvider,
    ca_certs_store: &tokio::sync::RwLock<Vec<gateway_model::types::sys::x509::x509::X509Cert>>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use gateway_model::types::services::kernel::kernel::ca_state_service_client::CaStateServiceClient;

    let mut client = CaStateServiceClient::new(channel);

    let mut request = tonic::Request::new(Default::default());
    if let Ok(token) = (token_provider)().await {
        let val: tonic::metadata::MetadataValue<tonic::metadata::Ascii> =
            format!("Bearer {}", token).parse()
                .map_err(|e| format!("invalid token metadata: {e}"))?;
        request.metadata_mut().insert("authorization", val);
    }

    let response = client.watch_ca_certs(request).await?;
    let mut stream = response.into_inner();

    tracing::info!("CA cert watcher stream started");

    while let Some(msg) = stream.next().await {
        match msg {
            Ok(entries) => {
                if !entries.entries.is_empty() {
                    let certs: Vec<_> = entries.entries.into_values().collect();
                    tracing::info!(count = certs.len(), "CA certificates updated from kernel CaState");
                    *ca_certs_store.write().await = certs;
                }
            }
            Err(e) => {
                tracing::warn!(error = %e, "WatchCaCerts stream error");
                return Err(e.into());
            }
        }
    }

    Ok(())
}

/// Wait for dynamic CA certificates from kernel's CaState.
/// These are the runtime CAs that sign per-service intermediate CAs via X509Mint.
async fn wait_for_ca_certs(
    channel: tonic::transport::Channel,
    token_provider: &TokenProvider,
) -> Result<Vec<gateway_model::types::sys::x509::x509::X509Cert>, Box<dyn std::error::Error>> {
    use gateway_model::types::services::kernel::kernel::ca_state_service_client::CaStateServiceClient;

    let mut client = CaStateServiceClient::new(channel);

    let mut request = tonic::Request::new(Default::default());
    if let Ok(token) = (token_provider)().await {
        let val: tonic::metadata::MetadataValue<tonic::metadata::Ascii> =
            format!("Bearer {}", token).parse()
                .map_err(|_| "invalid token metadata")?;
        request.metadata_mut().insert("authorization", val);
    }

    let response = client.watch_ca_certs(request).await?;
    let mut stream = response.into_inner();

    let mut log_interval = tokio::time::interval(Duration::from_secs(5));
    log_interval.tick().await;

    let result = timeout(Duration::from_secs(30), async {
        loop {
            tokio::select! {
                msg = stream.next() => {
                    match msg {
                        Some(Ok(entries)) => {
                            if !entries.entries.is_empty() {
                                let certs: Vec<_> = entries.entries.into_values().collect();
                                tracing::info!(count = certs.len(), "CA certificates received from kernel CaState");
                                return Ok(certs);
                            }
                        }
                        Some(Err(e)) => return Err(Box::new(e) as Box<dyn std::error::Error>),
                        None => return Err("WatchCaCerts stream ended without data".into()),
                    }
                }
                _ = log_interval.tick() => {
                    tracing::info!("waiting for CA certificates from kernel CaState...");
                }
            }
        }
    }).await;

    match result {
        Ok(inner) => inner,
        Err(_) => {
            tracing::warn!("no CA certificates received within 30s, proceeding with bootstrap CAs only");
            Ok(vec![])
        }
    }
}

/// Build the raw PEM bundle of all CA certificates (bootstrap + dynamic).
fn build_ca_pem_bundle(
    config: &gateway_model::types::sys::grpcconfig::grpcconfig::Config,
    dynamic_cas: &[gateway_model::types::sys::x509::x509::X509Cert],
) -> String {
    let mut pem_bundle = String::new();
    tracing::info!(count = config.trusted_cas.len(), "loading bootstrap CAs");
    for ca in &config.trusted_cas {
        decode_ca_pem(&ca.base64, &mut pem_bundle);
    }
    tracing::info!(count = dynamic_cas.len(), "loading dynamic CAs from CaState");
    for ca in dynamic_cas {
        decode_ca_pem(&ca.base64, &mut pem_bundle);
    }
    if pem_bundle.is_empty() {
        tracing::warn!("no CA certificates available for backend TLS — connections will fail");
    } else {
        tracing::info!(total_len = pem_bundle.len(), "backend TLS trust store built");
    }
    pem_bundle
}

/// Build a SPIFFE-aware verifier for gRPC backend connections from a PEM CA bundle.
fn build_backend_tls_verifier_from_pem(
    ca_pem_bundle: &str,
    spiffe_trust_domain: &str,
) -> Result<Arc<gateway_servicemanager::SpiffeServerCertVerifier>, Box<dyn std::error::Error>> {
    let (root_store, added) = gateway_servicemanager::spiffe::build_root_store(ca_pem_bundle);
    if added == 0 {
        return Err("no CA certificates available for backend TLS".into());
    }
    gateway_servicemanager::SpiffeServerCertVerifier::new(spiffe_trust_domain, root_store)
        .map_err(|e| format!("backend SPIFFE TLS verifier: {e}").into())
}

/// Decode a base64-encoded PEM certificate and append to the bundle.
/// Tries URL-safe (no pad), standard (no pad), and standard (padded) decoders
/// because different sources use different base64 variants.
fn decode_ca_pem(base64_str: &str, pem_bundle: &mut String) {
    use base64::Engine;

    if base64_str.is_empty() {
        return;
    }
    let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(base64_str)
        .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(base64_str))
        .or_else(|_| base64::engine::general_purpose::STANDARD_NO_PAD.decode(base64_str))
        .or_else(|_| base64::engine::general_purpose::STANDARD.decode(base64_str));

    match decoded {
        Ok(pem_bytes) => {
            if let Ok(pem_str) = String::from_utf8(pem_bytes) {
                tracing::debug!(len = pem_str.len(), "loaded CA certificate PEM");
                pem_bundle.push_str(&pem_str);
                pem_bundle.push('\n');
            } else {
                tracing::warn!("CA cert base64 decoded but is not valid UTF-8");
            }
        }
        Err(e) => {
            tracing::warn!(error = %e, "failed to decode CA cert base64");
        }
    }
}

/// Convert a Host (host + port) to a SocketAddr for binding.
fn host_to_socket_addr(host: &Host) -> SocketAddr {
    let addr_str = format!("{}:{}", host.host, host.port);
    addr_str.parse().unwrap_or_else(|_| {
        // If the host string isn't a valid IP, fall back to 0.0.0.0.
        format!("0.0.0.0:{}", host.port)
            .parse()
            .expect("fallback socket addr")
    })
}
