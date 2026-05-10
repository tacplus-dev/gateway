mod auth;
mod idp_proxy;
mod proxy_grpc;
mod health;
mod mint;
mod registry;
mod resolver;
mod rest_translation;
mod spa;
mod tls;

use std::net::SocketAddr;
use std::sync::Arc;

use axum::http::StatusCode;
use axum::routing::get;
use tokio::time::{timeout, Duration};
use tokio_stream::StreamExt;
use tracing_subscriber::EnvFilter;

use gateway_tacplus::s2sm::ServiceManager;
use gateway_tacplus::types::libs::host::host::Host;
use gateway_tacplus::types::services::gateway::gateway::Config as GatewayConfig;
use gateway_tacplus::types::services::gateway::helpers::{config_defaults, config_from_bytes};
use gateway_tacplus::types::services::kernel::kernel::gateway_tls_state_service_client::GatewayTlsStateServiceClient;
use gateway_tacplus::types::services::kernel::GatewayTlsCert;
use crate::health::TokenProvider;

#[tokio::main]
async fn main() {
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install rustls crypto provider");

    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::from_default_env().add_directive("gateway=info".parse().unwrap()),
        )
        .init();

    if let Err(e) = run().await {
        tracing::error!(error = %e, "gateway failed");
        std::process::exit(1);
    }
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Load gateway-specific config (listen address, enable flags).
    let cfg = load_gateway_config();
    let tcp_addr = host_to_socket_addr(
        cfg.tcp_listener.as_ref().expect("tcp_listener must be set after config_defaults"),
    );
    tracing::info!(
        tcp_addr = %tcp_addr,
        http = cfg.enable_http,
        grpc = cfg.enable_grpc,
        http3 = cfg.enable_http3,
        "starting gateway"
    );

    // Log SPA serving mode.
    match spa::web_root() {
        Some(root) => tracing::info!(web_root = %root.display(), "SPA: serving from disk (WEB_ROOT)"),
        None => tracing::info!("SPA: serving from embedded assets"),
    }

    // Initialize bootstrap config for SPA — webapp reads window.__CAVALIER__ for gateway URL.
    // Empty string = same origin (webapp is served by the gateway itself).
    spa::init_bootstrap("");

    if !cfg.enable_http && !cfg.enable_http3 && !cfg.enable_grpc {
        return Err("at least one of enable_http, enable_http3, or enable_grpc must be true".into());
    }

    // 2. Connect to kernel via ServiceManager.
    // SM loads bootstrap config, creates connection pool, StateClients, GrpcClients.
    let sm = Arc::new(ServiceManager::new().await?);
    let kernel_channel = sm.conn().await
        .ok_or("no active kernel connection")?;

    tracing::info!("ServiceManager connected to kernel");

    // Use the generated token provider from ServiceManager.
    let token_provider = sm.token_provider();

    // 3. Wait for TLS certificate from kernel state (GatewayTlsState.all_certs view).
    // Gateway requires a publicly-signed cert — either manually configured or from LetsEncrypt.
    // Crash after 60 seconds if no cert is available.
    let initial_cert = wait_for_tls_cert(kernel_channel.clone(), &token_provider).await?;
    let tls_config = tls::build_server_config(&initial_cert)?;
    let tls_acceptor = axum_server::tls_rustls::RustlsConfig::from_config(tls_config);

    // Spawn background watcher for cert hot-reload.
    spawn_cert_watcher(kernel_channel.clone(), token_provider.clone(), tls_acceptor.clone());

    // 4. Log the compile-time route table.
    registry::Registry::load();

    // 5. Start HealthWatcher (watches ServiceHealthState.instances from kernel).
    let health_watcher = health::HealthWatcher::new(kernel_channel.clone(), token_provider.clone());

    // Wait for initial health data so gRPC proxy channels connect to real endpoints.
    match timeout(Duration::from_secs(30), health_watcher.wait_ready()).await {
        Ok(()) => tracing::info!("initial health data received"),
        Err(_) => tracing::warn!("timed out waiting for health data, proceeding with available endpoints"),
    }

    // 6. Fetch dynamic CAs from kernel's CaState and build backend TLS config.
    // CaState.ca_certs contains the runtime CA(s) that sign per-service intermediate CAs
    // via X509Mint. Without these, the resolver can't verify backend service TLS certs.
    let initial_cas = wait_for_ca_certs(kernel_channel.clone(), &token_provider).await?;
    let ca_pem_bundle = build_ca_pem_bundle(sm.config(), &initial_cas);
    let backend_tls = build_backend_tls_config_from_pem(&ca_pem_bundle);
    let resolver = Arc::new(resolver::Resolver::new(health_watcher.clone(), backend_tls));

    // Store CA certs in a shared RwLock so the Mint service can serve them via PublicCa.
    let ca_certs_store = Arc::new(tokio::sync::RwLock::new(initial_cas));
    spawn_ca_cert_watcher(kernel_channel.clone(), token_provider.clone(), Arc::clone(&ca_certs_store));


    // 7. Create gateway auth using the SM's authorizer's JWK cache.
    // Entitlements are read from the service_entitlements JWT claim — no profile cache needed.
    let authorizer = sm.authorizer();
    let auth_passthrough = std::env::var("GATEWAY_AUTH_PASSTHROUGH")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    if auth_passthrough {
        tracing::warn!("GATEWAY_AUTH_PASSTHROUGH is enabled — all C2S auth checks are bypassed");
    }
    let gateway_auth = Arc::new(auth::GatewayAuth::new(
        authorizer.jwk_cache().clone(),
        auth_passthrough,
    ));

    // 8. Build gateway Mint service (local OIDC/JWKS, delegates TokenMint/X509Mint to kernel).
    let mint_service = mint::GatewayMintService::new(
        kernel_channel.clone(),
        Arc::clone(&gateway_auth),
        String::new(), // issuer URL — empty = same origin
        Arc::clone(&ca_certs_store),
    );

    // 9. Create trace publisher (shared between gRPC proxy and REST handler).
    let trace_publisher = sm.create_trace_publisher().await;

    // 10. Build gRPC router: Mint (native tonic) + raw proxy for all other services.
    let sm_for_grpc_trace = Arc::clone(&sm);
    let proxy_state = Arc::new(proxy_grpc::ProxyState {
        resolver: Arc::clone(&resolver),
        auth: Arc::clone(&gateway_auth),
        trace_publisher: Arc::clone(&trace_publisher),
        trace_round: Box::new(move || sm_for_grpc_trace.trace_round()),
    });

    let grpc_router = {
        use gateway_tacplus::types::services::gateway::gateway::mint_server::MintServer;
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
        kernel_channel: kernel_channel.clone(),
        auth: Arc::clone(&gateway_auth),
        ca_certs: Arc::clone(&ca_certs_store),
    });

    // 12. Build IDP proxy for /realms/* and /admin/* → Keycloak.
    // This is the only HTTP (non-gRPC) backend proxy in gateway.
    // Keycloak is proxied over plain HTTP on port 8080 (intra-cluster connection).
    let idp_proxy = Arc::new(idp_proxy::IdpProxy::new(health_watcher.clone()));

    // 13. Layer the routers: Mint (tonic) → gRPC proxy → IDP proxy → REST/SPA.
    // Mint is a native tonic service; all other gRPC requests are proxied
    // as raw HTTP/2 through the resolver to backend services.
    let registry_route = format!("{}/registry/{{file}}", gateway_tacplus::s2sm::rest_dispatch::REST_ROOT_PATH);
    let spa_and_rest = rest_translation::router(rest_state)
        .route("/healthz", get(healthz))
        .route("/readyz", get(healthz))
        .route(&registry_route, get(spa::registry_handler))
        .fallback(spa::spa_handler);

    // Intercept gRPC requests before they reach REST/SPA routing.
    // Native gRPC clients (cavalierctl, service-to-service) send content-type: application/grpc.
    // These are proxied as raw HTTP/2 to backend services. Non-gRPC requests pass through
    // to the IDP proxy check, then REST routes and SPA handler.
    let proxy_state_clone = Arc::clone(&proxy_state);
    let idp_proxy_clone = Arc::clone(&idp_proxy);
    let grpc_and_idp_intercept = axum::middleware::from_fn(
        move |req: axum::extract::Request, next: axum::middleware::Next| {
            let proxy = Arc::clone(&proxy_state_clone);
            let idp = Arc::clone(&idp_proxy_clone);
            async move {
                if proxy_grpc::is_grpc(&req) {
                    proxy_grpc::handle(&proxy, req).await
                } else if idp_proxy::IdpProxy::is_idp_request(req.uri().path()) {
                    idp.handle(req).await
                } else {
                    next.run(req).await
                }
            }
        },
    );

    // Mint (tonic) handles /gateway.Mint/* methods.
    // Everything else hits the intercept layer: gRPC → IDP proxy → REST/SPA.
    let app = grpc_router
        .fallback_service(spa_and_rest.layer(grpc_and_idp_intercept));

    // 13. Start TLS listener — serves both HTTP and gRPC on the same port.
    tracing::info!(addr = %tcp_addr, "listening (TLS, HTTP+gRPC)");

    axum_server::bind_rustls(tcp_addr, tls_acceptor)
        .serve(app.into_make_service())
        .await?;

    // Graceful shutdown.
    sm.close();

    Ok(())
}

/// Wait for a TLS certificate from GatewayTlsState.all_certs view.
/// Logs every 5 seconds while waiting. Returns error after 60 seconds.
async fn wait_for_tls_cert(
    channel: tonic::transport::Channel,
    token_provider: &TokenProvider,
) -> Result<GatewayTlsCert, Box<dyn std::error::Error>> {
    let mut client = GatewayTlsStateServiceClient::new(channel);

    let mut request = tonic::Request::new(Default::default());
    if let Ok(token) = (token_provider)().await {
        let val: tonic::metadata::MetadataValue<tonic::metadata::Ascii> =
            format!("Bearer {}", token).parse()
                .map_err(|_| "invalid token metadata")?;
        request.metadata_mut().insert("authorization", val);
    }

    let response = client.watch_all_certs(request).await?;
    let mut stream = response.into_inner();

    let mut log_interval = tokio::time::interval(Duration::from_secs(5));
    log_interval.tick().await; // consume immediate first tick

    let result = timeout(Duration::from_secs(60), async {
        loop {
            tokio::select! {
                msg = stream.next() => {
                    match msg {
                        Some(Ok(entries)) => {
                            if let Some((domain, cert)) = entries.entries.into_iter().next() {
                                tracing::info!(domain = %domain, "TLS certificate received from kernel state");
                                return Ok(cert);
                            }
                            // Empty entries — keep waiting.
                        }
                        Some(Err(e)) => return Err(Box::new(e) as Box<dyn std::error::Error>),
                        None => return Err("WatchAllCerts stream ended without data".into()),
                    }
                }
                _ = log_interval.tick() => {
                    tracing::info!("waiting for TLS certificate from kernel state...");
                }
            }
        }
    }).await;

    match result {
        Ok(inner) => inner,
        Err(_) => Err("no TLS certificate received within 60 seconds — shutting down".into()),
    }
}

/// Spawn a background task that watches GatewayTlsState.all_certs and
/// hot-reloads the TLS config when certificates change.
fn spawn_cert_watcher(
    channel: tonic::transport::Channel,
    token_provider: TokenProvider,
    tls_config: axum_server::tls_rustls::RustlsConfig,
) {
    tokio::spawn(async move {
        loop {
            match watch_cert_updates(channel.clone(), &token_provider, &tls_config).await {
                Ok(()) => tracing::warn!("WatchAllCerts stream ended, reconnecting"),
                Err(e) => {
                    tracing::error!(error = %e, "WatchAllCerts cert watcher failed, retrying in 5s");
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
    let mut client = GatewayTlsStateServiceClient::new(channel);

    let mut request = tonic::Request::new(Default::default());
    if let Ok(token) = (token_provider)().await {
        let val: tonic::metadata::MetadataValue<tonic::metadata::Ascii> =
            format!("Bearer {}", token).parse()
                .map_err(|e| format!("invalid token metadata: {e}"))?;
        request.metadata_mut().insert("authorization", val);
    }

    let response = client.watch_all_certs(request).await?;
    let mut stream = response.into_inner();

    tracing::info!("TLS cert watcher stream started");

    while let Some(msg) = stream.next().await {
        match msg {
            Ok(entries) => {
                if let Some((domain, cert)) = entries.entries.into_iter().next() {
                    match tls::build_server_config(&cert) {
                        Ok(new_config) => {
                            tls_config.reload_from_config(new_config);
                            tracing::info!(domain = %domain, "TLS certificate hot-reloaded");
                        }
                        Err(e) => {
                            tracing::error!(error = %e, "failed to build TLS config from updated cert");
                        }
                    }
                }
            }
            Err(e) => {
                tracing::warn!(error = %e, "WatchAllCerts stream error");
                return Err(e.into());
            }
        }
    }

    Ok(())
}

async fn healthz() -> StatusCode {
    StatusCode::OK
}

/// Load gateway-specific config from GATEWAY_CONFIG env var, or use defaults.
/// The bootstrap/kernel config (-c/--config, BOOTSTRAP_CONFIG) is handled
/// separately by the ServiceManager.
fn load_gateway_config() -> GatewayConfig {
    let mut cfg = match std::env::var("GATEWAY_CONFIG") {
        Ok(data) => config_from_bytes(data.as_bytes()).unwrap_or_else(|e| {
            tracing::warn!(error = %e, "failed to parse GATEWAY_CONFIG, using defaults");
            GatewayConfig::default()
        }),
        Err(_) => GatewayConfig::default(),
    };
    config_defaults(&mut cfg);
    cfg
}

/// Spawn a background task that watches kernel's CaState and updates the shared CA cert store.
fn spawn_ca_cert_watcher(
    channel: tonic::transport::Channel,
    token_provider: TokenProvider,
    ca_certs_store: Arc<tokio::sync::RwLock<Vec<gateway_tacplus::types::libs::x509::x509::X509Cert>>>,
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
    ca_certs_store: &tokio::sync::RwLock<Vec<gateway_tacplus::types::libs::x509::x509::X509Cert>>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use gateway_tacplus::types::services::kernel::kernel::ca_state_service_client::CaStateServiceClient;

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
) -> Result<Vec<gateway_tacplus::types::libs::x509::x509::X509Cert>, Box<dyn std::error::Error>> {
    use gateway_tacplus::types::services::kernel::kernel::ca_state_service_client::CaStateServiceClient;

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
    config: &gateway_tacplus::types::libs::grpcconfig::grpcconfig::Config,
    dynamic_cas: &[gateway_tacplus::types::libs::x509::x509::X509Cert],
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

/// Build a ClientTlsConfig for gRPC backend connections from a PEM CA bundle.
fn build_backend_tls_config_from_pem(ca_pem_bundle: &str) -> tonic::transport::ClientTlsConfig {
    let mut tls_config = tonic::transport::ClientTlsConfig::new();
    if !ca_pem_bundle.is_empty() {
        let ca_cert = tonic::transport::Certificate::from_pem(ca_pem_bundle);
        tls_config = tls_config.ca_certificate(ca_cert);
    }
    tls_config
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
