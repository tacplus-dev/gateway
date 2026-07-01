mod auth;
mod client_download;
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

use gateway_model::s2sm::{rest_dispatch::REST_ROOT_PATH, ServiceManager};
use gateway_model::types::libs::host::host::Host;
use gateway_model::types::services::gateway::gateway::ExternalTlsMode;
use gateway_model::types::services::letsencrypt::letsencrypt::lets_encrypt_state_service_client::LetsEncryptStateServiceClient;
use gateway_model::types::services::letsencrypt::letsencrypt::LetsEncryptCertData;
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
    // 1. Connect to kernel via ServiceManager.
    // SM loads bootstrap config, creates connection pool, StateClients, GrpcClients.
    let sm = Arc::new(ServiceManager::new().await?);
    let kernel_channel = sm.conn().await
        .ok_or("no active kernel connection")?;

    tracing::info!("ServiceManager connected to kernel");

    // 2. Fetch gateway config from kernel state (delivered by operator via bootstrap).
    let cfg = sm
        .state_clients()
        .services()
        .gateway_config_state()
        .config()
        .fetch()
        .await
        .map_err(|e| format!("failed to fetch gateway config from kernel: {e}"))?;

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

    // Initialize bootstrap config for SPA — webapp reads window.__CAVALIER__ for gateway URL.
    // Empty string = same origin (webapp is served by the gateway itself).
    spa::init_bootstrap("");

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
            let cert_data = wait_for_tls_cert(kernel_channel.clone(), &token_provider).await?;
            let chain = cert_data.tls_cert
                .as_ref()
                .ok_or("LetsEncryptState cert_data has no tls_cert")?;
            tls::build_server_config(chain)?
        }
        ExternalTlsMode::Unspecified => {
            return Err("external_tls_mode must be set in gateway config (cert_chain or letsencrypt)".into());
        }
    };
    let tls_acceptor = axum_server::tls_rustls::RustlsConfig::from_config(tls_config);

    // Spawn cert hot-reload watcher for letsencrypt mode (cert_chain is static config).
    if cfg.external_tls_mode() == ExternalTlsMode::Letsencrypt {
        spawn_cert_watcher(kernel_channel.clone(), token_provider.clone(), tls_acceptor.clone());
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

    // Store CA certs in a shared RwLock so the Mint service can serve them via ListPublicCa.
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

    // Derive the public OIDC issuer URL from configured external_hostnames.
    // Kernel signs JWTs with `https://<host>/api/v1` as `iss`; discovery must
    // advertise that exact value for external verifiers such as Anthropic WIF.
    let issuer_url = cfg
        .external_hostnames
        .first()
        .map(|h| format!("https://{}{}", h, REST_ROOT_PATH))
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

    // 9. Create trace publisher (shared between gRPC proxy and REST handler).
    let trace_publish = sm.create_trace_publisher().await;
    let trace_publisher: Arc<
        dyn Fn(gateway_model::types::libs::trace::TraceEvent) + Send + Sync,
    > = Arc::new(move |event| {
        if trace_publish(event).is_err() {
            tracing::warn!("trace publisher queue full, dropping trace event");
        }
    });

    // 10. Build gRPC router: Mint (native tonic) + raw proxy for all other services.
    let sm_for_grpc_trace = Arc::clone(&sm);
    let proxy_state = Arc::new(proxy_grpc::ProxyState {
        resolver: Arc::clone(&resolver),
        auth: Arc::clone(&gateway_auth),
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
        ca_certs: Arc::clone(&ca_certs_store),
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
    let registry_route = format!("{}/registry/{{file}}", gateway_model::s2sm::rest_dispatch::REST_ROOT_PATH);
    let client_route = format!("{}/client/{{os}}/{{arch}}", gateway_model::s2sm::rest_dispatch::REST_ROOT_PATH);
    let client_auth = Arc::clone(&gateway_auth);
    let spa_and_rest = rest_translation::router(rest_state)
        .route("/healthz", get(healthz))
        .route("/readyz", get(healthz))
        .route(&registry_route, get(spa::registry_handler))
        .route(&client_route, get(move |path, req| client_download::handler(path, req, client_auth.clone())))
        .fallback(spa::spa_handler);

    // Intercept gRPC requests before they reach REST/SPA routing.
    // Native gRPC clients (operator, service-to-service) send content-type: application/grpc.
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

/// Wait for a TLS certificate from LetsEncryptState.cert_data.
/// Logs every 5 seconds while waiting. Returns error after 60 seconds.
async fn wait_for_tls_cert(
    channel: tonic::transport::Channel,
    token_provider: &TokenProvider,
) -> Result<LetsEncryptCertData, Box<dyn std::error::Error>> {
    let mut client = LetsEncryptStateServiceClient::new(channel);

    let mut request = tonic::Request::new(Default::default());
    if let Ok(token) = (token_provider)().await {
        let val: tonic::metadata::MetadataValue<tonic::metadata::Ascii> =
            format!("Bearer {}", token).parse()
                .map_err(|_| "invalid token metadata")?;
        request.metadata_mut().insert("authorization", val);
    }

    let response = client.watch_cert_data(request).await?;
    let mut stream = response.into_inner();

    let mut log_interval = tokio::time::interval(Duration::from_secs(5));
    log_interval.tick().await; // consume immediate first tick

    let result = timeout(Duration::from_secs(60), async {
        loop {
            tokio::select! {
                msg = stream.next() => {
                    match msg {
                        Some(Ok(cert_data)) if cert_data.tls_cert.is_some() => {
                            tracing::info!(
                                hostnames = ?cert_data.hostnames,
                                "TLS certificate received from LetsEncryptState"
                            );
                            return Ok(cert_data);
                        }
                        Some(Ok(_)) => {
                            // Empty cert_data — keep waiting.
                        }
                        Some(Err(e)) => return Err(Box::new(e) as Box<dyn std::error::Error>),
                        None => return Err("WatchCertData stream ended without data".into()),
                    }
                }
                _ = log_interval.tick() => {
                    tracing::info!("waiting for TLS certificate from LetsEncryptState...");
                }
            }
        }
    }).await;

    match result {
        Ok(inner) => inner,
        Err(_) => Err("no TLS certificate received within 60 seconds — shutting down".into()),
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
            Ok(cert_data) => {
                if let Some(chain) = cert_data.tls_cert.as_ref() {
                    match tls::build_server_config(chain) {
                        Ok(new_config) => {
                            tls_config.reload_from_config(new_config);
                            tracing::info!(hostnames = ?cert_data.hostnames, "TLS certificate hot-reloaded");
                        }
                        Err(e) => {
                            tracing::error!(error = %e, "failed to build TLS config from renewed cert");
                        }
                    }
                }
            }
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
    ca_certs_store: Arc<tokio::sync::RwLock<Vec<gateway_model::types::libs::x509::x509::X509Cert>>>,
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
    ca_certs_store: &tokio::sync::RwLock<Vec<gateway_model::types::libs::x509::x509::X509Cert>>,
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
) -> Result<Vec<gateway_model::types::libs::x509::x509::X509Cert>, Box<dyn std::error::Error>> {
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
    config: &gateway_model::types::libs::grpcconfig::grpcconfig::Config,
    dynamic_cas: &[gateway_model::types::libs::x509::x509::X509Cert],
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
