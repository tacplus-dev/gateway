mod auth;
mod config;
mod grpc_dispatch;
mod health;
mod mint;
mod registry;
mod resolver;
mod rest;
mod spa;
mod tls;

use std::sync::Arc;

use axum::http::StatusCode;
use axum::routing::get;
use tracing_subscriber::EnvFilter;

use gateway_tacplus::s2sm::ServiceManager;

use crate::config::GatewayConfig;
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
    let cfg = GatewayConfig::load();
    tracing::info!(
        tcp_addr = %cfg.tcp_listener,
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

    // Build a token provider closure for authenticated gRPC calls to kernel.
    let token_provider: TokenProvider = {
        let sm = Arc::clone(&sm);
        Arc::new(move || {
            let sm = Arc::clone(&sm);
            Box::pin(async move {
                match sm.get_token().await {
                    Ok(t) => Some(t),
                    Err(e) => {
                        tracing::warn!(error = %e, "failed to get token for kernel RPC");
                        None
                    }
                }
            })
        })
    };

    // 3. Load registry.json for routing metadata.
    let registry = Arc::new(registry::Registry::load());

    // 4. Start HealthWatcher (watches ServiceHealthState.instances from kernel).
    let health_watcher = health::HealthWatcher::new(kernel_channel.clone(), token_provider.clone());

    // 5. Create resolver (round-robin over healthy endpoints).
    let resolver = Arc::new(resolver::Resolver::new(health_watcher));

    // 6. Create gateway auth (watches JWK keys from kernel, validates tokens).
    let gateway_auth = Arc::new(auth::GatewayAuth::new(
        kernel_channel.clone(),
        Arc::clone(&registry),
        token_provider,
    ));

    // 7. Build gateway MintService (local OIDC/JWKS, delegates TokenMint/X509Mint to kernel).
    let mint_service = mint::GatewayMintService::new(
        kernel_channel.clone(),
        Arc::clone(&gateway_auth),
        String::new(), // issuer URL — empty = same origin
    );

    // 8. Build gRPC router: passthrough services + gateway MintService.
    let resolver_for_dial = Arc::clone(&resolver);
    let auth_fn = gateway_auth.auth_fn();

    #[allow(deprecated)]
    let grpc_router = {
        let server = tonic::transport::Server::builder();
        let tonic_router = gateway_tacplus::s2sm::internal::passthrough::passthrough::register_all(
            server,
            |service_id| resolver_for_dial.dial(service_id),
            auth_fn,
        );
        // Register gateway's MintService alongside passthrough services.
        use gateway_tacplus::types::services::gateway::gateway::mint_service_server::MintServiceServer;
        let tonic_router = tonic_router.add_service(MintServiceServer::new(mint_service));
        tonic_router.into_router()
    };

    // 9. Build HTTP router.
    let rest_state = Arc::new(rest::AppState {
        resolver: Arc::clone(&resolver),
        auth: Arc::clone(&gateway_auth),
        registry: Arc::clone(&registry),
        kernel_channel: kernel_channel.clone(),
    });

    // Layer the routers: gRPC routes first, then HTTP routes, then REST + SPA fallback.
    // Since tonic's into_router() includes a fallback, and rest::router() uses a fallback
    // for catch-all REST routing, we need to nest them using fallback_service chains.
    let spa_and_rest = rest::router(rest_state)
        .route("/healthz", get(healthz))
        .route("/readyz", get(healthz))
        .route("/registry/:file", get(spa::registry_handler))
        .fallback(spa::spa_handler);

    // gRPC requests have content-type application/grpc and match tonic's routes.
    // Everything else falls through to the REST/SPA layer.
    let app = grpc_router.fallback_service(spa_and_rest);

    // 10. Build TLS config.
    let tls_config = tls::build_server_config(&cfg)?;
    let tls_acceptor = axum_server::tls_rustls::RustlsConfig::from_config(Arc::new(tls_config));

    // 11. Start TLS listener — serves both HTTP and gRPC on the same port.
    let tcp_addr = cfg.tcp_listener;
    tracing::info!(addr = %tcp_addr, "listening (TLS, HTTP+gRPC)");

    axum_server::bind_rustls(tcp_addr, tls_acceptor)
        .serve(app.into_make_service())
        .await?;

    // Graceful shutdown.
    sm.close();

    Ok(())
}

async fn healthz() -> StatusCode {
    StatusCode::OK
}
