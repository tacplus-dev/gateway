use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};

use gateway_servicemanager::SpiffeServerCertVerifier;
use tonic::transport::{Channel, ClientTlsConfig, Endpoint};

use crate::health::HealthWatcher;

/// Round-robin resolver that uses HealthWatcher to provide tonic Channels
/// to healthy service instances. Connects via TLS using the cluster CA.
///
/// Uses eager `Endpoint::connect()` for all connections. Lazy channels
/// (`connect_lazy()`) cause a 30s stream death from HTTP/2 keep-alive
/// interactions. Eager connections are proven stable (S2S streams live
/// for hours without disconnects).
pub struct Resolver {
    health: HealthWatcher,
    tls_verifier: Arc<SpiffeServerCertVerifier>,
    counter: AtomicUsize,
}

impl Resolver {
    pub fn new(health: HealthWatcher, tls_verifier: Arc<SpiffeServerCertVerifier>) -> Self {
        Self {
            health,
            tls_verifier,
            counter: AtomicUsize::new(0),
        }
    }

    /// Returns a reference to the underlying HealthWatcher.
    pub fn health(&self) -> &HealthWatcher {
        &self.health
    }

    /// Create a tonic Channel to the given service_id.
    /// Connects eagerly to a healthy backend endpoint via TLS.
    pub async fn dial(&self, service_id: &str) -> Channel {
        let endpoints = self.health.get_endpoints(service_id);
        self.dial_endpoints(service_id, &endpoints).await
    }

    /// Try each unique endpoint with a raw TCP probe and return a channel to the
    /// first reachable one. Falls back to round-robin if no endpoint responds.
    pub async fn dial_ready_any(&self, service_id: &str) -> Channel {
        let all_endpoints = self.health.get_endpoints(service_id);
        if all_endpoints.is_empty() {
            return self.dial_spiffe(service_id).await;
        }

        // Deduplicate: try each unique endpoint address exactly once.
        let mut seen = std::collections::HashSet::new();
        let unique: Vec<String> = all_endpoints
            .iter()
            .filter(|ep| seen.insert(ep.as_str()))
            .cloned()
            .collect();

        for ep in &unique {
            // TCP probe — drops the TcpStream immediately after connect.
            let reachable = tokio::time::timeout(
                std::time::Duration::from_millis(500),
                tokio::net::TcpStream::connect(ep.as_str()),
            )
            .await
            .map(|r| r.is_ok())
            .unwrap_or(false);

            if reachable {
                let verifier = self.tls_verifier(service_id);
                let uri = format!("https://{}", ep);
                tracing::debug!(service = %service_id, endpoint = %ep, "dial_ready_any: found live endpoint");
                match Self::connect_eager(&uri, verifier).await {
                    Ok(ch) => return ch,
                    Err(e) => {
                        tracing::warn!(service = %service_id, endpoint = %ep, error = %e, "eager connect failed after TCP probe");
                    }
                }
            }
            tracing::debug!(service = %service_id, endpoint = %ep, "dial_ready_any: TCP probe failed, trying next");
        }
        tracing::warn!(service = %service_id, endpoints = unique.len(), "dial_ready_any: no live endpoint found");
        self.dial(service_id).await
    }

    /// Create a tonic Channel to a service identified by its SPIFFE path.
    pub async fn dial_spiffe(&self, spiffe_path: &str) -> Channel {
        let endpoints = self.health.get_endpoints_by_spiffe_path(spiffe_path);
        self.dial_endpoints(spiffe_path, &endpoints).await
    }

    async fn dial_endpoints(&self, label: &str, endpoints: &[String]) -> Channel {
        if endpoints.is_empty() {
            tracing::warn!(service = %label, "no healthy endpoints, creating placeholder channel");
            return Endpoint::from_static("http://[::1]:1")
                .connect_lazy();
        }

        let idx = if endpoints.len() == 1 {
            0
        } else {
            self.counter.fetch_add(1, Ordering::Relaxed) % endpoints.len()
        };

        let uri = format!("https://{}", endpoints[idx]);
        let verifier = self.tls_verifier(label);

        match Self::connect_eager(&uri, verifier.clone()).await {
            Ok(ch) => {
                tracing::debug!(service = %label, endpoint = %uri, "connected");
                ch
            }
            Err(e) => {
                // Fall back to lazy if eager fails (e.g., during startup race).
                tracing::warn!(service = %label, endpoint = %uri, error = %e, "eager connect failed, falling back to lazy");
                Endpoint::from_shared(uri)
                    .expect("valid endpoint URI")
                    .tls_config_with_verifier(ClientTlsConfig::new(), verifier)
                    .expect("valid TLS config")
                    .connect_lazy()
            }
        }
    }

    /// Eagerly connect to an endpoint with keep-alive settings.
    ///
    /// No `.timeout()` is set on the endpoint: tonic's `Endpoint::timeout()`
    /// applies the timeout to the entire RPC, which for streaming RPCs (bidi,
    /// server-stream) is a hard wall-clock kill — not an idle timeout. Long-
    /// lived streams like `oauth.Session.Session` (held open while the user
    /// authenticates in the browser) and `eventbus.Trace.WatchTrace` must not
    /// be capped here. HTTP/2 keep-alive pings detect dead peers; per-call
    /// deadlines belong on individual unary calls, not on the channel.
    async fn connect_eager(
        uri: &str,
        verifier: Arc<dyn rustls::client::danger::ServerCertVerifier>,
    ) -> Result<Channel, Box<dyn std::error::Error>> {
        let endpoint = Endpoint::from_shared(uri.to_string())?
            .tls_config_with_verifier(ClientTlsConfig::new(), verifier)?
            .http2_keep_alive_interval(std::time::Duration::from_secs(10))
            .keep_alive_while_idle(true)
            .keep_alive_timeout(std::time::Duration::from_secs(60));
        let channel = endpoint.connect().await?;
        Ok(channel)
    }

    fn tls_verifier(&self, service_id: &str) -> Arc<dyn rustls::client::danger::ServerCertVerifier> {
        self.tls_verifier.clone().expect_service(service_id)
    }
}
