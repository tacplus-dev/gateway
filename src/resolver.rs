use std::sync::atomic::{AtomicUsize, Ordering};

use tonic::transport::{Channel, ClientTlsConfig, Endpoint};

use crate::health::HealthWatcher;

/// Round-robin resolver that uses HealthWatcher to provide tonic Channels
/// to healthy service instances. Connects via TLS using the cluster CA.
pub struct Resolver {
    health: HealthWatcher,
    tls_config: ClientTlsConfig,
    counter: AtomicUsize,
}

impl Resolver {
    pub fn new(health: HealthWatcher, tls_config: ClientTlsConfig) -> Self {
        Self {
            health,
            tls_config,
            counter: AtomicUsize::new(0),
        }
    }

    /// Returns a reference to the underlying HealthWatcher.
    pub fn health(&self) -> &HealthWatcher {
        &self.health
    }

    /// Create a tonic Channel to the given service_id.
    /// Connects to a healthy backend endpoint via TLS.
    pub fn dial(&self, service_id: &str) -> Channel {
        let endpoints = self.health.get_endpoints(service_id);
        self.dial_endpoints(service_id, &endpoints)
    }

    /// Try each unique endpoint with a raw TCP probe and return a channel to the
    /// first reachable one. Falls back to round-robin if no endpoint responds.
    ///
    /// `Channel::poll_ready()` is a no-op for lazy-connect channels — it always
    /// returns immediately without testing connectivity. A raw TCP connect is the
    /// only way to determine if a backend pod is actually reachable before
    /// committing the request.
    pub async fn dial_ready_any(&self, service_id: &str) -> Channel {
        let all_endpoints = self.health.get_endpoints(service_id);
        if all_endpoints.is_empty() {
            return self.dial_spiffe(service_id);
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
            // Fails fast (ECONNREFUSED) for dead pods; succeeds within ~1ms for live ones.
            let reachable = tokio::time::timeout(
                std::time::Duration::from_millis(500),
                tokio::net::TcpStream::connect(ep.as_str()),
            )
            .await
            .map(|r| r.is_ok())
            .unwrap_or(false);

            if reachable {
                let tls = self.tls_config.clone().domain_name("kernel");
                let uri = format!("https://{}", ep);
                tracing::debug!(service = %service_id, endpoint = %ep, "dial_ready_any: found live endpoint");
                return Endpoint::from_shared(uri)
                    .expect("valid endpoint URI")
                    .tls_config(tls)
                    .expect("valid TLS config")
                    .http2_keep_alive_interval(std::time::Duration::from_secs(10))
                    .keep_alive_while_idle(true)
                    .timeout(std::time::Duration::from_secs(300))
                    .connect_lazy();
            }
            tracing::debug!(service = %service_id, endpoint = %ep, "dial_ready_any: TCP probe failed, trying next");
        }
        tracing::warn!(service = %service_id, endpoints = unique.len(), "dial_ready_any: no live endpoint found");
        self.dial(service_id)
    }

    /// Create a tonic Channel to a service identified by its SPIFFE path.
    /// Uses hierarchical fallback: if "mud-controller/agent-42" has no
    /// registered endpoints, falls back to "mud-controller" (the parent).
    pub fn dial_spiffe(&self, spiffe_path: &str) -> Channel {
        let endpoints = self.health.get_endpoints_by_spiffe_path(spiffe_path);
        self.dial_endpoints(spiffe_path, &endpoints)
    }

    fn dial_endpoints(&self, label: &str, endpoints: &[String]) -> Channel {
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
        tracing::info!(service = %label, endpoint = %uri, "dialing service");
        // Override the TLS domain to "kernel" — all service certs have SAN DNS:kernel
        // because X509Mint uses the kernel's identity as the cert subject.
        let tls = self.tls_config.clone().domain_name("kernel");
        Endpoint::from_shared(uri)
            .expect("valid endpoint URI")
            .tls_config(tls)
            .expect("valid TLS config")
            .http2_keep_alive_interval(std::time::Duration::from_secs(10))
            .keep_alive_while_idle(true)
            .timeout(std::time::Duration::from_secs(300))
            .connect_lazy()
    }
}
