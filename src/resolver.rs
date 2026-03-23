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

    /// Create a tonic Channel to the given service_id.
    /// Connects to a healthy backend endpoint via TLS.
    pub fn dial(&self, service_id: &str) -> Channel {
        let endpoints = self.health.get_endpoints(service_id);
        if endpoints.is_empty() {
            tracing::warn!(service = %service_id, "no healthy endpoints, creating placeholder channel");
            return Endpoint::from_static("http://[::1]:1")
                .connect_lazy();
        }

        let idx = if endpoints.len() == 1 {
            0
        } else {
            self.counter.fetch_add(1, Ordering::Relaxed) % endpoints.len()
        };

        let uri = format!("https://{}", endpoints[idx]);
        tracing::info!(service = %service_id, endpoint = %uri, "dialing service");
        // Override the TLS domain to "kernel" — all service certs have SAN DNS:kernel
        // because X509Mint uses the kernel's identity as the cert subject.
        let tls = self.tls_config.clone().domain_name("kernel");
        Endpoint::from_shared(uri)
            .expect("valid endpoint URI")
            .tls_config(tls)
            .expect("valid TLS config")
            .connect_lazy()
    }
}
