use std::sync::atomic::{AtomicUsize, Ordering};

use tonic::transport::{Channel, Endpoint};

use crate::health::HealthWatcher;

/// Round-robin resolver that uses HealthWatcher to provide tonic Channels
/// to healthy service instances.
pub struct Resolver {
    health: HealthWatcher,
    counter: AtomicUsize,
}

impl Resolver {
    pub fn new(health: HealthWatcher) -> Self {
        Self {
            health,
            counter: AtomicUsize::new(0),
        }
    }

    /// Resolve a single healthy backend address for the given service.
    /// Uses round-robin across healthy instances.
    pub fn resolve_addr(&self, service_id: &str) -> Option<String> {
        let endpoints = self.health.get_endpoints(service_id);
        if endpoints.is_empty() {
            return None;
        }
        let idx = self.counter.fetch_add(1, Ordering::Relaxed) % endpoints.len();
        Some(endpoints[idx].clone())
    }

    /// Create a tonic Channel to the given service_id.
    /// Connects to a healthy backend endpoint via the health resolver.
    pub fn dial(&self, service_id: &str) -> Channel {
        let endpoints = self.health.get_endpoints(service_id);
        if endpoints.is_empty() {
            tracing::warn!(service = %service_id, "no healthy endpoints, creating placeholder channel");
            // Return a channel that will fail on use — the passthrough handler
            // will get a connection error which maps to UNAVAILABLE.
            return Endpoint::from_static("http://[::1]:1")
                .connect_lazy();
        }

        // Build a channel that load-balances across all healthy endpoints.
        // For tonic 0.12, we create an endpoint for each address.
        if endpoints.len() == 1 {
            let uri = format!("http://{}", endpoints[0]);
            tracing::info!(service = %service_id, endpoint = %uri, "dialing service");
            return Endpoint::from_shared(uri)
                .expect("valid endpoint URI")
                .connect_lazy();
        }

        // Multiple endpoints: use round-robin by picking one.
        // tonic's built-in load balancing requires tower::discover which is complex;
        // for now, pick one via round-robin on each dial() call.
        let idx = self.counter.fetch_add(1, Ordering::Relaxed) % endpoints.len();
        let uri = format!("http://{}", endpoints[idx]);
        tracing::info!(service = %service_id, endpoint = %uri, "dialing service (round-robin)");
        Endpoint::from_shared(uri)
            .expect("valid endpoint URI")
            .connect_lazy()
    }
}
