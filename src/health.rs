use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};

use tokio::sync::Notify;
use tokio_stream::StreamExt;
use tonic::transport::Channel;

use gateway_model::types::sys::servicehealth::servicehealth::service_health_state_service_client::ServiceHealthStateServiceClient;
use gateway_model::types::sys::servicehealth::servicehealth::InstancesEntriesResponse;

const SERVICE_HEALTH_MAX_MESSAGE_BYTES: usize = 64 * 1024 * 1024;

/// Token provider: returns a bearer token or an error.
/// Re-exported from the generated ServiceManager.
pub use gateway_model::s2sm::TokenProvider;

/// A healthy service instance endpoint.
#[derive(Debug, Clone)]
pub struct ServiceEndpoint {
    pub host: String,
    pub port: i32,
}

/// HealthWatcher watches ServiceHealthState.instances from kernel via
/// WatchInstances streaming RPC and maintains an in-memory map of healthy
/// endpoints grouped by service_id and by SPIFFE path.
#[derive(Clone)]
pub struct HealthWatcher {
    services: Arc<RwLock<HashMap<String, Vec<ServiceEndpoint>>>>,
    /// SPIFFE path index: maps the service-relative path segment of a SPIFFE URI
    /// (e.g., "mud-controller/agent-42") to endpoints. Used for hierarchical routing.
    spiffe_services: Arc<RwLock<HashMap<String, Vec<ServiceEndpoint>>>>,
    ready: Arc<Notify>,
    has_data: Arc<AtomicBool>,
}

impl HealthWatcher {
    /// Creates a HealthWatcher and starts watching the kernel's
    /// ServiceHealthState.instances collection.
    pub fn new(channel: Channel, token_provider: TokenProvider) -> Self {
        let hw = Self {
            services: Arc::new(RwLock::new(HashMap::new())),
            spiffe_services: Arc::new(RwLock::new(HashMap::new())),
            ready: Arc::new(Notify::new()),
            has_data: Arc::new(AtomicBool::new(false)),
        };

        let hw_clone = hw.clone();
        tokio::spawn(async move {
            hw_clone.watch_loop(channel, token_provider).await;
        });

        hw
    }

    /// Waits until the first batch of health data has been received.
    pub async fn wait_ready(&self) {
        if self.has_data.load(Ordering::Acquire) {
            return;
        }
        self.ready.notified().await;
    }

    /// Builds a HealthWatcher with a fixed endpoint table and no kernel watch.
    /// Test-only: the real constructor needs a live kernel channel to stream
    /// ServiceHealthState.instances from.
    #[cfg(test)]
    pub fn seeded(services: HashMap<String, Vec<ServiceEndpoint>>) -> Self {
        Self {
            services: Arc::new(RwLock::new(services)),
            spiffe_services: Arc::new(RwLock::new(HashMap::new())),
            ready: Arc::new(Notify::new()),
            has_data: Arc::new(AtomicBool::new(true)),
        }
    }

    /// Returns gRPC endpoints (host:port) for healthy instances of a service.
    pub fn get_endpoints(&self, service_id: &str) -> Vec<String> {
        let map = self.services.read().unwrap();
        map.get(service_id)
            .map(|endpoints| {
                endpoints
                    .iter()
                    .map(|ep| format!("{}:{}", ep.host, ep.port))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Returns gRPC endpoints for an exact SPIFFE path match.
    /// The path is the service-relative portion (e.g., "mud-controller/agent-42").
    /// No hierarchical fallback — multi-segment paths must match exactly or fail.
    pub fn get_endpoints_by_spiffe_path(&self, path: &str) -> Vec<String> {
        let map = self.spiffe_services.read().unwrap();
        map.get(path)
            .map(|endpoints| {
                endpoints
                    .iter()
                    .map(|ep| format!("{}:{}", ep.host, ep.port))
                    .collect()
            })
            .unwrap_or_default()
    }

    async fn watch_loop(&self, channel: Channel, token_provider: TokenProvider) {
        loop {
            match self.start_watch(channel.clone(), &token_provider).await {
                Ok(()) => {
                    tracing::warn!("WatchInstances stream ended, reconnecting");
                }
                Err(e) => {
                    tracing::error!(error = %e, "WatchInstances failed, retrying in 5s");
                    tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                }
            }
        }
    }

    async fn start_watch(
        &self,
        channel: Channel,
        token_provider: &TokenProvider,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut client = ServiceHealthStateServiceClient::new(channel)
            .max_decoding_message_size(SERVICE_HEALTH_MAX_MESSAGE_BYTES);

        let mut request = tonic::Request::new(Default::default());
        if let Ok(token) = (token_provider)().await {
            let val: tonic::metadata::MetadataValue<tonic::metadata::Ascii> =
                format!("Bearer {}", token)
                    .parse()
                    .map_err(|_| "invalid token metadata")?;
            request.metadata_mut().insert("authorization", val);
        }

        let response = client.watch_instances(request).await?;
        let mut stream = response.into_inner();

        tracing::info!("WatchInstances stream started");

        while let Some(msg) = stream.next().await {
            match msg {
                Ok(entries_response) => {
                    self.process_entries(&entries_response);
                }
                Err(e) => {
                    tracing::warn!(error = %e, "WatchInstances stream error");
                    return Err(e.into());
                }
            }
        }

        Ok(())
    }

    fn process_entries(&self, entries_response: &InstancesEntriesResponse) {
        let mut grouped: HashMap<String, Vec<ServiceEndpoint>> = HashMap::new();
        let mut spiffe_grouped: HashMap<String, Vec<ServiceEndpoint>> = HashMap::new();

        for inst in entries_response.entries.values() {
            if !is_routable(inst.status) {
                continue;
            }

            if let Some(ref ep) = inst.grpc_endpoint {
                if !ep.host.is_empty() {
                    let endpoint = ServiceEndpoint {
                        host: ep.host.clone(),
                        port: ep.port,
                    };

                    // Index by service_id. When service_id is a SPIFFE URI
                    // (e.g., "spiffe://local/dev/fleetwood"), also index by
                    // the extracted service path ("fleetwood") so that
                    // dial("fleetwood") works.
                    grouped
                        .entry(inst.service_id.clone())
                        .or_default()
                        .push(endpoint.clone());

                    if let Some(path) = extract_spiffe_service_path(&inst.service_id) {
                        if path != inst.service_id {
                            grouped
                                .entry(path.clone())
                                .or_default()
                                .push(endpoint.clone());
                        }
                    }

                    // Index by SPIFFE path if present.
                    if !inst.spiffe_id.is_empty() {
                        if let Some(path) = extract_spiffe_service_path(&inst.spiffe_id) {
                            spiffe_grouped.entry(path).or_default().push(endpoint);
                        }
                    }
                }
            }
        }

        for (sid, eps) in &grouped {
            let addrs: Vec<String> = eps
                .iter()
                .map(|e| format!("{}:{}", e.host, e.port))
                .collect();
            tracing::info!(
                service = %sid,
                instances = eps.len(),
                endpoints = ?addrs,
                "health update"
            );
        }

        {
            let mut map = self.services.write().unwrap();
            *map = grouped;
        }
        {
            let mut map = self.spiffe_services.write().unwrap();
            *map = spiffe_grouped;
        }

        if !self.has_data.swap(true, Ordering::Release) {
            self.ready.notify_waiters();
        }
    }
}

/// Returns true if the instance status is HEALTHY or DEGRADED.
fn is_routable(status: i32) -> bool {
    use gateway_model::types::sys::healthreport::healthreport::InstanceStatus;
    matches!(
        InstanceStatus::try_from(status),
        Ok(InstanceStatus::Healthy | InstanceStatus::Degraded)
    )
}

/// Extracts the service-relative path from a SPIFFE URI.
/// Input:  "spiffe://schematic/cluster-prod/mud-controller/agent-42"
/// Output: "mud-controller/agent-42"
///
/// The SPIFFE URI format is spiffe://<org>/<cluster>/<service>[/<child>/...].
/// We strip the first three segments (scheme + org + cluster) since traffic
/// arriving at the gateway is already cluster-scoped.
fn extract_spiffe_service_path(spiffe_id: &str) -> Option<String> {
    let stripped = spiffe_id.strip_prefix("spiffe://")?;
    // Split: org / cluster / service [/ child / ...]
    let mut parts = stripped.splitn(3, '/');
    let _org = parts.next()?; // e.g., "schematic"
    let _cluster = parts.next()?; // e.g., "cluster-prod"
    let service_path = parts.next()?; // e.g., "mud-controller/agent-42"
    if service_path.is_empty() {
        return None;
    }
    Some(service_path.to_string())
}
