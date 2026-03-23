use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::sync::atomic::{AtomicBool, Ordering};

use tokio::sync::Notify;
use tokio_stream::StreamExt;
use tonic::transport::Channel;

use gateway_tacplus::types::services::kernel::kernel::service_health_state_service_client::ServiceHealthStateServiceClient;
use gateway_tacplus::types::services::kernel::kernel::InstancesEntriesResponse;

/// Token provider: returns a bearer token or an error.
/// Re-exported from the generated ServiceManager.
pub use gateway_tacplus::s2sm::TokenProvider;

/// A healthy service instance endpoint.
#[derive(Debug, Clone)]
pub struct ServiceEndpoint {
    pub host: String,
    pub port: i32,
}

/// HealthWatcher watches ServiceHealthState.instances from kernel via
/// WatchInstances streaming RPC and maintains an in-memory map of healthy
/// endpoints grouped by service_id.
#[derive(Clone)]
pub struct HealthWatcher {
    services: Arc<RwLock<HashMap<String, Vec<ServiceEndpoint>>>>,
    ready: Arc<Notify>,
    has_data: Arc<AtomicBool>,
}

impl HealthWatcher {
    /// Creates a HealthWatcher and starts watching the kernel's
    /// ServiceHealthState.instances collection.
    pub fn new(channel: Channel, token_provider: TokenProvider) -> Self {
        let hw = Self {
            services: Arc::new(RwLock::new(HashMap::new())),
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

    async fn start_watch(&self, channel: Channel, token_provider: &TokenProvider) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut client = ServiceHealthStateServiceClient::new(channel);

        let mut request = tonic::Request::new(());
        if let Ok(token) = (token_provider)().await {
            let val: tonic::metadata::MetadataValue<tonic::metadata::Ascii> = format!("Bearer {}", token)
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

        for inst in entries_response.entries.values() {
            if !is_routable(inst.status) {
                continue;
            }

            if let Some(ref ep) = inst.grpc_endpoint {
                if !ep.host.is_empty() {
                    let service_id = inst.service_id.clone();
                    grouped
                        .entry(service_id)
                        .or_default()
                        .push(ServiceEndpoint {
                            host: ep.host.clone(),
                            port: ep.port,
                        });
                }
            }
        }

        for (sid, eps) in &grouped {
            let addrs: Vec<String> = eps.iter().map(|e| format!("{}:{}", e.host, e.port)).collect();
            tracing::info!(
                service = %sid,
                instances = eps.len(),
                endpoints = ?addrs,
                "health update"
            );
        }

        let mut map = self.services.write().unwrap();
        *map = grouped;
        drop(map);

        if !self.has_data.swap(true, Ordering::Release) {
            self.ready.notify_waiters();
        }
    }
}

/// Returns true if the instance status is HEALTHY or DEGRADED.
fn is_routable(status: i32) -> bool {
    // INSTANCE_STATUS_HEALTHY = 1, INSTANCE_STATUS_DEGRADED = 2
    status == 1 || status == 2
}
