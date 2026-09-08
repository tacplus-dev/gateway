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
    /// Test-only: dial backends over plaintext h2c instead of TLS. Production
    /// always speaks TLS to backends; the entitlement end-to-end test stands its
    /// backend up on a bare socket because the decision it proves — does this
    /// caller's grant admit this method — is made before any dial and does not
    /// depend on the transport.
    #[cfg(test)]
    plaintext: bool,
}

impl Resolver {
    pub fn new(health: HealthWatcher, tls_verifier: Arc<SpiffeServerCertVerifier>) -> Self {
        Self {
            health,
            tls_verifier,
            counter: AtomicUsize::new(0),
            #[cfg(test)]
            plaintext: false,
        }
    }

    /// Test-only constructor: see the `plaintext` field.
    #[cfg(test)]
    pub fn plaintext_backends(
        health: HealthWatcher,
        tls_verifier: Arc<SpiffeServerCertVerifier>,
    ) -> Self {
        Self {
            health,
            tls_verifier,
            counter: AtomicUsize::new(0),
            plaintext: true,
        }
    }

    #[cfg(test)]
    fn scheme(&self) -> &'static str {
        if self.plaintext {
            "http"
        } else {
            "https"
        }
    }

    #[cfg(not(test))]
    fn scheme(&self) -> &'static str {
        "https"
    }

    /// Returns a reference to the underlying HealthWatcher.
    pub fn health(&self) -> &HealthWatcher {
        &self.health
    }

    /// Create a tonic Channel to the given service_id.
    /// Connects eagerly to a healthy backend endpoint via TLS.
    ///
    /// `route_key` selects the health entry and `service_label` is the
    /// location-agnostic SPIFFE service the backend's certificate must present.
    /// They are the same string for a shared service. For a tenant-owned one
    /// they differ: the instance is registered as `<svc>-<tenant>` (the name the
    /// operator deploys, item 4 §2.3) while its certificate carries
    /// `spiffe://<td>/tenants/<tenant>/services/<svc>`, whose location-agnostic
    /// service label is the bare `<svc>`.
    pub async fn dial(&self, route_key: &str, service_label: &str) -> Channel {
        let endpoints = self.health.get_endpoints(route_key);
        self.dial_endpoints(route_key, service_label, &endpoints)
            .await
    }

    /// Try each unique endpoint with a raw TCP probe and return a channel to the
    /// first reachable one. Falls back to round-robin if no endpoint responds.
    pub async fn dial_ready_any(&self, route_key: &str, service_label: &str) -> Channel {
        let all_endpoints = self.health.get_endpoints(route_key);
        if all_endpoints.is_empty() {
            return self.dial_spiffe(route_key, service_label).await;
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
                let verifier = self.tls_verifier(service_label);
                let uri = format!("{}://{}", self.scheme(), ep);
                tracing::debug!(service = %route_key, endpoint = %ep, "dial_ready_any: found live endpoint");
                match Self::connect_eager(&uri, verifier).await {
                    Ok(ch) => return ch,
                    Err(e) => {
                        tracing::warn!(service = %route_key, endpoint = %ep, error = %e, "eager connect failed after TCP probe");
                    }
                }
            }
            tracing::debug!(service = %route_key, endpoint = %ep, "dial_ready_any: TCP probe failed, trying next");
        }
        tracing::warn!(service = %route_key, endpoints = unique.len(), "dial_ready_any: no live endpoint found");
        self.dial(route_key, service_label).await
    }

    /// Create a tonic Channel to a service identified by its SPIFFE path.
    pub async fn dial_spiffe(&self, spiffe_path: &str, service_label: &str) -> Channel {
        let endpoints = self.health.get_endpoints_by_spiffe_path(spiffe_path);
        self.dial_endpoints(spiffe_path, service_label, &endpoints)
            .await
    }

    async fn dial_endpoints(
        &self,
        label: &str,
        service_label: &str,
        endpoints: &[String],
    ) -> Channel {
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

        let uri = format!("{}://{}", self.scheme(), endpoints[idx]);
        let verifier = self.tls_verifier(service_label);

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
        let endpoint = Endpoint::from_shared(uri.to_string())?;
        // A plaintext target carries no server cert to verify (test-only path).
        let endpoint = if uri.starts_with("http://") {
            endpoint
        } else {
            endpoint.tls_config_with_verifier(ClientTlsConfig::new(), verifier)?
        };
        let endpoint = endpoint
            .http2_keep_alive_interval(std::time::Duration::from_secs(10))
            .keep_alive_while_idle(true)
            .keep_alive_timeout(std::time::Duration::from_secs(60));
        let channel = endpoint.connect().await?;
        Ok(channel)
    }

    /// Narrows the trust-domain verifier to one service identity. The generated
    /// `SpiffeServerCertVerifier` compares this against the certificate's
    /// location-agnostic service label, so it matches both
    /// `spiffe://<td>/system/<loc...>/services/<svc>` and the tenant-owned
    /// `spiffe://<td>/tenants/<tenant>/services/<svc>` — see the decision doc's
    /// Open question 4 for what it does NOT pin.
    fn tls_verifier(
        &self,
        service_label: &str,
    ) -> Arc<dyn rustls::client::danger::ServerCertVerifier> {
        self.tls_verifier.clone().expect_service(service_label)
    }
}

#[cfg(test)]
mod tests {
    /// The property `tls_verifier()` relies on, asserted against the generated
    /// parser rather than assumed: a tenant-owned backend's certificate names
    /// `spiffe://<td>/tenants/<tenant>/services/<svc>`, and that ID must
    /// classify as a SERVICE whose location-agnostic label is the bare `<svc>` —
    /// which is what `SpiffeServerCertVerifier::expect_service` compares
    /// against. Before the model was regenerated (decision doc §1.2) this shape
    /// parsed as `Unknown` and every tenant-owned backend's cert was rejected.
    #[test]
    fn a_tenant_owned_backend_identity_is_a_service_named_by_its_bare_label() {
        let tenant = gateway_spiffe::parse_spiffe_id(
            "spiffe://local.dev/tenants/acme/services/docmanager",
        )
        .expect("the canonical tenant-owned service identity must parse");

        assert_eq!(tenant.subject_kind, gateway_spiffe::SubjectKind::Service);
        assert_eq!(tenant.subject_path, "docmanager");
        assert_eq!(tenant.namespace, "/tenants/acme");

        // The shared shape is unchanged, and reduces to the same label — which
        // is why one `expect_service(service_id)` serves both.
        let system = gateway_spiffe::parse_spiffe_id(
            "spiffe://local.dev/system/us-east/services/docmanager",
        )
        .expect("the shared service identity must parse");
        assert_eq!(system.subject_kind, gateway_spiffe::SubjectKind::Service);
        assert_eq!(system.subject_path, "docmanager");
        assert_eq!(system.namespace, "/system/us-east");
    }
}
