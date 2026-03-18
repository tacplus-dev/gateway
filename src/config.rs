use std::net::SocketAddr;

use serde::Deserialize;

/// Gateway configuration.
/// Loaded from GATEWAY_CONFIG env var (JSON) or defaults.
#[derive(Debug, Clone, Deserialize)]
pub struct GatewayConfig {
    /// TCP listen address for HTTP/1.1, HTTP/2, and gRPC.
    #[serde(default = "default_tcp_listener")]
    pub tcp_listener: SocketAddr,

    /// UDP listen address for HTTP/3 (QUIC).
    #[allow(dead_code)]
    #[serde(default = "default_quic_listener")]
    pub quic_listener: SocketAddr,

    /// Kernel gRPC address for ServiceManager connection.
    #[serde(default = "default_kernel_addr")]
    pub kernel_addr: String,

    /// Enable HTTP/1.1 and HTTP/2 serving.
    #[serde(default = "default_true")]
    pub enable_http: bool,

    /// Enable HTTP/3 (QUIC) serving.
    #[serde(default)]
    pub enable_http3: bool,

    /// Enable gRPC passthrough.
    #[serde(default = "default_true")]
    pub enable_grpc: bool,

    /// TLS certificate PEM file path (optional, generates self-signed if absent).
    pub tls_cert_path: Option<String>,

    /// TLS private key PEM file path (optional).
    pub tls_key_path: Option<String>,
}

fn default_tcp_listener() -> SocketAddr {
    "0.0.0.0:8443".parse().unwrap()
}

fn default_quic_listener() -> SocketAddr {
    "0.0.0.0:8443".parse().unwrap()
}

fn default_kernel_addr() -> String {
    "http://localhost:5701".to_string()
}

fn default_true() -> bool {
    true
}

impl Default for GatewayConfig {
    fn default() -> Self {
        Self {
            tcp_listener: default_tcp_listener(),
            quic_listener: default_quic_listener(),
            kernel_addr: default_kernel_addr(),
            enable_http: true,
            enable_http3: false,
            enable_grpc: true,
            tls_cert_path: None,
            tls_key_path: None,
        }
    }
}

impl GatewayConfig {
    /// Load config from environment or config file.
    /// Checks: GATEWAY_CONFIG env var (JSON string), -c/--config flag, then defaults.
    pub fn load() -> Self {
        // Try GATEWAY_CONFIG env var
        if let Ok(json) = std::env::var("GATEWAY_CONFIG") {
            match serde_json::from_str(&json) {
                Ok(cfg) => return cfg,
                Err(e) => {
                    tracing::warn!(error = %e, "failed to parse GATEWAY_CONFIG, using defaults");
                }
            }
        }

        // Try -c/--config flag
        let args: Vec<String> = std::env::args().collect();
        for i in 0..args.len().saturating_sub(1) {
            if args[i] == "-c" || args[i] == "--config" {
                match std::fs::read_to_string(&args[i + 1]) {
                    Ok(content) => match serde_json::from_str(&content) {
                        Ok(cfg) => return cfg,
                        Err(e) => {
                            tracing::warn!(error = %e, path = %args[i + 1], "failed to parse config file");
                        }
                    },
                    Err(e) => {
                        tracing::warn!(error = %e, path = %args[i + 1], "failed to read config file");
                    }
                }
            }
        }

        // Try KERNEL_ADDR env var as override
        let mut cfg = Self::default();
        if let Ok(addr) = std::env::var("KERNEL_ADDR") {
            cfg.kernel_addr = addr;
        }
        cfg
    }
}
